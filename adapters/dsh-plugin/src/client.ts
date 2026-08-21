// DAP/1 outbound WS client: hello/welcome handshake, signed sends, flush after
// welcome, capped-backoff reconnect, inbound msg decryption, on-disk identity
// (Ed25519 for signing + dedicated X25519 for E2E, per protocol addendum).
import { existsSync, readFileSync, writeFileSync, chmodSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { randomUUID, randomBytes } from 'node:crypto';
import WebSocket from 'ws';
import * as dap from './crypto.js';

export interface ChannelKey {
  /** Channel name; the channel x25519 public key (hub stores this one). */
  name: string;
  pub: string;
  /** Member-only: channel x25519 private key, distributed out-of-band. */
  priv?: string;
}

export interface MsgEvent {
  dm: boolean;
  channel?: string;
  from: string;
  text: string;
  ts: number;
}

export interface ClientOpts {
  url: string;
  keyPath: string;
  name?: string;
  channels?: ChannelKey[];
  backoff?: { initialMs?: number; maxMs?: number };
  onMessage?: (m: MsgEvent) => void;
  onReady?: (agentId: string) => void;
}

const INBOX_CAP = 100;
const READY_TIMEOUT_MS = 5000;

interface Identity {
  edPriv: Uint8Array;
  edPub: Uint8Array;
  xPriv: Uint8Array;
  xPub: Uint8Array;
}

interface IdentityFile {
  edPriv: string;
  edPub: string;
  xPriv: string;
  xPub: string;
}

function loadIdentity(keyPath: string): Identity {
  if (existsSync(keyPath)) {
    const f = JSON.parse(readFileSync(keyPath, 'utf8')) as IdentityFile;
    return { edPriv: dap.b64d(f.edPriv), edPub: dap.b64d(f.edPub), xPriv: dap.b64d(f.xPriv), xPub: dap.b64d(f.xPub) };
  }
  const ed = dap.newEdKeypair();
  const x = dap.newX25519Keypair();
  mkdirSync(dirname(keyPath), { recursive: true });
  const f: IdentityFile = {
    edPriv: dap.b64e(ed.priv),
    edPub: dap.b64e(ed.pub),
    xPriv: dap.b64e(x.priv),
    xPub: dap.b64e(x.pub),
  };
  writeFileSync(keyPath, JSON.stringify(f), { mode: 0o600 });
  chmodSync(keyPath, 0o600); // enforce on pre-existing files too
  return { edPriv: ed.priv, edPub: ed.pub, xPriv: x.priv, xPub: x.pub };
}

interface AgentInfo {
  /** Identity Ed25519 public key. */
  edPub: Uint8Array;
  /** Recipient's X25519 public key (empty when the peer didn't send one). */
  xPub: Uint8Array;
  name?: string;
  online?: boolean;
}

export class DapClient {
  readonly agentId: string;
  private readonly id: Identity;
  private readonly opts: ClientOpts;
  private readonly channels = new Map<string, ChannelKey>();
  private readonly initialMs: number;
  private readonly maxMs: number;
  private readonly inboxMsgs: MsgEvent[] = [];
  private readonly known = new Map<string, AgentInfo>();
  private readonly whoisWaiters = new Map<string, ((info: AgentInfo) => void)[]>();
  private readonly readyWaiters: (() => void)[] = [];
  private ws: WebSocket | null = null;
  private retryTimer: NodeJS.Timeout | null = null;
  private delay: number;
  private welcomed = false;
  private stopped = false;
  lastError = '';

  constructor(opts: ClientOpts) {
    this.opts = opts;
    this.id = loadIdentity(opts.keyPath);
    this.agentId = dap.agentIdOf(this.id.edPub);
    for (const ch of opts.channels ?? []) this.channels.set(ch.name, ch);
    this.initialMs = opts.backoff?.initialMs ?? 1000;
    this.maxMs = opts.backoff?.maxMs ?? 30_000;
    this.delay = this.initialMs;
  }

  start(): void {
    this.stopped = false;
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.ws?.close();
    this.ws = null;
  }

  inbox(): MsgEvent[] {
    return [...this.inboxMsgs];
  }

  async whois(agentId: string): Promise<{ agentId: string; pubkey: string; x25519: string; name?: string; online?: boolean }> {
    const info = await this.agentInfo(agentId);
    return {
      agentId,
      pubkey: dap.b64e(info.edPub),
      x25519: info.xPub.length ? dap.b64e(info.xPub) : '',
      name: info.name,
      online: info.online,
    };
  }

  /** Send an E2E-encrypted message to a channel (channel x25519 pub from config). */
  async send(channel: string, text: string): Promise<void> {
    const ch = this.channels.get(channel);
    if (!ch) throw new Error(`unknown channel: ${channel}`);
    await this.whenReady();
    const id = randomUUID();
    const frame: dap.Frame = {
      op: 'send',
      channel,
      id,
      ts: Date.now(),
      ciphertext: dap.seal(text, id, channel, this.id.xPriv, dap.b64d(ch.pub)),
    };
    this.signAndSend(frame);
  }

  /** Direct message: whois the peer first, then ECDH with their x25519 key. */
  async dm(to: string, text: string): Promise<void> {
    const info = await this.agentInfo(to);
    if (!info.xPub.length) throw new Error(`agent ${to} has no x25519 key`);
    await this.whenReady();
    const id = randomUUID();
    const frame: dap.Frame = {
      op: 'send',
      to,
      id,
      ts: Date.now(),
      ciphertext: dap.seal(text, id, to, this.id.xPriv, info.xPub),
    };
    this.signAndSend(frame);
  }

  private signAndSend(frame: dap.Frame): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) throw new Error('not connected');
    frame.sig = dap.signFrame(frame, this.id.edPriv);
    this.ws.send(JSON.stringify(frame));
  }

  private connect(): void {
    if (this.stopped) return;
    this.ws = new WebSocket(this.opts.url);
    this.ws.on('open', () => this.sendHello());
    this.ws.on('message', (data) => this.handleRaw(String(data)));
    this.ws.on('close', () => this.onDisconnect());
    this.ws.on('error', (err) => {
      this.lastError = String(err);
    }); // close always follows
  }

  private sendHello(): void {
    const frame: dap.Frame = {
      op: 'hello',
      v: 1,
      pubkey: dap.b64e(this.id.edPub),
      x25519: dap.b64e(this.id.xPub),
      name: this.opts.name,
      nonce: randomBytes(16).toString('hex'),
      ts: Date.now(),
    };
    frame.sig = dap.signFrame(frame, this.id.edPriv);
    this.ws?.send(JSON.stringify(frame));
  }

  private handleRaw(raw: string): void {
    let frame: dap.Frame;
    try {
      frame = JSON.parse(raw) as dap.Frame;
    } catch {
      this.lastError = 'bad frame (not JSON)';
      return;
    }
    switch (frame.op) {
      case 'welcome':
        this.onWelcome();
        break;
      case 'agent_info':
        this.onAgentInfo(frame);
        break;
      case 'msg':
        void this.onMsg(frame);
        break;
      case 'error':
        this.lastError = `hub error ${frame.code}: ${frame.msg}`;
        break;
      default:
        break; // presence / flushed: nothing to do
    }
  }

  private onWelcome(): void {
    this.welcomed = true;
    this.delay = this.initialMs; // backoff resets after a successful welcome
    this.ws?.send(JSON.stringify({ op: 'flush' }));
    for (const wake of this.readyWaiters.splice(0)) wake();
    this.opts.onReady?.(this.agentId);
  }

  private onDisconnect(): void {
    this.welcomed = false;
    if (this.stopped) return;
    const wait = this.delay;
    this.delay = Math.min(this.delay * 2, this.maxMs);
    this.retryTimer = setTimeout(() => this.connect(), wait);
  }

  private onAgentInfo(frame: dap.Frame): void {
    const agentId = String(frame.agentId);
    const x25519 = typeof frame.x25519 === 'string' ? frame.x25519 : '';
    const info: AgentInfo = {
      edPub: dap.b64d(String(frame.pubkey)),
      xPub: x25519 ? dap.b64d(x25519) : new Uint8Array(0),
      name: frame.name as string | undefined,
      online: frame.online as boolean | undefined,
    };
    this.known.set(agentId, info);
    for (const resolve of this.whoisWaiters.get(agentId) ?? []) resolve(info);
    this.whoisWaiters.delete(agentId);
  }

  private agentInfo(agentId: string): Promise<AgentInfo> {
    const cached = this.known.get(agentId);
    if (cached) return Promise.resolve(cached);
    const { promise, resolve } = Promise.withResolvers<AgentInfo>();
    const list = this.whoisWaiters.get(agentId) ?? [];
    list.push(resolve);
    this.whoisWaiters.set(agentId, list);
    this.ws?.send(JSON.stringify({ op: 'whois', agentId }));
    return promise;
  }

  private async onMsg(frame: dap.Frame): Promise<void> {
    try {
      const ev = await this.decryptMsg(frame);
      this.inboxMsgs.push(ev);
      if (this.inboxMsgs.length > INBOX_CAP) this.inboxMsgs.shift();
      this.opts.onMessage?.(ev);
    } catch (err) {
      this.lastError = `undecryptable msg: ${String(err)}`;
    }
  }

  private async decryptMsg(frame: dap.Frame): Promise<MsgEvent> {
    const id = String(frame.id);
    const from = String(frame.from);
    const sender = await this.agentInfo(from);
    if (frame.channel !== undefined) {
      const ch = this.channels.get(String(frame.channel));
      // Channel: receiver ECDH = channel x25519 priv x sender x25519 pub.
      if (!ch?.priv) throw new Error('no channel private key');
      const text = dap.open(String(frame.ciphertext), id, String(frame.channel), dap.b64d(ch.priv), sender.xPub);
      return { dm: false, channel: String(frame.channel), from, text, ts: Number(frame.ts) };
    }
    if (!sender.xPub.length) throw new Error('sender has no x25519 key');
    // DM: receiver ECDH = own x25519 priv x sender x25519 pub; AAD peer = recipient.
    const text = dap.open(String(frame.ciphertext), id, String(frame.to), this.id.xPriv, sender.xPub);
    return { dm: true, from, text, ts: Number(frame.ts) };
  }

  private whenReady(): Promise<void> {
    if (this.welcomed && this.ws?.readyState === WebSocket.OPEN) return Promise.resolve();
    const { promise, resolve, reject } = Promise.withResolvers<void>();
    const wake = () => {
      clearTimeout(timer);
      resolve();
    };
    const timer = setTimeout(() => {
      const i = this.readyWaiters.indexOf(wake);
      if (i >= 0) this.readyWaiters.splice(i, 1);
      reject(new Error('hub not ready'));
    }, READY_TIMEOUT_MS);
    this.readyWaiters.push(wake);
    return promise;
  }
}

export const defaultKeyPath = (): string => join(homedir(), '.dsh', 'dap-identity.json');
