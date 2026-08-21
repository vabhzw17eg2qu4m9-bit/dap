// DAP/1 outbound WS client: hello/welcome handshake (with the additive signed
// "x25519" field), flush after welcome, capped-backoff reconnect (1s→30s,
// reset on welcome), channel join (create-on-first-join), E2E channel + DM
// sends, whois-before-DM, inbound decryption to RAW plaintext strings (payload
// shaping — e.g. glossary negotiation — layers on top, see docs/protocol.md).
// Identity on disk: one JSON file {priv,pub,xpriv,xpub}, permissions 0600.
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

export interface WhoisInfo {
  agentId: string;
  pubkey: string;
  x25519: string;
  name?: string;
  online?: boolean;
}

export interface SendResult {
  ok: true;
  id: string;
  from: string;
  channel?: string;
  to?: string;
  /** True when this send created the channel (we generated its keypair). */
  created?: boolean;
  /** Channel public key (b64) — share out-of-band with future members. */
  chanPubkey?: string;
}

export interface ClientOpts {
  url: string;
  keyPath: string;
  name?: string;
  channels?: ChannelKey[];
  backoff?: { initialMs?: number; maxMs?: number };
}

interface PeerInfo extends WhoisInfo {
  xPub: Uint8Array;
}

interface Identity {
  priv: Uint8Array;
  pub: Uint8Array;
  xpriv: Uint8Array;
  xpub: Uint8Array;
}

const INBOX_CAP = 100;
const WAIT_MS = 5000;

function loadIdentity(keyPath: string): Identity {
  if (existsSync(keyPath)) {
    const f = JSON.parse(readFileSync(keyPath, 'utf8')) as Record<string, string>;
    const id = { priv: dap.b64d(f.priv), pub: dap.b64d(f.pub), xpriv: dap.b64d(f.xpriv), xpub: dap.b64d(f.xpub) };
    if (Object.values(id).every((k) => k.length === 32)) return id;
  }
  const ed = dap.newEdKeypair();
  const x = dap.newX25519Keypair();
  mkdirSync(dirname(keyPath), { recursive: true });
  writeFileSync(keyPath, JSON.stringify({
    priv: dap.b64e(ed.priv), pub: dap.b64e(ed.pub), xpriv: dap.b64e(x.priv), xpub: dap.b64e(x.pub),
  }), { mode: 0o600 });
  chmodSync(keyPath, 0o600); // enforce on pre-existing files too
  return { priv: ed.priv, pub: ed.pub, xpriv: x.priv, xpub: x.pub };
}

export class DapClient {
  readonly agentId: string;
  /** Hub `whois` requests issued — lets tests prove whois-before-DM. */
  whoisCalls = 0;
  lastError = '';
  private readonly id: Identity;
  private readonly opts: ClientOpts;
  private readonly channels = new Map<string, ChannelKey>();
  private readonly joined = new Set<string>();
  private readonly inboxMsgs: MsgEvent[] = [];
  private readonly known = new Map<string, PeerInfo>();
  private readonly whoisWaiters = new Map<string, Array<(info?: PeerInfo) => void>>();
  private readonly joinWaiters = new Map<string, Array<(err?: Error) => void>>();
  private readonly readyWaiters: Array<() => void> = [];
  private readonly listeners = new Set<(m: MsgEvent) => void>();
  private ws: WebSocket | null = null;
  private retryTimer: NodeJS.Timeout | null = null;
  private readonly initialMs: number;
  private readonly maxMs: number;
  private delay: number;
  private welcomed = false;
  private stopped = false;

  constructor(opts: ClientOpts) {
    this.opts = opts;
    this.id = loadIdentity(opts.keyPath);
    this.agentId = dap.agentIdOf(this.id.pub);
    for (const ch of opts.channels ?? []) this.channels.set(ch.name, ch);
    this.initialMs = opts.backoff?.initialMs ?? 1000;
    this.maxMs = opts.backoff?.maxMs ?? 30_000;
    this.delay = this.initialMs;
  }

  /** Observe every decrypted inbound message (raw plaintext string). */
  onMessage(cb: (m: MsgEvent) => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  start(): void {
    this.stopped = false;
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = null;
    this.ws?.close();
    this.ws = null;
  }

  /** Resolve once `welcome` arrived (bounded — rejects on timeout). */
  ready(timeoutMs = WAIT_MS): Promise<void> {
    if (this.welcomed && this.ws?.readyState === WebSocket.OPEN) return Promise.resolve();
    const { promise, resolve, reject } = Promise.withResolvers<void>();
    const wake = () => { clearTimeout(timer); resolve(); };
    const timer = setTimeout(() => {
      const i = this.readyWaiters.indexOf(wake);
      if (i >= 0) this.readyWaiters.splice(i, 1);
      reject(new Error('hub not ready'));
    }, timeoutMs);
    this.readyWaiters.push(wake);
    return promise;
  }

  /** Register out-of-band channel keys (e.g. DAP_CHANNELS env, test setup). */
  addChannel(ch: ChannelKey): void {
    this.channels.set(ch.name, ch);
  }

  /** Known channel keys (creator holds `priv` locally). */
  channel(name: string): ChannelKey | undefined {
    return this.channels.get(name);
  }

  /** Join a channel. First join ever creates it and registers chanPubkey. */
  async join(name: string, chanPubkey: string): Promise<void> {
    await this.ready();
    if (this.joined.has(name)) return;
    const { promise, resolve, reject } = Promise.withResolvers<void>();
    const timer = setTimeout(() => reject(new Error(`timeout joining ${name}`)), WAIT_MS);
    const done = (err?: Error) => { clearTimeout(timer); if (err) reject(err); else resolve(); };
    const list = this.joinWaiters.get(name) ?? [];
    list.push(done);
    this.joinWaiters.set(name, list);
    try {
      this.sendFrame({ op: 'join', channel: name, chanPubkey });
    } catch (err) {
      done(err as Error);
    }
    await promise;
  }

  /** Ensure the channel exists and we are a member; create it if unknown.
   *  ponytail: on a name collision the hub keeps the ORIGINAL channel pubkey
   *  and ours is ignored — the creator effectively owns the channel (v1). */
  async ensureChannel(name: string): Promise<ChannelKey & { created: boolean }> {
    const known = this.channels.get(name);
    if (known) {
      await this.join(name, known.pub);
      return { ...known, created: false };
    }
    const kp = dap.newX25519Keypair();
    const ch: ChannelKey = { name, pub: dap.b64e(kp.pub), priv: dap.b64e(kp.priv) };
    await this.join(name, ch.pub); // first join registers the channel pubkey
    this.channels.set(name, ch);
    return { ...ch, created: true };
  }

  /** Send an E2E-encrypted message to a channel (creates it on first use). */
  async send(channel: string, text: string): Promise<SendResult> {
    const ch = await this.ensureChannel(channel);
    await this.ready();
    const id = randomUUID();
    this.signAndSend({
      op: 'send',
      channel,
      id,
      ts: Date.now(),
      ciphertext: dap.seal(text, id, channel, this.id.xpriv, dap.b64d(ch.pub)),
    });
    const res: SendResult = { ok: true, id, from: this.agentId, channel, chanPubkey: ch.pub };
    if (ch.created) res.created = true;
    return res;
  }

  /** Direct message: whois the peer first, then ECDH with their x25519 key. */
  async dm(to: string, text: string): Promise<SendResult> {
    const info = await this.agentInfo(to);
    if (!info.xPub.length) throw new Error(`agent ${to} has no x25519 key`);
    await this.ready();
    const id = randomUUID();
    this.signAndSend({
      op: 'send',
      to,
      id,
      ts: Date.now(),
      ciphertext: dap.seal(text, id, to, this.id.xpriv, info.xPub),
    });
    return { ok: true, id, from: this.agentId, to };
  }

  /** Pubkey directory lookup (needed for DM key agreement). */
  async whois(agentId: string): Promise<WhoisInfo> {
    const { xPub: _internal, ...out } = await this.agentInfo(agentId);
    return out;
  }

  /** Drain the decrypted inbox (pull-mode inbound — the MCP `dap_inbox` tool). */
  drainInbox(): MsgEvent[] {
    return this.inboxMsgs.splice(0);
  }

  // --- internals ---

  private sendFrame(frame: dap.Frame): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) throw new Error('not connected');
    this.ws.send(JSON.stringify(frame));
  }

  private signAndSend(frame: dap.Frame): void {
    frame.sig = dap.signFrame(frame, this.id.priv);
    this.sendFrame(frame);
  }

  private connect(): void {
    if (this.stopped) return;
    this.ws = new WebSocket(this.opts.url);
    this.ws.on('open', () => this.sendHello());
    this.ws.on('message', (data) => this.handleRaw(String(data)));
    this.ws.on('close', () => this.onDisconnect());
    this.ws.on('error', (err) => { this.lastError = String(err); }); // close always follows
  }

  private sendHello(): void {
    const frame: dap.Frame = {
      op: 'hello',
      v: 1,
      pubkey: dap.b64e(this.id.pub),
      x25519: dap.b64e(this.id.xpub), // additive, covered by the signature
      name: this.opts.name,
      nonce: randomBytes(16).toString('hex'),
      ts: Date.now(),
    };
    frame.sig = dap.signFrame(frame, this.id.priv);
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
      case 'welcome': this.onWelcome(); break;
      case 'joined': this.onJoined(String(frame.channel)); break;
      case 'agent_info': this.onAgentInfo(frame); break;
      case 'msg': void this.onMsg(frame); break;
      case 'error': this.onError(frame); break;
      default: break; // presence / flushed: nothing to do
    }
  }

  private onWelcome(): void {
    this.welcomed = true;
    this.delay = this.initialMs; // backoff resets after a successful welcome
    this.joined.clear(); // hub membership is in-memory: re-join on demand
    this.ws?.send(JSON.stringify({ op: 'flush' })); // drain offline mailbox
    for (const wake of this.readyWaiters.splice(0)) wake();
  }

  private onJoined(channel: string): void {
    this.joined.add(channel);
    for (const done of this.joinWaiters.get(channel) ?? []) done();
    this.joinWaiters.delete(channel);
  }

  private onError(frame: dap.Frame): void {
    this.lastError = `hub error ${frame.code}: ${frame.msg}`;
    if (frame.code === 'unknown_channel' || frame.code === 'access_denied') {
      const err = new Error(this.lastError);
      for (const done of this.joinWaiters.get(String(frame.channel)) ?? []) done(err);
      this.joinWaiters.delete(String(frame.channel));
    }
    if (frame.code === 'unknown_agent') {
      for (const resolves of this.whoisWaiters.values()) for (const r of resolves) r(undefined);
      this.whoisWaiters.clear();
    }
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
    const info: PeerInfo = {
      agentId,
      pubkey: String(frame.pubkey),
      x25519,
      name: frame.name as string | undefined,
      online: frame.online as boolean | undefined,
      xPub: x25519 ? dap.b64d(x25519) : new Uint8Array(0),
    };
    this.known.set(agentId, info);
    for (const resolve of this.whoisWaiters.get(agentId) ?? []) resolve(info);
    this.whoisWaiters.delete(agentId);
  }

  private agentInfo(agentId: string): Promise<PeerInfo> {
    const cached = this.known.get(agentId);
    if (cached) return Promise.resolve(cached);
    const { promise, resolve, reject } = Promise.withResolvers<PeerInfo | undefined>();
    const timer = setTimeout(() => reject(new Error(`timeout whois ${agentId}`)), WAIT_MS);
    const done = (info?: PeerInfo) => { clearTimeout(timer); resolve(info); };
    const list = this.whoisWaiters.get(agentId) ?? [];
    list.push(done);
    this.whoisWaiters.set(agentId, list);
    this.whoisCalls++;
    this.ws?.send(JSON.stringify({ op: 'whois', agentId }));
    return promise.then((info) => {
      if (!info) throw new Error(`unknown_agent: ${agentId}`);
      return info;
    });
  }

  private async onMsg(frame: dap.Frame): Promise<void> {
    try {
      const ev = await this.decryptMsg(frame);
      this.inboxMsgs.push(ev);
      if (this.inboxMsgs.length > INBOX_CAP) this.inboxMsgs.shift();
      for (const cb of this.listeners) cb(ev);
    } catch (err) {
      this.lastError = `undecryptable msg: ${String(err)}`;
    }
  }

  private async decryptMsg(frame: dap.Frame): Promise<MsgEvent> {
    const id = String(frame.id);
    const from = String(frame.from);
    const sender = await this.agentInfo(from);
    if (frame.channel !== undefined) {
      // Channel: receiver ECDH = channel x25519 priv x sender x25519 pub.
      const ch = this.channels.get(String(frame.channel));
      if (!ch?.priv) throw new Error('no channel private key');
      const text = dap.open(String(frame.ciphertext), id, String(frame.channel), dap.b64d(ch.priv), sender.xPub);
      return { dm: false, channel: String(frame.channel), from, text, ts: Number(frame.ts) };
    }
    if (!sender.xPub.length) throw new Error('sender has no x25519 key');
    // DM: receiver ECDH = own x25519 priv x sender x25519 pub; AAD peer = recipient.
    const text = dap.open(String(frame.ciphertext), id, String(frame.to), this.id.xpriv, sender.xPub);
    return { dm: true, from, text, ts: Number(frame.ts) };
  }
}

export const defaultKeyPath = (): string => join(homedir(), '.dap', 'agent.key');
