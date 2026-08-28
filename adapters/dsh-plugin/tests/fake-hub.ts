// In-test fake DAP/1 hub: verifies hello/send signatures, answers whois (with
// the additive x25519 field), tracks channel joins (spec § join), routes
// plugin-to-plugin DMs and channel fan-out, and can push encrypted frames
// from a synthetic peer agent to any connected plugin.
import { randomUUID } from 'node:crypto';
import { WebSocketServer, type WebSocket } from 'ws';
import * as dap from '../src/crypto.js';

/** A hello-verified plugin connection, keyed by agentId. */
interface HubAgent {
  ws: WebSocket | null;
  pub: Uint8Array;
  x: Uint8Array | null;
  name?: string;
}

export class FakeHub {
  readonly frames: dap.Frame[] = [];
  /** Fake peer agent: Ed25519 identity + dedicated X25519 E2E key. */
  readonly peer = dap.newEdKeypair();
  readonly peerX = dap.newX25519Keypair();
  readonly peerId: string;
  /** Channel keypair, generated once by the "creator" (plain X25519). */
  readonly channel = dap.newX25519Keypair();
  /** channel -> member agentIds (join tracking, spec § join). */
  readonly channelMembers = new Map<string, Set<string>>();
  /** channel -> registered chanPubkey (b64); first joiner creates (hub law). */
  readonly chanPubkeys = new Map<string, string>();
  hellos = 0;
  /** Test switch: drop whois queries on the floor (bounded-wait tests). */
  answerWhois = true;
  private wss = new WebSocketServer({ port: 0 });
  private agents = new Map<string, HubAgent>();
  private lastAgentId = '';
  private frameWaiters: ((f: dap.Frame) => void)[] = [];

  constructor() {
    this.peerId = dap.agentIdOf(this.peer.pub);
  }

  async start(): Promise<this> {
    const { promise, resolve } = Promise.withResolvers<void>();
    this.wss.on('connection', (ws) => {
      let agentId = '';
      ws.on('message', (data) => {
        agentId = this.onFrame(JSON.parse(String(data)), ws, agentId) ?? agentId;
      });
      ws.on('close', () => {
        const a = this.agents.get(agentId);
        if (a && a.ws === ws) a.ws = null;
      });
    });
    this.wss.once('listening', resolve);
    await promise;
    return this;
  }

  get url(): string {
    const addr = this.wss.address();
    return `ws://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}/ws`;
  }

  /** The most recent plugin to complete a hello (single-plugin tests). */
  get pluginAgentId(): string {
    if (!this.lastAgentId) throw new Error('no hello yet');
    return this.lastAgentId;
  }

  get pluginPubOrThrow(): Uint8Array {
    const a = this.agents.get(this.pluginAgentId);
    if (!a?.pub) throw new Error('no hello yet');
    return a.pub;
  }

  get pluginXOrThrow(): Uint8Array {
    const a = this.agents.get(this.pluginAgentId);
    if (!a?.x) throw new Error('no hello yet');
    return a.x;
  }

  /** Returns the agentId once hello'd, else the previous one. */
  private onFrame(frame: dap.Frame, ws: WebSocket, agentId: string): string | undefined {
    this.frames.push(frame);
    for (const notify of this.frameWaiters.splice(0)) notify(frame);
    if (frame.op === 'hello') return this.onHello(frame, ws);
    if (!agentId) return undefined;
    if (frame.op === 'flush') ws.send(JSON.stringify({ op: 'flushed', count: 0 }));
    else if (frame.op === 'whois') this.onWhois(frame, ws);
    else if (frame.op === 'presence_query') this.onPresenceQuery(ws);
    else if (frame.op === 'join') this.onJoin(frame, ws, agentId);
    else if (frame.op === 'send') this.onSend(frame, ws, agentId);
    return undefined;
  }

  private onHello(frame: dap.Frame, ws: WebSocket): string {
    this.hellos++;
    const pub = dap.b64d(String(frame.pubkey));
    const x = typeof frame.x25519 === 'string' && frame.x25519 ? dap.b64d(String(frame.x25519)) : null;
    const agentId = dap.agentIdOf(pub);
    this.agents.set(agentId, { ws, pub, x, name: frame.name as string | undefined });
    this.lastAgentId = agentId;
    if (!dap.verifyFrame(frame, pub)) {
      ws.send(JSON.stringify({ op: 'error', code: 'bad_signature', msg: 'hello' }));
      return agentId;
    }
    if (typeof frame.nonce !== 'string' || frame.nonce.length < 16) {
      ws.send(JSON.stringify({ op: 'error', code: 'bad_frame', msg: 'nonce' }));
      return agentId;
    }
    ws.send(JSON.stringify({ op: 'welcome', agentId }));
    return agentId;
  }

  private onWhois(frame: dap.Frame, ws: WebSocket): void {
    if (!this.answerWhois) return;
    const q = String(frame.agentId);
    const isPeer = q === this.peerId;
    const known = this.agents.get(q);
    const pub = isPeer ? this.peer.pub : (known?.pub ?? this.pluginPubOrThrow);
    const x = isPeer ? this.peerX.pub : (known?.x ?? this.pluginXOrThrow);
    ws.send(
      JSON.stringify({
        op: 'agent_info',
        agentId: q,
        pubkey: dap.b64e(pub),
        x25519: dap.b64e(x),
        name: isPeer ? 'peer' : (known?.name ?? 'plugin'),
        online: true,
      }),
    );
  }

  /** Spec § presence: registry = connected plugins + the synthetic peer
   *  (a hub-lifetime agent, always online). */
  private onPresenceQuery(ws: WebSocket): void {
    const agents = [...this.agents.entries()].map(([agentId, a]) => ({
      agentId,
      name: a.name,
      online: a.ws !== null,
      lastSeen: Date.now(),
    }));
    agents.push({ agentId: this.peerId, name: 'peer', online: true, lastSeen: Date.now() });
    ws.send(JSON.stringify({ op: 'presence', agents }));
  }

  /** Spec § join: first join creates the channel and registers chanPubkey;
   *  re-join is idempotent. */
  private onJoin(frame: dap.Frame, ws: WebSocket, agentId: string): void {
    const name = String(frame.channel);
    if (!name) {
      ws.send(JSON.stringify({ op: 'error', code: 'bad_frame', msg: 'join requires channel' }));
      return;
    }
    const members = this.channelMembers.get(name) ?? new Set<string>();
    members.add(agentId);
    this.channelMembers.set(name, members);
    if (!this.chanPubkeys.has(name) && typeof frame.chanPubkey === 'string') {
      this.chanPubkeys.set(name, frame.chanPubkey);
    }
    ws.send(JSON.stringify({ op: 'joined', channel: name }));
  }

  /** Verified sends: DMs route to the recipient, channel sends fan out to
   *  the joined members (ciphertext only — never decrypted hub-side). */
  private onSend(frame: dap.Frame, ws: WebSocket, agentId: string): void {
    const sender = this.agents.get(agentId)!;
    if (!dap.verifyFrame(frame, sender.pub)) {
      ws.send(JSON.stringify({ op: 'error', code: 'bad_signature', msg: 'send' }));
      return;
    }
    const msg: dap.Frame = {
      op: 'msg',
      from: agentId,
      id: String(frame.id),
      ts: Number(frame.ts),
      ciphertext: String(frame.ciphertext),
    };
    if (frame.to !== undefined) {
      const to = String(frame.to);
      if (to !== this.peerId) {
        // peerId is the synthetic agent: tests decrypt its DMs manually.
        const target = this.agents.get(to);
        if (target?.ws) {
          target.ws.send(JSON.stringify({ ...msg, to }));
        }
      }
      return;
    }
    if (frame.channel !== undefined) {
      const channel = String(frame.channel);
      msg.channel = channel;
      for (const member of this.channelMembers.get(channel) ?? []) {
        if (member === agentId) continue;
        const target = this.agents.get(member);
        if (target?.ws) target.ws.send(JSON.stringify(msg));
      }
    }
  }

  /** Test injection: broadcast to every connected plugin (single-plugin
   *  equivalent of the old one-connection hub). */
  send(frame: dap.Frame): void {
    for (const a of this.agents.values()) a.ws?.send(JSON.stringify(frame));
  }

  /** Resolves on the first frame (already received or future) matching pred. */
  waitFor(pred: (f: dap.Frame) => boolean, timeoutMs = 3000): Promise<dap.Frame> {
    const already = this.frames.find(pred);
    if (already) return Promise.resolve(already);
    const { promise, resolve, reject } = Promise.withResolvers<dap.Frame>();
    const timer = setTimeout(() => {
      const i = this.frameWaiters.indexOf(notify);
      if (i >= 0) this.frameWaiters.splice(i, 1);
      reject(new Error('fake hub: timed out waiting for frame'));
    }, timeoutMs);
    const notify = (f: dap.Frame): void => {
      if (!pred(f)) {
        this.frameWaiters.push(notify); // re-arm: not the frame we want
        return;
      }
      clearTimeout(timer);
      resolve(f);
    };
    this.frameWaiters.push(notify);
    return promise;
  }

  /** DM from fake peer -> an agent (E2E; hub sees ciphertext only). */
  pushDm(text: string, to = this.pluginAgentId): void {
    const target = this.agents.get(to);
    if (!target?.x) throw new Error('no hello with x25519 yet');
    const id = randomUUID();
    const ciphertext = dap.seal(text, id, to, this.peerX.priv, target.x);
    target.ws?.send(JSON.stringify({ op: 'msg', to, from: this.peerId, id, ts: Date.now(), ciphertext }));
  }

  /** Channel message from fake peer -> a plugin's channel. */
  pushChannel(name: string, text: string, to = this.pluginAgentId): void {
    const target = this.agents.get(to);
    if (!target?.ws) throw new Error('no hello yet');
    const id = randomUUID();
    const ciphertext = dap.seal(text, id, name, this.peerX.priv, this.channel.pub);
    target.ws.send(JSON.stringify({ op: 'msg', channel: name, from: this.peerId, id, ts: Date.now(), ciphertext }));
  }

  killClient(agentId = this.pluginAgentId): void {
    const a = this.agents.get(agentId);
    a?.ws?.terminate();
    if (a) a.ws = null;
  }

  /** Server-side view: is this agent's socket still open? */
  isOnline(agentId: string): boolean {
    return this.agents.get(agentId)?.ws != null;
  }

  async stop(): Promise<void> {
    for (const a of this.agents.values()) a.ws?.terminate();
    for (const c of this.wss.clients) c.terminate();
    const { promise, resolve } = Promise.withResolvers<void>();
    this.wss.close(() => resolve());
    await promise;
  }
}

/** Await a condition without sleep-as-synchronization. */
export async function until(cond: () => boolean, timeoutMs = 3000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error('timed out waiting for condition');
    const { promise, resolve } = Promise.withResolvers<void>();
    setTimeout(resolve, 5);
    await promise;
  }
}

export const channelConfig = (hub: FakeHub) => [
  { name: 'general', pub: dap.b64e(hub.channel.pub), priv: dap.b64e(hub.channel.priv) },
];
