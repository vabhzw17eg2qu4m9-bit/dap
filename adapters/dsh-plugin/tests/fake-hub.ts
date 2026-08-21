// In-test fake DAP/1 hub: verifies hello/send signatures, answers whois (with
// the additive x25519 field), encrypts inbound DM/channel frames to the plugin.
import { randomUUID } from 'node:crypto';
import { WebSocketServer, type WebSocket } from 'ws';
import * as dap from '../src/crypto.js';

export class FakeHub {
  readonly frames: dap.Frame[] = [];
  /** Fake peer agent: Ed25519 identity + dedicated X25519 E2E key. */
  readonly peer = dap.newEdKeypair();
  readonly peerX = dap.newX25519Keypair();
  readonly peerId: string;
  /** Channel keypair, generated once by the "creator" (plain X25519). */
  readonly channel = dap.newX25519Keypair();
  hellos = 0;
  private wss = new WebSocketServer({ port: 0 });
  private conn: WebSocket | null = null;
  private pluginPub: Uint8Array | null = null;
  private pluginX: Uint8Array | null = null;
  private frameWaiters: ((f: dap.Frame) => void)[] = [];

  constructor() {
    this.peerId = dap.agentIdOf(this.peer.pub);
  }

  async start(): Promise<this> {
    const { promise, resolve } = Promise.withResolvers<void>();
    this.wss.on('connection', (ws) => {
      this.conn = ws;
      ws.on('message', (data) => this.onFrame(JSON.parse(String(data))));
    });
    this.wss.once('listening', resolve);
    await promise;
    return this;
  }

  get url(): string {
    const addr = this.wss.address();
    return `ws://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}/ws`;
  }

  get pluginAgentId(): string {
    if (!this.pluginPub) throw new Error('no hello yet');
    return dap.agentIdOf(this.pluginPub);
  }

  get pluginPubOrThrow(): Uint8Array {
    if (!this.pluginPub) throw new Error('no hello yet');
    return this.pluginPub;
  }

  get pluginXOrThrow(): Uint8Array {
    if (!this.pluginX) throw new Error('no hello yet');
    return this.pluginX;
  }

  private onFrame(frame: dap.Frame): void {
    this.frames.push(frame);
    for (const notify of this.frameWaiters.splice(0)) notify(frame);
    if (frame.op === 'hello') this.onHello(frame);
    else if (frame.op === 'flush') this.send({ op: 'flushed', count: 0 });
    else if (frame.op === 'whois') this.onWhois(frame);
  }

  private onHello(frame: dap.Frame): void {
    this.hellos++;
    this.pluginPub = dap.b64d(String(frame.pubkey));
    this.pluginX = typeof frame.x25519 === 'string' && frame.x25519 ? dap.b64d(String(frame.x25519)) : null;
    if (!dap.verifyFrame(frame, this.pluginPub)) {
      this.send({ op: 'error', code: 'bad_signature', msg: 'hello' });
      return;
    }
    if (typeof frame.nonce !== 'string' || frame.nonce.length < 16) {
      this.send({ op: 'error', code: 'bad_frame', msg: 'nonce' });
      return;
    }
    this.send({ op: 'welcome', agentId: this.pluginAgentId });
  }

  private onWhois(frame: dap.Frame): void {
    const isPeer = frame.agentId === this.peerId;
    this.send({
      op: 'agent_info',
      agentId: String(frame.agentId),
      pubkey: dap.b64e(isPeer ? this.peer.pub : this.pluginPubOrThrow),
      x25519: dap.b64e(isPeer ? this.peerX.pub : this.pluginXOrThrow),
      name: isPeer ? 'peer' : 'plugin',
      online: true,
    });
  }

  send(frame: dap.Frame): void {
    this.conn?.send(JSON.stringify(frame));
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

  /** DM from fake peer -> plugin agent (E2E; hub sees ciphertext only). */
  pushDm(text: string): void {
    const id = randomUUID();
    const ciphertext = dap.seal(text, id, this.pluginAgentId, this.peerX.priv, this.pluginXOrThrow);
    this.send({ op: 'msg', to: this.pluginAgentId, from: this.peerId, id, ts: Date.now(), ciphertext });
  }

  /** Channel message from fake peer -> plugin's channel. */
  pushChannel(name: string, text: string): void {
    const id = randomUUID();
    const ciphertext = dap.seal(text, id, name, this.peerX.priv, this.channel.pub);
    this.send({ op: 'msg', channel: name, from: this.peerId, id, ts: Date.now(), ciphertext });
  }

  killClient(): void {
    this.conn?.terminate();
    this.conn = null;
  }

  async stop(): Promise<void> {
    this.killClient();
    const { promise, resolve } = Promise.withResolvers<void>();
    this.wss.close(() => resolve());
    await promise;
  }
}

/** Await a condition without sleep-as-synchronization. */
export async function until(cond: () => boolean, timeoutMs = 3000): Promise<void> {
  const { promise, resolve, reject } = Promise.withResolvers<void>();
  const deadline = Date.now() + timeoutMs;
  const poll = setInterval(() => {
    if (cond()) {
      clearInterval(poll);
      resolve();
    } else if (Date.now() > deadline) {
      clearInterval(poll);
      reject(new Error('condition not met before timeout'));
    }
  }, 5);
  await promise;
}

export const channelConfig = (hub: FakeHub) => [
  { name: 'general', pub: dap.b64e(hub.channel.pub), priv: dap.b64e(hub.channel.priv) },
];
