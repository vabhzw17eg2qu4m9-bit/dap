import WebSocket from 'ws';
import { randomBytes, bytesToHex } from '@noble/hashes/utils';
import { signFrame, agentIdFor, b64, type KeyPair } from './crypto.ts';
import { DEFAULT_KEEP_ALIVE, KeepAliveWatchdog, type KeepAliveOptions } from './keepalive.ts';

export interface Timers {
  setInterval: (fn: () => void, ms: number) => unknown;
  clearInterval: (handle: unknown) => void;
}

export type TimerHandle = NodeJS.Timeout;

export interface Backoff {
  initial: number;
  max: number;
}

export const DEFAULT_BACKOFF: Backoff = { initial: 1000, max: 30000 };

export interface MsgFrame {
  op: 'msg';
  channel?: string;
  from: string;
  id: string;
  ts: number;
  ciphertext: string;
}

/** One agent in a presence snapshot (hub registry view). */
export interface PresenceAgent {
  agentId: string;
  name?: string;
  online: boolean;
  lastSeen?: number;
}

export interface AgentInfo {
  agentId: string;
  pubkey: string;
  /** Agent's X25519 public key (b64); empty string when the peer did not send one. */
  x25519: string;
  name?: string;
  online: boolean;
}

export interface WelcomeInfo {
  agentId: string;
}

export interface DapOptions {
  url: string;
  keys: KeyPair;
  name?: string;
  backoff?: Partial<Backoff>;
  timers?: Timers;
  /** Client keepalive: ping the hub while idle, terminate on missed pong. */
  keepAlive?: Partial<KeepAliveOptions>;
}

type Listener = (value: unknown) => void;

/**
 * DAP/1 wire client: hello handshake, signed send frames, flush after
 * welcome, and a setInterval-driven reconnect loop with exponential
 * backoff (1s doubling, 30s cap, reset on welcome).
 */
export class DapClient {
  readonly agentId: string;
  connected = false;
  helloCount = 0;
  welcomeCount = 0;
  /** Delays handed to setInterval for each reconnect — spec-visible backoff. */
  readonly backoffSchedule: number[] = [];
  onMessage: ((frame: MsgFrame) => void | Promise<void>) | undefined;

  private readonly backoff: Backoff;
  private readonly timers: Timers;
  private readonly watchdog: KeepAliveWatchdog;
  private ws: WebSocket | undefined;
  private delay: number;
  private timer: unknown;
  private stopped = false;
  private readonly listeners = new Map<string, Set<Listener>>();
  private readonly emitCounts = new Map<string, number>();
  private readonly whoisCache = new Map<string, AgentInfo>();
  private readonly whoisWaiters = new Map<string, Array<(info: AgentInfo | undefined) => void>>();

  constructor(private readonly opts: DapOptions) {
    this.agentId = agentIdFor(opts.keys.pub);
    this.backoff = { ...DEFAULT_BACKOFF, ...opts.backoff };
    this.delay = this.backoff.initial;
    this.timers =
      opts.timers ?? {
        setInterval: (fn, ms) => setInterval(fn, ms),
        clearInterval: (h) => clearInterval(h as TimerHandle),
      };
    this.watchdog = new KeepAliveWatchdog({ ...DEFAULT_KEEP_ALIVE, ...opts.keepAlive });
  }

  connect(): void {
    if (this.stopped) return;
    this.helloCount++;
    const ws = new WebSocket(this.opts.url);
    this.ws = ws;
    ws.on('error', () => {}); // 'close' always follows; schedule from there
    ws.on('open', () => {
      this.watchdog.start(ws); // refresh while idle; terminate a dead conn
      this.sendHello();
    });
    ws.on('message', (data) => this.handleFrame(data.toString()));
    ws.on('close', () => this.onClose());
  }

  stop(): void {
    this.stopped = true;
    this.watchdog.stop();
    if (this.timer !== undefined) this.timers.clearInterval(this.timer);
    this.timer = undefined;
    this.ws?.close();
  }

  send(frame: Record<string, unknown>): void {
    if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(frame));
  }

  /** Build, sign and send a `send` frame; `id` binds the E2E payload (HKDF salt / AAD). */
  signedSend(payload: { channel?: string; to?: string; id: string; ciphertext: string }): number {
    const frame: Record<string, unknown> = {
      op: 'send',
      id: payload.id,
      ts: Date.now(),
      ciphertext: payload.ciphertext,
    };
    if (payload.channel) frame.channel = payload.channel;
    if (payload.to) frame.to = payload.to;
    frame.sig = signFrame(this.opts.keys.priv, 'send', frame);
    this.send(frame);
    return frame.ts as number;
  }

  /** Channel membership (spec § join): first join creates the channel and
   * registers chanPubkey; re-join is idempotent — safe on every reconnect. */
  join(channel: string, chanPubkeyB64: string): void {
    this.send({ op: 'join', channel, chanPubkey: chanPubkeyB64 });
  }

  /** Presence snapshot: every agent the hub knows (id, name, online, lastSeen). */
  presence(): Promise<PresenceAgent[]> {
    const prev = this.eventCount('presence');
    this.send({ op: 'presence_query' });
    return this.waitForAfter<{ agents: PresenceAgent[] }>('presence', prev, 5000)
      .then((f) => f.agents);
  }

  /** Pubkey directory lookup (needed for DM key agreement). */
  whois(agentId: string): Promise<AgentInfo | undefined> {
    const cached = this.whoisCache.get(agentId);
    if (cached) return Promise.resolve(cached);
    const { promise, resolve } = Promise.withResolvers<AgentInfo | undefined>();
    const waiters = this.whoisWaiters.get(agentId) ?? [];
    waiters.push(resolve);
    this.whoisWaiters.set(agentId, waiters);
    this.send({ op: 'whois', agentId });
    return promise;
  }

  on(event: string, listener: Listener): () => void {
    const set = this.listeners.get(event) ?? new Set();
    set.add(listener);
    this.listeners.set(event, set);
    return () => set.delete(listener);
  }

  /** Emission counter for an event (monotonic; enables wait-for-the-Nth). */
  eventCount(event: string): number {
    return this.emitCounts.get(event) ?? 0;
  }

  /** Resolve with the first emission of `event` AFTER `prev` emissions
   *  already happened. Registering before the trigger avoids races. */
  waitForAfter<T>(event: string, prev: number, timeoutMs = 5000): Promise<T> {
    if (this.eventCount(event) > prev) return Promise.resolve(undefined as T);
    const { promise, resolve, reject } = Promise.withResolvers<T>();
    const off = this.on(event, (value) => {
      if (this.eventCount(event) <= prev) return;
      clearTimeout(timer);
      off();
      resolve(value as T);
    });
    const timer = setTimeout(() => {
      off();
      reject(new Error('timeout waiting for ' + event));
    }, timeoutMs);
    return promise;
  }

  private sendHello(): void {
    const frame: Record<string, unknown> = {
      op: 'hello',
      v: 1,
      pubkey: b64(this.opts.keys.pub),
      x25519: b64(this.opts.keys.xpub), // additive, covered by the signature
      nonce: bytesToHex(randomBytes(16)),
      ts: Date.now(),
    };
    if (this.opts.name) frame.name = this.opts.name;
    frame.sig = signFrame(this.opts.keys.priv, 'hello', frame);
    this.send(frame);
  }

  private handleFrame(text: string): void {
    let frame: Record<string, unknown>;
    try {
      frame = JSON.parse(text) as Record<string, unknown>;
    } catch {
      return;
    }
    switch (frame.op) {
      case 'welcome':
        this.onWelcome(frame as unknown as WelcomeInfo & Record<string, unknown>);
        break;
      case 'msg': {
        const msgFrame = frame as unknown as MsgFrame;
        // 'inbound' fires only after the handler's async chain (decrypt,
        // inbox, steer) settled — tests can rely on it deterministically.
        void Promise.resolve(this.onMessage?.(msgFrame))
          .catch(() => {})
          .then(() => this.emit('inbound', msgFrame));
        break;
      }
      case 'agent_info': {
        const info = frame as unknown as AgentInfo;
        this.whoisCache.set(info.agentId, info);
        for (const resolve of this.whoisWaiters.get(info.agentId) ?? []) resolve(info);
        this.whoisWaiters.delete(info.agentId);
        this.emit('agent_info', info);
        break;
      }
      case 'joined':
        this.emit('joined', frame);
        break;
      case 'flushed':
        this.emit('flushed', frame);
        break;
      case 'presence':
        this.emit('presence', frame);
        break;
      case 'error':
        for (const waiters of this.whoisWaiters.values()) for (const resolve of waiters) resolve(undefined);
        this.whoisWaiters.clear();
        this.emit('error', frame);
        break;
      default:
        break;
    }
  }

  private onWelcome(welcome: WelcomeInfo & Record<string, unknown>): void {
    this.connected = true;
    this.welcomeCount++;

    this.delay = this.backoff.initial; // backoff resets after a successful welcome
    this.send({ op: 'flush' }); // drain offline mailbox
    this.emit('welcome', welcome);
  }

  private onClose(): void {
    this.watchdog.stop();
    const wasConnected = this.connected;
    this.connected = false;
    this.ws = undefined;
    this.emit('close', { wasConnected });
    if (!this.stopped) this.scheduleReconnect();
  }

  private scheduleReconnect(): void {
    if (this.timer !== undefined) return; // one pending attempt at a time
    const ms = this.delay;
    this.backoffSchedule.push(ms);
    // A throw in a raw (unmanaged) timer callback kills the whole omp session — the body must never throw.
    this.timer = this.timers.setInterval(() => {
      try {
        this.timers.clearInterval(this.timer);
        this.timer = undefined;
        this.connect();
      } catch {
        // swallowed: connect() errors surface via the ws 'close' path, which reschedules
      }
    }, ms);
    this.delay = Math.min(this.delay * 2, this.backoff.max);
  }

  private emit(event: string, value: unknown): void {
    this.emitCounts.set(event, (this.emitCounts.get(event) ?? 0) + 1);
    for (const listener of this.listeners.get(event) ?? []) listener(value);
  }
}
