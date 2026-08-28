// DAP/1 outbound WS client: hello/welcome handshake (with the additive signed
// "x25519" field), flush after welcome, capped-backoff reconnect (1s→30s,
// reset on welcome), channel join (create-on-first-join), E2E channel + DM
// sends, whois-before-DM, inbound decryption to RAW plaintext strings (payload
// shaping — e.g. glossary negotiation — layers on top, see docs/protocol.md).
// Identity on disk: one JSON file {priv,pub,xpriv,xpub}, permissions 0600.
// Zero-config channels: keys load from / persist to the channels file
// (default ~/.dap/channels.json, see config.ts); unknown channels keygen on
// first send, known channels auto-join after every welcome, and chankey DMs
// (dap_invite) are accepted by persisting + joining + surfacing a notice.
import { existsSync, readFileSync, writeFileSync, chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomUUID, randomBytes } from 'node:crypto';
import WebSocket from 'ws';
import * as dap from './crypto.js';
import { DEFAULT_KEEP_ALIVE, KeepAliveWatchdog } from './keepalive.js';
import { loadChannelKeys, parseChankeyInvite, persistChannelKeys } from './channels.js';
import { persistDapConfig, readDapConfig, type PendingInvite } from './config.js';

/** A hub `error` frame observed on the wire (unknown_agent, access_denied, …)
 *  — plus locally-detected inbound failures (`undecryptable`), which carry
 *  the sender frame's `from`/`id` when the frame had them. */
export interface HubErrorEvent {
  code: string;
  msg: string;
  ts: number;
  from?: string;
  id?: string;
}

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
  /** Set when this entry is a channel-invite notice (not chat): the invited
   *  channel's name. The raw chankey DM never reaches the inbox as text. */
  invite?: string;
}

export interface WhoisInfo {
  agentId: string;
  pubkey: string;
  x25519: string;
  name?: string;
  online?: boolean;
}

export interface PresenceAgent {
  agentId: string;
  name?: string;
  online?: boolean;
  lastSeen?: number;
}

export interface StatusInfo {
  connected: boolean;
  agentId: string;
  name?: string;
  url: string;
  channels: string[];
  /** Successful welcome handshakes (one per authenticated connection). */
  welcomes: number;
  /** Connection attempts (one hello per socket open). */
  hellos: number;
}

export interface ArmedInvite {
  ok: true;
  /** True: the chankey DM is deferred until the name comes online. */
  pending: true;
  name: string;
  channel: string;
  /** Paste-ready connect line for the invited user (shared out-of-band). */
  connectLine: string;
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
  /** Channels file (default ~/.dap/channels.json via config.ts): known
   *  channels load from it; created/invited keypairs persist to it. */
  channelsFile?: string;
  backoff?: { initialMs?: number; maxMs?: number };
  /** Pending by-name invites (dap_invite with a not-yet-online name): load
   *  + arm entries in ~/.dap/config.json and deliver them from a presence
   *  poller. Opt-in — the long-lived bridge process enables it; plain
   *  library clients (tests, peer stubs) stay inert. */
  invites?: boolean;
  /** Tests pin a fast poll interval; production uses the 15s default. */
  invitePollMs?: number;
  /** Fired for every hub `error` frame (surfacing hook — see drainErrors). */
  onHubError?: (e: HubErrorEvent) => void;
}

interface PeerInfo extends WhoisInfo {
  xPub: Uint8Array;
}

export interface Identity {
  priv: Uint8Array;
  pub: Uint8Array;
  xpriv: Uint8Array;
  xpub: Uint8Array;
}

const INBOX_CAP = 100;
const ERRORS_CAP = 20;
const WAIT_MS = 5000;
const NOT_CONNECTED = 'not connected to the hub (reconnecting with backoff — retry in a moment)';
const INVITE_POLL_MS = 15_000;

/** Shareable host[:port] for connect lines: strip the ws(s):// scheme and
 *  the trailing /ws path from a full hub URL. */
const hostOf = (url: string): string => url.replace(/^wss?:\/\//, '').replace(/\/ws$/, '');

export function loadIdentity(keyPath: string): Identity {
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
  /** Agent id = sha256(ed25519 pub)[:16], derived from the CURRENT keys —
   *  retargeting with new keys IS a new agent. */
  get agentId(): string {
    return dap.agentIdOf(this.id.pub);
  }

  /** Hub `whois` requests issued — lets tests prove whois-before-DM. */
  whoisCalls = 0;
  lastError = '';
  private id: Identity;
  private opts: ClientOpts;
  private readonly watchdog: KeepAliveWatchdog;
  private readonly errorRing: HubErrorEvent[] = [];
  private readonly channels = new Map<string, ChannelKey>();
  private readonly joined = new Set<string>();
  private readonly inboxMsgs: MsgEvent[] = [];
  private readonly known = new Map<string, PeerInfo>();
  private readonly whoisWaiters = new Map<string, Array<(err?: Error, info?: PeerInfo) => void>>();
  hellos = 0;
  welcomes = 0;
  private readonly readyWaiters: Array<(err?: Error) => void> = [];
  private readonly presenceWaiters: Array<(err?: Error, agents?: PresenceAgent[]) => void> = [];
  private readonly joinWaiters = new Map<string, Array<(err?: Error) => void>>();
  private readonly listeners = new Set<(m: MsgEvent) => void>();
  private ws: WebSocket | null = null;
  private retryTimer: NodeJS.Timeout | undefined;
  private inviteTimer: NodeJS.Timeout | undefined;
  private readonly invitePollMs: number;
  /** Armed by-name invites (config.json `invites`); delivered + removed by
   *  the poller. */
  private readonly pendingInvites: PendingInvite[] = [];
  private deliveringInvites = false;
  private readonly initialMs: number;
  private readonly maxMs: number;
  private delay: number;
  private welcomed = false;
  private stopped = false;

  constructor(opts: ClientOpts) {
    this.opts = opts;
    this.id = loadIdentity(opts.keyPath);
    // File first, then explicit DAP_CHANNELS entries — explicit wins per the
    // settings precedence (config.ts).
    if (opts.channelsFile) {
      for (const [name, keys] of Object.entries(loadChannelKeys(opts.channelsFile))) {
        this.channels.set(name, { name, ...keys });
      }
    }
    for (const ch of opts.channels ?? []) this.channels.set(ch.name, ch);
    this.initialMs = opts.backoff?.initialMs ?? 1000;
    this.maxMs = opts.backoff?.maxMs ?? 30_000;
    this.delay = this.initialMs;
    this.watchdog = new KeepAliveWatchdog(DEFAULT_KEEP_ALIVE);
    this.invitePollMs = opts.invitePollMs ?? INVITE_POLL_MS;
    // Restart redelivery: pendings armed before shutdown load here and the
    // welcome-time check delivers them without waiting a tick.
    if (opts.invites) this.pendingInvites.push(...(readDapConfig().invites ?? []));
  }

  /** True while the welcome handshake is done on an open socket. */
  get connected(): boolean {
    return this.welcomed && this.ws?.readyState === WebSocket.OPEN;
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
    this.watchdog.stop();
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = undefined;
    clearInterval(this.inviteTimer);
    this.inviteTimer = undefined;
    this.ws?.close();
    this.ws = null;
  }

  /** Runtime retarget (dap_connect): stop timers/watchdog, close the socket,
   *  swap url and/or identity keys and display name, then connect fresh. A
   *  new name means a new identity (name-derived key file) — a new agentId. */
  retarget(next: { url?: string; keys?: Identity; name?: string }): void {
    clearTimeout(this.retryTimer);
    this.retryTimer = undefined;
    this.watchdog.stop();
    if (this.ws) {
      this.ws.removeAllListeners(); // the dying socket must not trigger reconnect
      this.ws.on('error', () => {}); // 'close' always follows; swallow errors
      this.ws.close();
      this.ws = null;
    }
    this.failWaiters(new Error('retargeted — in-flight hub call dropped, retry on the new connection'));
    this.welcomed = false;
    this.stopped = false; // connect() again after the implicit stop
    if (next.url) this.opts.url = next.url;
    if (next.keys) this.id = next.keys;
    if (next.name !== undefined) this.opts.name = next.name;
    this.known.clear(); // other hub and/or other identity: registry cache is stale
    this.joined.clear(); // hub membership dies with the connection
    this.delay = this.initialMs;
    this.connect();
  }

  /** Fail every waiter parked on a deliberately-killed connection (retarget,
   *  terminal stop): fail-fast beats a 5s timeout drift for calls in flight. */
  private failWaiters(err: Error): void {
    for (const resolves of this.whoisWaiters.values()) for (const done of resolves) done(err);
    this.whoisWaiters.clear();
    for (const done of this.presenceWaiters.splice(0)) done(err);
    for (const wake of this.readyWaiters.splice(0)) wake(err);
  }

  /** Resolve once `welcome` arrived (bounded — rejects on timeout). */
  ready(timeoutMs = WAIT_MS): Promise<void> {
    if (this.welcomed && this.ws?.readyState === WebSocket.OPEN) return Promise.resolve();
    const { promise, resolve, reject } = Promise.withResolvers<void>();
    const wake = (err?: Error) => { clearTimeout(timer); if (err) reject(err); else resolve(); };
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

  /** Channels the hub confirmed we joined on this connection. */
  get joinedChannels(): string[] {
    return [...this.joined];
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
   *  Creation is zero-config: fresh keypair persisted to the channels file
   *  (read-modify-write, keeps the other channels).
   *  ponytail: on a name collision the hub keeps the ORIGINAL channel pubkey
   *  and ours is ignored — the creator effectively owns the channel (v1). */
  async ensureChannel(name: string): Promise<ChannelKey & { created: boolean }> {
    const known = this.channels.get(name);
    if (known) {
      await this.join(name, known.pub);
      return { ...known, created: false };
    }
    const ch = this.ensureChannelKeys(name);
    await this.join(name, ch.pub); // first join registers the channel pubkey
    return { ...ch, created: true };
  }

  /** Register a channel zero-config: keygen when unknown, persist to the
   *  channels file (read-modify-write), keep in memory — joined on the next
   *  welcome (every known channel auto-joins after each handshake). */
  ensureChannelKeys(name: string): ChannelKey {
    const known = this.channels.get(name);
    if (known) return known;
    const kp = dap.newX25519Keypair();
    const keys = { pub: dap.b64e(kp.pub), priv: dap.b64e(kp.priv) };
    const ch: ChannelKey = { name, ...keys };
    this.channels.set(name, ch);
    if (this.opts.channelsFile) persistChannelKeys(this.opts.channelsFile, name, keys);
    return ch;
  }

  /** Send an E2E-encrypted message to a channel (creates it on first use). */
  async send(channel: string, text: string): Promise<SendResult> {
    if (!this.connected) throw new Error(NOT_CONNECTED);
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
    if (!this.connected) throw new Error(NOT_CONNECTED);
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

  /** Invite an agent to a channel: DMs them the channel keypair inside a
   *  normal E2E DM (the plaintext happens to be JSON, see channels.ts).
   *  Creates the channel zero-config when unknown; pub-only membership
   *  (out-of-band pubkey, no priv) cannot invite — that needs a member. */
  async invite(channel: string, to: string): Promise<SendResult> {
    const ch = await this.ensureChannel(channel);
    if (!ch.priv) throw new Error(`no private key for channel ${channel} — ask a member to invite you`);
    const payload = JSON.stringify({ t: 'chankey', channel, pub: ch.pub, priv: ch.priv });
    const res = await this.dm(to, payload);
    const out: SendResult = { ...res, channel, chanPubkey: ch.pub };
    if (ch.created) out.created = true;
    return out;
  }

  /** dap_invite target resolution (shared contract): a 16-hex id DMs the
   *  chankey now; a name resolves case-insensitively via presence — exactly
   *  one ONLINE match DMs now, several matches fail as ambiguous, and an
   *  unknown or offline name arms a pending invite delivered when that name
   *  comes online. */
  async inviteByName(channel: string, who: string): Promise<SendResult | ArmedInvite> {
    if (!this.connected) throw new Error(NOT_CONNECTED);
    if (/^[0-9a-f]{16}$/.test(who)) return this.invite(channel, who);
    const wanted = who.toLowerCase();
    const matches = (await this.presence()).filter((a) => a.name?.toLowerCase() === wanted);
    if (matches.length === 1 && matches[0].online) return this.invite(channel, matches[0].agentId);
    if (matches.length > 1) {
      throw new Error(`"${who}" is ambiguous — use an id: ${matches.map((m) => m.agentId).join(', ')}`);
    }
    return this.armInvite(who, channel);
  }

  /** Arm a pending by-name invite: create the channel under our key (the
   *  zero-config path — keygen, persist, join now) and remember {name,
   *  channel}, deduped case-insensitively on (name, channel). */
  private async armInvite(name: string, channel: string): Promise<ArmedInvite> {
    await this.ensureChannel(channel);
    if (!this.pendingInvites.some((p) => p.name.toLowerCase() === name.toLowerCase() && p.channel === channel)) {
      this.pendingInvites.push({ name, channel });
      persistDapConfig({ invites: [...this.pendingInvites] });
    }
    this.pollPendingInvites(); // arm-time check: the name may be online already
    return {
      ok: true,
      pending: true,
      name,
      channel,
      connectLine: `send to ${name}:  /dap ${hostOf(this.opts.url)} ${name}`,
    };
  }

  /** Start (once) the pending-invite poller and check immediately: pendings
   *  armed before a restart deliver without waiting a tick. */
  private startInvitePoller(): void {
    if (this.inviteTimer === undefined) {
      this.inviteTimer = setInterval(() => this.pollPendingInvites(), this.invitePollMs);
    }
    this.pollPendingInvites();
  }

  private pollPendingInvites(): void {
    void this.deliverPendingInvites().catch((err: unknown) => this.surfaceInviteFailure(err));
  }

  /** One delivery pass (poller tick + arm/welcome-time check): a single
   *  presence snapshot, every pending with exactly one online name-match
   *  gets its chankey DM. Own agentId is excluded — the config file is
   *  machine-shared, so our own name must never match. Per-invite failures
   *  keep the entry for the next tick. */
  private async deliverPendingInvites(): Promise<void> {
    if (this.deliveringInvites || this.pendingInvites.length === 0 || !this.connected) return;
    this.deliveringInvites = true;
    try {
      const agents = await this.presence();
      for (let i = this.pendingInvites.length - 1; i >= 0; i--) {
        const pending = this.pendingInvites[i]!;
        const online = agents.filter(
          (a) => a.online && a.agentId !== this.agentId && a.name?.toLowerCase() === pending.name.toLowerCase(),
        );
        if (online.length !== 1) continue; // still away (or ambiguous): keep waiting
        try {
          await this.invite(pending.channel, online[0].agentId);
        } catch {
          continue; // hub rejected the frame — retried on the next tick
        }
        this.pendingInvites.splice(i, 1);
        persistDapConfig({ invites: [...this.pendingInvites] });
        this.deliver({
          dm: false,
          channel: pending.channel,
          invite: pending.channel,
          from: this.agentId,
          text: `[dap] invited ${pending.name} to #${pending.channel}`,
          ts: Date.now(),
        });
      }
    } finally {
      this.deliveringInvites = false;
    }
  }

  /** Check-level failures are never silent: error ring (drained by
   *  dap_inbox) + the onHubError hook, like every other hub verdict. */
  private surfaceInviteFailure(err: unknown): void {
    const msg = `pending invite check failed: ${err instanceof Error ? err.message : String(err)}`;
    this.lastError = msg;
    this.ringError({ code: 'invite_failed', msg, ts: Date.now() });
  }

  /** Pubkey directory lookup (needed for DM key agreement). */
  async whois(agentId: string): Promise<WhoisInfo> {
    const { xPub: _internal, ...out } = await this.agentInfo(agentId);
    return out;
  }

  /** Snapshot of this client's connection state (the MCP `dap_status` tool). */
  status(): StatusInfo {
    return {
      connected: this.connected,
      agentId: this.agentId,
      name: this.opts.name,
      url: this.opts.url,
      channels: [...this.channels.keys()],
      welcomes: this.welcomes,
      hellos: this.hellos,
    };
  }

  /** Hub presence list (the MCP `dap_peers` tool): every agent in the
   *  registry with online/lastSeen. Bounded wait, like whois. */
  async presence(): Promise<PresenceAgent[]> {
    if (!this.connected) throw new Error(NOT_CONNECTED);
    const { promise, resolve, reject } = Promise.withResolvers<PresenceAgent[]>();
    const done = (err?: Error, agents?: PresenceAgent[]) => {
      clearTimeout(timer);
      if (err) reject(err); else resolve(agents ?? []);
    };
    const timer = setTimeout(() => {
      const i = this.presenceWaiters.indexOf(done);
      if (i >= 0) this.presenceWaiters.splice(i, 1);
      reject(new Error('timeout waiting for presence'));
    }, WAIT_MS);
    this.presenceWaiters.push(done);
    try {
      this.sendFrame({ op: 'presence_query' });
    } catch (err) {
      const i = this.presenceWaiters.indexOf(done);
      if (i >= 0) this.presenceWaiters.splice(i, 1);
      done(err as Error);
    }
    return promise;
  }

  /** Drain the decrypted inbox (pull-mode inbound — the MCP `dap_inbox` tool). */
  drainInbox(): MsgEvent[] {
    return this.inboxMsgs.splice(0);
  }

  /** Drain observed hub `error` frames (surfaced via `dap_inbox` too). */
  drainErrors(): HubErrorEvent[] {
    return this.errorRing.splice(0);
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
    this.ws.on('open', () => {
      this.watchdog.start(this.ws!); // refresh while idle; terminate a dead conn
      this.sendHello();
    });
    this.ws.on('message', (data) => this.handleRaw(String(data)));
    this.ws.on('close', () => this.onDisconnect());
    this.ws.on('error', (err) => { this.lastError = String(err); }); // close always follows
  }

  private sendHello(): void {
    this.hellos++;
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
      case 'presence': this.onPresence(frame); break;
      case 'msg': void this.onMsg(frame); break;
      case 'error': this.onError(frame); break;
      default: break; // flushed: nothing to do
    }
  }

  private onWelcome(): void {
    this.welcomed = true;
    this.welcomes++;
    this.delay = this.initialMs; // backoff resets after a successful welcome
    this.joined.clear(); // hub membership is in-memory: re-join on demand
    this.ws?.send(JSON.stringify({ op: 'flush' })); // drain offline mailbox
    for (const wake of this.readyWaiters.splice(0)) wake();
    // Membership: join every known channel after each welcome (idempotent;
    // reconnect-safe — the hub's live membership dies with the connection).
    // Join failures surface via the error ring / onHubError, never silently.
    for (const [name, ch] of this.channels) void this.join(name, ch.pub).catch(() => {});
    if (this.opts.invites) this.startInvitePoller(); // restart redelivery
  }

  private onJoined(channel: string): void {
    this.joined.add(channel);
    for (const done of this.joinWaiters.get(channel) ?? []) done();
    this.joinWaiters.delete(channel);
  }

  /** A presence frame either answers our `presence_query` (full registry
   *  snapshot) or broadcasts a peer's online/offline to channel-mates —
   *  both carry the same shape, so both resolve pending waiters. */
  private onPresence(frame: dap.Frame): void {
    const agents = (Array.isArray(frame.agents) ? frame.agents : []).map((a) => {
      const e = a as Record<string, unknown>;
      return {
        agentId: String(e.agentId),
        name: e.name as string | undefined,
        online: e.online as boolean | undefined,
        lastSeen: e.lastSeen as number | undefined,
      };
    });
    for (const done of this.presenceWaiters.splice(0)) done(undefined, agents);
  }

  /** Hub verdicts are never silent: bounded ring (drained by dap_inbox) +
   *  the onHubError hook — one path for every observed failure. */
  private ringError(event: HubErrorEvent): void {
    this.errorRing.push(event);
    if (this.errorRing.length > ERRORS_CAP) this.errorRing.shift();
    this.opts.onHubError?.(event);
  }

  private onError(frame: dap.Frame): void {
    this.lastError = `hub error ${frame.code}: ${frame.msg}`;
    this.ringError({ code: String(frame.code), msg: String(frame.msg), ts: Date.now() });
    if (frame.code === 'unknown_channel' || frame.code === 'access_denied') {
      const err = new Error(this.lastError);
      for (const done of this.joinWaiters.get(String(frame.channel)) ?? []) done(err);
      this.joinWaiters.delete(String(frame.channel));
    }
    if (frame.code === 'unknown_agent') {
      for (const [agentId, resolves] of this.whoisWaiters) for (const done of resolves) {
        done(new Error(`unknown_agent: ${agentId}`));
      }
      this.whoisWaiters.clear();
    }
  }

  private onDisconnect(): void {
    this.watchdog.stop();
    this.welcomed = false;
    if (this.stopped) {
      // Terminal stop: nothing will reconnect — fail parked waiters now.
      this.failWaiters(new Error('connection closed — client stopped'));
      return;
    }
    // Transient drop: waiters ride the reconnect (bounded by their own
    // timeouts) and the welcome resolves them — the reconnect contract.
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
    for (const done of this.whoisWaiters.get(agentId) ?? []) done(undefined, info);
    this.whoisWaiters.delete(agentId);
  }

  private agentInfo(agentId: string): Promise<PeerInfo> {
    const cached = this.known.get(agentId);
    if (cached) return Promise.resolve(cached);
    const { promise, resolve, reject } = Promise.withResolvers<PeerInfo>();
    const timer = setTimeout(() => reject(new Error(`timeout whois ${agentId}`)), WAIT_MS);
    const done = (err?: Error, info?: PeerInfo) => {
      clearTimeout(timer);
      if (err) reject(err);
      else if (info) resolve(info);
    };
    const list = this.whoisWaiters.get(agentId) ?? [];
    list.push(done);
    this.whoisWaiters.set(agentId, list);
    this.whoisCalls++;
    this.ws?.send(JSON.stringify({ op: 'whois', agentId }));
    return promise;
  }

  private async onMsg(frame: dap.Frame): Promise<void> {
    try {
      const ev = await this.decryptMsg(frame);
      // A DM carrying a channel keypair is an invite, not chat: persist the
      // keys, join, surface a notice. Trust model: possession of the channel
      // private key IS v1 membership; the introducer is whoever DM'd us
      // (same trust as manually sharing the channels file).
      const invite = ev.dm ? parseChankeyInvite(ev.text) : undefined;
      if (invite) {
        const keys = { name: invite.channel, pub: invite.pub, priv: invite.priv };
        this.channels.set(invite.channel, keys);
        if (this.opts.channelsFile) {
          persistChannelKeys(this.opts.channelsFile, invite.channel, { pub: invite.pub, priv: invite.priv });
        }
        void this.join(invite.channel, invite.pub).catch(() => {}); // failure -> error ring
        this.deliver({ ...ev, invite: invite.channel, text: `[dap] invited to #${invite.channel} by ${ev.from}` });
        return;
      }
      this.deliver(ev);
    } catch (err) {
      const msg = `undecryptable msg: ${err instanceof Error ? err.message : String(err)}`;
      this.lastError = msg;
      // Never silent — same surfacing as hub verdicts (drained by dap_inbox).
      const event: HubErrorEvent = { code: 'undecryptable', msg, ts: Date.now() };
      if (frame.from !== undefined) event.from = String(frame.from);
      if (frame.id !== undefined) event.id = String(frame.id);
      this.ringError(event);
    }
  }

  /** One inbound message -> bounded inbox + every listener. */
  private deliver(ev: MsgEvent): void {
    this.inboxMsgs.push(ev);
    if (this.inboxMsgs.length > INBOX_CAP) this.inboxMsgs.shift();
    for (const cb of this.listeners) cb(ev);
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