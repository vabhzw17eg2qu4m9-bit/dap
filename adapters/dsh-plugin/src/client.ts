// DAP/1 outbound WS client: hello/welcome handshake, signed sends, flush after
// welcome, capped-backoff reconnect, inbound msg decryption, on-disk identity
// (Ed25519 for signing + dedicated X25519 for E2E, per protocol addendum).
// Zero-config channels: keys live in the channels file (default
// ~/.dap/channels.json, shared across adapters); the first sender keygens,
// joins happen after every welcome, and chankey DM invites are accepted
// in-band (possession of the channel private key IS v1 membership).
import { existsSync, readFileSync, writeFileSync, chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomUUID, randomBytes } from 'node:crypto';
import WebSocket from 'ws';
import * as dap from './crypto.js';
import { loadChannelKeys, persistChannelKeys, newChannelKeypair, parseChankeyInvite, type ChankeyInvite } from './channels.js';
import { persistDapConfig, optStr } from './config.js';
import { DEFAULT_KEEP_ALIVE, KeepAliveWatchdog } from './keepalive.js';

/** A hub `error` frame observed on the wire (unknown_agent, access_denied, …). */
export interface HubErrorEvent {
  code: string;
  msg: string;
  ts: number;
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
}

/** One entry of a hub `presence` frame (spec § presence). */
export interface PresenceAgent {
  agentId: string;
  name?: string;
  online: boolean;
  lastSeen: number;
  /** True on the requesting agent's own entry (client-side marking). */
  self: boolean;
}

export interface ClientOpts {
  url: string;
  keyPath: string;
  name?: string;
  /** Explicit channel list (pub for sending, priv for decrypting) — opts out
   *  of the channels-file lifecycle entirely. */
  channels?: ChannelKey[];
  /** Channels file (zero-config mode): loaded at startup, auto-joined after
   *  every welcome, auto-keygen'd on first send, updated on invites. */
  channelsFile?: string;
  backoff?: { initialMs?: number; maxMs?: number };
  onMessage?: (m: MsgEvent) => void;
  onReady?: (agentId: string) => void;
  /** Fired for every hub `error` frame (surfacing hook — see drainErrors). */
  onHubError?: (e: HubErrorEvent) => void;
  /** Fired when an inbound DM carried a chankey invite: keys already
   *  persisted and the channel joined by then; not an inbox message. */
  onInvite?: (invite: ChankeyInvite, from: string) => void;
  /** Persisted enrollment secret (config file). DAP_CLIENT_SECRET env
   *  overrides it at dial time; DAP_MASTER_SECRET (env) turns the dial
   *  into an enrollment connection instead. */
  clientSecret?: string;
  /** Fired once the hub accepted a master-secret enrollment and the issued
   *  client secret was persisted; the secret itself is never passed or logged. */
  onEnrolled?: () => void;
}

const INBOX_CAP = 100;
const ERRORS_CAP = 20;
const READY_TIMEOUT_MS = 5000;
const NOT_CONNECTED = 'not connected to the hub (reconnecting with backoff — retry in a moment)';
/** Frozen adapter-contract text for an HTTP 401 upgrade rejection
 *  (identical across adapters). */
export const AUTH_REQUIRED =
  'hub rejected connection (HTTP 401): set DAP_MASTER_SECRET to enroll, or DAP_CLIENT_SECRET / config clientSecret to connect';

/** Where a dial's bearer token came from — the 401 escalation fires only for
 *  config-cached secrets (env = explicit user intent, never wiped). */
type AuthSource = 'env' | 'config' | 'master';

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
  /** Identity follows the key file: agentId is derived from the Ed25519
   *  pubkey, so retargeting onto a new key file yields a new agentId. */
  get agentId(): string {
    return dap.agentIdOf(this.id.edPub);
  }
  private id: Identity;
  private readonly opts: ClientOpts;
  private readonly watchdog: KeepAliveWatchdog;
  private readonly errorRing: HubErrorEvent[] = [];
  private readonly channels = new Map<string, ChannelKey>();
  private readonly initialMs: number;
  private readonly maxMs: number;
  private readonly inboxMsgs: MsgEvent[] = [];
  private readonly known = new Map<string, AgentInfo>();
  /** This socket dialled with the master secret: enroll after welcome. */
  private enrollMode = false;
  /** Source of the current dial's bearer token: the 401 escalation (stale
   *  config-cache recovery) fires only for config-sourced secrets. */
  private dialSource: AuthSource | undefined;
  /** 401 escalation latch: at most ONE stale-cache re-enroll per client —
   *  the second 401 is fatal with the frozen hint. */
  private reEnrolled = false;
  private ws: WebSocket | null = null;
  private readonly whoisWaiters = new Map<string, ((info: AgentInfo | undefined, err?: Error) => void)[]>();
  private readonly readyWaiters: (() => void)[] = [];
  /** True when channel keys persist to opts.channelsFile (no explicit list). */
  private readonly useChannelFile: boolean;
  private retryTimer: NodeJS.Timeout | null = null;
  private delay: number;
  private welcomed = false;
  private stopped = false;
  /** hello frames sent (connection attempts) / welcome frames received. */
  hellos = 0;
  welcomes = 0;
  /** Parked presence() resolvers by request frame id (spec § presence). */
  private readonly presenceWaiters = new Map<string, (f: dap.Frame) => void>();
  /** Sticky client-lifetime echo latch: once a replyTo-carrying presence
   *  answer is seen, the hub is echo-capable and id-less presence frames are
   *  broadcasts — they must never complete waiters (BUG 5). Never reset on
   *  reconnect: the every-other-restart race is exactly what this closes. */
  private echoSeen = false;
  lastError = '';

  constructor(opts: ClientOpts) {
    this.opts = opts;
    this.id = loadIdentity(opts.keyPath);
    for (const ch of opts.channels ?? []) this.channels.set(ch.name, ch);
    // Zero-config mode: pick the shared channels file up on startup — every
    // key there is auto-joined after each welcome (reconnect-safe).
    this.useChannelFile = !opts.channels && !!opts.channelsFile;
    if (this.useChannelFile) {
      for (const [name, keys] of Object.entries(loadChannelKeys(opts.channelsFile!))) {
        this.channels.set(name, { name, ...keys });
      }
    }
    this.initialMs = opts.backoff?.initialMs ?? 1000;
    this.maxMs = opts.backoff?.maxMs ?? 30_000;
    this.delay = this.initialMs;
    this.watchdog = new KeepAliveWatchdog(DEFAULT_KEEP_ALIVE);
  }

  /** True while the welcome handshake is done on an open socket. */
  get connected(): boolean {
    return this.welcomed && this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }

  start(): void {
    this.stopped = false;
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    this.failWhoisWaiters('whois: client stopped'); // the close guard below skips onDisconnect for a retired socket
    this.watchdog.stop();
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.ws?.close();
    this.ws = null;
  }

  /** Runtime retarget (dap_connect): stop everything, swap url and/or
   *  identity key file and display name, then connect fresh. A new name
   * means a new identity (name-derived key file) — a different agentId. */
  retarget(next: { url?: string; keyPath?: string; name?: string }): void {
    clearTimeout(this.retryTimer ?? undefined); // no-op when nothing is pending
    this.retryTimer = null;
    this.watchdog.stop();
    this.ws?.close(); // retiring socket: late events are ignored (see connect)
    this.ws = null;
    this.welcomed = false;
    this.stopped = false; // connect() again after the implicit stop
    this.failWhoisWaiters('whois: retargeted — the retired socket can never answer');
    if (next.url) this.opts.url = next.url;
    if (next.keyPath) this.id = loadIdentity(next.keyPath);
    this.known.clear(); // other hub and/or other identity: registry cache is stale
    if (next.name !== undefined) this.opts.name = next.name;
    this.delay = this.initialMs;
    this.connect();
  }

  /** Hub `error` frames observed since the last drain. */
  drainErrors(): HubErrorEvent[] {
    return this.errorRing.splice(0);
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

  /** Self-reported connection state (identity, link, known channels, counters). */
  status(): { connected: boolean; agentId: string; name: string; url: string; channels: string[]; welcomes: number; hellos: number } {
    return {
      connected: this.connected,
      agentId: this.agentId,
      name: this.opts.name ?? '',
      url: this.opts.url,
      channels: [...this.channels.keys()],
      welcomes: this.welcomes,
      hellos: this.hellos,
    };
  }

  /** Online-only presence list from the hub (spec § presence): offline
   *  entries never surface, the requester's own entry stays in with
   *  `self: true`. The query carries a per-request id; only the answer
   *  echoing it (replyTo) completes the wait — bounded, like whois. */
  async presence(): Promise<PresenceAgent[]> {
    if (!this.connected) throw new Error(NOT_CONNECTED);
    const frame = await this.queryPresence(randomUUID());
    const agents = Array.isArray(frame.agents) ? (frame.agents as Record<string, unknown>[]) : [];
    return agents
      .filter((a) => Boolean(a.online))
      .map((a) => ({
        agentId: String(a.agentId),
        name: a.name === undefined ? undefined : String(a.name),
        online: true,
        lastSeen: Number(a.lastSeen),
        self: String(a.agentId) === this.agentId,
      }));
  }

  /** One id-carrying presence query, completed only by its replyTo echo
   *  (bounded — the legacy one-completes-all path can also complete it). */
  private queryPresence(id: string): Promise<dap.Frame> {
    const { promise, resolve, reject } = Promise.withResolvers<dap.Frame>();
    const timer = setTimeout(() => {
      if (this.presenceWaiters.get(id) === resolve) this.presenceWaiters.delete(id);
      reject(new Error('presence: hub did not reply'));
    }, READY_TIMEOUT_MS);
    this.presenceWaiters.set(id, resolve);
    this.ws?.send(JSON.stringify({ op: 'presence_query', id }));
    return promise.finally(() => clearTimeout(timer));
  }

  /** Welcome-time warm-up (BUG 5): a throwaway id-carrying presence query
   *  whose replyTo echo arms the sticky latch BEFORE the first user query —
   *  closing the window where a legacy/unsolicited id-less roster frame
   *  completes it one-completes-all. Legacy hubs answer without replyTo:
   *  the latch stays unarmed and presence() keeps its back-compat path.
   *  Reconnect re-runs it (cheap); echoSeen stays client-lifetime. Hot-path
   *  tradeoff: an extra round trip per connection, off the user's latency. */
  private warmUpEcho(): void {
    void (async () => {
      for (let attempt = 0; attempt < 3 && !this.echoSeen; attempt++) {
        if (!this.connected) return; // socket died mid-warm-up: reconnect re-runs it
        try {
          await this.queryPresence(randomUUID()); // result discarded
        } catch {
          // never-echoing hub: retry bounded, then stay on the legacy path
        }
      }
    })();
  }

  /** Send an E2E-encrypted message to a channel. Unknown channel = zero-config
   *  creation: keygen, persist (read-modify-write), join — then the send. */
  async send(channel: string, text: string): Promise<void> {
    if (!this.connected) throw new Error(NOT_CONNECTED);
    const ch = this.channels.get(channel) ?? this.createChannel(channel);
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
    if (!this.connected) throw new Error(NOT_CONNECTED);
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

  /** Invite another agent to a channel: DM them the keypair inside a normal
   *  E2E DM (the plaintext happens to be JSON — the hub sees only ciphertext). */
  async invite(to: string, channel: string): Promise<void> {
    if (!this.connected) throw new Error(NOT_CONNECTED);
    const ch = this.channels.get(channel);
    // No private key held (unknown or pub-only channel) -> fresh keypair via
    // zero-config creation; otherwise reuse the member keypair verbatim.
    const keys = ch?.priv ? { pub: ch.pub, priv: ch.priv } : this.createChannel(channel);
    await this.dm(to, JSON.stringify({ t: 'chankey', channel, pub: keys.pub, priv: keys.priv }));
  }

  /** Channel membership (spec § join): first join creates the channel and
   *  registers chanPubkey; re-join is idempotent — safe after every welcome. */
  join(channel: string, chanPubkeyB64: string): void {
    this.ws?.send(JSON.stringify({ op: 'join', channel, chanPubkey: chanPubkeyB64 }));
  }

  /** dap_connect default room: make sure the channel is known — zero-config
   *  keygen + persist when it is not; joins land after the next welcome. */
  ensureChannel(channel: string): ChannelKey {
    return this.channels.get(channel) ?? this.createChannel(channel);
  }

  /** Zero-config channel creation: the first user generates the keypair,
   *  persists it (keeping the other channels) and joins — creating it. */
  private createChannel(channel: string): ChannelKey {
    const keys = newChannelKeypair();
    const entry: ChannelKey = { name: channel, pub: keys.pub, priv: keys.priv };
    this.channels.set(channel, entry);
    if (this.useChannelFile) persistChannelKeys(this.opts.channelsFile!, channel, keys);
    this.join(channel, keys.pub);
    return entry;
  }

  /** Trust model: possession of the channel private key IS v1 membership; the
   *  introducer is whoever DM'd you (same trust as manually sharing the file). */
  private acceptInvite(invite: ChankeyInvite): void {
    this.channels.set(invite.channel, { name: invite.channel, pub: invite.pub, priv: invite.priv });
    if (this.useChannelFile) persistChannelKeys(this.opts.channelsFile!, invite.channel, { pub: invite.pub, priv: invite.priv });
    this.join(invite.channel, invite.pub);
  }

  private signAndSend(frame: dap.Frame): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) throw new Error('not connected');
    frame.sig = dap.signFrame(frame, this.id.edPriv);
    this.ws.send(JSON.stringify(frame));
  }

  /** Dial token per the enrollment contract: DAP_CLIENT_SECRET env >
   *  config clientSecret (opts, issued by a previous enrollment) >
   *  DAP_MASTER_SECRET env (marks the dial enroll-mode). Empty token dials
   *  headerless — the hub answers 401. `source` says which branch won, so
   *  the 401 path can decide on recovery. */
  private dialAuth(): { token: string; enroll: boolean; source: AuthSource | undefined } {
    const env = optStr(process.env.DAP_CLIENT_SECRET);
    if (env) return { token: env, enroll: false, source: 'env' };
    const persisted = optStr(this.opts.clientSecret);
    if (persisted) return { token: persisted, enroll: false, source: 'config' };
    const master = optStr(process.env.DAP_MASTER_SECRET);
    return master ? { token: master, enroll: true, source: 'master' } : { token: '', enroll: false, source: undefined };
  }

  private connect(): void {
    if (this.stopped) return;
    const { token, enroll, source } = this.dialAuth();
    this.enrollMode = enroll;
    this.dialSource = source;
    const ws = new WebSocket(this.opts.url, token ? { headers: { authorization: `Bearer ${token}` } } : undefined);
    this.ws = ws;
    // Socket-identity guards: a socket retired by stop()/retarget() must not
    // act on late events — a stray close would arm a phantom reconnect.
    ws.on('open', () => {
      if (this.ws !== ws) return;
      this.watchdog.start(ws); // refresh while idle; terminate a dead conn
      this.sendHello();
    });
    ws.on('message', (data) => {
      if (this.ws === ws) this.handleRaw(String(data));
    });
    ws.on('close', () => {
      if (this.ws === ws) this.onDisconnect();
    });
    // Post-open socket errors only: a dial-phase 401 already owns lastError
    // (the terminate in unexpected-response fires a late generic error that
    // must not clobber it).
    ws.on('error', (err) => {
      if (this.ws !== ws) return; // stale socket: retired by stop()/retarget()
      if (ws.readyState !== WebSocket.OPEN) return;
      this.lastError = String(err);
    }); // close always follows
    ws.on('unexpected-response', (_req, res) => {
      if (this.ws !== ws) return; // stale socket: retired by stop()/retarget()
      if (res.statusCode !== 401) return;
      this.lastError = AUTH_REQUIRED;
      this.surfaceError('unauthorized', AUTH_REQUIRED);
      // Stale config-cache recovery (e.g. a hub restart wiped the
      // server-side secrets): once, when the rejected secret came from the
      // persisted cache AND a master secret is available, purge the cache
      // (disk + the in-memory copy — the scheduled reconnect re-dials in
      // enroll-mode and `enrolled` persists the new secret). Env-provided
      // secrets are explicit user intent — never wiped; keys and agentId
      // are untouched either way.
      if (this.dialSource === 'config' && !this.reEnrolled && optStr(process.env.DAP_MASTER_SECRET)) {
        this.reEnrolled = true;
        this.opts.clientSecret = undefined;
        persistDapConfig({ clientSecret: null });
      }
      ws.terminate(); // close (and the reconnect backoff) always follows
    });
  }

  private sendHello(): void {
    this.hellos++;
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
    if (frame.t === 'enrolled') return this.onEnrolled(String(frame.secret));
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
        this.onHubErrorFrame(frame);
        break;
      case 'presence':
        this.resolvePresence(frame);
        break;
      default:
        break; // flushed: nothing to do
    }
  }

  /** Hub rejections are never silent: recorded, hooked, and any pending
   *  whois they answer fails fast instead of hanging forever. */
  private onHubErrorFrame(frame: dap.Frame): void {
    this.lastError = `hub error ${frame.code}: ${frame.msg}`;
    this.surfaceError(String(frame.code), String(frame.msg));
    if (frame.code === 'unknown_agent') {
      for (const resolves of this.whoisWaiters.values()) for (const r of resolves) r(undefined);
      this.whoisWaiters.clear();
    }
  }

  /** One surfaced hub-side failure: bounded ring (drained by dap_inbox) + host hook. */
  private surfaceError(code: string, msg: string): void {
    const event: HubErrorEvent = { code, msg, ts: Date.now() };
    this.errorRing.push(event);
    if (this.errorRing.length > ERRORS_CAP) this.errorRing.shift();
    this.opts.onHubError?.(event);
  }

  private onWelcome(): void {
    this.welcomed = true;
    this.welcomes++;
    this.delay = this.initialMs; // backoff resets after a successful welcome
    if (this.enrollMode) this.ws?.send(JSON.stringify({ t: 'enroll' })); // master-authed conn: enrollment rides it
    this.ws?.send(JSON.stringify({ op: 'flush' }));
    // Membership: join every known channel after each welcome (idempotent;
    // the first join ever creates the channel and registers its pubkey).
    for (const ch of this.channels.values()) this.join(ch.name, ch.pub);
    this.warmUpEcho(); // arm the echo latch before any user query (first-query steal window)
    for (const wake of this.readyWaiters.splice(0)) wake();
    this.opts.onReady?.(this.agentId);
  }

  /** Hub accepted the master-secret enrollment: adopt the issued client
   *  secret for every future dial (memory + config file, DAP_CONFIG_FILE
   *  aware). The connection stays open — it is already master-authed. */
  private onEnrolled(secret: string): void {
    if (!secret) return;
    this.opts.clientSecret = secret;
    this.enrollMode = false; // later dials authenticate as a client
    persistDapConfig({ clientSecret: secret });
    this.opts.onEnrolled?.();
  }

  private onDisconnect(): void {
    this.watchdog.stop();
    this.welcomed = false;
    this.failWhoisWaiters('whois: hub connection closed');
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
    const { promise, resolve, reject } = Promise.withResolvers<AgentInfo | undefined>();
    const list = this.whoisWaiters.get(agentId) ?? [];
    const done = (info?: AgentInfo, err?: Error): void => {
      clearTimeout(timer);
      if (err) reject(err);
      else resolve(info);
    };
    const timer = setTimeout(() => {
      const i = list.indexOf(done);
      if (i >= 0) list.splice(i, 1);
      reject(new Error(`whois ${agentId}: hub did not reply`));
    }, READY_TIMEOUT_MS);
    list.push(done);
    this.whoisWaiters.set(agentId, list);
    this.ws?.send(JSON.stringify({ op: 'whois', agentId }));
    return promise.then((info) => {
      if (!info) throw new Error(`unknown_agent: ${agentId}`);
      return info;
    });
  }

  /** Route an inbound presence frame to its waiters (spec § presence): an
   *  answer echoing OUR request id completes only that query — a stale or
   *  foreign echo matches nobody. A legacy answer carries no replyTo and is
   *  wire-indistinguishable from a broadcast push, so — until the hub has
   *  proven it echoes — it completes every pending query one-completes-all.
   *
   *  // ponytail: sticky latch, Dart fah_hub_client 0.2.1 parity — armed =
   *  hub is echo-capable, so id-less frames are broadcasts and get dropped
   *  (this adapter keeps no roster cache to serve them from). */
  private resolvePresence(frame: dap.Frame): void {
    const rid = typeof frame.replyTo === 'string' ? frame.replyTo : '';
    if (rid) {
      this.echoSeen = true; // any echo — even a stale one — proves the hub echoes
      const resolve = this.presenceWaiters.get(rid);
      if (!resolve) return;
      this.presenceWaiters.delete(rid);
      resolve(frame);
      return;
    }
    if (this.echoSeen) return; // echo-capable hub: id-less frame = unsolicited broadcast
    for (const resolve of [...this.presenceWaiters.values()]) resolve(frame);
    this.presenceWaiters.clear();
  }

  /** Pending whois never outlives its socket: close/retarget/stop fail every
   *  waiter so dm()/whois() error out instead of hanging on a retired socket. */
  private failWhoisWaiters(reason: string): void {
    if (this.whoisWaiters.size === 0) return;
    const err = new Error(reason);
    for (const resolves of this.whoisWaiters.values()) for (const r of resolves) r(undefined, err);
    this.whoisWaiters.clear();
  }

  private async onMsg(frame: dap.Frame): Promise<void> {
    try {
      const ev = await this.decryptMsg(frame);
      const invite = ev.dm ? parseChankeyInvite(ev.text) : undefined;
      if (invite) {
        // Not chat: persist + join, then surface a short notice — no inbox.
        this.acceptInvite(invite);
        this.opts.onInvite?.(invite, ev.from);
        return;
      }
      this.inboxMsgs.push(ev);
      if (this.inboxMsgs.length > INBOX_CAP) this.inboxMsgs.shift();
      this.opts.onMessage?.(ev);
    } catch (err) {
      this.lastError = `undecryptable msg: ${String(err)}`;
      this.surfaceError('undecryptable', String(err)); // ring + hook: visible via dap_inbox
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
