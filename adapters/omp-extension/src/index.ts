import { loadOrCreateKeys, x25519, b64, unb64, type KeyPair } from './crypto.ts';
import { DapClient, type Backoff, type Timers } from './conn.ts';
import { Inbox, type InboxEntry } from './inbox.ts';
import {
  encryptForChannel,
  encryptForDM,
  decryptInbound,
  type PayloadCryptoContext,
} from './codec.ts';
import { resolveDapSettings, optStr, defaultKeyPath, persistDapConfig } from './config.ts';
import {
  loadChannelKeys,
  persistChannelKeys,
  newChannelKeypair,
  type ChannelKeys,
} from './channels.ts';
import type { AgentToolResult, ExtensionAPI, SessionCtx } from './types.ts';

export interface ExtensionOptions {
  /** Test/config overrides; otherwise env (DAP_HUB_URL / DAP_KEY_PATH /
   *  DAP_AGENT_NAME / DAP_CHANNELS_FILE) > ~/.dap/config.json > defaults. */
  url?: string;
  keyPath?: string;
  name?: string;
  channelsFile?: string;
  channels?: Record<string, string>;
  channelPrivs?: Record<string, string>;
  backoff?: Partial<Backoff>;
  timers?: Timers;
}

export interface DapExtension {
  client: DapClient;
  inbox: Inbox;
  dispose(): void;
}

const str = (v: unknown): string => {
  if (typeof v !== 'string' || v.length === 0) throw new Error('expected non-empty string');
  return v;
};

/** Real omp pi has no timers: DapClient's own default is the raw-timer
 *  fallback (with a throw-safe callback body — see conn.ts). */
const toolResult = (result: unknown): AgentToolResult => ({
  content: [{ type: 'text', text: JSON.stringify(result) }],
  details: result,
});

/** Injection text: enough context for the steered turn to answer in-channel. */
function formatEntry(entry: InboxEntry, peerName: string): string {
  const where = entry.channel ? '#' + entry.channel : 'DM';
  return `[dap] ${where} from ${peerName}: ${entry.text}`;
}

/** Channels file -> cryptoCtx maps (pub for sending, priv for decrypting). */
function channelsFromFile(file: string): { channels: Record<string, string>; channelPrivs: Record<string, string> } {
  const channels: Record<string, string> = {};
  const channelPrivs: Record<string, string> = {};
  for (const [name, keys] of Object.entries(loadChannelKeys(file))) {
    channels[name] = keys.pub;
    channelPrivs[name] = keys.priv;
  }
  return { channels, channelPrivs };
}

/** A DM whose decrypted text is exactly a channel-invite payload. */
function parseChankeyInvite(text: string): { channel: string; pub: string; priv: string } | undefined {
  if (text.charCodeAt(0) !== 0x7b) return undefined; // not JSON — regular chat
  try {
    const v = JSON.parse(text) as { t?: unknown; channel?: unknown; pub?: unknown; priv?: unknown };
    if (v.t !== 'chankey') return undefined;
    if (typeof v.channel !== 'string' || typeof v.pub !== 'string' || typeof v.priv !== 'string') {
      return undefined;
    }
    if (unb64(v.pub).length !== 32 || unb64(v.priv).length !== 32) return undefined;
    return { channel: v.channel, pub: v.pub, priv: v.priv };
  } catch {
    return undefined;
  }
}

/**
 * oh-my-pi DAP/1 extension. Default-export factory:
 * registers dap_send/dap_dm/dap_invite/dap_inbox/dap_whois tools, keeps one
 * outbound WS to the hub (signed hello, flush after welcome, setInterval
 * reconnect), and delivers inbound msg frames as steer injections + durable
 * inbox entries. Channel keys auto-generate on first send and persist to
 * ~/.dap/channels.json; invites travel as E2E DMs (see dap_invite).
 */
export default function dapExtension(ctx: ExtensionAPI, overrides: ExtensionOptions = {}): DapExtension {
  const settings = resolveDapSettings(overrides);
  let keys: KeyPair = loadOrCreateKeys(settings.keyPath);

  const client = new DapClient({
    url: settings.url,
    keys,
    name: settings.name,
    backoff: overrides.backoff,
    timers: overrides.timers,
  });
  const agentId = client.agentId; // available synchronously — no await needed
  ctx.setLabel('DAP — distributed agents');
  // Persistent connection line in the omp footer (visible without asking):
  // DAP <name|id> · <host> · <state> · #chan1,#chan2. ui reference is
  // captured at session_start; setStatus is a no-op in headless modes and
  // a fire-and-forget request in RPC — safe to call from any event.
  let ui: SessionCtx['ui'] | undefined;
  const renderStatus = (state: string): void => {
    const who = settings.name ?? agentId;
    const host = settings.url.replace(/^wss?:\/\//, '').replace(/\/ws$/, '');
    const chans = Object.keys(cryptoCtx.channels)
      .map((c) => '#' + c)
      .join(',');
    ui?.setStatus?.('dap', `DAP ${who} · ${host} · ${state}${chans ? ' · ' + chans : ''}`);
  };
  ctx.on('session_start', (_event, sctx) => {
    ui = sctx.ui;
    if (sctx.hasUI && sctx.ui) {
      sctx.ui.notify(`DAP connected as ${agentId}${settings.name ? ` (${settings.name})` : ''}`, 'info');
    }
    renderStatus(client.connected ? 'connected' : 'connecting…');
  });
  const inbox = new Inbox(100, (entry) => ctx.appendEntry('io.dap.message', entry));
  // Explicit channel maps (tests) opt out of the channels-file lifecycle;
  // otherwise keys live in settings.channelsFile (default ~/.dap/channels.json).
  const useChannelFile = !(overrides.channels || overrides.channelPrivs);
  const fromFile = useChannelFile ? channelsFromFile(settings.channelsFile) : null;
  const cryptoCtx: PayloadCryptoContext = {
    keys,
    selfAgentId: client.agentId,
    channels: overrides.channels ?? fromFile?.channels ?? {},
    channelPrivs: overrides.channelPrivs ?? fromFile?.channelPrivs ?? {},
    peerXPub: async (agentId) => (await client.whois(agentId))?.x25519,
  };

  /** Zero-config channel creation: the first user generates the keypair,
   *  persists it (read-modify-write, keeps other channels) and joins —
   *  creating the channel. */
  const createChannel = (channel: string): ChannelKeys => {
    const created = newChannelKeypair();
    cryptoCtx.channels[channel] = created.pub;
    cryptoCtx.channelPrivs[channel] = created.priv;
    if (useChannelFile) persistChannelKeys(settings.channelsFile, channel, created);
    client.join(channel, created.pub);
    return created;
  };

  /** Full keypair for inviting: create the channel zero-config when its
   *  private key isn't held; derive pub from priv when only priv is known. */
  const channelKeysFor = (channel: string): ChannelKeys => {
    const priv = cryptoCtx.channelPrivs[channel];
    if (!priv) return createChannel(channel);
    return { pub: cryptoCtx.channels[channel] ?? b64(x25519.getPublicKey(unb64(priv))), priv };
  };

  // Trust model: possession of the channel private key IS v1 membership; the
  // introducer is whoever DM'd you (same trust as manually sharing the file).
  const acceptInvite = (invite: { channel: string; pub: string; priv: string }, from: string): void => {
    cryptoCtx.channels[invite.channel] = invite.pub;
    cryptoCtx.channelPrivs[invite.channel] = invite.priv;
    if (useChannelFile) persistChannelKeys(settings.channelsFile, invite.channel, invite);
    client.join(invite.channel, invite.pub);
    ctx.sendMessage(`[dap] invited to #${invite.channel} by ${from}`, { deliverAs: 'steer', triggerTurn: true });
  };

  client.onMessage = (frame) =>    decryptInbound(frame, cryptoCtx)
      .then((payload) => {
        const invite = payload.dm ? parseChankeyInvite(payload.text) : undefined;
        if (invite) {
          acceptInvite(invite, frame.from); // not chat: no inbox entry, just the notice
          return;
        }
        const entry = inbox.add({
          id: frame.id,
          ts: frame.ts,
          from: frame.from,
          channel: payload.channel,
          dm: payload.dm,
          text: payload.text,
        });
        // Steer + triggerTurn: steers the live turn AND starts one when the
        // agent is idle — without triggerTurn an idle agent shows nothing.
        ctx.sendMessage(formatEntry(entry, frame.from), { deliverAs: 'steer', triggerTurn: true });
      })
      .catch((err: unknown) =>
        ctx.appendEntry('io.dap.undecryptable', { type: 'dap_undecryptable', id: frame.id, error: String(err) }),
      );

  // Membership: join every configured channel after each welcome (idempotent;
  // first join ever creates the channel and registers its public key).
  client.on('welcome', () => {
    for (const [name, pub] of Object.entries(cryptoCtx.channels)) client.join(name, pub);
    renderStatus('connected');
  });

  client.on('close', () => renderStatus('reconnecting…'));

  // Hub rejections (unknown_agent, access_denied, replay, …) must never be
  // silent: the sending tool already returned ok (it only proves the frame
  // was signed and put on the wire) — the verdict arrives here.
  client.on('error', (f) => {
    const code = typeof f === 'object' && f !== null && 'code' in f ? String(f.code) : 'error';
    const msg = typeof f === 'object' && f !== null && 'msg' in f ? String(f.msg) : JSON.stringify(f);
    ctx.appendEntry('io.dap.error', { code, msg });
    ctx.sendMessage(`[dap] hub rejected a frame — ${code}: ${msg}`, {
      deliverAs: 'steer',
      triggerTurn: true,
    });
  });

  /** Honest failure: never report ok for a frame that left nothing —
   * sends while disconnected are dropped silently by the socket layer. */
  const requireConnected = (): { ok: false; error: string } | undefined =>
    client.connected ? undefined : { ok: false, error: 'not connected to the hub (reconnecting with backoff — retry in a moment)' };

  ctx.registerTool({
    name: 'dap_send',
    description: 'Send an end-to-end-encrypted message to a DAP channel.',
    parameters: {
      type: 'object',
      properties: {
        channel: { type: 'string', description: 'Channel name, e.g. general' },
        text: { type: 'string', description: 'Message text' },
      },
      required: ['channel', 'text'],
    },
    execute: async (_toolCallId, params) => {
      const down = requireConnected();
      if (down) return toolResult(down);
      const channel = str(params.channel);
      // Unknown channel -> zero-config keygen + persist + join (spec § join:
      // senders only need the channel public key).
      if (!cryptoCtx.channels[channel]) cryptoCtx.channels[channel] = createChannel(channel).pub;
      const frameId = crypto.randomUUID();
      const ciphertext = await encryptForChannel(str(params.text), channel, frameId, cryptoCtx);
      const ts = client.signedSend({ channel, id: frameId, ciphertext });
      return toolResult({ ok: true, channel, id: frameId, ts });
    },
  });

  ctx.registerTool({
    name: 'dap_dm',
    description: 'Send an end-to-end-encrypted direct message to another agent (by agentId).',
    parameters: {
      type: 'object',
      properties: {
        to: { type: 'string', description: 'Recipient agentId' },
        text: { type: 'string', description: 'Message text' },
      },
      required: ['to', 'text'],
    },
    execute: async (_toolCallId, params) => {
      const down = requireConnected();
      if (down) return toolResult(down);
      const to = str(params.to);
      const frameId = crypto.randomUUID();
      const ciphertext = await encryptForDM(str(params.text), to, frameId, cryptoCtx);
      const ts = client.signedSend({ to, id: frameId, ciphertext });
      return toolResult({ ok: true, to, id: frameId, ts });
    },
  });

  ctx.registerTool({
    name: 'dap_invite',
    description: 'Invite another agent to a channel: DMs them the channel keypair (normal E2E DM encryption; the text payload happens to be JSON).',
    parameters: {
      type: 'object',
      properties: {
        channel: { type: 'string', description: 'Channel name, e.g. general' },
        to: { type: 'string', description: 'Recipient agentId' },
      },
      required: ['channel', 'to'],
    },
    execute: async (_toolCallId, params) => {
      const down = requireConnected();
      if (down) return toolResult(down);
      const channel = str(params.channel);
      const to = str(params.to);
      const keys = channelKeysFor(channel);
      const frameId = crypto.randomUUID();
      const payload = JSON.stringify({ t: 'chankey', channel, pub: keys.pub, priv: keys.priv });
      const ciphertext = await encryptForDM(payload, to, frameId, cryptoCtx);
      const ts = client.signedSend({ to, id: frameId, ciphertext });
      return toolResult({ ok: true, channel, to, id: frameId, ts });
    },
  });

  ctx.registerTool({
    name: 'dap_inbox',
    description: 'List recent DAP messages delivered to this agent (durable inbox).',
    parameters: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Max entries (default 20)' },
        channel: { type: 'string', description: 'Filter to one channel' },
      },
    },
    execute: async (_toolCallId, params) =>
      toolResult({
        count: inbox.size,
        entries: inbox.list(
          typeof params.limit === 'number' ? params.limit : 20,
          optStr(params.channel),
        ),
      }),
  });

  ctx.registerTool({
    name: 'dap_whois',
    description: 'Look up another agent (pubkey, display name, online) by agentId. Ids are 16-hex — discover them via dap_peers, never names.',
    parameters: {
      type: 'object',
      properties: { agentId: { type: 'string' } },
      required: ['agentId'],
    },
    execute: async (_toolCallId, params) => {
      const info = await client.whois(str(params.agentId));
      return toolResult(info ?? { error: 'unknown_agent' });
    },
  });

  ctx.registerTool({
    name: 'dap_status',
    description: 'Own DAP connection status: are we connected to the hub, our agentId, name, hub url, known channels.',
    parameters: { type: 'object', properties: {} },
    execute: async () =>
      toolResult({
        connected: client.connected,
        agentId,
        name: settings.name,
        url: settings.url,
        channels: Object.keys(cryptoCtx.channels),
        welcomes: client.welcomeCount,
        hellos: client.helloCount,
      }),
  });

  ctx.registerTool({
    name: 'dap_peers',
    description: 'Agents on the hub, ONLINE ONLY by default (id, name, lastSeen). Discover agentIds here — they are 16-hex ids, never names. Set includeOffline:true to also list offline agents (their DMs queue to the hub mailbox).',
    parameters: {
      type: 'object',
      properties: { includeOffline: { type: 'boolean', description: 'Also list offline agents (default false)' } },
    },
    execute: async (_toolCallId, params) => {
      const all = await client.presence();
      const agents = params.includeOffline === true ? all : all.filter((a) => a.online);
      return toolResult({ agents });
    },
  });

  /** dap_connect: manual invitation to any DAP server — host, optional
   *  name (a new name = a new identity: name-derived key file), optional
   *  default room (persisted; auto-joined on every later launch). */
  const configFile = optStr(process.env.DAP_CONFIG_FILE);
  const normalizeHost = (h: string): string => {
    const withScheme = /^wss?:\/\//.test(h) ? h : 'ws://' + h;
    const u = new URL(withScheme);
    return u.toString().replace(/\/$/, '');
  };
  const connectTo = (host?: string, name?: string, channel?: string) => {
    const url = host ? normalizeHost(host) : settings.url;
    let nextKeys: KeyPair | undefined;
    if (name) {
      settings.name = name;
      nextKeys = loadOrCreateKeys(defaultKeyPath(name));
      keys = nextKeys;
      cryptoCtx.keys = nextKeys;
    }
    if (host) settings.url = url;
    persistDapConfig({ url: host ? url : undefined, name, channels: channel ? [channel] : undefined }, configFile);
    if (channel && !cryptoCtx.channels[channel]) cryptoCtx.channels[channel] = createChannel(channel).pub;
    client.retarget({ url: host ? url : undefined, keys: nextKeys, name });
    renderStatus('connecting…');
    return { ok: true, url: settings.url, name: settings.name ?? client.agentId, agentId: client.agentId, channels: Object.keys(cryptoCtx.channels) };
  };
  ctx.registerTool({
    name: 'dap_connect',
    description: "Connect to any DAP hub at runtime (a manual invitation): host (hub.example.com, hub:8787, or ws(s)://…), optional name (display name AND identity — same name = same agent everywhere), optional channel (default room, joined after connect and on every later launch; persisted to ~/.dap/config.json). NOTE: if the room already exists on that hub under another member's key, ask a member to dap_invite you — otherwise you can post but members cannot read you.",
    parameters: {
      type: 'object',
      properties: {
        host: { type: 'string', description: 'hub host[:port] or ws(s):// URL' },
        name: { type: 'string', description: 'agent name (new identity)' },
        channel: { type: 'string', description: 'default room to join after connect' },
      },
    },
    execute: async (_toolCallId, params) => {
      const host = optStr(params.host);
      const name = optStr(params.name);
      const channel = optStr(params.channel);
      if (!host && !name) return toolResult({ ok: false, error: 'host or name required' });
      return toolResult(connectTo(host, name, channel));
    },
  });
  ctx.registerCommand?.('dap', {
    description: '/dap <host[:port]|ws(s)://…> [name] [channel] — connect to a DAP hub',
    handler: (args: string) => {
      const [host, name, channel] = args.trim().split(/\s+/).filter(Boolean);
      if (!host) return `current: ${settings.url}${settings.name ? ' as ' + settings.name : ''}`;
      return JSON.stringify(connectTo(optStr(host), optStr(name), optStr(channel)));
    },
  });
  const dispose = (): void => client.stop();
  // Clean exit: closing the socket lets the hub deregister immediately
  // (identity + mailbox survive for offline DMs).
  ctx.on('session_shutdown', dispose);
  client.connect();
  return { client, inbox, dispose };
}
