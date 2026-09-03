// deepseek-harness (Cordis) plugin for the Distributed Agents Platform.
// Default-exported Cordis plugin: apply(ctx, config) registers dap_* tools and
// wakes the idle agent (Agent.followup) on every inbound E2E-encrypted message.
// Zero-config: settings resolve as config arg > DAP_* env > ~/.dap/config.json
// > defaults (see config.ts); channel keys live in the shared channels file.
import { DapClient, type ChannelKey, type MsgEvent } from './client.js';
import { resolveDapSettings, optStr, defaultKeyPath, persistDapConfig, readDapConfig, type PendingInvite } from './config.js';

export interface DapToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  execute: (args: Record<string, unknown>) => Promise<unknown>;
}

/** Minimal Cordis context surface this plugin consumes. */
export interface DshContext {
  tools: { register: (def: DapToolDef) => unknown };
  agent?: { followup: (text: string) => unknown };
  on?: (event: 'dispose', cb: () => void) => unknown;
  logger?: { warn: (msg: string) => void };
}

export interface DapPluginConfig {
  /** Hub WS endpoint (env DAP_HUB_URL; default ws://127.0.0.1:8787/ws). */
  url?: string;
  /** Ed25519 identity key file, created 0600 if absent (DAP_KEY_PATH;
   *  default ~/.dap/keys/dsh/<name|hostname>.key). */
  keyPath?: string;
  /** Display name (DAP_AGENT_NAME). */
  name?: string;
  /** Channel keypairs file, shared across adapters (DAP_CHANNELS_FILE;
   *  default ~/.dap/channels.json). Ignored when `channels` is given. */
  channelsFile?: string;
  /** Explicit channel keypairs — opts out of the channels-file lifecycle. */
  channels?: ChannelKey[];
  backoff?: { initialMs?: number; maxMs?: number };
  /** Pending-invite presence poll interval (default 15s; tests shrink it). */
  invitePollMs?: number;
 }
 
/** Hub host[:port] for the paste-ready connect line: scheme and the trailing
 *  /ws path stripped from a full hub URL. */
const hostOf = (url: string): string => url.replace(/^wss?:\/\//, '').replace(/\/ws$/, '');

const S = (v: unknown): string => String(v);
/** Frozen adapter-contract enrollment notice (never carries the secret). */
const ENROLL_NOTICE = 'enrolled: client secret persisted';

/** Frozen inactive notice (master-secret gate): the ONE answer every tool
 *  gives while DAP_MASTER_SECRET is unset or empty. */
const DISABLED_ERROR = 'DAP_MASTER_SECRET is not set — DAP disabled';

/** Tool contracts (name/description/schema) — the single source of truth for
 *  the dap_* surface, registered identically whether the plugin is active or
 *  gated off; only the execute differs. */
const TOOL_SHELLS: Record<string, Omit<DapToolDef, 'execute'>> = {
  dap_send: {
    name: 'dap_send',
    description: 'Send an end-to-end-encrypted message to a DAP channel',
    inputSchema: {
      type: 'object',
      properties: { channel: { type: 'string' }, text: { type: 'string' } },
      required: ['channel', 'text'],
    },
  },
  dap_dm: {
    name: 'dap_dm',
    description: 'Send an end-to-end-encrypted direct message to another agent',
    inputSchema: {
      type: 'object',
      properties: { to: { type: 'string' }, text: { type: 'string' } },
      required: ['to', 'text'],
    },
  },
  dap_invite: {
    name: 'dap_invite',
    description:
      'Invite another agent to a channel: DMs them the channel keypair (normal E2E DM; the payload happens to be JSON). `to` may be a 16-hex agentId or a display name — a name that is unknown or offline arms a pending invite and returns the paste-ready connect line; the chankey DM fires automatically when that name comes online.',
    inputSchema: {
      type: 'object',
      properties: {
        to: { type: 'string', description: '16-hex agentId or display name' },
        channel: { type: 'string', description: 'channel to invite to (default general)' },
      },
      required: ['to'],
    },
  },
  dap_inbox: {
    name: 'dap_inbox',
    description: 'List the most recent decrypted DAP messages (channel + DM) plus recent hub error frames',
    inputSchema: { type: 'object', properties: {} },
  },
  dap_whois: {
    name: 'dap_whois',
    description: 'Look up an agent by DAP agentId — agentId is the 16-hex DAP id; discover ids via dap_peers, not names',
    inputSchema: {
      type: 'object',
      properties: { agentId: { type: 'string' } },
      required: ['agentId'],
    },
  },
  dap_status: {
    name: 'dap_status',
    description: 'Connection state of this agent\'s DAP hub link: agentId, url, known channels, welcome/hello counters',
    inputSchema: { type: 'object', properties: {} },
  },
  dap_peers: {
    name: 'dap_peers',
    description: 'Online agents on the hub (agentId, name, online, lastSeen): online peers only. Your own entry is included and marked self:true; every other entry is self:false.',
    inputSchema: { type: 'object', properties: {} },
  },
  dap_connect: {
    name: 'dap_connect',
    description: "Connect to any DAP hub at runtime (a manual invitation): host (hub.example.com, hub:8787, or ws(s)://…), optional name (display name AND identity — same name = same agent everywhere), optional channel (default room, joined after connect and on every later launch; persisted to ~/.dap/config.json). NOTE: if the room already exists on that hub under another member's key, ask a member to dap_invite you — otherwise you can post but members cannot read you.",
    inputSchema: {
      type: 'object',
      properties: {
        host: { type: 'string', description: 'hub host[:port] or ws(s):// URL' },
        name: { type: 'string', description: 'agent name (new identity)' },
        channel: { type: 'string', description: 'default room to join after connect' },
      },
    },
  },
};

export default {
  name: 'dsh-dap',
  apply(ctx: DshContext, config: DapPluginConfig = {}) {
    // Master-secret gate: with DAP_MASTER_SECRET unset or empty the plugin
    // does nothing and shows nothing — no client, no WebSocket dial, no
    // reconnect loop, no keepalive watchdog, no invite poller, no output.
    // The tool shells still register so an invocation gets the one honest
    // error instead of an unknown-tool silence.
    if (!optStr(process.env.DAP_MASTER_SECRET)) {
      for (const shell of Object.values(TOOL_SHELLS)) {
        ctx.tools.register({ ...shell, execute: async () => ({ ok: false, error: DISABLED_ERROR }) });
      }
      return;
    }
    const settings = resolveDapSettings(config);
    const { name } = settings;

    const announce = (m: MsgEvent): void => {
      const where = m.dm ? 'dm' : m.channel;
      ctx.agent?.followup(`[dap:${where}] ${m.from}: ${m.text}`);
    };
    // Hub rejections (unknown_agent, access_denied, replay, …) must never be
    // silent: the sending tool already returned — the verdict arrives here.
    const client = new DapClient({
      url: settings.url,
      keyPath: settings.keyPath,
      name,
      channels: config.channels,
      channelsFile: config.channels ? undefined : settings.channelsFile,
      backoff: config.backoff,
      clientSecret: settings.clientSecret,
      onReady: () => pollPending(), // welcome/reconnect: redeliver pendings without waiting a tick
      onMessage: announce,
      onInvite: (invite, from) => {
        ctx.agent?.followup(`[dap] invited to #${invite.channel} by ${from}`);
      },
      onHubError: (e) => {
        ctx.logger?.warn(`[dap] hub rejected a frame — ${e.code}: ${e.msg}`);
        ctx.agent?.followup(`[dap] hub rejected a frame — ${e.code}: ${e.msg}`);
      },
      onEnrolled: () => {
        ctx.logger?.warn(ENROLL_NOTICE);
        ctx.agent?.followup(ENROLL_NOTICE);
      },
    });
    client.start();

    /** Honest failure: never report ok for a frame that went nowhere —
     *  sends while disconnected never reach the wire. */
    const requireConnected = (): { ok: false; error: string } | undefined =>
      client.connected ? undefined : { ok: false, error: 'not connected to the hub (reconnecting with backoff — retry in a moment)' };

    /** Pending by-name invites: dap_invite against a user not yet on the hub.
     *  The chankey DM fires automatically once the name appears online;
     *  entries survive restarts in ~/.dap/config.json (DAP_CONFIG_FILE in
     *  tests). Shared-config hazard: own agentId is always excluded. */
    const configFile = optStr(process.env.DAP_CONFIG_FILE);
    const pendingInvites: PendingInvite[] = readDapConfig(configFile).invites ?? [];
    const persistInvites = (): void => persistDapConfig({ invites: [...pendingInvites] }, configFile);
    /** Shared delivery engine (poller tick + arm/welcome-time checks): one
     *  presence snapshot, every matching pending gets its chankey DM. Never
     *  throws — it runs inside timers. */
    let delivering = false;
    const deliverPending = async (): Promise<void> => {
      if (delivering || pendingInvites.length === 0 || !client.connected) return;
      delivering = true;
      try {
        const agents = await client.presence();
        for (let i = pendingInvites.length - 1; i >= 0; i--) {
          const pending = pendingInvites[i];
          const online = agents.filter((x) => x.agentId !== client.agentId && x.name?.toLowerCase() === pending.name.toLowerCase());
          if (online.length !== 1) continue; // still away (or ambiguous): keep waiting
          try {
            await client.invite(online[0].agentId, pending.channel);
          } catch {
            continue; // hub error already surfaced via onHubError; retried on the next tick
          }
          pendingInvites.splice(i, 1);
          persistInvites();
          ctx.agent?.followup(`[dap] invited ${pending.name} to #${pending.channel}`);
        }
      } finally {
        delivering = false;
      }
    };
    const pollPending = (): void => {
      void deliverPending().catch((err: unknown) => {
        const msg = `pending invite check failed: ${String(err)}`;
        ctx.logger?.warn(`[dap] ${msg}`);
        ctx.agent?.followup(`[dap] ${msg}`);
      });
    };
    const poller = setInterval(pollPending, config.invitePollMs ?? 15_000);

    ctx.tools.register({
      ...TOOL_SHELLS.dap_send,
      execute: async (a) => {
        const down = requireConnected();
        if (down) return down;
        return client.send(S(a.channel), S(a.text));
      },
    });
    ctx.tools.register({
      ...TOOL_SHELLS.dap_dm,
      execute: async (a) => {
        const down = requireConnected();
        if (down) return down;
        return client.dm(S(a.to), S(a.text));
      },
    });
    ctx.tools.register({
      ...TOOL_SHELLS.dap_invite,
      execute: async (a) => {
        const down = requireConnected();
        if (down) return down;
        const who = S(a.to);
        const channel = optStr(a.channel) ?? 'general';
        try {
          if (/^[0-9a-f]{16}$/.test(who)) return void (await client.invite(who, channel));
          const agents = await client.presence();
          const matches = agents.filter((x) => x.name?.toLowerCase() === who.toLowerCase());
          if (matches.length === 1) return void (await client.invite(matches[0].agentId, channel));
          if (matches.length > 1)
            return { ok: false, error: `"${who}" is ambiguous — use an id: ${matches.map((m) => m.agentId).join(', ')}` };
          // Unknown or offline name: not an error — arm now, deliver on arrival.
          client.ensureChannel(channel);
          if (!pendingInvites.some((p) => p.name.toLowerCase() === who.toLowerCase() && p.channel === channel)) {
            pendingInvites.push({ name: who, channel });
            persistInvites();
          }
          pollPending(); // arm-time check: the name may have connected just now
          return {
            ok: true,
            pending: true,
            name: who,
            channel,
            connectLine: `send to ${who}:  /dap ${hostOf(settings.url)} ${who}`,
            hint: 'first connect needs DAP_MASTER_SECRET set (enrolls once, then stored)',
          };
        } catch (err) {
          return { ok: false, error: String(err) };
        }
      },
    });
    ctx.tools.register({
      ...TOOL_SHELLS.dap_inbox,
      execute: async () => ({ messages: client.inbox(), errors: client.drainErrors() }),
    });
    ctx.tools.register({
      ...TOOL_SHELLS.dap_whois,
      execute: (a) => client.whois(S(a.agentId)),
    });
    ctx.tools.register({
      ...TOOL_SHELLS.dap_status,
      execute: async () => client.status(),
    });
    ctx.tools.register({
      ...TOOL_SHELLS.dap_peers,
      execute: async () => {
        const down = requireConnected();
        if (down) return down;
        return { agents: await client.presence() };
      },
    });

  /** dap_connect: manual invitation to any DAP server — host, optional
   *  name (a new name = a new identity: name-derived key file), optional
   *  default room (persisted; auto-joined on every later launch). */
  const normalizeHost = (h: string): string => {
    const withScheme = /^wss?:\/\//.test(h) ? h : 'ws://' + h;
    const u = new URL(withScheme);
    if (u.pathname === '/') u.pathname = '/ws'; // bare host: default hub path
    return u.toString().replace(/\/$/, '');
  };
  const connectTo = (host?: string, name?: string, channel?: string) => {
    const url = host ? normalizeHost(host) : settings.url;
    if (name) settings.name = name;
    if (host) settings.url = url;
    persistDapConfig({ url: host ? url : undefined, name, channels: channel ? [channel] : undefined });
    if (channel) client.ensureChannel(channel);
    client.retarget({ url: host ? url : undefined, keyPath: name ? defaultKeyPath(name) : undefined, name });
    return {
      ok: true,
      url: settings.url,
      name: settings.name ?? client.agentId,
      agentId: client.agentId,
      channels: client.status().channels,
    };
  };
  ctx.tools.register({
    ...TOOL_SHELLS.dap_connect,
    execute: async (a) => {
      const host = optStr(a.host);
      const name = optStr(a.name);
      const channel = optStr(a.channel);
      if (!host && !name) return { ok: false, error: 'host or name required' };
      return connectTo(host, name, channel);
    },
  });

    ctx.on?.('dispose', () => {
      clearInterval(poller);
      client.stop();
    });
    return client;
  },
};
