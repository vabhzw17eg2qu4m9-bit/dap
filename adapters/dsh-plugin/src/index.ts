// deepseek-harness (Cordis) plugin for the Distributed Agents Platform.
// Default-exported Cordis plugin: apply(ctx, config) registers dap_* tools and
// wakes the idle agent (Agent.followup) on every inbound E2E-encrypted message.
// Zero-config: settings resolve as config arg > DAP_* env > ~/.dap/config.json
// > defaults (see config.ts); channel keys live in the shared channels file.
import { DapClient, type ChannelKey, type MsgEvent } from './client.js';
import { resolveDapSettings } from './config.js';

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
}

const S = (v: unknown): string => String(v);

export default {
  name: 'dsh-dap',
  apply(ctx: DshContext, config: DapPluginConfig = {}) {
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
      onMessage: announce,
      onInvite: (invite, from) => {
        ctx.agent?.followup(`[dap] invited to #${invite.channel} by ${from}`);
      },
      onHubError: (e) => {
        ctx.logger?.warn(`[dap] hub rejected a frame — ${e.code}: ${e.msg}`);
        ctx.agent?.followup(`[dap] hub rejected a frame — ${e.code}: ${e.msg}`);
      },
    });
    client.start();

    /** Honest failure: never report ok for a frame that went nowhere —
     *  sends while disconnected never reach the wire. */
    const requireConnected = (): { ok: false; error: string } | undefined =>
      client.connected ? undefined : { ok: false, error: 'not connected to the hub (reconnecting with backoff — retry in a moment)' };

    ctx.tools.register({
      name: 'dap_send',
      description: 'Send an end-to-end-encrypted message to a DAP channel',
      inputSchema: {
        type: 'object',
        properties: { channel: { type: 'string' }, text: { type: 'string' } },
        required: ['channel', 'text'],
      },
      execute: async (a) => {
        const down = requireConnected();
        if (down) return down;
        return client.send(S(a.channel), S(a.text));
      },
    });
    ctx.tools.register({
      name: 'dap_dm',
      description: 'Send an end-to-end-encrypted direct message to another agent',
      inputSchema: {
        type: 'object',
        properties: { to: { type: 'string' }, text: { type: 'string' } },
        required: ['to', 'text'],
      },
      execute: async (a) => {
        const down = requireConnected();
        if (down) return down;
        return client.dm(S(a.to), S(a.text));
      },
    });
    ctx.tools.register({
      name: 'dap_invite',
      description: 'Invite another agent to a channel: DMs them the channel keypair (normal E2E DM; the payload happens to be JSON)',
      inputSchema: {
        type: 'object',
        properties: { channel: { type: 'string' }, to: { type: 'string' } },
        required: ['channel', 'to'],
      },
      execute: async (a) => {
        const down = requireConnected();
        if (down) return down;
        return client.invite(S(a.to), S(a.channel));
      },
    });
    ctx.tools.register({
      name: 'dap_inbox',
      description: 'List the most recent decrypted DAP messages (channel + DM) plus recent hub error frames',
      inputSchema: { type: 'object', properties: {} },
      execute: async () => ({ messages: client.inbox(), errors: client.drainErrors() }),
    });
    ctx.tools.register({
      name: 'dap_whois',
      description: 'Look up an agent by DAP agentId — agentId is the 16-hex DAP id; discover ids via dap_peers, not names',
      inputSchema: {
        type: 'object',
        properties: { agentId: { type: 'string' } },
        required: ['agentId'],
      },
      execute: (a) => client.whois(S(a.agentId)),
    });
    ctx.tools.register({
      name: 'dap_status',
      description: 'Connection state of this agent\'s DAP hub link: agentId, url, known channels, welcome/hello counters',
      inputSchema: { type: 'object', properties: {} },
      execute: async () => client.status(),
    });
    ctx.tools.register({
      name: 'dap_peers',
      description: 'List agents visible on the DAP hub (presence): agentId, name, online, lastSeen',
      inputSchema: { type: 'object', properties: {} },
      execute: async () => {
        const down = requireConnected();
        if (down) return down;
        return { agents: await client.presence() };
      },
    });

    ctx.on?.('dispose', () => client.stop());
    return client;
  },
};
