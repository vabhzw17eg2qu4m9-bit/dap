// deepseek-harness (Cordis) plugin for the Distributed Agents Platform.
// Default-exported Cordis plugin: apply(ctx, config) registers dap_* tools and
// wakes the idle agent (Agent.followup) on every inbound E2E-encrypted message.
import { DapClient, defaultKeyPath, type ChannelKey, type MsgEvent } from './client.js';

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
  /** Hub WS endpoint, e.g. ws://hub:8080/ws (env fallback DAP_HUB_URL). */
  url?: string;
  /** Ed25519 identity key file, created 0600 if absent (DAP_KEY_PATH). */
  keyPath?: string;
  /** Display name (DAP_AGENT_NAME). */
  name?: string;
  /** Channel keypairs (pub = hub-side key, priv = out-of-band member key). */
  channels?: ChannelKey[];
  backoff?: { initialMs?: number; maxMs?: number };
}

const S = (v: unknown): string => String(v);

export default {
  name: 'dsh-dap',
  apply(ctx: DshContext, config: DapPluginConfig = {}) {
    const url = config.url ?? process.env.DAP_HUB_URL;
    if (!url) throw new Error('dsh-dap: config.url (or DAP_HUB_URL) is required');
    const keyPath = config.keyPath ?? process.env.DAP_KEY_PATH ?? defaultKeyPath();
    const name = config.name ?? process.env.DAP_AGENT_NAME;

    const announce = (m: MsgEvent): void => {
      const where = m.dm ? 'dm' : m.channel;
      ctx.agent?.followup(`[dap:${where}] ${m.from}: ${m.text}`);
    };
    // Hub rejections (unknown_agent, access_denied, replay, …) must never be
    // silent: the sending tool already returned — the verdict arrives here.
    const client = new DapClient({
      url,
      keyPath,
      name,
      channels: config.channels,
      backoff: config.backoff,
      onMessage: announce,
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
      name: 'dap_inbox',
      description: 'List the most recent decrypted DAP messages (channel + DM) plus recent hub error frames',
      inputSchema: { type: 'object', properties: {} },
      execute: async () => ({ messages: client.inbox(), errors: client.drainErrors() }),
    });
    ctx.tools.register({
      name: 'dap_whois',
      description: 'Look up an agent by DAP agentId',
      inputSchema: {
        type: 'object',
        properties: { agentId: { type: 'string' } },
        required: ['agentId'],
      },
      execute: (a) => client.whois(S(a.agentId)),
    });

    ctx.on?.('dispose', () => client.stop());
    return client;
  },
};
