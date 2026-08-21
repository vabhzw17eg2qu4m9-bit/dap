import os from 'node:os';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { loadOrCreateKeys, type KeyPair } from './crypto.ts';
import { DapClient, type Backoff, type Timers, type AgentInfo } from './conn.ts';
import { Inbox, type InboxEntry } from './inbox.ts';
import {
  encryptForChannel,
  encryptForDM,
  decryptInbound,
  type PayloadCryptoContext,
} from './codec.ts';
import type { ExtensionAPI } from './types.ts';

export interface ExtensionOptions {
  /** Test/config overrides; env DAP_HUB_URL / DAP_KEY_PATH / DAP_AGENT_NAME otherwise. */
  url?: string;
  keyPath?: string;
  name?: string;
  channels?: Record<string, string>;
  channelPrivs?: Record<string, string>;
  backoff?: Partial<Backoff>;
  timers?: Timers;
}

/** DAP_CHANNELS_FILE: JSON { "<channel>": { "pub": "<b64>", "priv": "<b64>" } }.
 * Members hold the channel private key (needed to decrypt); share the file
 * with every member. Only used when no override passed (omp loads with none). */
function channelsFromEnv(): { channels: Record<string, string>; channelPrivs: Record<string, string> } {
  const file = optStr(process.env.DAP_CHANNELS_FILE);
  if (!file) return { channels: {}, channelPrivs: {} };
  const raw: Record<string, { pub?: string; priv?: string }> = JSON.parse(readFileSync(file, 'utf8'));
  const channels: Record<string, string> = {};
  const channelPrivs: Record<string, string> = {};
  for (const [name, keys] of Object.entries(raw)) {
    if (keys.pub) channels[name] = keys.pub;
    if (keys.priv) channelPrivs[name] = keys.priv;
  }
  return { channels, channelPrivs };
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

const optStr = (v: unknown): string | undefined => (typeof v === 'string' && v.length > 0 ? v : undefined);

function resolveTimers(ctx: ExtensionAPI, overrides?: Timers): Timers {
  if (overrides) return overrides;
  if (typeof ctx.setInterval === 'function') {
    return {
      setInterval: (fn, ms) => ctx.setInterval!(fn, ms),
      clearInterval: (h) => ctx.clearInterval?.(h),
    };
  }
  return {
    setInterval: (fn, ms) => setInterval(fn, ms),
    clearInterval: (h) => clearInterval(h as NodeJS.Timeout),
  };
}

/** Injection text: enough context for the steered turn to answer in-channel. */
function formatEntry(entry: InboxEntry, peerName: string): string {
  const where = entry.channel ? '#' + entry.channel : 'DM';
  return `[dap] ${where} from ${peerName}: ${entry.text}`;
}

/**
 * oh-my-pi DAP/1 extension. Default-export factory:
 * registers dap_send/dap_dm/dap_inbox/dap_whois tools, keeps one outbound WS
 * to the hub (signed hello, flush after welcome, setInterval reconnect),
 * and delivers inbound msg frames as steer injections + durable inbox entries.
 */
export default function dapExtension(ctx: ExtensionAPI, overrides: ExtensionOptions = {}): DapExtension {
  const url = overrides.url ?? process.env.DAP_HUB_URL ?? 'ws://127.0.0.1:8787/ws';
  const keyPath =
    overrides.keyPath ?? process.env.DAP_KEY_PATH ?? path.join(os.homedir(), '.omp', 'dap-key.json');
  const name = overrides.name ?? optStr(process.env.DAP_AGENT_NAME);
  const keys: KeyPair = loadOrCreateKeys(keyPath);

  const client = new DapClient({ url, keys, name, backoff: overrides.backoff, timers: resolveTimers(ctx, overrides.timers) });
  const inbox = new Inbox(100, (entry) => ctx.appendEntry(entry));
  const envChannels = overrides.channels || overrides.channelPrivs ? null : channelsFromEnv();
  const cryptoCtx: PayloadCryptoContext = {
    keys,
    selfAgentId: client.agentId,
    channels: overrides.channels ?? envChannels?.channels ?? {},
    channelPrivs: overrides.channelPrivs ?? envChannels?.channelPrivs ?? {},
    peerXPub: async (agentId) => (await client.whois(agentId))?.x25519,
  };

  client.onMessage = (frame) =>
    decryptInbound(frame, cryptoCtx)
      .then((payload) => {
        const entry = inbox.add({
          id: frame.id,
          ts: frame.ts,
          from: frame.from,
          channel: payload.channel,
          dm: payload.dm,
          text: payload.text,
        });
        // Steer injection: wakes an idle turn and steers the live one.
        ctx.sendMessage(formatEntry(entry, frame.from), { type: 'steer' });
      })
      .catch((err: unknown) =>
        ctx.appendEntry({ type: 'dap_undecryptable', id: frame.id, error: String(err) }),
      );

  // Membership: join every configured channel after each welcome (idempotent;
  // first join ever creates the channel and registers its public key).
  client.on('welcome', () => {
    for (const [name, pub] of Object.entries(cryptoCtx.channels)) client.join(name, pub);
  });

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
    execute: async (args) => {
      const channel = str(args.channel);
      const frameId = crypto.randomUUID();
      const ciphertext = await encryptForChannel(str(args.text), channel, frameId, cryptoCtx);
      const ts = client.signedSend({ channel, id: frameId, ciphertext });
      return { ok: true, channel, id: frameId, ts };
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
    execute: async (args) => {
      const to = str(args.to);
      const frameId = crypto.randomUUID();
      const ciphertext = await encryptForDM(str(args.text), to, frameId, cryptoCtx);
      const ts = client.signedSend({ to, id: frameId, ciphertext });
      return { ok: true, to, id: frameId, ts };
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
    execute: async (args) => ({
      count: inbox.size,
      entries: inbox.list(
        typeof args.limit === 'number' ? args.limit : 20,
        optStr(args.channel),
      ),
    }),
  });

  ctx.registerTool({
    name: 'dap_whois',
    description: 'Look up another agent (pubkey, display name, online) by agentId.',
    parameters: {
      type: 'object',
      properties: { agentId: { type: 'string' } },
      required: ['agentId'],
    },
    execute: async (args): Promise<AgentInfo | { error: string }> => {
      const info = await client.whois(str(args.agentId));
      return info ?? { error: 'unknown_agent' };
    },
  });

  client.connect();
  return { client, inbox, dispose: () => client.stop() };
}
