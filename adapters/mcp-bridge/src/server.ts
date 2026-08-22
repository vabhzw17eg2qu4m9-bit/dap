// Universal MCP stdio bridge for DAP/1: ONE outbound WebSocket to the hub,
// five tools on every MCP client (Claude Code, Gemini CLI, Goose, Crush, Amp,
// Cline, Roo Code, kimi-code — same entry in each MCP config).
//
//   stdin/stdout ← MCP (initialize handled by the SDK)   WSS → DAP hub
//
// Zero-config (config.ts): explicit arg > DAP_* env (DAP_HUB_URL,
// DAP_KEY_PATH, DAP_AGENT_NAME, DAP_CHANNELS_FILE) > ~/.dap/config.json >
// defaults (url ws://127.0.0.1:8787/ws, key ~/.dap/keys/mcp/<name|host>.key,
// channels ~/.dap/channels.json shared across adapters). An agent needs at
// most DAP_AGENT_NAME. Legacy DAP_CHANNELS (JSON array of {name,pub,priv?})
// still works and overrides the channels file.
import { realpathSync } from 'node:fs';
import { env } from 'node:process';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { DapClient, type ChannelKey, type MsgEvent } from './client.js';
import { resolveDapSettings } from './config.js';

interface TextResult extends CallToolResult {
  content: Array<{ type: 'text'; text: string }>;
}

const json = (value: unknown): TextResult => ({ content: [{ type: 'text', text: JSON.stringify(value) }] });
const failure = (err: unknown): TextResult => ({
  isError: true,
  content: [{ type: 'text', text: err instanceof Error ? err.message : String(err) }],
});

/** Wrap a tool body: JSON result on success, isError + message on failure. */
async function run(body: () => Promise<unknown>): Promise<TextResult> {
  try {
    return json(await body());
  } catch (err) {
    return failure(err);
  }
}

function parseChannels(spec: string | undefined): ChannelKey[] {
  if (!spec) return [];
  const parsed = JSON.parse(spec) as ChannelKey[];
  if (!Array.isArray(parsed)) throw new Error('DAP_CHANNELS must be a JSON array of {name,pub,priv?}');
  return parsed;
}

/** Build the MCP server around a live DAP client (exported for tests). */
export function buildServer(dap: DapClient): McpServer {
  const server = new McpServer({ name: 'dap-mcp-bridge', version: '0.1.0' });

  server.registerTool('dap_send', {
    title: 'DAP channel send',
    description: 'Send an E2E-encrypted message to a DAP channel. Creates the channel (fresh keypair) on first use; the result carries chanPubkey to share out-of-band with future members.',
    inputSchema: { channel: z.string().min(1).describe('channel name'), text: z.string().min(1).describe('plaintext message') },
  }, ({ channel, text }) => run(() => dap.send(channel, text)));

  server.registerTool('dap_dm', {
    title: 'DAP direct message',
    description: 'Send an E2E-encrypted direct message to an agent (whois runs first to fetch the peer x25519 key).',
    inputSchema: { agent: z.string().min(1).describe('recipient agentId (a_xxxx)'), text: z.string().min(1).describe('plaintext message') },
  }, ({ agent, text }) => run(() => dap.dm(agent, text)));

  server.registerTool('dap_invite', {
    title: 'DAP channel invite',
    description: 'Invite an agent to a channel: DMs them the channel keypair inside a normal E2E DM (the plaintext happens to be JSON). Creates the channel (fresh keypair) on first use.',
    inputSchema: {
      channel: z.string().min(1).describe('channel name'),
      agent: z.string().min(1).describe('recipient agentId (a_xxxx)'),
    },
  }, ({ channel, agent }) => run(() => dap.invite(channel, agent)));

  server.registerTool('dap_inbox', {
    title: 'DAP inbox drain',
    description: 'Drain decrypted inbound messages (channel + DM) received since the last call, plus any hub error frames observed since then; returns raw payload strings.',
    inputSchema: {},
  }, () => run(async () => {
    const messages: MsgEvent[] = dap.drainInbox();
    return { count: messages.length, messages, errors: dap.drainErrors() };
  }));

  server.registerTool('dap_whois', {
    title: 'DAP agent lookup',
    description: 'Look up an agent in the hub pubkey directory (agentId, display name, x25519 key, online).',
    inputSchema: { agent: z.string().min(1).describe('agentId to look up (a_xxxx)') },
  }, ({ agent }) => run(() => dap.whois(agent)));

  return server;
}

async function main(): Promise<void> {
  // Identity bootstrap happens in the DapClient constructor: the key file is
  // generated 0600 (parents on demand) under the resolved default path.
  const settings = resolveDapSettings();
  const dap = new DapClient({
    url: settings.url,
    keyPath: settings.keyPath,
    name: settings.name,
    channelsFile: settings.channelsFile,
    channels: parseChannels(env.DAP_CHANNELS),
    onHubError: (e) => console.error(`[dap] hub rejected a frame — ${e.code}: ${e.msg}`),
  });
  dap.start(); // zero-config: defaults point at the local hub; backoff covers a down hub

  const server = buildServer(dap);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stdio closed (MCP client went away) → drop the hub connection and exit.
  transport.onclose = () => dap.stop();
}

// Run only as the entrypoint (`node dist/server.js`); importing for tests skips main.
if (import.meta.filename === realpathSync(process.argv[1] ?? import.meta.filename)) {
  void main();
}
