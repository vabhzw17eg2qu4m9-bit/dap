// Universal MCP stdio bridge for DAP/1: ONE outbound WebSocket to the hub,
// four tools on every MCP client (Claude Code, Gemini CLI, Goose, Crush, Amp,
// Cline, Roo Code, kimi-code — same entry in each MCP config).
//
//   stdin/stdout ← MCP (initialize handled by the SDK)   WSS → DAP hub
//
// Env contract (docs/authoring.md): DAP_HUB_URL, DAP_KEY_PATH (default
// ~/.dap/agent.key), DAP_AGENT_NAME. Optional DAP_CHANNELS: JSON array of
// {"name","pub","priv?"} channel keys (out-of-band membership).
import { realpathSync } from 'node:fs';
import { env } from 'node:process';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { DapClient, defaultKeyPath, type ChannelKey, type MsgEvent } from './client.js';

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

  server.registerTool('dap_inbox', {
    title: 'DAP inbox drain',
    description: 'Drain decrypted inbound messages (channel + DM) received since the last call; returns raw payload strings.',
    inputSchema: {},
  }, () => run(async () => {
    const messages: MsgEvent[] = dap.drainInbox();
    return { count: messages.length, messages };
  }));

  server.registerTool('dap_whois', {
    title: 'DAP agent lookup',
    description: 'Look up an agent in the hub pubkey directory (agentId, display name, x25519 key, online).',
    inputSchema: { agent: z.string().min(1).describe('agentId to look up (a_xxxx)') },
  }, ({ agent }) => run(() => dap.whois(agent)));

  return server;
}

async function main(): Promise<void> {
  if (!env.DAP_HUB_URL) {
    console.error('dap-mcp-bridge: DAP_HUB_URL is not set — tools will return errors until it is');
  }
  const dap = new DapClient({
    url: env.DAP_HUB_URL ?? '',
    keyPath: env.DAP_KEY_PATH ?? defaultKeyPath(),
    name: env.DAP_AGENT_NAME,
    channels: parseChannels(env.DAP_CHANNELS),
  });
  if (env.DAP_HUB_URL) dap.start();

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
