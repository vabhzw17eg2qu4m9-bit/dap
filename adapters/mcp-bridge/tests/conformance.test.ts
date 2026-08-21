// MCP conformance: drive the BUILT server artifact (`node dist/server.js`)
// over real stdio with the SDK client against the LIVE hub binary.
// initialize handshake → tools/list (four dap tools) → tools/call dap_send
// round-trip → dap_dm / dap_whois / dap_inbox.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ListToolsResultSchema } from '@modelcontextprotocol/sdk/types.js';
import { startHub } from './hub.js';
import { pollUntil } from './util.js';

const here = dirname(fileURLToPath(import.meta.url));

interface InboxResult {
  count: number;
  messages: Array<{ dm: boolean; channel?: string; from: string; text: string }>;
}

const textOf = (result: { content?: Array<{ type: string; text?: string }> }): Record<string, unknown> =>
  JSON.parse(result.content?.find((c) => c.type === 'text')?.text ?? '{}') as Record<string, unknown>;

test('MCP conformance: initialize → tools/list → tools/call dap_send round-trip', async () => {
  const hub = await startHub(); // builds + spawns the real hub binary, polls /healthz
  const keyPath = join(mkdtempSync(join(tmpdir(), 'dap-conf-')), 'agent.key');
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(here, '..', 'dist', 'server.js')],
    env: {
      ...process.env,
      DAP_HUB_URL: hub.url,
      DAP_KEY_PATH: keyPath,
      DAP_AGENT_NAME: 'conformance-1',
    } as Record<string, string>,
    stderr: 'ignore',
  });
  const client = new Client({ name: 'dap-conformance-check', version: '0.1.0' });
  await client.connect(transport); // performs the MCP initialize handshake

  // tools/list: exactly the four dap tools
  const listed = await client.request({ method: 'tools/list', params: {} }, ListToolsResultSchema);
  const names = listed.tools.map((t) => t.name).sort();
  assert.deepEqual(names, ['dap_dm', 'dap_inbox', 'dap_send', 'dap_whois']);

  // tools/call dap_send: creates the channel, E2E round-trips through the live hub
  const sent = textOf(await client.callTool({ name: 'dap_send', arguments: { channel: 'conformance', text: 'round-trip through the live hub' } }));
  assert.equal(sent.ok, true);
  assert.equal(sent.created, true);
  assert.match(String(sent.chanPubkey), /^[A-Za-z0-9+/]{43}=$/);

  // tools/call dap_dm to self (whois-first happens inside the client)
  const dm = textOf(await client.callTool({ name: 'dap_dm', arguments: { agent: String(sent.from), text: 'dm round-trip' } }));
  assert.equal(dm.ok, true);

  // tools/call dap_whois: the hub directory knows us
  const who = textOf(await client.callTool({ name: 'dap_whois', arguments: { agent: String(sent.from) } }));
  assert.equal(who.agentId, sent.from);
  assert.equal(who.name, 'conformance-1');
  assert.equal(who.online, true);

  // tools/call dap_inbox: sender echo of the channel send + the self-DM
  let inbox = {} as InboxResult;
  await pollUntil(async () => {
    inbox = textOf(await client.callTool({ name: 'dap_inbox', arguments: {} })) as unknown as InboxResult;
    return inbox.count >= 2;
  });
  assert.equal(inbox.count, 2);
  const chanMsg = inbox.messages.find((m) => m.channel === 'conformance');
  assert.equal(chanMsg?.text, 'round-trip through the live hub');
  const dmMsg = inbox.messages.find((m) => m.dm);
  assert.equal(dmMsg?.text, 'dm round-trip');

  await client.close(); // closes stdio; the server child exits with it
  const exit = await hub.stop();
  assert.ok(exit.signal === 'SIGTERM' || exit.code !== null, 'hub process reaped on teardown');
});
