// dap_status / dap_peers against the LIVE spawned hub: status shape flips
// connected false→true across start()/welcome (hellos = connection attempts,
// welcomes = successful handshakes), and the presence query (presence_query
// op → presence frame) lists the agent itself with agentId + online.
// dap_peers tool offline filter: default lists online agents only;
// includeOffline:true also lists offline peers (in-memory MCP transport).
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DapClient } from '../src/client.js';
import { buildServer } from '../src/server.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { startHub } from './hub.js';
import { pollUntil } from './util.js';

const hub = await startHub(); // one hub per test file (hub.ts caches)
after(() => hub.stop().then((exit) => {
  assert.ok(exit.signal === 'SIGTERM' || exit.code !== null, 'hub process reaped on teardown');
}));

function newClient(name: string): DapClient {
  const dir = mkdtempSync(join(tmpdir(), 'dap-status-'));
  return new DapClient({ url: hub.url, keyPath: join(dir, 'agent.key'), name });
}

test('dap_status: connected false before start, true after welcome, false after stop', async () => {
  const c = newClient('status-probe');

  const before = c.status();
  assert.equal(before.connected, false);
  assert.equal(before.hellos, 0);
  assert.equal(before.welcomes, 0);
  assert.deepEqual(before.channels, []);
  assert.match(before.agentId, /^[0-9a-f]{16}$/); // agentId = 16-hex DAP id
  assert.equal(before.url, hub.url);
  assert.equal(before.name, 'status-probe');
  await assert.rejects(c.presence(), /not connected/); // no hub connection yet

  c.start();
  await c.ready();
  const live = c.status();
  assert.equal(live.connected, true);
  assert.equal(live.agentId, before.agentId); // identity is stable across connects
  assert.equal(live.hellos, 1);
  assert.equal(live.welcomes, 1);

  c.stop();
  assert.equal(c.status().connected, false);
});

test('dap_peers: presence query lists itself (agentId + online) via the real hub', async () => {
  const c = newClient('peers-probe');
  c.start();
  await c.ready();

  const agents = await c.presence();
  assert.ok(agents.length >= 1, 'presence lists at least the agent itself');
  const self = agents.find((a) => a.agentId === c.agentId);
  assert.equal(self?.online, true);

  c.stop();
});

test('dap_peers tool: offline agent excluded by default, listed with includeOffline:true', async () => {
  const survivor = newClient('peers-survivor');
  const leaver = newClient('peers-leaver');
  survivor.start();
  leaver.start();
  await Promise.all([survivor.ready(), leaver.ready()]);

  // The hub registry must see the leaver online before dropping it.
  const seen = async (online: boolean) =>
    (await survivor.presence()).find((a) => a.agentId === leaver.agentId)?.online === online;
  await pollUntil(() => seen(true));

  // Drop the leaver; poll presence until the hub marks it offline (no sleeps).
  leaver.stop();
  await pollUntil(() => seen(false));

  // Drive the real dap_peers tool through an in-memory MCP transport.
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  const mcp = new Client({ name: 'dap-peers-test', version: '0.1.0' });
  await buildServer(survivor).connect(serverSide);
  await mcp.connect(clientSide);
  const peers = async (args: Record<string, unknown>) => {
    const res = await mcp.callTool({ name: 'dap_peers', arguments: args });
    return JSON.parse(res.content?.find((c) => c.type === 'text')?.text ?? '{}') as { agents: Array<{ agentId: string; online?: boolean }> };
  };

  const online = await peers({});
  assert.ok(online.agents.some((a) => a.agentId === survivor.agentId), 'survivor listed by default');
  assert.ok(online.agents.every((a) => a.online === true), 'default dap_peers lists online agents only');
  assert.ok(!online.agents.some((a) => a.agentId === leaver.agentId), 'offline leaver excluded by default');

  const all = await peers({ includeOffline: true });
  const dropped = all.agents.find((a) => a.agentId === leaver.agentId);
  assert.equal(dropped?.online, false, 'includeOffline:true lists the leaver as offline');

  await mcp.close();
  survivor.stop();
});
