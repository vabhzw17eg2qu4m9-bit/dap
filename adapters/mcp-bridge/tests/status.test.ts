// dap_status / dap_peers against the LIVE spawned hub: status shape flips
// connected false→true across start()/welcome (hellos = connection attempts,
// welcomes = successful handshakes), and the presence query (presence_query
// op → presence frame) lists the agent itself with agentId + online.
// dap_peers contract: ONLINE peers only — the requesting agent's own entry is
// present and marked self:true (client-side marking), offline entries are
// absent; there is no includeOffline flag.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import { WebSocketServer } from 'ws';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DapClient } from '../src/client.js';
import { readDapConfig } from '../src/config.js';
import { buildServer } from '../src/server.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { pinMasterAuth, startHub } from './hub.js';
import { pollUntil } from './util.js';

const hub = await startHub(); // one hub per test file (hub.ts caches)
after(() => hub.stop().then((exit) => {
  assert.ok(exit.signal === 'SIGTERM' || exit.code !== null, 'hub process reaped on teardown');
}));

/** Fresh identity + its own config file (enrollment lands there). The auth
 *  env is pinned at DIAL time — pin before start(), unpin in finally. */
function newClient(name: string): { c: DapClient; cfg: string } {
  const dir = mkdtempSync(join(tmpdir(), 'dap-status-'));
  const cfg = join(dir, 'config.json');
  return { c: new DapClient({ url: hub.url, keyPath: join(dir, 'agent.key'), name }), cfg };
}

test('dap_status: connected false before start, true after welcome, false after stop', async () => {
  const { c, cfg } = newClient('status-probe');
  const unpin = pinMasterAuth(hub, cfg);
  try {
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
  } finally {
    unpin();
  }
});

test('dap_peers: presence query lists itself (agentId + online) via the real hub', async () => {
  const { c, cfg } = newClient('peers-probe');
  const unpin = pinMasterAuth(hub, cfg);
  try {
    c.start();
    await c.ready();

    const agents = await c.presence();
    assert.ok(agents.length >= 1, 'presence lists at least the agent itself');
    const self = agents.find((a) => a.agentId === c.agentId);
    assert.equal(self?.online, true);
    assert.equal(self?.self, true, 'own entry marked self:true');
    assert.ok(agents.every((a) => a.self === (a.agentId === c.agentId)), 'self marks exactly the own entry');
  } finally {
    c.stop();
    unpin();
  }
});

test('dap_peers tool: online-only roster, own entry marked self, offline ghost absent', async () => {
  // Dedicated hub: an empty registry makes the entry-count assertion exact —
  // the shared file hub carries offline ghosts from this file's earlier tests.
  const rosterHub = await startHub('peers-roster');
  const client = (name: string) => {
    const dir = mkdtempSync(join(tmpdir(), 'dap-peers-'));
    const cfg = join(dir, 'config.json');
    return { c: new DapClient({ url: rosterHub.url, keyPath: join(dir, 'agent.key'), name }), cfg };
  };
  const survivor = client('peers-survivor');
  const bystander = client('peers-bystander');
  const leaver = client('peers-leaver');
  const dial = async (x: { c: DapClient; cfg: string }) => {
    const unpin = pinMasterAuth(rosterHub, x.cfg);
    x.c.start();
    await x.c.ready();
    // Enrollment persists a frame after the welcome — wait for it before the
    // next client dials under its own config (one env, one enrolled identity).
    await pollUntil(() => readDapConfig(x.cfg).clientSecret !== undefined, 5000, 20);
    unpin();
  };
  try {
    await dial(survivor);
    await dial(bystander);
    await dial(leaver);

    // Roster: self + 1 online peer + 1 online leaver (about to ghost).
    await pollUntil(async () => (await survivor.c.presence()).length === 3);

    // Drop the leaver; the offline ghost must leave the online-only roster.
    leaver.c.stop();
    await pollUntil(async () => (await survivor.c.presence()).length === 2);

    // Drive the real dap_peers tool through an in-memory MCP transport.
    // The tool layer is gated on DAP_MASTER_SECRET — dial() unpins after
    // each enrollment, so pin it again for the tool call.
    const unpinTool = pinMasterAuth(rosterHub, survivor.cfg);
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    const mcp = new Client({ name: 'dap-peers-test', version: '0.1.0' });
    await buildServer(survivor.c).connect(serverSide);
    await mcp.connect(clientSide);
    const res = await mcp.callTool({ name: 'dap_peers', arguments: {} });
    const peers = JSON.parse(res.content?.find((c) => c.type === 'text')?.text ?? '{}') as {
      agents: Array<{ agentId: string; online?: boolean; self: boolean }>;
    };

    // Contract: exactly self + the online peer; the ghost is absent.
    assert.equal(peers.agents.length, 2, 'exactly self + one online peer');
    assert.ok(peers.agents.every((a) => a.online === true), 'dap_peers lists online agents only');
    assert.ok(!peers.agents.some((a) => a.agentId === leaver.c.agentId), 'offline ghost excluded');
    assert.equal(peers.agents.find((a) => a.agentId === survivor.c.agentId)?.self, true, 'own entry marked self:true');
    assert.equal(peers.agents.find((a) => a.agentId === bystander.c.agentId)?.self, false, 'peer entry marked self:false');

    await mcp.close();
    unpinTool();
  } finally {
    survivor.c.stop();
    bystander.c.stop();
    leaver.c.stop();
  }
  await rosterHub.stop(); // reaped here: a live hub child keeps the test process alive
});

/** Minimal fake hub for client-level correlation tests: answers hello with
 *  welcome, records presence_query ids in arrival order, and lets the test
 *  push crafted presence frames to every socket — deterministic, no sleeps. */
async function startFakeHub() {
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await once(wss, 'listening');
  const { port } = wss.address() as AddressInfo;
  const socks: { send: (s: string) => void }[] = [];
  const queryIds: string[] = [];
  wss.on('connection', (sock) => {
    socks.push(sock);
    sock.on('message', (raw) => {
      const f = JSON.parse(String(raw)) as { op?: string; id?: string };
      if (f.op === 'hello') sock.send(JSON.stringify({ op: 'welcome' }));
      else if (f.op === 'presence_query' && f.id !== undefined) queryIds.push(f.id);
    });
  });
  return {
    url: `ws://127.0.0.1:${port}`,
    nextQuery: async (): Promise<string> => {
      await pollUntil(() => queryIds.length > 0);
      return queryIds.shift()!;
    },
    broadcast: (frame: Record<string, unknown>): void => {
      for (const s of socks) s.send(JSON.stringify(frame));
    },
    close: (): Promise<void> => {
      const { promise, resolve, reject } = Promise.withResolvers<void>();
      wss.close((err) => (err ? reject(err) : resolve()));
      return promise;
    },
  };
}

function fakeClient(url: string): DapClient {
  const dir = mkdtempSync(join(tmpdir(), 'dap-fake-'));
  return new DapClient({ url, keyPath: join(dir, 'agent.key'), name: 'fake-probe' });
}

test('presence correlation: only the replyTo-matched answer completes; stale echoes never win', async () => {
  const fake = await startFakeHub();
  const c = fakeClient(fake.url);
  try {
    c.start();
    await c.ready();
    await fake.nextQuery(); // welcome-time warm-up query (result discarded by the client)

    const pending = c.presence();
    const queryId = await fake.nextQuery();

    // Someone else's echo (wrong roster) arrives first — and must be ignored.
    fake.broadcast({ op: 'presence', replyTo: 'stale-other-query', agents: [{ agentId: 'f'.repeat(16), name: 'ghost', online: true }] });
    // The real answer carries our query id and the full roster.
    fake.broadcast({
      op: 'presence',
      replyTo: queryId,
      agents: [
        { agentId: c.agentId, name: 'fake-probe', online: true },
        { agentId: 'a'.repeat(16), name: 'peer-a', online: true },
      ],
    });

    const agents = await pending;

    assert.equal(agents.length, 2, 'matched answer roster, not the stale echo');
    assert.ok(agents.some((a) => a.agentId === c.agentId && a.self === true));
    assert.ok(agents.some((a) => a.agentId === 'a'.repeat(16) && a.self === false));
  } finally {
    c.stop();
    await fake.close();
  }
});

test('presence correlation: legacy id-less answer still completes (back-compat)', async () => {
  const fake = await startFakeHub();
  const c = fakeClient(fake.url);
  try {
    c.start();
    await c.ready();
    await fake.nextQuery(); // welcome-time warm-up query (result discarded by the client)

    const pending = c.presence();
    await fake.nextQuery(); // query is out; reply in legacy shape (no replyTo)
    fake.broadcast({ op: 'presence', agents: [{ agentId: c.agentId, name: 'fake-probe', online: true }] });

    const agents = await pending;
    assert.deepEqual(agents.map((a) => a.agentId), [c.agentId]);
    assert.equal(agents[0]?.self, true);
  } finally {
    c.stop();
    await fake.close();
  }
});

test('presence echo latch: once the hub echoes, id-less broadcasts never complete queries', async () => {
  const fake = await startFakeHub();
  const c = fakeClient(fake.url);
  try {
    c.start();
    await c.ready();
    await fake.nextQuery(); // welcome-time warm-up query (result discarded by the client)

    // Query A answered WITH replyTo — arms the client-lifetime latch.
    const a = c.presence();
    const aId = await fake.nextQuery();
    fake.broadcast({ op: 'presence', replyTo: aId, agents: [{ agentId: c.agentId, online: true }] });
    assert.deepEqual((await a).map((x) => x.agentId), [c.agentId]);

    // Query B pends; the hub pushes an unsolicited one-agent presence
    // broadcast WITHOUT replyTo — on an echo-capable hub that is a
    // broadcast and must NOT satisfy the query (BUG 5 shape).
    const b = c.presence();
    const bId = await fake.nextQuery();
    fake.broadcast({ op: 'presence', agents: [{ agentId: 'b'.repeat(16), name: 'loner', online: true }] });
    const completed = await Promise.race([b.then(() => true, () => true), Promise.resolve(false)]);

    // The matching echo still completes B with the full roster.
    fake.broadcast({
      op: 'presence',
      replyTo: bId,
      agents: [{ agentId: c.agentId, online: true }, { agentId: 'a'.repeat(16), online: true }],
    });
    const agents = await b;
    assert.deepEqual(agents.map((x) => x.agentId), [c.agentId, 'a'.repeat(16)]);
  } finally {
    c.stop();
    await fake.close();
  }
});
test('welcome warm-up: the latch is armed before any user query — a join-echo broadcast cannot steal query #1', async () => {
  const fake = await startFakeHub();
  const c = fakeClient(fake.url);
  try {
    c.start();
    await c.ready();

    // The warm-up query fires unprompted at welcome; its replyTo echo arms
    // the echo latch (the warm-up roster itself is discarded by the client).
    const warmId = await fake.nextQuery();
    fake.broadcast({ op: 'presence', replyTo: warmId, agents: [{ agentId: c.agentId, online: true }] });

    // FIRST user query; an unsolicited join self-echo (replyTo-less,
    // one-agent roster — the 0.2.1 first-query steal) races in before the
    // answer and must NOT complete it.
    const pending = c.presence();
    const userId = await fake.nextQuery();
    fake.broadcast({ op: 'presence', agents: [{ agentId: 'b'.repeat(16), name: 'loner', online: true }] });
    fake.broadcast({
      op: 'presence',
      replyTo: userId,
      agents: [{ agentId: c.agentId, online: true }, { agentId: 'a'.repeat(16), name: 'peer-a', online: true }],
    });
    const agents = await pending;
    assert.deepEqual(agents.map((x) => x.agentId), [c.agentId, 'a'.repeat(16)]);
  } finally {
    c.stop();
    await fake.close();
  }
});

test('presence correlation: concurrent callers each get their own answer', async () => {
  const fake = await startFakeHub();
  const c = fakeClient(fake.url);
  try {
    c.start();
    await c.ready();
    await fake.nextQuery(); // welcome-time warm-up query (result discarded by the client)

    const p1 = c.presence();
    const p2 = c.presence();
    const first = await fake.nextQuery();
    const second = await fake.nextQuery();
    // Answers in REVERSE order with DISTINCT rosters: only per-id routing
    // delivers each caller its own roster.
    fake.broadcast({ op: 'presence', replyTo: second, agents: [{ agentId: c.agentId, online: true }, { agentId: 'b'.repeat(16), online: true }] });
    fake.broadcast({ op: 'presence', replyTo: first, agents: [{ agentId: c.agentId, online: true }, { agentId: 'a'.repeat(16), online: true }] });

    const [one, two] = await Promise.all([p1, p2]);
    assert.ok(one.some((a) => a.agentId === 'a'.repeat(16)), 'first caller got its own roster');
    assert.ok(two.some((a) => a.agentId === 'b'.repeat(16)), 'second caller got its own roster');
  } finally {
    c.stop();
    await fake.close();
  }
});
