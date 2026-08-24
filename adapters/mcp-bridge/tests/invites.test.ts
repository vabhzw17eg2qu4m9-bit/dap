// Pending by-name invites (parity with omp-extension, shared contract):
// dap_invite with a name that is unknown or offline arms {name, channel} in
// ~/.dap/config.json (DAP_CONFIG_FILE pins a tmp path), auto-creates the
// channel under the inviter's key, and returns the paste-ready connect line;
// a presence poller (fast interval pinned here — 15s in production) delivers
// the chankey DM when the name comes online, removes the entry, and surfaces
// a notice. Runs against the REAL spawned hub (tests/hub.ts) with in-memory
// MCP transports (status.test.ts pattern); the invitee is a plain DapClient
// (invites stay off — plain library clients are inert).
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DapClient } from '../src/client.js';
import { buildServer } from '../src/server.js';
import { persistDapConfig, readDapConfig } from '../src/config.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { startHub } from './hub.js';
import { pollUntil } from './util.js';

const hub = await startHub(); // one hub per test file (hub.ts caches)
// ws:// form so the connect line's host[:port] (scheme + /ws stripped) is
// exactly what a user pastes after /dap.
const url = hub.url.replace(/^http/, 'ws');
const host = url.replace(/^wss?:\/\//, '').replace(/\/ws$/, '');
after(() =>
  hub.stop().then((exit) => {
    assert.ok(exit.signal === 'SIGTERM' || exit.code !== null, 'hub process reaped on teardown');
  }),
);

const tmp = (): string => mkdtempSync(join(tmpdir(), 'dap-mcp-inv-'));
const keyFile = (): string => join(tmp(), 'agent.key');

/** MCP client around a DapClient over the in-memory transport. */
async function mcpAround(dap: DapClient): Promise<Client> {
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  const mcp = new Client({ name: 'dap-invites-test', version: '0.1.0' });
  await buildServer(dap).connect(serverSide);
  await mcp.connect(clientSide);
  return mcp;
}

type Res = Record<string, unknown>;
const invite = async (mcp: Client, args: Res): Promise<Res> => {
  const out = await mcp.callTool({ name: 'dap_invite', arguments: args });
  return JSON.parse(out.content?.find((c) => c.type === 'text')?.text ?? '{}') as Res;
};

// DAP_CONFIG_FILE is read at DapClient construction and at each persist —
// pin it for the whole scenario, restore after.
const pin = (file: string): string | undefined => {
  const prev = process.env.DAP_CONFIG_FILE;
  process.env.DAP_CONFIG_FILE = file;
  return prev;
};
const unpin = (prev: string | undefined): void => {
  if (prev === undefined) delete process.env.DAP_CONFIG_FILE;
  else process.env.DAP_CONFIG_FILE = prev;
};

test('dap_invite <unknown name>: arms a pending invite, persists (deduped), returns the connect line', async () => {
  const prev = pin(join(tmp(), 'config.json'));
  const A = new DapClient({
    url, keyPath: keyFile(), name: 'inviter-a', channelsFile: join(tmp(), 'ch-a.json'),
    invites: true, invitePollMs: 10_000, // tick never fires: only arm-time state is under test
  });
  const mcp = await mcpAround(A);
  try {
    A.start();
    await A.ready();
    const res = await invite(mcp, { channel: 'general', agent: 'carol' });
    assert.equal(res.ok, true);
    assert.equal(res.pending, true);
    assert.equal(res.name, 'carol');
    assert.equal(res.channel, 'general');
    assert.equal(res.connectLine, `send to carol:  /dap ${host} carol`, 'paste-ready connect line');
    assert.ok(A.joinedChannels.includes('general'), 'channel auto-created + inviter joined at arm time');
    assert.deepEqual(readDapConfig(process.env.DAP_CONFIG_FILE).invites, [{ name: 'carol', channel: 'general' }], 'pending persisted');

    // Same (name, channel), different case: deduped — still exactly one entry.
    const again = await invite(mcp, { channel: 'general', agent: 'CAROL' });
    assert.equal(again.pending, true);
    assert.deepEqual(readDapConfig(process.env.DAP_CONFIG_FILE).invites, [{ name: 'carol', channel: 'general' }], 'deduped');
  } finally {
    await mcp.close();
    A.stop();
    unpin(prev);
  }
});

test('pending invite: the name connects later -> poller DMs the chankey, invitee joins, pending removed', async () => {
  const prev = pin(join(tmp(), 'config.json'));
  const A = new DapClient({
    url, keyPath: keyFile(), name: 'inviter-b', channelsFile: join(tmp(), 'ch-a.json'),
    invites: true, invitePollMs: 40, // fast tick: delivery comes from the poller
  });
  const mcp = await mcpAround(A);
  const B = new DapClient({ url, keyPath: keyFile(), name: 'dave', channelsFile: join(tmp(), 'ch-b.json') });
  try {
    A.start();
    await A.ready();
    assert.equal((await invite(mcp, { channel: 'general', agent: 'dave' })).pending, true);

    B.start(); // dave comes online AFTER the arm — only the poller can deliver
    await B.ready();
    await pollUntil(() => B.joinedChannels.includes('general'), 5000, 20);
    assert.deepEqual(readDapConfig(process.env.DAP_CONFIG_FILE).invites, [], 'pending removed after delivery');
    assert.ok(
      A.drainInbox().some((m) => m.invite === 'general' && /\[dap\] invited dave to #general/.test(m.text)),
      'short notice surfaced to the inviter inbox',
    );
  } finally {
    await mcp.close();
    A.stop();
    B.stop();
    unpin(prev);
  }
});

test('dap_invite <online name>: immediate chankey DM, nothing armed', async () => {
  const prev = pin(join(tmp(), 'config.json'));
  const A = new DapClient({
    url, keyPath: keyFile(), name: 'inviter-c', channelsFile: join(tmp(), 'ch-a.json'),
    invites: true, invitePollMs: 10_000,
  });
  const B = new DapClient({ url, keyPath: keyFile(), name: 'erin', channelsFile: join(tmp(), 'ch-b.json') });
  const mcp = await mcpAround(A);
  try {
    A.start();
    B.start();
    await Promise.all([A.ready(), B.ready()]);
    const res = await invite(mcp, { channel: 'immediate', agent: 'ERIN' }); // case-insensitive match
    assert.equal(res.ok, true);
    assert.equal(res.pending, undefined, 'online name: immediate DM, nothing deferred');
    assert.equal(res.to, B.agentId);
    await pollUntil(() => B.joinedChannels.includes('immediate'), 5000, 20);
    assert.deepEqual(readDapConfig(process.env.DAP_CONFIG_FILE).invites, [], 'nothing armed for an online name');
  } finally {
    await mcp.close();
    A.stop();
    B.stop();
    unpin(prev);
  }
});

test('dap_invite <ambiguous name>: honest failure listing both ids, nothing armed', async () => {
  const prev = pin(join(tmp(), 'config.json'));
  const A = new DapClient({
    url, keyPath: keyFile(), name: 'inviter-d', channelsFile: join(tmp(), 'ch-a.json'),
    invites: true, invitePollMs: 10_000,
  });
  const zoe1 = new DapClient({ url, keyPath: keyFile(), name: 'zoe', channelsFile: join(tmp(), 'ch-1.json') });
  const zoe2 = new DapClient({ url, keyPath: keyFile(), name: 'zoe', channelsFile: join(tmp(), 'ch-2.json') });
  const mcp = await mcpAround(A);
  try {
    A.start();
    zoe1.start();
    zoe2.start();
    await Promise.all([A.ready(), zoe1.ready(), zoe2.ready()]);
    const out = await mcp.callTool({ name: 'dap_invite', arguments: { channel: 'general', agent: 'zoe' } });
    assert.equal(out.isError, true, 'ambiguous name is an honest failure, never ok:true');
    assert.match(String(out.content?.find((c) => c.type === 'text')?.text), /"zoe" is ambiguous/);
    assert.deepEqual(readDapConfig(process.env.DAP_CONFIG_FILE).invites, [], 'nothing armed');
  } finally {
    await mcp.close();
    A.stop();
    zoe1.stop();
    zoe2.stop();
    unpin(prev);
  }
});

test('pending invites survive a restart: the welcome-time check delivers without waiting a tick', async () => {
  const prev = pin(join(tmp(), 'config.json'));
  const dir = tmp();
  const keyA = join(dir, 'a.key');
  const chFile = join(dir, 'channels.json');
  // 60s tick: only the welcome-time check can deliver within the deadline.
  const A1 = new DapClient({ url, keyPath: keyA, name: 'inviter-e', channelsFile: chFile, invites: true, invitePollMs: 60_000 });
  const mcp1 = await mcpAround(A1);
  const B = new DapClient({ url, keyPath: keyFile(), name: 'frank', channelsFile: join(tmp(), 'ch-b.json') });
  try {
    A1.start();
    await A1.ready();
    await invite(mcp1, { channel: 'general', agent: 'frank' });
    await mcp1.close();
    A1.stop(); // the inviter goes away entirely

    B.start();
    await B.ready();
    const A2 = new DapClient({ url, keyPath: keyA, name: 'inviter-e', channelsFile: chFile, invites: true, invitePollMs: 60_000 });
    A2.start(); // restart: pendings load from config, welcome check delivers
    await pollUntil(() => B.joinedChannels.includes('general'), 5000, 20);
    assert.deepEqual(readDapConfig(process.env.DAP_CONFIG_FILE).invites, [], 'pending consumed after restart delivery');
    A2.stop();
  } finally {
    B.stop();
    unpin(prev);
  }
});

test('config back-compat: file without invites key loads (invites defaults to []), persist keeps other keys', () => {
  const cfg = join(tmp(), 'legacy.json');
  writeFileSync(cfg, JSON.stringify({ url: 'ws://legacy:9/ws', name: 'legacy', channels: ['ops'] }));
  const cfgLoaded = readDapConfig(cfg);
  assert.deepEqual(cfgLoaded.invites, [], 'missing invites key defaults to []');
  assert.equal(cfgLoaded.url, 'ws://legacy:9/ws');
  persistDapConfig({ invites: [{ name: 'newbie', channel: 'general' }] }, cfg);
  const after = readDapConfig(cfg);
  assert.deepEqual(after.invites, [{ name: 'newbie', channel: 'general' }]);
  assert.equal(after.url, 'ws://legacy:9/ws', 'existing keys survive');
  assert.deepEqual(after.channels, ['ops']);
  writeFileSync(cfg, JSON.stringify({ invites: 'corrupt' }));
  assert.deepEqual(readDapConfig(cfg).invites, [], 'non-array invites treated as absent');
});
