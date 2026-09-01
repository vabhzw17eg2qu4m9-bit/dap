// 401 stale-cache recovery (shared contract): a dial rejected with HTTP 401
// while carrying the CONFIG-CACHED clientSecret escalates ONCE — purge the
// cached secret from the config file, re-dial in enroll-mode with
// DAP_MASTER_SECRET, and persist the newly issued secret (keys and agentId
// untouched). An ENV-sourced secret is explicit user intent: hard fail, file
// untouched. Without a master secret: today's frozen hint. A second 401
// never re-escalates. Stub hub (tests/hub.ts) asserts the Authorization
// headers; offline, event-driven.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DapClient, DIAL_401_HELP } from '../src/client.js';
import { readDapConfig } from '../src/config.js';
import { stubHub, type StubHub } from './hub.js';
import { delay, pollUntil } from './util.js';

// Determinism: no secret env leaks in from the machine running the tests
// (restored after); each test pins exactly what it asserts on.
const AUTH_KEYS = ['DAP_MASTER_SECRET', 'DAP_CLIENT_SECRET', 'DAP_CONFIG_FILE'] as const;
const savedEnv = Object.fromEntries(AUTH_KEYS.map((k) => [k, process.env[k]]));
for (const k of AUTH_KEYS) delete process.env[k];
after(() => {
  for (const [k, v] of Object.entries(savedEnv)) if (v !== undefined) process.env[k] = v;
});

const tmp = (): string => mkdtempSync(join(tmpdir(), 'dap-reenroll-'));
// Fast backoff: the escalation retry rides the normal reconnect schedule.
const client = (hub: StubHub, dir: string): DapClient =>
  new DapClient({ url: hub.url, keyPath: join(dir, 'agent.key'), backoff: { initialMs: 40, maxMs: 40 } });

test('config-secret 401 + master: purge cache, ONE enroll-mode retry, new secret persisted, agentId stable', async () => {
  const hub = await stubHub({ expect: 'master-secret' }); // rejects the stale cache, admits the master
  const dir = tmp();
  const configFile = join(dir, 'config.json');
  writeFileSync(configFile, JSON.stringify({ url: hub.url, clientSecret: 'stale-secret' }));
  process.env.DAP_CONFIG_FILE = configFile;
  process.env.DAP_MASTER_SECRET = 'master-secret';
  const c = client(hub, dir);
  const agentId = c.agentId;
  try {
    c.start();
    await c.ready(); // welcome lands on the enroll-mode retry dial
    await pollUntil(() => existsSync(configFile) && readDapConfig(configFile).clientSecret !== undefined);
    assert.deepEqual(hub.auths, ['Bearer stale-secret', 'Bearer master-secret'], 'exactly one escalation retry');
    assert.equal(hub.frames.some((f) => f.t === 'enroll'), true, 'retry dialed in enroll-mode');
    assert.equal(readDapConfig(configFile).clientSecret, hub.secret, 'stale cache replaced by the issued secret');
    assert.equal(readDapConfig(configFile).url, hub.url, 'other config fields survive the purge');
    assert.equal(c.agentId, agentId, 'identity untouched');
  } finally {
    c.stop();
    for (const k of AUTH_KEYS) delete process.env[k];
    await hub.close();
  }
});

test('env-secret 401: hard fail, config file untouched (explicit intent, never wiped)', async () => {
  const hub = await stubHub({ reject: true });
  const dir = tmp();
  const configFile = join(dir, 'config.json');
  writeFileSync(configFile, JSON.stringify({ url: 'ws://example:1/ws', clientSecret: 'cfg-secret' }));
  process.env.DAP_CONFIG_FILE = configFile;
  process.env.DAP_CLIENT_SECRET = 'env-secret';
  process.env.DAP_MASTER_SECRET = 'master-secret'; // present — must not matter
  const c = client(hub, dir);
  try {
    c.start();
    await pollUntil(() => c.lastError === DIAL_401_HELP);
    assert.equal(hub.auths[0], 'Bearer env-secret');
    assert.deepEqual(readDapConfig(configFile), { url: 'ws://example:1/ws', clientSecret: 'cfg-secret', invites: [] });
  } finally {
    c.stop();
    for (const k of AUTH_KEYS) delete process.env[k];
    await hub.close();
  }
});

test('config-secret 401, no master: hard fail with the frozen hint, stale cache kept', async () => {
  const hub = await stubHub({ reject: true });
  const dir = tmp();
  const configFile = join(dir, 'config.json');
  writeFileSync(configFile, JSON.stringify({ clientSecret: 'cfg-secret' }));
  process.env.DAP_CONFIG_FILE = configFile;
  const c = client(hub, dir);
  try {
    c.start();
    await pollUntil(() => c.lastError === DIAL_401_HELP);
    assert.equal(hub.auths[0], 'Bearer cfg-secret');
    assert.equal(hub.frames.some((f) => f.t === 'enroll'), false, 'no enrollment without a master secret');
    assert.equal(readDapConfig(configFile).clientSecret, 'cfg-secret', 'nothing purged');
  } finally {
    c.stop();
    for (const k of AUTH_KEYS) delete process.env[k];
    await hub.close();
  }
});

test('escalation retry also 401s: frozen hint, no second escalation, no enroll', async () => {
  const hub = await stubHub({ reject: true });
  const dir = tmp();
  const configFile = join(dir, 'config.json');
  writeFileSync(configFile, JSON.stringify({ url: 'ws://example:1/ws', clientSecret: 'cfg-secret' }));
  process.env.DAP_CONFIG_FILE = configFile;
  process.env.DAP_MASTER_SECRET = 'master-secret';
  const c = client(hub, dir);
  try {
    c.start();
    await pollUntil(() => hub.auths.length >= 2, 5000, 20); // dial 1 stale cache, dial 2 the one escalation retry
    await delay(250); // several backoff cycles — the loop must stay enroll-mode
    assert.equal(hub.auths[0], 'Bearer cfg-secret');
    assert.equal(hub.auths[1], 'Bearer master-secret', 'exactly one enroll-mode retry');
    assert.ok(hub.auths.slice(2).every((a) => a === 'Bearer master-secret'), 'no re-escalation');
    assert.equal(readDapConfig(configFile).clientSecret, undefined, 'stale cache purged once');
    assert.equal(readDapConfig(configFile).url, 'ws://example:1/ws', 'other fields survive');
    assert.equal(hub.frames.some((f) => f.t === 'enroll'), false, 'never welcomed, never enrolled');
    assert.equal(c.lastError, DIAL_401_HELP, 'frozen hint');
  } finally {
    c.stop();
    for (const k of AUTH_KEYS) delete process.env[k];
    await hub.close();
  }
});
