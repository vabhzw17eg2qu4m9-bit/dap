// Master-secret enrollment auth (shared contract): the dial carries the
// resolved bearer token (DAP_CLIENT_SECRET env > config clientSecret >
// DAP_MASTER_SECRET env → enroll-mode), a headerless dial surfaces the frozen
// 401 help text, and an enroll-mode connection persists the issued client
// secret to DAP_CONFIG_FILE and reconnects with it. Stub hub = http server +
// ws upgrade (captures the Authorization header); offline, event-driven.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { DapClient, DIAL_401_HELP } from '../src/client.js';
import { readDapConfig } from '../src/config.js';
import { pinMasterAuth, startHub, stubHub, type StubHub } from './hub.js';
import { pollUntil } from './util.js';

// Determinism: no secret env leaks in from the machine running the tests
// (restored after); each test pins exactly what it asserts on.
const AUTH_KEYS = ['DAP_MASTER_SECRET', 'DAP_CLIENT_SECRET', 'DAP_CONFIG_FILE'] as const;
const savedEnv = Object.fromEntries(AUTH_KEYS.map((k) => [k, process.env[k]]));
for (const k of AUTH_KEYS) delete process.env[k];
after(() => {
  for (const [k, v] of Object.entries(savedEnv)) if (v !== undefined) process.env[k] = v;
});

const tmp = (): string => mkdtempSync(join(tmpdir(), 'dap-auth-'));
const keyFile = (dir: string): string => join(dir, 'agent.key');
const newSecret = (): string => randomBytes(32).toString('base64url');
const client = (hub: StubHub, dir = tmp()): DapClient =>
  new DapClient({ url: hub.url, keyPath: keyFile(dir) });

test('dial sends Authorization: Bearer from DAP_CLIENT_SECRET (no enroll-mode)', async () => {
  const hub = await stubHub();
  process.env.DAP_CLIENT_SECRET = 'env-secret';
  const c = client(hub);
  try {
    c.start();
    await c.ready();
    await pollUntil(() => hub.auths.length > 0);
    assert.equal(hub.auths[0], 'Bearer env-secret');
    assert.equal(hub.frames.some((f) => f.t === 'enroll'), false, 'client-secret dial is a normal connection');
  } finally {
    c.stop();
    delete process.env.DAP_CLIENT_SECRET;
    await hub.close();
  }
});

test('token precedence: DAP_CLIENT_SECRET env > config clientSecret > DAP_MASTER_SECRET', async () => {
  const hub = await stubHub();
  const dir = tmp();
  const configFile = join(dir, 'config.json');
  writeFileSync(configFile, JSON.stringify({ clientSecret: 'cfg-secret' }));
  process.env.DAP_CONFIG_FILE = configFile;
  process.env.DAP_CLIENT_SECRET = 'env-secret';
  process.env.DAP_MASTER_SECRET = 'master-secret';
  const c = client(hub, dir);
  try {
    c.start();
    await c.ready();
    await pollUntil(() => hub.auths.length > 0);
    assert.equal(hub.auths[0], 'Bearer env-secret', 'env client secret wins over everything');

    delete process.env.DAP_CLIENT_SECRET;
    c.stop();
    c.start();
    await c.ready();
    await pollUntil(() => hub.auths.length > 1);
    assert.equal(hub.auths[1], 'Bearer cfg-secret', 'config clientSecret beats the master env');
    assert.equal(hub.frames.some((f) => f.t === 'enroll'), false, 'a resolved client secret never enrolls');
  } finally {
    c.stop();
    for (const k of AUTH_KEYS) delete process.env[k];
    await hub.close();
  }
});

test('headerless dial against a 401 hub surfaces the frozen help text', async () => {
  const hub = await stubHub({ reject: true });
  const c = client(hub);
  try {
    c.start();
    await pollUntil(() => c.lastError === DIAL_401_HELP);
    assert.ok(
      c.drainErrors().some((e) => e.code === 'unauthorized' && e.msg === DIAL_401_HELP),
      '401 surfaced through the error ring too',
    );
  } finally {
    c.stop();
    await hub.close();
  }
});

test('auto-enroll: master-mode dial sends {"t":"enroll"}, persists the issued secret, reconnects with it', async () => {
  const hub = await stubHub({ expect: 'master-secret' });
  const dir = tmp();
  const configFile = join(dir, 'config.json');
  process.env.DAP_CONFIG_FILE = configFile;
  process.env.DAP_MASTER_SECRET = 'master-secret';
  const c = client(hub, dir);
  try {
    c.start();
    await c.ready(); // master-authed welcome — enrollment runs on this connection
    await pollUntil(() => hub.frames.some((f) => f.t === 'enroll'));
    assert.equal(hub.auths[0], 'Bearer master-secret');
    assert.equal(c.connected, true, 'connection stays open after enrolling');

    await pollUntil(() => existsSync(configFile) && readDapConfig(configFile).clientSecret !== undefined);
    assert.equal(readDapConfig(configFile).clientSecret, hub.secret, 'issued secret persisted to DAP_CONFIG_FILE');

    // Reconnect: the persisted secret resolves ahead of the still-set master
    // env — the hub sees a normal client-secret connection, no re-enroll.
    hub.setAuth(hub.secret); // the stub now admits the issued credential
    c.stop();
    c.start();
    await c.ready();
    await pollUntil(() => hub.auths.length > 1);
    assert.equal(hub.auths[1], `Bearer ${hub.secret}`);
    assert.equal(hub.frames.filter((f) => f.t === 'enroll').length, 1, 'exactly one enroll ever');

    // A wrong-issued-secret dial is rejected by the hub (name binding).
    hub.setAuth('rotated');
    c.stop();
    c.start();
    await pollUntil(() => c.lastError === DIAL_401_HELP);
  } finally {
    c.stop();
    for (const k of AUTH_KEYS) delete process.env[k];
    await hub.close();
  }
});

test('enrolled secret never lands in the client logs or error ring', async () => {
  const hub = await stubHub();
  const dir = tmp();
  process.env.DAP_CONFIG_FILE = join(dir, 'config.json');
  process.env.DAP_MASTER_SECRET = 'master-secret';
  const c = client(hub, dir);
  const logs: string[] = [];
  const origErr = console.error;
  console.error = (...args: unknown[]) => logs.push(args.join(' '));
  try {
    c.start();
    await c.ready();
    await pollUntil(() => existsSync(join(dir, 'config.json')) && readDapConfig(join(dir, 'config.json')).clientSecret);
    c.stop();
    assert.deepEqual(c.drainErrors().filter((e) => e.msg.includes(hub.secret)), [], 'no secret in the error ring');
    assert.equal(logs.some((l) => l.includes(hub.secret)), false, 'no secret in logs');
    assert.ok(logs.some((l) => l.includes('enrolled: client secret persisted')), 'enrollment logged (secret-free)');
  } finally {
    console.error = origErr;
    c.stop();
    for (const k of AUTH_KEYS) delete process.env[k];
    await hub.close();
  }
});
