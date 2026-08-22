// Zero-config onboarding parity with omp-extension (shared contract):
// settings precedence (per-adapter key dir + shared channels file), channel
// auto-keygen + auto-join after welcome, and chankey invites over E2E DMs.
// Live tests run against the REAL spawned hub binary (tests/hub.ts builds
// ../../hub and polls /healthz — no blind sleeps, offline localhost only).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, statSync, rmSync } from 'node:fs';
import { tmpdir, hostname } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { DapClient, type MsgEvent } from '../src/client.js';
import { loadChannelKeys, newChannelKeypair, parseChankeyInvite } from '../src/channels.js';
import { resolveDapSettings } from '../src/config.js';
import { b64d } from '../src/crypto.js';
import { startHub } from './hub.js';
import { pollUntil } from './util.js';

const here = dirname(fileURLToPath(import.meta.url));

// Determinism: clear any DAP_* env leaked in from the machine running the
// tests (restored after); nothing here may depend on the operator's shell.
const DAP_ENV_KEYS = ['DAP_HUB_URL', 'DAP_KEY_PATH', 'DAP_AGENT_NAME', 'DAP_CHANNELS_FILE', 'DAP_CHANNELS'] as const;
const savedEnv = Object.fromEntries(DAP_ENV_KEYS.map((k) => [k, process.env[k]]));
for (const k of DAP_ENV_KEYS) delete process.env[k];
test.after(() => {
  for (const [k, v] of Object.entries(savedEnv)) if (v !== undefined) process.env[k] = v;
});

const tmp = (): string => mkdtempSync(join(tmpdir(), 'dap-mcp-zero-'));
const keyFile = (dir: string): string => join(dir, 'agent.key');

function collect(client: DapClient): { all: () => MsgEvent[]; has: (pred: (m: MsgEvent) => boolean) => boolean } {
  const got: MsgEvent[] = [];
  client.onMessage((m) => got.push(m));
  return { all: () => [...got], has: (pred) => got.some(pred) };
}

test('settings precedence: override > env > ~/.dap/config.json > defaults; mcp key dir + shared channels file', () => {
  const home = tmp();
  const prevHome = process.env.HOME;
  process.env.HOME = home;
  try {
    // No config file, no env: plain defaults. Identity file sits in the
    // per-adapter dir ~/.dap/keys/mcp/<name|hostname>.key; channels file is
    // ~/.dap/channels.json — SHARED across adapters on the machine.
    let s = resolveDapSettings();
    assert.equal(s.url, 'ws://127.0.0.1:8787/ws');
    assert.equal(s.keyPath, join(home, '.dap', 'keys', 'mcp', `${hostname()}.key`));
    assert.equal(s.channelsFile, join(home, '.dap', 'channels.json'));
    assert.equal(s.name, undefined);
    assert.equal(resolveDapSettings({ name: 'alice' }).keyPath, join(home, '.dap', 'keys', 'mcp', 'alice.key'));

    // Config file fills every unset field.
    mkdirSync(join(home, '.dap'), { recursive: true });
    const cfgFile = join(home, '.dap', 'config.json');
    writeFileSync(cfgFile, JSON.stringify({
      url: 'ws://cfg:1/ws', name: 'cfg-agent', keyPath: '/cfg/key.json', channelsFile: '/cfg/channels.json',
    }));
    s = resolveDapSettings();
    assert.equal(s.url, 'ws://cfg:1/ws');
    assert.equal(s.name, 'cfg-agent');
    assert.equal(s.keyPath, '/cfg/key.json');
    assert.equal(s.channelsFile, '/cfg/channels.json');

    // Env beats the file; the file still beats the defaults.
    process.env.DAP_HUB_URL = 'ws://env:2/ws';
    process.env.DAP_CHANNELS_FILE = '/env/channels.json';
    process.env.DAP_AGENT_NAME = 'env-agent';
    s = resolveDapSettings();
    assert.equal(s.url, 'ws://env:2/ws');
    assert.equal(s.channelsFile, '/env/channels.json');
    assert.equal(s.keyPath, '/cfg/key.json', 'file beats default when env is silent');

    // Explicit override beats env.
    assert.equal(resolveDapSettings({ url: 'ws://ov:3/ws' }).url, 'ws://ov:3/ws');

    // An invalid config file counts as absent.
    writeFileSync(cfgFile, '{not json');
    delete process.env.DAP_HUB_URL;
    delete process.env.DAP_CHANNELS_FILE;
    delete process.env.DAP_AGENT_NAME;
    s = resolveDapSettings();
    assert.equal(s.url, 'ws://127.0.0.1:8787/ws');
    assert.equal(s.channelsFile, join(home, '.dap', 'channels.json'));
  } finally {
    process.env.HOME = prevHome;
    rmSync(home, { recursive: true, force: true });
  }
});

test('auto-keygen: send to an unknown channel persists keys; second instance auto-joins + decrypts', async () => {
  const hub = await startHub();
  const dirA = tmp();
  const dirB = tmp();
  const channelsFile = join(dirA, 'channels.json');
  const A = new DapClient({ url: hub.url, keyPath: keyFile(dirA), channelsFile });
  try {
    A.start();
    await A.ready();

    // First-ever use of the channel: keygen + persist + join, send works.
    const first = await A.send('zc-auto', 'zero config');
    assert.equal(first.ok, true);
    assert.equal(first.created, true);
    // Second unknown channel: read-modify-write keeps the first one.
    await A.send('zc-auto-2', 'still zero config');
    const saved = loadChannelKeys(channelsFile);
    assert.deepEqual(Object.keys(saved).sort(), ['zc-auto', 'zc-auto-2']);
    assert.equal(b64d(saved['zc-auto']!.pub).length, 32, 'x25519 public key persisted');
    assert.equal(b64d(saved['zc-auto']!.priv).length, 32, 'x25519 private key persisted');

    // Fresh instance, same channels file: auto-joins every known channel
    // after welcome — zero config beyond pointing at the same file.
    const B = new DapClient({ url: hub.url, keyPath: keyFile(dirB), channelsFile });
    const seenB = collect(B);
    try {
      B.start();
      await B.ready();
      await pollUntil(() => B.joinedChannels.includes('zc-auto') && B.joinedChannels.includes('zc-auto-2'));
      await A.send('zc-auto', 'second message');
      await pollUntil(() => seenB.has((m) => m.channel === 'zc-auto' && m.text === 'second message'));

      // Reconnect-safe: welcome after a dropped connection re-joins (the
      // hub's live membership is in-memory).
      B.stop();
      B.start();
      await B.ready();
      await pollUntil(() => B.joinedChannels.includes('zc-auto'));
    } finally {
      B.stop();
    }
  } finally {
    A.stop();
  }
});

test('invite: full server (dap_invite tool) invites a plain client; B auto-persists, joins and decrypts', async () => {
  const hub = await startHub();
  // Server child: zero-config identity — only DAP_AGENT_NAME given, key lands
  // in ~/.dap/keys/mcp/<name>.key (0600) under the pinned HOME.
  const serverHome = tmp();
  const fileA = join(serverHome, 'channels-a.json');
  const fileB = join(tmp(), 'channels-b.json');
  writeFileSync(fileB, '{}', { flag: 'wx' }); // B literally starts with an empty channels file
  const B = new DapClient({ url: hub.url, keyPath: keyFile(tmp()), channelsFile: fileB });
  const seenB = collect(B);
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(here, '..', 'dist', 'server.js')],
    env: {
      ...process.env,
      HOME: serverHome,
      DAP_HUB_URL: hub.url,
      DAP_AGENT_NAME: 'zc-server',
      DAP_CHANNELS_FILE: fileA,
    } as Record<string, string>,
    stderr: 'ignore',
  });
  const mcp = new Client({ name: 'dap-zeroconfig-check', version: '0.1.0' });
  await mcp.connect(transport);
  try {
    B.start();
    await B.ready();

    // dap_invite on a channel A doesn't hold yet: zero-config creation inlined.
    const out = await mcp.callTool({ name: 'dap_invite', arguments: { channel: 'zc-server-invite', agent: B.agentId } });
    const res = JSON.parse((out.content ?? []).find((c) => c.type === 'text')?.text ?? '{}') as Record<string, unknown>;
    assert.equal(res.ok, true);
    assert.equal(res.created, true, 'channel created by the invite itself');
    assert.ok(loadChannelKeys(fileA)['zc-server-invite']?.pub, 'creator keypair persisted');

    // B accepted: notice surfaced, keypair persisted, joined the channel.
    await pollUntil(() => seenB.has((m) => m.invite === 'zc-server-invite'));
    await pollUntil(() => B.joinedChannels.includes('zc-server-invite'));
    assert.equal(loadChannelKeys(fileB)['zc-server-invite']?.pub, loadChannelKeys(fileA)['zc-server-invite']?.pub);

    // Subsequent channel send through the server decrypts on B.
    await mcp.callTool({ name: 'dap_send', arguments: { channel: 'zc-server-invite', text: 'welcome aboard' } });
    await pollUntil(() => seenB.has((m) => m.channel === 'zc-server-invite' && m.text === 'welcome aboard'));

    // Identity bootstrap: server generated its key under the mcp default path.
    const keyPath = join(serverHome, '.dap', 'keys', 'mcp', 'zc-server.key');
    assert.equal(statSync(keyPath).mode & 0o777, 0o600);
  } finally {
    await mcp.close(); // closes stdio; the server child exits with it
    B.stop();
  }
});

test('chankey DM is not a normal inbox message on B (invite notice instead)', async () => {
  const hub = await startHub();
  const fileA = join(tmp(), 'channels-a.json');
  const fileB = join(tmp(), 'channels-b.json');
  const A = new DapClient({ url: hub.url, keyPath: keyFile(tmp()), channelsFile: fileA });
  const B = new DapClient({ url: hub.url, keyPath: keyFile(tmp()), channelsFile: fileB });
  const seenB = collect(B);
  try {
    A.start();
    B.start();
    await Promise.all([A.ready(), B.ready()]);

    await A.invite('zc-notice', B.agentId);
    await pollUntil(() => seenB.has((m) => m.invite === 'zc-notice'));
    const notice = seenB.all().find((m) => m.invite === 'zc-notice')!;
    assert.equal(notice.dm, true);
    assert.match(notice.text, /\[dap\] invited to #zc-notice by /);
    assert.ok(loadChannelKeys(fileB)['zc-notice']?.priv, 'invite persisted to the channels file');

    // Not chat: the raw chankey JSON never lands in the inbox as a message.
    const inbox = B.drainInbox();
    assert.ok(!inbox.some((m) => m.text.includes('chankey') || m.text.includes('"pub"')), 'no key material in the inbox');
    assert.ok(inbox.some((m) => m.invite === 'zc-notice'), 'notice entry present');

    // Only exactly-shaped chankey DMs are intercepted; JSON-looking chat and
    // malformed invites stay normal messages.
    await A.dm(B.agentId, '{"t":"chankey"}');
    await pollUntil(() => seenB.has((m) => m.text === '{"t":"chankey"}'));
    const after = B.drainInbox();
    assert.equal(after.find((m) => m.text === '{"t":"chankey"}')?.invite, undefined);

    // Parser boundary: shape and key length both matter.
    const kp = newChannelKeypair();
    const valid = JSON.stringify({ t: 'chankey', channel: 'x', pub: kp.pub, priv: kp.priv });
    assert.deepEqual(parseChankeyInvite(valid), { channel: 'x', pub: kp.pub, priv: kp.priv });
    assert.equal(parseChankeyInvite('plain text'), undefined);
    assert.equal(parseChankeyInvite('{"t":"other"}'), undefined);
    assert.equal(parseChankeyInvite(valid.replace(kp.pub, 'short')), undefined);
  } finally {
    A.stop();
    B.stop();
    const exit = await hub.stop(); // last live test in this file reaps the hub
    assert.ok(exit.signal === 'SIGTERM' || exit.code !== null, 'hub process reaped on teardown');
  }
});
