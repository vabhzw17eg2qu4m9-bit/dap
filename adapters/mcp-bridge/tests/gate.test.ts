// DAP_MASTER_SECRET gate (shared DAP contract): unset or empty → the bridge
// is fully inert — the spawned server makes ZERO WebSocket attempts (the stub
// hub records every upgrade; the window outlives the first backoff retry),
// writes no identity key or config file, and every registered tool answers
// with the one honest error. With the secret set, init is unchanged: the
// bridge dials the stub and dap_status reports connected. Offline; stub hub
// = http server + ws upgrade (tests/hub.ts).
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { DapClient } from '../src/client.js';
import { DAP_DISABLED_MSG, buildServer } from '../src/server.js';
import { stubHub, type StubHub } from './hub.js';
import { delay, pollUntil } from './util.js';

const here = dirname(fileURLToPath(import.meta.url));

// Determinism: gate keys are snapshotted, cleared, and restored; each test
// pins exactly what it asserts on.
const GATE_KEYS = [
  'DAP_HUB_URL', 'DAP_KEY_PATH', 'DAP_AGENT_NAME', 'DAP_CHANNELS_FILE', 'DAP_CHANNELS',
  'DAP_MASTER_SECRET', 'DAP_CLIENT_SECRET', 'DAP_CONFIG_FILE',
] as const;
const savedEnv = Object.fromEntries(GATE_KEYS.map((k) => [k, process.env[k]]));
for (const k of GATE_KEYS) delete process.env[k];
test.after(() => {
  for (const [k, v] of Object.entries(savedEnv)) if (v !== undefined) process.env[k] = v;
});

const tmp = (): string => mkdtempSync(join(tmpdir(), 'dap-mcp-gate-'));
const textOf = (res: { content?: Array<{ type: string; text?: string }> }): string =>
  res.content?.find((c) => c.type === 'text')?.text ?? '';

/** All eight tools with minimal valid arguments — registration and the
 *  honest error are asserted for each while disabled. */
const TOOL_ARGS: Record<string, Record<string, string>> = {
  dap_send: { channel: 'gate', text: 'hi' },
  dap_dm: { agent: '0123456789abcdef', text: 'hi' },
  dap_invite: { channel: 'gate', agent: '0123456789abcdef' },
  dap_inbox: {},
  dap_whois: { agent: '0123456789abcdef' },
  dap_status: {},
  dap_peers: {},
  dap_connect: { host: '127.0.0.1:59999' },
};

/** Child env for the spawned dist/server.js: HOME pinned to a tmp dir, gate
 *  keys pinned explicitly (master only when passed), the rest inherited. */
const childEnv = (home: string, hub: StubHub, master?: string): Record<string, string> => {
  const e = { ...process.env, HOME: home } as Record<string, string>;
  delete e.DAP_MASTER_SECRET;
  delete e.DAP_CLIENT_SECRET;
  e.DAP_HUB_URL = hub.url;
  e.DAP_CONFIG_FILE = join(home, 'config.json');
  if (master !== undefined) e.DAP_MASTER_SECRET = master;
  return e;
};

test('gate boundary: unset and empty disable, before any client side effect (in-process)', async () => {
  const hub = await stubHub();
  const dir = tmp();
  const c = new DapClient({ url: hub.url, keyPath: join(dir, 'agent.key'), channelsFile: join(dir, 'channels.json') });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  const mcp = new Client({ name: 'dap-gate-unit', version: '0.1.0' });
  await buildServer(c).connect(serverSide);
  await mcp.connect(clientSide);
  try {
    for (const master of [undefined, '']) {
      if (master === undefined) delete process.env.DAP_MASTER_SECRET;
      else process.env.DAP_MASTER_SECRET = master;
      const res = await mcp.callTool({ name: 'dap_status', arguments: {} });
      assert.equal(res.isError, true, `master=${JSON.stringify(master)} is an honest failure`);
      assert.equal(textOf(res), DAP_DISABLED_MSG, 'the one honest error text');
      assert.equal(hub.auths.length, 0, 'no dial while disabled');
    }
  } finally {
    delete process.env.DAP_MASTER_SECRET;
    await mcp.close();
    await hub.close();
  }
});

test('no DAP_MASTER_SECRET: spawned bridge never dials, every tool answers the honest error', async () => {
  const hub = await stubHub();
  const home = tmp();
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(here, '..', 'dist', 'server.js')],
    env: childEnv(home, hub),
    stderr: 'ignore',
  });
  const mcp = new Client({ name: 'dap-gate-off', version: '0.1.0' });
  await mcp.connect(transport);
  try {
    // Outlive the ungated startup path: an ungated bridge dials at t=0 and
    // retries ~1s later (capped backoff). The gated one stays silent. (Wall
    // clock — timers cannot be faked across the child process boundary.)
    await delay(1600);
    assert.equal(hub.auths.length, 0, 'zero WebSocket connection attempts');

    for (const [name, args] of Object.entries(TOOL_ARGS)) {
      const res = await mcp.callTool({ name, arguments: args });
      assert.equal(res.isError, true, `${name} is an honest failure`);
      assert.equal(textOf(res), DAP_DISABLED_MSG, `${name} error text`);
    }
    assert.ok(!existsSync(join(home, '.dap')), 'no identity key written under HOME');
    assert.ok(!existsSync(join(home, 'config.json')), 'no config written (dap_connect stays side-effect-free)');
  } finally {
    await mcp.close(); // closes stdio; the server child exits with it
    await hub.close();
  }
});

test('DAP_MASTER_SECRET set: spawned bridge dials the stub and dap_status reports connected', async () => {
  const hub = await stubHub();
  const home = tmp();
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(here, '..', 'dist', 'server.js')],
    env: childEnv(home, hub, hub.secret), // enroll-mode: unchanged pre-gate behavior
    stderr: 'ignore',
  });
  const mcp = new Client({ name: 'dap-gate-on', version: '0.1.0' });
  await mcp.connect(transport);
  try {
    const status = async (): Promise<{ connected: boolean; welcomes: number }> =>
      JSON.parse(textOf(await mcp.callTool({ name: 'dap_status', arguments: {} }))) as { connected: boolean; welcomes: number };
    await pollUntil(async () => (await status()).connected === true, 5000, 25);
    const st = await status();
    assert.equal(st.welcomes >= 1, true, 'handshake completed');
  } finally {
    await mcp.close();
    await hub.close();
  }
});
