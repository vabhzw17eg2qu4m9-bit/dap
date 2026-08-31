// dap_connect (the manual invitation): the bridge starts on hub1, then
// retargets AT RUNTIME to a SECOND live hub — host given WITHOUT scheme,
// new name (new identity: name-derived key file under ~/.dap/keys/mcp/),
// default room lobby. Asserts: normalized ws url, new agentId, welcome from
// hub2, lobby joined + E2E round-trip there, config persisted under
// DAP_CONFIG_FILE, and hub1 seeing the disconnect.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { DapClient } from '../src/client.js';
import { loadChannelKeys } from '../src/channels.js';
import { pinMasterAuth, startHub } from './hub.js';
import { pollUntil } from './util.js';

const here = dirname(fileURLToPath(import.meta.url));

interface InboxResult {
  count: number;
  messages: Array<{ dm: boolean; channel?: string; from: string; text: string }>;
}

const textOf = (result: { content?: Array<{ type: string; text?: string }> }): Record<string, unknown> =>
  JSON.parse(result.content?.find((c) => c.type === 'text')?.text ?? '{}') as Record<string, unknown>;

test('dap_connect: runtime retarget to a second hub — new identity, default room, persisted config, hub1 disconnect', async () => {
  // One shared master secret: the bridge re-enrolls on hub2 under the same
  // enrollment credential (client secrets are hub-scoped, the master is not).
  const hub1 = await startHub();
  const hub2 = await startHub('second', hub1.masterSecret);
  const host2 = new URL(hub2.url).host; // scheme-less host:port — normalization must add ws:// and /ws

  // Hub1 watcher: observes the bridge online, then offline after the retarget.
  const watcherDir = mkdtempSync(join(tmpdir(), 'dap-con-w-'));
  const watcher = new DapClient({ url: hub1.url, keyPath: join(watcherDir, 'w.key'), name: 'connect-watch' });
  const unWatcher = pinMasterAuth(hub1, join(watcherDir, 'config.json'));
  watcher.start();
  await watcher.ready();

  // Server child: everything writable pinned under tmp — HOME (name-derived
  // key path lands at <tmp>/.dap/keys/mcp/), config, key and channels files.
  const dir = mkdtempSync(join(tmpdir(), 'dap-con-'));
  const configFile = join(dir, 'config.json');
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(here, '..', 'dist', 'server.js')],
    env: {
      ...process.env,
      HOME: dir,
      DAP_HUB_URL: hub1.url,
      DAP_KEY_PATH: join(dir, 'agent.key'),
      DAP_CHANNELS_FILE: join(dir, 'channels.json'),
      DAP_CONFIG_FILE: configFile,
      DAP_MASTER_SECRET: hub1.masterSecret, // phase 1 enrolls; the issued secret persists to the config file
      DAP_AGENT_NAME: 'connect-a',
    } as Record<string, string>,
    stderr: 'ignore',
  });
  const client = new Client({ name: 'dap-connect-check', version: '0.1.0' });
  await client.connect(transport);

  const status = async (): Promise<Record<string, unknown>> => textOf(await client.callTool({ name: 'dap_status', arguments: {} }));

  // Phase 1: live on hub1 as connect-a.
  await pollUntil(async () => (await status()).connected === true);
  const before = await status();
  assert.equal(before.url, hub1.url);
  assert.equal(before.name, 'connect-a');
  const firstId = String(before.agentId);
  await pollUntil(async () => (await watcher.presence()).some((a) => a.agentId === firstId && a.online === true));

  // Phase 1 must have enrolled: the issued client secret is in the config.
  const phase1 = JSON.parse(readFileSync(configFile, 'utf8')) as Record<string, unknown>;
  assert.ok(typeof phase1.clientSecret === 'string' && phase1.clientSecret.length > 0, 'phase 1 enrolled');
  // Client secrets are hub-scoped: drop the hub1-issued secret so phase 2
  // re-enrolls on hub2 with the shared master credential.
  delete phase1.clientSecret;
  writeFileSync(configFile, JSON.stringify(phase1, null, 2) + '\n', { mode: 0o600 });

  // Phase 2: dap_connect to hub2 without scheme, new name, default room.
  const res = textOf(await client.callTool({ name: 'dap_connect', arguments: { host: host2, name: 'x', channel: 'lobby' } }));
  assert.equal(res.ok, true);
  assert.equal(res.url, `ws://${host2}/ws`); // ws:// added, /ws path defaulted
  assert.equal(res.name, 'x');
  assert.notEqual(res.agentId, firstId); // new name = new identity = new agentId
  assert.deepEqual(res.channels, ['lobby']);

  // Welcome from hub2: connected at the normalized url under the new id.
  await pollUntil(async () => {
    const st = await status();
    return st.connected === true && st.url === `ws://${host2}/ws`;
  });
  const after = await status();
  assert.equal(after.agentId, res.agentId);
  assert.equal(after.name, 'x');

  // Lobby joined on hub2: an E2E send round-trips (a send joins first).
  const sent = textOf(await client.callTool({ name: 'dap_send', arguments: { channel: 'lobby', text: 'retargeted' } }));
  assert.equal(sent.ok, true);
  assert.equal(sent.from, res.agentId);
  let inbox = {} as InboxResult;
  await pollUntil(async () => {
    inbox = textOf(await client.callTool({ name: 'dap_inbox', arguments: {} })) as unknown as InboxResult;
    return inbox.count >= 1;
  });
  assert.equal(inbox.messages.find((m) => m.channel === 'lobby')?.text, 'retargeted');

  // Hub1 saw the disconnect: the old identity is offline in its registry.
  await pollUntil(async () => !(await watcher.presence()).some((a) => a.agentId === firstId && a.online === true));

  // Persistence: config file (url/name/channels), name-derived key 0600, lobby keypair.
  const cfg = JSON.parse(readFileSync(configFile, 'utf8')) as Record<string, unknown>;
  assert.equal(cfg.url, `ws://${host2}/ws`);
  assert.equal(cfg.name, 'x');
  assert.deepEqual(cfg.channels, ['lobby']);
  assert.ok(typeof cfg.clientSecret === 'string', 'phase 2 re-enrolled on hub2');
  const keyFile = join(dir, '.dap', 'keys', 'mcp', 'x.key');
  assert.equal(existsSync(keyFile), true);
  assert.equal(statSync(keyFile).mode & 0o777, 0o600);
  assert.ok(loadChannelKeys(join(dir, 'channels.json')).lobby?.priv);

  await client.close(); // closes stdio; the server child exits with it
  watcher.stop();
  unWatcher();
  for (const hub of [hub1, hub2]) {
    const exit = await hub.stop();
    assert.ok(exit.signal === 'SIGTERM' || exit.code !== null, 'hub process reaped on teardown');
  }
});
