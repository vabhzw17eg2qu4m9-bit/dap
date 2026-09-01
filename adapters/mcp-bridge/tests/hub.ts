// Test helper: build the REAL hub binary once per test process and spawn it on
// an ephemeral localhost port (offline, deterministic). Readiness = poll
// GET /healthz under a deadline (never a blind sleep); teardown = SIGTERM and
// assert the process actually exits.
import http from 'node:http';
import { WebSocketServer } from 'ws';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { createServer } from 'node:net';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

export interface HubProc {
  /** DAP WebSocket endpoint. */
  url: string;
  httpUrl: string;
  adminToken: string;
  /** The hub's master secret (HUB_MASTER_SECRET) — clients enroll with it. */
  masterSecret: string;
  /** SIGTERM the hub and resolve once the process is reaped. */
  stop(): Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
}

function freePort(): Promise<number> {
  const { promise, resolve, reject } = Promise.withResolvers<number>();
  const srv = createServer();
  srv.listen(0, '127.0.0.1', () => {
    const { port } = srv.address() as { port: number };
    srv.close(() => resolve(port));
  });
  srv.on('error', reject);
  return promise;
}

const delay = (ms: number): Promise<void> => {
  const { promise, resolve } = Promise.withResolvers<void>();
  setTimeout(resolve, ms);
  return promise;
};

function pollHealth(url: string, deadlineMs: number): Promise<void> {
  const deadline = Date.now() + deadlineMs;
  const attempt = async (): Promise<void> => {
    if (Date.now() > deadline) throw new Error(`hub not healthy after ${deadlineMs}ms`);
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      // not listening yet — retry
    }
    await delay(50);
    return attempt();
  };
  return attempt();
}

async function boot(masterSecret?: string): Promise<HubProc> {
  const dir = mkdtempSync(join(tmpdir(), 'dap-mcp-hub-'));
  const bin = join(dir, 'dap-hub');
  // Build the live hub from source (cached per test process; GOCACHE dedupes
  // work). -buildvcs=false: no git probing — hermetic and immune to
  // concurrent `git status` index-lock races from sibling test runs.
  execFileSync('go', ['build', '-buildvcs=false', '-o', bin, '.'], { cwd: join(repoRoot, 'hub'), stdio: 'pipe' });

  const port = await freePort();
  const adminToken = randomBytes(16).toString('hex');
  const master = masterSecret ?? randomBytes(32).toString('base64url');
  const child = spawn(bin, [
    '-addr', `127.0.0.1:${port}`,
    '-admin-token', adminToken,
    '-channels-file', join(dir, 'channels.json'),
    '-secrets-file', join(dir, 'secrets.json'),
  ], {
    env: { ...process.env, HUB_MASTER_SECRET: master },
    stdio: ['ignore', 'ignore', 'pipe'],
  });

  const httpUrl = `http://127.0.0.1:${port}`;
  await pollHealth(`${httpUrl}/healthz`, 10_000);

  const stop = () => {
    const { promise, resolve } = Promise.withResolvers<{ code: number | null; signal: NodeJS.Signals | null }>();
    child.once('exit', (code, signal) => resolve({ code, signal }));
    child.kill('SIGTERM');
    setTimeout(() => child.kill('SIGKILL'), 5000).unref();
    return promise;
  };
  return { url: `${httpUrl}/ws`, httpUrl, adminToken, masterSecret: master, stop };
}

const hubs = new Map<string, Promise<HubProc>>();

/** Start (or reuse) a named live hub for this test process — tests that need
 *  TWO independent hubs pass distinct names; a shared `masterSecret` makes
 *  both hubs accept the same enrollment credential (multi-hub dial flows). */
export function startHub(name = 'main', masterSecret?: string): Promise<HubProc> {
  let hub = hubs.get(name);
  if (!hub) hubs.set(name, (hub = boot(masterSecret)));
  return hub;
}

const AUTH_ENV_KEYS = ['DAP_MASTER_SECRET', 'DAP_CLIENT_SECRET', 'DAP_CONFIG_FILE'] as const;

/** Point dial auth at `hub`: DAP_MASTER_SECRET (enroll-mode) + a per-client
 *  DAP_CONFIG_FILE, so the issued client secret persists to a tmp file —
 *  never the operator's real ~/.dap. Clients sharing one config file share
 *  one enrolled identity. Returns a restore fn; keep calls LIFO when
 *  re-pointing mid-test (each snapshot restores independently). */
export function pinMasterAuth(hub: HubProc, configFile: string): () => void {
  const saved = Object.fromEntries(AUTH_ENV_KEYS.map((k) => [k, process.env[k]]));
  process.env.DAP_MASTER_SECRET = hub.masterSecret;
  delete process.env.DAP_CLIENT_SECRET;
  process.env.DAP_CONFIG_FILE = configFile;
  return () => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  };
}

// --- Stub hub: offline stand-in for the dial-auth / 401 contract tests ----

export interface StubHub {
  url: string;
  /** Authorization headers observed, in dial order. */
  auths: string[];
  /** Non-hello frames the hub received (enroll probes land here). */
  frames: Record<string, unknown>[];
  secret: string;
  /** Flip what an authenticated dial must present (default: the master). */
  setAuth(token: string): void;
  close(): Promise<void>;
}

/** Hub stand-in: 401s dials whose bearer != the expected token, otherwise
 *  upgrades, welcomes, and answers {"t":"enroll"} with an issued secret. */
export async function stubHub(opts: { reject?: boolean; expect?: string; secret?: string } = {}): Promise<StubHub> {
  let expected: string | undefined = opts.expect; // undefined = accept any bearer
  const state: StubHub = {
    url: '',
    auths: [],
    frames: [],
    secret: opts.secret ?? randomBytes(32).toString('base64url'),
    setAuth(token: string) { expected = token; },
    close: () => {
      const { promise, resolve } = Promise.withResolvers<void>();
      wss.close(() => srv.close(() => resolve()));
      return promise;
    },
  };
  const wss = new WebSocketServer({ noServer: true });
  const srv = http.createServer();
  srv.on('upgrade', (req, socket, head) => {
    state.auths.push(String(req.headers.authorization ?? ''));
    // Reject only when asked: blanket (reject) or a pinned expected token.
    if (opts.reject || (expected !== undefined && state.auths[state.auths.length - 1] !== `Bearer ${expected}`)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      ws.send(JSON.stringify({ op: 'welcome' }));
      ws.on('message', (data) => {
        const frame = JSON.parse(String(data)) as Record<string, unknown>;
        if (frame.op === 'hello') return;
        state.frames.push(frame);
        if (frame.t === 'enroll') ws.send(JSON.stringify({ t: 'enrolled', secret: state.secret }));
      });
    });
  });
  const { promise: listening, resolve: onListening } = Promise.withResolvers<void>();
  srv.listen(0, '127.0.0.1', onListening);
  await listening;
  const addr = srv.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  state.url = `ws://127.0.0.1:${port}/ws`;
  return state;
}
