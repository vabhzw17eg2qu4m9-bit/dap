// Test helper: build the REAL hub binary once per test process and spawn it on
// an ephemeral localhost port (offline, deterministic). Readiness = poll
// GET /healthz under a deadline (never a blind sleep); teardown = SIGTERM and
// assert the process actually exits.
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

async function boot(): Promise<HubProc> {
  const dir = mkdtempSync(join(tmpdir(), 'dap-mcp-hub-'));
  const bin = join(dir, 'dap-hub');
  // Build the live hub from source (cached per test process; GOCACHE dedupes
  // work). -buildvcs=false: no git probing — hermetic and immune to
  // concurrent `git status` index-lock races from sibling test runs.
  execFileSync('go', ['build', '-buildvcs=false', '-o', bin, '.'], { cwd: join(repoRoot, 'hub'), stdio: 'pipe' });

  const port = await freePort();
  const adminToken = randomBytes(16).toString('hex');
  const child = spawn(bin, [
    '-addr', `127.0.0.1:${port}`,
    '-admin-token', adminToken,
    '-channels-file', join(dir, 'channels.json'),
  ], { stdio: ['ignore', 'ignore', 'pipe'] });

  const httpUrl = `http://127.0.0.1:${port}`;
  await pollHealth(`${httpUrl}/healthz`, 10_000);

  const stop = () => {
    const { promise, resolve } = Promise.withResolvers<{ code: number | null; signal: NodeJS.Signals | null }>();
    child.once('exit', (code, signal) => resolve({ code, signal }));
    child.kill('SIGTERM');
    setTimeout(() => child.kill('SIGKILL'), 5000).unref();
    return promise;
  };
  return { url: `${httpUrl}/ws`, httpUrl, adminToken, stop };
}

const hubs = new Map<string, Promise<HubProc>>();

/** Start (or reuse) a named live hub for this test process — tests that need
 *  TWO independent hubs pass distinct names. */
export function startHub(name = 'main'): Promise<HubProc> {
  let hub = hubs.get(name);
  if (!hub) hubs.set(name, (hub = boot()));
  return hub;
}
