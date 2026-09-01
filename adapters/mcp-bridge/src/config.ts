// Settings resolution (zero-config onboarding): explicit arg > DAP_* env >
// ~/.dap/config.json > defaults. An agent needs at most DAP_AGENT_NAME; the
// url, identity file and channels file all have defaults. Mirrors
// omp-extension/src/config.ts — differences: the identity default lives in the
// per-adapter subdirectory ~/.dap/keys/mcp/.
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

/** A pending by-name invite: armed by `dap_invite` for a user not yet on
 *  the hub; delivered automatically when that name comes online. */
export interface PendingInvite {
  name: string;
  channel: string;
}

/** Optional persisted settings: ~/.dap/config.json (all fields optional). */
export interface DapFileConfig {
  url?: string;
  name?: string;
  keyPath?: string;
  channelsFile?: string;
  /** Default rooms: ensured (keygen if unknown) and auto-joined after connect. */
  channels?: string[];
  /** Armed invite-by-name entries; removed once delivered. */
  invites?: PendingInvite[];
  /** Hub-issued client secret, persisted after master-secret enrollment; the
   *  master secret itself is never persisted. */
  clientSecret?: string;
}

export interface DapSettings {
  url: string;
  keyPath: string;
  name?: string;
  channelsFile: string;
}

export const DEFAULT_URL = 'ws://127.0.0.1:8787/ws';

export const optStr = (v: unknown): string | undefined => (typeof v === 'string' && v.length > 0 ? v : undefined);

/** Config file path: DAP_CONFIG_FILE env (tests pin a tmp path) > ~/.dap/config.json. */
const defaultConfigFile = (): string => optStr(process.env.DAP_CONFIG_FILE) ?? path.join(os.homedir(), '.dap', 'config.json');

/** Read the config file; a missing or invalid file counts as absent.
 *  `invites` is normalized to [] (files written before the key lack it). */
export function readDapConfig(file = defaultConfigFile()): DapFileConfig {
  try {
    const cfg = JSON.parse(fs.readFileSync(file, 'utf8')) as DapFileConfig;
    // `invites` is normalized to [] (files written before the key lack it).
    return { ...cfg, invites: Array.isArray(cfg.invites) ? cfg.invites : [] };
  } catch {
    return { invites: [] };
  }
}

/** Merge `update` into the config file (read-modify-write, mkdir on demand):
 *  dap_connect persists host/name/default-rooms so the next launch
 *  auto-connects with the same identity and auto-joins the same rooms.
 *  `invites` is the authoritative list — delivered entries are removed by
 *  the caller. `clientSecret: null` purges the cached secret (401 stale-cache
 *  recovery); a string persists it. */
export function persistDapConfig(
  update: { url?: string; name?: string; channels?: string[]; invites?: PendingInvite[]; clientSecret?: string | null },
  file = defaultConfigFile(),
): void {
  const cur = readDapConfig(file);
  const next: DapFileConfig = { ...cur };
  if (update.url) next.url = update.url;
  if (update.name) next.name = update.name;
  if (update.channels?.length) {
    next.channels = [...new Set([...(cur.channels ?? []), ...update.channels])];
  }
  if (update.invites) next.invites = update.invites;
  if (update.clientSecret === null) delete next.clientSecret;
  else if (update.clientSecret) next.clientSecret = update.clientSecret;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(next, null, 2) + '\n', { mode: 0o600 });
}

/** Default identity file: ~/.dap/keys/mcp/<name|hostname>.key — the
 *  per-adapter subdirectory keeps this bridge's keys apart from the other
 *  adapters on the same machine. Auto-generated 0600 by the client on first
 *  use, so a second agent needs nothing but DAP_AGENT_NAME. */
export function defaultKeyPath(name: string | undefined): string {
  const who = (name ?? os.hostname()).replace(/[^a-zA-Z0-9._-]/g, '_');
  return path.join(os.homedir(), '.dap', 'keys', 'mcp', `${who}.key`);
}

/** Precedence: explicit override > env var > ~/.dap/config.json > defaults.
 *  channelsFile defaults to ~/.dap/channels.json — SHARED across adapters. */
export function resolveDapSettings(
  overrides: { url?: string; keyPath?: string; name?: string; channelsFile?: string } = {},
): DapSettings {
  const home = os.homedir();
  const file = readDapConfig();
  const name = overrides.name ?? optStr(process.env.DAP_AGENT_NAME) ?? file.name;
  return {
    url: overrides.url ?? optStr(process.env.DAP_HUB_URL) ?? file.url ?? DEFAULT_URL,
    keyPath: overrides.keyPath ?? optStr(process.env.DAP_KEY_PATH) ?? file.keyPath ?? defaultKeyPath(name),
    name,
    channelsFile:
      overrides.channelsFile ??
      optStr(process.env.DAP_CHANNELS_FILE) ??
      file.channelsFile ??
      path.join(home, '.dap', 'channels.json'),
  };
}
