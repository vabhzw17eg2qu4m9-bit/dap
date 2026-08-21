import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

/** Optional persisted settings: ~/.dap/config.json (all fields optional). */
export interface DapFileConfig {
  url?: string;
  name?: string;
  keyPath?: string;
  channelsFile?: string;
}

export const DEFAULT_URL = 'ws://127.0.0.1:8787/ws';

export const optStr = (v: unknown): string | undefined => (typeof v === 'string' && v.length > 0 ? v : undefined);

/** Read ~/.dap/config.json; a missing or invalid file counts as absent. */
export function readDapConfig(file = path.join(os.homedir(), '.dap', 'config.json')): DapFileConfig {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8')) as DapFileConfig;
  } catch {
    return {};
  }
}

export interface SettingsOverrides {
  url?: string;
  keyPath?: string;
  name?: string;
  channelsFile?: string;
}

export interface DapSettings {
  url: string;
  keyPath: string;
  name?: string;
  channelsFile: string;
}

/** Precedence: explicit override > env var > ~/.dap/config.json > defaults.
 *  channelsFile defaults to ~/.dap/channels.json so no env is needed at all. */
export function resolveDapSettings(overrides: SettingsOverrides = {}): DapSettings {
  const home = os.homedir();
  const file = readDapConfig();
  return {
    url: overrides.url ?? optStr(process.env.DAP_HUB_URL) ?? file.url ?? DEFAULT_URL,
    keyPath:
      overrides.keyPath ??
      optStr(process.env.DAP_KEY_PATH) ??
      file.keyPath ??
      path.join(home, '.omp', 'dap-key.json'),
    name: overrides.name ?? optStr(process.env.DAP_AGENT_NAME) ?? file.name,
    channelsFile:
      overrides.channelsFile ??
      optStr(process.env.DAP_CHANNELS_FILE) ??
      file.channelsFile ??
      path.join(home, '.dap', 'channels.json'),
  };
}
