/// Zero-config settings shared by every DAP adapter (same `~/.dap`
/// layout): precedence explicit config (`.fah/packages.yaml` `hub:` section
/// — env wins within that tier, see [HubConfig.fromMap]) > env
/// (`DAP_HUB_URL`/`DAP_KEY_PATH`/`DAP_AGENT_NAME`/`DAP_CHANNELS_FILE`) >
/// `~/.dap/config.json` > defaults.
///
/// Defaults keep onboarding to a single env var: url
/// `ws://127.0.0.1:8787/ws`, identity `~/.dap/keys/fah/<name|hostname>.key`
/// (auto-generated 0600 on first use — a second agent on the machine needs
/// nothing but `DAP_AGENT_NAME`), channels file `~/.dap/channels.json`
/// (machine-shared with the other adapters).
library;

import 'dart:convert';
import 'dart:io';

import 'hub_config.dart';

/// Optional persisted settings: `~/.dap/config.json` (all fields optional).
class DapSettings {
  const DapSettings({
    required this.url,
    required this.keyPath,
    required this.channelsFile,
    this.name,
  });

  final String url;
  final String keyPath;
  final String channelsFile;
  final String? name;
}

const String defaultDapUrl = 'ws://127.0.0.1:8787/ws';

const String envChannelsFile = 'DAP_CHANNELS_FILE';

/// `~` on POSIX and Windows alike (dart:io has no homedir).
String defaultHome([Map<String, String> environment = const {}]) =>
    environment['HOME'] ??
    environment['USERPROFILE'] ??
    Directory.current.path;

String _withTrailingSlash(String path) => path.endsWith('/') ? path : '$path/';

/// Default identity file, derived from the agent name (or hostname):
/// `~/.dap/keys/fah/<sanitized>.key`.
String defaultDapKeyPath(String? name, String home) {
  final who = (name ?? Platform.localHostname)
      .replaceAll(RegExp(r'[^a-zA-Z0-9._-]'), '_');
  return '${_withTrailingSlash(home)}.dap/keys/fah/$who.key';
}

/// Reads `~/.dap/config.json`; a missing or invalid file counts as absent.
Map<String, dynamic> readDapConfig(String file) {
  try {
    final decoded = jsonDecode(File(file).readAsStringSync());
    return decoded is Map<String, dynamic> ? decoded : {};
  } on Object {
    return {};
  }
}

/// Resolves the effective settings (see library doc for precedence).
/// [config] is the already env-merged `hub:` section ([HubConfig.fromMap]).
DapSettings resolveDapSettings({
  HubConfig config = const HubConfig(),
  Map<String, String> environment = const {},
  String? home,
}) {
  final root = _withTrailingSlash(home ?? defaultHome(environment));
  final file = readDapConfig('${root}.dap/config.json');
  String? optStr(String key) =>
      file[key] is String && (file[key] as String).isNotEmpty
          ? file[key] as String
          : null;
  final name = config.name ?? optStr('name');
  return DapSettings(
    url: config.url ?? optStr('url') ?? defaultDapUrl,
    keyPath:
        config.keyPath ?? optStr('keyPath') ?? defaultDapKeyPath(name, root),
    name: name,
    channelsFile:
        environment[envChannelsFile] ?? optStr('channelsFile') ?? '${root}.dap/channels.json',
  );
}
