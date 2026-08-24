/// `FahPlugin` (`.fah/packages.yaml` key `hub:`) wiring hub delivery into
/// the agent loop via `Agent.externalSteeringSource`.
///
/// Host wiring (upstream PR):
/// ```dart
/// final plugin = HubPlugin();
/// plugin.register(context);            // reads context.config['hub']
/// await plugin.start();
/// agent.externalSteeringSource = plugin.externalSteeringSource;
/// ```
library;

import 'dart:async';
import 'dart:io';

import '../fah/messaging.dart';
import '../fah/plugin.dart';
import 'channels.dart';
import 'dap_settings.dart';
import 'hub_client.dart';
import 'hub_config.dart';
import 'hub_messaging_repository.dart';
import 'identity.dart';

class HubPlugin implements FahPlugin {
  HubPlugin({Map<String, String>? environment, this.home})
      : environment = environment ?? Platform.environment;

  /// Injected environment (defaults to `Platform.environment`).
  final Map<String, String> environment;

  /// Home directory for the `~/.dap` zero-config layout (test seam;
  /// defaults to the platform home).
  final String? home;

  HubConfig _config = const HubConfig();
  PluginIO? _io;
  HubClient? _client;
  HubMessagingRepository? _repository;
  HubIdentity? _identity;
  StreamSubscription<HubError>? _errorSub;

  @override
  String get name => 'hub';

  @override
  void register(PluginContext context) {
    final section = context.config['hub'];
    _config = HubConfig.fromMap(
      section is Map<String, dynamic> ? section : const {},
      environment,
    );
    _io = context.io;
  }

  /// Loads the identity, connects to the hub, and starts inbox delivery —
  /// zero-config: url/keyPath default per [resolveDapSettings] (env >
  /// `~/.dap/config.json` > `ws://127.0.0.1:8787/ws` /
  /// `~/.dap/keys/fah/<name|hostname>.key`), and the channel store picks up
  /// the machine-shared `~/.dap/channels.json`. Idempotent.
  Future<void> start({HubIdentity? identity}) async {
    if (_repository != null) return;
    final settings =
        resolveDapSettings(config: _config, environment: environment, home: home);
    _identity = identity ?? await HubIdentity.load(settings.keyPath);
    _client = HubClient(
      config: HubConfig(
        url: settings.url,
        name: settings.name,
        channels: _config.channels,
        channelSecrets: _config.channelSecrets,
      ),
      identity: _identity!,
      channelStore: await ChannelStore.fromFile(settings.channelsFile),
    );
    // Hub rejections must never be silent: print them to the host terminal.
    _errorSub = _client!.errors.listen(
      (e) => _io?.writeln('[hub] hub rejected a frame — ${e.code}: ${e.msg}'),
    );
    _repository = HubMessagingRepository(_client!);
    await _repository!.start();
    _io?.writeln('[hub] connected as ${_client!.agentId}');
  }

  /// Inbound hub mail, drained at every turn boundary. Contract per
  /// upstream: never throws, empty list when nothing arrived.
  ExternalSteeringSource get externalSteeringSource => () async {
        final repository = _repository;
        final agentId = _client?.agentId;
        if (repository == null || agentId == null) return const [];
        try {
          return await repository.drain(agentId);
        } on Object {
          return const <AgentMessage>[];
        }
      };

  /// The backing repository (exposed for hosts that prefer direct access).
  HubMessagingRepository? get repository => _repository;

  /// Invites [agentId] to [channel] (see [HubClient.inviteTo]). The
  /// mirrored [PluginContext] subset carries no tool registry, so hosts
  /// register their `invite` tool around this one-liner; the upstream PR
  /// would wire `registerTool` directly.
  Future<void> inviteTo(String channel, String agentId) async {
    final repository = _repository;
    if (repository == null) {
      throw StateError('plugin not started — call start() first');
    }
    await repository.inviteTo(channel, agentId);
  }

  /// Connection snapshot for the `dap_status` tool (see
  /// [HubClient.status]). The mirrored [PluginContext] subset carries no
  /// tool registry, so hosts register their `status` tool around this
  /// one-liner; the upstream PR would wire `registerTool` directly.
  Future<HubStatus> status() async {
    final repository = _repository;
    if (repository == null) {
      throw StateError('plugin not started — call start() first');
    }
    return repository.status();
  }

  /// Hub presence list for the `dap_peers` tool (see [HubClient.peers]);
  /// same registerTool pattern as [status].
  Future<List<AgentInfo>> peers() async {
    final repository = _repository;
    if (repository == null) {
      throw StateError('plugin not started — call start() first');
    }
    return repository.peers();
  }

  /// Our hub agent id once connected.
  String? get agentId => _client?.agentId;

  Future<void> dispose() async {
    await _errorSub?.cancel();
    await _repository?.dispose();
    _repository = null;
    _client = null;
  }
}
