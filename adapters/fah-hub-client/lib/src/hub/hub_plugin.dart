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
import 'hub_client.dart';
import 'hub_config.dart';
import 'hub_messaging_repository.dart';
import 'identity.dart';

class HubPlugin implements FahPlugin {
  HubPlugin({Map<String, String>? environment})
      : environment = environment ?? Platform.environment;

  /// Injected environment (defaults to `Platform.environment`).
  final Map<String, String> environment;

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

  /// Loads the identity, connects to the hub, and starts inbox delivery.
  /// Idempotent.
  Future<void> start({HubIdentity? identity}) async {
    if (_repository != null) return;
    if (_config.url == null) {
      throw StateError('hub.url (or DAP_HUB_URL) is not configured');
    }
    if (_config.keyPath == null) {
      throw StateError('hub.keyPath (or DAP_KEY_PATH) is not configured');
    }
    _identity = identity ?? await HubIdentity.load(_config.keyPath!);
    _client = HubClient(config: _config, identity: _identity!);
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

  /// Our hub agent id once connected.
  String? get agentId => _client?.agentId;

  Future<void> dispose() async {
    await _errorSub?.cancel();
    await _repository?.dispose();
    _repository = null;
    _client = null;
  }
}
