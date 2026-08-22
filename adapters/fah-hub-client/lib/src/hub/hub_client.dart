/// DAP/1 WebSocket hub client (docs/protocol.md): signed hello handshake,
/// E2E-encrypted channel/DM sends, whois-before-first-DM, flush after
/// welcome, and reconnect with exponential backoff (1 s → 30 s, reset after
/// a successful welcome).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';

import 'canonical.dart';
import 'channels.dart';
import 'hub_config.dart';
import 'identity.dart';
import 'payload_crypto.dart';

/// A hub `error` frame.
class HubError implements Exception {
  HubError(this.code, this.msg);

  final String code;
  final String msg;

  @override
  String toString() => 'HubError($code): $msg';
}

/// Peer directory entry returned by whois/presence.
class AgentInfo {
  AgentInfo({
    required this.agentId,
    required this.online,
    this.name,
    this.signingPubkeyB64,
    this.dhPublicKey,
  });

  final String agentId;
  final String? name;
  final bool online;
  final String? signingPubkeyB64;

  /// Peer X25519 public key for payload E2E (the hello `x25519` field,
  /// echoed by `agent_info`).
  final SimplePublicKey? dhPublicKey;
}

/// One inbound `msg` frame: decrypted when a key is available.
class InboundMessage {
  InboundMessage({
    required this.id,
    required this.from,
    required this.ts,
    this.channel,
    this.to,
    this.plaintext,
  });

  final String id;
  final String from;
  final int ts;
  final String? channel;
  final String? to;

  /// Null when no key is configured to decrypt (payload still delivered).
  final String? plaintext;
}

class HubClient {
  HubClient({
    required this.config,
    required this.identity,
    this.channelStore,
    Duration Function(int attempt)? backoff,
    this.pingInterval = const Duration(seconds: 20),
  }) : backoff = backoff ?? HubClient.defaultBackoff;

  final HubConfig config;
  final HubIdentity identity;

  /// Zero-config channel-key lifecycle (auto-keygen on first send, invite
  /// accept, auto-join). Null keeps the explicit-config-only behavior:
  /// unknown channels fail honestly with [ArgumentError].
  final ChannelStore? channelStore;
  final Duration Function(int attempt) backoff;

  /// Client keepalive interval. Native mechanism: dart:io WebSocket
  /// auto-pings the hub every [pingInterval] and closes the socket when the
  /// pong does not come back in time — which drops us into the reconnect
  /// loop below (re-hello → flush → hold) before a user send buffers into a
  /// half-open corpse. Null disables it.
  final Duration? pingInterval;

  WebSocket? _ws;
  StreamSubscription? _subscription;
  bool _closing = false;
  int _reconnectAttempt = 0;

  final _firstWelcome = Completer<String>();
  Completer<bool>? _welcomeCompleter;
  Completer<int>? _flushCompleter;
  Completer<void>? _presenceCompleter;
  List<AgentInfo>? _presenceResult;
  final _pendingWhois = <String, Completer<AgentInfo>>{};
  final _whoisCache = <String, AgentInfo>{};

  final _inbound = StreamController<InboundMessage>.broadcast();
  final _errors = StreamController<HubError>.broadcast();

  /// All inbound `msg` frames, oldest first.
  Stream<InboundMessage> get inbound => _inbound.stream;

  /// Every hub `error` frame received (unknown_agent, access_denied, …).
  /// Hub rejections must never be silent — listeners surface them.
  Stream<HubError> get errors => _errors.stream;

  /// True while a welcome was received on a currently open socket.
  bool get connected =>
      _ws != null && _ws!.readyState == WebSocket.open && _firstWelcome.isCompleted;

  /// Completes with our agent id after the first welcome.
  Future<String> get welcomed => _firstWelcome.future;

  /// Our hub agent id once the hub welcomed us.
  String? agentId;

  /// 1 s doubling, capped at 30 s (spec "Client reconnect").
  static Duration defaultBackoff(int attempt) {
    final seconds = 1 << (attempt - 1);
    return seconds > 30
        ? const Duration(seconds: 30)
        : Duration(seconds: seconds);
  }

  /// Connects and keeps the connection alive until [disconnect]. Completes
  /// after the first welcome; a later drop re-hellos (after backoff) and
  /// flushes the offline mailbox again. A rejected hello completes this
  /// future with [HubError].
  bool _loopStarted = false;

  Future<String> connect() {
    if (config.url == null) {
      return Future.error(StateError('hub config has no url'));
    }
    if (!_loopStarted) {
      _loopStarted = true;
      _closing = false;
      unawaited(_connectLoop());
    }
    return _firstWelcome.future;
  }

  Future<void> _connectLoop() async {
    while (!_closing) {
      var welcomed = false;
      try {
        welcomed = await _cycle();
      } on HubError catch (error) {
        // pre-welcome rejection (bad signature, …) — fatal, stop retrying
        if (!_firstWelcome.isCompleted) _firstWelcome.completeError(error);
        return;
      } on Object {
        // unexpected cycle failure — treat as unwelcomed cycle
      }
      if (_closing) return;
      if (welcomed) _reconnectAttempt = 0;
      _reconnectAttempt++;
      await Future<void>.delayed(backoff(_reconnectAttempt));
    }
  }

  /// One connect → hello → welcome → flush → hold-until-close cycle.
  /// Returns whether the hub welcomed us; only pre-welcome hub rejections
  /// throw ([HubError]) — transport failures just return `false`.
  Future<bool> _cycle() async {
    final WebSocket ws;
    try {
      ws = await WebSocket.connect(config.url!);
    } on Object {
      _failPending('connect failed');
      return false;
    }
    _ws = ws;
    ws.pingInterval = pingInterval; // native liveness watchdog (see field doc)
    final welcomed = Completer<bool>();
    final done = Completer<void>();
    _welcomeCompleter = welcomed;
    _subscription = ws.listen(
      (dynamic data) => _onFrame(data as String),
      onDone: () => _abandon(welcomed, done),
      onError: (Object _) => _abandon(welcomed, done),
      cancelOnError: true,
    );
    ws.add(jsonEncode(await _helloFrame()));
    final bool ok;
    try {
      ok = await welcomed.future;
    } on StateError {
      // transport died before welcome — plain retry
      await done.future;
      return false;
    } on HubError {
      // hub rejected the hello — close our side, propagate
      await _subscription?.cancel();
      await ws.close();
      rethrow;
    }
    if (ok) {
      agentId = _welcomedAgentId;
      if (!_firstWelcome.isCompleted) _firstWelcome.complete(agentId);
      await _joinKnownChannels();
      await _flushAfterWelcome();
    }
    await done.future;
    return ok;
  }

  String? _welcomedAgentId;

  void _abandon(Completer<bool> welcomed, Completer<void> done) {
    if (!welcomed.isCompleted) {
      welcomed.completeError(StateError('connection closed before welcome'));
    }
    _failPending('connection closed');
    if (!done.isCompleted) done.complete();
  }

  Future<void> disconnect() async {
    _closing = true;
    await _subscription?.cancel();
    await _ws?.close();
    _failPending('disconnecting');
    if (!_firstWelcome.isCompleted) {
      _firstWelcome.completeError(StateError('disconnected'));
    }
    await _inbound.close();
    await _errors.close();
  }

  // ---- outbound ----

  Future<Map<String, dynamic>> _helloFrame() async {
    final frame = <String, dynamic>{
      'op': 'hello',
      'v': 1,
      'pubkey': identity.signingPubkeyB64,
      'x25519': identity.dhPubkeyB64,
      'nonce': randomHex(16),
      'ts': DateTime.now().millisecondsSinceEpoch,
      if (config.name != null) 'name': config.name,
    };
    frame['sig'] = await signFrame(frame, identity.signingKeyPair);
    return frame;
  }

  /// Channel membership (spec § join): the first join creates the channel
  /// and registers [chanPubkeyB64]; re-join is idempotent — safe after
  /// every reconnect.
  void join(String channel, String chanPubkeyB64) =>
      _send({'op': 'join', 'channel': channel, 'chanPubkey': chanPubkeyB64});

  /// Membership: join every known channel after each welcome (idempotent,
  /// reconnect-safe). A failed join is transient — the reconnect loop
  /// retries after the next welcome.
  Future<void> _joinKnownChannels() async {
    try {
      final store = channelStore;
      if (store != null) {
        for (final entry in store.all.entries) {
          join(entry.key, entry.value.pub);
        }
      }
      for (final entry in config.channels.entries) {
        if (store == null || !store.knows(entry.key)) join(entry.key, entry.value);
      }
    } on Object {
      // socket dropped mid-join — the reconnect loop re-runs us
    }
  }

  Future<void> sendToChannel(String channel, String text) async {
    final pubkeyB64 = await _channelPubFor(channel);
    await _sendEncrypted(
      extra: {'channel': channel},
      recipientDhPubkey: _dhPubkey(pubkeyB64),
      aadTarget: channel,
      text: text,
    );
  }

  /// Explicit config first; otherwise the store auto-generates + persists
  /// the keypair and joins — creating the channel (spec § join: senders
  /// only need the channel public key).
  Future<String> _channelPubFor(String channel) async {
    final explicit = config.channels[channel];
    if (explicit != null) return explicit;
    final store = channelStore;
    if (store == null) {
      throw ArgumentError('no channel pubkey configured for "$channel"');
    }
    final keys = await _channelKeysOrCreate(channel, store);
    return keys.pub;
  }

  /// Keys for [channel] via [store], joining too when the keypair was just
  /// created (zero-config channel creation).
  Future<ChannelKeys> _channelKeysOrCreate(
      String channel, ChannelStore store) async {
    final existed = store.knows(channel);
    final keys = await store.keysFor(channel);
    if (!existed) join(channel, keys.pub);
    return keys;
  }

  /// Invites [toAgentId] to [channel]: DMs them the channel keypair as a
  /// normal E2E DM whose plaintext is the chankey JSON (spec § "Channel key
  /// distribution"). Trust model: possession of the channel private key IS
  /// v1 membership; the introducer is whoever DM'd you the key.
  Future<void> inviteTo(String channel, String toAgentId) async {
    final store = channelStore;
    final keys = store != null
        ? await _channelKeysOrCreate(channel, store)
        : await _keysFromConfig(channel);
    await sendDm(
      toAgentId,
      jsonEncode(
          {'t': 'chankey', 'channel': channel, 'pub': keys.pub, 'priv': keys.priv}),
    );
  }

  /// Explicit-config fallback: priv is required (it is the invite payload),
  /// pub is derived from it when only the secret is configured.
  Future<ChannelKeys> _keysFromConfig(String channel) async {
    final priv = config.channelSecrets[channel];
    if (priv == null) {
      throw StateError(
          'no channel key for "$channel" — an invite needs the private key');
    }
    var pub = config.channels[channel];
    final fromSeed = await X25519().newKeyPairFromSeed(base64Decode(priv));
    pub ??= base64Encode((await fromSeed.extractPublicKey()).bytes);
    return ChannelKeys(pub: pub, priv: priv);
  }

  /// Sends an E2E DM. Whois resolves the peer's X25519 pubkey on first use.
  Future<void> sendDm(String toAgentId, String text) async {
    final peer = await whois(toAgentId);
    final peerKey = peer.dhPublicKey;
    if (peerKey == null) {
      throw StateError('hub returned no x25519 pubkey for "$toAgentId"');
    }
    await _sendEncrypted(
      extra: {'to': toAgentId},
      recipientDhPubkey: peerKey,
      aadTarget: toAgentId,
      text: text,
    );
  }

  Future<void> _sendEncrypted({
    required Map<String, dynamic> extra,
    required SimplePublicKey recipientDhPubkey,
    required String aadTarget,
    required String text,
  }) async {
    final id = newFrameId();
    final ciphertext = await encryptPayload(
      senderDhKeyPair: identity.dhKeyPair,
      recipientDhPubkey: recipientDhPubkey,
      frameId: id,
      aadTarget: aadTarget,
      plaintext: text,
    );
    final frame = <String, dynamic>{
      'op': 'send',
      ...extra,
      'id': id,
      'ts': DateTime.now().millisecondsSinceEpoch,
      'ciphertext': ciphertext,
    };
    frame['sig'] = await signFrame(frame, identity.signingKeyPair);
    _send(frame);
  }

  /// Whois with caching — the spec-required lookup before a first DM.
  Future<AgentInfo> whois(String targetAgentId) async {
    final cached = _whoisCache[targetAgentId];
    if (cached != null) return cached;
    final completer = Completer<AgentInfo>();
    _pendingWhois[targetAgentId] = completer;
    try {
      _send({'op': 'whois', 'agentId': targetAgentId});
    } on Object {
      _pendingWhois.remove(targetAgentId); // never answered — don't leak it
      rethrow;
    }
    final info = await completer.future;
    _whoisCache[targetAgentId] = info;
    return info;
  }

  /// Drains the hub-side offline mailbox; returns the drained count.
  Future<int> flush() {
    final completer = Completer<int>();
    _flushCompleter = completer;
    _send({'op': 'flush'});
    return completer.future;
  }

  Future<List<AgentInfo>> presenceQuery() {
    final completer = Completer<void>();
    _presenceCompleter = completer;
    _presenceResult = null;
    _send({'op': 'presence_query'});
    return completer.future.then((_) => _presenceResult ?? const []);
  }

  void _send(Map<String, dynamic> frame) {
    final ws = _ws;
    if (ws == null || ws.readyState != WebSocket.open) {
      throw StateError(
          'not connected to the hub (reconnecting with backoff — retry in a moment)');
    }
    ws.add(jsonEncode(frame));
  }

  // ---- inbound ----

  Future<void> _onFrame(Object data) async {
    final Map<String, dynamic> frame;
    try {
      frame = (jsonDecode(data as String) as Map).cast<String, dynamic>();
    } on FormatException {
      return;
    }
    switch (frame['op'] as String?) {
      case 'welcome':
        _welcomedAgentId = frame['agentId'] as String?;
        _completeWelcome(true);
      case 'error':
        _onError(frame);
      case 'msg':
        await _onMsg(frame);
      case 'agent_info':
        _onAgentInfo(frame);
      case 'presence':
        _onPresence(frame);
      case 'flushed':
        final flush = _flushCompleter;
        _flushCompleter = null;
        if (flush != null && !flush.isCompleted) {
          flush.complete(frame['count'] as int? ?? 0);
        }
    }
  }

  void _onError(Map<String, dynamic> frame) {
    final error = HubError(
      frame['code'] as String? ?? 'unknown',
      frame['msg'] as String? ?? '',
    );
    if (!_errors.isClosed) _errors.add(error); // never silent
    final welcome = _welcomeCompleter;
    if (welcome != null && !welcome.isCompleted) {
      _welcomeCompleter = null;
      welcome.completeError(error);
      return;
    }
    for (final completer in _pendingWhois.values) {
      if (!completer.isCompleted) completer.completeError(error);
    }
    _pendingWhois.clear();
  }

  Future<void> _onMsg(Map<String, dynamic> frame) async {
    final channel = frame['channel'] as String?;
    String? plaintext;
    try {
      plaintext = channel != null
          ? await _decryptChannel(channel, frame)
          : await _decryptDm(frame);
    } on Object {
      plaintext = null; // no key or tampered payload — deliver opaque
    }
    if (_inbound.isClosed) return;
    // A chankey DM is an invite, not chat: persist the keypair, join, and
    // surface a short notice — never the raw key JSON.
    if (channel == null && plaintext != null) {
      final store = channelStore;
      final invite = parseChankeyInvite(plaintext);
      if (invite != null && store != null) {
        await store.accept(
          invite.channel,
          ChannelKeys(pub: invite.pub, priv: invite.priv),
        );
        join(invite.channel, invite.pub);
        plaintext = '[hub] invited to #${invite.channel} by ${frame['from']}';
      }
    }
    _inbound.add(InboundMessage(
      id: frame['id'] as String? ?? '',
      from: frame['from'] as String? ?? '',
      ts: frame['ts'] as int? ?? 0,
      channel: channel,
      to: frame['to'] as String?,
      plaintext: plaintext,
    ));
  }

  Future<String> _decryptChannel(String channel, Map frame) async {
    final privB64 = channelStore?.privOf(channel) ?? config.channelSecrets[channel];
    final pubB64 = channelStore?.pubOf(channel) ?? config.channels[channel];
    if (privB64 == null || pubB64 == null) throw StateError('no channel key');
    // Sender encrypted with senderPriv x channelPub; we decrypt with
    // channelPriv x senderPub (the sender is a registered agent).
    final sender = await whois(frame['from'] as String);
    final senderKey = sender.dhPublicKey;
    if (senderKey == null) throw StateError('no sender dh pubkey');
    return decryptPayload(
      recipientDhKeyPair: SimpleKeyPairData(
        base64Decode(privB64),
        publicKey: _dhPubkey(pubB64),
        type: KeyPairType.x25519,
      ),
      senderDhPubkey: senderKey,
      frameId: frame['id'] as String,
      aadTarget: channel,
      ciphertextB64: frame['ciphertext'] as String,
    );
  }

  Future<String> _decryptDm(Map frame) async {
    final me = agentId;
    if (me == null) throw StateError('not welcomed');
    final sender = await whois(frame['from'] as String);
    final senderKey = sender.dhPublicKey;
    if (senderKey == null) throw StateError('no sender dh pubkey');
    return decryptPayload(
      recipientDhKeyPair: identity.dhKeyPair,
      senderDhPubkey: senderKey,
      frameId: frame['id'] as String,
      aadTarget: me,
      ciphertextB64: frame['ciphertext'] as String,
    );
  }

  void _onAgentInfo(Map<String, dynamic> frame) {
    final info = _infoFrom(frame);
    final completer = _pendingWhois.remove(info.agentId);
    if (completer != null && !completer.isCompleted) {
      completer.complete(info);
    }
  }

  void _onPresence(Map<String, dynamic> frame) {
    _presenceResult = (frame['agents'] as List? ?? [])
        .map((raw) => _infoFrom((raw as Map).cast<String, dynamic>()))
        .toList();
    final completer = _presenceCompleter;
    _presenceCompleter = null;
    if (completer != null && !completer.isCompleted) completer.complete();
  }

  AgentInfo _infoFrom(Map<String, dynamic> frame) {
    final dhB64 = frame['x25519'] as String?;
    return AgentInfo(
      agentId: frame['agentId'] as String,
      name: frame['name'] as String?,
      online: frame['online'] as bool? ?? false,
      signingPubkeyB64: frame['pubkey'] as String?,
      dhPublicKey:
          (dhB64 == null || dhB64.isEmpty) ? null : _dhPubkey(dhB64),
    );
  }

  Future<void> _flushAfterWelcome() async {
    try {
      await flush();
    } on Object {
      // hub without flush support or early drop — non-fatal
    }
  }

  void _completeWelcome(bool ok) {
    final welcome = _welcomeCompleter;
    _welcomeCompleter = null;
    if (welcome != null && !welcome.isCompleted) welcome.complete(ok);
  }

  void _failPending(String reason) {
    final welcome = _welcomeCompleter;
    _welcomeCompleter = null;
    if (welcome != null && !welcome.isCompleted) {
      welcome.completeError(StateError(reason));
    }
    for (final completer in _pendingWhois.values) {
      if (!completer.isCompleted) completer.completeError(StateError(reason));
    }
    _pendingWhois.clear();
    for (final completer in [_flushCompleter, _presenceCompleter]) {
      if (completer != null && !completer.isCompleted) {
        completer.completeError(StateError(reason));
      }
    }
    _flushCompleter = null;
    _presenceCompleter = null;
  }

  static SimplePublicKey _dhPubkey(String b64) =>
      SimplePublicKey(base64Decode(b64), type: KeyPairType.x25519);
}
