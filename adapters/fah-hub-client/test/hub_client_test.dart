import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:fah_hub_client/fah_hub_client.dart';
import 'package:test/test.dart';

import 'fake_hub.dart';

const timeout = Timeout(Duration(seconds: 10));
final tinyBackoff = (int _) => const Duration(milliseconds: 5);

Future<HubClient> connect(FakeHub hub, HubIdentity identity,
    {Map<String, String> channels = const {},
    Map<String, String> channelSecrets = const {},
    Duration Function(int)? backoff}) async {
  final client = HubClient(
    config: HubConfig(
      url: hub.url.toString(),
      channels: channels,
      channelSecrets: channelSecrets,
    ),
    identity: identity,
    backoff: backoff,
  );
  await client.connect();
  return client;
}

void main() {
  late FakeHub hub;

  setUp(() async {
    hub = FakeHub();
    await hub.start();
  });

  tearDown(() async {
    await hub.stop();
  });

  test('hello → welcome handshake; hub verifies the ed25519 signature',
      () async {
    final identity = await HubIdentity.generate();
    final client = await connect(hub, identity);

    // agentId = hex(sha256(ed25519_pubkey_raw))[:16], independently computed
    final digest = await Sha256().hash(identity.signingPublicKey.bytes);
    final expected = digest.bytes
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join()
        .substring(0, 16);
    expect(client.agentId, expected);

    // welcomed => the hub accepted our signed hello
    expect(hub.rejectedHellos, 0);
    expect(client.welcomed, completion(expected));
    await client.disconnect();
  }, timeout: timeout);

  test('hub rejects a hello with a bad signature', () async {
    final identity = await HubIdentity.generate();
    final raw = await WebSocket.connect(hub.url.toString());
    final error = Completer<String>();
    late final StreamSubscription sub;
    sub = raw.listen((dynamic data) {
      final frame = jsonDecode(data as String) as Map;
      if (frame['op'] == 'error') {
        error.complete(frame['code'] as String);
      }
    });
    // hello claiming identity's pubkey but signed by a different key
    final impostor = await Ed25519().newKeyPair();
    final frame = <String, dynamic>{
      'op': 'hello',
      'v': 1,
      'pubkey': identity.signingPubkeyB64,
      'x25519': identity.dhPubkeyB64,
      'nonce': randomHex(16),
      'ts': DateTime.now().millisecondsSinceEpoch,
    };
    frame['sig'] = await signFrame(frame, impostor);
    raw.add(jsonEncode(frame));
    expect(await error.future.timeout(const Duration(seconds: 5)),
        'bad_signature');
    expect(hub.rejectedHellos, 1);
    await sub.cancel();
    await raw.close();
  }, timeout: timeout);

  test('signed channel send is relayed and decryptable by the other member',
      () async {
    final channelKeys = await X25519().newKeyPair();
    final channelPub = base64Encode(
        (await channelKeys.extractPublicKey()).bytes);
    final channelPriv =
        base64Encode(await channelKeys.extractPrivateKeyBytes());

    final alice = await connect(hub, await HubIdentity.generate(),
        channels: {'general': channelPub});
    final bob = await connect(hub, await HubIdentity.generate(),
        channels: {'general': channelPub},
        channelSecrets: {'general': channelPriv});

    final received = bob.inbound
        .firstWhere((m) => m.plaintext == 'chan hello')
        .timeout(const Duration(seconds: 5));
    await alice.sendToChannel('general', 'chan hello');
    final msg = await received;

    expect(msg.channel, 'general');
    expect(msg.from, alice.agentId);
    expect(hub.deliveredTo, [bob.agentId]); // sender not echoed
    // hub routed ciphertext only
    expect(jsonEncode(hub.relayed.single), isNot(contains('chan hello')));

    await alice.disconnect();
    await bob.disconnect();
  }, timeout: timeout);

  test('DM round-trip: whois first, then E2E decrypt on the recipient',
      () async {
    final alice = await connect(hub, await HubIdentity.generate(),
        backoff: tinyBackoff);
    final bob = await connect(hub, await HubIdentity.generate());

    final received = bob.inbound
        .firstWhere((m) => m.plaintext == 'secret dm')
        .timeout(const Duration(seconds: 5));
    await alice.sendDm(bob.agentId!, 'secret dm');
    final msg = await received;

    expect(msg.from, alice.agentId);
    expect(msg.channel, isNull);
    expect(hub.deliveredTo, [bob.agentId]); // DM reaches recipient only
    expect(hub.whoisQueries, contains(bob.agentId)); // whois before first DM
    expect(jsonEncode(hub.relayed.single), isNot(contains('secret dm')));

    await alice.disconnect();
    await bob.disconnect();
  }, timeout: timeout);

  test('reconnect: re-hello and flush re-receives the queued DM', () async {
    final alice = await connect(hub, await HubIdentity.generate(),
        backoff: tinyBackoff);
    final bob = await connect(hub, await HubIdentity.generate());

    // Drop alice's connection hub-side, wait until the hub sees her offline.
    final offline = hub.agentOffline
        .firstWhere((id) => id == alice.agentId)
        .timeout(const Duration(seconds: 5));
    await hub.closeAgent(alice.agentId!);
    await offline;

    // While alice is offline, bob DMs her → hub queues it in her mailbox.
    await bob.sendDm(alice.agentId!, 'queued while away');

    // Alice reconnects on her own (5 ms backoff), re-hellos, and flushes.
    final queued = alice.inbound
        .firstWhere((m) => m.plaintext == 'queued while away')
        .timeout(const Duration(seconds: 5));
    await hub.waitForHellos(3); // alice initial + bob + alice re-hello
    final msg = await queued;

    expect(msg.from, bob.agentId);
    expect(hub.rejectedHellos, 0);
    expect(hub.deliveredTo, isEmpty); // never delivered live: queued path

    await alice.disconnect();
    await bob.disconnect();
  }, timeout: timeout);

  test('presence query lists connected agents', () async {
    final alice = await connect(hub, await HubIdentity.generate());
    final bob = await connect(hub, await HubIdentity.generate());

    final agents = await bob.presenceQuery();
    expect(
      agents.map((a) => a.agentId),
      containsAll([alice.agentId, bob.agentId]),
    );
    expect(
      agents.firstWhere((a) => a.agentId == alice.agentId).dhPublicKey,
      isNotNull,
    );

    await alice.disconnect();
    await bob.disconnect();
  }, timeout: timeout);
}
