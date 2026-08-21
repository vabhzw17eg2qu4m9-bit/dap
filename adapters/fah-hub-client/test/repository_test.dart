import 'dart:io';

import 'package:fah_hub_client/fah_hub_client.dart';
import 'package:test/test.dart';

import 'fake_hub.dart';

const timeout = Timeout(Duration(seconds: 10));

void main() {
  late FakeHub hub;
  late HubClient sender;

  setUp(() async {
    hub = FakeHub();
    await hub.start();
    sender = HubClient(
      config: HubConfig(url: hub.url.toString()),
      identity: await HubIdentity.generate(),
    );
    await sender.connect();
  });

  tearDown(() async {
    await sender.disconnect();
    await hub.stop();
  });

  test('repository delivers inbound to the steering source and drains once',
      () async {
    final client = HubClient(
      config: HubConfig(url: hub.url.toString()),
      identity: await HubIdentity.generate(),
    );
    final repository = HubMessagingRepository(client);
    await repository.start();
    final me = client.agentId!;

    final arrived = client.inbound
        .firstWhere((m) => m.plaintext == 'steer me')
        .timeout(const Duration(seconds: 5));
    await sender.sendDm(me, 'steer me');
    await arrived;

    // The steering source drains exactly what arrived, once.
    final drained = await repository.drain(me);
    expect(drained, hasLength(1));
    expect(drained.single.text, 'steer me');
    expect(drained.single.fromId, sender.agentId);
    expect(drained.single.toId, me);
    expect(DateTime.parse(drained.single.sentAt).isUtc, isTrue);
    expect(await repository.drain(me), isEmpty); // consumed, never again
    expect(await repository.peek(me), isEmpty);

    await repository.dispose();
  }, timeout: timeout);

  test('peek is non-consuming; drain takes the whole inbox', () async {
    final client = HubClient(
      config: HubConfig(url: hub.url.toString()),
      identity: await HubIdentity.generate(),
    );
    final repository = HubMessagingRepository(client);
    await repository.start();
    final me = client.agentId!;

    final second = client.inbound
        .firstWhere((m) => m.id != '' && m.plaintext == 'two')
        .timeout(const Duration(seconds: 5));
    await sender.sendDm(me, 'one');
    await client.inbound
        .firstWhere((m) => m.plaintext == 'one')
        .timeout(const Duration(seconds: 5));
    await sender.sendDm(me, 'two');
    await second;

    expect((await repository.peek(me)).map((m) => m.text), ['one', 'two']);
    expect((await repository.peek(me)).map((m) => m.text), ['one', 'two']);
    expect((await repository.drain(me)).map((m) => m.text), ['one', 'two']);
    expect(await repository.peek(me), isEmpty);

    await repository.dispose();
  }, timeout: timeout);

  test('send maps #channel to channel sends and agent ids to DMs', () async {
    final recipient = HubClient(
      config: HubConfig(url: hub.url.toString()),
      identity: await HubIdentity.generate(),
    );
    final repository = HubMessagingRepository(recipient);
    await repository.start();

    final dm = recipient.inbound
        .firstWhere((m) => m.plaintext == 'via repository')
        .timeout(const Duration(seconds: 5));
    await repository.send(
      AgentMessage(
        id: 'ignored',
        fromId: 'ignored',
        toId: recipient.agentId!,
        text: 'via repository',
        sentAt: '',
      ),
    );
    await dm;
    expect(hub.relayed.single['to'], recipient.agentId);

    // unknown channel → throws (never lose a message silently)
    expect(
      repository.send(AgentMessage(
        id: '',
        fromId: '',
        toId: '#nosuch',
        text: 'x',
        sentAt: '',
      )),
      throwsArgumentError,
    );

    await repository.dispose();
  }, timeout: timeout);

  test('directory maps hub presence onto mailbox entries', () async {
    final client = HubClient(
      config: HubConfig(url: hub.url.toString(), name: 'directory-probe'),
      identity: await HubIdentity.generate(),
    );
    final repository = HubMessagingRepository(client);
    await repository.start();

    final entries = await repository.directory();
    expect(entries.map((e) => e.id),
        containsAll([sender.agentId, client.agentId]));
    expect(
      entries.firstWhere((e) => e.id == client.agentId).slug,
      'directory-probe',
    );

    await repository.dispose();
  }, timeout: timeout);

  test('HubPlugin: config wiring, persisted 0600 key, steering delivery',
      () async {
    final tmp = await Directory.systemTemp.createTemp('fah-hub');
    final keyPath = '${tmp.path}/hub-key';
    addTearDown(() => tmp.delete(recursive: true));

    final plugin = HubPlugin(environment: {});
    plugin.register(PluginContext(config: {
      'hub': {'url': hub.url.toString(), 'keyPath': keyPath, 'name': 'bee'},
    }));
    expect(plugin.name, 'hub');
    await plugin.start();
    final me = plugin.agentId!;
    expect(me, isNotEmpty);

    // key persisted with 0600 and reloads to the same identity
    final stat = await File(keyPath).stat();
    expect(stat.modeString(), 'rw-------');
    expect((await HubIdentity.load(keyPath)).agentId, me);

    // second start is a no-op (one repository, one connection)
    await plugin.start();

    final arrived = plugin.repository!.client.inbound
        .firstWhere((m) => m.plaintext == 'wake up')
        .timeout(const Duration(seconds: 5));
    await sender.sendDm(me, 'wake up');
    await arrived;

    // the Agent.externalSteeringSource seam: drains, never throws
    final steering = plugin.externalSteeringSource;
    final messages = await steering();
    expect(messages, hasLength(1));
    expect(messages.single.text, 'wake up');
    expect(await steering(), isEmpty);

    await plugin.dispose();
  }, timeout: timeout);
}
