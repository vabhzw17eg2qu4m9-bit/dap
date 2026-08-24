/// [MessagingRepository] over a DAP/1 hub connection — the "future
/// database/network implementation" the upstream interface doc invites.
///
/// Mapping to the hub model:
/// * `register`/`connect` announce presence via the signed hello.
/// * `send` routes on [AgentMessage.toId]: `#channel` → channel send,
///   anything else → E2E DM (whois resolves the peer key first).
/// * Inbound `msg` frames land in per-agent inboxes, drained at the next
///   turn boundary by [drain] (wired to `Agent.externalSteeringSource`).
/// * `directory` maps a hub presence query onto [MailboxEntry]es.
library;

import 'dart:async';

import '../fah/messaging.dart';
import 'hub_client.dart';

class HubMessagingRepository implements MessagingRepository {
  HubMessagingRepository(this.client);

  final HubClient client;
  final _inboxes = <String, List<AgentMessage>>{};
  StreamSubscription<InboundMessage>? _subscription;

  /// Connects to the hub and starts delivering inbound messages. Must be
  /// called before [send]/[peek]/[drain].
  Future<void> start() async {
    await client.connect();
    await _subscription?.cancel();
    _subscription = client.inbound.listen(_deliver);
  }

  void _deliver(InboundMessage message) {
    final text = message.plaintext;
    if (text == null) return;
    final toId = _inboxIdFor(message);
    _inboxes.putIfAbsent(toId, () => []).add(AgentMessage(
          id: message.id,
          fromId: message.from,
          toId: toId,
          text: text,
          sentAt: DateTime.fromMillisecondsSinceEpoch(message.ts)
              .toUtc()
              .toIso8601String(),
        ));
  }

  String _inboxIdFor(InboundMessage message) =>
      message.channel != null ? '#${message.channel}' : (client.agentId ?? '');

  @override
  Future<void> send(AgentMessage message) async {
    final toId = message.toId;
    if (toId.startsWith('#')) {
      await client.sendToChannel(toId.substring(1), message.text);
    } else {
      await client.sendDm(toId, message.text);
    }
  }

  /// Invites [agentId] to [channel] (see [HubClient.inviteTo]): the channel
  /// keypair travels inside a normal E2E DM; the recipient auto-persists,
  /// joins, and gets a notice on the steering source.
  Future<void> inviteTo(String channel, String agentId) =>
      client.inviteTo(channel, agentId);

  /// `dap_status` passthrough (see [HubClient.status]): connection state,
  /// identity, known channels, and hello/welcome counters.
  HubStatus status() => client.status();

  /// `dap_peers` passthrough (see [HubClient.peers]): hub presence list.
  Future<List<AgentInfo>> peers() => client.peers();

  @override
  Future<void> register(String agentId) => start();

  @override
  Future<List<AgentMessage>> peek(String agentId) =>
      Future.value(List.of(_inboxes[agentId] ?? const []));

  @override
  Future<List<AgentMessage>> drain(String agentId) =>
      Future.value(List.of(_inboxes.remove(agentId) ?? const []));

  @override
  Future<List<MailboxEntry>> directory() async {
    final agents = await client.presenceQuery();
    return [
      for (final agent in agents)
        MailboxEntry(id: agent.agentId, slug: agent.name),
    ];
  }

  Future<void> dispose() async {
    await _subscription?.cancel();
    await client.disconnect();
  }
}
