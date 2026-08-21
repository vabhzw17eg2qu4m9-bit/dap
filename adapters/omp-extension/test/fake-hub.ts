import http from 'node:http';
import { WebSocketServer, type WebSocket } from 'ws';
import { verifyFrame, agentIdFor, unb64, type KeyPair } from '../src/crypto.ts';

/** Signature check that treats malformed input as a bad signature, never a crash. */
function verifies(edPub: Uint8Array, op: string, frame: Record<string, unknown>): boolean {
  try {
    return verifyFrame(edPub, op, frame);
  } catch {
    return false;
  }
}

interface HubAgent {
  ws?: WebSocket;
  pub: string;
  x25519: string;
  name?: string;
  lastSeen: number;
}

interface SendFrame {
  op: 'send';
  channel?: string;
  to?: string;
  id: string;
  ts: number;
  ciphertext: string;
  sig: string;
}

/**
 * Local fake DAP/1 hub for tests: verifies hello signatures exactly per
 * spec, fans out / mailboxes sends, serves whois + flush. Ciphertext-only.
 */
export class FakeHub {
  readonly agents = new Map<string, HubAgent>();
  /** channel -> member agentIds (spec § join). */
  readonly channelMembers = new Map<string, Set<string>>();
  readonly mailboxes = new Map<string, Record<string, unknown>[]>();
  readonly verifiedSends: SendFrame[] = [];
  readonly rejected: { code: string; agentId?: string }[] = [];
  readonly log: string[] = [];
  private readonly server = http.createServer((req, res) => {
    if (req.url === '/healthz') {
      res.end('ok');
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  private readonly wss = new WebSocketServer({ server: this.server, path: '/ws' });
  private readonly noncesSeen = new Set<string>();
  private readonly mailboxFull = new Set<string>();
  private readonly offlineWaiters = new Map<string, Array<() => void>>();
  private readonly sendWaiters: Array<() => void> = [];
  port = 0;
  url = '';

  constructor() {
    this.wss.on('connection', (ws) => {
      let agentId = '';
      ws.on('error', () => {});
      ws.on('message', (data) => {
        agentId = this.handle(ws, agentId, String(data)) ?? agentId;
      });
      ws.on('close', () => {
        if (agentId && this.agents.get(agentId)?.ws === ws) {
          this.agents.get(agentId)!.ws = undefined;
          for (const resolve of this.offlineWaiters.get(agentId) ?? []) resolve();
          this.offlineWaiters.delete(agentId);
        }
      });
    });
  }

  async listen(): Promise<this> {
    await new Promise<void>((resolve) => this.server.listen(0, '127.0.0.1', resolve));
    this.port = (this.server.address() as { port: number }).port;
    this.url = 'ws://127.0.0.1:' + this.port + '/ws';
    return this;
  }

  /** Resolve once `n` send frames passed signature verification. */
  waitVerifiedSends(n: number): Promise<void> {
    if (this.verifiedSends.length >= n) return Promise.resolve();
    const { promise, resolve } = Promise.withResolvers<void>();
    this.sendWaiters.push(() => {
      if (this.verifiedSends.length >= n) resolve();
    });
    return promise;
  }

  async close(): Promise<void> {
    for (const client of this.wss.clients) client.terminate();
    this.wss.close(() => {});
    this.server.closeAllConnections();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  /** Drop one agent's connection server-side (reconnect tests). */
  drop(agentId: string): void {
    this.agents.get(agentId)?.ws?.close();
  }

  /** Push an error frame to a connected agent (rejection-surfacing tests). */
  sendError(agentId: string, code: string, msg: string): void {
    this.agents.get(agentId)?.ws?.send(JSON.stringify({ op: 'error', code, msg }));
  }

  /** Resolve once the hub has processed an agent's disconnect. */
  waitOffline(agentId: string): Promise<void> {
    if (this.agents.get(agentId)?.ws === undefined) return Promise.resolve();
    const { promise, resolve } = Promise.withResolvers<void>();
    const waiters = this.offlineWaiters.get(agentId) ?? [];
    waiters.push(resolve);
    this.offlineWaiters.set(agentId, waiters);
    return promise;
  }

  private handle(ws: WebSocket, agentId: string, text: string): string | undefined {
    let frame: Record<string, unknown>;
    try {
      frame = JSON.parse(text) as Record<string, unknown>;
    } catch {
      this.error(ws, 'bad_frame');
      return undefined;
    }
    if (frame.op === 'hello') return this.hello(ws, frame);
    if (!agentId) {
      this.error(ws, 'not_authenticated');
      return undefined;
    }
    if (frame.op === 'whois') return this.whois(ws, String(frame.agentId));
    if (frame.op === 'join') return this.join(agentId, ws, frame);
    if (frame.op === 'presence_query') return this.presence(ws);
    if (frame.op === 'send') return this.send(agentId, ws, frame as unknown as SendFrame);
    if (frame.op === 'flush') return this.flush(ws, agentId);
    this.error(ws, 'bad_frame');
    return undefined;
  }

  private hello(ws: WebSocket, frame: Record<string, unknown>): string | undefined {
    const id = agentIdFor(unb64(String(frame.pubkey)));
    if (Math.abs(Date.now() - Number(frame.ts)) > 300_000) {
      this.reject(ws, id, 'stale_ts');
      return undefined;
    }
    const nonce = String(frame.nonce);
    if (this.noncesSeen.has(nonce)) {
      this.reject(ws, id, 'replayed_nonce');
      return undefined;
    }
    if (!verifies(unb64(String(frame.pubkey)), 'hello', frame)) {
      this.reject(ws, id, 'bad_signature');
      return undefined;
    }
    this.noncesSeen.add(nonce);
    const prev = this.agents.get(id)?.ws; // one connection per agent: evict old
    if (prev && prev !== ws) {
      this.log.push('evict:' + id);
      prev.close();
    }
    this.agents.set(id, {
      ws,
      pub: String(frame.pubkey),
      x25519: typeof frame.x25519 === 'string' ? frame.x25519 : '',
      name: optName(frame.name),
      lastSeen: Date.now(),
    });
    this.log.push('hello-verified:' + id);
    ws.send(JSON.stringify({ op: 'welcome', agentId: id }));
    return id;
  }

  private join(agentId: string, ws: WebSocket, frame: Record<string, unknown>): undefined {
    const name = String(frame.channel);
    const members = this.channelMembers.get(name) ?? new Set<string>();
    members.add(agentId);
    this.channelMembers.set(name, members);
    this.log.push('join:' + name + ':' + agentId);
    ws.send(JSON.stringify({ op: 'joined', channel: name })); // first join creates it
    return undefined;
  }

  private whois(ws: WebSocket, agentId: string): undefined {
    const agent = this.agents.get(agentId);
    if (!agent) {
      this.error(ws, 'unknown_agent');
      return undefined;
    }
    ws.send(
      JSON.stringify({
        op: 'agent_info',
        agentId,
        pubkey: agent.pub,
        x25519: agent.x25519, // echoed opaquely; '' when absent
        name: agent.name,
        online: agent.ws !== undefined,
      }),
    );
    return undefined;
  }

  private presence(ws: WebSocket): undefined {
    const agents = [...this.agents.entries()].map(([agentId, a]) => ({
      agentId,
      name: a.name,
      online: a.ws !== undefined,
      lastSeen: a.lastSeen,
    }));
    ws.send(JSON.stringify({ op: 'presence', agents }));
    return undefined;
  }

  private send(from: string, ws: WebSocket, frame: SendFrame): undefined {
    const agent = this.agents.get(from)!;
    if (!verifies(unb64(agent.pub), 'send', frame as unknown as Record<string, unknown>)) {
      this.rejected.push({ code: 'bad_signature', agentId: from });
      this.error(ws, 'bad_signature');
      return undefined;
    }
    this.verifiedSends.push(frame);
    for (const wake of this.sendWaiters) wake();
    const targets = frame.to ? [frame.to] : [...this.agents.keys()].filter((a) => a !== from);
    const msg: Record<string, unknown> = {
      op: 'msg',
      from,
      id: frame.id,
      ts: frame.ts,
      ciphertext: frame.ciphertext,
    };
    if (frame.channel) msg.channel = frame.channel;
    for (const target of targets) {
      const targetWs = this.agents.get(target)?.ws;
      if (targetWs) targetWs.send(JSON.stringify(msg));
      else this.enqueue(target, msg);
    }
    return undefined;
  }

  private enqueue(agentId: string, msg: Record<string, unknown>): void {
    const queue = this.mailboxes.get(agentId) ?? [];
    if (queue.length >= 100) {
      queue.shift(); // overflow drops oldest
      if (!this.mailboxFull.has(agentId)) {
        this.mailboxFull.add(agentId);
        this.rejected.push({ code: 'mailbox_full', agentId });
      }
    }
    queue.push(msg);
    this.mailboxes.set(agentId, queue);
  }

  private flush(ws: WebSocket, agentId: string): undefined {
    const queue = this.mailboxes.get(agentId) ?? [];
    for (const msg of queue) ws.send(JSON.stringify(msg));
    this.mailboxes.set(agentId, []);
    ws.send(JSON.stringify({ op: 'flushed', count: queue.length }));
    return undefined;
  }

  private reject(ws: WebSocket, agentId: string, code: string): void {
    this.rejected.push({ code, agentId });
    this.error(ws, code);
    ws.close();
  }

  private error(ws: WebSocket, code: string): void {
    ws.send(JSON.stringify({ op: 'error', code, msg: code }));
  }
}

function optName(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}
