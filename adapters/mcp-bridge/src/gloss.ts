// Glossary negotiation per docs/protocol.md § "Glossary negotiation": two
// agents grow their OWN shared minimal-token language at runtime, inside the
// E2E-encrypted payloads (the hub stays zero-knowledge). A GlossAgent watches
// its own outgoing text; once a term recurs across ≥2 messages it generates an
// abbreviation FOR THAT TERM at runtime (multi-word → initials, single word →
// consonant skeleton, collisions → numeric suffix) and proposes it. An entry
// goes live only after propose→ack: the proposer activates on receiving the
// peer's ack, the acking side on SENDING its ack. Active terms compact
// outgoing bodies to `~<abbrev>`; incoming `~<abbrev>` expands back to the
// exact original term (round-trip fidelity). There is no preset dictionary
// anywhere — every abbreviation is derived from live observation.
import type { DapClient, MsgEvent, SendResult } from './client.js';

export interface ChatEvent {
  dm: boolean;
  channel?: string;
  from: string;
  /** Expanded plaintext body. */
  body: string;
  ts: number;
}

export interface GlossPair {
  term: string;
  abbrev: string;
  /** 'proposed' = sent, awaiting the peer's ack; 'active' = both sides hold it. */
  state: 'proposed' | 'active';
}

interface Conv {
  entries: Map<string, GlossPair>; // term -> pair
  reverse: Map<string, string>; // active abbrev -> term
  seen: Map<string, number>; // term -> #outgoing messages containing it
  dropped: Set<string>; // terms removed by `drop` — never re-proposed
  reserved: Set<string>; // abbrevs ever used — never reused (delayed msgs stay sane)
}

type Dest = { channel: string } | { dm: string };

interface GlossFrame {
  t?: string;
  act?: string;
  body?: string;
  entries?: Array<[string, string]>;
  terms?: string[];
}

const MIN_TERM = 8; // proposed terms must be long enough to be worth shortening
const MIN_MSGS = 2; // term seen in ≥2 distinct outgoing messages → candidate
const MAX_NGRAM = 3; // terms are 1..3 words
const MAX_ABBREV = 4;

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Runtime abbreviation for an observed term — NOT a lookup, pure derivation. */
function genAbbrev(term: string, reserved: Set<string>): string {
  const words = term.split(' ');
  const base = (words.length === 1
    ? words[0][0] + words[0].slice(1).replace(/[aeiou]/g, '') // consonant skeleton
    : words.map((w) => w[0]).join('') // initials
  ).slice(0, MAX_ABBREV);
  let abbrev = base;
  for (let i = 2; reserved.has(abbrev); i++) abbrev = base + i;
  reserved.add(abbrev);
  return abbrev;
}

/** All 1..MAX_NGRAM word n-grams of `text` whose every word has ≥4 letters. */
function ngrams(text: string): string[] {
  const ws = text.toLowerCase().match(/[a-z]{4,}/g) ?? [];
  const out: string[] = [];
  for (let n = 1; n <= MAX_NGRAM; n++) {
    for (let i = 0; i + n <= ws.length; i++) out.push(ws.slice(i, i + n).join(' '));
  }
  return out;
}

export class GlossAgent {
  constructor(readonly client: DapClient) {}

  private readonly convs = new Map<string, Conv>();
  private readonly listeners = new Set<(ev: ChatEvent) => void>();
  private started = false;

  start(): void {
    if (this.started) return;
    this.started = true;
    this.client.onMessage((m) => this.handleInbound(m));
    this.client.start();
  }

  stop(): void {
    this.client.stop();
  }

  /** Observe every expanded chat body (gloss frames are consumed internally). */
  onChat(cb: (ev: ChatEvent) => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  /** Say something on a channel: observe → propose new candidates → compacted
   *  send. Returns the body that actually went on the wire. */
  async say(channel: string, text: string): Promise<string> {
    return this.sayTo({ channel }, `chan:${channel}`, text);
  }

  /** DM variant; the glossary is per-peer. */
  async sayDm(peer: string, text: string): Promise<string> {
    return this.sayTo({ dm: peer }, `dm:${peer}`, text);
  }

  /** Stop using an abbreviation; both sides deactivate (spec: drop by abbrev). */
  async drop(channel: string, abbrev: string): Promise<void> {
    const key = `chan:${channel}`;
    this.deactivate(this.conv(key), [abbrev]);
    await this.send({ channel }, { t: 'gloss', act: 'drop', terms: [abbrev] });
  }

  /** Introspection: active [term, abbrev] pairs of a conversation. */
  active(conv: string): Array<[string, string]> {
    return [...this.conv(conv).entries.values()].filter((e) => e.state === 'active').map((e) => [e.term, e.abbrev]);
  }

  /** Pure compaction: occurrences of active terms → `~<abbrev>` (longest first). */
  compact(conv: string, text: string): string {
    const c = this.conv(conv);
    const act = [...c.entries.values()].filter((e) => e.state === 'active')
      .sort((a, b) => b.term.length - a.term.length);
    let out = text;
    for (const { term, abbrev } of act) {
      // ponytail: case-sensitive match — capitalized variants stay verbatim,
      // which keeps expansion an exact inverse (round-trip fidelity).
      out = out.replace(new RegExp(`(?<![a-z0-9])${escapeRe(term)}(?![a-z0-9])`, 'g'), `~${abbrev}`);
    }
    return out;
  }

  /** Pure expansion: `~<abbrev>` → term; unknown tokens stay verbatim. */
  expand(conv: string, body: string): string {
    const c = this.conv(conv);
    return body.replace(/~([a-z0-9]+)/g, (tok, abbrev: string) => c.reverse.get(abbrev) ?? tok);
  }

  /** Serialize ACTIVE glossaries (all conversations) — portable session state. */
  serialize(): string {
    const out: Record<string, Record<string, string>> = {};
    for (const [key, c] of this.convs) {
      const terms: Record<string, string> = {};
      for (const e of c.entries.values()) if (e.state === 'active') terms[e.term] = e.abbrev;
      if (Object.keys(terms).length) out[key] = terms;
    }
    return JSON.stringify(out);
  }

  /** Restore glossaries serialized by `serialize` (entries become active). */
  load(json: string): void {
    const data = JSON.parse(json) as Record<string, Record<string, string>>;
    for (const [key, terms] of Object.entries(data)) {
      const c = this.conv(key);
      for (const [term, abbrev] of Object.entries(terms)) {
        c.entries.set(term, { term, abbrev, state: 'active' });
        c.reverse.set(abbrev, term);
        c.reserved.add(abbrev);
      }
    }
  }

  // --- internals ---

  private conv(key: string): Conv {
    let c = this.convs.get(key);
    if (!c) {
      c = { entries: new Map(), reverse: new Map(), seen: new Map(), dropped: new Set(), reserved: new Set() };
      this.convs.set(key, c);
    }
    return c;
  }

  /** Observe own text → propose terms recurring across ≥MIN_MSGS messages →
   *  send the body compacted with the terms that are already active. */
  private async sayTo(dest: Dest, key: string, text: string): Promise<string> {
    const c = this.conv(key);
    for (const term of new Set(ngrams(text))) c.seen.set(term, (c.seen.get(term) ?? 0) + 1);
    const proposals = [...c.seen.entries()]
      .filter(([term, n]) => n >= MIN_MSGS && term.length >= MIN_TERM && !c.entries.has(term) && !c.dropped.has(term))
      .map(([term]) => [term, genAbbrev(term, c.reserved)] as [string, string]);
    for (const [term, abbrev] of proposals) c.entries.set(term, { term, abbrev, state: 'proposed' });
    if (proposals.length) await this.send(dest, { t: 'gloss', act: 'propose', entries: proposals });
    const body = this.compact(key, text);
    await this.send(dest, { t: 'msg', body });
    return body;
  }

  private send(dest: Dest, payload: GlossFrame): Promise<SendResult> {
    return 'channel' in dest
      ? this.client.send(dest.channel, JSON.stringify(payload))
      : this.client.dm(dest.dm, JSON.stringify(payload));
  }

  private handleInbound(m: MsgEvent): void {
    if (m.from === this.client.agentId) return; // own channel echo: nothing to negotiate with ourselves
    let frame: GlossFrame;
    try {
      frame = JSON.parse(m.text) as GlossFrame;
    } catch {
      return; // not a glossary payload — ignored by this layer
    }
    const key = m.channel ? `chan:${m.channel}` : `dm:${m.from}`;
    if (frame.t === 'gloss') {
      const dest = m.channel ? { channel: m.channel } : { dm: m.from };
      void this.handleGloss(key, dest, frame).catch(() => {}); // failures surface via client.lastError
    } else if (frame.t === 'msg') {
      const body = this.expand(key, String(frame.body));
      for (const cb of this.listeners) cb({ dm: m.dm, channel: m.channel, from: m.from, body, ts: m.ts });
    }
  }

  private async handleGloss(key: string, dest: Dest, frame: GlossFrame): Promise<void> {
    if (frame.act === 'propose') {
      const c = this.conv(key);
      const ack: Array<[string, string]> = [];
      for (const [term, abbrev] of frame.entries ?? []) {
        const cur = c.entries.get(term);
        if (cur?.state === 'active') {
          ack.push([term, cur.abbrev]); // already live here: our binding is authoritative
          continue;
        }
        // A pending proposal of ours for the same term yields to theirs.
        c.entries.set(term, { term, abbrev, state: 'active' }); // acker activates on SENDING the ack
        c.reverse.set(abbrev, term);
        c.reserved.add(abbrev);
        ack.push([term, abbrev]);
      }
      await this.send(dest, { t: 'gloss', act: 'ack', entries: ack });
    } else if (frame.act === 'ack') {
      const c = this.conv(key);
      for (const [term, abbrev] of frame.entries ?? []) {
        if (c.entries.get(term)?.state !== 'proposed') continue;
        c.entries.set(term, { term, abbrev, state: 'active' }); // proposer activates on the peer's ack
        c.reverse.set(abbrev, term);
        c.reserved.add(abbrev);
      }
    } else if (frame.act === 'drop') {
      this.deactivate(this.conv(key), frame.terms ?? []);
    }
  }

  private deactivate(c: Conv, abbrevs: string[]): void {
    for (const abbrev of abbrevs) {
      const term = c.reverse.get(abbrev);
      if (term === undefined) continue;
      c.entries.delete(term);
      c.reverse.delete(abbrev);
      c.dropped.add(term);
    }
  }
}
