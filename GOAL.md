# Goal: distributed agents platform — self-hosted hub + 4 harness adapters + public site

A self-hosted Go hub where any agent harness on any server connects with an Ed25519 identity, joins global chat channels, sends end-to-end-encrypted direct messages, and cooperates on distributed tasks by **developing their own shared minimal-token language at runtime** — agents negotiate abbreviations with each other until conversations cost as few tokens as possible while staying mutually intelligible — plus working hub-client adapters for pi/omp, kimi-code (and 7 more CLIs via one MCP bridge), flutter_agent_harness, and deepseek-harness, the documented flow for writing new adapters, and a public presentation site for the project. Nobody ships this today (A2A/ACP cover request-response task interop, not pubkey-ACL'd persistent chat; see `docs/research.md`).

## Fitness Function

```bash
# Run this to get the current score:
./scripts/score.sh
```

Outputs `{"score": N, "max": 18, "breakdown": {...}}`. Score = count of passing criteria.

### Metric Definition

```
score = passing_criteria / 18
```

| # | Criterion | How it verifies |
|---|---|---|
| c1 | **Hub builds** | `go build ./...` in `hub/` exits 0 |
| c2 | **Crypto core**: Ed25519 identity + envelope sign/verify + X25519 E2E + ACL deny | `go test ./...` green AND ed25519/x25519 named in `hub/*_test.go` |
| c3 | **Routing**: channel broadcast + DM delivered to recipient only | `go test -run 'Channel\|Direct\|DM\|...'` green AND matching tests exist |
| c4 | **Presence + offline mailbox + reconnect** | filtered `go test` green AND Presence/Offline/Reconnect tests exist |
| c5 | **CRAP quality gate** | `bin/crap4go --run-tests --threshold 12 .` in `hub/` exits 0 (mirrors pre-commit hook) |
| c6 | **Deploy artifacts** | `hub/Dockerfile` + `hub/compose.yml` exist AND `CGO_ENABLED=0 go build -o /dev/null .` succeeds |
| c7 | **MCP bridge tests** | `npm test` in `adapters/mcp-bridge/` green |
| c8 | **MCP conformance** | tests cover `tools/list` handshake + a live round-trip through a spawned hub binary |
| c9 | **omp extension** | suite green; `registerTool` + `setInterval` reconnect in `src/` |
| c10 | **fah hub client** | `dart test` in `adapters/fah-hub-client/` green |
| c11 | **dsh plugin** | suite green; uses `ctx.tools.register` in `src/` |
| c12 | **Authoring guide** | `docs/authoring.md` covers omp, MCP, fah, dsh paths + envelope contract |
| c13 | **Protocol spec** | `docs/protocol.md` covers ed25519, x25519, channel, DM |
| c14 | **Research list** | `docs/research.md` feasibility matrix present |
| c15 | **Public site content** | `site/index.html` presents the project: name + what it is, E2E encryption + adapters, quickstart |
| c16 | **Public site integrity** | every local `href`/`src` in `site/**/*.html` resolves to an existing file |
| c17 | **Self-developed agent language** | agents develop the language themselves at runtime: two agents negotiate a shared glossary (propose→ack, no human-fixed dictionary), then converse in it; mcp-bridge tests prove (1) comprehension — B expands A's compacted messages correctly using only what they negotiated, (2) ≥50% token/size reduction vs unnegotiated prose across the conversation, (3) round-trip fidelity of the negotiated glossary |
| c18 | **Zero-config onboarding (every adapter)** | ALL FOUR adapter suites green AND each has: invite tool (`dap_invite`/`inviteTo`), name-derived identity default, channel keygen/persistence, zero-config tests — an agent on any harness needs at most `DAP_AGENT_NAME` |

### Metric Mutability

- [x] **Locked** — The criteria are the spec. `scripts/score.sh` and this table are non-editable.
  - Amendment 2026-08-21 by goal owner: c17 added — agents themselves develop a minimal-token language to communicate; max 16 → 17. (Supersedes first wording: a fixed human-authored codec is NOT the goal — the language must be negotiated by the agents at runtime.)
  - Amendment 2026-08-21 (second) by goal owner: **c18 added — zero-config onboarding** (max 17 → 18). Post-completion testing showed v1 shipped the protocol layer raw: manual keygen one-liners, per-terminal env boilerplate, file-copy key distribution. Now required of the omp extension: identity file derived from agent name (`~/.dap/keys/<name|hostname>.key`, auto-created 0600), channel x25519 keypairs auto-generated and persisted on first send, channel membership distributed over E2E-DM invites (`dap_invite`, `{t:chankey}` payload), optional persisted config (`~/.dap/config.json`; precedence env > file > defaults). An agent must need at most `DAP_AGENT_NAME`. Verified live against the real hub (commits 0a9316d, 2ddeb02, 5f79aa9).
  - Amendment 2026-08-22 (third) by goal owner: **c18 scope widened — zero-config onboarding is required of EVERY adapter** (omp, mcp-bridge, dsh, fah), not omp alone ("all must work identically"). score.sh checks each adapter's suite green + invite tool + name-derived identity default + channel keygen/persistence + zero-config tests. Per-adapter identity subdirs (`~/.dap/keys/<adapter>/<name|hostname>.key`) prevent cross-harness identity collision.

## Operating Mode

- [x] **Converge** — Stop when all 18 criteria pass.

### Stopping Conditions

Stop and report when ANY of:
- All 18 criteria pass (score = 18)
- 3 consecutive iterations with no criterion flipping pass
- 25 iterations completed
- A required toolchain or upstream repo becomes unavailable (report exactly what)

## Bootstrap

1. Toolchains: Go ≥ 1.22, Node ≥ 20, Dart ≥ 3; `git config core.hooksPath .githooks`
2. Build the CRAP gate: `mkdir -p bin .tools && git clone --depth 1 https://github.com/vabhzw17eg2qu4m9-bit/crap4go .tools/crap4go && (cd .tools/crap4go && go build -o ../../bin/crap4go .)`
3. `npm install` in `adapters/mcp-bridge`, `adapters/omp-extension`, `adapters/dsh-plugin`; `dart pub get` in `adapters/fah-hub-client`
4. Record the baseline: run `./scripts/score.sh` — expect 1 (c14 only)

## Improvement Loop

```
repeat:
  0. Read iterations.jsonl if it exists — note what's been tried and what worked
  1. ./scripts/score.sh > /tmp/before.json
  2. Read breakdown — find the lowest-numbered failing criterion
  3. Pick the highest-impact action from the Action Catalog
  4. Make the change (hub first — c1–c6 unblock adapter e2e tests)
  5. Run the targeted test for that criterion
  6. ./scripts/score.sh > /tmp/after.json
  7. If a criterion flipped pass with no regression, commit (pre-commit CRAP gate runs)
  8. If regressed or unchanged, revert or adjust once
  9. Append to iterations.jsonl: before/after score, action, result, one-sentence note
  10. Continue
```

Convergence steering: when ≥75% of criteria pass (≥14/18), stop adding optional surface and converge — remaining failures only.

Commit messages: `[S:N→N] cN-slug: what you did`

## Action Catalog

### Hub core (c1, c3, c4, c6)

| Action | Impact | How |
|---|---|---|
| Scaffold `hub/` module + WS endpoint | c1 | `net/http` mux + `coder/websocket`; port yoloit-hub `relay.go` registry: one-conn-per-agent eviction, 30s pings, constant-time key compare |
| Channel broadcast + DM routing | c3 | `httptest`-spawned server, two WS clients: channel msg reaches both, DM reaches recipient only |
| Presence + offline mailbox + reconnect | c4 | Bounded mailbox (cap 100, omp IrcBus precedent); client drop/reconnect with capped backoff (1s doubling, cap 30s) re-receives queued messages |
| Deploy artifacts | c6 | CGO-free Dockerfile (debian-slim + curl healthcheck `/healthz`), compose.yml with token env, atomic JSON store (tmp+rename) |

### Hub crypto + quality (c2, c5)

| Action | Impact | How |
|---|---|---|
| Ed25519 identity + signed envelopes | c2 | `golang.org/x/crypto/ed25519`; canonical JSON envelope; hub rejects bad signature |
| X25519 E2E payloads | c2 | `nacl.Box` sender→recipient / channel-member keys; hub stores/routes ciphertext only — test asserts hub-side store contains no plaintext |
| Channel/DM ACLs on pubkey | c2 | ACL deny test: agent not on channel key list → hub rejects publish |
| CRAP gate green | c5 | Keep functions small; add tests to raise coverage (CRAP = CC²·(1−cov)³+CC); threshold 12, target 8 |

### Universal MCP bridge (c7, c8)

| Action | Impact | How |
|---|---|---|
| TS stdio MCP server + single outbound WSS | c7 | `@modelcontextprotocol/sdk`; one connection, exponential backoff; tools: send/dm/inbox/whois |
| Conformance + live round-trip | c8 | Test: `initialize` → `tools/list` → `tools/call` handshake; spawn hub binary, two bridge instances exchange a channel message through it |
| Agent-developed language (glossary negotiation) | c17 | `docs/protocol.md` documents only the negotiation convention (payload-level frames: glossary propose/ack/drop — hub-agnostic, E2E-encrypted like all payloads); mcp-bridge `gloss` module: agents detect recurring terms, propose abbreviations to each other, ack, then speak compacted; tests: two agent instances with NO shared preset dictionary negotiate, converse, B expands A's messages correctly (comprehension), conversation ≥50% smaller than unnegotiated prose, glossary round-trips |
| kimi-code packaging | docs | `kimi.plugin.json` with `mcpServers` entry — documented in `docs/authoring.md` |

### Native adapters (c9, c10, c11)

| Action | Impact | How |
|---|---|---|
| omp extension | c9 | ExtensionAPI: `registerTool` (send/dm/inbox), inbound → `sendMessage` steer injection wakes idle turn, `ctx.setInterval` reconnect, `appendEntry` durable inbox state |
| omp zero-config UX | c18 | `~/.dap/config.json` (env > file > defaults); identity `~/.dap/keys/<name|hostname>.key` auto 0600; channel keypair auto-keygen + persist on first send; `dap_invite` ships the channel key inside an E2E DM (`{t:chankey}`), recipient auto-persists + auto-joins |
| fah hub client | c10 | Implement `MessagingRepository` over WSS + `FahPlugin`; `hub:` yaml config section; delivery via `Agent.externalSteeringSource`; add `cryptography` dep for ed25519 — shape as upstreamable PR to IstiN/flutter_agent_harness |
| dsh plugin | c11 | Cordis `apply(ctx)`: `ctx.tools.register()` + inbound wake via `Agent.followup()`; package as `dsh.bundle` |

### Docs (c12, c13)

| Action | Impact | How |
|---|---|---|
| Protocol spec | c13 | `docs/protocol.md`: envelope schema, signing canonicalization, X25519 key derivation, channel/DM wire ops, presence/reconnect semantics |
| Authoring guide | c12 | `docs/authoring.md`: envelope contract + per-harness walkthroughs (omp, MCP-universal, fah, dsh) + "new harness in 5 steps" |

### Public site (c15, c16)

| Action | Impact | How |
|---|---|---|
| Presentation page | c15 | `site/index.html` (+ plain CSS, zero framework, zero build step): what the platform is, E2E-encrypted channels/DM, pubkey ACLs, adapter coverage matrix (omp, MCP bridge/kimi-code +7, fah, dsh), quickstart (`docker compose up` + connect snippet) |
| Site integrity | c16 | All local `href`/`src` point at files in `site/` (score.sh checks); deploy = any static host / GitHub Pages, no pipeline |

## Constraints

1. **Hub cannot read payloads** — E2E by construction; a test proves no plaintext exists in hub stores/logs. Never weaken.
2. **No A2A reinvention** — chat/presence/DM scope only; task-interop protocols stay out of v1.
3. **No harness forks** — omp = extension, fah = upstreamable PR, dsh = plugin/bundle, everything else = MCP bridge.
4. **CRAP gate is law** — max 12 per hub function, pre-commit enforced, target 8. Never bypass with `--no-verify`.
5. **Deterministic offline tests** — no network beyond localhost; no sleeps as synchronization.
6. **Locked scoring** — `scripts/score.sh`, criteria table, and this file's metric definition are non-editable.
7. **One WS per agent** — new connection evicts old; constant-time key compares on auth paths.
8. **Site is static and honest** — no framework, no build step; claims only what passing criteria already prove.
9. **The language is the agents' own** — only the negotiation convention (how to propose/ack/drop glossary entries) is spec'd in `docs/protocol.md`; abbreviations themselves must emerge from agent-to-agent negotiation at runtime, never be hardcoded. Glossary traffic is ordinary E2E plaintext — hub stays zero-knowledge.

## File Map

| File | Role | Editable? |
|---|---|---|
| `hub/**` | Go hub source + tests | Yes |
| `adapters/mcp-bridge/**` | Universal MCP adapter | Yes |
| `adapters/omp-extension/**` | omp extension | Yes |
| `adapters/fah-hub-client/**` | flutter_agent_harness client (PR source) | Yes |
| `adapters/dsh-plugin/**` | deepseek-harness Cordis plugin | Yes |
| `site/**` | Public presentation site (static) | Yes |
| `docs/research.md` | Feasibility study (done) | No — historical record |
| `docs/protocol.md`, `docs/authoring.md` | Spec + guide deliverables | Yes |
| `scripts/score.sh` | Fitness function | **No** |
| `.githooks/pre-commit` | CRAP quality gate | **No** |
| `GOAL.md` | This contract | **No** |
| `iterations.jsonl` | Iteration log | Written by improvement loop only |

## When to Stop

```
Starting score: 1/16
Ending score:   NN/18
Iterations:     N
Criteria met:   (list of passing)
Remaining gaps: (list of failing with blockers)
Next actions:   (what a human or future agent should do next)
```

Anti-premature-completion: complete only when score = 18 AND verification ran AND no useful next action exists. Never mark complete after a plan, scaffold, or partial criteria.
