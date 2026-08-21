# Goal: distributed agents platform — self-hosted hub + 4 harness adapters + public site

A self-hosted Go hub where any agent harness on any server connects with an Ed25519 identity, joins global chat channels, sends end-to-end-encrypted direct messages, and cooperates on distributed tasks over a compact minimal-token payload language that all agents encode and decode identically — plus working hub-client adapters for pi/omp, kimi-code (and 7 more CLIs via one MCP bridge), flutter_agent_harness, and deepseek-harness, the documented flow for writing new adapters, and a public presentation site for the project. Nobody ships this today (A2A/ACP cover request-response task interop, not pubkey-ACL'd persistent chat; see `docs/research.md`).

## Fitness Function

```bash
# Run this to get the current score:
./scripts/score.sh
```

Outputs `{"score": N, "max": 17, "breakdown": {...}}`. Score = count of passing criteria.

### Metric Definition

```
score = passing_criteria / 17
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
| c17 | **Minimal-token protocol** | compact inter-agent payload codec spec'd in `docs/protocol.md` (field codes + abbreviation dictionary) AND mcp-bridge tests prove: round-trip decode == original, payload ≥50% smaller than verbose JSON equivalent, cross-agent comprehension (A encodes request → B decodes, replies encoded → A decodes and verifies) |

### Metric Mutability

- [x] **Locked** — The 17 criteria are the spec. `scripts/score.sh` and this table are non-editable.
  - Amendment 2026-08-21 by goal owner: c17 added (minimal-token inter-agent protocol); max 16 → 17.

## Operating Mode

- [x] **Converge** — Stop when all 17 criteria pass.

### Stopping Conditions

Stop and report when ANY of:
- All 17 criteria pass (score = 17)
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

Convergence steering: when ≥75% of criteria pass (≥13/17), stop adding optional surface and converge — remaining failures only.

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
| Minimal-token payload codec (DAP-mini) | c17 | `docs/protocol.md` §Compact payload: 1–3 char field codes + shared abbreviation dictionary as the single spec; mcp-bridge `codec` module implements it; tests assert round-trip equality, ≥50% size reduction vs verbose JSON, and cross-agent Q→A comprehension between two codec instances; hub stays zero-knowledge (codec output is just E2E plaintext input) |
| kimi-code packaging | docs | `kimi.plugin.json` with `mcpServers` entry — documented in `docs/authoring.md` |

### Native adapters (c9, c10, c11)

| Action | Impact | How |
|---|---|---|
| omp extension | c9 | ExtensionAPI: `registerTool` (send/dm/inbox), inbound → `sendMessage` steer injection wakes idle turn, `ctx.setInterval` reconnect, `appendEntry` durable inbox state |
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
9. **One codec, one spec** — the compact payload format lives only in `docs/protocol.md`; every adapter's encode/decode follows it verbatim. Codec output is plaintext *input to* E2E encryption — hub never sees it.

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
Ending score:   NN/17
Iterations:     N
Criteria met:   (list of passing)
Remaining gaps: (list of failing with blockers)
Next actions:   (what a human or future agent should do next)
```

Anti-premature-completion: complete only when score = 17 AND verification ran AND no useful next action exists. Never mark complete after a plan, scaffold, or partial criteria.
