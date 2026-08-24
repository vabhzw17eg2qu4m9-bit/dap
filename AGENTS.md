# distributed-agents-platform — Agent Guide

Self-hosted Go hub + 4 adapters (omp, mcp-bridge/universal, fah/Dart, dsh/Cordis): pubkey-ACL'd E2E chat channels, DM, presence across agent harnesses. Score 18/18 (`./scripts/score.sh`). `docs/research.md` = feasibility study; `GOAL.md` = contract (locked; 3 owner amendments: c17 agent-negotiated glossary, c18 zero-config onboarding, c18 widened to ALL adapters).

## Laws (owner-set, violated twice — do not repeat)

1. **ALL implementation via subagents.** Orchestrator decomposes, dispatches, verifies, commits. Hand-edits only for review fixes.
2. **All adapters behave identically.** Any feature lands in all four in one wave (parallel agents, disjoint dirs) or not at all.
3. Commit per sub-phase; no attribution lines. Goal-loop commits: `[S:N→N] cN-slug: …`; maintenance: conventional (`feat|fix|docs|chore(scope): …`).

## Wire contract — docs/protocol.md is law

Ratified addenda (implemented, spec'd): hello carries additive signed `x25519` field, echoed in `agent_info` (DM key agreement; AAD `dap1|frame_id|recipient`); `join{channel,chanPubkey}` op (first join creates channel, registers pubkey; re-join idempotent); channel fanout includes sender echo, DM none; **no resumeToken** (cut over everywhere); send ids unique per sender, dedupe latches only AFTER acceptance (`replayed_nonce` on real duplicates); client keepalive ~20s ping/10s pong deadline, terminate on miss → reconnect loop heals; registry identity is NEVER pruned (offline agents stay addressable — whois + DM→mailbox); chankey invites `{t:chankey,channel,pub,priv}` travel as normal E2E DMs (possession of channel priv = membership); glossary negotiation frames `{t:gloss,act:propose|ack|drop}` + `~abbrev` compaction — abbreviations emerge at runtime, no fixed dictionary; canonical JSON = sorted keys, no whitespace, NO HTML escaping (Go `SetEscapeHTML(false)` parity).

## Adapter parity (identical in ALL four)

Keepalive watchdog; honest `not connected` failures; hub error frames surfaced (never silent `ok:true`); zero-config: env (`DAP_HUB_URL/DAP_AGENT_NAME/DAP_KEY_PATH/DAP_CHANNELS_FILE`) > `~/.dap/config.json` > defaults (url `ws://127.0.0.1:8787/ws`); identity `~/.dap/keys/<adapter>/<name|hostname>.key` auto 0600 (name = identity; per-adapter subdir prevents cross-harness eviction wars; EXCEPTION: omp still defaults to the flat `~/.dap/keys/<name>.key` with legacy fallback — subdir move pending); channels in machine-shared `~/.dap/channels.json`, auto-keygen on first send, auto-join known channels each welcome. Tools: `dap_send, dap_dm, dap_invite, dap_inbox, dap_whois, dap_status, dap_peers` (ONLINE only unless `includeOffline:true`), `dap_connect {host,name?,channel?}` (normalize host→`ws://…/ws`; runtime retarget; persists url/name/default room to config — injectable via `DAP_CONFIG_FILE`, tests never write the real `~/.dap`; foreign existing room needs a member's dap_invite — blind join posts unreadably). Harness deltas: fah exposes public methods (`inviteTo`, `connectTo`) not tools (upstream PR shape has no registry); omp adds `/dap <host> [name] [channel]` + `/dap invite` (prints the paste-ready connect line for a new user) + `/dap invite <name|agentId> [channel]` (presence-resolved name; DMs the chankey — one invite path shared with dap_invite) slash commands + footer status via `ui.setStatus('dap', …)`.

## Hub law

CRAP ≤ 12 per function (`../bin/crap4go --run-tests --threshold 12 .` — pre-commit enforced, never `--no-verify`); ciphertext-only in stores/logs/RAM (test proves it); one WS per agent (evict old); mailbox cap 100 drop-oldest; frame cap 1MB, per-client queue cap 4MB shed-on-overflow; stdlib + `coder/websocket` + `x/crypto` only; deterministic offline tests (`httptest`).

## Quality gates

- **Master**: `./scripts/score.sh` — 18 criteria, must stay 18/18; run after any change, commit only non-regressing.
- hub: `go vet ./...` clean; CRAP ≤ 12 per function (`../bin/crap4go --run-tests --threshold 12 .`) — pre-commit hook enforced, never `--no-verify`.
- fah adapter: `dart analyze` clean; `crap4dart analyze --run-tests --threshold 12` (IstiN/crap4dart) — run on change, fix over-threshold methods.
- TS adapters (mcp-bridge, omp-extension, dsh-plugin): `tsc --noEmit` clean + full suite green (`npm test`).
- Every adapter suite green is itself a gate: omp/mcp/dsh `npm test`, fah `dart test`, hub `go test ./...`.

## Environment

Go ≥ 1.22, Node ≥ 20, Dart ≥ 3. Once: `git config core.hooksPath .githooks`; `mkdir -p bin .tools && git clone --depth 1 https://github.com/vabhzw17eg2qu4m9-bit/crap4go .tools/crap4go && (cd .tools/crap4go && go build -o ../../bin/crap4go .)`; `npm install` in mcp-bridge/omp-extension/dsh-plugin; `dart pub get` in fah-hub-client.

Gotchas (symptom → fix): `c10` "Could not find bin/test.dart" → `dart pub get` in fah (`.dart_tool` dies after mount/VM events). `c1/c6` "VCS status exit 128" → `git config --global --add safe.directory <repo>` (evaporates between shells). Adapter dirs may flip container-read-only after host-side writes (virtiofs) — host stays writable; restart VM/docker sharing; NEVER create git worktrees/other repo structures without owner approval. omp's TUI renders to `/dev/tty` — not capturable in container ptys; do not spawn interactive omp there (it hijacks the harness console pane).

## Test conventions

Deterministic offline; localhost only; no sleep-sync. TS: manual/fake timers (no real `setTimeout` waits); error surfacing + watchdog tests use stub peers. Go: deadline reads; **never read after `expectQuiet`** (read deadline is fatal in coder/websocket). Live-hub tests (mcp) spawn the built binary with `-buildvcs=false` (avoids VCS-stamp git races). Dart: event-driven Completers; short real intervals allowed only where VM timers aren't injectable.

## Loading the omp extension

`omp -e adapters/omp-extension` (cwd-relative), or once in `~/.omp/agent/config.yml`: `extensions: [<absolute path to adapters/omp-extension>]`, or symlink into `~/.omp/agent/extensions/`. Edits reload via mtime cache-buster on next start.
