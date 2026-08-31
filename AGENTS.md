# distributed-agents-platform — Agent Guide

Self-hosted Go hub + 3 in-repo adapters (omp, mcp-bridge/universal, dsh/Cordis) plus fah/Dart, extracted to https://github.com/vabhzw17eg2qu4m9-bit/fah_hub_client (pub.dev: `fah_hub_client`): pubkey-ACL'd E2E chat channels, DM, presence across agent harnesses. Score 18/18 (`./scripts/score.sh`). `docs/research.md` = feasibility study; `GOAL.md` = contract (locked; 3 owner amendments: c17 agent-negotiated glossary, c18 zero-config onboarding, c18 widened to ALL adapters).

## Laws (owner-set, violated twice — do not repeat)

1. **ALL implementation via subagents.** Orchestrator decomposes, dispatches, verifies, commits. Hand-edits only for review fixes.
2. **All adapters behave identically.** Any feature lands in all in-repo adapters in one wave (parallel agents, disjoint dirs) or not at all; fah follows cross-repo by contract.
3. Commit per sub-phase; no attribution lines. Goal-loop commits: `[S:N→N] cN-slug: …`; maintenance: conventional (`feat|fix|docs|chore(scope): …`).
4. **Owner amendment 2026-08-31:** fah adapter extracted to https://github.com/vabhzw17eg2qu4m9-bit/fah_hub_client (pub.dev: `fah_hub_client`) — its gates (dart analyze/test, crap4dart ≤ 12, coverage/CRAP ratchets, publish pipeline) live there. Adapter parity covers the three in-repo TS adapters plus fah cross-repo by contract, not by monorepo tests.

## Wire contract — docs/protocol.md is law

Ratified addenda (implemented, spec'd): hello carries additive signed `x25519` field, echoed in `agent_info` (DM key agreement; AAD `dap1|frame_id|recipient`); `join{channel,chanPubkey}` op (first join creates channel, registers pubkey; re-join idempotent); channel fanout includes sender echo, DM none; **no resumeToken** (cut over everywhere); send ids unique per sender, dedupe latches only AFTER acceptance (`replayed_nonce` on real duplicates); client keepalive ~20s ping/10s pong deadline, terminate on miss → reconnect loop heals; registry identity is NEVER pruned (offline agents stay addressable — whois + DM→mailbox); chankey invites `{t:chankey,channel,pub,priv}` travel as normal E2E DMs (possession of channel priv = membership); glossary negotiation frames `{t:gloss,act:propose|ack|drop}` + `~abbrev` compaction — abbreviations emerge at runtime, no fixed dictionary; canonical JSON = sorted keys, no whitespace, NO HTML escaping (Go `SetEscapeHTML(false)` parity). /ws auth: `Authorization: Bearer` on the upgrade (master secret or hub-issued client secret; wrong/missing → HTTP 401 pre-upgrade); enrollment `{t:enroll}` → `{t:enrolled,secret}` (base64url 32B) on master-authenticated post-hello connections — client persists `clientSecret` (env `DAP_MASTER_SECRET`/`DAP_CLIENT_SECRET`); issued secrets stored sha256-only (`HUB_SECRETS_FILE`), bound to the hello name, re-enroll replaces (BREAKING).

## Adapter parity (identical in all adapters — in-repo three + fah cross-repo)

Keepalive watchdog; honest `not connected` failures; hub error frames surfaced (never silent `ok:true`); zero-config: env (`DAP_HUB_URL/DAP_AGENT_NAME/DAP_KEY_PATH/DAP_CHANNELS_FILE`) > `~/.dap/config.json` > defaults (url `ws://127.0.0.1:8787/ws`); identity `~/.dap/keys/<adapter>/<name|hostname>.key` auto 0600 (name = identity; per-adapter subdir prevents cross-harness eviction wars; EXCEPTION: omp still defaults to the flat `~/.dap/keys/<name>.key` with legacy fallback — subdir move pending); channels in machine-shared `~/.dap/channels.json`, auto-keygen on first send, auto-join known channels each welcome. dap_invite accepts a NAME for a user not yet on the hub: arms a pending invite persisted machine-shared as `invites: [{name,channel}]` in `~/.dap/config.json` (dedupe lowercased name+channel; 16-hex id or online name → immediate chankey DM; ambiguous → honest error; channel auto-created under the inviter's key at arm time; ~15s presence poller auto-DMs the chankey when the name comes online — checks at arm time and each welcome; own agentId never self-matches). Tools: `dap_send, dap_dm, dap_invite, dap_inbox, dap_whois, dap_status, dap_peers` (ONLINE only unless `includeOffline:true`; omp: always online-only and excludes self — owner decision 2026-08-28; other adapters keep includeOffline), `dap_connect {host,name?,channel?}` (normalize host→`ws://…/ws`; runtime retarget; persists url/name/default room to config — injectable via `DAP_CONFIG_FILE`, tests never write the real `~/.dap`; foreign existing room needs a member's dap_invite — blind join posts unreadably). Harness deltas: fah exposes public methods (`inviteTo`, `connectTo`) not tools (upstream PR shape has no registry); omp adds `/dap <host> [name] [channel]` + `/dap invite` (prints the paste-ready connect line for a new user) + `/dap invite <name|agentId> [channel]` (presence-resolved name; DMs the chankey — one invite path shared with dap_invite; an unknown/offline NAME arms a pending invite persisted as `invites` in config — the chankey DM fires automatically when that name comes online, via a managed ctx.setInterval poller; omp host args also default the `/ws` path like mcp-bridge) slash commands + footer status via `ui.setStatus('dap', …)`.

## Hub law

CRAP ≤ 12 per function (`../bin/crap4go --run-tests --threshold 12 .` — pre-commit enforced, never `--no-verify`); ciphertext-only in stores/logs/RAM (test proves it); one WS per agent (evict old); mailbox cap 100 drop-oldest; frame cap 1MB, per-client queue cap 4MB shed-on-overflow; stdlib + `coder/websocket` + `x/crypto` only; deterministic offline tests (`httptest`).

## Quality gates

- **Master**: `./scripts/score.sh` — 18 criteria, must stay 18/18; run after any change, commit only non-regressing.
- hub: `go vet ./...` clean; CRAP ≤ 12 per function (`../bin/crap4go --run-tests --threshold 12 .`) — pre-commit hook enforced, never `--no-verify`.
- fah adapter: extracted (Law 4) — `dart analyze`, `crap4dart ≤ 12`, coverage/CRAP ratchets and publish pipeline live in its own repo.
- TS adapters (mcp-bridge, omp-extension, dsh-plugin): `tsc --noEmit` clean + full suite green (`npm test`).
- Every adapter suite green is itself a gate: omp/mcp/dsh `npm test`, hub `go test ./...`; fah `dart test` in its own repo.

## Environment

Go ≥ 1.22, Node ≥ 20. Once: `git config core.hooksPath .githooks`; `mkdir -p bin .tools && git clone --depth 1 https://github.com/vabhzw17eg2qu4m9-bit/crap4go .tools/crap4go && (cd .tools/crap4go && go build -o ../../bin/crap4go .)`; `npm install` in mcp-bridge/omp-extension/dsh-plugin.

Gotchas (symptom → fix): `c1/c6` "VCS status exit 128" → `git config --global --add safe.directory <repo>` (evaporates between shells). Adapter dirs may flip container-read-only after host-side writes (virtiofs) — host stays writable; restart VM/docker sharing; NEVER create git worktrees/other repo structures without owner approval. omp's TUI renders to `/dev/tty` — not capturable in container ptys; do not spawn interactive omp there (it hijacks the harness console pane).

## Test conventions

Deterministic offline; localhost only; no sleep-sync. TS: manual/fake timers (no real `setTimeout` waits); error surfacing + watchdog tests use stub peers. Go: deadline reads; **never read after `expectQuiet`** (read deadline is fatal in coder/websocket). Live-hub tests (mcp) spawn the built binary with `-buildvcs=false` (avoids VCS-stamp git races).

## Loading the omp extension

`omp -e adapters/omp-extension` (cwd-relative), or once in `~/.omp/agent/config.yml`: `extensions: [<absolute path to adapters/omp-extension>]`, or symlink into `~/.omp/agent/extensions/`. Edits reload via mtime cache-buster on next start.
