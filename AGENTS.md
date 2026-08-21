# distributed-agents-platform — Agent Guide

Self-hosted hub connecting agent harnesses across servers: global chat channels, direct messages, presence, pubkey-controlled ACLs, end-to-end encrypted payloads. Go single-binary hub + four adapters (omp extension, universal MCP bridge, flutter_agent_harness PR, deepseek-harness plugin). Greenfield — see `docs/research.md` for the grounded feasibility study and `GOAL.md` for the completion contract.

## Working Principles

- Code-as-truth: docs can lie, source can't. `docs/research.md` cites sources; verify before relying.
- Read the nearest AGENTS.md in the directory tree before working in a directory (none yet — add one per adapter when it grows).
- Focused changes; no drive-by refactors. Every changed line traces to `GOAL.md` criteria.
- No attribution lines in commits. Conventional commit titles.

## Project Map

| Path | What it is |
|---|---|
| `hub/` | Go hub: WebSocket server, Ed25519 identity/ACL, X25519 E2E routing, channels/DM/presence, offline mailboxes. yoloit-hub relay pattern. |
| `adapters/mcp-bridge/` | Universal adapter: TS stdio MCP server holding one outbound WSS. Works for kimi-code (via plugin), Claude Code, Gemini CLI, Goose, Crush, Amp, Cline, Roo Code. |
| `adapters/omp-extension/` | oh-my-pi extension: `registerTool` + steer-injection delivery + reconnect loop. |
| `adapters/fah-hub-client/` | Dart `MessagingRepository` implementation + `FahPlugin` — upstreamable PR to IstiN/flutter_agent_harness. |
| `adapters/dsh-plugin/` | Cordis plugin for deepseek-harness: `ctx.tools.register` + `Agent.followup()` inbound wake. Ships as `dsh.bundle`. |
| `docs/` | `research.md` (feasibility), `protocol.md` (wire spec), `authoring.md` (how to write an adapter for any harness). |
| `scripts/score.sh` | Fitness function — 14 criteria. Non-negotiable truth for progress. |
| `.githooks/pre-commit` | crap4go CRAP gate on hub Go code. |

## Environment Requirements

- Go ≥ 1.22, Node ≥ 20 (+npm), Dart ≥ 3 (fah adapter only)
- Activate hooks once: `git config core.hooksPath .githooks`
- Build quality gate once: `mkdir -p bin .tools && git clone --depth 1 https://github.com/vabhzw17eg2qu4m9-bit/crap4go .tools/crap4go && (cd .tools/crap4go && go build -o ../../bin/crap4go .)`
- Adapter installs: `npm install` in each of `adapters/mcp-bridge`, `adapters/omp-extension`, `adapters/dsh-plugin`; `dart pub get` in `adapters/fah-hub-client`

## General Coding Rules

- Go hub: stdlib first; single allowed dep is `coder/websocket`. `golang.org/x/crypto` for ed25519/nacl.
- Hub must never be able to read message payloads — ciphertext-only in stores, logs, RAM. A test proves it.
- Max CRAP 12 per function (target 8), enforced by pre-commit; run manually: `(cd hub && ../bin/crap4go --run-tests --threshold 12 .)`
- One outbound WebSocket per agent; hub evicts the old connection on re-connect (yoloit-hub pattern).
- Tests deterministic and offline; `httptest` contract tests for HTTP/WS surfaces.
- Do not reinvent A2A — chat/presence/DM only; task-interop protocols are out of scope.

## Workflow Requirements

- After any change: `./scripts/score.sh` — compare before/after; commit only non-regressing.
- Append one line per iteration to `iterations.jsonl`.
- Adapters must not fork harness cores: omp = extension, fah = upstreamable PR, dsh = plugin/bundle, everything else = MCP.
- Never commit secrets, private keys, or `bin/`, `.tools/`, `node_modules/`.
