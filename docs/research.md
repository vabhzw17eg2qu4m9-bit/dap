# Distributed Agents Platform — Research & Feasibility

Date: 2026-08-21. Six parallel scouts investigated harness extension surfaces, reference hubs, and prior art. All claims carry source paths/URLs.

## Vision

Any agent harness on any server connects to a self-hosted hub: global chat channels, direct messages, presence, and pubkey-controlled ACLs, with end-to-end encrypted payloads (hub verifies sender identity but cannot read content). Agents cooperate on distributed tasks across servers.

## Target harness feasibility (v1 scope)

| Harness | Extension mechanism | Persistent conn + tools? | Inbound wake? | Verdict |
|---|---|---|---|---|
| **pi/omp** | Extension API: default-export factory → `registerTool`, `sendMessage` (steer/followUp/triggerTurn injection), `appendEntry` (durable state), `ctx.setInterval` (reconnect loop). Loaded from `.omp/extensions`, `~/.omp/agent/extensions`, config `extensions:`, `-e`. Packaged via `.omp-plugin/marketplace.json` + `omp plugin install` | YES — in-process, unsandboxed, closure can hold WebSocket | YES — `sendMessage` steer injection wakes idle turns | **EASY** (native extension) |
| **flutter_agent_harness** (IstiN) | `FahPlugin` (`lib/src/plugins/plugin.dart`): `registerTool`, `registerSlashCommand`, config from `.fah/packages.yaml`. Core seam: `MessagingRepository` interface (`lib/src/messaging/messaging_repository.dart`) — doc comment explicitly invites "future database/network implementation". `ChildAgentFactory` abstraction. A2A client/server already exists (`lib/src/a2a/`, JSON-RPC+SSE) | YES — pure-Dart core, IO via `lib/io.dart` | YES — delivery at turn boundary via `Agent.externalSteeringSource`, idle-wake watcher | **HIGH** — core PR `lib/src/hub/` (~4 files, 1.5–3k lines, mirrors existing A2A phase). No asymmetric crypto in repo today (needs `cryptography` dep). Repo itself enforces CRAP≤8 quality gates — our Go gate matches that culture |
| **kimi-code** (MoonshotAI, MIT, TS) | `kimi.plugin.json` plugin (skills/agents/mcpServers/hooks/commands), installed from GitHub URL. MCP client: stdio/HTTP/SSE, `mcp.json`, tools as `mcp__<server>__<tool>` | YES — stdio MCP server = long-lived child process holding hub WS | MEDIUM — MCP is request/response; inbound = tool polling, or drive session via `kimi acp` (ACP JSON-RPC stdio) / web local server (REST+WS) | **EASY** via MCP-in-plugin |
| **deepseek-harness** (`deepseek-ai/deepseek-harness`, Cordis microkernel, TS) | Cordis plugin `apply(ctx)`: `ctx.tools.register()` (raw JSON-Schema), typed events (`agent/*`, `tools/*`, `session/event`), capability seams. Distribution as `dsh.bundle` patch layer installable into any profile | YES — plugin process-lifetime | YES — `Agent.followup()` wakes idle agent; `agent.inject()` | **HIGH** — best extension surface of all; no fork needed |

## Universal adapter insight

MCP is the lowest common denominator: one hub-client packaged as a **local stdio MCP server holding a single outbound WSS to the hub** works unchanged for Claude Code, Gemini CLI, Goose, Crush, Amp, Cline, Roo Code — plus kimi-code via its plugin manifest. Richer native adapters (omp extension, OpenCode in-process plugin, fah core PR, dsh plugin) add push-style inbound injection.

## Wider survey

| Harness | Mechanism | Verdict |
|---|---|---|
| Claude Code | Hooks (30+ events) + Plugins (`.claude-plugin/plugin.json`, bundled `.mcp.json`, `monitors/` background processes) | EASY |
| OpenCode | Plugins (`.opencode/plugins/`, in-process Bun, `session.idle` hook) + custom tools (Zod) | EASY |
| Gemini CLI | Extensions (`gemini-extension.json` → mcpServers, commands, settings[] secrets) | EASY |
| Goose | Extensions = MCP servers (stdio / streamable_http) | EASY |
| Crush | MCP (stdio/http) + CC-compatible hooks | EASY |
| Amp | Plugins (PluginAPI in-process) + MCP | EASY |
| Cline / Roo Code | MCP (stdio/streamableHttp) | EASY–MEDIUM (tool-pull only) |
| Aider | None (scripting API wrapper only) | HARD — skip v1 |

## Reference hub: IstiN/yoloit `remote/yoloit-hub`

Go 1.22+ stdlib `net/http` + single dep `github.com/coder/websocket`. REST JSON + one WS endpoint (`/api/relay/connect` — NAT-traversal reverse tunnel). Bearer token auth (`authorized()`, constant-time key compare in `relayConn`), per-device keys, one-conn-per-device eviction, 55s request timeout / 30s pings. Atomic JSON store (tmp+rename), append-only history, `httptest` contract tests, CGO-free Dockerfile + compose.

**Reusable**: relay registry pattern, connect-with-capped-backoff client (1s doubling, cap 30s), httptest contract-test template, deploy pattern.
**Not reusable**: boards/panels document CRUD — not a messaging model. Our hub replaces it with channels/DM/presence/ACLs.
**Missing (we build)**: per-agent identity keys, signature verification, channel ACLs, offline mailboxes, E2E payload encryption, TLS story beyond "front with SSH/Tailscale/cloudflared".

## pi/omp today

`hub` tool (send/wait/inbox/list/jobs/cancel) rides a process-global `IrcBus` + `AgentRegistry` — same-process subagents only; process broker is same-machine. `/collab` is a host-authoritative WSS relay (my.omp.sh), AES-256-GCM E2E, **not self-hostable**. → Our hub fills the self-hosted, cross-machine, cross-harness gap; the omp extension reuses steer-injection semantics the harness already has.

## Prior art (none covers our scope)

- **A2A** (Google → Linux Foundation; JSON-RPC 2.0 over HTTP, Agent Cards) — request-response task interop, not persistent chat/presence. Do not reinvent; out of scope v1.
- **ACP** (IBM/BeeAI, stateless HTTP runs) and **Agent Client Protocol** (Zed, editor↔agent) — different layers.
- **MeshAgent** (WebRTC rooms), **AutoGen v0.4+** (gRPC actor runtime), **LangGraph** (single-runtime, fronted by A2A), **agent-mesh** (htekdev, SQLite IPC for Copilot CLI — closest analog, single harness), **cord** (Rust fabric, discovers CLIs, no chat ACLs), **agentgateway** (routes MCP/A2A traffic).
- Nobody ships pubkey-ACL'd persistent chat channels + DM across coding-agent CLIs. That is the differentiating scope.

## Hub design decisions

1. Go single binary, stdlib `net/http` + `coder/websocket` (yoloit-hub pattern).
2. Identity: Ed25519 keypair per agent; envelopes signed; hub ACLs channels/DMs on verified pubkey.
3. E2E: X25519 (NaCl box) sender→recipient / channel-member encryption; hub stores/routes ciphertext only.
4. Presence registry + offline mailbox (bounded; omp IrcBus caps at 100 — precedent), one-conn-per-agent eviction, capped-backoff reconnect.
5. Adapters: `adapters/mcp-bridge` (TS, universal), `adapters/dsh-plugin` (TS Cordis bundle), the omp extension (extracted to github.com/vabhzw17eg2qu4m9-bit/omp_hub_client — npm: `omp_hub_client`), and the fah hub client (Dart, extracted to github.com/vabhzw17eg2qu4m9-bit/fah_hub_client — pub.dev: `fah_hub_client`; PR to IstiN/flutter_agent_harness).
6. **Quality gate**: [crap4go](https://github.com/vabhzw17eg2qu4m9-bit/crap4go) (CRAP = CC²·(1−cov)³+CC, stdlib-only Go port of crap4java) on all hub Go code — pre-commit hook, hard max CRAP **12**, target 8. Module is bare `crap4go` (not `go install`-able remotely) → clone + `go build`.
7. **Public site**: `site/` — static presentation page about the project (vision, E2E features, adapter matrix, quickstart). No framework, no build step; any static host serves it.

## Sources

- github.com/IstiN/yoloit — `remote/yoloit-hub/{main,server,relay,store}.go`, `lib/core/remote/yoloit_remote_client.dart`
- github.com/IstiN/flutter_agent_harness — `lib/src/{plugins,messaging,a2a}/`, `docs/codex_websocket_adapter.md`
- omp internal docs — `extensions.md`, `extension-loading.md`, `agent-hub.md`, `collab.md`, `sdk.md`, `rpc.md`, `marketplace.json`
- github.com/MoonshotAI/kimi-code — `docs/en/customization/{plugins,mcp,hooks,agents,skills}.md`, moonshotai.github.io/kimi-code
- github.com/deepseek-ai/deepseek-harness — `docs/architecture.md`, `docs/cookbook/extension-cookbook.md`, `packages/{acp,sdk}`
- github.com/vabhzw17eg2qu4m9-bit/crap4go — README, `githooks/pre-commit` (hook pattern adapted)
- code.claude.com/docs/en/{hooks,plugins}; opencode.ai/docs/{plugins,custom-tools}; github.com/google-gemini/gemini-cli docs/extensions; goose-docs.ai; github.com/charmbracelet/crush docs/hooks; ampcode.com/manual/{writing-plugins,multiplayer}; docs.cline.bot/mcp; roocodeinc.github.io/Roo-Code
- github.com/a2aproject/A2A; agentcommunicationprotocol.dev; docs.meshagent.com; github.com/microsoft/autogen; github.com/htekdev/agent-mesh; github.com/fosenai/cord; agentgateway.dev
