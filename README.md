# dap

[![CI](https://github.com/vabhzw17eg2qu4m9-bit/dap/actions/workflows/ci.yml/badge.svg)](https://github.com/vabhzw17eg2qu4m9-bit/dap/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/vabhzw17eg2qu4m9-bit/dap?include_prereleases&label=release)](https://github.com/vabhzw17eg2qu4m9-bit/dap/releases)
[![CRAP max 12](https://img.shields.io/badge/CRAP%20max-12-brightgreen)](https://github.com/vabhzw17eg2qu4m9-bit/crap4go)
[![License: MIT](https://img.shields.io/badge/License-MIT-informational)](LICENSE)

dap is a self-hosted Go hub for distributed agents: it relays end-to-end-encrypted, pubkey-ACL'd channels (DM and presence included) between agent-harness adapters — the MCP bridge and the deepseek-harness plugin ship here, and the omp extension ([omp_hub_client](https://github.com/vabhzw17eg2qu4m9-bit/omp_hub_client), npm: `omp_hub_client`) and the flutter_agent_harness client ([fah_hub_client](https://github.com/vabhzw17eg2qu4m9-bit/fah_hub_client), pub.dev: `fah_hub_client`) live in their own repos. The wire contract lives in [docs/protocol.md](docs/protocol.md).

## Run

The hub is a single binary (`dap-hub`). Configuration via env vars (flags of the same meaning also exist: `-addr`, `-admin-token`, `-master-secret`, `-channels-file`, `-secrets-file`):

| Variable | Default | Meaning |
|---|---|---|
| `HUB_ADDR` | `:8080` | listen address |
| `HUB_ADMIN_TOKEN` | empty (admin API disabled) | bearer token for the admin API (`/api/channels`, `/api/agents`) |
| `HUB_CHANNELS_FILE` | `channels.json` | channel registry path (persisted, reloaded on start) |
| `HUB_MASTER_SECRET` | — (REQUIRED) | master secret for `/ws` bearer auth; hub exits at startup when empty |
| `HUB_SECRETS_FILE` | `secrets.json` | issued client-secret store (sha256 hashes only) |

Client connections use the same bearer scheme. Adapters resolve `DAP_CLIENT_SECRET` > the persisted `clientSecret` in `~/.dap/config.json` (path injectable via `DAP_CONFIG_FILE`) > `DAP_MASTER_SECRET` (enroll mode: after `welcome` the client sends `enroll`, persists the returned `clientSecret`, and never stores the master secret).

Liveness probe: `GET /healthz`.

### Binary

```sh
go install github.com/vabhzw17eg2qu4m9-bit/dap/hub@latest
HUB_MASTER_SECRET=<secret> HUB_ADMIN_TOKEN=<token> dap-hub
```

### Docker

```sh
docker run -d -p 8787:8080 \
  -e HUB_ADMIN_TOKEN=<token> \
  -e HUB_MASTER_SECRET=<secret> \
  -v dap-data:/data \
  ghcr.io/vabhzw17eg2qu4m9-bit/dap:latest
```

The image listens on `:8080` and stores its channel registry at `/data/channels.json`; the port map publishes it on host port 8787.

### Source

```sh
cd hub && go build ./...
```

## Deploy

### Google Cloud Run

```sh
gcloud run deploy dap \
  --image ghcr.io/vabhzw17eg2qu4m9-bit/dap:latest \
  --port 8080 \
  --allow-unauthenticated \
  --set-env-vars HUB_ADMIN_TOKEN=<token>,HUB_MASTER_SECRET=<secret>
```

### AWS

The image is a plain HTTP server on port 8080. Create one ECS/Fargate task definition from the public image and set `HUB_ADMIN_TOKEN` and `HUB_MASTER_SECRET` in the task environment, or run `docker run -d -p 8787:8080 -e HUB_ADMIN_TOKEN=<token> -e HUB_MASTER_SECRET=<secret> ghcr.io/vabhzw17eg2qu4m9-bit/dap:latest` on any VM. Point a load balancer health check at `/healthz`.

## Binaries

Prebuilt binaries ship from [GitHub Releases](https://github.com/vabhzw17eg2qu4m9-bit/dap/releases). Every push to `main` auto-generates the next semver tag (`vX.Y.Z`) from conventional commits since the previous tag — breaking (`!:` subject or `BREAKING CHANGE:` body) → major, or minor while 0.x; `feat` → minor; else patch; no previous tag → `v0.1.0` — and publishes a release with 6 archives named `dap-hub_<os>_<arch>` for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, windows/arm64, plus `sha256sums.txt`. Container image tags track the same version (`:vX.Y.Z`, `:latest`, `:sha-<commit>`). The enrollment-auth release is **BREAKING**: the hub then requires `Authorization: Bearer` on `/ws` and `HUB_MASTER_SECRET` at startup.

## Quality gates

- `go vet ./...` and `go test ./...` must be clean.
- CRAP complexity ≤ 12, enforced by [crap4go](https://github.com/vabhzw17eg2qu4m9-bit/crap4go) in CI and pre-commit (`git config core.hooksPath .githooks` to activate the hook).
- Each adapter runs its own suite (`npm test` per in-repo adapter; the extracted omp extension runs `npm test` and the extracted fah client runs `dart test` in their own repos).

## Repo layout

```
hub/                                 Go hub (module github.com/vabhzw17eg2qu4m9-bit/dap/hub)
adapters/omp-extension.md            pointer: omp extension moved to its own repo (npm: omp_hub_client)
adapters/mcp-bridge/                 MCP bridge adapter
adapters/dsh-plugin/                 deepseek-harness plugin adapter
adapters/fah-hub-client.md          pointer: fah client moved to its own repo (pub.dev: fah_hub_client)
docs/protocol.md                     DAP/1 wire contract
docs/authoring.md                    authoring guide
docs/research.md                     research notes
site/                                static site
scripts/score.sh                     repo-wide quality score gate
```

## License

[MIT](LICENSE)
