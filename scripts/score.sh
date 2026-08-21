#!/usr/bin/env bash
# Fitness function for GOAL.md. Score = count of passing criteria (max 14).
# Exit 0 ALWAYS: non-zero exit means this script broke, not that the repo is unhealthy.
set -u
cd "$(dirname "$0")/.."

declare -A R
NOTES=()

has() { command -v "$1" >/dev/null 2>&1; }

# --- precompute test results (each heavy command runs once) ---
GO_OK=0; has go && GO_OK=1
NPM_OK=0; has npm && NPM_OK=1
DART_OK=0; has dart && DART_OK=1

hub_build_rc=1
hub_test_rc=1
hub_filter_rc=1
crap_rc=1
mcp_rc=1; omp_rc=1; dsh_rc=1; fah_rc=1

if [ "$GO_OK" = 1 ] && [ -d hub ] && ls hub/*.go >/dev/null 2>&1; then
  (cd hub && timeout 60 go build ./... >/dev/null 2>&1); hub_build_rc=$?
  (cd hub && timeout 120 go test ./... >/dev/null 2>&1); hub_test_rc=$?
  (cd hub && timeout 60 go test -run 'Channel|Direct|DM|Presence|Offline|Reconnect' ./... >/dev/null 2>&1); hub_filter_rc=$?
  if [ -x bin/crap4go ]; then
    (cd hub && timeout 120 ../bin/crap4go --run-tests --threshold 12 . >/dev/null 2>&1); crap_rc=$?
  else
    NOTES+=("crap4go binary missing (see GOAL.md bootstrap)")
  fi
else
  [ "$GO_OK" = 0 ] && NOTES+=("go toolchain missing")
fi

npm_dir_test() { # dir -> rc via npm test
  [ "$NPM_OK" = 1 ] && [ -f "$1/package.json" ] && [ -d "$1/node_modules" ] \
    && (cd "$1" && timeout 180 npm test --silent >/dev/null 2>&1)
}
npm_dir_test adapters/mcp-bridge; mcp_rc=$?
npm_dir_test adapters/omp-extension; omp_rc=$?
npm_dir_test adapters/dsh-plugin;     dsh_rc=$?
[ "$NPM_OK" = 0 ] && NOTES+=("npm toolchain missing")
if [ "$DART_OK" = 1 ] && [ -f adapters/fah-hub-client/pubspec.yaml ]; then
  (cd adapters/fah-hub-client && timeout 180 dart test >/dev/null 2>&1); fah_rc=$?
else
  [ "$DART_OK" = 0 ] && NOTES+=("dart toolchain missing")
fi

# --- criteria ---
# c1: hub compiles
[ "$hub_build_rc" = 0 ] && R[c1_hub_build]=pass || R[c1_hub_build]=fail

# c2: crypto unit tests exist and suite passes (ed25519 identity, sign/verify, x25519 E2E, ACL deny)
if [ "$hub_test_rc" = 0 ] && grep -rqi 'ed25519\|x25519' hub --include='*_test.go' 2>/dev/null; then
  R[c2_crypto_tests]=pass; else R[c2_crypto_tests]=fail; fi

# c3: channel broadcast + DM routing integration tests pass
if [ "$hub_filter_rc" = 0 ] && grep -rqi 'Channel' hub --include='*_test.go' 2>/dev/null && grep -rqi 'DM\|Direct' hub --include='*_test.go' 2>/dev/null; then
  R[c3_routing_tests]=pass; else R[c3_routing_tests]=fail; fi

# c4: presence + offline mailbox + reconnect tests pass
if [ "$hub_filter_rc" = 0 ] && grep -rqi 'Presence' hub --include='*_test.go' 2>/dev/null && grep -rqi 'Offline\|Reconnect' hub --include='*_test.go' 2>/dev/null; then
  R[c4_presence_tests]=pass; else R[c4_presence_tests]=fail; fi

# c5: CRAP quality gate — max CRAP <= 12 with coverage (crap4go, pre-commit mirror)
[ "$crap_rc" = 0 ] && R[c5_crap_gate]=pass || R[c5_crap_gate]=fail

# c6: deploy artifacts — Dockerfile + compose + CGO-free static build
if [ -f hub/Dockerfile ] && [ -f hub/compose.yml ] && [ "$GO_OK" = 1 ] && [ -d hub ] \
  && (cd hub && CGO_ENABLED=0 timeout 60 go build -o /dev/null . >/dev/null 2>&1); then
  R[c6_deploy_artifacts]=pass; else R[c6_deploy_artifacts]=fail; fi

# c7: universal MCP bridge adapter — test suite green
[ "$mcp_rc" = 0 ] && R[c7_mcp_tests]=pass || R[c7_mcp_tests]=fail

# c8: MCP conformance — initialize/tools-list/tools-call handshake + live-hub roundtrip covered by tests
if [ "$mcp_rc" = 0 ] && grep -rqi 'tools/list' adapters/mcp-bridge/tests 2>/dev/null \
  && grep -rqiE 'round.?trip|spawn.*hub|live.?hub' adapters/mcp-bridge/tests 2>/dev/null; then
  R[c8_mcp_conformance]=pass; else R[c8_mcp_conformance]=fail; fi

# c9: omp extension — suite green + registers tools + reconnect loop
if [ "$omp_rc" = 0 ] && grep -rq 'registerTool' adapters/omp-extension/src 2>/dev/null \
  && grep -rq 'setInterval' adapters/omp-extension/src 2>/dev/null; then
  R[c9_omp_extension]=pass; else R[c9_omp_extension]=fail; fi

# c10: flutter_agent_harness hub client — dart test green
[ "$fah_rc" = 0 ] && R[c10_fah_tests]=pass || R[c10_fah_tests]=fail

# c11: deepseek-harness plugin — suite green + uses ctx.tools.register
if [ "$dsh_rc" = 0 ] && grep -rq 'ctx.tools.register\|ctx\.tools\.register' adapters/dsh-plugin/src 2>/dev/null; then
  R[c11_dsh_plugin]=pass; else R[c11_dsh_plugin]=fail; fi

# c12: adapter authoring guide covers all four paths + envelope contract
if [ -f docs/authoring.md ] && grep -qi 'omp' docs/authoring.md && grep -qi 'mcp' docs/authoring.md \
  && grep -qiE 'flutter_agent_harness|fah' docs/authoring.md && grep -qiE 'deepseek|dsh' docs/authoring.md \
  && grep -qi 'envelope' docs/authoring.md; then
  R[c12_authoring_doc]=pass; else R[c12_authoring_doc]=fail; fi

# c13: protocol spec — envelope schema + crypto + routing
if [ -f docs/protocol.md ] && grep -qi 'ed25519' docs/protocol.md && grep -qi 'x25519' docs/protocol.md \
  && grep -qi 'channel' docs/protocol.md && grep -qiE '\bdm\b|direct message' docs/protocol.md; then
  R[c13_protocol_doc]=pass; else R[c13_protocol_doc]=fail; fi

# c14: feasibility research list present
if [ -f docs/research.md ] && grep -qi 'kimi-code' docs/research.md && grep -qi 'aider' docs/research.md \
  && grep -qi 'opencode' docs/research.md; then
  R[c14_research_doc]=pass; else R[c14_research_doc]=fail; fi

# --- JSON output ---
ORDER="c1_hub_build c2_crypto_tests c3_routing_tests c4_presence_tests c5_crap_gate c6_deploy_artifacts c7_mcp_tests c8_mcp_conformance c9_omp_extension c10_fah_tests c11_dsh_plugin c12_authoring_doc c13_protocol_doc c14_research_doc"
score=0
parts=""
for k in $ORDER; do
  [ "${R[$k]}" = pass ] && score=$((score+1))
  parts="${parts:+$parts, }\"$k\": \"${R[$k]}\""
done
notes_json=""
for n in "${NOTES[@]:-}"; do
  [ -n "$n" ] && notes_json="${notes_json:+$notes_json, }\"$n\""
done
echo "{\"score\": $score, \"max\": 14, \"breakdown\": {$parts}${notes_json:+, \"notes\": [$notes_json]}}"
exit 0
