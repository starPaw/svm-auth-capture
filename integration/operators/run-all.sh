#!/usr/bin/env bash
# SAC-006 live Devnet evidence run (acceptance criteria 2-5). Runs every scenario against the
# committed entry points and drivers in this directory and retains, under
# docs/evidence/sac-006/runs/<run-id>/: a manifest (source revision, file hashes, record pin,
# binary hash, non-secret configuration), every log, finalized state snapshots, operation and
# submission journals, and reconciliation reports. Secrets never enter the run directory: keys
# are read from paths, identified by public key only, and the RPC URL is checked absent at the end.
#
# Required env: SOLANA_RPC_URL, SAC006_FACILITATOR_KEYPAIR_PATH, SAC006_PAYER_KEYPAIR_PATH,
#               SAC006_SERVER_KEYPAIR_PATH, SAC006_ASSET_MINT (classic SPL test mint; the payer
#               and server ATAs must exist and the payer must hold >= 300 units).
# Optional:     SAC006_DEPLOYMENT_RECORD_PATH (defaults to the accepted SAC-007 record),
#               SAC006_PORT (8787), SAC006_RESOURCE_PORT (8788).
# Usage, from integration/:  evidence/run-all.sh
set -euo pipefail
cd "$(dirname "$0")/.."

: "${SOLANA_RPC_URL:?}" "${SAC006_FACILITATOR_KEYPAIR_PATH:?}" "${SAC006_PAYER_KEYPAIR_PATH:?}" "${SAC006_SERVER_KEYPAIR_PATH:?}" "${SAC006_ASSET_MINT:?}"
export SAC006_DEPLOYMENT_RECORD_PATH="${SAC006_DEPLOYMENT_RECORD_PATH:-../docs/evidence/sac-007/deployment-identity.v1.json}"
export SAC006_PORT="${SAC006_PORT:-8787}" SAC006_RESOURCE_PORT="${SAC006_RESOURCE_PORT:-8788}"
# Settlement window for the in-process drivers (the services keep the 60s runtime default).
export SAC006_CONFIRM_TIMEOUT_MS="${SAC006_CONFIRM_TIMEOUT_MS:-120000}"
NODE=(node --experimental-strip-types --no-warnings)

# The evidence must describe committed code: refuse a dirty runtime/driver tree.
dirty="$(git status --porcelain -- src evidence package.json package-lock.json tsconfig.json)"
if [[ -n "$dirty" ]]; then echo "refusing to run: uncommitted changes in the runtime or drivers:"; echo "$dirty"; exit 1; fi

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$(cd ../docs/evidence/sac-006 && pwd)/runs/$RUN_ID"
mkdir -p "$OUT/logs" "$OUT/reports"
export SAC006_EVIDENCE_DIR="$OUT" SAC006_EVIDENCE_EVENTS="$OUT/events.jsonl"
LOG="$OUT/logs"
step() { echo; echo "==== $*" | tee -a "$LOG/run-all.log"; }
run() { local name="$1"; shift; "$@" 2>&1 | tee "$LOG/$name.log"; return "${PIPESTATUS[0]}"; }

eval "$("${NODE[@]}" evidence/pubkeys.ts)"
export SAC006_BEARER_TOKEN="$(openssl rand -hex 24)"
export SAC006_FACILITATOR_URL="http://127.0.0.1:$SAC006_PORT" SAC006_RESOURCE_URL="http://127.0.0.1:$SAC006_RESOURCE_PORT"
export SAC006_FACILITATOR_JOURNAL_DIR="$OUT/facilitator-journal" SAC006_STORE_DIR="$OUT/operation-store"
export SAC006_ALLOWLIST_MERCHANT="$SERVER" SAC006_ALLOWLIST_MINT="$SAC006_ASSET_MINT" SAC006_FEE_PAYER="$SPONSOR"
export SAC006_AUTHORIZE_AMOUNT=100 SAC006_CAPTURE_DEADLINE_SECONDS=60 SAC006_REFUND_DEADLINE_SECONDS=600
export SAC006_CLIENT_TRUSTED_MERCHANT="$SERVER" SAC006_CLIENT_TRUSTED_MINT="$SAC006_ASSET_MINT" SAC006_CLIENT_MAX_AMOUNT=100 SAC006_CLIENT_EXPECTED_FEE_PAYER="$SPONSOR"

step "manifest"
{
  echo "run_id: $RUN_ID"
  echo "source_revision: $(git rev-parse HEAD)"
  echo "runtime_and_driver_tree_clean: true"
  echo "node: $(node --version)"
  echo "deployment_record: $SAC006_DEPLOYMENT_RECORD_PATH sha256=$(shasum -a 256 "$SAC006_DEPLOYMENT_RECORD_PATH" | cut -d' ' -f1)"
  echo "deployment_record_pin: $(grep -o 'revision: "[0-9a-f]*"' src/deployment-record.ts) $(grep -o 'acceptance: "[^"]*"' src/deployment-record.ts)"
  if [[ -f ../target/deploy/svm_auth_capture.so ]]; then echo "local_sbf_sha256: $(shasum -a 256 ../target/deploy/svm_auth_capture.so | cut -d' ' -f1)"; fi
  echo "sponsor: $SPONSOR"; echo "payer: $PAYER"; echo "server: $SERVER"; echo "mint: $SAC006_ASSET_MINT"
  echo "authorize_amount: $SAC006_AUTHORIZE_AMOUNT capture_deadline_seconds: $SAC006_CAPTURE_DEADLINE_SECONDS refund_deadline_seconds: $SAC006_REFUND_DEADLINE_SECONDS"
  echo "services_settlement_window_ms: 60000 (runtime default) drivers_settlement_window_ms: $SAC006_CONFIRM_TIMEOUT_MS"
  echo "rpc: $("${NODE[@]}" -e 'import("./src/rpc-ledger.ts").then(m => console.log(m.redactRpcUrl(process.env.SOLANA_RPC_URL)))')"
} | tee "$OUT/MANIFEST.txt"
shasum -a 256 src/*.ts evidence/* package.json package-lock.json tsconfig.json > "$OUT/SOURCE_SHA256SUMS"

FAC_PID=""; RES_PID=""
start_services() {
  local tag="$1"
  npm run --silent devnet > "$LOG/facilitator-$tag.log" 2>&1 & FAC_PID=$!
  until grep -q "listening" "$LOG/facilitator-$tag.log"; do kill -0 "$FAC_PID" 2>/dev/null || { cat "$LOG/facilitator-$tag.log"; exit 1; }; sleep 1; done
  npm run --silent devnet:resource > "$LOG/resource-$tag.log" 2>&1 & RES_PID=$!
  until grep -q "listening" "$LOG/resource-$tag.log"; do kill -0 "$RES_PID" 2>/dev/null || { cat "$LOG/resource-$tag.log"; exit 1; }; sleep 1; done
  cat "$LOG/facilitator-$tag.log" "$LOG/resource-$tag.log" | tee -a "$LOG/run-all.log"
}
stop_process_tree() {
  local pid="$1" child
  [[ -n "$pid" ]] || return 0
  while read -r child; do
    [[ -z "$child" ]] || stop_process_tree "$child"
  done < <(pgrep -P "$pid" || true)
  kill "$pid" 2>/dev/null || true
}
stop_services() {
  local tag="$1"
  # Stop only the processes this run owns; never kill another checkout's demo.
  stop_process_tree "$FAC_PID"
  stop_process_tree "$RES_PID"
  wait "$FAC_PID" "$RES_PID" 2>/dev/null || true
  FAC_PID=""; RES_PID=""
  sleep 1
  {
    echo "services stopped ($tag) at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "processes matching src/devnet-(server|resource-server).ts: $(pgrep -fl 'src/devnet-(server|resource-server)\.ts' || echo none)"
    for port in "$SAC006_PORT" "$SAC006_RESOURCE_PORT"; do
      if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$port/"; then echo "port $port: STILL ANSWERING"; exit 1; else echo "port $port: connection refused"; fi
    done
  } | tee "$LOG/services-stopped-$tag.log"
}
trap 'stop_services trap >/dev/null 2>&1 || true' EXIT
reconcile() { local name="$1"; shift; npm run --silent devnet:reconcile -- "$@" > "$OUT/reports/$name.json"; }
json_field() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$@"; }

step "initial state"
run 00-initial "${NODE[@]}" evidence/snapshot.ts initial

step "1. real processes over the x402 transport: authorize -> capture 60 + release (criteria 2, 5)"
export SAC006_DEMO_RELEASE_REMAINDER=true SAC006_DEMO_CAPTURE_AMOUNT=60
start_services capture
curl -s -D "$LOG/10-challenge-headers.txt" -o "$LOG/10-challenge-body.json" "$SAC006_RESOURCE_URL/resource" || true
grep -i '^payment-required:' "$LOG/10-challenge-headers.txt" | cut -d' ' -f2 | tr -d '\r' | base64 -d > "$OUT/reports/10-payment-required.json"
run 11-client-capture npm run --silent devnet:client
P1="$(grep -o '"payment": "[^"]*"' "$LOG/11-client-capture.log" | head -1 | cut -d'"' -f4)"
run 12-after-capture "${NODE[@]}" evidence/snapshot.ts "after capture" "$P1"

step "2. lost facilitator response (criteria 2, 3)"
run 13-lost-response "${NODE[@]}" evidence/lost-response.ts
FP2="$(json_field "$OUT/lost-response.result.json" fingerprint)"; P2="$(json_field "$OUT/lost-response.result.json" payment)"; DC2="$(json_field "$OUT/lost-response.result.json" captureDeadline)"
npm run --silent devnet:reconcile > "$LOG/14-unresolved-list.log"
FP1="$(ls "$SAC006_STORE_DIR" | sed 's/\.json$//' | grep -v "$FP2")"
reconcile 11-reconcile-capture "$FP1"
( unset SAC006_FACILITATOR_JOURNAL_DIR; reconcile 14-reconcile-lost-chain-search "$FP2" )
reconcile 14-reconcile-lost-facilitator-journal "$FP2"
stop_services capture

step "3. reclaim of the lost-response hold with both services stopped (criterion 2)"
run 15-wait-dc "${NODE[@]}" evidence/wait-clock.ts "$DC2" "Dc of the lost-response payment"
run 15-before-reclaim "${NODE[@]}" evidence/snapshot.ts "before reclaim (lost response)" "$P2"
run 15-reclaim npm run --silent devnet:reclaim -- "$P2"
run 15-after-reclaim "${NODE[@]}" evidence/snapshot.ts "after reclaim (lost response)" "$P2"
reconcile 15-reconcile-lost-after-reclaim "$FP2"

step "4. partial capture 30 without release, then payer reclaim at Dc with services stopped (criterion 2)"
export SAC006_DEMO_RELEASE_REMAINDER=false SAC006_DEMO_CAPTURE_AMOUNT=30
start_services partial
run 16-client-partial-capture npm run --silent devnet:client
P3="$(grep -o '"payment": "[^"]*"' "$LOG/16-client-partial-capture.log" | head -1 | cut -d'"' -f4)"
run 16-after-partial-capture "${NODE[@]}" evidence/snapshot.ts "after partial capture" "$P3"
stop_services partial
DC3="$(grep -o '"captureDeadline":"[0-9]*"' "$LOG/16-after-partial-capture.log" | head -1 | grep -o '[0-9]*')"
run 17-wait-dc "${NODE[@]}" evidence/wait-clock.ts "$DC3" "Dc of the partially captured payment"
run 17-before-reclaim "${NODE[@]}" evidence/snapshot.ts "before reclaim (partial capture)" "$P3"
run 17-reclaim npm run --silent devnet:reclaim -- "$P3"
run 17-after-reclaim "${NODE[@]}" evidence/snapshot.ts "after reclaim (partial capture)" "$P3"
FP3="$(ls "$SAC006_STORE_DIR" | sed 's/\.json$//' | grep -v -e "$FP1" -e "$FP2")"
reconcile 17-reconcile-partial "$FP3"

step "5. escrow paths and rejections on the real adapter (criteria 2, 4)"
run 20-chains "${NODE[@]}" evidence/chains.ts

step "6. fault injection around the real adapter (criterion 3)"
run 30-fault-injection "${NODE[@]}" evidence/fault-injection.ts

step "7. real resource handler failure -> void (criterion 2)"
run 40-handler-failure "${NODE[@]}" evidence/handler-failure.ts

step "final state and per-payment transaction history"
run 99-final "${NODE[@]}" evidence/snapshot.ts final
run 99-history "${NODE[@]}" evidence/history.ts

step "secret scan"
query="${SOLANA_RPC_URL#*\?}"
if grep -rqF -e "$SOLANA_RPC_URL" -e "$SAC006_BEARER_TOKEN" "$OUT" || { [[ "$query" != "$SOLANA_RPC_URL" ]] && grep -rqF -e "$query" "$OUT"; }; then
  echo "SECRET FOUND in $OUT; not keeping this run"; exit 1
fi
echo "no RPC credential or bearer token in the run directory" | tee -a "$LOG/run-all.log"
# Finish all writers, including the EXIT trap's service-stop log, before hashing.
stop_services final
trap - EXIT
echo "run complete: $OUT" | tee -a "$LOG/run-all.log"
(cd "$OUT" && find . -type f ! -name RUN_SHA256SUMS | sort | xargs shasum -a 256 > RUN_SHA256SUMS && shasum -a 256 -c RUN_SHA256SUMS)
