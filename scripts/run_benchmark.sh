#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  run_benchmark.sh — One-command driver for the T1-T4 sweep benchmark.
#
#  Wraps bin/benchmark_harness:
#    - Generates a fresh tick CSV (if missing or --regen-csv)
#    - Sweeps tiers × rates × reps
#    - Streams progress to stdout and writes a timestamped CSV in results/
#    - Cleans up zombie receivers/sources between runs
#
#  Run on lxcpu1 (the receiver host). Sender is on lxcpu2 — make sure
#  scripts/run_live_sender.sh OR the harness's spawned data_source is producing
#  packets. By default the harness spawns ./bin/data_source replay locally.
#
#  Usage:
#    ./scripts/run_benchmark.sh                                    # full sweep
#    ./scripts/run_benchmark.sh --tiers 1,4 --quick                # smoke test
#    ./scripts/run_benchmark.sh --rates 100000,500000,1000000      # custom rates
#    ./scripts/run_benchmark.sh --duration 60 --warmup 10
#    ./scripts/run_benchmark.sh --symbols 64 --csv-rows 2000000    # bigger stress
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ── Defaults ─────────────────────────────────────────────────────────────────
TIERS="1,2,3,4"
RATES="10000,50000,100000,250000,500000,1000000"
REPS=3
WARMUP=5
DURATION=30
CSV_ROWS=1000000
SYMBOLS=32
CSV_PATH="data/ticks.csv"
REGEN_CSV=0
QUICK=0
IFACE_ARG=""    # forwarded as --iface to harness (NIC IP for T2/T4 mcast egress)

while [[ $# -gt 0 ]]; do
    case $1 in
        --tiers)        TIERS="$2"; shift 2 ;;
        --rates)        RATES="$2"; shift 2 ;;
        --reps)         REPS="$2"; shift 2 ;;
        --warmup)       WARMUP="$2"; shift 2 ;;
        --duration)     DURATION="$2"; shift 2 ;;
        --csv-rows)     CSV_ROWS="$2"; shift 2 ;;
        --symbols)      SYMBOLS="$2"; shift 2 ;;
        --csv)          CSV_PATH="$2"; shift 2 ;;
        --regen-csv)    REGEN_CSV=1; shift ;;
        --iface)        IFACE_ARG="--iface $2"; shift 2 ;;
        --quick)        QUICK=1; shift ;;
        --help|-h)      sed -n '2,22p' "$0"; exit 0 ;;
        *)              echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [[ $QUICK -eq 1 ]]; then
    TIERS="1,4"
    RATES="50000,500000"
    REPS=1
    DURATION=10
    WARMUP=2
fi

# ── Logging ──────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    C=$'\e[1;36m'; OK=$'\e[1;32m'; ERR=$'\e[1;31m'; DIM=$'\e[2m'; R=$'\e[0m'
else
    C=""; OK=""; ERR=""; DIM=""; R=""
fi
log()    { printf "%s[bench]%s %s\n" "$C" "$R" "$*"; }
log_ok() { printf "%s[bench]%s %s✓%s %s\n" "$C" "$R" "$OK" "$R" "$*"; }
log_err(){ printf "%s[bench]%s %s✗%s %s\n" "$C" "$R" "$ERR" "$R" "$*" >&2; }

# ── Pre-flight ───────────────────────────────────────────────────────────────
log "Checking binaries..."
HARNESS="bin/benchmark_harness"
DATA_SRC="bin/data_source"
declare -A TIER_BIN=(
    [1]="bin/cpu_receiver"
    [2]="bin/dpdk_receiver"
    [3]="bin/rdma_receiver"
    [4]="bin/gpu_receiver"
)

[[ -x "$HARNESS"  ]] || { log_err "Missing $HARNESS — run: make harness"; exit 1; }
[[ -x "$DATA_SRC" ]] || { log_err "Missing $DATA_SRC — run: make data_source"; exit 1; }

for tier in ${TIERS//,/ }; do
    bin="${TIER_BIN[$tier]:-}"
    [[ -z "$bin"   ]] && { log_err "Unknown tier $tier"; exit 1; }
    [[ -x "$bin"   ]] || { log_err "Missing $bin — run: make t${tier}"; exit 1; }
done
log_ok "All required binaries present for tiers: $TIERS"

# ── Tick CSV ─────────────────────────────────────────────────────────────────
if [[ ! -s "$CSV_PATH" || $REGEN_CSV -eq 1 ]]; then
    log "Generating tick CSV: $CSV_ROWS rows × $SYMBOLS symbols → $CSV_PATH"
    python3 scripts/generate_ticks.py --rows "$CSV_ROWS" --symbols "$SYMBOLS" \
                                      --output "$CSV_PATH"
else
    rows=$(wc -l < "$CSV_PATH")
    log_ok "Reusing existing $CSV_PATH ($((rows-1)) rows). Use --regen-csv to refresh."
fi

# ── Output path ──────────────────────────────────────────────────────────────
mkdir -p results
TS=$(date +%Y%m%d_%H%M%S)
RESULTS="results/benchmark_${TS}.csv"

# ── Run plan summary ─────────────────────────────────────────────────────────
N_TIERS=$(echo "$TIERS" | tr ',' '\n' | wc -l)
N_RATES=$(echo "$RATES" | tr ',' '\n' | wc -l)
TOTAL_RUNS=$((N_TIERS * N_RATES * REPS))
PER_RUN_S=$((WARMUP + DURATION + 2))   # +2 for spawn/teardown
ETA_S=$((TOTAL_RUNS * PER_RUN_S))
ETA_M=$((ETA_S / 60))

cat <<EOF

${C}══════════════════════════════════════════════════════════════════════${R}
  Sweep plan
    tiers     : $TIERS
    rates     : $RATES
    reps      : $REPS
    warmup    : ${WARMUP}s
    duration  : ${DURATION}s
    runs      : $TOTAL_RUNS  (~${ETA_M} min total)
    csv       : $CSV_PATH ($CSV_ROWS rows, $SYMBOLS symbols)
    results   : $RESULTS
${C}══════════════════════════════════════════════════════════════════════${R}

EOF

# ── Cleanup trap ─────────────────────────────────────────────────────────────
HARNESS_PID=""
cleanup() {
    log "Cleaning up..."
    if [[ -n "$HARNESS_PID" ]] && kill -0 "$HARNESS_PID" 2>/dev/null; then
        kill "$HARNESS_PID" 2>/dev/null || true
        wait "$HARNESS_PID" 2>/dev/null || true
    fi
    pkill -f bin/cpu_receiver  2>/dev/null || true
    pkill -f bin/dpdk_receiver 2>/dev/null || true
    pkill -f bin/rdma_receiver 2>/dev/null || true
    pkill -f bin/gpu_receiver  2>/dev/null || true
    pkill -f bin/data_source   2>/dev/null || true
}
trap cleanup INT TERM EXIT

# ── Run ──────────────────────────────────────────────────────────────────────
log "Starting harness — Ctrl+C to abort"
echo ""

"$HARNESS" \
    --csv-dir  "$(dirname "$CSV_PATH")" \
    --results  "$RESULTS" \
    --tiers    "$TIERS" \
    --rates    "$RATES" \
    --reps     "$REPS" \
    --warmup   "$WARMUP" \
    --duration "$DURATION" \
    $IFACE_ARG &
HARNESS_PID=$!
wait "$HARNESS_PID"
HARNESS_PID=""

echo ""
log_ok "Sweep complete → $RESULTS"
log    "Plot with: python3 scripts/plot_benchmark.py $RESULTS"
