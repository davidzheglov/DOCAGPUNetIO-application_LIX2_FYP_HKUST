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
#    ./scripts/run_benchmark.sh --sender-password                   # prompt once for lxcpu2 SSH password
#    ./scripts/run_benchmark.sh --receiver-iface ens21f0np0
#    ./scripts/run_benchmark.sh --light-bench
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
LIGHT_BENCH=0
IFACE_ARG=""    # forwarded as --iface to harness (NIC IP for sender/DPU mcast egress)
RECEIVER_IFACE_ARG=""  # forwarded as --receiver-iface to harness (T1 CPU receiver iface name)

# ── Remote sender (lxcpu2 host) — set to empty to use local sender ──────────
SENDER_SSH="${SENDER_SSH:-lix2@lxcpu2.cse.ust.hk}"
SENDER_REMOTE_DIR="${SENDER_REMOTE_DIR:-DOCAGPUNetIO-application_LIX2_FYP_HKUST}"
SENDER_BIN="${SENDER_BIN:-\$HOME/$SENDER_REMOTE_DIR/bin/data_source}"
SENDER_CSV="${SENDER_CSV:-\$HOME/$SENDER_REMOTE_DIR/data/ticks.csv}"
SENDER_DEST="${SENDER_DEST:-192.168.100.2:6005}"
SENDER_HOST="${SENDER_SSH#*@}"

# ── DPU relay (lxcpu2 DPU ARM, reached *from* lxcpu2 host) ──────────────────
DPU_USER="${DPU_USER:-ubuntu}"
DPU_IP="${DPU_IP:-192.168.100.2}"
DPU_RELAY_PATH="${DPU_RELAY_PATH:-/home/ubuntu/dpu_relay}"
DPU_MCAST_IFACE="${DPU_MCAST_IFACE:-10.10.10.3}"
RELAY_PORT="${RELAY_PORT:-6005}"
RELAY_STATS_PATH="${RELAY_STATS_PATH:-/tmp/doca_bench_relay_stats.txt}"

# ── Cross-host clock calibration (UDP data path, started via SSH) ───────────
CLOCK_CAL_HOST="${CLOCK_CAL_HOST:-$SENDER_HOST}"
CLOCK_CAL_BIND="${CLOCK_CAL_BIND:-0.0.0.0}"
CLOCK_CAL_PORT="${CLOCK_CAL_PORT:-6006}"
CLOCK_CAL_SCRIPT="${CLOCK_CAL_SCRIPT:-\$HOME/$SENDER_REMOTE_DIR/scripts/clock_cal_server.py}"
CLOCK_TUNNEL_PID=""

LOCAL_SENDER=0   # if 1, run sender locally (T1-only loopback fallback)
SENDER_PASSWORD=0
SSH_CONTROL_PATH=""

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
        --receiver-iface) RECEIVER_IFACE_ARG="--receiver-iface $2"; shift 2 ;;
        --sender-ssh)   SENDER_SSH="$2"; shift 2 ;;
        --clock-cal-host) CLOCK_CAL_HOST="$2"; shift 2 ;;
        --clock-cal-bind) CLOCK_CAL_BIND="$2"; shift 2 ;;
        --clock-cal-port) CLOCK_CAL_PORT="$2"; shift 2 ;;
        --sender-password) SENDER_PASSWORD=1; shift ;;
        --local-sender) LOCAL_SENDER=1; SENDER_SSH=""; shift ;;
        --light-bench)  LIGHT_BENCH=1; shift ;;
        --quick)        QUICK=1; shift ;;
        --help|-h)      sed -n '2,22p' "$0"; exit 0 ;;
        *)              echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [[ $QUICK -eq 1 ]]; then
    # All four tiers, two rates, single rep — covers the full receiver matrix
    # in ~2 min so we catch tier-specific regressions before the long sweep.
    TIERS="1,2,3,4"
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

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=5)
SCP_OPTS=(-q)
log()    { printf "%s[bench]%s %s\n" "$C" "$R" "$*"; }
log_ok() { printf "%s[bench]%s %s✓%s %s\n" "$C" "$R" "$OK" "$R" "$*"; }
log_err(){ printf "%s[bench]%s %s✗%s %s\n" "$C" "$R" "$ERR" "$R" "$*" >&2; }

sender_ssh() { ssh "${SSH_OPTS[@]}" "$@"; }
sender_scp() { scp "${SCP_OPTS[@]}" "$@"; }

if [[ -n "$SENDER_SSH" && $SENDER_PASSWORD -eq 1 ]]; then
    SSH_CONTROL_PATH="/tmp/bench_sender_ssh_${USER}_$$"
    log "Opening reusable SSH session to $SENDER_SSH (password may be prompted once)..."
    if ! ssh -o BatchMode=no -o ConnectTimeout=5 \
             -o ControlMaster=yes -o ControlPersist=yes \
             -o ControlPath="$SSH_CONTROL_PATH" \
             "$SENDER_SSH" "true"; then
        log_err "SSH to $SENDER_SSH failed"
        exit 1
    fi
    SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=5 -o ControlMaster=no -o ControlPath="$SSH_CONTROL_PATH")
    SCP_OPTS=(-q -o ControlMaster=no -o ControlPath="$SSH_CONTROL_PATH")
    log_ok "Reusable SSH session established"
fi

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

# ── Remote sender pre-flight (skip if --local-sender) ────────────────────────
if [[ -n "$SENDER_SSH" ]]; then
    log "Verifying keyless SSH to $SENDER_SSH..."
    if ! sender_ssh "$SENDER_SSH" "true" 2>/dev/null; then
        log_err "SSH to $SENDER_SSH failed"
        if [[ $SENDER_PASSWORD -eq 0 ]]; then
            log_err "  Set up keyless auth once: ssh-copy-id $SENDER_SSH"
            log_err "  Or rerun with: --sender-password"
        fi
        exit 1
    fi
    log_ok "SSH OK"

    log "Checking remote data_source binary..."
    EXPANDED_BIN=$(sender_ssh "$SENDER_SSH" "echo $SENDER_BIN")
    if ! sender_ssh "$SENDER_SSH" "test -x $EXPANDED_BIN" 2>/dev/null; then
        log_err "Remote sender not found at $EXPANDED_BIN"
        log_err "  On $SENDER_SSH run: cd ~/$SENDER_REMOTE_DIR && make data_source"
        exit 1
    fi
    log_ok "Remote data_source: $EXPANDED_BIN"

    log "Checking remote clock calibration helper..."
    EXPANDED_CLOCK_SCRIPT=$(sender_ssh "$SENDER_SSH" "echo $CLOCK_CAL_SCRIPT")
    if ! sender_ssh "$SENDER_SSH" "test -f $EXPANDED_CLOCK_SCRIPT" 2>/dev/null; then
        log_err "Clock calibration helper not found at $EXPANDED_CLOCK_SCRIPT"
        log_err "  Sync the repo to $SENDER_SSH or set CLOCK_CAL_SCRIPT=/path/to/clock_cal_server.py"
        exit 1
    fi
    log_ok "Remote clock calibration helper: $EXPANDED_CLOCK_SCRIPT"

    log "Starting UDP/TCP clock calibration helper on $SENDER_SSH..."
    CLOCK_PID_FILE="/tmp/doca_clock_cal_server.pid"
    if ! sender_ssh "$SENDER_SSH" \
        "sh -lc 'if test -f $CLOCK_PID_FILE; then kill \$(cat $CLOCK_PID_FILE) 2>/dev/null || true; rm -f $CLOCK_PID_FILE; fi; \
                  nohup python3 $EXPANDED_CLOCK_SCRIPT --ip $CLOCK_CAL_BIND --port $CLOCK_CAL_PORT \
                    >/tmp/clock_cal_server.log 2>&1 </dev/null & \
                  echo \$! > $CLOCK_PID_FILE'" ; then
        log_err "failed to launch clock_cal_server.py on $SENDER_SSH"
        exit 1
    fi
    sleep 0.5
    if ! sender_ssh "$SENDER_SSH" \
        "sh -lc 'test -f $CLOCK_PID_FILE && kill -0 \$(cat $CLOCK_PID_FILE) 2>/dev/null'" \
        2>/dev/null; then
        log_err "clock_cal_server.py did not stay running on $SENDER_SSH"
        sender_ssh "$SENDER_SSH" "tail -20 /tmp/clock_cal_server.log" 2>&1 || true
        exit 1
    fi
    log_ok "Clock calibration helper running on ${CLOCK_CAL_BIND}:${CLOCK_CAL_PORT}"

    if [[ "$CLOCK_CAL_HOST" == "$SENDER_HOST" || "$CLOCK_CAL_HOST" == "lxcpu2.cse.ust.hk" ]]; then
        log "Opening persistent SSH tunnel for clock calibration..."
        ssh "${SSH_OPTS[@]}" -N \
            -L "127.0.0.1:${CLOCK_CAL_PORT}:127.0.0.1:${CLOCK_CAL_PORT}" \
            "$SENDER_SSH" &
        CLOCK_TUNNEL_PID=$!
        sleep 0.5
        if ! kill -0 "$CLOCK_TUNNEL_PID" 2>/dev/null; then
            log_err "clock calibration SSH tunnel failed to start"
            exit 1
        fi
        CLOCK_CAL_HOST="127.0.0.1"
        log_ok "Clock calibration tunnel ready at ${CLOCK_CAL_HOST}:${CLOCK_CAL_PORT}"
    fi

    log "Verifying SSH from $SENDER_SSH → $DPU_USER@$DPU_IP (DPU relay path)..."
    if ! sender_ssh "$SENDER_SSH" \
        "ssh -o BatchMode=yes -o ConnectTimeout=5 ${DPU_USER}@${DPU_IP} 'true'" 2>/dev/null; then
        log_err "lxcpu2 host cannot SSH to its DPU ARM ($DPU_USER@$DPU_IP)"
        log_err "  On $SENDER_SSH: ssh-copy-id ${DPU_USER}@${DPU_IP}"
        exit 1
    fi
    log_ok "lxcpu2 → DPU ARM SSH OK"

    log "Checking dpu_relay on DPU ARM..."
    if ! sender_ssh "$SENDER_SSH" "ssh ${DPU_USER}@${DPU_IP} 'test -x $DPU_RELAY_PATH'" 2>/dev/null; then
        log_err "dpu_relay missing on DPU ARM at $DPU_RELAY_PATH"
        log_err "  On $SENDER_SSH: cd ~/$SENDER_REMOTE_DIR && make dpu_relay_dpu && \\"
        log_err "    scp bin/dpu_relay_dpu ${DPU_USER}@${DPU_IP}:$DPU_RELAY_PATH"
        exit 1
    fi
    log_ok "dpu_relay binary present on DPU ARM"
else
    log "--local-sender: spawning data_source on this host (loopback, T1 only)"
fi

# ── Tick CSV ─────────────────────────────────────────────────────────────────
if [[ ! -s "$CSV_PATH" || $REGEN_CSV -eq 1 ]]; then
    log "Generating tick CSV: $CSV_ROWS rows × $SYMBOLS symbols → $CSV_PATH"
    python3 scripts/generate_ticks.py --rows "$CSV_ROWS" --symbols "$SYMBOLS" \
                                      --output "$CSV_PATH"
else
    rows=$(wc -l < "$CSV_PATH")
    log_ok "Reusing existing $CSV_PATH ($((rows-1)) rows). Use --regen-csv to refresh."
fi

# scp the CSV to lxcpu2 host so its data_source can replay it
if [[ -n "$SENDER_SSH" ]]; then
    EXPANDED_CSV=$(sender_ssh "$SENDER_SSH" "echo $SENDER_CSV")
    LOCAL_HASH=$(sha256sum "$CSV_PATH" | awk '{print $1}')
    REMOTE_HASH=$(sender_ssh "$SENDER_SSH" "test -f $EXPANDED_CSV && sha256sum $EXPANDED_CSV | awk '{print \$1}'" 2>/dev/null || echo "")
    if [[ "$LOCAL_HASH" != "$REMOTE_HASH" ]]; then
        log "Copying tick CSV → $SENDER_SSH:$EXPANDED_CSV"
        sender_ssh "$SENDER_SSH" "mkdir -p $(dirname "$EXPANDED_CSV")"
        sender_scp "$CSV_PATH" "$SENDER_SSH:$EXPANDED_CSV"
        log_ok "CSV synced"
    else
        log_ok "Remote CSV up to date (sha256 matches)"
    fi
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

# ── Local sudo pre-flight for privileged tiers ──────────────────────────────
NEEDS_LOCAL_SUDO=0
for tier in ${TIERS//,/ }; do
    if [[ "$tier" == "2" || "$tier" == "3" || "$tier" == "4" || "$tier" == "5" ]]; then
        NEEDS_LOCAL_SUDO=1
        break
    fi
done

if [[ $NEEDS_LOCAL_SUDO -eq 1 ]]; then
    log "Refreshing local sudo credential for privileged receiver tiers..."
    if ! sudo -v; then
        log_err "sudo authentication failed"
        exit 1
    fi
    log_ok "sudo credential ready"
fi

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
    clock cal : ${CLOCK_CAL_HOST:-local}:${CLOCK_CAL_PORT} (bind $CLOCK_CAL_BIND)
${C}══════════════════════════════════════════════════════════════════════${R}

EOF

# ── Start dpu_relay on lxcpu2 DPU ARM (via lxcpu2 host) ──────────────────────
if [[ -n "$SENDER_SSH" ]]; then
    log "Starting dpu_relay on $DPU_USER@$DPU_IP via $SENDER_SSH..."
    if ! sender_ssh "$SENDER_SSH" \
        "ssh -o BatchMode=yes -o ConnectTimeout=5 ${DPU_USER}@${DPU_IP} 'pkill -x dpu_relay 2>/dev/null || true; sleep 0.3; \
         rm -f $RELAY_STATS_PATH; \
         nohup $DPU_RELAY_PATH --listen-port $RELAY_PORT --iface $DPU_MCAST_IFACE \
              --stats-file $RELAY_STATS_PATH \
              --no-restamp \
              > /tmp/dpu_relay.log 2>&1 &'" ; then
        log_err "relay launch command returned non-zero; checking DPU log and port anyway"
    fi
    sleep 1
    if ! sender_ssh "$SENDER_SSH" \
        "ssh -o BatchMode=yes -o ConnectTimeout=5 ${DPU_USER}@${DPU_IP} 'ss -lun | grep -q :$RELAY_PORT'" 2>/dev/null; then
        log_err "dpu_relay failed to bind port $RELAY_PORT on DPU ARM"
        sender_ssh "$SENDER_SSH" \
            "ssh -o BatchMode=yes -o ConnectTimeout=5 ${DPU_USER}@${DPU_IP} 'tail -20 /tmp/dpu_relay.log'" 2>&1 || true
        exit 1
    fi
    log_ok "dpu_relay listening on $DPU_IP:$RELAY_PORT"
fi

# ── Cleanup trap ─────────────────────────────────────────────────────────────
HARNESS_PID=""
cleanup() {
    log "Cleaning up..."
    if [[ -n "$HARNESS_PID" ]] && kill -0 "$HARNESS_PID" 2>/dev/null; then
        kill "$HARNESS_PID" 2>/dev/null || true
        wait "$HARNESS_PID" 2>/dev/null || true
    fi
    if [[ -n "$CLOCK_TUNNEL_PID" ]] && kill -0 "$CLOCK_TUNNEL_PID" 2>/dev/null; then
        kill "$CLOCK_TUNNEL_PID" 2>/dev/null || true
        wait "$CLOCK_TUNNEL_PID" 2>/dev/null || true
    fi
    pkill -f bin/cpu_receiver  2>/dev/null || true
    pkill -f bin/dpdk_receiver 2>/dev/null || true
    pkill -f bin/rdma_receiver 2>/dev/null || true
    pkill -f bin/gpu_receiver  2>/dev/null || true
    pkill -f bin/data_source   2>/dev/null || true
    if [[ -n "$SENDER_SSH" ]]; then
        sender_ssh "$SENDER_SSH" \
            "pkill -x data_source 2>/dev/null || true; \
             if test -f /tmp/doca_clock_cal_server.pid; then kill \$(cat /tmp/doca_clock_cal_server.pid) 2>/dev/null || true; rm -f /tmp/doca_clock_cal_server.pid; fi; \
             ssh ${DPU_USER}@${DPU_IP} 'pkill -x dpu_relay 2>/dev/null || true'" \
            >/dev/null 2>&1 || true
        if [[ -n "$SSH_CONTROL_PATH" ]]; then
            ssh -o ControlPath="$SSH_CONTROL_PATH" -O exit "$SENDER_SSH" >/dev/null 2>&1 || true
        fi
    fi
}
trap cleanup INT TERM EXIT

# ── Run ──────────────────────────────────────────────────────────────────────
log "Starting harness — Ctrl+C to abort"
echo ""

SENDER_ARGS=()
if [[ -n "$SENDER_SSH" ]]; then
    SENDER_ARGS+=(--sender-ssh  "$SENDER_SSH")
    SENDER_ARGS+=(--sender-bin  "$SENDER_BIN")
    SENDER_ARGS+=(--sender-csv  "$SENDER_CSV")
    SENDER_ARGS+=(--sender-dest "$SENDER_DEST")
    SENDER_ARGS+=(--dpu-user "$DPU_USER")
    SENDER_ARGS+=(--dpu-ip "$DPU_IP")
    SENDER_ARGS+=(--relay-stats-path "$RELAY_STATS_PATH")
    SENDER_ARGS+=(--clock-cal-host "$CLOCK_CAL_HOST")
    SENDER_ARGS+=(--clock-cal-bind "$CLOCK_CAL_BIND")
    SENDER_ARGS+=(--clock-cal-port "$CLOCK_CAL_PORT")
    SENDER_ARGS+=(--clock-cal-script "$CLOCK_CAL_SCRIPT")
    [[ -n "$SSH_CONTROL_PATH" ]] && SENDER_ARGS+=(--sender-control-path "$SSH_CONTROL_PATH")
fi
if [[ $LIGHT_BENCH -eq 1 ]]; then
    SENDER_ARGS+=(--light-bench)
fi

"$HARNESS" \
    --csv-dir  "$(dirname "$CSV_PATH")" \
    --results  "$RESULTS" \
    --tiers    "$TIERS" \
    --rates    "$RATES" \
    --reps     "$REPS" \
    --warmup   "$WARMUP" \
    --duration "$DURATION" \
    $IFACE_ARG \
    $RECEIVER_IFACE_ARG \
    "${SENDER_ARGS[@]}" &
HARNESS_PID=$!
wait "$HARNESS_PID"
HARNESS_PID=""

echo ""
log_ok "Sweep complete → $RESULTS"
log    "Plot with: python3 scripts/plot_benchmark.py $RESULTS"
