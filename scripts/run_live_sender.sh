#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  run_live_sender.sh — One-command launcher for the Binance → DPU sender path.
#
#  What it does (run on lxcpu2 host):
#    1. Pre-flight: confirms binaries, tmfifo, SSH, internet are all up
#    2. SSHes to the DPU ARM and starts dpu_relay (output streamed back here)
#    3. Waits for the relay to be listening
#    4. Starts data_source_live on the host
#    5. Tags every log line so you can tell who said what
#    6. On Ctrl+C: kills both cleanly
#
#  Receivers on lxcpu1 are NOT started by this script — run them separately.
#  Use scripts/run_live_pipeline.sh if you also want a tier launched here.
#
#  Usage:
#    ./scripts/run_live_sender.sh                          # defaults
#    ./scripts/run_live_sender.sh --symbols BTCUSDT
#    ./scripts/run_live_sender.sh --verbose                # extra preflight info
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
DPU_USER="${DPU_USER:-ubuntu}"
DPU_IP="${DPU_IP:-192.168.100.2}"
DPU_RELAY_PATH="${DPU_RELAY_PATH:-/home/ubuntu/dpu_relay}"
DPU_MCAST_IFACE="${DPU_MCAST_IFACE:-10.10.10.3}"
RELAY_PORT="${RELAY_PORT:-6005}"
SYMBOLS="${SYMBOLS:-BTCUSDT,ETHUSDT}"

BINDIR="bin"
DATA_SOURCE="${BINDIR}/data_source_live"
DPU_RELAY_HOST="${BINDIR}/dpu_relay_dpu"

VERBOSE=0

# ── Argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --symbols)         SYMBOLS="$2"; shift 2 ;;
        --dpu-ip)          DPU_IP="$2"; shift 2 ;;
        --dpu-user)        DPU_USER="$2"; shift 2 ;;
        --dpu-relay-path)  DPU_RELAY_PATH="$2"; shift 2 ;;
        --iface)           DPU_MCAST_IFACE="$2"; shift 2 ;;
        --port)            RELAY_PORT="$2"; shift 2 ;;
        --verbose|-v)      VERBOSE=1; shift ;;
        --help|-h)
            sed -n '2,20p' "$0"
            exit 0 ;;
        *)
            echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Logging helpers ──────────────────────────────────────────────────────────
# Colored prefixes if stdout is a TTY. Three streams: pipeline, relay, source.
if [[ -t 1 ]]; then
    C_PIPE=$'\e[1;36m'   # cyan bold
    C_RELAY=$'\e[1;33m'  # yellow bold
    C_SRC=$'\e[1;32m'    # green bold
    C_OK=$'\e[1;32m'
    C_ERR=$'\e[1;31m'
    C_DIM=$'\e[2m'
    C_RST=$'\e[0m'
else
    C_PIPE=""; C_RELAY=""; C_SRC=""; C_OK=""; C_ERR=""; C_DIM=""; C_RST=""
fi

log()       { printf "%s[pipeline]%s %s\n" "$C_PIPE"  "$C_RST" "$*"; }
log_ok()    { printf "%s[pipeline]%s %s✓%s %s\n" "$C_PIPE" "$C_RST" "$C_OK" "$C_RST" "$*"; }
log_err()   { printf "%s[pipeline]%s %s✗%s %s\n" "$C_PIPE" "$C_RST" "$C_ERR" "$C_RST" "$*" >&2; }
log_step()  { printf "\n%s── %s ──%s\n" "$C_PIPE" "$*" "$C_RST"; }
log_dbg()   { [[ $VERBOSE -eq 1 ]] && printf "%s    %s%s\n" "$C_DIM" "$*" "$C_RST" || true; }

# Tag and forward a child process's stderr/stdout into our terminal, line-buffered.
# Usage: cmd 2>&1 | tag "[RELAY]" "$C_RELAY"
tag() {
    local label="$1" color="$2"
    awk -v lbl="$label" -v c="$color" -v r="$C_RST" \
        '{ printf("%s%s%s %s\n", c, lbl, r, $0); fflush(); }'
}

# ── Pre-flight checks ────────────────────────────────────────────────────────
log_step "Pre-flight checks"

# 1. Local binaries
if [[ ! -x "$DATA_SOURCE" ]]; then
    log_err "Missing $DATA_SOURCE — build with: make data_source_live"
    exit 1
fi
log_ok "Found $DATA_SOURCE"
log_dbg "$(file -b "$DATA_SOURCE" | head -c 80)"

if [[ ! -x "$DPU_RELAY_HOST" ]]; then
    log_err "Missing $DPU_RELAY_HOST — build with: make dpu_relay_dpu"
    exit 1
fi
log_ok "Found $DPU_RELAY_HOST (cross-compiled aarch64 binary for DPU ARM)"
log_dbg "$(file -b "$DPU_RELAY_HOST" | head -c 80)"

# 2. tmfifo connectivity
log "Pinging DPU ARM at $DPU_IP over tmfifo_net0..."
if ! ping -c 1 -W 2 "$DPU_IP" >/dev/null 2>&1; then
    log_err "Cannot reach $DPU_IP — is tmfifo_net0 up?"
    log_err "  Check: ip -br addr show tmfifo_net0"
    exit 1
fi
RTT=$(ping -c 3 -W 2 "$DPU_IP" 2>/dev/null | awk -F'/' '/rtt/ { print $5 " ms avg" }')
log_ok "DPU ARM reachable (${RTT:-rtt unknown})"

# 3. Internet to Binance
log "Probing Binance..."
if ! curl -sI --max-time 5 https://stream.binance.com/ws/btcusdt@aggTrade >/dev/null; then
    log_err "Cannot reach stream.binance.com — check internet/DNS/firewall"
    exit 1
fi
log_ok "stream.binance.com reachable over TLS"

# 4. SSH to DPU
log "Verifying passwordless SSH to ${DPU_USER}@${DPU_IP}..."
if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "${DPU_USER}@${DPU_IP}" "true" 2>/dev/null; then
    log_err "SSH to ${DPU_USER}@${DPU_IP} failed (no password prompt allowed)"
    log_err "  Set up keyless auth: ssh-copy-id ${DPU_USER}@${DPU_IP}"
    exit 1
fi
log_ok "SSH OK"

# 5. Relay binary on DPU — copy if missing or stale
log "Checking dpu_relay binary on DPU ARM..."
LOCAL_HASH=$(sha256sum "$DPU_RELAY_HOST" | awk '{print $1}')
REMOTE_HASH=$(ssh "${DPU_USER}@${DPU_IP}" "test -x $DPU_RELAY_PATH && sha256sum $DPU_RELAY_PATH | awk '{print \$1}'" 2>/dev/null || echo "")

if [[ "$LOCAL_HASH" != "$REMOTE_HASH" ]]; then
    log "Copying fresh dpu_relay → ${DPU_USER}@${DPU_IP}:${DPU_RELAY_PATH}"
    scp -q "$DPU_RELAY_HOST" "${DPU_USER}@${DPU_IP}:${DPU_RELAY_PATH}"
    log_ok "Relay binary synced"
else
    log_ok "Relay binary on DPU is up to date (sha256 matches)"
fi
log_dbg "local sha256:  $LOCAL_HASH"
log_dbg "remote sha256: $REMOTE_HASH"

# 6. Confirm DPU ARM has the multicast iface
log "Checking ${DPU_MCAST_IFACE} exists on DPU ARM..."
if ! ssh "${DPU_USER}@${DPU_IP}" "ip -br -4 addr | grep -qw $DPU_MCAST_IFACE"; then
    log_err "Address $DPU_MCAST_IFACE not found on any DPU ARM interface"
    log_err "  Run on DPU: ip -br -4 addr"
    exit 1
fi
log_ok "Address $DPU_MCAST_IFACE present on DPU ARM"

# 7. Make sure no stale relay is already running
if ssh "${DPU_USER}@${DPU_IP}" "pgrep -f dpu_relay" >/dev/null 2>&1; then
    log "Killing stale dpu_relay process on DPU ARM..."
    ssh "${DPU_USER}@${DPU_IP}" "pkill -f dpu_relay" 2>/dev/null || true
    sleep 0.5
fi

# ── Run plan summary ─────────────────────────────────────────────────────────
log_step "Run plan"
cat <<EOF
  Binance                                    Receivers (lxcpu1)
     │ wss                                       ▲ udp mcast
     ▼                                           │
  ┌──────────────────┐  unicast 6005   ┌────────┴────────┐
  │ data_source_live │ ──────────────► │    dpu_relay    │
  │  (this host)     │  via tmfifo_net0│ (DPU ARM ${DPU_IP}) │
  └──────────────────┘                 └─────────────────┘
                                                │
                                  --iface ${DPU_MCAST_IFACE}  239.0.0.1:5005

  Symbols       : ${SYMBOLS}
  Relay port    : ${RELAY_PORT}
  DPU SSH       : ${DPU_USER}@${DPU_IP}
  DPU egress    : ${DPU_MCAST_IFACE} → ovsbr1 → p0 → cable

EOF

# ── Cleanup trap ─────────────────────────────────────────────────────────────
RELAY_SSH_PID=""
SOURCE_PID=""

cleanup() {
    log_step "Shutdown"
    if [[ -n "$SOURCE_PID" ]] && kill -0 "$SOURCE_PID" 2>/dev/null; then
        log "Stopping data_source_live (pid $SOURCE_PID)..."
        kill "$SOURCE_PID" 2>/dev/null || true
        wait "$SOURCE_PID" 2>/dev/null || true
    fi
    if [[ -n "$RELAY_SSH_PID" ]] && kill -0 "$RELAY_SSH_PID" 2>/dev/null; then
        log "Stopping ssh tunnel to relay (pid $RELAY_SSH_PID)..."
        kill "$RELAY_SSH_PID" 2>/dev/null || true
    fi
    log "Killing any stray dpu_relay on DPU ARM..."
    ssh -o ConnectTimeout=3 "${DPU_USER}@${DPU_IP}" "pkill -f dpu_relay" 2>/dev/null || true
    log_ok "Shutdown complete"
}
trap cleanup INT TERM EXIT

# ── Start the relay on the DPU ARM ───────────────────────────────────────────
log_step "Starting dpu_relay on DPU ARM"

# We want the relay's stderr/stdout streamed back to this terminal with a
# [RELAY] tag. Do NOT use ssh -f (that detaches and we lose visibility).
# Instead: keep the ssh in foreground, pipe its output through tag().
# `-tt` forces a TTY so SIGINT propagates to the remote process when ssh dies.
ssh -tt -o ServerAliveInterval=10 "${DPU_USER}@${DPU_IP}" \
    "$DPU_RELAY_PATH --listen-port $RELAY_PORT --iface $DPU_MCAST_IFACE" \
    2>&1 | tag "[RELAY]" "$C_RELAY" &
RELAY_SSH_PID=$!
log_dbg "ssh pid: $RELAY_SSH_PID"

# Wait for the relay's "listening on UDP port" banner before launching source.
# It writes to stderr; we tee'd it through tag, but we also need a way to
# detect readiness. Simplest: poll the port from the host.
log "Waiting for relay to bind UDP port $RELAY_PORT on DPU..."
for i in $(seq 1 30); do
    # nc -uz returns 0 if a UDP packet to the port doesn't elicit ICMP unreach.
    # That's a weak signal but works here because the relay is the only thing
    # binding that port.
    if ssh -o ConnectTimeout=3 "${DPU_USER}@${DPU_IP}" \
        "ss -lun | grep -q ':$RELAY_PORT'" 2>/dev/null; then
        log_ok "Relay is listening (took ${i} probe(s))"
        break
    fi
    sleep 0.3
    if [[ $i -eq 30 ]]; then
        log_err "Relay did not start within 9s"
        exit 1
    fi
done

# ── Start data_source_live on the host ───────────────────────────────────────
log_step "Starting data_source_live on host"

"$DATA_SOURCE" --mode live \
    --symbols "$SYMBOLS" \
    --dest "${DPU_IP}:${RELAY_PORT}" \
    2>&1 | tag "[SOURCE]" "$C_SRC" &
SOURCE_PID=$!
log_dbg "source pid: $SOURCE_PID"

log_step "Pipeline live — Ctrl+C to stop"

# ── Wait for either side to exit ─────────────────────────────────────────────
# `wait -n` returns when the first child exits, so we tear down promptly if
# either dies.
wait -n "$SOURCE_PID" "$RELAY_SSH_PID" 2>/dev/null || true
log_err "One side exited unexpectedly — tearing down"
exit 1
