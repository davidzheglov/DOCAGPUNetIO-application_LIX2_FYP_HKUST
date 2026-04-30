#!/usr/bin/env bash
# Live demo pipeline launcher.
#
# This script runs on the receiver host (lxcpu1). It starts:
#   1. scripts/show_risk.py to display SignalResult trade/risk output.
#   2. The selected receiver tier, using the known-good manual commands.
#   3. bash scripts/run_live_sender.sh for Binance -> DPU relay -> multicast.
#
# Receiver stdout/stderr is left visible so GPU/DPDK/RDMA kernel logs appear in
# the terminal. show_risk.py listens on UDP 5006 and prints trade signals.

set -euo pipefail

TIER=""
SYMBOLS="${SYMBOLS:-BTCUSDT,ETHUSDT}"
HARNESS_IP="${HARNESS_IP:-127.0.0.1}"
FILLSIM_IP="${FILLSIM_IP:-127.0.0.1}"
SHOW_RAW=0

DPU_USER="${DPU_USER:-ubuntu}"
DPU_IP="${DPU_IP:-192.168.100.2}"
DPU_RELAY_PATH="${DPU_RELAY_PATH:-/home/ubuntu/dpu_relay}"
DPU_MCAST_IFACE="${DPU_MCAST_IFACE:-10.10.10.3}"
RELAY_PORT="${RELAY_PORT:-6005}"

RECEIVER_IFACE="${RECEIVER_IFACE:-ens21f0np0}"
DPDK_PCI="${DPDK_PCI:-0000:bd:00.0}"
RDMA_DEV="${RDMA_DEV:-mlx5_0}"
GPU_ID="${GPU_ID:-1}"
GPU_PCIE="${GPU_PCIE:-0000:ac:00.0}"
NIC_PCIE="${NIC_PCIE:-0000:bd:00.0}"

usage() {
    cat <<EOF
Usage: $0 --tier <1|2|3|4> [options]

Options:
  --symbols <SYM,...>        Binance symbols (default: ${SYMBOLS})
  --harness <ip>             Receiver BenchmarkResult destination (default: ${HARNESS_IP})
  --fillsim <ip>             Receiver SignalResult destination (default: ${FILLSIM_IP})
  --raw-signals              Print every SignalResult instead of dashboard view
  --dpu-user <user>          DPU ARM SSH user (default: ${DPU_USER})
  --dpu-ip <ip>              DPU ARM management IP (default: ${DPU_IP})
  --dpu-relay-path <path>    DPU relay path (default: ${DPU_RELAY_PATH})
  --dpu-mcast-iface <ip>     DPU multicast egress IP (default: ${DPU_MCAST_IFACE})
  --receiver-iface <dev>     T1 interface (default: ${RECEIVER_IFACE})
  --dpdk-pci <pci>           T2 NIC PCIe (default: ${DPDK_PCI})
  --rdma-dev <dev>           T3 RDMA device (default: ${RDMA_DEV})
  --gpu <id>                 T4 CUDA device id (default: ${GPU_ID})
  --gpu-pcie <pci>           T4 GPU PCIe (default: ${GPU_PCIE})
  --nic-pcie <pci>           T4 NIC PCIe (default: ${NIC_PCIE})

Examples:
  $0 --tier 4 --symbols BTCUSDT,ETHUSDT
  $0 --tier 1 --raw-signals
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tier) TIER="$2"; shift 2 ;;
        --symbols) SYMBOLS="$2"; shift 2 ;;
        --harness) HARNESS_IP="$2"; shift 2 ;;
        --fillsim) FILLSIM_IP="$2"; shift 2 ;;
        --raw-signals) SHOW_RAW=1; shift ;;
        --dpu-user) DPU_USER="$2"; shift 2 ;;
        --dpu-ip) DPU_IP="$2"; shift 2 ;;
        --dpu-relay-path) DPU_RELAY_PATH="$2"; shift 2 ;;
        --dpu-mcast-iface|--iface) DPU_MCAST_IFACE="$2"; shift 2 ;;
        --receiver-iface) RECEIVER_IFACE="$2"; shift 2 ;;
        --dpdk-pci) DPDK_PCI="$2"; shift 2 ;;
        --rdma-dev) RDMA_DEV="$2"; shift 2 ;;
        --gpu) GPU_ID="$2"; shift 2 ;;
        --gpu-pcie) GPU_PCIE="$2"; shift 2 ;;
        --nic-pcie) NIC_PCIE="$2"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ -z "$TIER" ]]; then
    echo "Error: --tier is required" >&2
    usage >&2
    exit 1
fi

case "$TIER" in
    1) RECEIVER="bin/cpu_receiver" ;;
    2) RECEIVER="bin/dpdk_receiver" ;;
    3) RECEIVER="bin/rdma_receiver" ;;
    4) RECEIVER="bin/gpu_receiver" ;;
    *) echo "Error: invalid tier '$TIER' (must be 1, 2, 3, or 4)" >&2; exit 1 ;;
esac

[[ -x "$RECEIVER" ]] || { echo "Error: missing $RECEIVER; run make t${TIER}" >&2; exit 1; }
[[ -x "bin/data_source_live" ]] || { echo "Error: missing bin/data_source_live; run make data_source_live" >&2; exit 1; }
[[ -x "bin/dpu_relay_dpu" ]] || { echo "Error: missing bin/dpu_relay_dpu; run make dpu_relay_dpu" >&2; exit 1; }
[[ -f "scripts/run_live_sender.sh" ]] || { echo "Error: missing scripts/run_live_sender.sh" >&2; exit 1; }
[[ -f "scripts/show_risk.py" ]] || { echo "Error: missing scripts/show_risk.py" >&2; exit 1; }

if [[ -t 1 ]]; then
    C_PIPE=$'\e[1;36m'
    C_RX=$'\e[1;35m'
    C_SIG=$'\e[1;32m'
    C_SEND=$'\e[1;33m'
    C_RST=$'\e[0m'
else
    C_PIPE=""; C_RX=""; C_SIG=""; C_SEND=""; C_RST=""
fi

tag() {
    local label="$1" color="$2"
    awk -v lbl="$label" -v c="$color" -v r="$C_RST" \
        '{ printf("%s%s%s %s\n", c, lbl, r, $0); fflush(); }'
}

RX_PID=""
SIG_PID=""
SENDER_PID=""

cleanup() {
    echo
    echo "${C_PIPE}[pipeline]${C_RST} shutting down..."
    if [[ -n "$SENDER_PID" ]] && kill -0 "$SENDER_PID" 2>/dev/null; then
        kill "$SENDER_PID" 2>/dev/null || true
        wait "$SENDER_PID" 2>/dev/null || true
    fi
    if [[ -n "$RX_PID" ]] && kill -0 "$RX_PID" 2>/dev/null; then
        kill "$RX_PID" 2>/dev/null || true
        wait "$RX_PID" 2>/dev/null || true
    fi
    if [[ -n "$SIG_PID" ]] && kill -0 "$SIG_PID" 2>/dev/null; then
        kill "$SIG_PID" 2>/dev/null || true
        wait "$SIG_PID" 2>/dev/null || true
    fi
    echo "${C_PIPE}[pipeline]${C_RST} done"
}
trap cleanup INT TERM EXIT

echo "${C_PIPE}[pipeline]${C_RST} starting live T${TIER} pipeline"
echo "${C_PIPE}[pipeline]${C_RST} symbols=${SYMBOLS} dpu=${DPU_USER}@${DPU_IP} relay=${DPU_RELAY_PATH} iface=${DPU_MCAST_IFACE}"

SHOW_ARGS=(scripts/show_risk.py --rate-hz 1.0)
if [[ "$SHOW_RAW" -eq 1 ]]; then
    SHOW_ARGS+=(--raw)
fi
python3 "${SHOW_ARGS[@]}" > >(tag "[SIGNAL]" "$C_SIG") 2>&1 &
SIG_PID=$!
sleep 0.3

echo "${C_PIPE}[pipeline]${C_RST} starting receiver command for T${TIER}"
case "$TIER" in
    1)
        sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}" \
            bin/cpu_receiver \
            --tier 1 --iface "$RECEIVER_IFACE" \
            --harness "$HARNESS_IP" --fillsim "$FILLSIM_IP" \
            > >(tag "[RX-T1]" "$C_RX") 2>&1 &
        RX_PID=$!
        ;;
    2)
        sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}" \
            bin/dpdk_receiver \
            -a "$DPDK_PCI" -l 0-1 -n 4 -- \
            --port 0 --tier 2 \
            --harness "$HARNESS_IP" --fillsim "$FILLSIM_IP" \
            > >(tag "[RX-T2]" "$C_RX") 2>&1 &
        RX_PID=$!
        ;;
    3)
        sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}" \
            bin/rdma_receiver \
            --dev "$RDMA_DEV" --tier 3 \
            --harness "$HARNESS_IP" --fillsim "$FILLSIM_IP" \
            > >(tag "[RX-T3]" "$C_RX") 2>&1 &
        RX_PID=$!
        ;;
    4)
        sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}" \
            bin/gpu_receiver --tier 4 --gpu "$GPU_ID" \
            --gpu-pcie "$GPU_PCIE" \
            --nic-pcie "$NIC_PCIE" \
            --harness "$HARNESS_IP" --fillsim "$FILLSIM_IP" \
            > >(tag "[RX-T4]" "$C_RX") 2>&1 &
        RX_PID=$!
        ;;
esac

sleep 2

echo "${C_PIPE}[pipeline]${C_RST} starting sender: bash scripts/run_live_sender.sh"
DPU_USER="$DPU_USER" \
DPU_IP="$DPU_IP" \
DPU_RELAY_PATH="$DPU_RELAY_PATH" \
DPU_MCAST_IFACE="$DPU_MCAST_IFACE" \
RELAY_PORT="$RELAY_PORT" \
SYMBOLS="$SYMBOLS" \
    bash scripts/run_live_sender.sh \
        --symbols "$SYMBOLS" \
        --dpu-user "$DPU_USER" \
        --dpu-ip "$DPU_IP" \
        --dpu-relay-path "$DPU_RELAY_PATH" \
        --iface "$DPU_MCAST_IFACE" \
        --port "$RELAY_PORT" \
        > >(tag "[SENDER]" "$C_SEND") 2>&1 &
SENDER_PID=$!

echo
echo "${C_PIPE}[pipeline]${C_RST} live pipeline running. Press Ctrl+C to stop."
wait "$SENDER_PID"
