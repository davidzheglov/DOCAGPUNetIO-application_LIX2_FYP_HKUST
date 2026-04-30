#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  run_live_pipeline.sh — Host-side launcher for live Binance → receivers
#
#  Architecture:
#    Host: data_source --mode live --dest 192.168.100.2:6005
#      ↓ (tmfifo_net0 management network, unicast UDP)
#    DPU ARM: dpu_relay --listen-port 6005 --iface 10.10.10.3
#      ↓ (p0 → bridge → host PF0, multicast UDP)
#    Host receivers: T1/T2/T3/T4 listening on 239.0.0.1:5005
#
#  Prerequisites:
#    - dpu_relay_dpu built and copied to DPU ARM
#    - SSH keyless auth to ubuntu@192.168.100.2
#    - data_source_live built on host (with libwebsockets)
#
#  Usage:
#    ./scripts/run_live_pipeline.sh --tier 1
#    ./scripts/run_live_pipeline.sh --tier 4 --symbols BTCUSDT,ETHUSDT
#    ./scripts/run_live_pipeline.sh --tier 1 --harness 127.0.0.1 --fillsim 127.0.0.1
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
DPU_ARM_IP="192.168.100.2"
DPU_ARM_USER="ubuntu"
DPU_RELAY_PORT="6005"
DPU_MCAST_IFACE="10.10.10.3"
DPU_RELAY_PATH="/home/ubuntu/dpu_relay"

RECEIVER_IFACE="ens21f0np0"
DPDK_PCI="0000:bd:00.0"
RDMA_DEV="mlx5_0"
GPU_ID="1"
GPU_PCIE="0000:ac:00.0"
NIC_PCIE="0000:bd:00.0"

TIER=""
SYMBOLS="BTCUSDT,ETHUSDT"
HARNESS_IP="127.0.0.1"
FILLSIM_IP="127.0.0.1"
RATE=""

BINDIR="bin"
DATA_SOURCE="${BINDIR}/data_source_live"
DPU_RELAY_HOST="${BINDIR}/dpu_relay_dpu"

# ── Parse arguments ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --tier)
            TIER="$2"; shift 2 ;;
        --symbols)
            SYMBOLS="$2"; shift 2 ;;
        --rate)
            RATE="$2"; shift 2 ;;
        --harness)
            HARNESS_IP="$2"; shift 2 ;;
        --fillsim)
            FILLSIM_IP="$2"; shift 2 ;;
        --dpu-user)
            DPU_ARM_USER="$2"; shift 2 ;;
        --dpu-ip)
            DPU_ARM_IP="$2"; shift 2 ;;
        --dpu-relay-path)
            DPU_RELAY_PATH="$2"; shift 2 ;;
        --dpu-mcast-iface)
            DPU_MCAST_IFACE="$2"; shift 2 ;;
        --receiver-iface)
            RECEIVER_IFACE="$2"; shift 2 ;;
        --dpdk-pci)
            DPDK_PCI="$2"; shift 2 ;;
        --rdma-dev)
            RDMA_DEV="$2"; shift 2 ;;
        --gpu)
            GPU_ID="$2"; shift 2 ;;
        --gpu-pcie)
            GPU_PCIE="$2"; shift 2 ;;
        --nic-pcie)
            NIC_PCIE="$2"; shift 2 ;;
        --help|-h)
            cat <<'EOF'
Usage: run_live_pipeline.sh --tier <1|2|3|4> [options]

Required:
  --tier <N>              Receiver tier to launch (1, 2, 3, or 4)

Options:
  --symbols <SYM,...>     Binance symbols (default: BTCUSDT,ETHUSDT)
  --rate <hz>             Ticks/sec limit for data_source (default: unlimited)
  --harness <ip>          Benchmark harness IP (default: 127.0.0.1)
  --fillsim <ip>          Fill simulator IP (default: 127.0.0.1)
  --dpu-user <user>       DPU ARM SSH user (default: ubuntu)
  --dpu-ip <ip>           DPU ARM management IP (default: 192.168.100.2)
  --dpu-relay-path <path> Path to dpu_relay on DPU ARM (default: /home/ubuntu/dpu_relay)
  --dpu-mcast-iface <ip>  DPU relay multicast egress IP (default: 10.10.10.3)
  --receiver-iface <dev>  T1 receiver interface (default: ens21f0np0)
  --dpdk-pci <pci>        T2 NIC PCIe address (default: 0000:bd:00.0)
  --rdma-dev <dev>        T3 RDMA device (default: mlx5_0)
  --gpu <id>              T4 CUDA device id (default: 1)
  --gpu-pcie <pci>        T4 GPU PCIe address (default: 0000:ac:00.0)
  --nic-pcie <pci>        T4 NIC PCIe address (default: 0000:bd:00.0)

Examples:
  ./scripts/run_live_pipeline.sh --tier 1
  ./scripts/run_live_pipeline.sh --tier 4 --symbols BTCUSDT
  ./scripts/run_live_pipeline.sh --tier 1 --harness 127.0.0.1 --fillsim 127.0.0.1
EOF
            exit 0 ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1 ;;
    esac
done

if [[ -z "$TIER" ]]; then
    echo "Error: --tier is required (1, 2, 3, or 4)" >&2
    echo "Run with --help for usage." >&2
    exit 1
fi

# ── Validate binaries exist ──────────────────────────────────────────────────
if [[ ! -x "$DATA_SOURCE" ]]; then
    echo "Error: data_source_live not found at $DATA_SOURCE" >&2
    echo "Build with: make data_source_live" >&2
    exit 1
fi

if [[ ! -x "$DPU_RELAY_HOST" ]]; then
    echo "Error: dpu_relay_dpu not found at $DPU_RELAY_HOST" >&2
    echo "Build with: make dpu_relay_dpu" >&2
    exit 1
fi

# ── Determine receiver binary ────────────────────────────────────────────────
case "$TIER" in
    1) RECEIVER="${BINDIR}/cpu_receiver" ;;
    2) RECEIVER="${BINDIR}/dpdk_receiver" ;;
    3) RECEIVER="${BINDIR}/rdma_receiver" ;;
    4) RECEIVER="${BINDIR}/gpu_receiver" ;;
    *) echo "Error: invalid tier '$TIER' (must be 1-4)" >&2; exit 1 ;;
esac

if [[ ! -x "$RECEIVER" ]]; then
    echo "Error: receiver not found at $RECEIVER" >&2
    echo "Build with: make t${TIER}" >&2
    exit 1
fi

# ── Copy relay to DPU if needed ──────────────────────────────────────────────
echo "[pipeline] Checking DPU relay..."
if ! ssh -o ConnectTimeout=5 "${DPU_ARM_USER}@${DPU_ARM_IP}" "test -x ${DPU_RELAY_PATH}" 2>/dev/null; then
    echo "[pipeline] Copying dpu_relay_dpu to DPU ARM..."
    scp "$DPU_RELAY_HOST" "${DPU_ARM_USER}@${DPU_ARM_IP}:${DPU_RELAY_PATH}"
fi

# ── Start DPU relay ──────────────────────────────────────────────────────────
echo "[pipeline] Starting dpu_relay on DPU ARM..."
ssh -f "${DPU_ARM_USER}@${DPU_ARM_IP}" \
    "nohup ${DPU_RELAY_PATH} --listen-port ${DPU_RELAY_PORT} --iface ${DPU_MCAST_IFACE} > /tmp/dpu_relay.log 2>&1 &"
sleep 1

# Verify relay is running
if ! ssh "${DPU_ARM_USER}@${DPU_ARM_IP}" "pgrep -f dpu_relay" >/dev/null 2>&1; then
    echo "Error: dpu_relay failed to start on DPU ARM" >&2
    ssh "${DPU_ARM_USER}@${DPU_ARM_IP}" "cat /tmp/dpu_relay.log" >&2 || true
    exit 1
fi
echo "[pipeline] DPU relay running"

# ── Start receiver ───────────────────────────────────────────────────────────
echo "[pipeline] Starting T${TIER} receiver..."
RECEIVER_PID=""

case "$TIER" in
    1)
        $RECEIVER --tier 1 --iface "$RECEIVER_IFACE" \
            --harness "$HARNESS_IP" --fillsim "$FILLSIM_IP" &
        RECEIVER_PID=$!
        ;;
    2)
        # DPDK receiver — requires hugepages setup
        sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
            $RECEIVER -a "$DPDK_PCI" -l 0-1 -n 4 -- \
            --port 0 --tier 2 --harness "$HARNESS_IP" --fillsim "$FILLSIM_IP" &
        RECEIVER_PID=$!
        ;;
    3)
        $RECEIVER --dev "$RDMA_DEV" --tier 3 \
            --harness "$HARNESS_IP" --fillsim "$FILLSIM_IP" &
        RECEIVER_PID=$!
        ;;
    4)
        sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
            $RECEIVER --tier 4 --gpu "$GPU_ID" \
            --gpu-pcie "$GPU_PCIE" --nic-pcie "$NIC_PCIE" \
            --harness "$HARNESS_IP" --fillsim "$FILLSIM_IP" &
        RECEIVER_PID=$!
        ;;
esac

sleep 2

# ── Start data_source ────────────────────────────────────────────────────────
echo "[pipeline] Starting data_source --mode live..."
RATE_ARG=""
if [[ -n "$RATE" ]]; then
    RATE_ARG="--rate $RATE"
fi

$DATA_SOURCE --mode live --symbols "$SYMBOLS" --dest "${DPU_ARM_IP}:${DPU_RELAY_PORT}" $RATE_ARG &
SOURCE_PID=$!

# ── Wait and cleanup ─────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "  Live pipeline running:"
echo "    DPU relay : ${DPU_ARM_USER}@${DPU_ARM_IP}:${DPU_RELAY_PORT}"
echo "    Data source: PID ${SOURCE_PID}"
echo "    Receiver   : PID ${RECEIVER_PID} (T${TIER})"
echo ""
echo "  Press Ctrl+C to stop"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""

cleanup() {
    echo ""
    echo "[pipeline] Shutting down..."
    kill $SOURCE_PID 2>/dev/null || true
    kill $RECEIVER_PID 2>/dev/null || true
    ssh "${DPU_ARM_USER}@${DPU_ARM_IP}" "pkill -f dpu_relay" 2>/dev/null || true
    wait
    echo "[pipeline] Done."
}
trap cleanup INT TERM

wait $SOURCE_PID
cleanup
