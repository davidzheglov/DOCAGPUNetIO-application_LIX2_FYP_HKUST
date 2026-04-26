#!/usr/bin/env bash
#
# diagnose_crosslink.sh — Diagnose the cross-DPU cable link between cpu1 and cpu2.
#
# Run ON cpu1 HOST (lxcpu1):
#   bash scripts/diagnose_crosslink.sh
#
# The script SSHes into both DPU ARMs and cpu2 host automatically.

set +e

# ── Connection targets ──────────────────────────────────────────────────
CPU1_DPU_SSH="ubuntu@192.168.100.2"       # cpu1 DPU ARM via tmfifo
CPU2_HOST_SSH="lix2@lxcpu2.cse.ust.hk"    # cpu2 host
CPU2_DPU_SSH_VIA_CPU2="ubuntu@192.168.100.2"  # cpu2 DPU ARM (from cpu2 host)

# ── Expected config ─────────────────────────────────────────────────────
CPU1_HOST_NIC="ens21f0np0"      # cpu1 host PF0 (cable side)
CPU1_HOST_IP="10.10.10.2"
CPU1_DPU_PORT="p0"              # physical port facing cable
CPU1_DPU_BRIDGE="ovsbr1"        # OVS bridge on cpu1 DPU ARM
CPU1_DPU_REP="pf0hpf"           # host PF0 representor

CPU2_HOST_NIC="enp129s0f0"      # cpu2 host PF0 (cable side)
CPU2_DPU_PORT="p0"              # physical port facing cable
CPU2_DPU_BRIDGE="ovsbr1"        # OVS bridge on cpu2 DPU ARM
CPU2_DPU_REP="pf0hpf"           # host PF0 representor
CPU2_DPU_IP="10.10.10.3"

GPU_PCIE="0000:ac:00.0"
NIC_PCIE="0000:bd:00.0"         # PF0 PCIe address
REQUIRED_KERNEL="6.11"

# ── Colors ───────────────────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
CYN='\033[0;36m'
DIM='\033[2m'
RST='\033[0m'

pass=0; fail=0; warn=0

ok()   { echo -e "  ${GRN}[PASS]${RST} $1"; ((pass++)) || true; }
bad()  { echo -e "  ${RED}[FAIL]${RST} $1"; ((fail++)) || true; }
info() { echo -e "  ${YLW}[WARN]${RST} $1"; ((warn++)) || true; }
dbg()  { echo -e "  ${DIM}       > $1${RST}"; }
hdr()  { echo -e "\n${CYN}── $1 ──${RST}"; }

ssh_cpu1_dpu() {
    ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes \
        "$CPU1_DPU_SSH" "$@" 2>/dev/null
}

ssh_cpu2_host() {
    ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes \
        "$CPU2_HOST_SSH" "$@" 2>/dev/null
}

ssh_cpu2_dpu() {
    ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes \
        "$CPU2_HOST_SSH" "ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes $CPU2_DPU_SSH_VIA_CPU2 '$*'" 2>/dev/null
}

echo -e "${CYN}╔══════════════════════════════════════════════════════════╗${RST}"
echo -e "${CYN}║   Cross-DPU Link Diagnostic (cpu1 ↔ cpu2 via cable)    ║${RST}"
echo -e "${CYN}╚══════════════════════════════════════════════════════════╝${RST}"
echo ""
echo "  cpu2 DPU ARM ($CPU2_DPU_IP)"
echo "       ↓ p0"
echo "    [cable]"
echo "       ↓ p0"
echo "  cpu1 DPU ARM → ovsbr1 → pf0hpf → host PF0 ($CPU1_HOST_IP)"
echo "       ↓"
echo "  DOCA Flow → GPU VRAM"
echo ""

# ═══════════════════════════════════════════════════════════════════════
#  Section 1: cpu1 Host checks
# ═══════════════════════════════════════════════════════════════════════
hdr "1. cpu1 Host — kernel & drivers"

KERN=$(uname -r)
if [[ "$KERN" == *"$REQUIRED_KERNEL"* ]]; then
    ok "Kernel $KERN (contains $REQUIRED_KERNEL)"
else
    bad "Kernel $KERN (expected $REQUIRED_KERNEL)"
fi

if lsmod | grep -q nvidia_peermem; then
    ok "nvidia-peermem loaded"
else
    bad "nvidia-peermem NOT loaded (run: sudo modprobe nvidia-peermem)"
fi

if nvidia-smi &>/dev/null; then
    GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1)
    ok "GPU found: $GPU_NAME"
else
    bad "nvidia-smi failed — no GPU driver"
fi

# ── Section 2: cpu1 Host NIC ────────────────────────────────────────────
hdr "2. cpu1 Host — PF0 network interface ($CPU1_HOST_NIC)"

if ip link show "$CPU1_HOST_NIC" &>/dev/null; then
    STATE=$(cat /sys/class/net/$CPU1_HOST_NIC/operstate 2>/dev/null || echo "?")
    CARRIER=$(cat /sys/class/net/$CPU1_HOST_NIC/carrier 2>/dev/null || echo "?")
    ok "$CPU1_HOST_NIC exists (state=$STATE carrier=$CARRIER)"
else
    bad "$CPU1_HOST_NIC not found"
fi

IP_FOUND=$(ip -4 addr show "$CPU1_HOST_NIC" 2>/dev/null | grep -oP 'inet \K[0-9.]+')
if [[ "$IP_FOUND" == "$CPU1_HOST_IP" ]]; then
    ok "$CPU1_HOST_NIC has IP $CPU1_HOST_IP"
else
    bad "$CPU1_HOST_NIC IP is '$IP_FOUND' (expected $CPU1_HOST_IP)"
    dbg "Fix: sudo ip addr add $CPU1_HOST_IP/24 dev $CPU1_HOST_NIC"
fi

PCIE_ACTUAL=$(ethtool -i "$CPU1_HOST_NIC" 2>/dev/null | grep bus-info | awk '{print $2}')
if [[ -n "$PCIE_ACTUAL" ]]; then
    ok "$CPU1_HOST_NIC PCIe: $PCIE_ACTUAL"
else
    info "Could not determine PCIe address for $CPU1_HOST_NIC"
fi

# ── Section 3: cpu1 DPU ARM ─────────────────────────────────────────────
hdr "3. cpu1 DPU ARM — SSH & bridge config"

if ssh_cpu1_dpu "echo ok" | grep -q ok; then
    ok "SSH to cpu1 DPU ARM works"
else
    bad "Cannot SSH to cpu1 DPU ARM ($CPU1_DPU_SSH)"
    dbg "Check tmfifo_net0 IP and DPU ARM status"
fi

DPU1_CARRIER=$(ssh_cpu1_dpu "cat /sys/class/net/$CPU1_DPU_PORT/carrier 2>/dev/null" || echo "?")
if [[ "$DPU1_CARRIER" == "1" ]]; then
    ok "cpu1 DPU $CPU1_DPU_PORT carrier=1 (cable connected)"
else
    bad "cpu1 DPU $CPU1_DPU_PORT carrier=$DPU1_CARRIER (no cable?)"
fi

BRIDGE_PORTS=$(ssh_cpu1_dpu "sudo ovs-vsctl list-ports $CPU1_DPU_BRIDGE 2>/dev/null" || echo "")
if echo "$BRIDGE_PORTS" | grep -q "$CPU1_DPU_PORT"; then
    ok "cpu1 DPU: $CPU1_DPU_PORT is in $CPU1_DPU_BRIDGE"
else
    bad "cpu1 DPU: $CPU1_DPU_PORT NOT in $CPU1_DPU_BRIDGE"
    dbg "Fix ON cpu1 DPU ARM: sudo ovs-vsctl add-port $CPU1_DPU_BRIDGE $CPU1_DPU_PORT"
fi

if echo "$BRIDGE_PORTS" | grep -q "$CPU1_DPU_REP"; then
    ok "cpu1 DPU: $CPU1_DPU_REP is in $CPU1_DPU_BRIDGE"
else
    bad "cpu1 DPU: $CPU1_DPU_REP NOT in $CPU1_DPU_BRIDGE"
    dbg "Fix ON cpu1 DPU ARM: sudo ovs-vsctl add-port $CPU1_DPU_BRIDGE $CPU1_DPU_REP"
fi

DPU1_OVS=$(ssh_cpu1_dpu "sudo ovs-vsctl show 2>/dev/null" || echo "")
if echo "$DPU1_OVS" | grep -q "error"; then
    info "cpu1 DPU OVS has errors:"
    dbg "$(echo "$DPU1_OVS" | grep error)"
else
    ok "cpu1 DPU OVS bridge clean (no errors)"
fi

# ── Section 4: cpu2 Host ────────────────────────────────────────────────
hdr "4. cpu2 Host — connectivity & rshim"

if ssh_cpu2_host "echo ok" 2>/dev/null | grep -q ok; then
    ok "SSH to cpu2 host works"
else
    bad "Cannot SSH to cpu2 host ($CPU2_HOST_SSH)"
fi

CPU2_KERN=$(ssh_cpu2_host "uname -r" || echo "?")
if [[ "$CPU2_KERN" == *"$REQUIRED_KERNEL"* ]]; then
    ok "cpu2 kernel: $CPU2_KERN"
else
    info "cpu2 kernel: $CPU2_KERN (expected $REQUIRED_KERNEL for rshim compat)"
fi

CPU2_RSHIM=$(ssh_cpu2_host "systemctl is-active rshim 2>/dev/null" || echo "?")
if [[ "$CPU2_RSHIM" == "active" ]]; then
    ok "cpu2 rshim service active"
else
    bad "cpu2 rshim service: $CPU2_RSHIM"
    dbg "Fix ON cpu2: sudo systemctl start rshim"
fi

CPU2_TMFIFO_IP=$(ssh_cpu2_host "ip -4 addr show tmfifo_net0 2>/dev/null | grep -oP 'inet \K[0-9.]+'" || echo "")
if [[ -n "$CPU2_TMFIFO_IP" ]]; then
    ok "cpu2 tmfifo_net0 has IP: $CPU2_TMFIFO_IP"
else
    bad "cpu2 tmfifo_net0 has no IPv4"
    dbg "Fix ON cpu2: sudo ip addr add 192.168.100.1/24 dev tmfifo_net0"
fi

CPU2_BF_MODE=$(ssh_cpu2_host "sudo cat /dev/rshim0/misc 2>/dev/null | grep BF_MODE" || echo "?")
if echo "$CPU2_BF_MODE" | grep -q "DPU"; then
    ok "cpu2 DPU mode: DPU"
elif echo "$CPU2_BF_MODE" | grep -q "NIC"; then
    bad "cpu2 DPU mode: NIC (needs DPU mode)"
    dbg "Fix ON cpu2: sudo mlxconfig -d 84:00.0 set INTERNAL_CPU_OFFLOAD_ENGINE=0"
else
    info "cpu2 DPU mode: $CPU2_BF_MODE"
fi

CPU2_CARRIER=$(ssh_cpu2_host "cat /sys/class/net/$CPU2_HOST_NIC/carrier 2>/dev/null" || echo "?")
if [[ "$CPU2_CARRIER" == "1" ]]; then
    ok "cpu2 host $CPU2_HOST_NIC carrier=1 (cable connected)"
else
    bad "cpu2 host $CPU2_HOST_NIC carrier=$CPU2_CARRIER"
fi

# ── Section 5: cpu2 DPU ARM ─────────────────────────────────────────────
hdr "5. cpu2 DPU ARM — SSH & bridge config"

if ssh_cpu2_dpu "echo ok" 2>/dev/null | grep -q ok; then
    ok "SSH to cpu2 DPU ARM works (via cpu2 host)"
else
    bad "Cannot SSH to cpu2 DPU ARM (via cpu2 host → $CPU2_DPU_SSH_VIA_CPU2)"
    dbg "Check cpu2 tmfifo_net0 and DPU ARM boot status"
fi

DPU2_CARRIER=$(ssh_cpu2_dpu "cat /sys/class/net/$CPU2_DPU_PORT/carrier 2>/dev/null" || echo "?")
if [[ "$DPU2_CARRIER" == "1" ]]; then
    ok "cpu2 DPU $CPU2_DPU_PORT carrier=1 (cable connected)"
else
    bad "cpu2 DPU $CPU2_DPU_PORT carrier=$DPU2_CARRIER"
fi

DPU2_BRIDGE_PORTS=$(ssh_cpu2_dpu "sudo ovs-vsctl list-ports $CPU2_DPU_BRIDGE 2>/dev/null" || echo "")
if echo "$DPU2_BRIDGE_PORTS" | grep -q "$CPU2_DPU_PORT"; then
    ok "cpu2 DPU: $CPU2_DPU_PORT is in $CPU2_DPU_BRIDGE"
else
    bad "cpu2 DPU: $CPU2_DPU_PORT NOT in $CPU2_DPU_BRIDGE"
    dbg "Fix ON cpu2 DPU ARM: sudo ovs-vsctl add-port $CPU2_DPU_BRIDGE $CPU2_DPU_PORT"
fi

if echo "$DPU2_BRIDGE_PORTS" | grep -q "$CPU2_DPU_REP"; then
    ok "cpu2 DPU: $CPU2_DPU_REP is in $CPU2_DPU_BRIDGE"
else
    bad "cpu2 DPU: $CPU2_DPU_REP NOT in $CPU2_DPU_BRIDGE"
fi

DPU2_IP=$(ssh_cpu2_dpu "ip -4 addr show $CPU2_DPU_BRIDGE 2>/dev/null | grep -oP 'inet \K[0-9.]+'" || echo "")
if [[ "$DPU2_IP" == "$CPU2_DPU_IP" ]]; then
    ok "cpu2 DPU $CPU2_DPU_BRIDGE has IP $CPU2_DPU_IP"
else
    bad "cpu2 DPU $CPU2_DPU_BRIDGE IP is '$DPU2_IP' (expected $CPU2_DPU_IP)"
    dbg "Fix ON cpu2 DPU ARM: sudo ip addr add $CPU2_DPU_IP/24 dev $CPU2_DPU_BRIDGE"
fi

DPU2_PYTHON=$(ssh_cpu2_dpu "which python3 2>/dev/null" || echo "")
if [[ -n "$DPU2_PYTHON" ]]; then
    ok "cpu2 DPU ARM has python3: $DPU2_PYTHON"
else
    bad "cpu2 DPU ARM: python3 not found"
    dbg "Fix ON cpu2 DPU ARM: sudo apt install python3"
fi

DPU2_SENDTICKS=$(ssh_cpu2_dpu "test -f ~/send_ticks.py && echo yes" || echo "")
if [[ "$DPU2_SENDTICKS" == "yes" ]]; then
    ok "cpu2 DPU ARM: ~/send_ticks.py exists"
else
    info "cpu2 DPU ARM: ~/send_ticks.py not found"
    dbg "Copy: scp send_ticks.py to cpu2 DPU ARM"
fi

# ── Section 6: End-to-end ping test ─────────────────────────────────────
hdr "6. End-to-end ping test (cpu2 DPU ARM → cpu1 host PF0)"

PING_RESULT=$(ssh_cpu2_dpu "sudo ping -c 3 -W 2 $CPU1_HOST_IP 2>&1" || echo "")
PING_OK=$(echo "$PING_RESULT" | grep -c "bytes from" || true)
if [[ "$PING_OK" -ge 1 ]]; then
    RTT=$(echo "$PING_RESULT" | grep "rtt" | awk -F'/' '{print $5}')
    ok "Ping cpu2 DPU ARM → cpu1 host ($CPU1_HOST_IP): ${PING_OK}/3 replies, avg ${RTT}ms"
else
    bad "Ping cpu2 DPU ARM → cpu1 host ($CPU1_HOST_IP): 0/3 replies"
    dbg "Check bridges, IPs, and cable"
fi

PING_REV=$(ping -c 3 -W 2 "$CPU2_DPU_IP" 2>&1 || true)
PING_REV_OK=$(echo "$PING_REV" | grep -c "bytes from" || true)
if [[ "$PING_REV_OK" -ge 1 ]]; then
    RTT_REV=$(echo "$PING_REV" | grep "rtt" | awk -F'/' '{print $5}')
    ok "Ping cpu1 host → cpu2 DPU ARM ($CPU2_DPU_IP): ${PING_REV_OK}/3 replies, avg ${RTT_REV}ms"
else
    bad "Ping cpu1 host → cpu2 DPU ARM ($CPU2_DPU_IP): 0/3 replies"
fi

# ── Section 7: gpu_receiver readiness ───────────────────────────────────
hdr "7. gpu_receiver readiness (cpu1 host)"

BINARY="./build/src/receivers/gpu/gpu_receiver"
if [[ -x "$BINARY" ]]; then
    ok "gpu_receiver binary exists and is executable"
else
    bad "gpu_receiver binary not found at $BINARY"
    dbg "Run: cd build && cmake .. && make gpu_receiver"
fi

if [[ -d "/opt/mellanox/doca" ]]; then
    ok "DOCA SDK installed at /opt/mellanox/doca"
else
    bad "DOCA SDK not found at /opt/mellanox/doca"
fi

CUDA_PATH=$(which nvcc 2>/dev/null || echo "")
if [[ -n "$CUDA_PATH" ]]; then
    CUDA_VER=$(nvcc --version 2>/dev/null | grep "release" | awk '{print $5}' | tr -d ',')
    ok "CUDA toolkit: $CUDA_VER ($CUDA_PATH)"
else
    info "nvcc not in PATH (export PATH=/usr/local/cuda-12.8/bin:\$PATH)"
fi

# ── Section 8: NIC PHY RX rate (background noise check) ────────────────
hdr "8. NIC PHY RX rate on cpu1 $CPU1_HOST_NIC (5-second sample)"

RX1=$(ethtool -S "$CPU1_HOST_NIC" 2>/dev/null | grep -m1 "rx_packets_phy" | awk '{print $2}' || echo "0")
sleep 5
RX2=$(ethtool -S "$CPU1_HOST_NIC" 2>/dev/null | grep -m1 "rx_packets_phy" | awk '{print $2}' || echo "0")

if [[ -n "$RX1" && -n "$RX2" ]]; then
    DELTA=$((RX2 - RX1))
    RATE=$((DELTA / 5))
    if [[ "$RATE" -gt 100000 ]]; then
        info "Background RX rate: ~${RATE} pkt/sec (${DELTA} in 5s) — high noise"
        dbg "Phantom packets likely from multicast flooding"
    elif [[ "$RATE" -gt 0 ]]; then
        ok "Background RX rate: ~${RATE} pkt/sec (${DELTA} in 5s)"
    else
        ok "No background RX traffic"
    fi
else
    info "Could not read PHY counters for $CPU1_HOST_NIC"
fi

# ═══════════════════════════════════════════════════════════════════════
#  Summary
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo -e "${CYN}══════════════════════════════════════════════════════════${RST}"
echo -e "  ${GRN}PASS: $pass${RST}  ${RED}FAIL: $fail${RST}  ${YLW}WARN: $warn${RST}"
echo -e "${CYN}══════════════════════════════════════════════════════════${RST}"

if [[ "$fail" -eq 0 ]]; then
    echo ""
    echo -e "  ${GRN}All checks passed! Ready to test:${RST}"
    echo ""
    echo "  ON cpu1 host:"
    echo "    sudo ./build/src/receivers/gpu/gpu_receiver --nic-addr ${NIC_PCIE#0000:} --gpu-addr ${GPU_PCIE#0000:}"
    echo ""
    echo "  ON cpu2 DPU ARM:"
    echo "    python3 ~/send_ticks.py --mode generate --rate 1000 --count 1000 --iface $CPU2_DPU_IP"
else
    echo ""
    echo -e "  ${RED}Fix the FAIL items above before testing.${RST}"
fi

echo ""
