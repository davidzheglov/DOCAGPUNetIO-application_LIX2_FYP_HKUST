#!/usr/bin/env bash
#
# diagnose_datapath.sh — Check every step of the DPU ARM → Host GPU data path.
#
# Run ON HOST (lxcpu1):
#   bash scripts/diagnose_datapath.sh
#
# The script SSHes into the DPU ARM automatically for DPU-side checks.

set -euo pipefail

DPU_SSH="ubuntu@192.168.100.2"
DPU_REPO="/home/ubuntu/DOCAGPUNetIO-application_LIX2_FYP_HKUST"

HOST_NIC="ens21f1np1"
HOST_NIC_IP="10.10.10.2"
DPU_DATA_IP="10.10.10.1"
GPU_PCIE="0000:ac:00.0"
NIC_PCIE="0000:bd:00.1"
MCAST_ADDR="239.0.0.1"
MCAST_PORT=5005
REQUIRED_KERNEL="6.11"

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
CYN='\033[0;36m'
RST='\033[0m'

pass=0
fail=0
warn=0

ok()   { echo -e "  ${GRN}[PASS]${RST} $1"; ((pass++)); }
bad()  { echo -e "  ${RED}[FAIL]${RST} $1"; ((fail++)); }
info() { echo -e "  ${YLW}[WARN]${RST} $1"; ((warn++)); }
hdr()  { echo -e "\n${CYN}── $1 ──${RST}"; }

ssh_dpu() {
    ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes \
        "$DPU_SSH" "$@" 2>/dev/null
}

# ────────────────────────────────────────────────────────────────────
hdr "1. HOST — Kernel & Drivers"
# ────────────────────────────────────────────────────────────────────

KVER=$(uname -r)
if [[ "$KVER" == ${REQUIRED_KERNEL}* ]]; then
    ok "Kernel $KVER (matches $REQUIRED_KERNEL.*)"
else
    bad "Kernel $KVER — expected ${REQUIRED_KERNEL}.* (DOCA ctx_start will fail on 6.17+)"
fi

if lsmod | grep -q nvidia_peermem; then
    ok "nvidia-peermem module loaded"
else
    bad "nvidia-peermem NOT loaded — run: sudo modprobe nvidia-peermem"
fi

if lsmod | grep -q nvidia; then
    ok "nvidia driver loaded"
else
    bad "nvidia driver NOT loaded"
fi

# ────────────────────────────────────────────────────────────────────
hdr "2. HOST — GPU"
# ────────────────────────────────────────────────────────────────────

if command -v nvidia-smi &>/dev/null; then
    GPU_COUNT=$(nvidia-smi -L 2>/dev/null | wc -l)
    ok "nvidia-smi OK — $GPU_COUNT GPU(s) detected"
    GPU1_NAME=$(nvidia-smi -i 1 --query-gpu=name --format=csv,noheader 2>/dev/null || echo "N/A")
    echo "       GPU 1: $GPU1_NAME"
else
    bad "nvidia-smi not found"
fi

if lspci -s "$GPU_PCIE" 2>/dev/null | grep -qi nvidia; then
    ok "GPU PCIe $GPU_PCIE present"
else
    bad "GPU PCIe $GPU_PCIE not found — check --gpu-pcie argument"
fi

# ────────────────────────────────────────────────────────────────────
hdr "3. HOST — NIC & Network"
# ────────────────────────────────────────────────────────────────────

if lspci -s "$NIC_PCIE" 2>/dev/null | grep -qi mellanox; then
    ok "NIC PCIe $NIC_PCIE present (Mellanox/NVIDIA)"
else
    bad "NIC PCIe $NIC_PCIE not found — check --nic-pcie argument"
fi

if ip link show "$HOST_NIC" 2>/dev/null | grep -q 'state UP'; then
    ok "$HOST_NIC is UP"
else
    bad "$HOST_NIC is DOWN or missing"
fi

HOST_ACTUAL_IP=$(ip -4 addr show "$HOST_NIC" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1)
if [[ "$HOST_ACTUAL_IP" == "$HOST_NIC_IP" ]]; then
    ok "$HOST_NIC has IP $HOST_NIC_IP"
else
    bad "$HOST_NIC has IP '$HOST_ACTUAL_IP' — expected $HOST_NIC_IP"
fi

ALL_IPS=$(ip -4 addr show "$HOST_NIC" 2>/dev/null | grep -oP 'inet \K[0-9./]+')
IP_COUNT=$(echo "$ALL_IPS" | wc -l)
if [[ $IP_COUNT -gt 1 ]]; then
    info "$HOST_NIC has $IP_COUNT IPs (may cause routing confusion): $ALL_IPS"
fi

PF0_IFACE="ens21f0np0"
PF0_IP=$(ip -4 addr show "$PF0_IFACE" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1 || true)
if [[ -n "$PF0_IP" ]]; then
    info "PF0 ($PF0_IFACE) has IP $PF0_IP — this interface is NOT in the DOCA data path"
    if [[ "$PF0_IP" == "$DPU_DATA_IP" ]]; then
        bad "PF0 has same IP as DPU ARM ($DPU_DATA_IP) — routing conflict!"
    fi
fi

if ping -c 1 -W 2 -I "$HOST_NIC" "$DPU_DATA_IP" &>/dev/null; then
    ok "Ping DPU $DPU_DATA_IP via $HOST_NIC — reachable"
else
    info "Ping DPU $DPU_DATA_IP via $HOST_NIC — no reply (may be normal if eswitch blocks ICMP)"
fi

# ────────────────────────────────────────────────────────────────────
hdr "4. HOST — DOCA & Build"
# ────────────────────────────────────────────────────────────────────

if [[ -d /opt/mellanox/doca ]]; then
    DOCA_VER=$(cat /opt/mellanox/doca/version 2>/dev/null || echo "unknown")
    ok "DOCA SDK installed — version: $DOCA_VER"
else
    bad "DOCA SDK not found at /opt/mellanox/doca"
fi

CUDA_BIN=$(which nvcc 2>/dev/null || echo "")
if [[ -n "$CUDA_BIN" ]]; then
    CUDA_VER=$($CUDA_BIN --version 2>/dev/null | grep 'release' | grep -oP 'V\K[0-9.]+')
    ok "CUDA toolkit: $CUDA_VER ($CUDA_BIN)"
else
    info "nvcc not in PATH — ensure CUDA 12.8 is exported"
fi

if [[ -x bin/gpu_receiver ]]; then
    ok "bin/gpu_receiver exists and is executable"
else
    bad "bin/gpu_receiver not found — rebuild needed"
fi

# ────────────────────────────────────────────────────────────────────
hdr "5. HOST — NIC RX counters (before test)"
# ────────────────────────────────────────────────────────────────────

RX_PKTS_BEFORE=$(ethtool -S "$HOST_NIC" 2>/dev/null | grep 'rx_packets_phy:' | awk '{print $2}' || echo "N/A")
RX_BYTES_BEFORE=$(ethtool -S "$HOST_NIC" 2>/dev/null | grep 'rx_bytes_phy:' | awk '{print $2}' || echo "N/A")
RX_MCAST_BEFORE=$(ethtool -S "$HOST_NIC" 2>/dev/null | grep 'rx_multicast_phy:' | awk '{print $2}' || echo "N/A")
echo "  rx_packets_phy:   $RX_PKTS_BEFORE"
echo "  rx_bytes_phy:     $RX_BYTES_BEFORE"
echo "  rx_multicast_phy: $RX_MCAST_BEFORE"

# ────────────────────────────────────────────────────────────────────
hdr "6. DPU ARM — SSH connectivity"
# ────────────────────────────────────────────────────────────────────

if ssh_dpu "echo ok" | grep -q ok; then
    ok "SSH to $DPU_SSH works"
else
    bad "Cannot SSH to $DPU_SSH — check tmfifo_net0 and 192.168.100.x setup"
    echo -e "\n${RED}Cannot reach DPU ARM — skipping DPU checks.${RST}"
    hdr "SUMMARY"
    echo -e "  ${GRN}PASS: $pass${RST}  ${RED}FAIL: $fail${RST}  ${YLW}WARN: $warn${RST}"
    exit 1
fi

# ────────────────────────────────────────────────────────────────────
hdr "7. DPU ARM — Bridge & interfaces"
# ────────────────────────────────────────────────────────────────────

BRIDGE_STATE=$(ssh_dpu "ip link show br-pf1 2>/dev/null | head -1" || true)
if echo "$BRIDGE_STATE" | grep -q 'state UP'; then
    ok "br-pf1 bridge is UP"
else
    bad "br-pf1 bridge is DOWN or missing — run bridge setup"
fi

BRIDGE_MEMBERS=$(ssh_dpu "bridge link show 2>/dev/null | grep br-pf1" || true)
if echo "$BRIDGE_MEMBERS" | grep -q 'p1'; then
    ok "p1 is a member of br-pf1"
else
    bad "p1 is NOT in br-pf1 — run: sudo ip link set p1 master br-pf1"
fi
if echo "$BRIDGE_MEMBERS" | grep -q 'pf1hpf'; then
    ok "pf1hpf is a member of br-pf1"
else
    bad "pf1hpf is NOT in br-pf1 — run: sudo ip link set pf1hpf master br-pf1"
fi

P1_STATE=$(ssh_dpu "ip link show p1 2>/dev/null | head -1" || true)
if echo "$P1_STATE" | grep -q 'state UP'; then
    ok "p1 is UP"
else
    bad "p1 is DOWN — run: sudo ip link set p1 up"
fi

PF1HPF_STATE=$(ssh_dpu "ip link show pf1hpf 2>/dev/null | head -1" || true)
if echo "$PF1HPF_STATE" | grep -q 'state UP'; then
    ok "pf1hpf is UP"
else
    bad "pf1hpf is DOWN — run: sudo ip link set pf1hpf up"
fi

# ────────────────────────────────────────────────────────────────────
hdr "8. DPU ARM — IGMP snooping (critical for multicast)"
# ────────────────────────────────────────────────────────────────────

IGMP_SNOOP=$(ssh_dpu "cat /sys/devices/virtual/net/br-pf1/bridge/multicast_snooping 2>/dev/null" || echo "unknown")
if [[ "$IGMP_SNOOP" == "0" ]]; then
    ok "IGMP snooping DISABLED on br-pf1 (correct for multicast)"
else
    bad "IGMP snooping is ENABLED ($IGMP_SNOOP) — multicast will be silently dropped!"
    echo "       Fix: sudo ip link set br-pf1 type bridge mcast_snooping 0"
fi

# ────────────────────────────────────────────────────────────────────
hdr "9. DPU ARM — IP addresses & routing"
# ────────────────────────────────────────────────────────────────────

DPU_BRIDGE_IP=$(ssh_dpu "ip -4 addr show br-pf1 2>/dev/null | grep -oP 'inet \K[0-9.]+'" || true)
DPU_P0_IP=$(ssh_dpu "ip -4 addr show p0 2>/dev/null | grep -oP 'inet \K[0-9.]+'" || true)

if [[ "$DPU_BRIDGE_IP" == "$DPU_DATA_IP" ]]; then
    ok "br-pf1 has IP $DPU_DATA_IP"
elif [[ "$DPU_P0_IP" == "$DPU_DATA_IP" ]]; then
    ok "p0 has IP $DPU_DATA_IP (alternative to br-pf1)"
else
    bad "Neither br-pf1 nor p0 has IP $DPU_DATA_IP"
    echo "       br-pf1=$DPU_BRIDGE_IP  p0=$DPU_P0_IP"
fi

if [[ -n "$DPU_P0_IP" && -n "$DPU_BRIDGE_IP" && "$DPU_P0_IP" == "$DPU_BRIDGE_IP" ]]; then
    info "Both p0 and br-pf1 have $DPU_DATA_IP — may cause confusion"
fi

DPU_PING=$(ssh_dpu "ping -c 1 -W 2 $HOST_NIC_IP 2>/dev/null && echo ok || echo fail")
if echo "$DPU_PING" | grep -q ok; then
    ok "DPU ARM can ping host $HOST_NIC_IP"
else
    info "DPU ARM cannot ping host $HOST_NIC_IP (may be normal)"
fi

# ────────────────────────────────────────────────────────────────────
hdr "10. DPU ARM — OVS bridges (should NOT hold p0/p1)"
# ────────────────────────────────────────────────────────────────────

OVS_PORTS=$(ssh_dpu "sudo ovs-vsctl list-ports ovsbr1 2>/dev/null; sudo ovs-vsctl list-ports ovsbr2 2>/dev/null" || true)
if echo "$OVS_PORTS" | grep -qE '^p[01]$'; then
    bad "p0 or p1 still in OVS bridge — remove them:"
    echo "       sudo ovs-vsctl del-port ovsbr1 p0; sudo ovs-vsctl del-port ovsbr2 p1"
else
    ok "p0/p1 not in OVS bridges"
fi

# ────────────────────────────────────────────────────────────────────
hdr "11. DPU ARM — Stale sender processes"
# ────────────────────────────────────────────────────────────────────

STALE=$(ssh_dpu "ps aux | grep -E 'data_source|send_ticks' | grep -v grep" || true)
if [[ -z "$STALE" ]]; then
    ok "No stale data_source or send_ticks processes"
else
    info "Found running sender processes:"
    echo "$STALE" | while read -r line; do echo "       $line"; done
fi

# ────────────────────────────────────────────────────────────────────
hdr "12. DPU ARM — Eswitch mode"
# ────────────────────────────────────────────────────────────────────

ESWITCH=$(ssh_dpu "sudo devlink dev eswitch show pci/0000:03:00.0 2>/dev/null" || true)
if echo "$ESWITCH" | grep -q switchdev; then
    ok "Eswitch mode: switchdev"
elif [[ -n "$ESWITCH" ]]; then
    bad "Eswitch mode: $ESWITCH (expected switchdev)"
else
    info "Could not query eswitch mode (devlink not available or wrong PCI address)"
fi

# ────────────────────────────────────────────────────────────────────
hdr "13. DATA PATH TEST — Send 5 UDP packets from DPU ARM"
# ────────────────────────────────────────────────────────────────────

echo "  Sending 5 test packets from DPU ARM to $MCAST_ADDR:$MCAST_PORT ..."

# Capture on DPU ARM br-pf1 in background
ssh_dpu "sudo timeout 5 tcpdump -i br-pf1 -c 5 -nn udp port $MCAST_PORT 2>&1 || true" &
TCPDUMP_BR_PID=$!

# Capture on DPU ARM pf1hpf in background
ssh_dpu "sudo timeout 5 tcpdump -i pf1hpf -c 5 -nn udp port $MCAST_PORT 2>&1 || true" &
TCPDUMP_PF1_PID=$!

sleep 1

# Send test packets from DPU ARM
SEND_IFACE="$DPU_DATA_IP"
ssh_dpu "python3 -c \"
import socket, struct, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('$SEND_IFACE'))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
for i in range(5):
    msg = struct.pack('<QIHBBdddd', int(time.time()*1e9), i, 1, 0, 0, 100.0, 100.1, 100.05, 1000.0)
    sock.sendto(msg, ('$MCAST_ADDR', $MCAST_PORT))
    time.sleep(0.1)
print('Sent 5 test packets')
\"" 2>&1 || true

sleep 3

echo ""
echo "  tcpdump on br-pf1:"
BR_RESULT=""
if wait $TCPDUMP_BR_PID 2>/dev/null; then true; fi
BR_RESULT=$(ssh_dpu "sudo timeout 3 tcpdump -i br-pf1 -c 3 -nn udp port $MCAST_PORT 2>&1 || true" 2>/dev/null || true)

echo ""
echo "  tcpdump on pf1hpf:"
PF1_RESULT=""
if wait $TCPDUMP_PF1_PID 2>/dev/null; then true; fi
PF1_RESULT=$(ssh_dpu "sudo timeout 3 tcpdump -i pf1hpf -c 3 -nn udp port $MCAST_PORT 2>&1 || true" 2>/dev/null || true)

# Re-send and capture sequentially for cleaner output
echo ""
echo "  Sending 10 more test packets and capturing..."
ssh_dpu "
sudo timeout 5 tcpdump -i br-pf1 -c 5 -nn udp port $MCAST_PORT &
TCPD_PID=\$!
sleep 0.5
python3 -c \"
import socket, struct, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('$SEND_IFACE'))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
for i in range(10):
    msg = struct.pack('<QIHBBdddd', int(time.time()*1e9), i, 1, 0, 0, 100.0, 100.1, 100.05, 1000.0)
    sock.sendto(msg, ('$MCAST_ADDR', $MCAST_PORT))
    time.sleep(0.05)
print('Sent 10 test packets')
\"
wait \$TCPD_PID 2>/dev/null
" 2>&1 | while read -r line; do echo "       $line"; done

echo ""
ssh_dpu "
sudo timeout 5 tcpdump -i pf1hpf -c 5 -nn udp port $MCAST_PORT &
TCPD_PID=\$!
sleep 0.5
python3 -c \"
import socket, struct, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('$SEND_IFACE'))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
for i in range(10):
    msg = struct.pack('<QIHBBdddd', int(time.time()*1e9), i, 1, 0, 0, 100.0, 100.1, 100.05, 1000.0)
    sock.sendto(msg, ('$MCAST_ADDR', $MCAST_PORT))
    time.sleep(0.05)
print('Sent 10 test packets')
\"
wait \$TCPD_PID 2>/dev/null
" 2>&1 | while read -r line; do echo "       $line"; done

# ────────────────────────────────────────────────────────────────────
hdr "14. HOST — NIC RX counters (after test)"
# ────────────────────────────────────────────────────────────────────

RX_PKTS_AFTER=$(ethtool -S "$HOST_NIC" 2>/dev/null | grep 'rx_packets_phy:' | awk '{print $2}' || echo "N/A")
RX_BYTES_AFTER=$(ethtool -S "$HOST_NIC" 2>/dev/null | grep 'rx_bytes_phy:' | awk '{print $2}' || echo "N/A")
RX_MCAST_AFTER=$(ethtool -S "$HOST_NIC" 2>/dev/null | grep 'rx_multicast_phy:' | awk '{print $2}' || echo "N/A")
echo "  rx_packets_phy:   $RX_PKTS_AFTER (was $RX_PKTS_BEFORE)"
echo "  rx_bytes_phy:     $RX_BYTES_AFTER (was $RX_BYTES_BEFORE)"
echo "  rx_multicast_phy: $RX_MCAST_AFTER (was $RX_MCAST_BEFORE)"

if [[ "$RX_PKTS_BEFORE" != "N/A" && "$RX_PKTS_AFTER" != "N/A" ]]; then
    DELTA=$((RX_PKTS_AFTER - RX_PKTS_BEFORE))
    if [[ $DELTA -gt 0 ]]; then
        ok "NIC received $DELTA new packets during test"
    else
        info "NIC received 0 new packets — packets may not be reaching the physical port"
    fi
fi

if [[ "$RX_MCAST_BEFORE" != "N/A" && "$RX_MCAST_AFTER" != "N/A" ]]; then
    MCAST_DELTA=$((RX_MCAST_AFTER - RX_MCAST_BEFORE))
    echo "  Multicast delta: $MCAST_DELTA"
fi

# ────────────────────────────────────────────────────────────────────
hdr "15. HOST — tcpdump on $HOST_NIC (5 second capture)"
# ────────────────────────────────────────────────────────────────────

echo "  Capturing on host while DPU sends 10 packets..."
sudo timeout 5 tcpdump -i "$HOST_NIC" -c 5 -nn udp port "$MCAST_PORT" 2>&1 &
HOST_TCPD_PID=$!
sleep 0.5

ssh_dpu "python3 -c \"
import socket, struct, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('$SEND_IFACE'))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
for i in range(10):
    msg = struct.pack('<QIHBBdddd', int(time.time()*1e9), i, 1, 0, 0, 100.0, 100.1, 100.05, 1000.0)
    sock.sendto(msg, ('$MCAST_ADDR', $MCAST_PORT))
    time.sleep(0.05)
\"" 2>/dev/null || true

if wait $HOST_TCPD_PID 2>/dev/null; then
    ok "Host tcpdump captured packets"
else
    info "Host tcpdump captured nothing — may be normal (DOCA steers before kernel if gpu_receiver is running)"
fi

# ────────────────────────────────────────────────────────────────────
hdr "16. HOST — Phantom packet check (NIC RX rate without sender)"
# ────────────────────────────────────────────────────────────────────

echo "  Sampling NIC RX counter for 3 seconds (no sender running)..."
RX_T0=$(ethtool -S "$HOST_NIC" 2>/dev/null | grep 'rx_packets_phy:' | awk '{print $2}' || echo "0")
sleep 3
RX_T1=$(ethtool -S "$HOST_NIC" 2>/dev/null | grep 'rx_packets_phy:' | awk '{print $2}' || echo "0")
PHANTOM_RATE=$(( (RX_T1 - RX_T0) / 3 ))
echo "  Packets in 3s: $((RX_T1 - RX_T0)) (~${PHANTOM_RATE}/sec)"

if [[ $PHANTOM_RATE -gt 100 ]]; then
    info "High background RX rate: ~${PHANTOM_RATE} pkt/s — this explains phantom packets in gpu_receiver"
    echo "       These are likely non-port-5005 UDP packets from the network"
elif [[ $PHANTOM_RATE -gt 0 ]]; then
    info "Low background RX: ~${PHANTOM_RATE} pkt/s"
else
    ok "No background RX traffic on $HOST_NIC"
fi

# ────────────────────────────────────────────────────────────────────
hdr "SUMMARY"
# ────────────────────────────────────────────────────────────────────

echo ""
echo -e "  ${GRN}PASS: $pass${RST}  ${RED}FAIL: $fail${RST}  ${YLW}WARN: $warn${RST}"
echo ""

if [[ $fail -gt 0 ]]; then
    echo -e "  ${RED}Fix the FAIL items above before running gpu_receiver.${RST}"
    exit 1
else
    echo -e "  ${GRN}Data path looks healthy.${RST}"
    exit 0
fi
