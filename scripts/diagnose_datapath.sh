#!/usr/bin/env bash
#
# diagnose_datapath.sh — Check every step of the DPU ARM → Host GPU data path.
#
# Run ON HOST (lxcpu1):
#   bash scripts/diagnose_datapath.sh
#
# The script SSHes into the DPU ARM automatically for DPU-side checks.

set +e  # do NOT exit on error — this script checks for failures

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
DIM='\033[2m'
RST='\033[0m'

pass=0
fail=0
warn=0

ok()   { echo -e "  ${GRN}[PASS]${RST} $1"; ((pass++)) || true; }
bad()  { echo -e "  ${RED}[FAIL]${RST} $1"; ((fail++)) || true; }
info() { echo -e "  ${YLW}[WARN]${RST} $1"; ((warn++)) || true; }
dbg()  { echo -e "  ${DIM}       > $1${RST}"; }
hdr()  { echo -e "\n${CYN}── $1 ──${RST}"; }

ssh_dpu() {
    ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes \
        "$DPU_SSH" "$@" 2>/dev/null
}

run_check() {
    local desc="$1"
    shift
    local output
    output=$("$@" 2>&1) || true
    dbg "cmd: $*"
    if [[ -n "$output" ]]; then
        dbg "out: $output"
    fi
    echo "$output"
}

# ────────────────────────────────────────────────────────────────────
hdr "1. HOST — Kernel & Drivers"
# ────────────────────────────────────────────────────────────────────

KVER=$(uname -r 2>&1) || true
dbg "uname -r => $KVER"
if [[ "$KVER" == ${REQUIRED_KERNEL}* ]]; then
    ok "Kernel $KVER (matches $REQUIRED_KERNEL.*)"
else
    bad "Kernel $KVER — expected ${REQUIRED_KERNEL}.* (DOCA ctx_start will fail on 6.17+)"
fi

PEERMEM=$(lsmod 2>/dev/null | grep nvidia_peermem || true)
dbg "lsmod | grep nvidia_peermem => ${PEERMEM:-<empty>}"
if [[ -n "$PEERMEM" ]]; then
    ok "nvidia-peermem module loaded"
else
    bad "nvidia-peermem NOT loaded — run: sudo modprobe nvidia-peermem"
fi

NVIDIA_MOD=$(lsmod 2>/dev/null | grep -w nvidia || true)
dbg "lsmod | grep nvidia => ${NVIDIA_MOD:+loaded}"
if [[ -n "$NVIDIA_MOD" ]]; then
    ok "nvidia driver loaded"
else
    bad "nvidia driver NOT loaded"
fi

# ────────────────────────────────────────────────────────────────────
hdr "2. HOST — GPU"
# ────────────────────────────────────────────────────────────────────

if command -v nvidia-smi &>/dev/null; then
    GPU_LIST=$(nvidia-smi -L 2>&1) || true
    GPU_COUNT=$(echo "$GPU_LIST" | wc -l)
    dbg "nvidia-smi -L =>"
    echo "$GPU_LIST" | while read -r line; do dbg "  $line"; done
    ok "nvidia-smi OK — $GPU_COUNT GPU(s) detected"
else
    bad "nvidia-smi not found"
fi

LSPCI_GPU=$(lspci -s "$GPU_PCIE" 2>&1) || true
dbg "lspci -s $GPU_PCIE => $LSPCI_GPU"
if echo "$LSPCI_GPU" | grep -qi nvidia; then
    ok "GPU PCIe $GPU_PCIE present"
else
    bad "GPU PCIe $GPU_PCIE not found — check --gpu-pcie argument"
fi

# ────────────────────────────────────────────────────────────────────
hdr "3. HOST — NIC & Network"
# ────────────────────────────────────────────────────────────────────

LSPCI_NIC=$(lspci -s "$NIC_PCIE" 2>&1) || true
dbg "lspci -s $NIC_PCIE => $LSPCI_NIC"
if echo "$LSPCI_NIC" | grep -qi -e mellanox -e nvidia; then
    ok "NIC PCIe $NIC_PCIE present (Mellanox/NVIDIA)"
else
    bad "NIC PCIe $NIC_PCIE not found — check --nic-pcie argument"
fi

NIC_STATE=$(ip link show "$HOST_NIC" 2>&1) || true
dbg "ip link show $HOST_NIC => $(echo "$NIC_STATE" | head -1)"
if echo "$NIC_STATE" | grep -q 'state UP'; then
    ok "$HOST_NIC is UP"
else
    bad "$HOST_NIC is DOWN or missing"
fi

HOST_ACTUAL_IP=$(ip -4 addr show "$HOST_NIC" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1) || true
dbg "$HOST_NIC IPs: $(ip -4 addr show "$HOST_NIC" 2>/dev/null | grep -oP 'inet \K[0-9./]+')" || true
if [[ "$HOST_ACTUAL_IP" == "$HOST_NIC_IP" ]]; then
    ok "$HOST_NIC has IP $HOST_NIC_IP"
else
    bad "$HOST_NIC has IP '$HOST_ACTUAL_IP' — expected $HOST_NIC_IP"
fi

ALL_IPS=$(ip -4 addr show "$HOST_NIC" 2>/dev/null | grep -oP 'inet \K[0-9./]+') || true
IP_COUNT=$(echo "$ALL_IPS" | grep -c . ) || true
if [[ $IP_COUNT -gt 1 ]]; then
    info "$HOST_NIC has $IP_COUNT IPs (may cause routing confusion):"
    echo "$ALL_IPS" | while read -r ip; do dbg "$ip"; done
fi

PF0_IFACE="ens21f0np0"
PF0_IP=$(ip -4 addr show "$PF0_IFACE" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1) || true
dbg "PF0 ($PF0_IFACE) IP: ${PF0_IP:-<none>}"
if [[ -n "$PF0_IP" ]]; then
    info "PF0 ($PF0_IFACE) has IP $PF0_IP — this interface is NOT in the DOCA data path"
    if [[ "$PF0_IP" == "$DPU_DATA_IP" ]]; then
        bad "PF0 has same IP as DPU ARM ($DPU_DATA_IP) — routing conflict!"
    fi
fi

ROUTE_OUT=$(ip route get "$DPU_DATA_IP" 2>&1) || true
dbg "ip route get $DPU_DATA_IP => $ROUTE_OUT"
ROUTE_DEV=$(echo "$ROUTE_OUT" | grep -oP 'dev \K\S+' | head -1) || true
if [[ "$ROUTE_DEV" == "$HOST_NIC" ]]; then
    ok "Route to $DPU_DATA_IP goes via $HOST_NIC"
else
    bad "Route to $DPU_DATA_IP goes via '$ROUTE_DEV' — expected $HOST_NIC"
    dbg "If PF0 also has $DPU_DATA_IP subnet, kernel picks wrong interface"
fi

dbg "Pinging $DPU_DATA_IP via $HOST_NIC ..."
PING_OUT=$(ping -c 1 -W 2 -I "$HOST_NIC" "$DPU_DATA_IP" 2>&1) || true
dbg "ping => $(echo "$PING_OUT" | tail -2 | head -1)"
if echo "$PING_OUT" | grep -q '1 received'; then
    ok "Ping DPU $DPU_DATA_IP via $HOST_NIC — reachable"
else
    info "Ping DPU $DPU_DATA_IP via $HOST_NIC — no reply (may be normal if eswitch blocks ICMP)"
fi

# ────────────────────────────────────────────────────────────────────
hdr "4. HOST — DOCA & Build"
# ────────────────────────────────────────────────────────────────────

if [[ -d /opt/mellanox/doca ]]; then
    DOCA_VER=$(cat /opt/mellanox/doca/version 2>/dev/null || echo "unknown")
    dbg "DOCA version file: $DOCA_VER"
    ok "DOCA SDK installed — version: $DOCA_VER"
else
    bad "DOCA SDK not found at /opt/mellanox/doca"
fi

CUDA_BIN=$(which nvcc 2>/dev/null) || true
dbg "which nvcc => ${CUDA_BIN:-<not found>}"
if [[ -n "$CUDA_BIN" ]]; then
    CUDA_VER=$($CUDA_BIN --version 2>/dev/null | grep 'release' | grep -oP 'V\K[0-9.]+') || true
    ok "CUDA toolkit: $CUDA_VER ($CUDA_BIN)"
else
    info "nvcc not in PATH — ensure CUDA 12.8 is exported"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
dbg "Project dir: $PROJECT_DIR"

if [[ -x "$PROJECT_DIR/bin/gpu_receiver" ]]; then
    ok "bin/gpu_receiver exists and is executable"
else
    bad "bin/gpu_receiver not found at $PROJECT_DIR/bin/ — rebuild needed"
fi

# ────────────────────────────────────────────────────────────────────
hdr "5. HOST — NIC RX counters (snapshot before test)"
# ────────────────────────────────────────────────────────────────────

ETHTOOL_OUT=$(ethtool -S "$HOST_NIC" 2>&1) || true
RX_PKTS_BEFORE=$(echo "$ETHTOOL_OUT" | grep 'rx_packets_phy:' | awk '{print $2}') || true
RX_BYTES_BEFORE=$(echo "$ETHTOOL_OUT" | grep 'rx_bytes_phy:' | awk '{print $2}') || true
RX_MCAST_BEFORE=$(echo "$ETHTOOL_OUT" | grep 'rx_multicast_phy:' | awk '{print $2}') || true
RX_VPORT_PKTS=$(echo "$ETHTOOL_OUT" | grep 'rx_vport_unicast_packets:' | awk '{print $2}') || true
RX_VPORT_MCAST=$(echo "$ETHTOOL_OUT" | grep 'rx_vport_multicast_packets:' | awk '{print $2}') || true
echo "  rx_packets_phy:             ${RX_PKTS_BEFORE:-N/A}"
echo "  rx_bytes_phy:               ${RX_BYTES_BEFORE:-N/A}"
echo "  rx_multicast_phy:           ${RX_MCAST_BEFORE:-N/A}"
echo "  rx_vport_unicast_packets:   ${RX_VPORT_PKTS:-N/A}"
echo "  rx_vport_multicast_packets: ${RX_VPORT_MCAST:-N/A}"

# ────────────────────────────────────────────────────────────────────
hdr "6. DPU ARM — SSH connectivity"
# ────────────────────────────────────────────────────────────────────

dbg "Trying: ssh $DPU_SSH echo ok"
SSH_TEST=$(ssh_dpu "echo ok" 2>&1) || true
dbg "ssh result: '$SSH_TEST'"
DPU_REACHABLE=false
if echo "$SSH_TEST" | grep -q ok; then
    ok "SSH to $DPU_SSH works"
    DPU_REACHABLE=true
else
    bad "Cannot SSH to $DPU_SSH — check tmfifo_net0 and 192.168.100.x setup"
    dbg "Hint: on host run: ip addr show tmfifo_net0"
    TMFIFO=$(ip addr show tmfifo_net0 2>&1) || true
    dbg "tmfifo_net0: $TMFIFO"
fi

if [[ "$DPU_REACHABLE" != "true" ]]; then
    echo -e "\n  ${RED}Cannot reach DPU ARM — skipping DPU checks (7-13).${RST}"
else

# ────────────────────────────────────────────────────────────────────
hdr "7. DPU ARM — Bridge & interfaces"
# ────────────────────────────────────────────────────────────────────

BRIDGE_STATE=$(ssh_dpu "ip link show br-pf1 2>&1") || true
dbg "ip link show br-pf1 => $(echo "$BRIDGE_STATE" | head -1)"
if echo "$BRIDGE_STATE" | grep -q 'state UP'; then
    ok "br-pf1 bridge is UP"
elif echo "$BRIDGE_STATE" | grep -q 'does not exist'; then
    bad "br-pf1 bridge does NOT exist — needs full bridge setup"
else
    bad "br-pf1 bridge state: $(echo "$BRIDGE_STATE" | head -1)"
fi

BRIDGE_MEMBERS=$(ssh_dpu "bridge link show 2>&1") || true
dbg "bridge link show =>"
echo "$BRIDGE_MEMBERS" | grep -E 'br-pf1|p1|pf1hpf' | while read -r line; do dbg "  $line"; done

if echo "$BRIDGE_MEMBERS" | grep -q 'p1.*br-pf1\|br-pf1.*p1'; then
    ok "p1 is a member of br-pf1"
elif echo "$BRIDGE_MEMBERS" | grep 'p1' | grep -q 'master br-pf1'; then
    ok "p1 is a member of br-pf1"
else
    # Try alternate check
    P1_MASTER=$(ssh_dpu "cat /sys/class/net/p1/master/ifindex 2>/dev/null && ip link show br-pf1 2>/dev/null | grep -oP '^\d+'") || true
    P1_IN_BRIDGE=$(ssh_dpu "ip link show p1 2>&1 | grep -o 'master br-pf1'") || true
    if [[ -n "$P1_IN_BRIDGE" ]]; then
        ok "p1 is a member of br-pf1"
    else
        bad "p1 is NOT in br-pf1 — run: sudo ip link set p1 master br-pf1"
    fi
fi

PF1HPF_IN_BRIDGE=$(ssh_dpu "ip link show pf1hpf 2>&1 | grep -o 'master br-pf1'") || true
if [[ -n "$PF1HPF_IN_BRIDGE" ]]; then
    ok "pf1hpf is a member of br-pf1"
else
    bad "pf1hpf is NOT in br-pf1 — run: sudo ip link set pf1hpf master br-pf1"
fi

P1_STATE=$(ssh_dpu "ip link show p1 2>&1 | head -1") || true
dbg "p1: $P1_STATE"
if echo "$P1_STATE" | grep -q 'state UP'; then
    ok "p1 is UP"
else
    bad "p1 is DOWN — run: sudo ip link set p1 up"
fi

PF1HPF_STATE=$(ssh_dpu "ip link show pf1hpf 2>&1 | head -1") || true
dbg "pf1hpf: $PF1HPF_STATE"
if echo "$PF1HPF_STATE" | grep -q 'state UP'; then
    ok "pf1hpf is UP"
else
    bad "pf1hpf is DOWN — run: sudo ip link set pf1hpf up"
fi

DPU_ALL_IFACES=$(ssh_dpu "ip -br addr 2>&1") || true
dbg "All DPU interfaces:"
echo "$DPU_ALL_IFACES" | while read -r line; do dbg "  $line"; done

# ────────────────────────────────────────────────────────────────────
hdr "8. DPU ARM — IGMP snooping (critical for multicast)"
# ────────────────────────────────────────────────────────────────────

IGMP_SNOOP=$(ssh_dpu "cat /sys/devices/virtual/net/br-pf1/bridge/multicast_snooping 2>&1") || true
dbg "multicast_snooping = $IGMP_SNOOP"
if [[ "$IGMP_SNOOP" == "0" ]]; then
    ok "IGMP snooping DISABLED on br-pf1 (correct for multicast)"
else
    bad "IGMP snooping is '$IGMP_SNOOP' — multicast will be silently dropped!"
    echo "       Fix: sudo ip link set br-pf1 type bridge mcast_snooping 0"
fi

# ────────────────────────────────────────────────────────────────────
hdr "9. DPU ARM — IP addresses & routing"
# ────────────────────────────────────────────────────────────────────

DPU_BRIDGE_IP=$(ssh_dpu "ip -4 addr show br-pf1 2>/dev/null | grep -oP 'inet \K[0-9.]+'") || true
DPU_P0_IP=$(ssh_dpu "ip -4 addr show p0 2>/dev/null | grep -oP 'inet \K[0-9.]+'") || true
dbg "br-pf1 IP: ${DPU_BRIDGE_IP:-<none>}"
dbg "p0 IP: ${DPU_P0_IP:-<none>}"

if [[ "$DPU_BRIDGE_IP" == "$DPU_DATA_IP" ]]; then
    ok "br-pf1 has IP $DPU_DATA_IP"
elif [[ "$DPU_P0_IP" == "$DPU_DATA_IP" ]]; then
    ok "p0 has IP $DPU_DATA_IP (alternative to br-pf1)"
else
    bad "Neither br-pf1 nor p0 has IP $DPU_DATA_IP"
fi

if [[ -n "$DPU_P0_IP" && -n "$DPU_BRIDGE_IP" && "$DPU_P0_IP" == "$DPU_BRIDGE_IP" ]]; then
    info "Both p0 and br-pf1 have $DPU_DATA_IP — may cause routing confusion"
fi

DPU_ROUTE=$(ssh_dpu "ip route get $HOST_NIC_IP 2>&1") || true
dbg "DPU route to $HOST_NIC_IP => $DPU_ROUTE"
DPU_ROUTE_DEV=$(echo "$DPU_ROUTE" | grep -oP 'dev \K\S+' | head -1) || true
if [[ -n "$DPU_ROUTE_DEV" ]]; then
    ok "DPU routes to $HOST_NIC_IP via $DPU_ROUTE_DEV"
else
    info "Could not determine DPU route to host"
fi

DPU_PING=$(ssh_dpu "ping -c 1 -W 2 $HOST_NIC_IP 2>&1") || true
dbg "DPU ping host => $(echo "$DPU_PING" | grep -E 'transmitted|icmp_seq' | head -1)"
if echo "$DPU_PING" | grep -q '1 received'; then
    ok "DPU ARM can ping host $HOST_NIC_IP"
else
    info "DPU ARM cannot ping host $HOST_NIC_IP (may be normal)"
fi

# ────────────────────────────────────────────────────────────────────
hdr "10. DPU ARM — OVS bridges (should NOT hold p0/p1)"
# ────────────────────────────────────────────────────────────────────

OVS_BR1=$(ssh_dpu "sudo ovs-vsctl list-ports ovsbr1 2>&1") || true
OVS_BR2=$(ssh_dpu "sudo ovs-vsctl list-ports ovsbr2 2>&1") || true
dbg "ovsbr1 ports: ${OVS_BR1:-<none/error>}"
dbg "ovsbr2 ports: ${OVS_BR2:-<none/error>}"
OVS_ALL="$OVS_BR1 $OVS_BR2"
if echo "$OVS_ALL" | grep -qwE 'p0|p1'; then
    bad "p0 or p1 still in OVS bridge — remove them:"
    echo "       sudo ovs-vsctl del-port ovsbr1 p0; sudo ovs-vsctl del-port ovsbr2 p1"
else
    ok "p0/p1 not in OVS bridges"
fi

# ────────────────────────────────────────────────────────────────────
hdr "11. DPU ARM — Stale sender processes"
# ────────────────────────────────────────────────────────────────────

STALE=$(ssh_dpu "ps aux | grep -E 'data_source|send_ticks' | grep -v grep") || true
if [[ -z "$STALE" ]]; then
    ok "No stale data_source or send_ticks processes"
else
    info "Found running sender processes:"
    echo "$STALE" | while read -r line; do dbg "$line"; done
fi

# ────────────────────────────────────────────────────────────────────
hdr "12. DPU ARM — Eswitch mode"
# ────────────────────────────────────────────────────────────────────

ESWITCH=$(ssh_dpu "sudo devlink dev eswitch show pci/0000:03:00.0 2>&1") || true
dbg "devlink eswitch => $ESWITCH"
if echo "$ESWITCH" | grep -q switchdev; then
    ok "Eswitch mode: switchdev"
elif echo "$ESWITCH" | grep -q legacy; then
    bad "Eswitch mode: legacy (expected switchdev)"
else
    info "Could not query eswitch mode: $ESWITCH"
    ESWITCH2=$(ssh_dpu "sudo devlink dev eswitch show pci/0000:03:00.1 2>&1") || true
    dbg "Trying pci/0000:03:00.1 => $ESWITCH2"
fi

# ────────────────────────────────────────────────────────────────────
hdr "13. DATA PATH TEST — Send packets from DPU ARM & capture"
# ────────────────────────────────────────────────────────────────────

echo "  Step A: tcpdump on DPU br-pf1 while sending 5 packets..."
DPU_TCPDUMP_BR=$(ssh_dpu "
sudo timeout 5 tcpdump -i br-pf1 -c 5 -nn udp port $MCAST_PORT 2>&1 &
TCPD_PID=\$!
sleep 0.5
python3 -c \"
import socket, struct, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('$DPU_DATA_IP'))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
for i in range(5):
    msg = struct.pack('<QIHBBdddd', int(time.time()*1e9), i, 1, 0, 0, 100.0, 100.1, 100.05, 1000.0)
    sock.sendto(msg, ('$MCAST_ADDR', $MCAST_PORT))
    time.sleep(0.1)
print('Sent 5 test packets from DPU')
\"
sleep 1
wait \$TCPD_PID 2>/dev/null || true
" 2>&1) || true
echo "$DPU_TCPDUMP_BR" | while read -r line; do dbg "$line"; done

if echo "$DPU_TCPDUMP_BR" | grep -q "$MCAST_ADDR.*$MCAST_PORT"; then
    ok "Packets visible on DPU br-pf1"
elif echo "$DPU_TCPDUMP_BR" | grep -q "Sent 5"; then
    info "Packets sent but NOT captured on br-pf1 — bridge may not be forwarding"
else
    bad "Send or capture failed on DPU br-pf1"
fi

echo ""
echo "  Step B: tcpdump on DPU pf1hpf while sending 5 packets..."
DPU_TCPDUMP_PF1=$(ssh_dpu "
sudo timeout 5 tcpdump -i pf1hpf -c 5 -nn udp port $MCAST_PORT 2>&1 &
TCPD_PID=\$!
sleep 0.5
python3 -c \"
import socket, struct, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('$DPU_DATA_IP'))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
for i in range(5):
    msg = struct.pack('<QIHBBdddd', int(time.time()*1e9), i, 1, 0, 0, 100.0, 100.1, 100.05, 1000.0)
    sock.sendto(msg, ('$MCAST_ADDR', $MCAST_PORT))
    time.sleep(0.1)
print('Sent 5 test packets from DPU')
\"
sleep 1
wait \$TCPD_PID 2>/dev/null || true
" 2>&1) || true
echo "$DPU_TCPDUMP_PF1" | while read -r line; do dbg "$line"; done

if echo "$DPU_TCPDUMP_PF1" | grep -q "$MCAST_ADDR.*$MCAST_PORT"; then
    ok "Packets visible on DPU pf1hpf (reaching host-side representor)"
elif echo "$DPU_TCPDUMP_PF1" | grep -q "Sent 5"; then
    info "Packets sent but NOT seen on pf1hpf — bridge not forwarding to representor"
else
    bad "Send or capture failed on pf1hpf"
fi

fi  # end DPU_REACHABLE block

# ────────────────────────────────────────────────────────────────────
hdr "14. HOST — NIC RX counters (after test)"
# ────────────────────────────────────────────────────────────────────

ETHTOOL_OUT2=$(ethtool -S "$HOST_NIC" 2>&1) || true
RX_PKTS_AFTER=$(echo "$ETHTOOL_OUT2" | grep 'rx_packets_phy:' | awk '{print $2}') || true
RX_BYTES_AFTER=$(echo "$ETHTOOL_OUT2" | grep 'rx_bytes_phy:' | awk '{print $2}') || true
RX_MCAST_AFTER=$(echo "$ETHTOOL_OUT2" | grep 'rx_multicast_phy:' | awk '{print $2}') || true
echo "  rx_packets_phy:   ${RX_PKTS_AFTER:-N/A}  (was ${RX_PKTS_BEFORE:-N/A})"
echo "  rx_multicast_phy: ${RX_MCAST_AFTER:-N/A}  (was ${RX_MCAST_BEFORE:-N/A})"

if [[ -n "$RX_PKTS_BEFORE" && -n "$RX_PKTS_AFTER" && "$RX_PKTS_BEFORE" != "N/A" && "$RX_PKTS_AFTER" != "N/A" ]]; then
    DELTA=$((RX_PKTS_AFTER - RX_PKTS_BEFORE))
    dbg "rx_packets delta = $DELTA"
    if [[ $DELTA -gt 0 ]]; then
        ok "NIC received $DELTA new packets during test"
    else
        info "NIC received 0 new packets — packets may not be reaching the physical port"
    fi
fi

if [[ -n "$RX_MCAST_BEFORE" && -n "$RX_MCAST_AFTER" && "$RX_MCAST_BEFORE" != "N/A" && "$RX_MCAST_AFTER" != "N/A" ]]; then
    MCAST_DELTA=$((RX_MCAST_AFTER - RX_MCAST_BEFORE))
    dbg "rx_multicast delta = $MCAST_DELTA"
fi

# ────────────────────────────────────────────────────────────────────
hdr "15. HOST — tcpdump on $HOST_NIC during DPU send"
# ────────────────────────────────────────────────────────────────────

if [[ "$DPU_REACHABLE" == "true" ]]; then
    echo "  Capturing on host while DPU sends 5 packets..."
    HOST_TCPDUMP=$(
        sudo timeout 6 tcpdump -i "$HOST_NIC" -c 5 -nn udp port "$MCAST_PORT" 2>&1 &
        HTPID=$!
        sleep 0.5
        ssh_dpu "python3 -c \"
import socket, struct, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('$DPU_DATA_IP'))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
for i in range(5):
    msg = struct.pack('<QIHBBdddd', int(time.time()*1e9), i, 1, 0, 0, 100.0, 100.1, 100.05, 1000.0)
    sock.sendto(msg, ('$MCAST_ADDR', $MCAST_PORT))
    time.sleep(0.1)
\"" || true
        sleep 2
        wait $HTPID 2>/dev/null || true
    ) || true
    echo "$HOST_TCPDUMP" | while read -r line; do dbg "$line"; done

    if echo "$HOST_TCPDUMP" | grep -q "$MCAST_ADDR"; then
        ok "Host tcpdump captured multicast packets from DPU"
    else
        info "Host tcpdump saw nothing — packets may bypass kernel (normal if DOCA flow rules are active)"
    fi
else
    info "Skipped — DPU ARM not reachable"
fi

# ────────────────────────────────────────────────────────────────────
hdr "16. HOST — Background NIC RX rate (phantom packet check)"
# ────────────────────────────────────────────────────────────────────

echo "  Sampling NIC RX counter for 3 seconds with no sender running..."
RX_T0=$(ethtool -S "$HOST_NIC" 2>/dev/null | grep 'rx_packets_phy:' | awk '{print $2}') || RX_T0=0
sleep 3
RX_T1=$(ethtool -S "$HOST_NIC" 2>/dev/null | grep 'rx_packets_phy:' | awk '{print $2}') || RX_T1=0
BG_TOTAL=$((RX_T1 - RX_T0))
BG_RATE=$((BG_TOTAL / 3))
dbg "rx_packets: $RX_T0 -> $RX_T1 (delta=$BG_TOTAL in 3s)"
echo "  Background packets in 3s: $BG_TOTAL (~${BG_RATE}/sec)"

if [[ $BG_RATE -gt 1000 ]]; then
    bad "Very high background RX: ~${BG_RATE} pkt/s — explains phantom packets in gpu_receiver"
elif [[ $BG_RATE -gt 100 ]]; then
    info "Moderate background RX: ~${BG_RATE} pkt/s — likely source of phantom packets"
elif [[ $BG_RATE -gt 0 ]]; then
    info "Low background RX: ~${BG_RATE} pkt/s"
else
    ok "No background RX traffic on $HOST_NIC"
fi

# Also check all-protocol traffic on the NIC
echo ""
echo "  Quick tcpdump: any traffic on $HOST_NIC (3 second sample, all protocols)..."
ALL_TRAFFIC=$(sudo timeout 3 tcpdump -i "$HOST_NIC" -c 20 -nn 2>&1) || true
CAPTURED=$(echo "$ALL_TRAFFIC" | grep 'packets captured' | grep -oP '\d+' | head -1) || true
echo "$ALL_TRAFFIC" | tail -5 | while read -r line; do dbg "$line"; done
if [[ -n "$CAPTURED" && "$CAPTURED" -gt 0 ]]; then
    info "$CAPTURED packets captured on $HOST_NIC (showing types of background traffic)"
    echo "$ALL_TRAFFIC" | grep -v 'listening\|capture\|packets' | head -10 | while read -r line; do dbg "$line"; done
else
    ok "No background traffic captured on $HOST_NIC"
fi

# ────────────────────────────────────────────────────────────────────
hdr "SUMMARY"
# ────────────────────────────────────────────────────────────────────

echo ""
echo -e "  ${GRN}PASS: $pass${RST}  ${RED}FAIL: $fail${RST}  ${YLW}WARN: $warn${RST}"
echo ""

if [[ $fail -gt 0 ]]; then
    echo -e "  ${RED}Fix the FAIL items above before running gpu_receiver.${RST}"
fi
if [[ $fail -eq 0 && $warn -eq 0 ]]; then
    echo -e "  ${GRN}Data path looks healthy.${RST}"
fi

exit 0
