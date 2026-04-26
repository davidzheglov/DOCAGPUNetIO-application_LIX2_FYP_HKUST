#!/bin/bash
# setup_dpdk.sh — Configure DPDK prerequisites on cpu1 host.
# Run once after each reboot, before launching dpdk_receiver.
# Usage: sudo bash scripts/setup_dpdk.sh
set -euo pipefail

NIC_PCIE="0000:bd:00.0"
HUGEPAGE_COUNT=1024          # 1024 × 2MB = 2GB
HUGEPAGE_SZ="2048kB"

echo "=== DPDK setup for dpdk_receiver ==="

# ── 1. Hugepages ────────────────────────────────────────────────────────────
current=$(cat /sys/kernel/mm/hugepages/hugepages-${HUGEPAGE_SZ}/nr_hugepages)
echo "[1/4] Hugepages: current=${current} requested=${HUGEPAGE_COUNT}"
if [ "$current" -lt "$HUGEPAGE_COUNT" ]; then
    echo "${HUGEPAGE_COUNT}" > /sys/kernel/mm/hugepages/hugepages-${HUGEPAGE_SZ}/nr_hugepages
    actual=$(cat /sys/kernel/mm/hugepages/hugepages-${HUGEPAGE_SZ}/nr_hugepages)
    echo "  Set to ${actual} (free=$(cat /sys/kernel/mm/hugepages/hugepages-${HUGEPAGE_SZ}/free_hugepages))"
    if [ "$actual" -lt "$HUGEPAGE_COUNT" ]; then
        echo "  WARN: only got ${actual}/${HUGEPAGE_COUNT} — system may be low on contiguous memory"
    fi
else
    echo "  Already sufficient"
fi

# Mount hugetlbfs if not already mounted
if ! mount | grep -q hugetlbfs; then
    mkdir -p /dev/hugepages
    mount -t hugetlbfs nodev /dev/hugepages
    echo "  Mounted hugetlbfs at /dev/hugepages"
else
    echo "  hugetlbfs already mounted"
fi

# ── 2. VFIO / IOMMU ────────────────────────────────────────────────────────
# mlx5 uses bifurcated driver (no rebind needed), but DPDK still needs
# vfio-pci module loaded for IOVA PA mode on some kernels.
echo "[2/4] Kernel modules"
if ! lsmod | grep -q vfio_pci; then
    modprobe vfio-pci 2>/dev/null || echo "  WARN: vfio-pci not available (ok for mlx5 bifurcated)"
else
    echo "  vfio-pci already loaded"
fi

# mlx5_core must remain bound — bifurcated driver, no rebinding
driver=$(basename "$(readlink /sys/bus/pci/devices/${NIC_PCIE}/driver 2>/dev/null)" 2>/dev/null || echo "none")
echo "  NIC ${NIC_PCIE} driver: ${driver}"
if [ "$driver" != "mlx5_core" ]; then
    echo "  WARN: expected mlx5_core (bifurcated). Current: ${driver}"
    echo "  mlx5 DPDK PMD works alongside kernel driver — do NOT rebind to vfio-pci"
fi

# ── 3. NIC link status ─────────────────────────────────────────────────────
echo "[3/4] NIC link status"
iface=$(ls /sys/bus/pci/devices/${NIC_PCIE}/net/ 2>/dev/null | head -1)
if [ -n "$iface" ]; then
    carrier=$(cat /sys/class/net/${iface}/carrier 2>/dev/null || echo "?")
    operstate=$(cat /sys/class/net/${iface}/operstate 2>/dev/null || echo "?")
    echo "  ${iface}: carrier=${carrier} operstate=${operstate}"
    ip addr show dev "$iface" 2>/dev/null | grep "inet " | awk '{print "  IP:", $2}'
else
    echo "  WARN: no net device found for ${NIC_PCIE}"
fi

# ── 4. Summary ──────────────────────────────────────────────────────────────
echo "[4/4] Ready check"
free_hp=$(cat /sys/kernel/mm/hugepages/hugepages-${HUGEPAGE_SZ}/free_hugepages)
if [ "$free_hp" -ge 512 ] && [ "$driver" = "mlx5_core" ]; then
    echo "  PASS — ready to run dpdk_receiver"
    echo ""
    echo "  Example:"
    echo "    sudo -E env \"PATH=\$PATH\" \"LD_LIBRARY_PATH=\$LD_LIBRARY_PATH\" \\"
    echo "        bin/dpdk_receiver \\"
    echo "        -a ${NIC_PCIE} -l 0-1 -n 4 -- \\"
    echo "        --port 0 --tier 2 \\"
    echo "        --harness 127.0.0.1 --fillsim 127.0.0.1"
else
    echo "  FAIL — hugepages free=${free_hp} (need >=512), driver=${driver} (need mlx5_core)"
fi
