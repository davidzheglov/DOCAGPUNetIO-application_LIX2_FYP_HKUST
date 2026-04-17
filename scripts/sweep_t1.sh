#!/usr/bin/env bash
# sweep_t1.sh — Run T1 (cpu_receiver) rate sweep: 7 rates × 3 reps each.
#
# Usage (ON HOST, no sudo needed — benchmark_cpu.py starts cpu_receiver with sudo internally):
#   bash scripts/sweep_t1.sh
#
# Override defaults:
#   DURATION=20 WARMUP=3 bash scripts/sweep_t1.sh
#   RATES="10000 50000 100000" bash scripts/sweep_t1.sh
#
# Results land in results/single/T1_<rate>hz_rep<N>_<ts>/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

RATES="${RATES:-10000 25000 50000 100000 200000 500000 1000000}"
REPS="${REPS:-3}"
DURATION="${DURATION:-30}"
WARMUP="${WARMUP:-5}"
SENDER_IFACE="${SENDER_IFACE:-10.10.10.2}"

echo "========================================================"
echo "  T1 cpu_receiver rate sweep"
echo "  rates     : $RATES"
echo "  reps      : $REPS"
echo "  duration  : ${DURATION}s  warmup: ${WARMUP}s"
echo "  sender    : iface=$SENDER_IFACE"
echo "  results   : $REPO_ROOT/results/single/"
echo "========================================================"
echo ""

FAILED=()

for rate in $RATES; do
    for rep in $(seq 1 "$REPS"); do
        label="rate=${rate} rep=${rep}"
        echo "------------------------------------------------------------"
        echo "  >>> $label"
        echo "------------------------------------------------------------"

        if sudo python3 "$SCRIPT_DIR/benchmark_cpu.py" \
                --rate       "$rate"         \
                --repetition "$rep"          \
                --duration   "$DURATION"     \
                --warmup     "$WARMUP"       \
                --sender-iface "$SENDER_IFACE"; then
            echo "  [OK] $label"
        else
            echo "  [FAIL] $label"
            FAILED+=("$label")
        fi
        echo ""
    done
done

echo "========================================================"
echo "  Sweep complete."
if [ ${#FAILED[@]} -eq 0 ]; then
    echo "  All runs succeeded."
else
    echo "  FAILED runs:"
    for f in "${FAILED[@]}"; do
        echo "    - $f"
    done
    exit 1
fi
echo "  Plots: python3 scripts/compare_t1_t4.py"
echo "========================================================"
