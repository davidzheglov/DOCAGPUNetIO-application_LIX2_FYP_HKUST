#!/usr/bin/env bash
set -euo pipefail

GPU_ID="${GPU_ID:-1}"
GPU_PCIE="${GPU_PCIE:-0000:ac:00.0}"
NIC_PCIE="${NIC_PCIE:-0000:bd:00.1}"   # important: .1 in your setup
HARNESS_IP="${HARNESS_IP:-127.0.0.1}"
FILLSIM_IP="${FILLSIM_IP:-127.0.0.1}"

cleanup() {
  echo "[host-pipeline] stopping..."
  jobs -pr | xargs -r kill
  wait || true
}
trap cleanup EXIT INT TERM

source scripts/env.sh
make -j t4 fill_sim

mkdir -p results

# 1) fill simulator (writes CSV)
bin/fill_simulator --port 5006 --output results/fills.csv \
  > results/fill_simulator.log 2>&1 &

# 2) optional live monitor for both result ports
python3 scripts/listen_results.py \
  > results/listen_results.log 2>&1 &

# 3) gpu receiver (foreground)
sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
  bin/gpu_receiver --tier 4 --gpu "${GPU_ID}" \
    --gpu-pcie "${GPU_PCIE}" \
    --nic-pcie "${NIC_PCIE}" \
    --harness "${HARNESS_IP}" \
    --fillsim "${FILLSIM_IP}"