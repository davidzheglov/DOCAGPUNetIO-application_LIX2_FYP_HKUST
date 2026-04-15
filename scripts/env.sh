#!/bin/bash
# Source this file to set up CUDA 12.8 + DOCA SDK environment.
# Usage: source scripts/env.sh
export PATH=/usr/local/cuda-12.8/bin:$PATH
export LD_LIBRARY_PATH=/opt/mellanox/doca/lib/x86_64-linux-gnu:/usr/local/cuda-12.8/lib64:$LD_LIBRARY_PATH

# DPU ARM management interface (needed for ssh ubuntu@192.168.100.2)
sudo ip addr add 192.168.100.1/24 dev tmfifo_net0 2>/dev/null || true

echo "[env] CUDA 12.8 + DOCA SDK paths set"
