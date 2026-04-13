#!/bin/bash
# Source this file to set up CUDA 12.8 + DOCA SDK environment.
# Usage: source scripts/env.sh
export PATH=/usr/local/cuda-12.8/bin:$PATH
export LD_LIBRARY_PATH=/opt/mellanox/doca/lib/x86_64-linux-gnu:/usr/local/cuda-12.8/lib64:$LD_LIBRARY_PATH
echo "[env] CUDA 12.8 + DOCA SDK paths set"
