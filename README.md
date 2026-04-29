# GPU-Accelerated Financial Tick Pipeline

HKUST Final Year Project — benchmarking NVIDIA GPUNetIO and BlueField-3 DPU offloading through a real financial backtesting application.

## Architecture

All components communicate via **UDP multicast (239.0.0.1:5005)** using a shared 48-byte `TickMessage` struct.

```
src/
├── common/              # tick_message.h, shared structs
├── data_source/         # replay + live Binance bridge (also runs on DPU ARM)
├── receivers/
│   ├── cpu/             # T1: recvfrom() + cudaMemcpy
│   ├── dpdk/            # T2: DPDK poll-mode
│   ├── rdma/            # T3: GPU RDMA via libibverbs
│   └── gpu/             # T4/T5: DOCA GPUNetIO (same binary, different deployment)
├── fill_simulator/      # Order book engine
├── benchmark_harness/   # Five-tier coordinator
└── dashboard/           # Python Plotly dashboard
reference/               # Archived prior DOCA/CUDA prototypes
```

## Benchmark Tiers

| Tier | Technology | Network path | CPU copies |
|------|-----------|--------------|------------|
| T1 | CPU naive | `recvfrom()` → `cudaMemcpy` | 3 |
| T2 | DPDK | Poll-mode driver + `rte_flow`, `cudaMemcpy` | 2 |
| T3 | GPU RDMA | `libibverbs` RAW_PACKET QP + `nvidia-peermem`, NIC DMAs to GPU | 0 (DMA) |
| T4 | GPUNetIO | DOCA Flow → GPU RX queue, NIC DMAs to GPU | 0 (DMA) |
| T5 | GPUNetIO + BlueField DPU | Same GPU binary as T4, adapter on DPU ARM | 0 (DMA) |

## Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# DPU ARM cross-compile
cmake -B build-arm -DCMAKE_TOOLCHAIN_FILE=cmake/aarch64-toolchain.cmake
cmake --build build-arm -j$(nproc)
```

## Cross-DPU Test (two servers)

Sender: `send_ticks.py` on cpu2's DPU ARM (`10.10.10.3`).
Receiver: any tier on cpu1 host (`lxcpu1`), packets arrive on PF0 (`ens21f0np0`, `0000:bd:00.0`).

```bash
# ON cpu2 DPU ARM — sender (same for all tiers)
python3 send_ticks.py --mode generate --rate 1000 --count 1000 --iface 10.10.10.3

# ON cpu1 HOST — T1: CPU socket receiver
sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
    bin/cpu_receiver --tier 1 --iface ens21f0np0 \
    --harness 127.0.0.1 --fillsim 127.0.0.1

# ON cpu1 HOST — T2: DPDK receiver (run scripts/setup_dpdk.sh first)
sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
    bin/dpdk_receiver -a 0000:bd:00.0 -l 0-1 -n 4 -- \
    --port 0 --tier 2 --harness 127.0.0.1 --fillsim 127.0.0.1

# ON cpu1 HOST — T3: RDMA receiver
sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
    bin/rdma_receiver --dev mlx5_0 --tier 3 \
    --harness 127.0.0.1 --fillsim 127.0.0.1

# ON cpu1 HOST — T4: GPU receiver (DOCA GPUNetIO)
sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
    bin/gpu_receiver --tier 4 --gpu 1 \
    --gpu-pcie 0000:ac:00.0 --nic-pcie 0000:bd:00.0 \
    --harness 127.0.0.1 --fillsim 127.0.0.1
```

## Live Binance Pipeline

The `data_source` binary supports `--mode live` which connects directly to the Binance WebSocket API (`stream.binance.com:9443`), subscribes to `bookTicker` + `aggTrade` streams, and converts JSON tick data into the same 48-byte `TickMessage` format used by replay mode.

### Network Topology Challenge

When running `data_source --mode live` on the **host**, the DPU bridge's split-horizon rule prevents host-sourced UDP multicast from looping back to the host's PF0/PF1 interfaces where receivers listen. This is the same reason `send_ticks.py` must run on the **DPU ARM** (not the host) for cross-machine tests.

### Solution: DPU ARM UDP Relay

A lightweight C++ relay (`dpu_relay`) runs on the DPU ARM, receives unicast UDP from the host via the management network (`tmfifo_net0`, `192.168.100.x`), and forwards to the working multicast path:

```
Host: data_source --mode live --dest 192.168.100.2:6005
    ↓ (tmfifo_net0, unicast UDP)
DPU ARM: dpu_relay --listen-port 6005 --iface 10.10.10.1
    ↓ (p0 → bridge → host PF0, multicast UDP)
Host receivers: T1–T4 listening on 239.0.0.1:5005
```

### Build

```bash
# Host binary (for local testing)
make dpu_relay

# Cross-compile for DPU ARM
make dpu_relay_dpu
```

### Deploy and Run

```bash
# 1. Copy relay to DPU ARM
scp bin/dpu_relay_dpu ubuntu@192.168.100.2:~/dpu_relay_dpu

# 2. Start relay on DPU ARM
ssh ubuntu@192.168.100.2 "./dpu_relay_dpu --listen-port 6005 --iface 10.10.10.1"

# 3. Start receiver on host (example: T1)
sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
    bin/cpu_receiver --tier 1 --iface ens21f0np0 \
    --harness 127.0.0.1 --fillsim 127.0.0.1

# 4. Start live data source on host
bin/data_source_live --mode live --symbols BTCUSDT,ETHUSDT \
    --dest 192.168.100.2:6005
```

### Convenience Script

For automated startup, use the provided pipeline script:

```bash
# Build everything first
make data_source_live dpu_relay_dpu t1

# Run full pipeline (starts relay, receiver, and data source)
./scripts/run_live_pipeline.sh --tier 1 --symbols BTCUSDT,ETHUSDT
```

## Frontend Demo Plan

We plan to add a frontend for the live demo in a separate `frontend` branch.
The intended frontend scope is to control and visualise the **existing backend
pipeline**, not to replace it.

The frontend should be able to:

- start and stop the live demo pipeline
- choose a receiver tier (`T1`–`T4`)
- choose demo symbols
- show pipeline health, logs, throughput, and recent signals

For the first milestone, the recommended target is the live-demo path:

```text
data_source_live (host)
  -> dpu_relay (DPU ARM)
  -> selected receiver tier on lxcpu1
  -> fill_simulator / local metrics display
```

The detailed handoff note for the teammate working on the frontend branch is:

[docs/FRONTEND_INTEGRATION.md](/home/timmy/DOCAGPUNetIO-application_LIX2_FYP_HKUST/docs/FRONTEND_INTEGRATION.md)

That document describes:

- which binaries/scripts already form the backend
- the recommended control model for the frontend
- the exact commands currently used to run each tier
- the suggested first frontend deliverable

## Timestamps

For the current T1-T4 benchmark path, latency decomposition uses a single
receiver-side clock domain on `lxcpu1`:
- **T1** — receiver-side ingress timestamp on `lxcpu1`
- **T2** — stamped when the tick reaches the tier's ingest point / GPU memory
- **T3** — stamped when compute completes
- **T4** — stamped when the result is available to send back to the harness

This means the reported benchmark latencies are receiver-ingress-to-output
measurements rather than cross-machine sender-to-receiver wall-clock times.
