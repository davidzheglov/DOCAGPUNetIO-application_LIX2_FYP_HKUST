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

## Timestamps

Each tick carries four timestamps for latency decomposition:
- **T1** — stamped by data source at `sendto()`
- **T2** — stamped when tick arrives in GPU memory
- **T3** — stamped by CUDA kernel on completion
- **T4** — stamped when signal written to output buffer
