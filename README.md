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

| Tier | Technology | Network path |
|------|-----------|--------------|
| T1 | CPU naive | `recvfrom()` → `cudaMemcpy` |
| T2 | DPDK | Poll-mode driver, no OS kernel, `cudaMemcpy` |
| T3 | GPU RDMA | `libibverbs` + `nv_peer_mem`, NIC writes GPU directly |
| T4 | GPUNetIO | DOCA `doca_gpu_eth_rxq_recv_strong`, adapter on host CPU |
| T5 | GPUNetIO + BlueField DPU | Same GPU binary as T4, adapter on DPU ARM |

## Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# DPU ARM cross-compile
cmake -B build-arm -DCMAKE_TOOLCHAIN_FILE=cmake/aarch64-toolchain.cmake
cmake --build build-arm -j$(nproc)
```

## Benchmark Run

```bash
# Start data source (replay mode)
./build/data_source --mode replay --csv data/ticks.csv --rate 500000

# Run a tier receiver (example: T1)
./build/cpu_receiver --multicast 239.0.0.1 --port 5005

# Run benchmark harness (all 75 runs)
./build/benchmark_harness --output results/
```

## Timestamps

Each tick carries four timestamps for latency decomposition:
- **T1** — stamped by data source at `sendto()`
- **T2** — stamped when tick arrives in GPU memory
- **T3** — stamped by CUDA kernel on completion
- **T4** — stamped when signal written to output buffer
