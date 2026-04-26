# System Specification: GPU-Accelerated Live Financial Backtesting Pipeline

**DOCAGPUNetIO — Final Year Project, HKUST**

This document specifies the hardware, software, data formats, algorithms, and communication protocols that make up the complete system. It is intended as a reference for anyone who needs to understand what every component does, how they connect, and why the system is designed this way.

---

## Table of Contents

1. [System Purpose](#1-system-purpose)
2. [Hardware Specification](#2-hardware-specification)
3. [Software Architecture Overview](#3-software-architecture-overview)
4. [Data Formats and Wire Protocols](#4-data-formats-and-wire-protocols)
5. [Component Specifications](#5-component-specifications)
6. [The Five Benchmark Tiers](#6-the-five-benchmark-tiers)
7. [GPU Kernel Specification](#7-gpu-kernel-specification)
8. [DOCA Initialization Specification](#8-doca-initialization-specification)
9. [DOCA Flow Pipe Specification](#9-doca-flow-pipe-specification)
10. [DPU Network Configuration](#10-dpu-network-configuration)
11. [Build System](#11-build-system)
12. [Benchmark Methodology](#12-benchmark-methodology)
13. [Configuration Reference](#13-configuration-reference)

---

## 1. System Purpose

This system is a benchmark platform that measures the latency of five different methods for moving financial market data from a network into a GPU for processing. The goal is to demonstrate that NVIDIA DOCA GPUNetIO — which transfers network packets directly into GPU memory without CPU involvement — achieves significantly lower latency than traditional approaches.

The system processes a stream of financial tick data (bid/ask prices, trade prices, volumes) arriving over UDP multicast. For each tick, a GPU kernel computes trading signals using two technical indicators: Exponential Moving Average (EMA) crossover and Relative Strength Index (RSI). The computed signals and latency timestamps are sent to a benchmark harness for analysis.

The five benchmark tiers use progressively more advanced hardware features:

| Tier | Network Method | CPU Copies | Approximate Latency |
|------|---------------|------------|-------------------|
| T1 | `recvfrom()` + `cudaMemcpy()` | 3 | Baseline |
| T2 | DPDK userspace driver | 2 | Lower |
| T3 | libibverbs GPU RDMA | 1 | Lower still |
| T4 | DOCA GPUNetIO | 0 | Lowest |
| T5 | DOCA GPUNetIO + DPU offload | 0 | Lowest + DPU-sourced data |

---

## 2. Hardware Specification

### 2.1 Host Server (`lxcpu1`)

| Component | Specification |
|-----------|--------------|
| CPU | x86_64 (multi-core) |
| OS | Ubuntu 24.04 LTS |
| Kernel | 6.11.0-17-generic (required — 6.17 breaks nvidia-peermem) |
| GPU | NVIDIA A2 (Ampere, SM 8.6, 16 GB GDDR6) |
| GPU PCIe Address | `0000:ac:00.0` |
| GPU CUDA Device Index | 1 (GPU 0 reserved for other workloads) |
| NIC | BlueField-3 DPU (ConnectX-7 ASIC) |
| NIC PF0 PCIe Address | `0000:bd:00.0` (host interface: `ens21f0np0`) — **data path** (cable side) |
| NIC PF1 PCIe Address | `0000:bd:00.1` (host interface: `ens21f1np1`) — unused |
| NVIDIA Driver | 570.x (nvidia-dkms-570) |
| CUDA Toolkit | 12.8 (`/usr/local/cuda-12.8/`) |
| DOCA SDK | 3.3 (`/opt/mellanox/doca/`) |
| Required Kernel Module | `nvidia-peermem` (loaded via `modprobe`) |

### 2.2 BlueField-3 DPU

The BlueField-3 DPU is a single PCIe card that contains three distinct hardware components:

**ConnectX-7 NIC ASIC**: The network processing chip. Contains:
- Two physical Ethernet ports (100 GbE capable)
- An embedded switch (eswitch) for routing packets between internal ports
- A packet parser that extracts header fields from raw packet bytes
- A flow table lookup engine where DOCA Flow rules are evaluated
- DMA engines that can write packet data to any PCIe-accessible memory (including GPU VRAM)
- RX/TX queue control logic

The ASIC sits on **both** the DPU's internal bus and the host's PCIe bus. This dual presence is what enables NIC-to-GPU DMA across the host's PCIe fabric.

**ARM Cortex-A78 Cores**: A general-purpose processor running its own Linux OS. It manages the eswitch, runs the data source in T5 mode, and provides configuration interfaces. The ARM cores are on the DPU's internal bus and **cannot** directly DMA to the host GPU — they have no peer-to-peer PCIe path.

**On-card memory**: DDR memory for the ARM cores' OS and applications. Separate from host RAM and GPU VRAM.

| Component | Specification |
|-----------|--------------|
| ASIC | ConnectX-7 (100 GbE, 2 ports) |
| CPU | ARM Cortex-A78 (8 cores) |
| OS | Ubuntu (BlueField OS) |
| Eswitch Mode | Switchdev (required for GPUNetIO) |
| DPU Mode | ECPF (Embedded Control Plane Function) |
| Management Access | SSH to `192.168.100.2` |
| Firmware | Queried via `mlxfwmanager` on DPU ARM |

### 2.3 Two-Server Cross-DPU Topology

The benchmark uses two servers connected by a direct cable between their BlueField-3 DPUs:

| Server | Hostname | Role |
|--------|----------|------|
| cpu1 | `lxcpu1` | Receiver — runs all tier receivers + GPU processing |
| cpu2 | `lxcpu2` | Sender — DPU ARM runs `send_ticks.py` |

**Cable connection**: cpu2 DPU port `p0` ↔ cpu1 DPU port `p0` (direct, no switch).

### 2.4 Network Addresses

| Address | What | Where |
|---------|------|-------|
| `10.10.10.2/24` | cpu1 host PF0 | Interface `ens21f0np0` on `lxcpu1` — receiver endpoint |
| `10.10.10.3/24` | cpu2 DPU ARM | Interface `p0` on cpu2's DPU ARM — sender endpoint |
| `239.0.0.1` | Multicast group | Virtual address; receivers join this group. NIC maps to Ethernet MAC `01:00:5e:00:00:01` |
| `5005` | UDP port | `TICK_MCAST_PORT` — identifies tick data traffic |
| `192.168.100.2` | DPU ARM management | Via `tmfifo_net0` (rshim) on each host — SSH access to local DPU ARM |
| `127.0.0.1` | Loopback | Harness (port 5010) and fill_simulator (port 5006) on cpu1 |

### 2.5 Network Interfaces

**cpu1 DPU ARM** (SSH via `192.168.100.2` from `lxcpu1`):

| Interface | Type | Description | IP Address |
|-----------|------|-------------|-----------|
| `p0` | Physical | Physical port 0 — cable to cpu2 | None (bridged) |
| `p1` | Physical | Physical port 1 — unused | None |
| `pf0hpf` | Representor | Internal pairing to host PF0 | None (bridged) |
| `pf1hpf` | Representor | Internal pairing to host PF1 | None |
| `ovsbr1` | OVS Bridge | Bridges `p0` and `pf0hpf` | None |

**cpu1 host** (`lxcpu1`):

| Interface | Type | PCIe Address | Description | IP Address |
|-----------|------|-------------|-------------|-----------|
| `ens21f0np0` | PF0 | `0000:bd:00.0` | Host PF0 — **data path** (cable side) | `10.10.10.2/24` |
| `ens21f1np1` | PF1 | `0000:bd:00.1` | Host PF1 — unused | None |

**cpu2 DPU ARM** (SSH via `192.168.100.2` from `lxcpu2`):

| Interface | Type | Description | IP Address |
|-----------|------|-------------|-----------|
| `p0` | Physical | Physical port 0 — cable to cpu1 | `10.10.10.3/24` |
| `pf0hpf` | Representor | Internal pairing to cpu2 host PF0 | None |
| `ovsbr1` | OVS Bridge | Bridges `p0` and `pf0hpf` | None |

### 2.6 PCIe Topology (cpu1)

```
Host PCIe Root Complex (lxcpu1)
├── 0000:ac:00.0  NVIDIA A2 GPU
│     └── GPU VRAM (16 GB, DMA target for NIC)
│
└── 0000:bd:00.x  BlueField-3 DPU (ConnectX-7 ASIC)
      ├── 0000:bd:00.0  PF0 — data path (ens21f0np0, mlx5_0)
      └── 0000:bd:00.1  PF1 — unused

DPU Internal Bus (separate from host PCIe)
├── ARM Cortex-A78 cores + DDR memory
└── ConnectX-7 ASIC (also on host PCIe, see above)
```

The ConnectX-7 ASIC bridges both buses. This is the only hardware component that can move data between the DPU-side network and the host-side GPU.

### 2.7 Physical Packet Path

All four tiers share the same physical path from sender to the NIC ASIC:

```
cpu2 DPU ARM                 cpu1 DPU ARM                    cpu1 Host
┌───────────┐                ┌────────────┐                  ┌──────────────┐
│send_ticks │                │            │                  │              │
│(10.10.10.3│──► p0 ═══cable═══► p0 ──►  │                  │              │
│  :5005)   │                │  ovsbr1    │                  │              │
└───────────┘                │  (bridge)  │                  │              │
                             │    │       │                  │              │
                             │  pf0hpf ───┼── eswitch ──►   │ PF0          │
                             │            │   pairing        │(ens21f0np0)  │
                             └────────────┘                  │(0000:bd:00.0)│
                                                             └──────┬───────┘
                                                                    │
                                                        ┌───────────┘
                                                        ▼
                                              Tier-specific receive path
                                                   (see below)
```

From PF0, each tier diverges:

**T1 — cpu_receiver (kernel socket)**:
```
PF0 → kernel network stack → recvfrom() → host RAM
    → cudaMemcpy H→D → GPU VRAM → process kernel
    → cudaMemcpy D→H → host RAM → sendto(harness/fillsim)
```

**T2 — dpdk_receiver (DPDK poll-mode)**:
```
PF0 → rte_flow steers UDP:5005 to DPDK queue (mlx5 bifurcated driver)
    → rte_eth_rx_burst → mbuf in host RAM
    → cudaMemcpy H→D → GPU VRAM → process kernel
    → cudaMemcpy D→H → host RAM → sendto(harness/fillsim)
```

**T3 — rdma_receiver (GPU RDMA, raw packet QP)**:
```
PF0 → ibv_create_flow steers UDP:5005 to RAW_PACKET QP
    → NIC DMA engine writes directly into GPU VRAM (nvidia-peermem)
    → extract_ticks_kernel parses ETH/IP/UDP headers on GPU
    → process kernel (already in GPU memory, NO cudaMemcpy H→D)
    → cudaMemcpy D→H → host RAM → sendto(harness/fillsim)
```

**T4 — gpu_receiver (DOCA GPUNetIO)**:
```
PF0 → DOCA Flow root CONTROL pipe → non-root BASIC pipe
    → RSS to GPU RX queue → NIC DMA into GPU VRAM
    → GPU kernel polls doca_gpu_dev_eth_rxq (already in GPU memory)
    → process kernel → CPU forwarder reads ring → sendto(harness/fillsim)
```

---

## 3. Software Architecture Overview

The system consists of six executable components that communicate over UDP:

```
┌──────────────┐   UDP 239.0.0.1:5005   ┌──────────────┐   GPU result ring   ┌──────────────┐
│              │   (multicast)           │              │   (pinned memory)   │  CPU Forward  │
│ data_source  │ ──────────────────────► │  Receiver    │ ◄─────────────────► │  Thread       │
│              │                         │  (T1-T5)     │                     │              │
└──────────────┘                         └──────────────┘                     └───────┬──────┘
                                                                                      │
                                                           ┌──────────────────────────┤
                                                           │                          │
                                              UDP :5010    │               UDP :5006  │
                                                           ▼                          ▼
                                                  ┌──────────────┐          ┌──────────────┐
                                                  │  Benchmark   │          │    Fill       │
                                                  │  Harness     │          │  Simulator    │
                                                  └──────────────┘          └──────────────┘
                                                           │
                                                           ▼
                                                  ┌──────────────┐
                                                  │  Dashboard   │
                                                  │  (Plotly)    │
                                                  └──────────────┘
```

### Component Summary

| Component | Binary | Language | Role |
|-----------|--------|----------|------|
| Data Source | `bin/data_source` | C++ | Generates or replays tick data, sends UDP multicast |
| T1 Receiver | `bin/cpu_receiver` | CUDA/C++ | Baseline: `recvfrom()` + `cudaMemcpy()` |
| T2 Receiver | `bin/dpdk_receiver` | CUDA/C++ | DPDK userspace poll-mode NIC driver |
| T3 Receiver | `bin/rdma_receiver` | CUDA/C++ | libibverbs + nv_peer_mem GPU RDMA |
| T4/T5 Receiver | `bin/gpu_receiver` | CUDA/C++ | DOCA GPUNetIO (same binary for both tiers) |
| Fill Simulator | `bin/fill_simulator` | C++ | Simulates order execution, tracks P&L |
| Benchmark Harness | `bin/benchmark_harness` | C++ | Orchestrates 75 benchmark runs, collects results |
| Dashboard | `src/dashboard/dashboard.py` | Python | Plotly visualization of benchmark results |
| Flow Test | `bin/doca_flow_test` | CUDA/C++ | Standalone DOCA Flow + GPUNetIO diagnostic |
| Tick Sender | `scripts/send_ticks.py` | Python | Lightweight tick sender for manual testing |
| DPU Relay | `bin/dpu_relay_dpu` | C++ | Bridges host unicast → DPU multicast for live feed |

---

## 4. Data Formats and Wire Protocols

All components communicate using fixed-size packed binary structs over UDP. There is no serialization library, no framing, no length prefix — each UDP datagram contains exactly one struct.

### 4.1 TickMessage (48 bytes)

Defined in `src/common/tick_message.h`. Sent as UDP multicast payload on `239.0.0.1:5005`.

```
Offset  Size  Type      Field           Description
──────  ────  ────      ─────           ───────────
 0      8     uint64_t  timestamp_ns    Wall-clock nanoseconds at sendto() [T1 timestamp]
 8      4     uint32_t  tick_id         Monotonic counter, unique per session
12      2     uint16_t  instrument_id   Hash of symbol string (0-255)
14      1     uint8_t   source          0 = replay, 1 = live
15      1     uint8_t   _pad            Reserved, zero
16      8     double    bid             Best bid price
24      8     double    ask             Best ask price
32      8     double    last_price      Last trade price
40      8     double    volume          Trade volume
```

`#pragma pack(push, 1)` ensures no padding between fields. A `static_assert` verifies the struct is exactly 48 bytes at compile time.

The `instrument_id` is computed by `symbol_to_id()`, a djb2 hash folded into the range `[0, MAX_INSTRUMENTS)` where `MAX_INSTRUMENTS = 256`.

### 4.2 BenchmarkResult (48 bytes)

Defined in `src/common/benchmark_result.h`. Sent via UDP unicast to the benchmark harness on port `5010`.

```
Offset  Size  Type      Field      Description
──────  ────  ────      ─────      ───────────
 0      8     uint64_t  tick_id    Matches TickMessage::tick_id
 8      8     uint64_t  t1_ns      Copied from TickMessage::timestamp_ns
16      8     uint64_t  t2_ns      Tick arrived in GPU memory (clock64, converted to ns)
24      8     uint64_t  t3_ns      GPU kernel finished processing (clock64, converted)
32      8     uint64_t  t4_ns      Signal written to result ring (clock64, converted)
40      1     uint8_t   tier       1-5
41      1     uint8_t   dropped    1 if packet was dropped
42      6     uint8_t[] _pad       Zero
```

**Timestamp stages**:
- **T1**: When the data source calls `sendto()`. Wall-clock `CLOCK_REALTIME` nanoseconds.
- **T2**: When the GPU kernel first reads the tick from the RX queue buffer. GPU `clock64()` cycles, converted to nanoseconds on the CPU using `ns_per_cyc = 1e6 / clock_khz`.
- **T3**: When the GPU kernel finishes computing EMA/RSI signals for this tick. Same conversion.
- **T4**: When the result is written to the GPU-to-CPU result ring. Same conversion.

Latency decomposition:
- **End-to-end latency**: T4 - T1
- **Ingestion latency** (network + DMA): T2 - T1
- **Compute latency** (GPU kernel): T3 - T2
- **Output latency** (ring write): T4 - T3

### 4.3 SignalResult (64 bytes)

Defined in `src/common/signal_result.h`. Sent via UDP unicast to the fill simulator on port `5006`.

```
Offset  Size  Type      Field           Description
──────  ────  ────      ─────           ───────────
 0      8     uint64_t  tick_id         Matches TickMessage::tick_id
 8      8     uint64_t  t3_ns           Kernel completion timestamp
16      8     uint64_t  t4_ns           Signal write timestamp
24      2     uint16_t  instrument_id   Instrument hash
26      1     int8_t    signal          Combined: +1 buy, -1 sell, 0 hold
27      1     int8_t    rsi_signal      RSI component: +1 oversold, -1 overbought
28      4     float     rsi             RSI value [0, 100]
32      8     double    mid_price       (bid + ask) / 2
40      8     double    spread          ask - bid
48      8     double    fast_ema        EMA with alpha = 0.05
56      8     double    slow_ema        EMA with alpha = 0.01
```

### 4.4 Communication Ports

| Port | Protocol | Transport | Sender | Receiver | Payload |
|------|----------|-----------|--------|----------|---------|
| 5005 | UDP multicast (`239.0.0.1`) | Ethernet | data_source / send_ticks.py | All receivers (T1-T5) | TickMessage (48 B) |
| 5006 | UDP unicast | Ethernet | All receivers (T1-T5) | fill_simulator | SignalResult (64 B) |
| 5010 | UDP unicast | Ethernet | All receivers (T1-T5) | benchmark_harness | BenchmarkResult (48 B) |

---

## 5. Component Specifications

### 5.1 Data Source (`bin/data_source`)

**Source**: `src/data_source/data_source.cpp`

Generates financial tick data and broadcasts it as TickMessage packets over UDP multicast.

**Operating Modes**:

| Mode | Description |
|------|-------------|
| `--mode replay` | Reads tick data from CSV file, sends at configurable rate with busy-wait timing |
| `--mode live` | Connects to Binance WebSocket (`stream.binance.com:9443`), bookTicker + aggTrade streams, converts JSON to TickMessage. Requires `libwebsockets`. |
| `--mode both` | Runs replay + live on separate threads at half rate each |

**Key Parameters**:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--rate` | 500000 | Ticks per second |
| `--csv` | `data/ticks.csv` | Source CSV for replay mode |
| `--iface` | `0.0.0.0` | NIC interface IP for multicast bind |
| `--loop` | off | Loop CSV data when end is reached |

**Timing**: Uses `clock_gettime(CLOCK_REALTIME)` for T1 timestamps. Rate control uses busy-wait on `clock_gettime(CLOCK_MONOTONIC)` for nanosecond-precision pacing.

**Cross-compilation for DPU ARM (T5)**:
```bash
make data_source_dpu    # Uses aarch64-linux-gnu-g++, static-linked
scp bin/data_source_dpu ubuntu@192.168.100.2:~/
```

**Live Mode Deployment with DPU Relay**:
When `--mode live` runs on the host, the DPU bridge's split-horizon rule prevents host-sourced multicast from looping back to host receivers. The solution is a lightweight UDP relay (`dpu_relay`) running on the DPU ARM:

```
Host: data_source --mode live --dest 192.168.100.2:6005
    ↓ (tmfifo_net0, unicast UDP)
DPU ARM: dpu_relay --listen-port 6005 --iface 10.10.10.1
    ↓ (p0 → bridge → host PF0, multicast UDP)
Host receivers: T1–T4 listening on 239.0.0.1:5005
```

The relay receives unicast UDP from the host management network and forwards to the working multicast path. This preserves the zero-copy architectures of T2–T4 while allowing the host (which has internet access) to connect to Binance WebSocket.

### 5.2 T1 CPU Receiver (`bin/cpu_receiver`)

**Source**: `src/receivers/cpu/cpu_receiver.cu`

Baseline receiver. The traditional approach with maximum CPU involvement.

**Data path**:
1. Join multicast group `239.0.0.1:5005` via `setsockopt(IP_ADD_MEMBERSHIP)`
2. `recvfrom()` — kernel copies packet from NIC RX queue (in kernel memory) to user-space buffer
3. Batch up to 256 ticks in a host-side array
4. `cudaMemcpy(HostToDevice)` — copy batch to GPU memory
5. Launch `process_ticks_kernel<<<ceil(n/256), 256>>>()` — one CUDA thread per tick
6. `cudaMemcpy(DeviceToHost)` — copy results back
7. `sendto()` — send BenchmarkResult to harness and SignalResult to fill simulator

Every packet is copied **three times**: kernel→userspace, userspace→GPU, GPU→userspace.

### 5.3 T2 DPDK Receiver (`bin/dpdk_receiver`)

**Source**: `src/receivers/dpdk/dpdk_receiver.cu`

Uses DPDK (Data Plane Development Kit) to bypass the Linux kernel's network stack entirely.

**Data path**:
1. DPDK initializes the NIC in poll mode — the NIC writes packets directly to userspace-mapped memory (hugepages)
2. Application polls the NIC's RX queue in a tight loop (no interrupts, no kernel)
3. `cudaMemcpy(HostToDevice)` — copy to GPU
4. Kernel launch + result copy back

Eliminates the kernel-to-userspace copy, but still requires `cudaMemcpy` to reach the GPU. Requires hugepage memory configuration and NIC driver unbinding.

### 5.4 T3 GPU RDMA Receiver (`bin/rdma_receiver`)

**Source**: `src/receivers/rdma/rdma_receiver.cu`

Uses InfiniBand Verbs (`libibverbs`) with NVIDIA GPUDirect RDMA (`nv_peer_mem`) to have the NIC DMA packets directly into GPU memory.

**Data path**:
1. Allocate GPU memory and register it as an RDMA memory region
2. Post receive work requests pointing to GPU memory
3. NIC DMAs incoming packets directly to GPU VRAM
4. Poll completion queue, launch kernel on received batch

Eliminates all CPU memory copies in the receive path. The CPU still manages work request posting and completion polling.

### 5.5 T4/T5 GPUNetIO Receiver (`bin/gpu_receiver`)

**Source**: `src/receivers/gpu/gpu_receiver.cu` (825 lines)

Uses DOCA GPUNetIO for fully hardware-steered NIC-to-GPU transfer with a persistent GPU kernel.

**Data path** (T4):
1. DOCA Flow hardware steering in the NIC ASIC classifies packets and DMAs them to a cyclic buffer in GPU VRAM
2. A persistent GPU kernel (running continuously) polls the RX queue for new packets
3. Each packet is parsed, processed (EMA/RSI), and results are written to a pinned-memory ring buffer
4. A CPU thread reads the ring buffer and sends results via UDP

The CPU is completely removed from the per-packet data path. It only reads processed results.

**T4 vs T5**: The binary is identical. The difference is deployment:
- T4: `data_source` runs on the host CPU, sends multicast over loopback or cross-PF
- T5: `data_source` runs on the DPU ARM cores, sends multicast through the physical network

**Command-line Parameters**:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--gpu-pcie` | (required) | GPU PCIe address (e.g., `0000:ac:00.0`) |
| `--nic-pcie` | (required) | NIC PF PCIe address (e.g., `0000:bd:00.1`) |
| `--gpu` | 1 | CUDA device index |
| `--tier` | 4 | Tier ID (affects BenchmarkResult::tier field) |
| `--harness` | `127.0.0.1` | Benchmark harness IP |
| `--fillsim` | `127.0.0.1` | Fill simulator IP |

**Internal Constants**:

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_PKT_PER_BURST` | 64 | CUDA threads per block, packets per receive burst |
| `MAX_PKT_NUM` | 2048 | RX queue cyclic buffer capacity (slots) |
| `MAX_PKT_SIZE` | 2048 | Maximum bytes per packet slot |
| `ETH_IP_UDP_HDR` | 42 | Bytes to skip to reach UDP payload (14 ETH + 20 IP + 8 UDP) |
| `RESULT_QUEUE_DEPTH` | 4096 | GPU-to-CPU result ring slots |
| `MAX_RX_TIMEOUT_NS` | 500,000 | RX poll timeout (0.5 ms) |
| `MAX_INSTRUMENTS` | 256 | Per-instrument state array size |

### 5.6 Fill Simulator (`bin/fill_simulator`)

**Source**: `src/fill_simulator/fill_simulator.cpp`

Simulates order execution for the trading signals produced by the GPU kernel.

**Behavior**:
1. Listens on UDP port 5006 for SignalResult packets
2. On `signal = +1` (buy): Opens a long position at `mid_price + commission`
3. On `signal = -1` (sell): Closes oldest open position (FIFO), computes realized P&L
4. On `signal = 0` (hold): No action
5. On shutdown: Writes trades CSV and prints summary (total P&L, win rate, max drawdown, Sharpe ratio)

**Parameters**:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--port` | 5006 | Listen port |
| `--commission` | 5 | Commission in basis points per side |
| `--output` | `results/fills.csv` | Output CSV path |

**Commission model**: 5 basis points = 0.05% of execution price per side. Applied as a fraction: buy price adjusted up, sell price adjusted down.

### 5.7 Benchmark Harness (`bin/benchmark_harness`)

**Source**: `src/benchmark_harness/benchmark_harness.cpp`

Orchestrates the full 75-run benchmark matrix.

**Benchmark Matrix**:
- **Tiers**: T1, T2, T3, T4, T5 (5 tiers)
- **Rates**: 10k, 50k, 100k, 250k, 500k ticks/sec (5 rates)
- **Repetitions**: 3 per combination
- **Total**: 5 * 5 * 3 = 75 runs

**Per-run procedure**:
1. Launch `data_source` in replay mode at the target rate
2. Launch the tier-specific receiver binary
3. Discard BenchmarkResult packets during 5-second warmup
4. Collect BenchmarkResult packets during 30-second measurement window
5. Kill both subprocesses
6. Compute latency percentiles (p50, p95, p99) and throughput
7. Write row to output CSV

**Output CSV columns**: `run_id, tier, rate_hz, repetition, n_ticks, drop_rate, e2e_p50, e2e_p95, e2e_p99, e2e_mean, ingest_p50, ingest_p95, ingest_p99, ingest_mean, compute_p50, compute_p95, compute_p99, compute_mean, throughput_per_sec`

### 5.8 Dashboard (`src/dashboard/dashboard.py`)

Reads `results/benchmark.csv` and generates interactive Plotly HTML charts:

| Chart | File | Content |
|-------|------|---------|
| Latency Percentiles | `latency_percentiles.html` | p50/p95/p99 E2E per tier |
| Throughput vs Latency | `throughput_latency.html` | Scatter plot per tier |
| Stage Breakdown | `stage_breakdown.html` | Ingestion / compute / total bars |
| Saturation Sweep | `saturation_sweep.html` | Latency vs rate (all tiers) |
| Speedup | `speedup.html` | Speedup factor vs T1 baseline |
| Comparison | `cpu_comparison.html` | Summary table |

**Color scheme**: T1 red, T2 orange, T3 yellow, T4 green, T5 blue.

### 5.9 Flow Test (`bin/doca_flow_test`)

**Source**: `tests/doca_flow_test.cu` (485 lines)

Standalone diagnostic that tests only the DOCA Flow + GPUNetIO packet reception path. No tick processing, no EMA/RSI, no result ring — just a GPU kernel that counts received packets, plus flow counter queries.

Used to isolate DOCA issues from application logic issues.

### 5.10 Tick Sender (`scripts/send_ticks.py`)

**Source**: `scripts/send_ticks.py` (195 lines)

Lightweight Python script for manual testing. Sends TickMessage packets matching the exact binary format. Supports generate mode (random-walk prices) and replay mode (from CSV).

### 5.11 DPU Relay (`bin/dpu_relay_dpu`)

**Source**: `src/dpu_relay/dpu_relay.cpp`

Lightweight UDP relay that bridges host-sourced unicast UDP to the DPU's working multicast path. Required for `--mode live` when the data source runs on the host (which has internet access) but receivers listen on the DPU-attached NIC.

**Problem**: The DPU bridge's split-horizon rule prevents host-sourced UDP multicast from looping back to host PF0/PF1. This is the same reason `send_ticks.py` must run on the DPU ARM (not the host) for cross-machine tests.

**Solution**: The relay runs on the DPU ARM, receives unicast UDP from the host via `tmfifo_net0` (management network, `192.168.100.x`), and forwards to multicast `239.0.0.1:5005` via `p0` (`10.10.10.1`). The multicast then traverses the working path (p0 → bridge → pf0hpf → eswitch → host PF0) to reach receivers.

**Data path**:
1. Host `data_source --mode live` sends UDP unicast to `192.168.100.2:6005`
2. DPU ARM `dpu_relay` receives on port `6005`
3. Relay forwards to multicast `239.0.0.1:5005` bound to `p0` (`10.10.10.1`)
4. Multicast traverses DPU bridge to host PF0
5. Host receivers (T1–T4) receive as usual

**Parameters**:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--listen-port` | `6005` | UDP port to listen on (host unicast destination) |
| `--mcast-addr` | `239.0.0.1` | Multicast destination address |
| `--mcast-port` | `5005` | Multicast destination port (`TICK_MCAST_PORT`) |
| `--iface` | `10.10.10.1` | Interface IP for multicast output (`p0` on DPU ARM) |

**Build**:
```bash
make dpu_relay        # Host binary (for local testing)
make dpu_relay_dpu    # Cross-compile for DPU ARM (aarch64)
```

**Deploy**:
```bash
scp bin/dpu_relay_dpu ubuntu@192.168.100.2:~/dpu_relay_dpu
ssh ubuntu@192.168.100.2 "./dpu_relay_dpu --listen-port 6005 --iface 10.10.10.1"
```

**Resource usage**: The relay is a simple `recvfrom`/`sendto` loop with no memory allocation after startup. CPU usage is negligible at tick rates below 1M/sec.

---

## 6. The Five Benchmark Tiers

### 6.1 Per-Packet Data Path Comparison

```
T1 (CPU Naive):
  NIC → kernel RX queue → recvfrom() → user buffer → cudaMemcpy → GPU → kernel
  Copies: 3 (kernel→user, user→GPU, GPU→user for results)
  CPU instructions per packet: ~thousands (syscall, memcpy, CUDA API)

T2 (DPDK):
  NIC → hugepage RX queue → poll → user buffer → cudaMemcpy → GPU → kernel
  Copies: 2 (NIC→hugepage is zero-copy from app perspective, still need cudaMemcpy)
  CPU instructions per packet: ~hundreds (poll loop, no syscall)

T3 (GPU RDMA):
  NIC → DMA → GPU memory → poll CQ → launch kernel
  Copies: 1 (NIC DMAs to GPU, CPU only manages work requests)
  CPU instructions per packet: ~tens (CQ poll, WR posting)

T4 (GPUNetIO):
  NIC ASIC → DOCA Flow → DMA → GPU memory → persistent kernel polls
  Copies: 0 CPU-side (NIC ASIC does everything)
  CPU instructions per packet: 0 (CPU only reads results)

T5 (GPUNetIO + DPU):
  Same as T4, but data_source runs on DPU ARM instead of host CPU
  Frees host CPU entirely — it only runs the GPU receiver
```

### 6.2 T4/T5 Detailed Data Flow

```
                    ┌──────────────────────────────────────────────────────────┐
                    │                  ConnectX-7 ASIC                        │
Packet arrives ───► │  eswitch ─► parser ─► flow table ─► DMA engine ────────│──► GPU VRAM
                    └──────────────────────────────────────────────────────────┘       │
                                                                                      │
                    ┌─────────────────────────────────────────────────────────────────┐
                    │                        GPU                                      │
                    │  Persistent kernel (1 block × 64 threads)                       │
                    │  ┌─────────────────────────────────────────────────────────┐    │
                    │  │  Thread 0: doca_gpu_dev_eth_rxq_recv<BLOCK_SCOPE>()    │    │
                    │  │           returns (first_pkt_idx, n_pkts)              │    │
                    │  │  __syncthreads()                                        │    │
                    │  │  All threads: parse packet[tid], compute EMA/RSI       │    │
                    │  │  All threads: write ResultSlot to ring                 │    │
                    │  │  __syncthreads()                                        │    │
                    │  │  Loop                                                   │    │
                    │  └─────────────────────────────────────────────────────────┘    │
                    │                            │                                    │
                    │                     Result Ring                                  │
                    │              (pinned host memory, GPU writes)                    │
                    └──────────────────────────┬──────────────────────────────────────┘
                                               │
                    ┌──────────────────────────┴──────────────────────────────────────┐
                    │                   Host CPU                                      │
                    │  CPU forward thread (polls ring every 10 μs)                    │
                    │  ├── Read ResultSlot from ring                                  │
                    │  ├── Convert GPU clock64 cycles → nanoseconds                   │
                    │  ├── sendto() BenchmarkResult → harness :5010                   │
                    │  └── sendto() SignalResult → fill_sim :5006                     │
                    └─────────────────────────────────────────────────────────────────┘
```

---

## 7. GPU Kernel Specification

### 7.1 Kernel Configuration

```cuda
gpu_recv_process_kernel<<<1, MAX_PKT_PER_BURST>>>(...)
```

- **Grid**: 1 block
- **Block**: 64 threads (`MAX_PKT_PER_BURST`)
- **Lifetime**: Persistent — runs from launch until `quit_flag` is set
- **Memory**: Uses shared memory for diagnostic counters

### 7.2 Receive Loop

The kernel runs an infinite loop. Each iteration:

1. **Thread 0** calls the block-scope receive function:
```cuda
doca_gpu_dev_eth_rxq_recv<
    DOCA_GPUNETIO_ETH_EXEC_SCOPE_BLOCK,
    DOCA_GPUNETIO_ETH_MCST_AUTO,
    DOCA_GPUNETIO_ETH_NIC_HANDLER_AUTO>(
        rxq, MAX_PKT_PER_BURST, MAX_RX_TIMEOUT_NS,
        &first_pkt_idx, &n_pkts, NULL);
```

Template parameters:
- `EXEC_SCOPE_BLOCK`: All threads in the block participate in the receive operation. Thread 0 drives it, others synchronize.
- `MCST_AUTO`: The NIC handles multicast group membership automatically.
- `NIC_HANDLER_AUTO`: The NIC handles error conditions automatically.

2. **`__syncthreads()`**: All threads wait for the receive to complete.

3. **Each thread** with `tid < n_pkts` processes one packet.

### 7.3 Packet Parsing

Each thread reads its packet from the cyclic buffer:

```cuda
uintptr_t buf_addr = doca_gpu_dev_eth_rxq_get_pkt_addr(rxq, first_pkt_idx + tid);
const uint8_t *pkt = reinterpret_cast<const uint8_t *>(buf_addr);
```

The raw packet contains Ethernet, IP, and UDP headers before the payload:

```
Byte 0-13:   Ethernet header (6 dst MAC + 6 src MAC + 2 EtherType)
Byte 14-33:  IPv4 header (20 bytes, no options)
Byte 34-41:  UDP header (2 src port + 2 dst port + 2 length + 2 checksum)
Byte 42-89:  TickMessage (48 bytes)
```

The kernel skips 42 bytes (`ETH_IP_UDP_HDR`) to reach the TickMessage payload. It also extracts the UDP destination port from bytes 36-37 to verify the packet is on port 5005.

### 7.4 Trading Signal Computation

**Dual EMA Crossover**:

An Exponential Moving Average (EMA) gives more weight to recent prices. Two EMAs with different smoothing factors (fast and slow) track price trends at different speeds. When the fast EMA crosses above the slow EMA, it signals upward momentum (buy). When it crosses below, it signals downward momentum (sell).

```
mid_price = (bid + ask) / 2
fast_ema = alpha_fast * mid + (1 - alpha_fast) * previous_fast_ema     [alpha_fast = 0.05]
slow_ema = alpha_slow * mid + (1 - alpha_slow) * previous_slow_ema     [alpha_slow = 0.01]

cross = (fast_ema - slow_ema) / slow_ema
if cross >  0.0003: ema_signal = +1 (buy)
if cross < -0.0003: ema_signal = -1 (sell)
else:               ema_signal =  0 (hold)
```

The threshold of 0.0003 (3 basis points) prevents noise from triggering false signals.

**RSI (Relative Strength Index)**:

RSI measures the magnitude of recent price changes to identify overbought or oversold conditions. It ranges from 0 to 100.

```
delta = mid - previous_mid
gain = max(delta, 0)
loss = max(-delta, 0)

avg_gain = rsi_alpha * gain + (1 - rsi_alpha) * previous_avg_gain    [rsi_alpha = 2/15]
avg_loss = rsi_alpha * loss + (1 - rsi_alpha) * previous_avg_loss

RS = avg_gain / avg_loss
RSI = 100 - 100 / (1 + RS)

if RSI < 30:  rsi_signal = +1 (oversold → buy)
if RSI > 70:  rsi_signal = -1 (overbought → sell)
else:         rsi_signal =  0 (hold)
```

The `rsi_alpha = 2/15` is equivalent to the standard 14-period Wilder smoothing.

**Combined Signal**:

```
if ema_signal != 0 AND ema_signal == rsi_signal:
    combined_signal = ema_signal     (both indicators agree)
else:
    combined_signal = 0              (hold — avoid false positives)
```

### 7.5 Atomic CAS Updates

Multiple GPU threads may process ticks for the same instrument simultaneously. The per-instrument EMA and RSI state arrays are updated using **Compare-And-Swap (CAS)** loops:

```cuda
__device__ static double ema_cas(double *slot, double sample, double alpha)
{
    unsigned long long *addr = reinterpret_cast<unsigned long long *>(slot);
    unsigned long long expected, desired;
    double old_val, new_val;
    do {
        expected = atomicAdd(addr, 0ULL);              // Read current value
        old_val  = __longlong_as_double((long long)expected);
        if (old_val == 0.0) old_val = sample;          // Initialize on first use
        new_val  = alpha * sample + (1.0 - alpha) * old_val;
        desired  = (unsigned long long)__double_as_longlong(new_val);
    } while (atomicCAS(addr, expected, desired) != expected);  // Retry if concurrent update
    return new_val;
}
```

This works by: reading the current value, computing the new value, then attempting to write it. If another thread modified the value between the read and write, `atomicCAS` returns the new current value (which doesn't match `expected`), and the loop retries with the updated value.

CUDA does not support atomic operations on `double` directly, so the values are reinterpreted as `unsigned long long` (both are 8 bytes) for the atomic operations.

### 7.6 Result Ring

The GPU kernel writes results to a lock-free single-producer-multiple-consumer ring buffer in **pinned host memory** (allocated with `cudaMallocHost`). Pinned memory is accessible by both GPU and CPU without explicit copies.

```
GPU writes:
    ring_idx = atomicAdd(ring_head, 1)
    result_ring[ring_idx % RESULT_QUEUE_DEPTH] = { BenchmarkResult, SignalResult }
    __threadfence()     // ensure write is visible to CPU

CPU reads:
    while (tail < *ring_head):
        read result_ring[tail % RESULT_QUEUE_DEPTH]
        tail++
```

The ring has 4096 slots. Each slot is a `ResultSlot` containing one `BenchmarkResult` (48 B) and one `SignalResult` (64 B) = 112 bytes per slot.

### 7.7 GPU Clock Conversion

The GPU's `clock64()` returns cycles of the SM (streaming multiprocessor) clock, not wall-clock nanoseconds. Conversion:

```c
int clock_khz;
cudaDeviceGetAttribute(&clock_khz, cudaDevAttrClockRate, cuda_device);
double ns_per_cyc = 1e6 / (double)clock_khz;

uint64_t wall_ns = (uint64_t)((double)gpu_cycles * ns_per_cyc);
```

This conversion is performed by the CPU forwarding thread before sending BenchmarkResult packets.

---

## 8. DOCA Initialization Specification

The `doca_init()` function in `gpu_receiver.cu` performs 15 sequential steps. Each step depends on the previous ones. All steps must return `DOCA_SUCCESS` or the application exits.

| Step | API Call | Purpose |
|------|---------|---------|
| 1 | `doca_gpu_create(gpu_pcie)` | Create GPU context from PCIe address |
| 1b | `doca_flow_cfg_create()` + `doca_flow_init()` + `doca_flow_port_start()` | Initialize flow steering subsystem. Mode: `"vnf,hws"` |
| 2 | `doca_eth_rxq_create(dev, 2048, 2048)` | Create RX queue: 2048 slots, 2048 bytes each |
| 3 | `doca_eth_rxq_set_type(CYCLIC)` | Set cyclic ring buffer mode |
| 4 | `doca_eth_rxq_estimate_packet_buf_size()` | Calculate buffer size (returns 4,194,304 bytes) |
| 5 | `doca_gpu_mem_alloc(4 MB)` | Allocate packet buffer in GPU VRAM |
| 6 | `doca_mmap_create()` + `doca_mmap_add_dev()` | Create memory map, associate with NIC |
| 7 | `doca_gpu_dmabuf_fd()` or `doca_mmap_set_memrange()` | Register GPU memory for DMA (dmabuf preferred, peermem fallback) |
| 8 | `doca_mmap_set_permissions()` + `doca_mmap_start()` | Set `LOCAL_READ_WRITE + PCI_RELAXED_ORDERING`, activate |
| 9 | `doca_eth_rxq_set_pkt_buf(mmap, 0, size)` | Bind GPU buffer to RX queue |
| 10 | `doca_eth_rxq_as_doca_ctx()` | Get generic context handle |
| 11 | `doca_ctx_set_datapath_on_gpu(gpu_dev)` | Tell DOCA the data path goes to the GPU |
| 12 | `doca_ctx_start()` | Activate the RX queue (programs DMA descriptors in ASIC) |
| 13 | `doca_eth_rxq_get_gpu_handle()` | Get GPU-side opaque handle (passed to GPU kernel) |
| 14 | `doca_eth_rxq_apply_queue_id(0)` | Assign queue ID 0 for flow steering |
| 15 | Create flow pipes | See Section 9 |

---

## 9. DOCA Flow Pipe Specification

DOCA Flow uses a two-pipe pattern to steer IPv4/UDP packets into the GPU RX queue. This pattern is required because root pipes in the hardware steering engine cannot match on `parser_meta` fields.

### 9.1 Pipe Architecture

```
Incoming packet on PF1 eswitch port
        │
        ▼
┌─────────────────────────────────────┐
│  ROOT CONTROL PIPE                  │
│  (is_root = true)                   │
│  (type = DOCA_FLOW_PIPE_CONTROL)    │
│                                     │
│  Entry (priority 1):               │
│    Match:                           │
│      outer.eth.type = 0x0800 (IPv4) │
│      outer.l3_type = IP4            │
│      outer.ip4.next_proto = 17(UDP) │
│    Action: forward to UDP pipe      │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  NON-ROOT BASIC PIPE                │
│  (is_root = false)                  │
│  (type = DOCA_FLOW_PIPE_BASIC)      │
│                                     │
│  Match:                             │
│    parser_meta.outer_l3_type = IPV4 │
│    parser_meta.outer_l4_type = UDP  │
│  Action: RSS to queue 0             │
│  Miss action: DROP                  │
│  Monitor: non-shared counter        │
└─────────────────────────────────────┘
```

### 9.2 Root CONTROL Pipe

The root pipe is the entry point of the flow pipeline. It is a CONTROL pipe, meaning each entry has its own independent match criteria and priority.

**Match fields** (per-entry, set via `doca_flow_pipe_control_add_entry`):
- `outer.eth.type = htons(0x0800)` — EtherType is IPv4. `htons()` converts to network byte order.
- `outer.l3_type = DOCA_FLOW_L3_TYPE_IP4` — Layer 3 type is IPv4
- `outer.ip4.next_proto = 17` — IP protocol number 17 is UDP

**Forward action**: `DOCA_FLOW_FWD_PIPE` → the non-root BASIC pipe

**Why CONTROL and not BASIC for root?** A root CONTROL pipe matches on raw outer packet headers, which the hardware can evaluate at the root level. A root BASIC pipe would need `parser_meta` fields for useful classification, but `parser_meta` is only available in non-root pipes.

### 9.3 Non-Root BASIC Pipe

The non-root pipe performs fine-grained classification using parsed metadata.

**Match fields** (template, set via `doca_flow_pipe_cfg_set_match`):
- `parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4`
- `parser_meta.outer_l4_type = DOCA_FLOW_L4_META_UDP`

**Forward action**: `DOCA_FLOW_FWD_RSS` with:
- `rss.queues_array = [0]` — single queue
- `rss.outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_UDP`
- `rss.nr_queues = 1`

**Miss action**: `DOCA_FLOW_FWD_DROP` — non-UDP packets are discarded.

**Monitor**: `DOCA_FLOW_RESOURCE_TYPE_NON_SHARED` counter. Queried every 5 seconds via `doca_flow_resource_query_entry()` for diagnostics.

### 9.4 Flow Mode: `"vnf,hws"`

- **`vnf`** (Virtual Network Function): The port operates in VNF mode, suitable for packet processing applications.
- **`hws`** (Hardware Steering): Flow rules are programmed into the NIC ASIC and evaluated in hardware at line rate.
- **`isolated` was removed**: In isolated mode, only DOCA Flow rules see packets. We removed it because packets arriving via the eswitch representor pairing were not reaching the flow rules in isolated mode.

---

## 10. DPU Network Configuration

### 10.1 Eswitch Mode

The DPU must be in **switchdev** mode. This is queried and set via:

```bash
# ON DPU ARM:
sudo devlink dev eswitch show pci/0000:03:00.0
# Expected: mode switchdev

# If in legacy mode, switch (requires reboot):
sudo devlink dev eswitch set pci/0000:03:00.0 mode switchdev
```

Switchdev mode is required because:
- It exposes representor interfaces (`pf0hpf`, `pf1hpf`)
- It enables programmable eswitch forwarding
- GPUNetIO's `doca_ctx_start()` fails in legacy mode

### 10.2 Bridge Configuration

**ON DPU ARM** (must be re-applied after every DPU reboot):

```bash
# Remove physical ports from any OVS bridges
sudo ovs-vsctl del-port ovsbr1 p0
sudo ovs-vsctl del-port ovsbr2 p1

# Create Linux bridge from p1 to host PF1
sudo ip link add br-pf1 type bridge
sudo ip link set p1 master br-pf1
sudo ip link set pf1hpf master br-pf1
sudo ip link set br-pf1 up
sudo ip link set p1 up
sudo ip link set pf1hpf up

# Disable IGMP snooping (required for UDP multicast forwarding)
sudo ip link set br-pf1 type bridge mcast_snooping 0
```

### 10.3 IP Configuration

**ON DPU ARM:**
```bash
sudo ip addr add 10.10.10.1/24 dev p0
sudo ip link set p0 up
# p1 must NOT have an IP address (avoid conflict with host PF1)
```

**ON HOST:**
```bash
sudo ip addr add 10.10.10.2/24 dev ens21f1np1
sudo ip link set ens21f1np1 up
```

---

## 11. Build System

### 11.1 Makefile

The project uses a traditional Makefile with dependency detection:

| Target | Binary | Dependencies | Description |
|--------|--------|-------------|-------------|
| `make data_source` | `bin/data_source` | g++ | Tick data generator (replay mode) |
| `make data_source_live` | `bin/data_source_live` | g++, libwebsockets | Tick data generator (with live Binance feed) |
| `make data_source_dpu` | `bin/data_source_dpu` | aarch64-linux-gnu-g++ | Cross-compiled for DPU ARM (T5) |
| `make t1` | `bin/cpu_receiver` | nvcc, CUDA | T1 CPU naive receiver |
| `make t2` | `bin/dpdk_receiver` | nvcc, CUDA, DPDK | T2 DPDK receiver |
| `make t3` | `bin/rdma_receiver` | nvcc, CUDA, libibverbs | T3 GPU RDMA receiver |
| `make t4` | `bin/gpu_receiver` | nvcc, CUDA, DOCA SDK | T4/T5 GPUNetIO receiver |
| `make fill_sim` | `bin/fill_simulator` | g++ | Fill simulator |
| `make harness` | `bin/benchmark_harness` | g++ | Benchmark orchestrator |
| `make test_flow` | `bin/doca_flow_test` | nvcc, CUDA, DOCA SDK | Standalone flow test |
| `make core` | All of: data_source, t1, fill_sim, harness | | Core pipeline (no special hardware) |
| `make all` | All targets | | Full build (skips missing deps) |

### 11.2 Compiler Settings

| Setting | Value |
|---------|-------|
| C++ standard | C++17 |
| Optimization | `-O3` |
| CUDA architecture | `sm_86` (NVIDIA A2) |
| DOCA SDK path | `/opt/mellanox/doca` |
| DOCA libraries | `-ldoca_gpunetio -ldoca_eth -ldoca_flow -ldoca_common -ldoca_argp` |
| CUDA libraries | `-lcuda -lcudart` |
| Required define | `-DALLOW_EXPERIMENTAL_API` (for DOCA GPUNetIO) |

### 11.3 Build Environment (HOST)

```bash
export PATH=/usr/local/cuda-12.8/bin:$PATH
export LD_LIBRARY_PATH=/opt/mellanox/doca/lib/x86_64-linux-gnu:/usr/local/cuda-12.8/lib64:$LD_LIBRARY_PATH
```

---

## 12. Benchmark Methodology

### 12.1 Measurement Points

Four timestamps are recorded for each tick:

```
T1: data_source calls sendto()     [wall-clock CLOCK_REALTIME]
    │
    │  network transit + DMA
    │
T2: GPU kernel reads tick           [GPU clock64()]
    │
    │  EMA + RSI computation
    │
T3: GPU kernel finishes processing  [GPU clock64()]
    │
    │  ring buffer write + threadfence
    │
T4: Result written to ring          [GPU clock64()]
```

### 12.2 Latency Metrics

| Metric | Formula | What It Measures |
|--------|---------|-----------------|
| End-to-end | T4 - T1 | Total time from send to result |
| Ingestion | T2 - T1 | Network + DMA transfer time |
| Compute | T3 - T2 | GPU processing time |
| Output | T4 - T3 | Result ring write time |

### 12.3 Statistical Aggregation

Per benchmark run, the harness computes:
- **p50** (median): 50th percentile latency
- **p95**: 95th percentile
- **p99**: 99th percentile
- **Mean**: Arithmetic mean
- **Standard deviation**
- **Throughput**: Ticks successfully processed per second
- **Drop rate**: Fraction of sent ticks not received

### 12.4 Benchmark Parameters

| Parameter | Value |
|-----------|-------|
| Warmup period | 5 seconds (results discarded) |
| Measurement window | 30 seconds |
| Repetitions per configuration | 3 |
| Tick rates tested | 10k, 25k, 50k, 100k, 200k, 500k, 1M ticks/sec |
| Data source mode | Replay (deterministic, repeatable) |

### 12.5 Cross-Machine Clock Limitation

The four timestamps span two machines: **T1 is captured on the DPU ARM** (`time.time_ns()` wall clock), while **T2/T3/T4 are captured on the host** (GPU `clock64()` cycles, anchored to host `CLOCK_REALTIME` at kernel start-up, see §7.7). This means that every latency metric which *crosses* the DPU↔host boundary — specifically **ingest (T2-T1)** and **end-to-end (T4-T1)** — is limited by the quality of DPU↔host clock alignment.

**Observed drift characteristics** (with no time-sync daemon on the DPU):

| Quantity | Typical Value |
|----------|---------------|
| Instantaneous DPU↔host wall-clock offset | seconds (DPU clock is unmaintained) |
| DPU clock rate error vs host | ~925 μs per second (~925 ppm) |
| Absolute offset drift over a 30 s run | ~28 ms accumulated |

**Correction stages applied by `benchmark.py`** (see the `collect()` method):

1. **NTP-style calibration** — four-timestamp UDP round-trip before the run measures the constant offset.
2. **Empirical p99 fallback** — the 99th percentile of `(T1 - T2)` across a stratified sample of the run approximates the "smallest real latency" baseline, which is a better estimator of pure clock skew than the NTP-style number when the DPU clock is unstable.
3. **Drift-aware linear fit** — an ordinary-least-squares line is fit through the per-bin p99 of `(T1 - T2)` vs `T2`. The resulting `(intercept, slope)` pair corrects each packet's T1 individually, removing the first-order drift component.

The correction source used for each run is recorded in `summary.json::clock_cal.offset_source` (one of `none`, `ntp`, `empirical_median`, `empirical_p99`, `drift_linear`).

**Residual error after correction.** Even with the drift_linear correction applied, residual non-linear clock error (thermal, scheduling jitter) produces an **ingest/e2e noise floor in the tens of ms** on a 30 s run. This is fundamental: sub-millisecond cross-machine latency measurement is not possible without PTP or chrony running on the DPU. The drift-corrected ingest/e2e figures should be read as **upper bounds**, not as point estimates of actual GPUNetIO ingest latency.

**Clock-independent metric — ingest jitter.** To measure GPUNetIO ingestion quality without crossing the machine boundary, the harness computes **inter-arrival jitter** using only host-side T2 timestamps:

```
For consecutive tick_ids N, N+1:
  observed_interval  = T2[N+1] − T2[N]          # host nanoseconds
  expected_interval  = 1e9 / rate_hz            # nanoseconds
  jitter[N]          = observed − expected      # signed nanoseconds
```

Because this uses only T2 (host clock), it is **completely immune to DPU↔host drift**. A well-behaved GPUNetIO path should produce |jitter| with p99 on the order of a few microseconds at moderate rates. Jitter is reported in `summary.json::ingest_jitter_us` and plotted as `plots/06_ingest_jitter.png`.

**Per-stage trustworthiness.**

| Metric | Trustworthy? | Why |
|--------|--------------|-----|
| Compute (T3-T2) | ✓ Yes | Both timestamps from the same GPU clock |
| Egress (T4-T3) | ✓ Yes | Both timestamps from the same GPU clock |
| Ingest jitter | ✓ Yes | Only uses host-side T2 |
| Throughput, drop rate | ✓ Yes | Counts, no clock |
| Ingest (T2-T1) | ⚠ Upper bound | Crosses DPU↔host, ~tens-of-ms floor |
| End-to-end (T4-T1) | ⚠ Upper bound | Crosses DPU↔host, ~tens-of-ms floor |

For the FYP report, the **trustworthy** metrics (compute latency, egress latency, jitter, throughput, drop rate) are the primary GPUNetIO performance claims. The cross-machine metrics are reported with the caveat above.

**Future work to remove the limitation.** Running `chronyd` (configured to discipline the DPU wall clock against an NTP server, or — better — against the host via the management network) before benchmarks would reduce the drift to microseconds and make the cross-machine metrics directly usable. PTP over the data path would push that to sub-microsecond. Neither is currently configured on the DPU.

---

## 13. Configuration Reference

### 13.1 Required System Configuration

| Item | Value | Where |
|------|-------|-------|
| Linux kernel | 6.11.0-17-generic | Host (6.17 breaks nvidia-peermem) |
| NVIDIA driver | 570.x | Host |
| CUDA toolkit | 12.8 | Host (`/usr/local/cuda-12.8/`) |
| DOCA SDK | 3.3 | Host (`/opt/mellanox/doca/`) |
| nvidia-peermem | loaded | Host (`sudo modprobe nvidia-peermem`) |
| Eswitch mode | switchdev | DPU |
| DPU mode | ECPF | DPU |
| IGMP snooping | disabled | DPU (`br-pf1` bridge) |

### 13.2 PCIe Addresses

| Device | Address | Used By |
|--------|---------|---------|
| NVIDIA A2 GPU | `0000:ac:00.0` | `--gpu-pcie` |
| BlueField-3 PF1 | `0000:bd:00.1` | `--nic-pcie` (data path) |
| BlueField-3 PF0 | `0000:bd:00.0` | Not used for data path |

### 13.3 IP Addresses

| Interface | Machine | IP | Purpose |
|-----------|---------|-----|---------|
| `p0` | DPU ARM | `10.10.10.1/24` | Send ticks (T5 data source) |
| `ens21f1np1` | Host | `10.10.10.2/24` | Receive ticks (DOCA Flow entry point) |
| `192.168.100.2` | DPU ARM | Management | SSH access to DPU ARM |

### 13.4 File Locations

| Item | Path | Machine |
|------|------|---------|
| CUDA 12.8 | `/usr/local/cuda-12.8/` | Host |
| DOCA SDK | `/opt/mellanox/doca/` | Host |
| DOCA headers | `/opt/mellanox/doca/include/` | Host |
| DOCA libraries | `/opt/mellanox/doca/lib/x86_64-linux-gnu/` | Host |
| Project repository | `~/DOCAGPUNetIO-application_LIX2_FYP_HKUST/` | Host |
| send_ticks.py | `~/send_ticks.py` | DPU ARM |
| dpu_relay_dpu | `~/dpu_relay_dpu` | DPU ARM |
| Benchmark results | `results/benchmark.csv` | Host |
| Dashboard plots | `results/plots/` | Host |

---

*This specification corresponds to the codebase as of April 2026. DOCA SDK 3.3, CUDA Toolkit 12.8, NVIDIA driver 570, kernel 6.11.0-17-generic.*
