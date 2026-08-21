import type { RunSummary } from "./types";

export const demoRuns: RunSummary[] = [
  {
    tier: 1,
    rate_hz: 50000,
    achieved_hz: 49200,
    drop_rate: 0.012,
    compute_p99_us: 71.2,
    egress_p99_us: 11.4,
    e2e_p99_us: 440.2,
    ingest_p99_us: 352.8,
    jitter_abs_p99_us: 42.4,
    timestamp: new Date().toISOString(),
  },
  {
    tier: 2,
    rate_hz: 50000,
    achieved_hz: 49780,
    drop_rate: 0.004,
    compute_p99_us: 30.6,
    egress_p99_us: 8.4,
    e2e_p99_us: 210.4,
    ingest_p99_us: 171.4,
    jitter_abs_p99_us: 18.7,
    timestamp: new Date().toISOString(),
  },
  {
    tier: 3,
    rate_hz: 50000,
    achieved_hz: 49910,
    drop_rate: 0.002,
    compute_p99_us: 16.4,
    egress_p99_us: 5.2,
    e2e_p99_us: 96.8,
    ingest_p99_us: 75.2,
    jitter_abs_p99_us: 8.6,
    timestamp: new Date().toISOString(),
  },
  {
    tier: 4,
    rate_hz: 50000,
    achieved_hz: 49960,
    drop_rate: 0.001,
    compute_p99_us: 8.7,
    egress_p99_us: 3.6,
    e2e_p99_us: 53.8,
    ingest_p99_us: 41.5,
    jitter_abs_p99_us: 4.8,
    timestamp: new Date().toISOString(),
  },
];

export const tierCopy = {
  1: {
    name: "T1 CPU naive",
    path: "Kernel socket -> user buffer -> cudaMemcpy -> GPU kernel",
    signal: "Baseline path with every CPU-side copy visible.",
  },
  2: {
    name: "T2 DPDK",
    path: "Poll-mode NIC -> hugepage mbuf -> cudaMemcpy -> GPU kernel",
    signal: "Kernel bypass, but the CPU still moves packets toward VRAM.",
  },
  3: {
    name: "T3 GPU RDMA",
    path: "RAW_PACKET QP -> NIC DMA -> GPU memory -> CUDA parse",
    signal: "GPU memory becomes the packet landing zone.",
  },
  4: {
    name: "T4 GPUNetIO",
    path: "DOCA Flow -> GPU RX queue -> persistent CUDA kernel",
    signal: "The hot path is NIC hardware and GPU work, not CPU copies.",
  },
} as const;
