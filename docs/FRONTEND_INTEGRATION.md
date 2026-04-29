# Frontend Integration Plan

This document is the handoff note for the planned live-demo frontend.

The goal is not to reimplement the pipeline in the UI. The goal is to make the
existing backend pipeline easy to start, observe, and stop from a frontend
running on the host machine.

## Goal

The frontend branch should be able to drive the full live-demo pipeline:

1. start the required backend processes
2. select a tier (`T1`–`T4` for host demo, `T5` later if needed)
3. select one or more symbols for live Binance mode
4. display live signals / throughput / health
5. stop the entire pipeline cleanly

## Recommended Demo Scope

For the first frontend milestone, target the **live demo path**, not the full
benchmark sweep path.

Recommended first supported mode:

- `data_source_live` on the host
- `dpu_relay` on the DPU ARM
- one selected receiver tier on `lxcpu1`
- local `fill_simulator`
- optional lightweight metrics/visualisation process

This is simpler and more demo-friendly than exposing the full benchmark harness
first.

## Current Backend Pieces

These binaries/scripts already exist and should be treated as the backend
building blocks:

- `bin/data_source_live`
- `bin/dpu_relay_dpu`
- `bin/cpu_receiver`
- `bin/dpdk_receiver`
- `bin/rdma_receiver`
- `bin/gpu_receiver`
- `bin/fill_simulator`
- `scripts/run_live_pipeline.sh`
- `scripts/run_benchmark.sh`

## Suggested Frontend Control Model

The frontend branch should call a small backend control layer rather than shell
out directly from UI components.

Recommended layering:

1. frontend UI
2. local control server / wrapper on `lxcpu1`
3. existing scripts/binaries

The control server can be very small. It only needs endpoints/actions like:

- `start_pipeline`
- `stop_pipeline`
- `pipeline_status`
- `tail_logs`
- `start_benchmark` (optional later)
- `stop_benchmark` (optional later)

## Minimum Inputs For Live Demo

The frontend should allow the operator to choose:

- tier: `1`, `2`, `3`, or `4`
- symbols: for example `BTCUSDT,ETHUSDT`
- receiver interface for `T1`: currently `ens21f0np0`
- DPU relay destination: currently `192.168.100.2:6005`

For the first pass, these hardware-specific values can be defaults instead of
editable form fields.

## Recommended Process Contract

The frontend branch should treat these as the process-level contracts.

### Live data source

Runs on host:

```bash
bin/data_source_live --mode live --symbols BTCUSDT,ETHUSDT --dest 192.168.100.2:6005
```

### DPU relay

Runs on DPU ARM:

```bash
./dpu_relay_dpu --listen-port 6005 --iface 10.10.10.1
```

### Tier receivers

`T1`:

```bash
sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
    bin/cpu_receiver --tier 1 --iface ens21f0np0 \
    --harness 127.0.0.1 --fillsim 127.0.0.1
```

`T2`:

```bash
sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
    bin/dpdk_receiver -a 0000:bd:00.0 -l 0-1 -n 4 -- \
    --port 0 --tier 2 --harness 127.0.0.1 --fillsim 127.0.0.1
```

`T3`:

```bash
sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
    bin/rdma_receiver --dev mlx5_0 --tier 3 \
    --harness 127.0.0.1 --fillsim 127.0.0.1
```

`T4`:

```bash
sudo -E env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
    bin/gpu_receiver --tier 4 --gpu 1 \
    --gpu-pcie 0000:ac:00.0 --nic-pcie 0000:bd:00.0 \
    --harness 127.0.0.1 --fillsim 127.0.0.1
```

## What The Frontend Should Display

Recommended live-demo panels:

- pipeline status
  - relay running / stopped
  - selected receiver running / stopped
  - live source connected / stopped
- current tier
- subscribed symbols
- recent signals
- recent throughput
- recent error/warning logs

Nice-to-have later:

- benchmark results browser
- tier comparison plots
- latency histograms

## Important Current Limitations

The frontend should reflect the system as it exists today:

- benchmark timestamping is still tier-specific at `t1`
- high-rate benchmark results are still under investigation
- `T4 --nic-t1` is experimental and should not be the default frontend mode
- the live demo path is stronger than the high-rate benchmark path right now

## Recommended Backend Work Split

For the `frontend` branch, the teammate can assume:

- this branch remains the source of truth for receivers, relay, benchmark, and
  pipeline scripts
- the frontend branch owns:
  - UI layout
  - start/stop controls
  - status/log presentation
  - any small wrapper service needed to invoke backend commands safely

## Suggested First Deliverable

A good first frontend milestone is:

1. choose tier `T1` or `T4`
2. start the live pipeline
3. show that the receiver is running
4. show logs / signals updating live
5. stop everything cleanly

Once that works, the same control layer can be extended to the other tiers and
later to benchmark orchestration.
