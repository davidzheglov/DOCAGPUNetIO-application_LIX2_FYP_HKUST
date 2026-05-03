# ═══════════════════════════════════════════════════════════════════════════════
#  Five-Tier GPU Tick Pipeline — Top-Level Makefile
#  Target machine: Ubuntu 24, NVIDIA A2 (sm_86), BlueField-3 DPU
# ═══════════════════════════════════════════════════════════════════════════════
#
#  Core targets (no special hardware — usable on any CUDA-capable machine):
#    make core        — data_source + cpu_receiver + fill_simulator + harness
#    make data_source — T0: replay/live data generator
#    make t1          — T1: CPU naive receiver (recvfrom + cudaMemcpy)
#    make fill_sim    — Fill simulator (FIFO P&L tracker)
#    make harness     — Benchmark harness (75-run coordinator)
#
#  Hardware-dependent targets:
#    make t2          — T2: DPDK poll-mode receiver (needs DPDK)
#    make t3          — T3: GPU RDMA receiver (needs libibverbs + nv_peer_mem)
#    make t4          — T4/T5: GPUNetIO receiver (needs DOCA SDK)
#
#  Convenience:
#    make all         — core + t2 + t3 + t4 (fails fast on missing deps)
#    make bench       — run quick benchmark after building core
#    make clean       — remove bin/
#
#  Build variables (override on command line):
#    CUDA_ARCH=86     GPU compute capability (default: 86 for NVIDIA A2)
#    DOCA_ROOT=/opt/mellanox/doca   (default)
#    DPDK_ROOT=/usr/local           (default)
# ═══════════════════════════════════════════════════════════════════════════════

NVCC      := nvcc
CXX       := g++
CXXFLAGS  := -O3 -std=c++17 -Wall -Wextra -pthread
NVCCFLAGS := -O3 -std=c++17 -Xcompiler -Wall

CUDA_ARCH ?= 86
ARCH_FLAG := -arch=sm_$(CUDA_ARCH)

COMMON    := src/common
BINDIR    := bin
MAKEFILE_DEPS := Makefile

# WebSocket support for --mode live (requires libwebsockets)
WS_LIBS   := -lwebsockets -lssl -lcrypto -lpthread
WS_FLAGS  := -DENABLE_LIVE_FEED

# DOCA SDK
DOCA_ROOT ?= /opt/mellanox/doca
DOCA_INC  := -I$(DOCA_ROOT)/include
DOCA_LIBS := -L$(DOCA_ROOT)/lib/x86_64-linux-gnu \
             -ldoca_gpunetio -ldoca_eth -ldoca_flow \
             -ldoca_common -ldoca_argp -lcuda -lcudart

# DPDK (via pkg-config) — strip -Wl,... flags that nvcc can't handle
DPDK_CFLAGS  := $(shell pkg-config --cflags libdpdk 2>/dev/null)
DPDK_LIBS    := $(filter-out -Wl%,$(shell pkg-config --libs libdpdk 2>/dev/null))

# ibverbs for T3 GPU RDMA
RDMA_LIBS := -libverbs

# ── Common headers (all targets depend on these) ───────────────────────────
COMMON_HDRS := $(COMMON)/tick_message.h     \
               $(COMMON)/signal_result.h    \
               $(COMMON)/benchmark_result.h \
               $(COMMON)/benchmark.h        \
               $(COMMON)/pnl_tracker.h

$(BINDIR):
	mkdir -p $(BINDIR)

# ═══════════════════════════════════════════════════════════════════════════════
#  T0: Data source
# ═══════════════════════════════════════════════════════════════════════════════

DATA_SRC  := src/data_source/data_source.cpp
DATA_BIN  := $(BINDIR)/data_source
DATA_LIVE := $(BINDIR)/data_source_live

data_source: $(DATA_BIN)

$(DATA_BIN): $(DATA_SRC) $(COMMON_HDRS) $(MAKEFILE_DEPS) | $(BINDIR)
	$(CXX) $(CXXFLAGS) -I$(COMMON) $< -o $@
	@echo "  [OK] $@"

data_source_live: $(DATA_LIVE)

$(DATA_LIVE): $(DATA_SRC) $(COMMON_HDRS) $(MAKEFILE_DEPS) | $(BINDIR)
	$(CXX) $(CXXFLAGS) $(WS_FLAGS) -I$(COMMON) $< -o $@ $(WS_LIBS)
	@echo "  [OK] $@  (with Binance WebSocket)"

# ═══════════════════════════════════════════════════════════════════════════════
#  DPU Relay (bridges host unicast -> DPU multicast for live feed)
# ═══════════════════════════════════════════════════════════════════════════════

DPU_RELAY_SRC := src/dpu_relay/dpu_relay.cpp
DPU_RELAY_BIN := $(BINDIR)/dpu_relay

dpu_relay: $(DPU_RELAY_BIN)

$(DPU_RELAY_BIN): $(DPU_RELAY_SRC) $(MAKEFILE_DEPS) | $(BINDIR)
	$(CXX) $(CXXFLAGS) $< -o $@
	@echo "  [OK] $@"

# ═══════════════════════════════════════════════════════════════════════════════
#  T1: CPU naive receiver
# ═══════════════════════════════════════════════════════════════════════════════

T1_SRC := src/receivers/cpu/cpu_receiver.cu
T1_BIN := $(BINDIR)/cpu_receiver

t1: $(T1_BIN)

$(T1_BIN): $(T1_SRC) $(COMMON_HDRS) $(COMMON)/process_kernel.cuh $(MAKEFILE_DEPS) | $(BINDIR)
	$(NVCC) $(NVCCFLAGS) $(ARCH_FLAG) -I$(COMMON) $< -o $@
	@echo "  [OK] $@"

# ═══════════════════════════════════════════════════════════════════════════════
#  T2: DPDK poll-mode receiver
# ═══════════════════════════════════════════════════════════════════════════════

T2_SRC := src/receivers/dpdk/dpdk_receiver.cu
T2_BIN := $(BINDIR)/dpdk_receiver

t2: $(T2_BIN)

$(T2_BIN): $(T2_SRC) $(COMMON_HDRS) $(COMMON)/process_kernel.cuh $(MAKEFILE_DEPS) | $(BINDIR)
	@if [ -z "$(DPDK_LIBS)" ]; then \
		echo "  [FAIL] T2: libdpdk not found (run: apt install dpdk-dev)"; \
		exit 1; \
	else \
		$(NVCC) $(NVCCFLAGS) $(ARCH_FLAG) -I$(COMMON) \
		    -Xcompiler "$(DPDK_CFLAGS)" \
		    $< -o $@ $(DPDK_LIBS) \
		&& echo "  [OK] $@" \
		|| { echo "  [FAIL] T2: compile/link failed"; exit 1; }; \
	fi

# ═══════════════════════════════════════════════════════════════════════════════
#  T3: GPU RDMA receiver (libibverbs + nv_peer_mem)
# ═══════════════════════════════════════════════════════════════════════════════

T3_SRC := src/receivers/rdma/rdma_receiver.cu
T3_BIN := $(BINDIR)/rdma_receiver

t3: $(T3_BIN)

$(T3_BIN): $(T3_SRC) $(COMMON_HDRS) $(COMMON)/process_kernel.cuh $(MAKEFILE_DEPS) | $(BINDIR)
	@if ! pkg-config --exists libibverbs 2>/dev/null && \
	    ! [ -f /usr/include/infiniband/verbs.h ]; then \
		echo "  [FAIL] T3: libibverbs not found (run: apt install libibverbs-dev)"; \
		exit 1; \
	else \
		$(NVCC) $(NVCCFLAGS) $(ARCH_FLAG) -I$(COMMON) \
		    $< -o $@ $(RDMA_LIBS) \
		&& echo "  [OK] $@" \
		|| { echo "  [FAIL] T3: compile/link failed"; exit 1; }; \
	fi

# ═══════════════════════════════════════════════════════════════════════════════
#  T4/T5: GPUNetIO receiver (DOCA SDK required)
# ═══════════════════════════════════════════════════════════════════════════════

T4_SRC := src/receivers/gpu/gpu_receiver.cu
T4_BIN := $(BINDIR)/gpu_receiver

t4: $(T4_BIN)

$(T4_BIN): $(T4_SRC) $(COMMON_HDRS) $(MAKEFILE_DEPS) | $(BINDIR)
	@if [ ! -d "$(DOCA_ROOT)/include" ]; then \
		echo "  [FAIL] T4/T5: DOCA SDK not found at $(DOCA_ROOT)"; \
		echo "         Install DOCA SDK or set DOCA_ROOT=/path/to/doca"; \
		exit 1; \
	else \
		$(NVCC) $(NVCCFLAGS) $(ARCH_FLAG) -I$(COMMON) $(DOCA_INC) \
		    -DALLOW_EXPERIMENTAL_API \
		    $< -o $@ $(DOCA_LIBS) \
		&& echo "  [OK] $@  (T4 + T5 share this binary)" \
		|| { echo "  [FAIL] T4/T5: compile/link failed"; exit 1; }; \
	fi

# ═══════════════════════════════════════════════════════════════════════════════
#  Fill simulator
# ═══════════════════════════════════════════════════════════════════════════════

FILL_SRC := src/fill_simulator/fill_simulator.cpp
FILL_BIN := $(BINDIR)/fill_simulator

fill_sim: $(FILL_BIN)

$(FILL_BIN): $(FILL_SRC) $(COMMON_HDRS) $(MAKEFILE_DEPS) | $(BINDIR)
	$(CXX) $(CXXFLAGS) -I$(COMMON) $< -o $@
	@echo "  [OK] $@"

# ═══════════════════════════════════════════════════════════════════════════════
#  Benchmark harness
# ═══════════════════════════════════════════════════════════════════════════════

HARNESS_SRC := src/benchmark_harness/benchmark_harness.cpp
HARNESS_BIN := $(BINDIR)/benchmark_harness

harness: $(HARNESS_BIN)

$(HARNESS_BIN): $(HARNESS_SRC) $(COMMON_HDRS) $(MAKEFILE_DEPS) | $(BINDIR)
	$(CXX) $(CXXFLAGS) -I$(COMMON) $< -o $@
	@echo "  [OK] $@"

# ═══════════════════════════════════════════════════════════════════════════════
#  Aggregate targets
# ═══════════════════════════════════════════════════════════════════════════════

core: data_source t1 fill_sim harness
	@echo ""
	@echo "  Core pipeline built.  Binaries in $(BINDIR)/"
	@echo "  Run: make bench  to validate end-to-end"

all: core t2 t3 t4
	@echo ""
	@echo "  Full build complete."

# ── Full T1-T4 benchmark sweep + plots ────────────────────────────────────
benchmark: all
	@bash scripts/run_benchmark.sh $(BENCHMARK_ARGS)
	@python3 scripts/plot_benchmark.py --latest

benchmark-quick: all
	@bash scripts/run_benchmark.sh --quick $(BENCHMARK_ARGS)
	@python3 scripts/plot_benchmark.py --latest

# Usage: make plots                    # uses latest results/benchmark.csv
#        make plots FILE=bm.csv        # uses specified file
plots:
	@if [ -n "$(FILE)" ]; then \
		python3 scripts/plot_scripts/plot_benchmark.py $(FILE) && \
		python3 scripts/plot_scripts/scatter_stages.py $(FILE) && \
		python3 scripts/plot_scripts/plot_stages.py $(FILE); \
	else \
		python3 scripts/plot_scripts/plot_benchmark.py --latest && \
		python3 scripts/plot_scripts/scatter_stages.py --latest && \
		python3 scripts/plot_scripts/plot_stages.py --latest; \
	fi

# ── Dashboard ─────────────────────────────────────────────────────────────
dashboard:
	@python3 src/dashboard/dashboard.py --results results/benchmark.csv

# ── Sync to DPU (T5: cross-compiled data_source_dpu) ──────────────────────
# Cross-compilation target for the BlueField-3 ARM cores.
# Requires: apt install g++-aarch64-linux-gnu
DPU_CXX   := aarch64-linux-gnu-g++
DPU_FLAGS := -O3 -std=c++17 -static-libstdc++
DPU_BIN   := $(BINDIR)/data_source_dpu

data_source_dpu: $(DATA_SRC) $(COMMON_HDRS) $(MAKEFILE_DEPS) | $(BINDIR)
	$(DPU_CXX) $(DPU_FLAGS) $(WS_FLAGS) -I$(COMMON) $< -o $(DPU_BIN) $(WS_LIBS)
	@echo "  [OK] $(DPU_BIN)  (aarch64 — deploy to DPU with scp)"

DPU_RELAY_DPU_BIN := $(BINDIR)/dpu_relay_dpu

dpu_relay_dpu: $(DPU_RELAY_SRC) $(MAKEFILE_DEPS) | $(BINDIR)
	$(DPU_CXX) $(DPU_FLAGS) $< -o $(DPU_RELAY_DPU_BIN)
	@echo "  [OK] $(DPU_RELAY_DPU_BIN)  (aarch64 — deploy to DPU with scp)"

# ═══════════════════════════════════════════════════════════════════════════════
#  Test: DOCA Flow + GPUNetIO minimal receiver test
# ═══════════════════════════════════════════════════════════════════════════════

TEST_FLOW_SRC := tests/doca_flow_test.cu
TEST_FLOW_BIN := $(BINDIR)/doca_flow_test

test_flow: $(TEST_FLOW_BIN)

$(TEST_FLOW_BIN): $(TEST_FLOW_SRC) $(MAKEFILE_DEPS) | $(BINDIR)
	@if [ ! -d "$(DOCA_ROOT)/include" ]; then \
		echo "  [FAIL] test_flow: DOCA SDK not found at $(DOCA_ROOT)"; \
		exit 1; \
	else \
		$(NVCC) $(NVCCFLAGS) $(ARCH_FLAG) $(DOCA_INC) \
		    -DALLOW_EXPERIMENTAL_API \
		    $< -o $@ $(DOCA_LIBS) \
		&& echo "  [OK] $@" \
		|| { echo "  [FAIL] test_flow: compile/link failed"; exit 1; }; \
	fi

# ── Clean ──────────────────────────────────────────────────────────────────
clean:
	rm -rf $(BINDIR)/

.PHONY: all core benchmark benchmark-quick plots clean dashboard
.PHONY: data_source data_source_live data_source_dpu
.PHONY: dpu_relay dpu_relay_dpu
.PHONY: t1 t2 t3 t4 fill_sim harness
