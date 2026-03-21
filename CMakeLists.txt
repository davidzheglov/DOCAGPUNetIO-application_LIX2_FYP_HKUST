cmake_minimum_required(VERSION 3.20)

project(gpu_tick_pipeline
    VERSION 1.0
    LANGUAGES C CXX CUDA
)

# ── Standards ────────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

# ── Output directories ────────────────────────────────────────────────────────
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ── Find CUDA ─────────────────────────────────────────────────────────────────
find_package(CUDAToolkit REQUIRED)

# GPU architecture: BlueField-3 host GPU — adjust for your actual GPU
# e.g. 80 = A100, 86 = RTX 3xxx, 89 = RTX 4xxx, 90 = H100
if(NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
    set(CMAKE_CUDA_ARCHITECTURES 80)
endif()

# ── Threads ───────────────────────────────────────────────────────────────────
find_package(Threads REQUIRED)

# ── Optional dependencies (each tier can be built independently) ──────────────
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# DPDK (T2)
find_package(DPDK QUIET)
if(DPDK_FOUND)
    message(STATUS "DPDK found — T2 (dpdk_receiver) will be built")
else()
    message(STATUS "DPDK not found — T2 (dpdk_receiver) skipped")
endif()

# libibverbs + rdma-core (T3)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(IBVERBS QUIET libibverbs)
    pkg_check_modules(RDMACM  QUIET librdmacm)
endif()
if(IBVERBS_FOUND AND RDMACM_FOUND)
    message(STATUS "libibverbs found — T3 (rdma_receiver) will be built")
else()
    message(STATUS "libibverbs not found — T3 (rdma_receiver) skipped")
endif()

# DOCA (T4/T5)
find_package(DOCA QUIET)
if(DOCA_FOUND)
    message(STATUS "DOCA found — T4/T5 (gpu_receiver) will be built")
else()
    message(STATUS "DOCA not found — T4/T5 (gpu_receiver) skipped")
endif()

# libwebsockets (live Binance bridge in data_source)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(LIBWEBSOCKETS QUIET libwebsockets)
endif()
if(NOT LIBWEBSOCKETS_FOUND)
    # Try cmake find
    find_package(libwebsockets QUIET)
    if(libwebsockets_FOUND)
        set(LIBWEBSOCKETS_FOUND TRUE)
        set(LIBWEBSOCKETS_LIBRARIES websockets)
        set(LIBWEBSOCKETS_INCLUDE_DIRS "")
    endif()
endif()
if(LIBWEBSOCKETS_FOUND)
    message(STATUS "libwebsockets found — live Binance bridge enabled")
else()
    message(STATUS "libwebsockets not found — live bridge disabled (replay only)")
endif()

# ── Common include path ───────────────────────────────────────────────────────
set(COMMON_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/src/common)

# ── Subdirectories ────────────────────────────────────────────────────────────
add_subdirectory(src/data_source)
add_subdirectory(src/receivers/cpu)

if(DPDK_FOUND)
    add_subdirectory(src/receivers/dpdk)
endif()

if(IBVERBS_FOUND AND RDMACM_FOUND)
    add_subdirectory(src/receivers/rdma)
endif()

if(DOCA_FOUND)
    add_subdirectory(src/receivers/gpu)
endif()

add_subdirectory(src/fill_simulator)
add_subdirectory(src/benchmark_harness)

# ── Install targets ────────────────────────────────────────────────────────────
install(DIRECTORY src/common/ DESTINATION include/tick_pipeline)

# ── Summary ───────────────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "=== gpu_tick_pipeline build summary ===")
message(STATUS "  CUDA architectures : ${CMAKE_CUDA_ARCHITECTURES}")
message(STATUS "  T1 cpu_receiver    : YES (always)")
message(STATUS "  T2 dpdk_receiver   : ${DPDK_FOUND}")
message(STATUS "  T3 rdma_receiver   : ${IBVERBS_FOUND}")
message(STATUS "  T4/T5 gpu_receiver : ${DOCA_FOUND}")
message(STATUS "  Live Binance feed  : ${LIBWEBSOCKETS_FOUND}")
message(STATUS "========================================")
message(STATUS "")
