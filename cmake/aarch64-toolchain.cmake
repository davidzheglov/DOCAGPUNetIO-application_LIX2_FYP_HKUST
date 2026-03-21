# aarch64-toolchain.cmake — cross-compile for BlueField-3 DPU ARM cores.
#
# Usage:
#   cmake -B build-dpu \
#         -DCMAKE_TOOLCHAIN_FILE=cmake/aarch64-toolchain.cmake \
#         -DBUILD_DPU_TARGETS_ONLY=ON
#   cmake --build build-dpu --target data_source
#
# Install cross toolchain on Ubuntu host:
#   sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

set(CMAKE_SYSTEM_NAME      Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# Toolchain executables — override with environment if needed
set(CROSS_PREFIX "aarch64-linux-gnu-"
    CACHE STRING "Cross-compiler prefix")

find_program(CMAKE_C_COMPILER   ${CROSS_PREFIX}gcc   REQUIRED)
find_program(CMAKE_CXX_COMPILER ${CROSS_PREFIX}g++   REQUIRED)
find_program(CMAKE_AR           ${CROSS_PREFIX}ar    REQUIRED)
find_program(CMAKE_STRIP        ${CROSS_PREFIX}strip REQUIRED)

# Sysroot (optional — set if you have a BlueField rootfs locally)
if(DEFINED AARCH64_SYSROOT)
    set(CMAKE_SYSROOT ${AARCH64_SYSROOT})
    set(CMAKE_FIND_ROOT_PATH ${AARCH64_SYSROOT})
endif()

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# No CUDA for DPU ARM target
set(CMAKE_CUDA_COMPILER "" CACHE STRING "" FORCE)

# DPU-only build: only build data_source (the Binance live bridge)
set(BUILD_DPU_TARGETS_ONLY ON CACHE BOOL "Only build targets that run on DPU")

# ARM-specific flags
set(CMAKE_C_FLAGS_INIT   "-march=armv8.2-a+crypto -mtune=cortex-a78")
set(CMAKE_CXX_FLAGS_INIT "-march=armv8.2-a+crypto -mtune=cortex-a78")

message(STATUS "Cross-compiling for BlueField-3 DPU (aarch64)")
message(STATUS "  C   compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  C++ compiler: ${CMAKE_CXX_COMPILER}")
