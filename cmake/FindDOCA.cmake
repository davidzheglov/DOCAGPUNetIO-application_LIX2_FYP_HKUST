# FindDOCA.cmake — locate NVIDIA DOCA SDK
#
# DOCA is typically installed at /opt/mellanox/doca on BlueField hosts
# and at the same path on the DPU ARM side after cross-install.
#
# Sets:
#   DOCA_FOUND
#   DOCA_INCLUDE_DIRS
#   DOCA_LIBRARIES
#   DOCA_GPU_LIBRARIES

set(_DOCA_SEARCH_PATHS
    /opt/mellanox/doca
    /usr/local/doca
    $ENV{DOCA_DIR}
)

find_path(DOCA_INCLUDE_DIR
    NAMES doca_version.h
    PATHS ${_DOCA_SEARCH_PATHS}
    PATH_SUFFIXES include
)

# Core library
find_library(DOCA_CORE_LIB
    NAMES doca_core
    PATHS ${_DOCA_SEARCH_PATHS}
    PATH_SUFFIXES lib lib64
)

# GPUNetIO library
find_library(DOCA_GPUNETIO_LIB
    NAMES doca_gpunetio
    PATHS ${_DOCA_SEARCH_PATHS}
    PATH_SUFFIXES lib lib64
)

# Ethernet TX/RX queues
find_library(DOCA_ETH_LIB
    NAMES doca_eth
    PATHS ${_DOCA_SEARCH_PATHS}
    PATH_SUFFIXES lib lib64
)

# Flow steering
find_library(DOCA_FLOW_LIB
    NAMES doca_flow
    PATHS ${_DOCA_SEARCH_PATHS}
    PATH_SUFFIXES lib lib64
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(DOCA
    REQUIRED_VARS DOCA_INCLUDE_DIR DOCA_CORE_LIB DOCA_GPUNETIO_LIB
)

if(DOCA_FOUND)
    set(DOCA_INCLUDE_DIRS ${DOCA_INCLUDE_DIR})
    set(DOCA_LIBRARIES
        ${DOCA_CORE_LIB}
        ${DOCA_GPUNETIO_LIB}
        ${DOCA_ETH_LIB}
        ${DOCA_FLOW_LIB}
    )
    # Device-side GPUNetIO stubs (CUDA)
    find_library(DOCA_GPUNETIO_DEVICE_LIB
        NAMES doca_gpunetio_device
        PATHS ${_DOCA_SEARCH_PATHS}
        PATH_SUFFIXES lib lib64
    )
    set(DOCA_GPU_LIBRARIES
        ${DOCA_GPUNETIO_DEVICE_LIB}
        ${DOCA_GPUNETIO_LIB}
    )

    if(NOT TARGET DOCA::doca)
        add_library(DOCA::doca INTERFACE IMPORTED)
        set_target_properties(DOCA::doca PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${DOCA_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES      "${DOCA_LIBRARIES}"
        )
    endif()
endif()
