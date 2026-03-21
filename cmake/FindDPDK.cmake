# FindDPDK.cmake — locate DPDK via pkg-config (preferred) or manual search.
#
# Sets:
#   DPDK_FOUND
#   DPDK_INCLUDE_DIRS
#   DPDK_LIBRARIES
#   DPDK_DEFINITIONS

find_package(PkgConfig QUIET)

if(PkgConfig_FOUND)
    pkg_check_modules(DPDK QUIET libdpdk)
endif()

if(NOT DPDK_FOUND)
    # Manual fallback
    find_path(DPDK_INCLUDE_DIR
        NAMES rte_eal.h
        PATHS
            /usr/include/dpdk
            /usr/local/include/dpdk
            $ENV{RTE_SDK}/build/include
            $ENV{DPDK_DIR}/include
    )
    find_library(DPDK_EAL_LIB
        NAMES rte_eal
        PATHS
            /usr/lib/x86_64-linux-gnu
            /usr/local/lib
            $ENV{RTE_SDK}/build/lib
            $ENV{DPDK_DIR}/lib
    )
    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(DPDK
        REQUIRED_VARS DPDK_INCLUDE_DIR DPDK_EAL_LIB
    )
    if(DPDK_FOUND)
        set(DPDK_INCLUDE_DIRS ${DPDK_INCLUDE_DIR})
        set(DPDK_LIBRARIES
            ${DPDK_EAL_LIB}
            -Wl,--whole-archive
            -lrte_ethdev -lrte_mempool -lrte_ring -lrte_mbuf
            -lrte_net -lrte_pci -lrte_bus_pci
            -Wl,--no-whole-archive
            -ldl -pthread -lnuma -lm
        )
    endif()
else()
    # pkg_check_modules sets DPDK_CFLAGS_OTHER and DPDK_LDFLAGS
    set(DPDK_DEFINITIONS ${DPDK_CFLAGS_OTHER})
endif()

if(DPDK_FOUND AND NOT TARGET DPDK::dpdk)
    add_library(DPDK::dpdk INTERFACE IMPORTED)
    set_target_properties(DPDK::dpdk PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${DPDK_INCLUDE_DIRS}"
        INTERFACE_LINK_LIBRARIES      "${DPDK_LIBRARIES}"
        INTERFACE_COMPILE_OPTIONS     "${DPDK_DEFINITIONS}"
    )
endif()
