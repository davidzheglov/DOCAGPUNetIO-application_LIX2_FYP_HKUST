# T2: DPDK poll-mode receiver

set(SOURCES dpdk_receiver.cu)

add_executable(dpdk_receiver ${SOURCES})

target_include_directories(dpdk_receiver PRIVATE
    ${COMMON_INCLUDE_DIR}
    ${CUDAToolkit_INCLUDE_DIRS}
    ${DPDK_INCLUDE_DIRS}
)

target_link_libraries(dpdk_receiver PRIVATE
    DPDK::dpdk
    CUDA::cudart
    Threads::Threads
)

target_compile_definitions(dpdk_receiver PRIVATE
    ${DPDK_DEFINITIONS}
)

set_target_properties(dpdk_receiver PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
)

target_compile_options(dpdk_receiver PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-O3 -Wall -Wextra>
    $<$<COMPILE_LANGUAGE:CUDA>:-O3 --use_fast_math>
)
