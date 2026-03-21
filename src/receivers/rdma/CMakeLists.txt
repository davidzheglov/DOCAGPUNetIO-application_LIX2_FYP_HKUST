# T3: GPU RDMA receiver via libibverbs + nv_peer_mem

set(SOURCES rdma_receiver.cu)

add_executable(rdma_receiver ${SOURCES})

target_include_directories(rdma_receiver PRIVATE
    ${COMMON_INCLUDE_DIR}
    ${CUDAToolkit_INCLUDE_DIRS}
    ${IBVERBS_INCLUDE_DIRS}
    ${RDMACM_INCLUDE_DIRS}
)

target_link_libraries(rdma_receiver PRIVATE
    ${IBVERBS_LIBRARIES}
    ${RDMACM_LIBRARIES}
    CUDA::cudart
    Threads::Threads
)

set_target_properties(rdma_receiver PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
)

target_compile_options(rdma_receiver PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-O3 -Wall -Wextra>
    $<$<COMPILE_LANGUAGE:CUDA>:-O3 --use_fast_math>
)
