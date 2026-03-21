# T4/T5: DOCA GPUNetIO receiver
# The SAME binary is deployed on host (T4) or with the data_source on DPU (T5).

set(SOURCES gpu_receiver.cu)

add_executable(gpu_receiver ${SOURCES})

target_include_directories(gpu_receiver PRIVATE
    ${COMMON_INCLUDE_DIR}
    ${CUDAToolkit_INCLUDE_DIRS}
    ${DOCA_INCLUDE_DIRS}
)

target_link_libraries(gpu_receiver PRIVATE
    DOCA::doca
    CUDA::cudart
    Threads::Threads
)

set_target_properties(gpu_receiver PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
    # DOCA device-side library is a relocatable CUDA object
    CUDA_RESOLVE_DEVICE_SYMBOLS ON
)

target_compile_options(gpu_receiver PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:
        -O3
        --use_fast_math
        -rdc=true
    >
    $<$<COMPILE_LANGUAGE:CXX>:-O3 -Wall -Wextra>
)
