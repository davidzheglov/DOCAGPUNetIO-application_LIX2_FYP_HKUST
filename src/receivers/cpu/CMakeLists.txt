# T1: CPU naive receiver — recvfrom() + cudaMemcpy
# Compiled as a CUDA translation unit so it can call kernels directly.

set(SOURCES cpu_receiver.cu)

add_executable(cpu_receiver ${SOURCES})

target_include_directories(cpu_receiver PRIVATE
    ${COMMON_INCLUDE_DIR}
    ${CUDAToolkit_INCLUDE_DIRS}
)

target_link_libraries(cpu_receiver PRIVATE
    CUDA::cudart
    CUDA::cuda_driver
    CUDA::nvToolsExt      # nvtxRangePushA / nvtxRangePop for nsys
    Threads::Threads
)

set_target_properties(cpu_receiver PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
)

target_compile_options(cpu_receiver PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-O3 -Wall -Wextra>
    $<$<COMPILE_LANGUAGE:CUDA>:-O3 --use_fast_math>
)
