add_executable(benchmark_harness benchmark_harness.cpp)

target_include_directories(benchmark_harness PRIVATE ${COMMON_INCLUDE_DIR})
target_link_libraries(benchmark_harness PRIVATE Threads::Threads)
target_compile_options(benchmark_harness PRIVATE -O2 -Wall -Wextra)
