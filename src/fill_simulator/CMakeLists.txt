add_executable(fill_simulator fill_simulator.cpp)

target_include_directories(fill_simulator PRIVATE ${COMMON_INCLUDE_DIR})
target_link_libraries(fill_simulator PRIVATE Threads::Threads)
target_compile_options(fill_simulator PRIVATE -O2 -Wall -Wextra)
