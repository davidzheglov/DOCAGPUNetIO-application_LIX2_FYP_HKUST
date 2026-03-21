set(SOURCES data_source.cpp)

add_executable(data_source ${SOURCES})

target_include_directories(data_source PRIVATE
    ${COMMON_INCLUDE_DIR}
)

target_link_libraries(data_source PRIVATE
    Threads::Threads
)

# Busy-wait timing hint (x86 PAUSE instruction)
target_compile_definitions(data_source PRIVATE
    $<$<STREQUAL:${CMAKE_SYSTEM_PROCESSOR},x86_64>:ARCH_X86_64>
    $<$<STREQUAL:${CMAKE_SYSTEM_PROCESSOR},aarch64>:ARCH_AARCH64>
)

# Live Binance feed support (requires libwebsockets)
if(LIBWEBSOCKETS_FOUND)
    target_compile_definitions(data_source PRIVATE ENABLE_LIVE_FEED)
    target_include_directories(data_source PRIVATE ${LIBWEBSOCKETS_INCLUDE_DIRS})
    target_link_libraries(data_source PRIVATE ${LIBWEBSOCKETS_LIBRARIES})
endif()

target_compile_options(data_source PRIVATE -O3 -Wall -Wextra)
