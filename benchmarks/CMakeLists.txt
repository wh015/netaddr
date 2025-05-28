find_package(benchmark REQUIRED)

include(CTest)

set(TARGET_NAME netaddr.bencmarks)

add_executable(${TARGET_NAME}
    main.cpp
    benchParser4.cpp
    benchParser6.cpp
    benchSubnet.cpp
)

target_link_libraries(${TARGET_NAME}
    netaddr
    benchmark::benchmark
)

add_test(NAME ${TARGET_NAME} COMMAND ${TARGET_NAME})

