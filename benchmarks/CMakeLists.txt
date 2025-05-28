find_package(benchmark REQUIRED)

include(CTest)

set(TARGET_NAME enricher.bencmarks)

add_executable(${TARGET_NAME}
    main.cpp
    benchAddressParser.cpp
    benchSubnet.cpp
)

target_link_libraries(${TARGET_NAME}
    netaddr
    benchmark::benchmark
)

add_test(NAME ${TARGET_NAME} COMMAND ${TARGET_NAME})

