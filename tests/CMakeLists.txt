set(TARGET_NAME netaddr.tests)

find_package(GTest REQUIRED)

include(CTest)

add_executable(${TARGET_NAME}
    testAddressParser.cpp
    testSubnet.cpp
    testAddress.cpp
)

target_link_libraries(${TARGET_NAME}
    netaddr
    GTest::gtest
    GTest::gtest_main
    $<$<BOOL:${MSVC}>:wsock32>
    $<$<BOOL:${MSVC}>:ws2_32>
)

add_test(NAME ${TARGET_NAME} COMMAND ${TARGET_NAME})
