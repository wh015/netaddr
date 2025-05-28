set(TARGET_NAME netaddr.tests)

find_package(GTest REQUIRED)

include(CTest)

add_executable(${TARGET_NAME}
    testAddressParser.cpp
    testSubnet.cpp
)

target_link_libraries(${TARGET_NAME}
    netaddr
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME ${TARGET_NAME} COMMAND ${TARGET_NAME})
