#include <gtest/gtest.h>

#include <utility>

#include <netaddr/address.h>

using namespace netaddr;

using TestPair = std::pair<const char*, const char*>;

TEST(Address, ValidConstructors) {
    // clang-format off
    constexpr const char* data[] = {
        // IPv4
        "1.1.1.1",
        "255.255.255.255",
        "127.0.0.1",
        "10.10.10.10",
        "192.168.1.133",
        "200.1.1.1",
        "0.0.0.0",
        // IPv6
        "2001:db8:3333:4444:5555:6666:7777:8888",
        "2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF",
        "2001:db8::",
        "2001:db8::1234:5678",
        "2001:0db8:0001:0000:0000:0ab9:C0A8:0102",
        "::"
    };
    // clang-format on

    for (auto item : data) {
        Address address;

        EXPECT_NO_THROW(address = Address(item))
            << "There must no exceptions thrown in constructor for " << item;
    }
}

TEST(Address, InvalidConstructors) {
    // clang-format off
    constexpr const char* data[] = {
        // IPv4
        "a.b.c.d",
        "Not even close",
        "999.255.255.255",
        "127..0.0.1",
        "10.10.10",
        "1.1.1.1.1",
        "255255255255",
        "145.12.12.6/-1",
        "145.12.12.6/33",
        "145.12.12.6/999999999999999999999999999999999999999999999999999999999999999",
        "2.22.99.130/12",
        ""
        // IPv6
        "1234:4567::/-1",
        "1234:4567::/129",
        "1234:4567::/999999999999999999999999999999999999999999999999999999999999999",
        "2001:db8:3333:44444:5555:6666:7777:8888",
        "2001:db8:3333:4444:5555:6666:7777:8888:9999",
        "2001:db8:3333:4444:5555:6666:7777:xxx",
        "22:::1",
        "2001:db8:",
        "2001:db8",
        "2001db8",
        "2001::db8::1",
        "::1234:5678/64"
        ""
        // Boost doesn't support such format
        // neither do we
        // the original Ada implementation, however, can handle ::ffff:a.b.c.d
        "::ffff:192.168.1.1"
    };
    // clang-format on

    for (auto item : data) {
        Address address;

        EXPECT_ANY_THROW(address == Address(item))
            << "There must be exception thrown in constructor for " << item;
    }
}