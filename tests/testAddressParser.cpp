#include <gtest/gtest.h>

#include <netaddr/parser4.h>
#include <netaddr/parser6.h>

using namespace netaddr;

constexpr static Parser4 parser4;
constexpr static Parser6 parser6;

TEST(Parser4, IPv4Valid) {
    // clang-format off
    constexpr const char* valid[] = {
        "1.1.1.1",
        "2.22.99.130",
        "255.255.255.255",
        "127.0.0.1",
        "10.10.10.10",
        "192.168.1.133",
        "200.1.1.1",
        "224.0.0.1",
        "0.0.0.0"
    };
    // clang-format on

    for (auto s : valid) {
        struct in_addr sys;
        Raw own;

        // expecting system library does a valid conversion
        ASSERT_GT(inet_pton(AF_INET, s, &sys), 0)
            << "inet_pton() for " << s << " must not fail";
        ASSERT_EQ(parser4.parse(s, own), true)
            << "parse<true>() for " << s << " must not fail";
        ASSERT_EQ(memcmp(&sys, &own.data.v4.in_addr, sizeof(struct in_addr)), 0)
            << "results from parser and system for " << s << " must be the same";
    }
}

TEST(Parser4, IPv4Malformed) {
    // clang-format off
    constexpr const char* invalid[] = {
        "a.b.c.d",
        "Not even close",
        "999.255.255.255",
        "127..0.0.1",
        "192.168.1.\0""133",
        "10.10.10",
        "22.22",
        "1.1.1.1.1",
        "255255255255",
        "2001:db8:3333:4444:5555:6666:7777:8888",
        "192.168.127.1111",
        ""
    };
    // clang-format on

    for (auto s : invalid) {
        Raw addr;

        ASSERT_EQ(parser4.parse(s, addr), false)
            << "parse() for " << s << " must not be succsessful";
    }
}

TEST(Parser4, IPv4Subsr) {
    std::string_view full = "Hello darkness, 2134.55.22.61 my old friend";
    std::string_view sv = full.substr(17, 11);
    std::string s = std::string(sv);

    struct in_addr sys;
    Raw own;

    ASSERT_GT(inet_pton(AF_INET, s.data(), &sys), 0);
    ASSERT_EQ(parser4.parse(sv, own), true);
    ASSERT_EQ(memcmp(&sys, &own.data.v4.in_addr, sizeof(struct in_addr)), 0);
}

TEST(Parser6, IPv6Valid) {
    // clang-format off
    constexpr const char* valid[] = {
        "2001:db8:3333:4444:5555:6666:7777:8888",
        "2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF",
        "::1234:5678",
        "2001:db8::",
        "2001:db8::1234:5678",
        "2001:0db8:0001:0000:0000:0ab9:C0A8:0102",
        "::",
        "::1",
        "64:ff9b::",
        "2002::",
        "fe80::2bc6:6b94:64e6:fb7d",
        "fec0::0000:0000:aabb:dd",
        "fc00::a1:2d",
        "ff00::22",
    };
    // clang-format on

    for (auto s : valid) {
        struct in6_addr sys;
        Raw own;

        // expecting system library does a valid conversion
        ASSERT_GT(inet_pton(AF_INET6, s, &sys), 0)
            << "inet_pton() for " << s << " must not fail";
        ASSERT_EQ(parser6.parse(s, own), true) << "parse() for " << s << " must not fail";
        ASSERT_EQ(memcmp(&sys, &own, sizeof(sys)), 0)
            << "results from parser and system for " << s
            << " must be the same different";
    }
}

TEST(Parser6, IPv6Malformed) {
    // clang-format off
    constexpr const char* invalid[] = {
        "2001:db8:3333:44444:5555:6666:7777:8888",
        "2001:db8:3333:4444:5555:6666:7777:8888:9999",
        "Not even close",
        "10.10.10.10",
        "::123:\0""4:5678",
        "2001:db8:3333:4444:5555:6666:7777:xxx",
        "22:::1",
        "2001:db8:",
        "2001:db8",
        "2001db8",
        "2001::db8::1",
        ""
        // Boost doesn't support such format
        // neither do we
        // the original Ada implementation, however, can handle ::ffff:a.b.c.d
        "::ffff:192.168.1.1"
    };
    // clang-format on

    for (auto s : invalid) {
        Raw addr;

        ASSERT_EQ(parser6.parse(s, addr), false)
            << "parse() for " << s << " must not be succsessful";
    }
}

TEST(Parser6, IPv6Subsr) {
    std::string_view full = "Hello darkness, 32001:db8:3333:4444:5555::223 my old friend";
    std::string_view sv = full.substr(17, 27);
    std::string s = std::string(sv);

    struct in6_addr sys;
    Raw own;

    ASSERT_GT(inet_pton(AF_INET6, s.data(), &sys), 0);
    ASSERT_EQ(parser6.parse(sv, own), true);
    ASSERT_EQ(memcmp(&sys, &own, sizeof(struct in6_addr)), 0);
}
