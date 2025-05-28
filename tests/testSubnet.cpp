#include <gtest/gtest.h>

#include <utility>

#include <netaddr/Subnet.h>

using namespace netaddr;

using TestPair = std::pair<const char*, const char*>;

TEST(Subnet, ValidConstructors) {
    // clang-format off
    constexpr const char* data[] = {
        // IPv4
        "1.1.1.1",
        "255.255.255.255",
        "127.0.0.1",
        "10.10.10.10",
        "192.168.1.133",
        "200.1.1.1",
        "2.22.99.130/12",
        "0.0.0.0",
        // IPv6
        "2001:db8:3333:4444:5555:6666:7777:8888",
        "2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF",
        "2001:db8::",
        "2001:db8::1234:5678",
        "2001:0db8:0001:0000:0000:0ab9:C0A8:0102",
        "::1234:5678/64"
        "::"
    };
    // clang-format on

    for (auto item : data) {
        Subnet subnet;

        EXPECT_NO_THROW(subnet = Subnet(item))
            << "There must no exceptions thrown in constructor for " << item;
    }
}

TEST(Subnet, InvalidConstructors) {
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
        ""
        // Boost doesn't support such format
        // neither do we
        // the original Ada implementation, however, can handle ::ffff:a.b.c.d
        "::ffff:192.168.1.1"
    };
    // clang-format on

    for (auto item : data) {
        Subnet subnet;

        EXPECT_ANY_THROW(subnet == Subnet(item))
            << "There must be exception thrown in constructor for " << item;
    }
}

TEST(Subnet, PublicData) {
    auto ipv4 = Subnet("192.168.1.1/24");
    auto ipv6 = Subnet("fe80:133:db2::1/56");

    EXPECT_FALSE(ipv4.empty());
    EXPECT_TRUE(ipv4.v4());
    EXPECT_FALSE(ipv4.v6());
    EXPECT_EQ(ipv4.prefix(), 24);

    EXPECT_FALSE(ipv6.empty());
    EXPECT_FALSE(ipv6.v4());
    EXPECT_TRUE(ipv6.v6());
    EXPECT_EQ(ipv6.prefix(), 56);
}

TEST(Subnet, IPv4Masks) {
    // clang-format off
    constexpr TestPair data[] = {
        {"255.255.255.255", "1.1.1.1/32"},
        {"255.255.255.0", "192.168.1.1/24"},
        {"128.0.0.0", "255.0.0.0/1"},
        {"255.224.0.0", "12.12.3.9/11"},
        {"0.0.0.0", "0.0.0.0/0"},
    };
    // clang-format on

    for (auto item : data) {
        struct in_addr sys, own;
        Subnet subnet(item.second);

        own = subnet.mask4();
        // expecting system library does a valid conversion
        ASSERT_GT(inet_pton(AF_INET, item.first, &sys), 0)
            << "inet_pton() for " << item.first << " failed";

        ASSERT_EQ(memcmp(&sys, &own, sizeof(struct in_addr)), 0)
            << "Subnet mask" << item.first << " doesn't match with parser result for "
            << item.second;
    }
}

TEST(Subnet, IPv6Masks) {
    // clang-format off
    constexpr TestPair data[] = {
        {"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"},
        {"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:4860:4814::1144"},
        {"8000::", "22::1234:5678/1"},
        {"ffff:ffff:ffff:ffff::", "2001:4860:4814::0/64"},
        {"::", "::/0"},
    };
    // clang-format on

    for (auto item : data) {
        struct in6_addr sys, own;
        Subnet subnet(item.second);

        own = subnet.mask6();
        // expecting system library does a valid conversion
        ASSERT_GT(inet_pton(AF_INET6, item.first, &sys), 0)
            << "inet_pton() for " << item.first << " failed";

        ASSERT_EQ(memcmp(&sys, &own, sizeof(struct in6_addr)), 0)
            << "Subnet mask" << item.first << " doesn't match with parser result for "
            << item.second;
    }
}

TEST(Subnet, IPv4Addresses) {
    // clang-format off
    constexpr TestPair data[] = {
        {"1.1.1.1", "1.1.1.1/32"},
        {"192.168.0.0", "192.168.0.1/24"},
        {"212.160.0.0", "212.164.39.156/11"},
        {"0.0.0.0", "0.0.0.0/0"},
    };
    // clang-format on

    for (auto item : data) {
        struct in_addr sys, own;
        Subnet subnet(item.second);

        own = subnet.addr4();
        // expecting system library does a valid conversion
        ASSERT_GT(inet_pton(AF_INET, item.first, &sys), 0)
            << "inet_pton() for " << item.first << " failed";

        ASSERT_EQ(memcmp(&sys, &own, sizeof(struct in_addr)), 0)
            << "IPv4 Address" << item.first << " doesn't match with parser result for "
            << item.second;
    }
}

TEST(Subnet, IPv6Addresses) {
    // clang-format off
    constexpr TestPair data[] = {
        {"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"},
        {"8000::", "8000::1234:5678/1"},
        {"2001:db8::", "2001:db8::1/64"},
        {"2001:4860:4814::1144", "2001:4860:4814::1144"},
        {"::", "::/0"},
    };
    // clang-format ob

    for (auto item : data) {
        struct in6_addr sys, own;
        Subnet subnet(item.second);

        own = subnet.addr6();
        // expecting system library does a valid conversion
        ASSERT_GT(inet_pton(AF_INET6, item.first, &sys), 0) <<
            "inet_pton() for " << item.first << " failed";

        ASSERT_EQ(memcmp(&sys, &own, sizeof(struct in6_addr)), 0) <<
            "Subnet mask" << item.first << " doesn't match with parser result for " << item.second;
    }
}

TEST(Subnet, RFC4038) {
    // clang-format off
    constexpr TestPair data  = {
        "1.1.1.1", "::ffff:0101:0101"
    };
    // clang-format on

    struct in_addr sys4, own4;
    struct in6_addr sys6, own6;
    Subnet subnet4(data.first), subnet6(data.second);

    own4 = subnet4.addr4();
    own6 = subnet6.addr6();

    // expecting system library does a valid conversion
    ASSERT_GT(inet_pton(AF_INET, data.first, &sys4), 0)
        << "inet_pton() for " << data.first << " failed";
    ASSERT_GT(inet_pton(AF_INET6, data.second, &sys6), 0)
        << "inet_pton() for " << data.second << " failed";

    ASSERT_EQ(memcmp(&sys4, &own4, sizeof(struct in_addr)), 0)
        << "results from parser and system for " << data.first << " are different";
    ASSERT_EQ(memcmp(&sys6, &own6, sizeof(struct in6_addr)), 0)
        << "results from parser and system for " << data.second << " are different";

    // switch, expect nothing was changed
    own6 = subnet4.addr6();
    own4 = subnet6.addr4();
    ASSERT_EQ(memcmp(&sys4, &own4, sizeof(struct in_addr)), 0)
        << "IPv4 address exttracted from " << data.second << " doesn't match with "
        << data.first;
    ASSERT_EQ(memcmp(&sys6, &own6, sizeof(struct in6_addr)), 0)
        << "IPv6 address mapped to " << data.first << " doesn't match with "
        << data.second;
}

TEST(Subnet, ChildNetworks) {
    // clang-format off
    constexpr TestPair data[] = {
        // IPv4
        {"192.168.0.1/24", "192.168.0.255"},
        {"192.168.0.1/8", "192.168.0.0/24"},
        // IPv6
        {"2a02:6b8::/32", "2a02:06b8::ffff"},
        {"2a02:6b8::/32", "2a02:06b8:ffff:22::/64"},
        {"2001:4860:4814::0/64", "2001:4860:4814::1144"},
        // RFC4038
        // it's mapped IPv4 host, so it's reasonably belongs to the corresponding IPv4 network
        {"127.0.0.0/8", "0:0:0:0:0:ffff:7f00:1"}
    };
    // clang-format on

    for (auto item : data) {
        Subnet parent(item.first), child(item.second);

        EXPECT_TRUE(parent.contains(child))
            << "Subnet " << item.first << " must contain " << item.second;
        EXPECT_FALSE(parent.belongs(child))
            << "Subnet " << item.second << " must not belong to " << item.first;
        EXPECT_TRUE(child.belongs(parent))
            << "Subnet " << item.first << " must belong to " << item.second;
        EXPECT_FALSE(child.contains(parent))
            << "Subnet " << item.first << " must not contain " << item.second;
    }
}

TEST(Subnet, DifferentNetworks) {
    // clang-format off
    constexpr TestPair data[] = {
        // IPv4
        {"1.2.3.4", "192.168.1.1"},
        {"192.168.1.1/16", "172.16.0.0/8"},
        // IPv6
        {"8000::1234:5678", "8011::1234:5672"},
        {"2a02:5b8::/96", "2a02:6b8:ffff:22::/64"},
        // IPv4 & IPv6
        {"2a02:6b8::/8", "192.168.0.0/16"},
        {"10.0.0.0/8", "0a::/16"},
        // RFC4038
        // it's IPv6 network, so it can not contain IPv4 hosts
        {"0:0:0:0:0:ffff:7f00:0/96", "127.0.0.1"}
    };
    // clang-format on

    for (auto item : data) {
        Subnet parent(item.first), child(item.second);

        EXPECT_FALSE(parent.contains(child))
            << "Subnet " << item.first << " must not contain " << item.second;
        EXPECT_FALSE(parent.belongs(child))
            << "Subnet " << item.second << " must not belong to " << item.first;
        EXPECT_FALSE(child.belongs(parent))
            << "Subnet " << item.first << " must not belong to " << item.second;
        EXPECT_FALSE(child.contains(parent))
            << "Subnet " << item.first << " must not contain " << item.second;
    }
}

TEST(Subnet, SameNetworks) {
    // clang-format off
    constexpr const char* data[] = {
        // IPv4
        "192.168.0.1/32",
        "192.168.0.1/12",
        // IPv6
        "2a02:6b8::/43",
        "2a02:6b8::1/128",
    };
    // clang-format on

    for (auto item : data) {
        Subnet subnet(item);

        EXPECT_TRUE(subnet.contains(subnet))
            << "Subnet " << item << " must contain " << item;
        EXPECT_TRUE(subnet.belongs(subnet))
            << "Subnet " << item << " must belong to " << item;
    }
}

TEST(Subnet, MappedNetworks) {
    // clang-format off
    constexpr TestPair data[] = {
        // RFC4038
        {"0:0:0:0:0:ffff:7f00:1","127.0.0.1"},
        {"127.0.0.1", "0:0:0:0:0:ffff:7f00:1"},
    };
    // clang-format on

    for (auto item : data) {
        Subnet parent(item.first), child(item.second);

        EXPECT_TRUE(parent.contains(child))
            << "Subnet " << item.first << " must contain " << item.second;
        EXPECT_TRUE(parent.belongs(child))
            << "Subnet " << item.second << " must belong to " << item.first;
        EXPECT_TRUE(child.belongs(parent))
            << "Subnet " << item.first << " must belong to " << item.second;
        EXPECT_TRUE(child.contains(parent))
            << "Subnet " << item.first << " must contain " << item.second;
    }
}

TEST(Subnet, ZeroNetworksSame) {
    // clang-format off
    constexpr TestPair data[] = {
        {"0.0.0.0/0", "1.2.3.4"},
        {"0.0.0.0/2", "63.255.255.254"},
        {"0.0.0.0/0", "0:0:0:0:0:ffff:7f00:1"},
        {"::/0", "2a02:06b8::"},
        {"::/0", "::"},
        {"0.0.0.0/0", "0.0.0.0"},
    };
    // clang-format on

    for (auto item : data) {
        Subnet parent(item.first), child(item.second);

        // not sure how to treat a zeroed address - as nothing or as INADDR_ANY
        EXPECT_TRUE(parent.contains(child))
            << "Subnet " << item.first << " must not contain " << item.second;
        EXPECT_FALSE(parent.belongs(child))
            << "Subnet " << item.second << " must not belong to " << item.first;
        EXPECT_TRUE(child.belongs(parent))
            << "Subnet " << item.first << " must not belong to " << item.second;
        EXPECT_FALSE(child.contains(parent))
            << "Subnet " << item.first << " must not contain " << item.second;
    }
}

TEST(Subnet, ZeroNetworksDifferent) {
    // clang-format off
    constexpr TestPair data[] = {
        {"::/96", "2a02:06b8::"},
        {"::/0", "1.2.3.4"},
        {"::/0", "0.0.0.0"},
        {"1.2.3.0/24", "0.0.0.0"},
        {"2a02:06b8::/64", "0.0.0.0"},
        {"2a02:06b8::/96", "::"},
        {"1.2.3.0/24", "::"},
        {"::/0", "0.0.0.0"},
        {"0.0.0.0/0", "::"},
    };
    // clang-format on

    for (auto item : data) {
        Subnet parent(item.first), child(item.second);

        // not sure how to treat a zeroed addresses - as nothing or as INADDR_ANY
        EXPECT_FALSE(parent.contains(child))
            << "Subnet " << item.first << " must not contain " << item.second;
        EXPECT_FALSE(parent.belongs(child))
            << "Subnet " << item.second << " must not belong to " << item.first;
        EXPECT_FALSE(child.belongs(parent))
            << "Subnet " << item.first << " must not belong to " << item.second;
        EXPECT_FALSE(child.contains(parent))
            << "Subnet " << item.first << " must not contain " << item.second;
    }
}

TEST(Subnet, ZeroAddresses) {
    // clang-format off
    constexpr TestPair data[] = {
        {"1.2.3.0", "0.0.0.0"},
        {"0.0.0.0", "1.2.3.0"},
        {"2a02:06b8::1", "0.0.0.0"},
        {"0.0.0.0", "2a02:06b8::1"},
        { "1.2.3.0", "::"},
        {"::", "1.2.3.0"},
        {"2a02:06b8::1", "::"},
        {"::", "2a02:06b8::1"},
    };
    // clang-format on

    for (auto item : data) {
        Subnet parent(item.first), child(item.second);

        // not sure how to treat a zeroed address - as nothing or as INADDR_ANY
        EXPECT_FALSE(parent.contains(child))
            << "Subnet " << item.first << " must not contain " << item.second;
        EXPECT_FALSE(parent.belongs(child))
            << "Subnet " << item.second << " must not belong to " << item.first;
        EXPECT_FALSE(child.belongs(parent))
            << "Subnet " << item.first << " must not belong to " << item.second;
        EXPECT_FALSE(child.contains(parent))
            << "Subnet " << item.first << " must not contain " << item.second;
    }
}

TEST(Subnet, Operators) {
    EXPECT_TRUE(Subnet("192.168.1.1") == Subnet("192.168.1.1"));
    EXPECT_TRUE(Subnet("2a02:06b8::1") == Subnet("2a02:06b8::1"));
    EXPECT_TRUE(Subnet("192.168.1.1/24") == Subnet("192.168.1.1/24"));
    EXPECT_TRUE(Subnet("2a02:06b8::1/64") == Subnet("2a02:06b8::1/64"));

    EXPECT_FALSE(Subnet("192.168.1.1") == Subnet("2a02:06b8::1"));
    EXPECT_FALSE(Subnet("192.168.1.2") == Subnet("192.168.1.1"));
    EXPECT_FALSE(Subnet("2a02:06b8::2") == Subnet("2a02:06b8::1"));
    EXPECT_FALSE(Subnet("192.168.1.1/24") == Subnet("192.168.1.1/16"));
    EXPECT_FALSE(Subnet("2a02:06b8::1/64") == Subnet("2a02:06b8::1/32"));

    EXPECT_FALSE(Subnet("192.168.1.2") < Subnet("192.168.1.1"));
    EXPECT_FALSE(Subnet("2a02:06b8::2") < Subnet("2a02:06b8::1"));
    EXPECT_FALSE(Subnet("2a02:06b8::2") < Subnet("192.168.1.1"));
    EXPECT_TRUE(Subnet("192.168.1.2/16") < Subnet("192.168.1.1/24"));
    EXPECT_TRUE(Subnet("2a02:06b8::2/48") < Subnet("2a02:06b8::1/56"));

    auto s = Subnet("192.168.1.1").dump();
    EXPECT_TRUE(s == "00000000000000000000FFFFC0A80101");
}
