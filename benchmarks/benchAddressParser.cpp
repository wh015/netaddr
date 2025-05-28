#include <benchmark/benchmark.h>

#include <netaddr/AddressParser.h>

// kindly do not run these benchmarks with ASAN
// or create std::string objects
// otherwise you'll get
// global-buffer-overflow in _mm_loadu_si128(long long __vector(2) const*)

using namespace netaddr;

// clang-format off
constexpr std::string_view DATA4[] = {
    "1.1.1.1",
    "2.22.99.130",
    "255.255.255.255",
    "127.0.0.1",
    "10.10.10.10",
    "192.168.1.133",
    "200.1.1.1",
    "0.0.0.0"
};

constexpr std::string_view DATA6[] = {
    "2001:db8:3333:4444:5555:6666:7777:8888",
    "2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF",
    "::1234:5678",
    "2001:db8::",
    "2001:db8::1234:5678",
    "2001:0db8:0001:0000:0000:0ab9:C0A8:0102",
    "::"
};

// clang-format on

static void BM_inet_pton4(benchmark::State& state) {
    for (auto _ : state) {
        for (auto item : DATA4) {
            struct in_addr dst;

            inet_pton(AF_INET, item.data(), &dst);
            benchmark::DoNotOptimize(dst);
        }
    }
}

static void BM_Parse4(benchmark::State& state) {
    static constexpr AddressParser4 parser;

    for (auto _ : state) {
        for (auto item : DATA4) {
            IPv4Address dst;

            parser.parse(item, dst);
            benchmark::DoNotOptimize(dst);
        }
    }
}

static void BM_inet_pton6(benchmark::State& state) {
    for (auto _ : state) {
        for (auto item : DATA6) {
            struct in6_addr dst;

            inet_pton(AF_INET6, item.data(), &dst);
            benchmark::DoNotOptimize(dst);
        }
    }
}

static void BM_Parse6(benchmark::State& state) {
    static constexpr AddressParser6 parser;

    for (auto _ : state) {
        for (auto item : DATA6) {
            IPv6Address dst;

            parser.parse(item, dst);
            benchmark::DoNotOptimize(dst);
        }
    }
}

BENCHMARK(BM_Parse4);
BENCHMARK(BM_inet_pton4);
BENCHMARK(BM_Parse6);
BENCHMARK(BM_inet_pton6);
