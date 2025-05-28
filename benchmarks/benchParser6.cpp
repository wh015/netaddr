#include <benchmark/benchmark.h>

#include <netaddr/parser4.h>
#include <netaddr/parser6.h>

using namespace netaddr;

// clang-format off
constexpr std::string_view BenchmarkData[] = {
    "2001:db8:3333:4444:5555:6666:7777:8888",
    "2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF",
    "::1234:5678",
    "2001:db8::",
    "2001:db8::1234:5678",
    "2001:0db8:0001:0000:0000:0ab9:C0A8:0102",
    "::"
};

// clang-format on

static void benchmarkInetPton6(benchmark::State& state) {
    for (auto _ : state) {
        for (auto item : BenchmarkData) {
            struct in6_addr dst;

            inet_pton(AF_INET6, item.data(), &dst);
            benchmark::DoNotOptimize(dst);
        }
    }
}

static void benchmarkParse6(benchmark::State& state) {
    static constexpr Parser6 parser;

    for (auto _ : state) {
        for (auto item : BenchmarkData) {
            Raw dst;

            parser.parse(item, dst);
            benchmark::DoNotOptimize(dst);
        }
    }
}

BENCHMARK(benchmarkParse6);
BENCHMARK(benchmarkInetPton6);
