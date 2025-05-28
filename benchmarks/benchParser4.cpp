#include <benchmark/benchmark.h>

#include <netaddr/parser4.h>
#include <netaddr/parser6.h>

using namespace netaddr;

// clang-format off
constexpr std::string_view BenchmarkData[] = {
    "1.1.1.1",
    "2.22.99.130",
    "255.255.255.255",
    "127.0.0.1",
    "10.10.10.10",
    "192.168.1.133",
    "200.1.1.1",
    "0.0.0.0"
};

// clang-format on

static void benchmarkInetPton4(benchmark::State& state) {
    for (auto _ : state) {
        for (auto item : BenchmarkData) {
            struct in_addr dst;

            inet_pton(AF_INET, item.data(), &dst);
            benchmark::DoNotOptimize(dst);
        }
    }
}

static void benchmarkParse4(benchmark::State& state) {
    static constexpr Parser4 parser;

    for (auto _ : state) {
        for (auto item : BenchmarkData) {
            Raw dst;

            parser.parse(item, dst);
            benchmark::DoNotOptimize(dst);
        }
    }
}

BENCHMARK(benchmarkParse4);
BENCHMARK(benchmarkInetPton4);
