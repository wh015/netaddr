#include <benchmark/benchmark.h>

#include <vector>

#include <netaddr/subnet.h>

using namespace netaddr;

// clang-format off
constexpr std::string_view BenchmarkData4[] = {
    "1.1.1.1",
    "2.22.99.130/32",
    "255.255.255.255",
    "127.0.0.1",
    "10.10.10.10/8",
    "192.168.1.133",
    "200.1.1.1",
    "0.0.0.0"
};

constexpr std::string_view BenchmarkData6[] = {
    "2001:db8:3333:4444:5555:6666:7777:8888",
    "2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF/64",
    "::1234:5678",
    "2001:db8::/4",
    "2001:db8::1234:5678/128",
    "2001:0db8:0001:0000:0000:0ab9:C0A8:0102",
    "::"
};

// clang-format on

static auto makeVector46() {
    std::vector<Subnet> v;

    for (auto item : BenchmarkData4) {
        v.push_back(item);
    }

    for (auto item : BenchmarkData6) {
        v.push_back(item);
    }

    return v;
}

static void benchmarkSubnet4(benchmark::State& state) {
    for (auto _ : state) {
        for (auto item : BenchmarkData4) {
            auto subnet = Subnet(item);
            benchmark::DoNotOptimize(subnet);
        }
    }
}

static void benchmarkSubnet6(benchmark::State& state) {
    for (auto _ : state) {
        for (auto item : BenchmarkData6) {
            auto subnet = Subnet(item);
            benchmark::DoNotOptimize(subnet);
        }
    }
}

static void benchmarkSubnetContains(benchmark::State& state) {
    auto v = makeVector46();

    for (auto _ : state) {
        for (auto it = v.begin(); it != v.end(); ++it) {
            for (auto it2 = it; it2 != v.end(); ++it2) {
                auto rc = it2->contains(*it);
                benchmark::DoNotOptimize(rc);
            }
        }
    }
}

static void benchmarkSubnetBelongs(benchmark::State& state) {
    auto v = makeVector46();

    for (auto _ : state) {
        for (auto it = v.begin(); it != v.end(); ++it) {
            for (auto it2 = it; it2 != v.end(); ++it2) {
                auto rc = it2->belongs(*it);
                benchmark::DoNotOptimize(rc);
            }
        }
    }
}

BENCHMARK(benchmarkSubnet4);
BENCHMARK(benchmarkSubnet6);
BENCHMARK(benchmarkSubnetContains);
BENCHMARK(benchmarkSubnetBelongs);
