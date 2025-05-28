#pragma once
#ifndef NETADDR_RAW_H_
#define NETADDR_RAW_H_

#include <cstdint>
#include <cstring>
#include <array>
#include <iomanip>
#include <sstream>

#include <immintrin.h>

#ifdef WIN32
#include <Ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace netaddr {

static constexpr std::size_t SizeIPv6 = 16;
static constexpr std::size_t SizeIPv4 = 4;
static constexpr std::size_t OffsetIPv4Dword = (SizeIPv6 - SizeIPv4) / SizeIPv4;

template <typename T>
// TODO: regualr array?
using Array = std::array<T, SizeIPv6 / sizeof(T)>;

using Address6 = Array<std::uint16_t>;

using Address4 = std::uint32_t;

struct Raw {
    Raw() noexcept {
        // help compiler here
        auto v0 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i*)&data, v0);
    }

    template <typename T>
    Raw(const T& val) noexcept {
        set(val);
    }

    void set(const struct in_addr& in_addr) noexcept {
        // legal because struct in_addr is just a wrapper around uint32_t
        auto v = *(reinterpret_cast<const std::uint32_t*>(&in_addr));
        set(v);
    }

    void set(const struct in6_addr& in_addr) noexcept {
        memcpy(&data, &in_addr, SizeIPv6);
    }

    void set(const Address4& addr) noexcept {
        // TODO: SSE
        // map IPv4 to IPv6 according RFC4038
        data.qwords[0] = 0;
        data.dwords[2] = htonl(0xFFFF);
        data.dwords[3] = addr;
    }

    void set(const Address6& addr) noexcept { memcpy(&data, &addr, SizeIPv6); }

    ~Raw() = default;

    struct in_addr addr4() const noexcept { return data.v4.in_addr; }

    struct in6_addr addr6() const noexcept { return data.v6.in_addr; }

    // TODO: other getters if needs

    bool operator==(const Raw& other) const {
        // TODO: SSE
        return (data.qwords[0] == other.data.qwords[0] &&
                data.qwords[1] == other.data.qwords[1]);
    }

    bool operator<(const Raw& other) const {
        // TODO: SSE
        return (data.qwords[0] < other.data.qwords[0] ||
                data.qwords[1] < other.data.qwords[1]);
    }

    std::string dump() const {
        std::ostringstream ss;

        for (const auto byte : data.bytes) {
            ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
               << std::uint32_t(byte);
        }

        return ss.str();
    }

    union {
        Array<std::uint8_t> bytes;
        Array<std::uint16_t> words;
        Array<std::uint32_t> dwords;
        Array<std::uint64_t> qwords;

        struct {
            struct in6_addr in_addr;
        } v6;

        struct {
            // for transition described in RFC 4038
            std::uint32_t padding[OffsetIPv4Dword];
            struct in_addr in_addr;
        } v4;
    } data;
};

static_assert(sizeof(Raw) == sizeof(struct in6_addr),
              "size of Raw must be equal size of struct in6_addr");
static_assert(sizeof(Raw) == SizeIPv6, "size of Raw must be equal SizeIPv6");

} // namespace netaddr

#endif
