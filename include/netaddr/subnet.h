#pragma once
#ifndef NETADDR_SUBNET_H_
#define NETADDR_SUBNET_H_

#include <algorithm>
#include <atomic>
#include <limits>
#include <stdexcept>

#include <netaddr/parser4.h>
#include <netaddr/parser6.h>

namespace netaddr {

class Subnet {
  public:
    using Prefix = std::size_t;

    bool empty() { return proto == Protocol::NONE; }

    bool v4() const noexcept { return proto == Protocol::IPV4; }

    bool v6() const noexcept { return proto == Protocol::IPV6; };

    auto addr4() const noexcept { return addr.data.v4.in_addr; }

    auto addr6() const noexcept { return addr.data.v6.in_addr; }

    auto mask4() const noexcept { return mask.data.v4.in_addr; }

    auto mask6() const noexcept { return mask.data.v6.in_addr; }

    auto cidr() const noexcept {
        return (proto == Protocol::IPV6) ? prefix : (prefix - IPv4PrefixOffset);
    }

    bool operator==(const Subnet& other) const {
        return (addr == other.addr && prefix == other.prefix);
    }

    bool operator<(const Subnet& other) const {
        return (addr < other.addr || prefix < other.prefix);
    }

    bool belongs(const Subnet& parent) const noexcept {
        // TODO: SSE
        auto& pmask = parent.mask;
        return (parent.prefix <= prefix && (parent.flags & flags) &&
                ((parent.addr.data.qwords[0] & pmask.data.qwords[0]) ==
                 (addr.data.qwords[0] & pmask.data.qwords[0])) &&
                ((parent.addr.data.qwords[1] & pmask.data.qwords[1]) ==
                 (addr.data.qwords[1] & pmask.data.qwords[1])));
    }

    bool contains(const Subnet& child) const noexcept {
        // TODO: SSE
        return (child.prefix >= prefix && (child.flags & flags) &&
                ((child.addr.data.qwords[0] & mask.data.qwords[0]) ==
                 (addr.data.qwords[0] & mask.data.qwords[0])) &&
                ((child.addr.data.qwords[1] & mask.data.qwords[1]) ==
                 (addr.data.qwords[1] & mask.data.qwords[1])));
    }

    Subnet() = default;

    Subnet(const char* input) : Subnet(std::string_view{input}){};

    Subnet(const std::string_view input) : Subnet() {
        suggest(input);

        auto addr = split(input);
        parse(addr);
    }

    ~Subnet() = default;

    std::string dump() const { return addr.dump() + "{" + mask.dump() + "}"; }

  protected:
    static constexpr Prefix IPv6MaxPrefix = 128;
    static constexpr Prefix IPv4MaxPrefix = 32;
    static constexpr Prefix IPv4PrefixOffset = IPv6MaxPrefix - IPv4MaxPrefix;

    using FlagsType = std::uint8_t;

    enum class Protocol : std::uint8_t {
        NONE = AF_UNSPEC,
        IPV4 = AF_INET,
        IPV6 = AF_INET6
    };

    enum class Flags : FlagsType {
        IPV4 = (1 << 0),
        IPV6 = (1 << 1),
        MAPPED = (1 << 2),
    };

    void suggest(std::string_view input) {
        constexpr auto MinInputLength = std::char_traits<char>::length("x.x.x.x");

        bool dot = false;
        if(input.size() >= MinInputLength) {
            dot |= (input[0] == '.');
            dot |= (input[1] == '.');
            dot |= (input[2] == '.');
            dot |= (input[3] == '.');
        }

        proto = dot ? Protocol::IPV4 : Protocol::IPV6;
        prefix = (proto == Protocol::IPV4) ? IPv4MaxPrefix : IPv6MaxPrefix;
    }

    void mapping4() noexcept {
        prefix += IPv4PrefixOffset;
        flags |= static_cast<FlagsType>(Flags::MAPPED);
    }

    void mapping6() noexcept {
        static constexpr std::size_t MinPrefix = 96;

        if (prefix >= MinPrefix && addr.data.qwords[0] == 0 &&
            addr.data.dwords[2] == htonl(0xFFFF)) {
            prefix = IPv6MaxPrefix;
            flags |= static_cast<FlagsType>(Flags::MAPPED);
        }
    }

    bool parse(std::string_view input) {
        return (proto == Protocol::IPV4) ? parse4(input) : parse6(input);
    }

    std::string_view split(std::string_view input) {
        auto nocidr = input;

        auto it = input.find('/');
        if (it != input.npos) {
            auto cidr = input.substr(it + 1);

            prefix = std::stoul(std::string(cidr));
            nocidr = input.substr(0, it);
        }

        return nocidr;
    }

    bool parse4(std::string_view input) {
        static constexpr Parser4 parser;

        if (prefix > IPv4MaxPrefix) {
            throw std::invalid_argument("subnet prefix for IPv4 is out of range");
        }

        auto rc = parser.parse(input, addr);
        if (!rc) {
            throw std::invalid_argument("mailformed IPv4 address");
        }

        flags |= static_cast<FlagsType>(Flags::IPV4);
        mapping4();
        masking();

        return rc;
    }

    bool parse6(std::string_view input) {
        static constexpr Parser6 parser;

        if (prefix > IPv6MaxPrefix) {
            throw std::invalid_argument("subnet prefix for IPv6 is out of range");
        }

        auto rc = parser.parse(input, addr);
        if (!rc) {
            throw std::invalid_argument("mailformed IPv6 address");
        }

        flags |= static_cast<FlagsType>(Flags::IPV6);
        mapping6();
        masking();

        return rc;
    }

    void masking() noexcept {
        constexpr auto max = std::numeric_limits<std::uint32_t>::max();
        auto bits = prefix;
        std::size_t i = 0;

        // TODO: SSE
        for (; bits > IPv4MaxPrefix; bits -= IPv4MaxPrefix) {
            mask.data.dwords[i++] = max;
        }
        mask.data.dwords[i] = bits < IPv4MaxPrefix ? htonl(~(max >> bits)) : max;

        // it's a bug in GCC 8.x
        // compiler puts a memory write operation above
        // for the last mask nonzero dword after the next AND operations
        std::atomic_thread_fence(std::memory_order_release);

        addr.data.qwords[0] &= mask.data.qwords[0];
        addr.data.qwords[1] &= mask.data.qwords[1];
    }

    Raw addr;
    Raw mask;
    Prefix prefix = 0;
    Protocol proto = Protocol::NONE;
    FlagsType flags = 0;
};

} // namespace netaddr

#endif
