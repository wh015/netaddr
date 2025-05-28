#pragma once

#include <netaddr/AddressParser.h>

#include <cctype>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>

namespace netaddr {

class Subnet {
  public:
    using Prefix = std::size_t;

    bool empty() { return proto_ == Protocol::NONE; }

    bool v4() const noexcept { return proto_ == Protocol::IPV4; }

    bool v6() const noexcept { return proto_ == Protocol::IPV6; };

    auto addr4() const noexcept { return addr_.v4.in_addr; }

    auto addr6() const noexcept { return addr_.v6.in_addr; }

    auto mask4() const noexcept { return mask_.v4.in_addr; }

    auto mask6() const noexcept { return mask_.v6.in_addr; }

    auto prefix() const noexcept {
        return (proto_ == Protocol::IPV6) ? prefix_ : (prefix_ - IPv4PrefixOffset);
    }

    bool operator==(const Subnet& other) const {
        return (prefix_ == other.prefix_ && addr_.qword[0] == other.addr_.qword[0] &&
                addr_.qword[1] == other.addr_.qword[1]);
    }

    bool operator<(const Subnet& other) const {
        return (addr_.qword[0] < other.addr_.qword[0] ||
                addr_.qword[1] < other.addr_.qword[1] || prefix_ < other.prefix_);
    }

    bool belongs(const Subnet& parent) const noexcept {
        // TODO: SSE
        auto& mask = parent.mask_;
        return (parent.prefix_ <= prefix_ && (parent.flags_ & flags_) &&
                ((parent.addr_.qword[0] & mask.qword[0]) ==
                 (addr_.qword[0] & mask.qword[0])) &&
                ((parent.addr_.qword[1] & mask.qword[1]) ==
                 (addr_.qword[1] & mask.qword[1])));
    }

    bool contains(const Subnet& child) const noexcept {
        // TODO: SSE
        return (child.prefix_ >= prefix_ && (child.flags_ & flags_) &&
                ((child.addr_.qword[0] & mask_.qword[0]) ==
                 (addr_.qword[0] & mask_.qword[0])) &&
                ((child.addr_.qword[1] & mask_.qword[1]) ==
                 (addr_.qword[1] & mask_.qword[1])));
    }

    Subnet() {
        mask_.qword[0] = mask_.qword[1] = 0;
        addr_.qword[0] = addr_.qword[1] = 0;
    };

    Subnet(const std::string_view input) : Subnet() {
        auto addr = split(input);
        parse(addr);
    }

    Subnet(const char* input) : Subnet(std::string_view{input}){};
    ~Subnet() = default;

    std::string dump() const {
        std::ostringstream ss;

        for (const auto byte : addr_.byte) {
            ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
               << std::uint32_t(byte);
        }

        return ss.str();
    }

  private:
    static constexpr Prefix IPv6MaxPrefix = 128;
    static constexpr Prefix IPv4MaxPrefix = 32;
    static constexpr Prefix IPv4PrefixOffset = IPv6MaxPrefix - IPv4MaxPrefix;

    using FlagsType = std::uint8_t;

    union Address {
        IPv6Array<std::uint8_t> byte;
        IPv6Array<std::uint16_t> word;
        IPv6Array<std::uint32_t> dword;
        IPv6Array<std::uint64_t> qword;

        struct {
            struct in6_addr in_addr;
        } v6;

        struct {
            // for transition described in RFC 4038
            std::uint32_t padding[IPv4OffsetDword];
            struct in_addr in_addr;
        } v4;
    };

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

    Protocol suggest(std::string_view addr) const {
        auto first4 = addr.substr(0, 4);
        auto it = first4.find('.', 0);
        return (it == first4.npos) ? Protocol::IPV6 : Protocol::IPV4;
    }

    void mapping4() noexcept {
        // map IPv4 to IPv6 according RFC4038
        addr_.qword[0] = 0;
        addr_.dword[2] = htonl(0xFFFF);
        prefix_ += IPv4PrefixOffset;
        flags_ |= static_cast<FlagsType>(Flags::MAPPED);
    }

    void mapping6() noexcept {
        static constexpr std::size_t prefix = 96;
        if (prefix_ >= prefix && addr_.qword[0] == 0 && addr_.dword[2] == htonl(0xFFFF)) {
            prefix_ = IPv6MaxPrefix;
            flags_ |= static_cast<FlagsType>(Flags::MAPPED);
        }
    }

    bool parse(std::string_view input) {
        return (proto_ == Protocol::IPV4) ? parse4(input) : parse6(input);
    }

    std::string_view split(std::string_view input) {
        auto addr = input;

        proto_ = suggest(input);
        prefix_ = (proto_ == Protocol::IPV4) ? IPv4MaxPrefix : IPv6MaxPrefix;

        auto it = input.find('/');
        if (it != input.npos) {
            auto prefix = input.substr(it + 1);

            prefix_ = std::stoul(std::string(prefix));
            addr = input.substr(0, it);
        }

        return addr;
    }

    bool parse4(std::string_view input) {
        static constexpr AddressParser4 parser;

        if (prefix_ > IPv4MaxPrefix) {
            throw std::invalid_argument("subnet prefix for IPv4 is out of range");
        }

        auto rc = parser.parse(input, addr_.dword[IPv4OffsetDword]);
        if (!rc) {
            throw std::invalid_argument("mailformed IPv4 address");
        }

        flags_ |= static_cast<FlagsType>(Flags::IPV4);
        mapping4();
        masking();

        return rc;
    }

    bool parse6(std::string_view input) {
        static constexpr AddressParser6 parser;

        if (prefix_ > IPv6MaxPrefix) {
            throw std::invalid_argument("subnet prefix for IPv6 is out of range");
        }

        auto rc = parser.parse(input, addr_.word);
        if (!rc) {
            throw std::invalid_argument("mailformed IPv6 address");
        }

        flags_ |= static_cast<FlagsType>(Flags::IPV6);
        mapping6();
        masking();

        return rc;
    }

    void masking() noexcept {
        constexpr auto max = std::numeric_limits<std::uint32_t>::max();
        auto bits = prefix_;
        std::size_t i = 0;

        // TODO: SSE
        for (; bits > IPv4MaxPrefix; bits -= IPv4MaxPrefix) {
            mask_.dword[i++] = max;
        }
        mask_.dword[i] = bits < IPv4MaxPrefix ? htonl(~(max >> bits)) : max;

        // it's a bug in GCC 8.x
        // compiler puts a memory write operation above
        // for the last mask nonzero dword after the next AND operations
        std::atomic_thread_fence(std::memory_order_release);

        addr_.qword[0] &= mask_.qword[0];
        addr_.qword[1] &= mask_.qword[1];
    }

    Address addr_;
    Address mask_;
    Prefix prefix_ = 0;
    Protocol proto_ = Protocol::NONE;
    FlagsType flags_ = 0;
};

} // namespace netaddr