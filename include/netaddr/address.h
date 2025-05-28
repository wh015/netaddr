#pragma once
#ifndef NETADDR_ADDRESS_H_
#define NETADDR_ADDRESS_H_

#include <netaddr/subnet.h>

namespace netaddr {

class Address : public Subnet {
  public:
    Address() = default;

    Address(const char* input) : Address(std::string_view{input}){};

    Address(const std::string_view input) : Address() {
        suggest(input);
        parse(input);
    }

    ~Address() = default;
};

} // namespace netaddr

#endif
