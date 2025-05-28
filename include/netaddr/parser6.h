#pragma once
#ifndef NETADDR_PARSER6_H_
#define NETADDR_PARSER6_H_

#include <optional>
#include <string>

#include <assert.h>

#include <netaddr/raw.h>

namespace netaddr {

class Parser6 {
  public:
    static bool parse(std::string_view input, Raw& output) noexcept {
        static constexpr auto MaxPieces = sizeof(struct in6_addr) / sizeof(std::uint16_t);
        static constexpr auto MaxPiecesSize = 4;

        if (input.empty()) {
            return false;
        }

        int pieceIndex = 0;
        std::optional<int> compress{};
        auto pointer = input.begin();
        auto* piece = output.data.words.data();

        output.data.qwords.fill(0);

        if (input[0] == ':') {
            if (input.size() == 1 || input[1] != ':') {
                return false;
            }
            pointer += 2;
            compress = ++pieceIndex;
        }

        while (pointer != input.end()) {
            std::uint16_t value = 0, length = 0;

            if (pieceIndex == MaxPieces) {
                return false;
            }

            if (*pointer == ':') {
                if (compress.has_value()) {
                    return false;
                }
                ++pointer;
                compress = ++pieceIndex;
                continue;
            }

            while (length < MaxPiecesSize && pointer != input.end() &&
                   isAsciiHexDigit(*pointer)) {
                value = static_cast<uint16_t>(value * 0x10 + hexToBinary(*pointer));
                ++pointer;
                length++;
            }

            if ((pointer != input.end()) && (*pointer == ':')) {
                ++pointer;
                if (pointer == input.end()) {
                    return false;
                }
            } else if (pointer != input.end()) {
                return false;
            }

            piece[pieceIndex] = htons(value);
            pieceIndex++;
        }

        if (compress.has_value()) {
            int swaps = pieceIndex - *compress;
            pieceIndex = MaxPieces - 1;

            while (pieceIndex != 0 && swaps > 0) {
                std::swap(piece[pieceIndex], piece[*compress + swaps - 1]);
                pieceIndex--;
                swaps--;
            }
        } else if (pieceIndex != MaxPieces) {
            return false;
        }

        return true;
    }

  private:
    static constexpr std::uint8_t hexToBinaryTable[] = {
        0,  1,  2,  3,  4, 5, 6, 7, 8, 9, 0, 0,  0,  0,  0,  0,  0,  10, 11,
        12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,
        0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15,
    };

    static constexpr std::uint8_t hexToBinary(const char c) noexcept {
        std::size_t index = c - '0';
        assert(index < sizeof(hexToBinaryTable));
        return hexToBinaryTable[index];
    }

    static constexpr bool isAsciiHexDigit(const char c) noexcept {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
    }
};

} // namespace netaddr

#endif
