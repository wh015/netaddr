#pragma once
#ifndef NETADDR_PARSER4_H_
#define NETADDR_PARSER4_H_

#include <string>

#include <netaddr/raw.h>

namespace netaddr {

class Parser4 {
  public:
    static bool parse(std::string_view input, Raw& output) noexcept {
        constexpr auto MaxInputLength = std::char_traits<char>::length("xxx.xxx.xxx.xxx");
        auto sz = input.size();

        if (sz > MaxInputLength) {
            return false;
        }

        char buf[MaxInputLength + 1] = {0};
        memcpy(buf, input.data(), sz);

        auto* src = (const __m128i*)buf;
        __m128i v = _mm_loadu_si128(src);
        __m128i isDot = _mm_cmpeq_epi8(v, _mm_set1_epi8('.'));
        uint32_t dotMask = (uint32_t)_mm_movemask_epi8(isDot);

        // set non-digits to 0x80..0x89, set digits to 0x00..0x09
        const __m128i saturationDistance = _mm_set1_epi8(0x7F - 9);
        v = _mm_xor_si128(v, _mm_set1_epi8('0'));
        v = _mm_adds_epu8(v, saturationDistance);
        uint32_t nonDigitMask = (uint32_t)_mm_movemask_epi8(v);
        v = _mm_subs_epi8(v, saturationDistance);

        uint32_t badMask = dotMask ^ nonDigitMask;
        uint32_t clipMask = badMask ^ (badMask - 1);
        uint32_t partitionMask = nonDigitMask & clipMask;

        const uint32_t length = (uint32_t)_mm_popcnt_u32(clipMask) - 1;

        uint32_t hashKey = (partitionMask * 0x00CF7800) >> 24;
        uint8_t hashId = patternsId[hashKey];
        if (hashId >= PatternsTableHeight) {
            return false;
        }

        const std::uint8_t(&pattern)[PatternsTableWidth] = patterns[hashId];
        const uint8_t* const patternPtr = &pattern[0];
        __m128i shuf = _mm_loadu_si128((const __m128i*)patternPtr);
        v = _mm_shuffle_epi8(v, shuf);

        const __m128i mulWeights =
            _mm_set_epi8(0, 100, 0, 100, 0, 100, 0, 100, 10, 1, 10, 1, 10, 1, 10, 1);
        __m128i acc = _mm_maddubs_epi16(mulWeights, v);
        __m128i swapped = _mm_shuffle_epi32(acc, _MM_SHUFFLE(1, 0, 3, 2));
        acc = _mm_adds_epu16(acc, swapped);

        // check `v` for leading zeros in each partition, ignore lanes if
        // partition has only one digit if hibyte of `acc` then bad_char or
        // overflow
        __m128i checkLZ = _mm_xor_si128(_mm_cmpeq_epi8(_mm_setzero_si128(), v), shuf);
        __m128i checkOF = _mm_adds_epu16(_mm_set1_epi16(0x7F00), acc);
        __m128i checks = _mm_or_si128(checkLZ, checkOF);
        uint32_t checkMask = (uint32_t)_mm_movemask_epi8(checks);
        checkMask &= 0x0000AA00; // the only lanes wanted

        // pack and we are done!
        auto value = (Address4)_mm_cvtsi128_si32(_mm_packus_epi16(acc, acc));
        output.set(value);

        bool rc = ((length + checkMask - patternPtr[6]) == 1);
        rc &= (length == input.size());

        return rc;
    }

  private:
    static constexpr std::size_t PatternsIdTableSize = 256;
    static constexpr std::size_t PatternsTableHeight = 81;
    static constexpr std::size_t PatternsTableWidth = 16;

    static constexpr std::uint8_t patternsId[PatternsIdTableSize] = {
        38,  65,  255, 56,  73,  255, 255, 255, 255, 255, 255, 3,   255, 255, 6,   255,
        255, 9,   255, 27,  255, 12,  30,  255, 255, 255, 255, 15,  255, 33,  255, 255,
        255, 255, 18,  36,  255, 255, 255, 54,  21,  255, 39,  255, 255, 57,  255, 255,
        255, 255, 255, 255, 255, 255, 24,  42,  255, 255, 255, 60,  255, 255, 255, 255,
        255, 255, 255, 255, 45,  255, 255, 63,  255, 255, 255, 255, 255, 255, 255, 255,
        255, 48,  53,  255, 255, 66,  71,  255, 255, 16,  255, 34,  255, 255, 255, 255,
        255, 255, 255, 52,  255, 255, 22,  70,  40,  255, 255, 58,  51,  255, 255, 69,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 5,   255, 255, 255, 255, 255, 255,
        11,  29,  46,  255, 255, 64,  255, 255, 72,  0,   77,  255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 76,  255, 255, 255, 255,
        255, 255, 255, 75,  255, 80,  255, 255, 255, 26,  255, 44,  255, 7,   62,  255,
        255, 25,  255, 43,  13,  31,  61,  255, 255, 255, 255, 255, 255, 255, 255, 255,
        2,   19,  37,  255, 255, 50,  55,  79,  68,  255, 255, 255, 255, 49,  255, 255,
        67,  255, 255, 255, 255, 17,  255, 35,  78,  255, 4,   255, 255, 255, 255, 255,
        255, 10,  23,  28,  41,  255, 255, 59,  255, 255, 255, 8,   255, 255, 255, 255,
        255, 1,   14,  32,  255, 255, 255, 255, 255, 255, 255, 255, 74,  255, 47,  20,
    };

    static constexpr std::uint8_t patterns[PatternsTableHeight][PatternsTableWidth] = {
        {0, 128, 2, 128, 4, 128, 6, 128, 128, 128, 128, 128, 128, 128, 128, 128},
        {0, 128, 2, 128, 4, 128, 7, 6, 128, 128, 128, 128, 128, 128, 128, 6},
        {0, 128, 2, 128, 4, 128, 8, 7, 128, 128, 128, 128, 128, 128, 6, 6},
        {0, 128, 2, 128, 5, 4, 7, 128, 128, 128, 128, 128, 128, 4, 128, 128},
        {0, 128, 2, 128, 5, 4, 8, 7, 128, 128, 128, 128, 128, 4, 128, 7},
        {0, 128, 2, 128, 5, 4, 9, 8, 128, 128, 128, 128, 128, 4, 7, 7},
        {0, 128, 2, 128, 6, 5, 8, 128, 128, 128, 128, 128, 4, 4, 128, 128},
        {0, 128, 2, 128, 6, 5, 9, 8, 128, 128, 128, 128, 4, 4, 128, 8},
        {0, 128, 2, 128, 6, 5, 10, 9, 128, 128, 128, 128, 4, 4, 8, 8},
        {0, 128, 3, 2, 5, 128, 7, 128, 128, 128, 128, 2, 128, 128, 128, 128},
        {0, 128, 3, 2, 5, 128, 8, 7, 128, 128, 128, 2, 128, 128, 128, 7},
        {0, 128, 3, 2, 5, 128, 9, 8, 128, 128, 128, 2, 128, 128, 7, 7},
        {0, 128, 3, 2, 6, 5, 8, 128, 128, 128, 128, 2, 128, 5, 128, 128},
        {0, 128, 3, 2, 6, 5, 9, 8, 128, 128, 128, 2, 128, 5, 128, 8},
        {0, 128, 3, 2, 6, 5, 10, 9, 128, 128, 128, 2, 128, 5, 8, 8},
        {0, 128, 3, 2, 7, 6, 9, 128, 128, 128, 128, 2, 5, 5, 128, 128},
        {0, 128, 3, 2, 7, 6, 10, 9, 128, 128, 128, 2, 5, 5, 128, 9},
        {0, 128, 3, 2, 7, 6, 11, 10, 128, 128, 128, 2, 5, 5, 9, 9},
        {0, 128, 4, 3, 6, 128, 8, 128, 128, 128, 2, 2, 128, 128, 128, 128},
        {0, 128, 4, 3, 6, 128, 9, 8, 128, 128, 2, 2, 128, 128, 128, 8},
        {0, 128, 4, 3, 6, 128, 10, 9, 128, 128, 2, 2, 128, 128, 8, 8},
        {0, 128, 4, 3, 7, 6, 9, 128, 128, 128, 2, 2, 128, 6, 128, 128},
        {0, 128, 4, 3, 7, 6, 10, 9, 128, 128, 2, 2, 128, 6, 128, 9},
        {0, 128, 4, 3, 7, 6, 11, 10, 128, 128, 2, 2, 128, 6, 9, 9},
        {0, 128, 4, 3, 8, 7, 10, 128, 128, 128, 2, 2, 6, 6, 128, 128},
        {0, 128, 4, 3, 8, 7, 11, 10, 128, 128, 2, 2, 6, 6, 128, 10},
        {0, 128, 4, 3, 8, 7, 12, 11, 128, 128, 2, 2, 6, 6, 10, 10},
        {1, 0, 3, 128, 5, 128, 7, 128, 128, 0, 128, 128, 128, 128, 128, 128},
        {1, 0, 3, 128, 5, 128, 8, 7, 128, 0, 128, 128, 128, 128, 128, 7},
        {1, 0, 3, 128, 5, 128, 9, 8, 128, 0, 128, 128, 128, 128, 7, 7},
        {1, 0, 3, 128, 6, 5, 8, 128, 128, 0, 128, 128, 128, 5, 128, 128},
        {1, 0, 3, 128, 6, 5, 9, 8, 128, 0, 128, 128, 128, 5, 128, 8},
        {1, 0, 3, 128, 6, 5, 10, 9, 128, 0, 128, 128, 128, 5, 8, 8},
        {1, 0, 3, 128, 7, 6, 9, 128, 128, 0, 128, 128, 5, 5, 128, 128},
        {1, 0, 3, 128, 7, 6, 10, 9, 128, 0, 128, 128, 5, 5, 128, 9},
        {1, 0, 3, 128, 7, 6, 11, 10, 128, 0, 128, 128, 5, 5, 9, 9},
        {1, 0, 4, 3, 6, 128, 8, 128, 128, 0, 128, 3, 128, 128, 128, 128},
        {1, 0, 4, 3, 6, 128, 9, 8, 128, 0, 128, 3, 128, 128, 128, 8},
        {1, 0, 4, 3, 6, 128, 10, 9, 128, 0, 128, 3, 128, 128, 8, 8},
        {1, 0, 4, 3, 7, 6, 9, 128, 128, 0, 128, 3, 128, 6, 128, 128},
        {1, 0, 4, 3, 7, 6, 10, 9, 128, 0, 128, 3, 128, 6, 128, 9},
        {1, 0, 4, 3, 7, 6, 11, 10, 128, 0, 128, 3, 128, 6, 9, 9},
        {1, 0, 4, 3, 8, 7, 10, 128, 128, 0, 128, 3, 6, 6, 128, 128},
        {1, 0, 4, 3, 8, 7, 11, 10, 128, 0, 128, 3, 6, 6, 128, 10},
        {1, 0, 4, 3, 8, 7, 12, 11, 128, 0, 128, 3, 6, 6, 10, 10},
        {1, 0, 5, 4, 7, 128, 9, 128, 128, 0, 3, 3, 128, 128, 128, 128},
        {1, 0, 5, 4, 7, 128, 10, 9, 128, 0, 3, 3, 128, 128, 128, 9},
        {1, 0, 5, 4, 7, 128, 11, 10, 128, 0, 3, 3, 128, 128, 9, 9},
        {1, 0, 5, 4, 8, 7, 10, 128, 128, 0, 3, 3, 128, 7, 128, 128},
        {1, 0, 5, 4, 8, 7, 11, 10, 128, 0, 3, 3, 128, 7, 128, 10},
        {1, 0, 5, 4, 8, 7, 12, 11, 128, 0, 3, 3, 128, 7, 10, 10},
        {1, 0, 5, 4, 9, 8, 11, 128, 128, 0, 3, 3, 7, 7, 128, 128},
        {1, 0, 5, 4, 9, 8, 12, 11, 128, 0, 3, 3, 7, 7, 128, 11},
        {1, 0, 5, 4, 9, 8, 13, 12, 128, 0, 3, 3, 7, 7, 11, 11},
        {2, 1, 4, 128, 6, 128, 8, 128, 0, 0, 128, 128, 128, 128, 128, 128},
        {2, 1, 4, 128, 6, 128, 9, 8, 0, 0, 128, 128, 128, 128, 128, 8},
        {2, 1, 4, 128, 6, 128, 10, 9, 0, 0, 128, 128, 128, 128, 8, 8},
        {2, 1, 4, 128, 7, 6, 9, 128, 0, 0, 128, 128, 128, 6, 128, 128},
        {2, 1, 4, 128, 7, 6, 10, 9, 0, 0, 128, 128, 128, 6, 128, 9},
        {2, 1, 4, 128, 7, 6, 11, 10, 0, 0, 128, 128, 128, 6, 9, 9},
        {2, 1, 4, 128, 8, 7, 10, 128, 0, 0, 128, 128, 6, 6, 128, 128},
        {2, 1, 4, 128, 8, 7, 11, 10, 0, 0, 128, 128, 6, 6, 128, 10},
        {2, 1, 4, 128, 8, 7, 12, 11, 0, 0, 128, 128, 6, 6, 10, 10},
        {2, 1, 5, 4, 7, 128, 9, 128, 0, 0, 128, 4, 128, 128, 128, 128},
        {2, 1, 5, 4, 7, 128, 10, 9, 0, 0, 128, 4, 128, 128, 128, 9},
        {2, 1, 5, 4, 7, 128, 11, 10, 0, 0, 128, 4, 128, 128, 9, 9},
        {2, 1, 5, 4, 8, 7, 10, 128, 0, 0, 128, 4, 128, 7, 128, 128},
        {2, 1, 5, 4, 8, 7, 11, 10, 0, 0, 128, 4, 128, 7, 128, 10},
        {2, 1, 5, 4, 8, 7, 12, 11, 0, 0, 128, 4, 128, 7, 10, 10},
        {2, 1, 5, 4, 9, 8, 11, 128, 0, 0, 128, 4, 7, 7, 128, 128},
        {2, 1, 5, 4, 9, 8, 12, 11, 0, 0, 128, 4, 7, 7, 128, 11},
        {2, 1, 5, 4, 9, 8, 13, 12, 0, 0, 128, 4, 7, 7, 11, 11},
        {2, 1, 6, 5, 8, 128, 10, 128, 0, 0, 4, 4, 128, 128, 128, 128},
        {2, 1, 6, 5, 8, 128, 11, 10, 0, 0, 4, 4, 128, 128, 128, 10},
        {2, 1, 6, 5, 8, 128, 12, 11, 0, 0, 4, 4, 128, 128, 10, 10},
        {2, 1, 6, 5, 9, 8, 11, 128, 0, 0, 4, 4, 128, 8, 128, 128},
        {2, 1, 6, 5, 9, 8, 12, 11, 0, 0, 4, 4, 128, 8, 128, 11},
        {2, 1, 6, 5, 9, 8, 13, 12, 0, 0, 4, 4, 128, 8, 11, 11},
        {2, 1, 6, 5, 10, 9, 12, 128, 0, 0, 4, 4, 8, 8, 128, 128},
        {2, 1, 6, 5, 10, 9, 13, 12, 0, 0, 4, 4, 8, 8, 128, 12},
        {2, 1, 6, 5, 10, 9, 14, 13, 0, 0, 4, 4, 8, 8, 12, 12},
    };
};

} // namespace netaddr

#endif
