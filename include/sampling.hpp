#pragma once
#include "field.hpp"
#include "shake256.hpp"
#include "utils.hpp"
#include <array>
#include <cstdint>
#include <span>

namespace sampling {

// Given a 64 -bit header and `𝜅` -bits seed as input, this routine can be used for mapping them to a degree n-1 polynomial f.
// This routine is invoked when expanding seed for computing matrix A.
template<size_t n, size_t 𝜅>
static inline void
sampleQ(std::span<const uint8_t, 8> hdr, std::span<const uint8_t, 𝜅 / 8> 𝜎, std::span<field::zq_t, n> f)
{
  shake256::shake256_t xof;
  xof.absorb(hdr);
  xof.absorb(𝜎);
  xof.finalize();

  for (size_t i = 0; i < n; i++) {
    uint64_t f_i = 0;

    do {
      std::array<uint8_t, (field::Q_BIT_WIDTH + 7) / 8> b{};
      xof.squeeze(b);

      constexpr uint64_t mask49 = (1ul << field::Q_BIT_WIDTH) - 1ul;

      const auto b_word = raccoon_utils::from_le_bytes<uint64_t>(b);
      f_i = b_word & mask49;
    } while (f_i >= field::Q);

    f[i] = f_i;
  }
}

}
