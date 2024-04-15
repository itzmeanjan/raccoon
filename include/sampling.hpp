#pragma once
#include "field.hpp"
#include "gadgets.hpp"
#include "mrng.hpp"
#include "prng.hpp"
#include "shake256.hpp"
#include "subtle.hpp"
#include "utils.hpp"
#include <array>
#include <cstdint>
#include <span>

namespace sampling {

// Given a 64 -bit header and `𝜅` -bits seed as input, this routine is used for mapping them to a degree n-1 polynomial f, following algorithm 5 of
// https://raccoonfamily.org/wp-content/uploads/2023/07/raccoon.pdf.
//
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

// Given `𝜅` -bits seed as input, this routine is used for generating public matrix A, following algorithm 6 of
// https://raccoonfamily.org/wp-content/uploads/2023/07/raccoon.pdf.
template<size_t k, size_t l, size_t n, size_t 𝜅>
static inline void
expandA(std::span<const uint8_t, 𝜅 / 8> seed, std::span<field::zq_t, k * l * n> A)
{
  for (size_t i = 0; i < k; i++) {
    for (size_t j = 0; j < l; j++) {

      uint64_t hdr = 0;
      hdr |= (static_cast<uint64_t>(j) << 16) | (static_cast<uint64_t>(i) << 8) | (static_cast<uint64_t>('A') << 0);

      const size_t poly_off = (i * l + j) * n;
      auto poly = std::span<field::zq_t, n>(A.subspan(poly_off, n));

      sampleQ<n, 𝜅>(std::span<const uint8_t, sizeof(hdr)>(reinterpret_cast<uint8_t*>(hdr), sizeof(hdr)), seed, poly);
    }
  }
}

// Given a 64 -bit header and `𝜅` -bits seed as input, this routine is used for uniform sampling a degree `n` polynomial s.t. each of its
// coefficients ∈ [-2^(u-1), 2^(u-1)), following algorithm 7 of https://raccoonfamily.org/wp-content/uploads/2023/07/raccoon.pdf.
template<size_t n, size_t u, size_t 𝜅>
static inline void
sampleU(std::span<const uint8_t, 8> hdr, std::span<const uint8_t, 𝜅 / 8> 𝜎, std::span<int64_t, n> f)
  requires(u > 0)
{
  shake256::shake256_t xof;
  xof.absorb(hdr);
  xof.absorb(𝜎);
  xof.finalize();

  constexpr uint64_t mask_msb = 1ul << (u - 1);
  constexpr uint64_t mask_lsb = mask_msb - 1;

  constexpr size_t squeezable_bytes = (u + 7) / 8;
  std::array<uint8_t, squeezable_bytes> b{};

  for (size_t i = 0; i < n; i++) {
    xof.squeeze(b);

    const uint64_t b_word = raccoon_utils::from_le_bytes<uint64_t>(b);
    const auto msb = static_cast<int64_t>(b_word & mask_msb);
    const auto lsb = static_cast<int64_t>(b_word & mask_lsb);

    const auto f_i = lsb - msb;
    f[i] = f_i;
  }
}

// Adds small uniform noise to each share of the `d` -sharing (masked) polynomial `a` s.t. `row_cnt` of them make up the input polynomial vector `v`, while
// implementing Sum of Uniforms (SU) distribution in masked domain, following algorithm 8 of https://raccoonfamily.org/wp-content/uploads/2023/07/raccoon.pdf.
//
// Each time noise is added polynomials are refreshed and this operation is repeated `rep` -many times.
template<size_t row_cnt, size_t d, size_t n, size_t u, size_t rep, size_t 𝜅>
static inline void
add_rep_noise(std::span<field::zq_t, row_cnt * n * d> vec, prng::prng_t& prng, mrng::mrng_t<d>& mrng)
{
  std::array<uint8_t, 𝜅 / 8> 𝜎{};
  std::array<int64_t, n> poly_u{};

  for (size_t i = 0; i < row_cnt; i++) {
    const size_t row_begin = i * (n * d);

    for (size_t i_rep = 0; i_rep < rep; i_rep++) {
      for (size_t j = 0; j < d; j++) {
        const size_t share_begin = row_begin + (j * n);

        prng.read(𝜎);

        uint64_t hdr_u = 0;
        hdr_u |= (static_cast<uint64_t>(j) << 24) | (static_cast<uint64_t>(i) << 16) | (static_cast<uint64_t>(i_rep) << 8) | (static_cast<uint64_t>('u') << 0);

        sampleU<n, u, 𝜅>(std::span<const uint8_t, sizeof(hdr_u)>(reinterpret_cast<uint8_t*>(&hdr_u), sizeof(hdr_u)), 𝜎, poly_u);

        for (size_t k = 0; k < n; k++) {
          const auto coeff = static_cast<int64_t>(vec[share_begin + k].raw()) + poly_u[k];

          const auto is_lt_zero = -(static_cast<uint64_t>(coeff) >> ((sizeof(coeff) * 8) - 1));
          const auto is_ge_q = subtle::ct_ge<uint64_t, uint64_t>(static_cast<uint64_t>(coeff & ~is_lt_zero), field::Q);

          const auto normalized_coeff = static_cast<uint64_t>(static_cast<int64_t>(field::Q & is_lt_zero) + coeff - static_cast<int64_t>(field::Q & is_ge_q));

          vec[share_begin + k] = field::zq_t(normalized_coeff);
        }
      }

      gadgets::refresh<d, n>(std::span<field::zq_t, n * d>(vec.subspan(row_begin, n * d)), mrng);
    }
  }
}

}
