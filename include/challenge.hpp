#pragma once
#include "field.hpp"
#include "polynomial.hpp"
#include "shake256.hpp"
#include "utils.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <span>

// Challenge computation
namespace challenge {

// Computes `2 * 𝜅` -bit digest of the commitment vector `w` and message, to be signed, hash 𝜇 (which is bound to the public key),
// following algorithm 9 of the Raccoon specification.
template<size_t k, size_t 𝜅>
static inline constexpr void
chal_hash(std::span<const polynomial::polynomial_t, k> w,
          std::span<const uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> 𝜇,
          std::span<uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> c_hash)
{
  shake256::shake256_t xof;

  std::array<uint8_t, shake256::RATE / std::numeric_limits<uint8_t>::digits> buffer{};
  auto _buffer = std::span(buffer);
  size_t buf_off = 0;

  std::array<uint8_t, sizeof(uint64_t)> hdr{};
  hdr[0] = 'h';
  hdr[1] = k;

  std::copy(hdr.begin(), hdr.end(), _buffer.begin());
  buf_off += hdr.size();

  constexpr size_t coeff_cnt = w.size() * polynomial::N;
  size_t coeff_idx = 0;

  while (coeff_idx < coeff_cnt) {
    if (buf_off == _buffer.size()) {
      xof.absorb(_buffer);
      buf_off = 0;
    }

    _buffer[buf_off] = static_cast<uint8_t>(w[coeff_idx / polynomial::N][coeff_idx % polynomial::N].raw());

    buf_off++;
    coeff_idx++;
  }

  if (buf_off > 0) {
    xof.absorb(_buffer.subspan(0, buf_off));
    buf_off = 0;
  }

  xof.absorb(𝜇);
  xof.finalize();
  xof.squeeze(c_hash);
}

// Expands a `2 * 𝜅` -bit challenge hash into a polynomial such that exactly `𝜔` -many of coefficients are set to +1/ -1,
// while others are set to 0, following algorithm 10 of the Raccoon specification.
template<size_t 𝜅, size_t 𝜔>
static inline constexpr polynomial::polynomial_t
chal_poly(std::span<const uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> c_hash)
{
  polynomial::polynomial_t c_poly{};
  shake256::shake256_t xof;

  std::array<uint8_t, sizeof(uint64_t)> hdr{};
  hdr[0] = 'c';
  hdr[1] = 𝜔;

  xof.absorb(hdr);
  xof.absorb(c_hash);
  xof.finalize();

  constexpr uint16_t mask = (1u << polynomial::LOG2N) - 1;
  size_t non_zero_coeff_cnt = 0;

  while (non_zero_coeff_cnt < 𝜔) {
    std::array<uint8_t, sizeof(uint16_t)> b{};
    xof.squeeze(b);

    const auto b_word = raccoon_utils::from_le_bytes<uint16_t>(b);
    const auto b_0 = b_word & 0b1u;
    const auto i = static_cast<uint16_t>(b_word >> 1u) & mask;

    if (c_poly[i] == 0) {
      c_poly[i] = field::zq_t::one() - field::zq_t(2 * b_0);
      non_zero_coeff_cnt += 1;
    }
  }

  return c_poly;
}

}
