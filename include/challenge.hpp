#pragma once
#include "polynomial.hpp"
#include "shake256.hpp"
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
chal_hash(std::span<const polynomial::polynomial_t, k> w, std::span<const uint8_t, (2 * 𝜅) / 8> 𝜇, std::span<uint8_t, (2 * 𝜅) / 8> c_hash)
{
  shake256::shake256_t xof;

  std::array<uint8_t, shake256::RATE / std::numeric_limits<uint8_t>::digits> buffer{};
  auto _buffer = std::span(buffer);
  size_t buf_off = 0;

  std::array<uint8_t, sizeof(uint64_t)> hdr{};
  std::fill(hdr.begin(), hdr.end(), 0x00);
  hdr[0] = 'h';
  hdr[1] = k;

  std::copy(hdr.begin(), hdr.end(), _buffer.begin());
  buf_off += hdr.size();

  constexpr size_t coeff_cnt = w.size() * polynomial::N;
  size_t coeff_idx = 0;

  while (coeff_idx < coeff_cnt) {
    if (buf_off == _buffer.size()) {
      xof.absorb(_buffer);
    }

    _buffer[buf_off] = w[coeff_idx / polynomial::N][coeff_idx % polynomial::N];

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

}
