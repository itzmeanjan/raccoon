#pragma once
#include "poly_vec.hpp"
#include "shake256.hpp"

// Challenge computation
namespace raccoon_challenge {

// Computes `2 * 𝜅` -bit digest of the commitment vector `w` and message, to be signed, hash 𝜇 (which is bound to the public key),
// following algorithm 9 of the Raccoon specification.
template<size_t k, size_t 𝜅>
static inline constexpr void
chal_hash(const raccoon_poly_vec::poly_vec_t<k, 1>& w,
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

  constexpr size_t coeff_cnt = w.num_rows() * raccoon_poly::N;
  size_t w_idx = 0;

  while (w_idx < coeff_cnt) {
    if (buf_off == _buffer.size()) {
      xof.absorb(_buffer);
      buf_off = 0;
    }

    const size_t row_idx = w_idx / raccoon_poly::N;
    const size_t coeff_idx = w_idx % raccoon_poly::N;

    _buffer[buf_off] = static_cast<uint8_t>(w[row_idx][0][coeff_idx].raw());

    buf_off++;
    w_idx++;
  }

  if (buf_off > 0) {
    xof.absorb(_buffer.subspan(0, buf_off));
    buf_off = 0;
  }

  xof.absorb(𝜇);
  xof.finalize();
  xof.squeeze(c_hash);
  xof.reset();
}

}
