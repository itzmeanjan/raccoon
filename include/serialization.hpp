#pragma once
#include "field.hpp"
#include "polynomial.hpp"
#include "prng.hpp"
#include "sampling.hpp"
#include "utils.hpp"
#include <limits>

namespace serialization {

// Given a public key of form (seed, t), this routine helps in serializing it, producing a byte array.
template<size_t 𝜅, size_t k, size_t 𝜈t>
static inline constexpr void
encode_public_key(std::span<const uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> seed,
                  std::span<const polynomial::polynomial_t, k> t,
                  std::span<uint8_t, raccoon_utils::get_pkey_byte_len<𝜅, k, polynomial::N, 𝜈t>()> pkey)
{
  // Serialize `seed`
  std::copy_n(seed.begin(), seed.size(), pkey.begin());

  // Serialize `t`
  constexpr size_t coeff_sig_bitcnt = field::Q_BIT_WIDTH - 𝜈t;
  constexpr uint64_t coeff_sig_bitmask = (1ul << coeff_sig_bitcnt) - 1;

  constexpr size_t buf_max_sig_bitcnt = std::lcm(coeff_sig_bitcnt, std::numeric_limits<uint8_t>::digits);
  constexpr size_t buf_max_sig_bytes = buf_max_sig_bitcnt / std::numeric_limits<uint8_t>::digits;

  size_t t_idx = 0;
  size_t pkey_idx = seed.size();

  size_t buf_sig_bitcnt = 0;
  uint64_t buffer = 0;

  static_assert(buf_max_sig_bytes <= sizeof(buffer), "Can't serialize public key into bytes using this method !");

  while (t_idx < t.size()) {
    for (size_t c_idx = 0; c_idx < polynomial::N; c_idx++) {
      if (buf_sig_bitcnt == buf_max_sig_bitcnt) {
        raccoon_utils::to_le_bytes(buffer, pkey.subspan(pkey_idx, buf_max_sig_bytes));

        pkey_idx += buf_max_sig_bytes;
        buf_sig_bitcnt = 0;
        buffer = 0;
      }

      buffer |= (t[t_idx][c_idx].raw() & coeff_sig_bitmask) << buf_sig_bitcnt;
      buf_sig_bitcnt += coeff_sig_bitcnt;
    }

    t_idx++;
  }

  if (buf_sig_bitcnt == buf_max_sig_bitcnt) {
    raccoon_utils::to_le_bytes(buffer, pkey.subspan(pkey_idx, buf_max_sig_bytes));

    pkey_idx += buf_max_sig_bytes;
    buf_sig_bitcnt = 0;
    buffer = 0;
  }
}

// Given a serialized public key, thir routine helps in deserializing it, producing (seed, t).
template<size_t 𝜅, size_t k, size_t 𝜈t>
static inline constexpr void
decode_public_key(std::span<const uint8_t, raccoon_utils::get_pkey_byte_len<𝜅, k, polynomial::N, 𝜈t>()> pkey,
                  std::span<uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> seed,
                  std::span<polynomial::polynomial_t, k> t)
{
  // Deserialize `seed`
  std::copy_n(pkey.begin(), seed.size(), seed.begin());

  // Deserialize `t`
  constexpr size_t coeff_sig_bitcnt = field::Q_BIT_WIDTH - 𝜈t;
  constexpr uint64_t coeff_sig_bitmask = (1ul << coeff_sig_bitcnt) - 1;

  constexpr size_t buf_max_sig_bitcnt = std::lcm(coeff_sig_bitcnt, std::numeric_limits<uint8_t>::digits);
  constexpr size_t buf_max_sig_bytes = buf_max_sig_bitcnt / std::numeric_limits<uint8_t>::digits;
  constexpr size_t dec_coeffs_per_round = buf_max_sig_bitcnt / coeff_sig_bitcnt;

  size_t t_idx = 0;
  size_t pkey_idx = seed.size();

  static_assert(buf_max_sig_bitcnt <= std::numeric_limits<uint64_t>::digits, "Can't deserialize public key from bytes using this method !");

  while (pkey_idx < pkey.size()) {
    auto buffer = raccoon_utils::from_le_bytes<uint64_t>(pkey.subspan(pkey_idx, buf_max_sig_bytes));
    pkey_idx += buf_max_sig_bytes;

    for (size_t i = 0; i < dec_coeffs_per_round; i++) {
      t[t_idx >> polynomial::LOG2N][t_idx & (polynomial::N - 1)] = field::zq_t(buffer & coeff_sig_bitmask);
      buffer >>= coeff_sig_bitcnt;

      t_idx++;
    }
  }
}

// Serializes masked (d -sharing) NTT domain secret key vector `[[s]]` as bytes, following algorithm 14 of Raccoon specification.
template<size_t 𝜅, size_t l, size_t d>
static inline constexpr void
mask_compress(std::span<const polynomial::polynomial_t, l * d> s,
              std::span<uint8_t, ((d - 1) * 𝜅 + l * polynomial::N * field::Q_BIT_WIDTH) / 8> s_c,
              prng::prng_t& prng)
{
  std::array<polynomial::polynomial_t, l> x{};
  for (size_t ridx = 0; ridx < l; ridx++) {
    x[ridx].copy_from(s[ridx * d]);
  }

  for (size_t sidx = 1; sidx < d; sidx++) {
    std::array<uint8_t, 𝜅 / 8> z{};
    polynomial::polynomial_t r{};

    const size_t s_c_off = (sidx - 1) * z.size();

    prng.read(z);
    std::copy_n(z.begin(), z.size(), s_c.subspan(s_c_off).begin());

    for (size_t ridx = 0; ridx < l; ridx++) {
      uint64_t hdr = 0;
      hdr |= (static_cast<uint64_t>(ridx) << 16) | (static_cast<uint64_t>(sidx) << 8) | (static_cast<uint64_t>('K') << 0);

      r.sampleQ<𝜅>(std::span<const uint8_t, sizeof(hdr)>(reinterpret_cast<uint8_t*>(&hdr), sizeof(hdr)), z);

      x[ridx] -= r;
    }

    for (size_t ridx = 0; ridx < l; ridx++) {
      x[ridx] += s[(ridx * d) + sidx];
    }
  }

  size_t s_c_off = ((d - 1) * 𝜅) / 8;
  for (size_t ridx = 0; ridx < l; ridx++) {
    constexpr uint64_t mask49 = (1ul << field::Q_BIT_WIDTH) - 1;

    uint64_t buffer = 0;
    size_t buf_bit_off = 0;
    size_t coeff_idx = 0;

    while (coeff_idx < polynomial::N) {
      buffer |= (x[ridx][coeff_idx].raw() & mask49) << buf_bit_off;
      buf_bit_off += field::Q_BIT_WIDTH;

      const size_t writeable_bitcnt = buf_bit_off & (-8ul);
      const size_t writeable_bytecnt = writeable_bitcnt / std::numeric_limits<uint8_t>::digits;

      std::copy_n(std::span<const uint8_t>(reinterpret_cast<uint8_t*>(&buffer), writeable_bytecnt).begin(), writeable_bytecnt, s_c.subspan(s_c_off).begin());

      buffer >>= writeable_bitcnt;
      buf_bit_off -= writeable_bitcnt;
      coeff_idx++;

      s_c_off += writeable_bytecnt;
    }
  }
}

// Deserializes bytes into masked (d -sharing) NTT domain secret key vector `[[s]]`, following algorithm 15 of Raccoon specification.
template<size_t 𝜅, size_t l, size_t d>
static inline constexpr void
mask_decompress(std::span<const uint8_t, ((d - 1) * 𝜅 + l * polynomial::N * field::Q_BIT_WIDTH) / 8> s_c, std::span<polynomial::polynomial_t, l * d> s)
{
  size_t s_c_off = ((d - 1) * 𝜅) / 8;
  for (size_t ridx = 0; ridx < l; ridx++) {
    constexpr uint64_t mask49 = (1ul << field::Q_BIT_WIDTH) - 1;

    uint64_t buffer = 0;
    size_t buf_bit_off = 0;
    size_t coeff_idx = 0;

    while (coeff_idx < polynomial::N) {
      const size_t bits_needed = field::Q_BIT_WIDTH - buf_bit_off;
      const size_t bits_to_be_read = (bits_needed + 7) & (-8ul);
      const size_t bytes_to_be_read = bits_to_be_read / std::numeric_limits<uint8_t>::digits;

      buffer |= raccoon_utils::from_le_bytes<uint64_t>(s_c.subspan(s_c_off, bytes_to_be_read)) << buf_bit_off;
      buf_bit_off += bits_to_be_read;

      s[ridx * d][coeff_idx] = field::zq_t(buffer & mask49);

      buffer >>= field::Q_BIT_WIDTH;
      buf_bit_off -= field::Q_BIT_WIDTH;

      s_c_off += bytes_to_be_read;
      coeff_idx++;
    }
  }

  for (size_t sidx = 1; sidx < d; sidx++) {
    const size_t s_c_off = (sidx - 1) * (𝜅 / 8);

    for (size_t ridx = 0; ridx < l; ridx++) {
      uint64_t hdr = 0;
      hdr |= (static_cast<uint64_t>(ridx) << 16) | (static_cast<uint64_t>(sidx) << 8) | (static_cast<uint64_t>('K') << 0);

      s[(ridx * d) + sidx].template sampleQ<𝜅>(std::span<const uint8_t, sizeof(hdr)>(reinterpret_cast<uint8_t*>(&hdr), sizeof(hdr)),
                                               std::span<const uint8_t, 𝜅 / 8>(s_c.subspan(s_c_off, 𝜅 / 8)));
    }
  }
}

}
