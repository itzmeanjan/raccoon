#pragma once
#include "field.hpp"
#include "utils.hpp"
#include <algorithm>
#include <bit>
#include <limits>

namespace serialization {

// Given a public key of form (seed, t), this routine helps in serializing it, producing a byte array.
template<size_t 𝜅, size_t k, size_t n, size_t 𝜈t>
static inline constexpr void
encode_public_key(std::span<const uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> seed,
                  std::span<const field::zq_t, k * n> t,
                  std::span<uint8_t, raccoon_utils::get_pkey_byte_len<𝜅, k, n, 𝜈t>()> pkey)
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
    if (buf_sig_bitcnt == buf_max_sig_bitcnt) {
      raccoon_utils::to_le_bytes(buffer, pkey.subspan(pkey_idx, buf_max_sig_bytes));

      pkey_idx += buf_max_sig_bytes;
      buf_sig_bitcnt = 0;
      buffer = 0;
    }

    buffer |= (t[t_idx].raw() & coeff_sig_bitmask) << buf_sig_bitcnt;
    buf_sig_bitcnt += coeff_sig_bitcnt;

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
template<size_t 𝜅, size_t k, size_t n, size_t 𝜈t>
static inline constexpr void
decode_public_key(std::span<const uint8_t, raccoon_utils::get_pkey_byte_len<𝜅, k, n, 𝜈t>()> pkey,
                  std::span<uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> seed,
                  std::span<field::zq_t, k * n> t)
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
      t[t_idx] = field::zq_t(buffer & coeff_sig_bitmask);
      buffer >>= coeff_sig_bitcnt;

      t_idx++;
    }
  }
}

}
