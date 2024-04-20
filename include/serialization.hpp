#pragma once
#include "field.hpp"
#include "prng.hpp"
#include "sampling.hpp"
#include "utils.hpp"

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

// Serializes masked (d -sharing) NTT domain secret key vector `[[s]]` as bytes, following algorithm 14 of Raccoon specification.
template<size_t 𝜅, size_t l, size_t d, size_t n>
static inline constexpr void
mask_compress(std::span<field::zq_t, l * d * n> s, std::span<uint8_t, ((d - 1) * 𝜅 + l * n * field::Q_BIT_WIDTH) / 8> s_c, prng::prng_t& prng)
{
  std::array<field::zq_t, l * n> x{};
  auto _x = std::span(x);

  for (size_t ridx = 0; ridx < l; ridx++) {
    const size_t s_off = ridx * (d * n);
    const size_t d_off = ridx * n;

    std::copy_n(s.subspan(s_off).begin(), n, _x.subspan(d_off).begin());
  }

  for (size_t sidx = 1; sidx < d; sidx++) {
    std::array<uint8_t, 𝜅 / 8> z{};
    std::array<field::zq_t, n> r{};

    const size_t s_c_off = (sidx - 1) * z.size();

    prng.read(z);
    std::copy_n(z.begin(), z.size(), s_c.subspan(s_c_off).begin());

    for (size_t ridx = 0; ridx < l; ridx++) {
      const size_t x_off = ridx * n;

      uint64_t hdr = 0;
      hdr |= (static_cast<uint64_t>(ridx) << 16) | (static_cast<uint64_t>(sidx) << 8) | (static_cast<uint64_t>('K') << 0);

      sampling::sampleQ<n, 𝜅>(std::span<const uint8_t, sizeof(hdr)>(reinterpret_cast<uint8_t*>(hdr), sizeof(hdr)), z, r);

      for (size_t coeff_idx = 0; coeff_idx < r.size(); coeff_idx++) {
        _x[x_off + coeff_idx] -= r[coeff_idx];
      }
    }

    for (size_t ridx = 0; ridx < l; ridx++) {
      const size_t s_off = ridx * (d * n) + sidx * n;
      const size_t x_off = ridx * n;

      for (size_t coeff_idx = 0; coeff_idx < n; coeff_idx++) {
        _x[x_off + coeff_idx] += s[s_off + coeff_idx];
      }
    }
  }

  size_t s_c_off = ((d - 1) * 𝜅) / 8;
  for (size_t ridx = 0; ridx < l; ridx++) {
    const size_t x_off = ridx * n;

    constexpr uint64_t mask49 = (1ul << field::Q_BIT_WIDTH) - 1;

    uint64_t buffer = 0;
    size_t buf_bit_off = 0;
    size_t coeff_idx = 0;

    while (coeff_idx < n) {
      buffer |= (_x[x_off + coeff_idx].raw() & mask49) << buf_bit_off;
      buf_bit_off += field::Q_BIT_WIDTH;

      const size_t writeable_bitcnt = buf_bit_off & (-8ul);
      const size_t writeable_bitmask = (1ul << writeable_bitcnt) - 1;
      const size_t writeable_bytecnt = writeable_bitcnt / std::numeric_limits<uint8_t>::digits;

      std::copy_n(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(buffer & writeable_bitmask), writeable_bytecnt).begin(),
                  writeable_bytecnt,
                  s_c.subspan(s_c_off).begin());

      buffer >>= writeable_bitcnt;
      buf_bit_off -= writeable_bitcnt;
      coeff_idx++;

      s_c_off += writeable_bytecnt;
    }
  }
}

}
