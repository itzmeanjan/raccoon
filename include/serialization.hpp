#pragma once
#include "field.hpp"
#include "polynomial.hpp"
#include "prng.hpp"
#include "utils.hpp"
#include <algorithm>
#include <cstdint>
#include <limits>
#include <span>
#include <tuple>

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

// Byte encodes a signature sig = (c_hash, h, z), following section 2.5.1 of the Raccoon specification.
//
// In case signature can *not* be encoded into fixed byte length `sig_byte_len`, it returns false, otherwise
// (i.e. in case of successful signature encoding ) it returns true.
template<size_t k, size_t l, size_t 𝜅, size_t sig_byte_len>
static inline constexpr bool
encode_sig(std::span<const uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> c_hash,
           std::span<const int64_t, k * polynomial::N> h,
           std::span<const int64_t, l * polynomial::N> z,
           std::span<uint8_t, sig_byte_len> sig)
{
  bool encodable = true;
  size_t sig_off = 0;

  std::copy(c_hash.begin(), c_hash.end(), sig.begin());
  sig_off += c_hash.size();

  uint64_t buffer = 0;
  size_t buf_bit_off = 0;

  for (size_t row_idx = 0; row_idx < k; row_idx++) {
    const size_t offset = row_idx * polynomial::N;

    for (size_t coeff_idx = 0; coeff_idx < polynomial::N; coeff_idx++) {
      if (buf_bit_off >= std::numeric_limits<uint8_t>::digits) {
        const size_t writeable_bitcnt = buf_bit_off & (-8ul);
        const size_t writeable_bytecnt = writeable_bitcnt / std::numeric_limits<uint8_t>::digits;

        if ((sig_off + writeable_bytecnt) > sig_byte_len) {
          encodable = false;
          break;
        }

        raccoon_utils::to_le_bytes(buffer, sig.subspan(sig_off, writeable_bytecnt));

        sig_off += writeable_bytecnt;
        buf_bit_off -= writeable_bitcnt;
        buffer >>= writeable_bitcnt;
      }

      const auto x = h[offset + coeff_idx];
      const auto abs_x = static_cast<size_t>(std::abs(x));

      const uint64_t ones = (1ul << abs_x) - 1;

      if (x > 0) {
        buffer |= (((0b00ul << abs_x) | ones) << buf_bit_off);
        buf_bit_off += (abs_x + 2);
      } else if (x < 0) {
        buffer |= (((0b10ul << abs_x) | ones) << buf_bit_off);
        buf_bit_off += (abs_x + 2);
      } else {
        buffer |= (0b0ul << buf_bit_off);
        buf_bit_off += 1;
      }
    }

    if (!encodable) {
      break;
    }
  }

  if (!encodable) {
    return encodable;
  }

  for (size_t row_idx = 0; row_idx < l; row_idx++) {
    const size_t offset = row_idx * polynomial::N;

    for (size_t coeff_idx = 0; coeff_idx < polynomial::N; coeff_idx++) {
      if (buf_bit_off >= std::numeric_limits<uint8_t>::digits) {
        const size_t writeable_bitcnt = buf_bit_off & (-8ul);
        const size_t writeable_bytecnt = writeable_bitcnt / std::numeric_limits<uint8_t>::digits;

        if ((sig_off + writeable_bytecnt) > sig_byte_len) {
          encodable = false;
          break;
        }

        raccoon_utils::to_le_bytes(buffer, sig.subspan(sig_off, writeable_bytecnt));

        sig_off += writeable_bytecnt;
        buf_bit_off -= writeable_bitcnt;
        buffer >>= writeable_bitcnt;
      }

      const auto x = z[offset + coeff_idx];
      const auto abs_x = std::abs(x);

      const auto a = abs_x & ((1l << 40) - 1);
      const auto b = static_cast<size_t>(abs_x >> 40);

      buffer |= (static_cast<uint64_t>(a) << buf_bit_off);
      buf_bit_off += 40;

      const uint64_t ones = (1ul << b) - 1;

      if (x > 0) {
        buffer |= (((0b00ul << b) | ones) << buf_bit_off);
        buf_bit_off += (b + 2);
      } else if (x < 0) {
        buffer |= (((0b10ul << b) | ones) << buf_bit_off);
        buf_bit_off += (b + 2);
      } else {
        buf_bit_off += 1;
      }
    }

    if (!encodable) {
      break;
    }
  }

  if (!encodable) {
    return encodable;
  }

  if (buf_bit_off > 0) {
    const size_t writeable_bitcnt = (buf_bit_off + 7) & (-8ul);
    const size_t writeable_bytecnt = writeable_bitcnt / std::numeric_limits<uint8_t>::digits;

    if ((sig_off + writeable_bytecnt) > sig_byte_len) {
      encodable = false;
      return encodable;
    }

    raccoon_utils::to_le_bytes(buffer, sig.subspan(sig_off, writeable_bytecnt));

    sig_off += writeable_bytecnt;
    buf_bit_off -= writeable_bitcnt;
    buffer >>= writeable_bitcnt;
  }

  std::fill_n(sig.subspan(sig_off).begin(), sig_byte_len - sig_off, 0x00);
  return encodable;
}

// Extracts n -th bit from 64 -bit word s.t. n < 64.
static inline constexpr uint64_t
get_bit_at(const uint64_t word, const size_t idx)
{
  return (word >> idx) & 0b1ul;
}

// Given a 64 -bit buffer s.t. `buf_bit_off` bits, from LSB side, are part of current active buffer, this routine tries to decode
// a small signed integer (which is a coefficient of the hint vector `h`), from those bits, while also returning how many bits were
// consumed during decoding.
static inline constexpr std::pair<int64_t, size_t>
decode_bits_as_hint_coeff(const uint64_t buffer, const size_t buf_bit_off)
{
  int64_t res = 0;
  size_t bit_idx = 0;

  while ((bit_idx < buf_bit_off) && get_bit_at(buffer, bit_idx) == 1) {
    res++;
    bit_idx++;
  }

  // exhaused all available bits
  if (bit_idx == buf_bit_off) {
    return { 0, 0 };
  }

  // skip the stop bit
  bit_idx++;

  // figure out the sign bit
  if (res > 0) {
    if (get_bit_at(buffer, bit_idx) == 1) {
      res = -res;
    }
    bit_idx++;
  }

  return { res, bit_idx };
}

// Given a 64 -bit buffer s.t. `buf_bit_off` bits, from LSB side, are part of the current active buffer area and a 40 -bit unsigned
// integer `a` (i.e. low 40 -bits of the resulting coefficient), this routine tries to decode a small signed integer (which forms the
// high bits of a coefficient of the response vector `z`), from those bits, while returning a signed integer which is ~40 -bits and
// how many bits were consumed for decoding the high part of the coefficient.
static inline constexpr std::pair<int64_t, size_t>
decode_bits_as_response_coeff(const uint64_t buffer, const size_t buf_bit_off, const int64_t a)
{
  int64_t b = 0;
  size_t bit_idx = 0;

  while ((bit_idx < buf_bit_off) && (get_bit_at(buffer, bit_idx) == 1)) {
    b++;
    bit_idx++;
  }

  // exhausted all available bits in the buffer
  if (bit_idx == buf_bit_off) {
    return { a, 0 };
  }

  // skip the stop bit
  bit_idx++;

  // figure out if there is any sign bit that needs to be read
  int64_t res = (b << 40) | a;
  if (res > 0) {
    if (get_bit_at(buffer, bit_idx) == 1) {
      res = -res;
    }
    bit_idx++;
  }

  return { res, bit_idx };
}

// Decodes a byte encoded signature as (c_hash, h, z), following section 2.5.1 of the Raccoon specification.
//
// In case signature decoding fails, it returns false, else it returns true.
template<size_t k, size_t l, size_t 𝜅, size_t sig_byte_len>
static inline constexpr bool
decode_sig(std::span<const uint8_t, sig_byte_len> sig,
           std::span<uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> c_hash,
           std::span<int64_t, k * polynomial::N> h,
           std::span<int64_t, l * polynomial::N> z)
{
  bool decodable = true;
  size_t sig_off = 0;

  std::copy_n(sig.begin(), c_hash.size(), c_hash.begin());
  sig_off += c_hash.size();

  uint64_t buffer = 0;
  size_t buf_bit_off = 0;

  size_t h_coeff_idx = 0;
  while ((sig_off < sig_byte_len) && (h_coeff_idx < h.size())) {
    const size_t bufferable_num_bits = std::numeric_limits<uint64_t>::digits - buf_bit_off;
    const size_t readable_num_bits = bufferable_num_bits & (-8ul);
    const size_t readable_num_bytes = readable_num_bits / std::numeric_limits<uint8_t>::digits;
    const size_t to_be_buffered_num_bytes = std::min(readable_num_bytes, sig_byte_len - sig_off);

    const auto word = raccoon_utils::from_le_bytes<uint64_t>(sig.subspan(sig_off, to_be_buffered_num_bytes));
    buffer |= (word << buf_bit_off);
    buf_bit_off += (to_be_buffered_num_bytes * std::numeric_limits<uint8_t>::digits);

    int64_t coeff = 0;
    size_t bits_consumed = 0;
    std::tie(coeff, bits_consumed) = decode_bits_as_hint_coeff(buffer, buf_bit_off);

    if (bits_consumed > 0) [[likely]] {
      h[h_coeff_idx] = coeff;
      h_coeff_idx++;

      buf_bit_off -= bits_consumed;
      buffer >>= bits_consumed;
    } else {
      decodable = false;
      break;
    }

    sig_off += to_be_buffered_num_bytes;
  }

  if (!decodable) {
    return decodable;
  }

  if ((sig_off == sig_byte_len) || (h_coeff_idx != h.size())) {
    decodable = false;
    return decodable;
  }

  size_t z_coeff_idx = 0;
  while ((sig_off < sig_byte_len) && (z_coeff_idx < z.size())) {
    const size_t bufferable_num_bits = std::numeric_limits<uint64_t>::digits - buf_bit_off;
    const size_t readable_num_bits = bufferable_num_bits & (-8ul);
    const size_t readable_num_bytes = readable_num_bits / std::numeric_limits<uint8_t>::digits;
    const size_t to_be_buffered_num_bytes = std::min(readable_num_bytes, sig_byte_len - sig_off);

    const auto word = raccoon_utils::from_le_bytes<uint64_t>(sig.subspan(sig_off, to_be_buffered_num_bytes));
    buffer |= (word << buf_bit_off);
    buf_bit_off += (to_be_buffered_num_bytes * std::numeric_limits<uint8_t>::digits);

    if (buf_bit_off > 40) [[likely]] {
      constexpr uint64_t mask40 = (1ul << 40) - 1;
      const auto a = static_cast<int64_t>(buffer & mask40);

      buffer >>= 40;
      buf_bit_off -= 40;

      int64_t coeff = 0;
      size_t bits_consumed = 0;
      std::tie(coeff, bits_consumed) = decode_bits_as_response_coeff(buffer, buf_bit_off, a);

      if (bits_consumed > 0) [[likely]] {
        z[z_coeff_idx] = coeff;
        z_coeff_idx++;

        buf_bit_off -= bits_consumed;
        buffer >>= bits_consumed;
      } else {
        decodable = false;
        break;
      }
    }

    sig_off += to_be_buffered_num_bytes;
  }

  if (!decodable) {
    return decodable;
  }

  if (z_coeff_idx != z.size()) {
    decodable = false;
    return decodable;
  }

  if (buf_bit_off > 0) {
    const uint64_t mask = (1ul << buf_bit_off) - 1;
    decodable = ((buffer & mask) == 0);

    buffer >>= buf_bit_off;
    buf_bit_off = 0;
  }

  if (!decodable) {
    return decodable;
  }

  auto remaining_sig = sig.subspan(sig_off, sig_byte_len - sig_off);
  for (auto byte : remaining_sig) {
    decodable &= (byte == 0);
  }

  return decodable;
}

}
