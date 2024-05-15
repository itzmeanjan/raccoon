#pragma once
#include "prng.hpp"
#include "public_key.hpp"

namespace raccoon_skey {

// Raccoon Secret Key
template<size_t 𝜅, size_t k, size_t l, size_t d, size_t 𝜈t>
struct skey_t
{
private:
  raccoon_pkey::pkey_t<𝜅, k, 𝜈t> pkey{};
  raccoon_poly_vec::poly_vec_t<l, d> s{};

  // Serializes masked (d -sharing) NTT domain secret key vector `[[s]]` as bytes, following algorithm 14 of Raccoon specification.
  static inline constexpr void mask_compress(
    const raccoon_poly_vec::poly_vec_t<l, d>& s,
    std::span<uint8_t, ((d - 1) * 𝜅 + l * raccoon_poly::N * field::Q_BIT_WIDTH) / std::numeric_limits<uint8_t>::digits> s_c,
    prng::prng_t& prng)
  {
    raccoon_poly_vec::poly_vec_t<l, 1> x{};

    for (size_t ridx = 0; ridx < x.num_rows(); ridx++) {
      x[ridx][0] = s[ridx][0];
    }

    for (size_t sidx = 1; sidx < d; sidx++) {
      std::array<uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> z{};
      raccoon_poly::poly_t r{};

      const size_t s_c_off = (sidx - 1) * z.size();

      prng.read(z);
      std::copy_n(z.begin(), z.size(), s_c.subspan(s_c_off).begin());

      for (size_t ridx = 0; ridx < x.num_rows(); ridx++) {
        uint64_t hdr = 0;
        hdr |= (static_cast<uint64_t>(ridx) << 16) | (static_cast<uint64_t>(sidx) << 8) | (static_cast<uint64_t>('K') << 0);

        r.sampleQ<𝜅>(std::span<const uint8_t, sizeof(hdr)>(reinterpret_cast<uint8_t*>(&hdr), sizeof(hdr)), z);

        x[ridx][0] -= r;
      }

      for (size_t ridx = 0; ridx < x.num_rows(); ridx++) {
        x[ridx][0] += s[ridx][sidx];
      }
    }

    size_t s_c_off = ((d - 1) * 𝜅) / 8;
    for (size_t ridx = 0; ridx < x.num_rows(); ridx++) {
      constexpr uint64_t mask49 = (1ul << field::Q_BIT_WIDTH) - 1;

      uint64_t buffer = 0;
      size_t buf_bit_off = 0;
      size_t coeff_idx = 0;

      while (coeff_idx < raccoon_poly::N) {
        buffer |= (x[ridx][0][coeff_idx].raw() & mask49) << buf_bit_off;
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
  static inline constexpr raccoon_poly_vec::poly_vec_t<l, d> mask_decompress(
    std::span<const uint8_t, ((d - 1) * 𝜅 + l * raccoon_poly::N * field::Q_BIT_WIDTH) / 8> s_c)
  {
    raccoon_poly_vec::poly_vec_t<l, d> s{};

    size_t s_c_off = ((d - 1) * 𝜅) / 8;
    for (size_t ridx = 0; ridx < s.num_rows(); ridx++) {
      constexpr uint64_t mask49 = (1ul << field::Q_BIT_WIDTH) - 1;

      uint64_t buffer = 0;
      size_t buf_bit_off = 0;
      size_t coeff_idx = 0;

      while (coeff_idx < raccoon_poly::N) {
        const size_t bits_needed = field::Q_BIT_WIDTH - buf_bit_off;
        const size_t bits_to_be_read = (bits_needed + 7) & (-8ul);
        const size_t bytes_to_be_read = bits_to_be_read / std::numeric_limits<uint8_t>::digits;

        buffer |= raccoon_utils::from_le_bytes<uint64_t>(s_c.subspan(s_c_off, bytes_to_be_read)) << buf_bit_off;
        buf_bit_off += bits_to_be_read;

        s[ridx][0][coeff_idx] = field::zq_t(buffer & mask49);

        buffer >>= field::Q_BIT_WIDTH;
        buf_bit_off -= field::Q_BIT_WIDTH;

        s_c_off += bytes_to_be_read;
        coeff_idx++;
      }
    }

    for (size_t sidx = 1; sidx < d; sidx++) {
      const size_t s_c_off = (sidx - 1) * (𝜅 / 8);

      for (size_t ridx = 0; ridx < s.num_rows(); ridx++) {
        uint64_t hdr = 0;
        hdr |= (static_cast<uint64_t>(ridx) << 16) | (static_cast<uint64_t>(sidx) << 8) | (static_cast<uint64_t>('K') << 0);

        s[ridx][sidx].template sampleQ<𝜅>(std::span<const uint8_t, sizeof(hdr)>(reinterpret_cast<uint8_t*>(&hdr), sizeof(hdr)),
                                          std::span<const uint8_t, 𝜅 / 8>(s_c.subspan(s_c_off, 𝜅 / 8)));
      }
    }

    return s;
  }

public:
  // Constructor(s)
  inline constexpr skey_t() = default;
  inline constexpr skey_t(raccoon_pkey::pkey_t<𝜅, k, 𝜈t>& pkey, raccoon_poly_vec::poly_vec_t<l, d>& s)
  {
    this->pkey = pkey;
    this->s = s;
  }

  // Accessor(s)
  inline constexpr const raccoon_pkey::pkey_t<𝜅, k, 𝜈t>& get_pkey_mut() const { return this->pkey; }
  inline constexpr const raccoon_poly_vec::poly_vec_t<l, d>& get_s_mut() const { return this->s; }

  // Returns byte length of the serialized secret key.
  static inline constexpr size_t get_byte_len() { return raccoon_utils::get_skey_byte_len<𝜅, k, l, d, raccoon_poly::N, 𝜈t>(); }

  // Byte serializes the secret key, which includes a copy of the public key.
  inline constexpr void to_bytes(std::span<uint8_t, get_byte_len()> bytes, prng::prng_t& prng) const
  {
    constexpr size_t skoff0 = 0;
    constexpr size_t skoff1 = skoff0 + pkey.get_byte_len();
    constexpr size_t skoff2 = skoff1 + (bytes.size() - pkey.get_byte_len());

    this->pkey.to_bytes(bytes.template subspan<skoff0, skoff1 - skoff0>());
    mask_compress(this->s, bytes.template subspan<skoff1, skoff2 - skoff1>(), prng);
  }

  // Given a byte serialized secret key, this routine helps in deserializing it, producing components ((seed, t), [[s]]).
  static inline constexpr skey_t from_bytes(std::span<const uint8_t, get_byte_len()> bytes)
  {
    constexpr size_t pklen = raccoon_pkey::pkey_t<𝜅, k, 𝜈t>::get_byte_len();
    constexpr size_t skoff0 = 0;
    constexpr size_t skoff1 = skoff0 + pklen;
    constexpr size_t skoff2 = skoff1 + (bytes.size() - pklen);

    skey_t<𝜅, k, l, d, 𝜈t> skey{};

    skey.pkey = raccoon_pkey::pkey_t<𝜅, k, 𝜈t>::from_bytes(bytes.template subspan<skoff0, skoff1 - skoff0>());
    skey.s = mask_decompress(bytes.template subspan<skoff1, skoff2 - skoff1>());

    return skey;
  }
};

}
