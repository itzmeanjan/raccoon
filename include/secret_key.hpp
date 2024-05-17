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

  // [Constant-time] Checks for equality of two secret keys.
  inline constexpr bool operator==(const skey_t& rhs) const
  {
    bool res = true;

    res &= (this->get_pkey_mut() == rhs.get_pkey_mut());
    res &= (this->get_s_mut() == rhs.get_s_mut());

    return res;
  }

  // Byte serializes the secret key, which includes a copy of the public key.
  inline constexpr void to_bytes(std::span<uint8_t, get_byte_len()> bytes, prng::prng_t& prng) const
  {
    constexpr size_t skoff0 = 0;
    constexpr size_t skoff1 = skoff0 + pkey.get_byte_len();
    constexpr size_t skoff2 = skoff1 + (bytes.size() - pkey.get_byte_len());

    this->pkey.to_bytes(bytes.template subspan<skoff0, skoff1 - skoff0>());
    raccoon_serialization::mask_compress<𝜅, l, d>(this->s, bytes.template subspan<skoff1, skoff2 - skoff1>(), prng);
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
    skey.s = raccoon_serialization::mask_decompress<𝜅, l, d>(bytes.template subspan<skoff1, skoff2 - skoff1>());

    return skey;
  }
};

}
