#pragma once
#include "poly_vec.hpp"
#include "serialization.hpp"
#include "utils.hpp"

namespace raccoon_pkey {

// Raccoon Public Key
template<size_t 𝜅, size_t k, size_t 𝜈t>
struct pkey_t
{
private:
  std::array<uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> seed{};
  raccoon_poly_vec::poly_vec_t<k, 1> t{};

public:
  // Constructor(s)
  inline constexpr pkey_t() = default;
  inline constexpr pkey_t(std::span<const uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> seed, const raccoon_poly_vec::poly_vec_t<k, 1>& t)
  {
    std::copy(seed.begin(), seed.end(), this->seed.begin());
    this->t = t;
  }

  // Accessor(s)
  inline constexpr std::span<const uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> get_seed() const { return this->seed; }
  inline constexpr std::span<uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> get_seed() { return this->seed; }

  inline constexpr const raccoon_poly_vec::poly_vec_t<k, 1>& get_t() const { return this->t; }
  inline constexpr raccoon_poly_vec::poly_vec_t<k, 1>& get_t() { return this->t; }

  // Returns byte length of the serialized public key.
  static inline constexpr size_t get_byte_len() { return raccoon_utils::get_pkey_byte_len<𝜅, k, raccoon_poly::N, 𝜈t>(); }

  // [Constant-time] Checks for equality of two public keys.
  inline constexpr bool operator==(const pkey_t& rhs) const
  {
    bool res = true;

    for (size_t i = 0; i < this->get_seed().size(); i++) {
      res &= (this->get_seed()[i] == rhs.get_seed()[i]);
    }
    res &= (this->get_t_mut() == rhs.get_t_mut());

    return res;
  }

  // Byte serializes the public key.
  inline constexpr void to_bytes(std::span<uint8_t, get_byte_len()> bytes) const
  {
    raccoon_serialization::encode_public_key<𝜅, k, 𝜈t>(this->seed, this->t, bytes);
  }

  // Given a byte serialized public key, this routine helps in deserializing it, producing components (seed, t).
  static inline constexpr pkey_t from_bytes(std::span<const uint8_t, get_byte_len()> bytes)
  {
    pkey_t<𝜅, k, 𝜈t> pkey{};
    raccoon_serialization::decode_public_key<𝜅, k, 𝜈t>(bytes, pkey.get_seed_mut(), pkey.get_t_mut());
    return pkey;
  }
};

}
