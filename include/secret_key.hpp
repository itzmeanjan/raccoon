#pragma once
#include "mrng.hpp"
#include "params.hpp"
#include "poly_mat.hpp"
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
  inline constexpr skey_t(const raccoon_pkey::pkey_t<𝜅, k, 𝜈t>& pkey, const raccoon_poly_vec::poly_vec_t<l, d>& s)
  {
    this->pkey = pkey;
    this->s = s;
  }

  // Accessor(s)
  inline constexpr const raccoon_pkey::pkey_t<𝜅, k, 𝜈t>& get_pkey() const { return this->pkey; }
  inline constexpr raccoon_pkey::pkey_t<𝜅, k, 𝜈t>& get_pkey() { return this->pkey; }

  inline constexpr const raccoon_poly_vec::poly_vec_t<l, d>& get_s() const { return this->s; }
  inline constexpr raccoon_poly_vec::poly_vec_t<l, d>& get_s() { return this->s; }

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

  // Given `𝜅/ 8` -bytes seed as input, this routine can be used for (un)masked Raccoon key generation, following algorithm 1 of the specification.
  //
  // When `d = 1`, it's the unmasked case, while for `d > 1`, key generation process is masked.
  template<size_t 𝑢t, size_t rep>
  static inline constexpr skey_t generate(std::span<const uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> seed)
    requires(raccoon_params::validate_keygen_args(𝜅, k, l, d, 𝑢t, 𝜈t, rep))
  {
    prng::prng_t prng{};
    mrng::mrng_t<d> mrng{};

    // Step 2: Generate matrix A
    const auto A = raccoon_poly_mat::poly_mat_t<k, l>::template expandA<k, l, 𝜅>(seed);

    // Step 3: Generate masked zero vector [[s]]
    auto s = raccoon_poly_vec::poly_vec_t<l, d>::zero_encoding(mrng);

    // Step 4: Generate secret distribution [[s]]
    s.template add_rep_noise<𝑢t, rep, 𝜅>(prng, mrng);

    // Step 5: Compute matrix vector multiplication, producing masked vector [[t]]
    s.ntt();
    auto t = A * s;
    t.intt();

    // Step 6: Add masked noise to vector [[t]]
    t.template add_rep_noise<𝑢t, rep, 𝜅>(prng, mrng);

    // Step 7: Collapse [[t]] into unmasked format
    auto t_prime = t.decode();

    // Step 8: Rounding and right shifting of unmasked vector t
    t_prime.template rounding_shr<𝜈t>();

    const auto vk = raccoon_pkey::pkey_t<𝜅, k, 𝜈t>(seed, t);
    const auto sk = raccoon_skey::skey_t<𝜅, k, l, d, 𝜈t>(vk, s);

    return sk;
  }

  // Byte serializes the secret key, which includes a copy of the public key.
  inline constexpr void to_bytes(std::span<uint8_t, get_byte_len()> bytes, prng::prng_t& prng) const
  {
    constexpr size_t pklen = raccoon_utils::get_pkey_byte_len<𝜅, k, raccoon_poly::N, 𝜈t>();
    constexpr size_t skoff0 = 0;
    constexpr size_t skoff1 = skoff0 + pklen;
    constexpr size_t skoff2 = skoff1 + (bytes.size() - pklen);

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
