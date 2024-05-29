#pragma once
#include "raccoon/internals/math/field.hpp"
#include "raccoon/internals/polynomial/challenge.hpp"
#include "raccoon/internals/polynomial/poly_mat.hpp"
#include "raccoon/internals/polynomial/poly_vec.hpp"
#include "raccoon/internals/utility/serialization.hpp"
#include "raccoon/internals/utility/utils.hpp"
#include "shake256.hpp"
#include "signature.hpp"
#include <array>
#include <cstdint>

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

  // Given a byte serialized Raccon signature and corresponding message (which was signed by the owner of the secret key, which is linked to this public key),
  // this routine verifies the validity of the signature, returning boolean truth value in case of success, else returning false. This is an implementation of
  // the algorithm 3 of the specification.
  template<size_t l, size_t 𝜈w, size_t 𝜔, size_t sig_byte_len, uint64_t Binf, uint64_t B22>
  inline constexpr bool verify(std::span<const uint8_t> msg, std::span<const uint8_t, sig_byte_len> sig) const
  {
    // Step 1: Attempt to decode signature into its components
    auto sig_opt = raccoon_sig::sig_t<𝜅, k, l, 𝜈w, sig_byte_len>::from_bytes(sig);
    const bool is_decoded = sig_opt.has_value();
    if (!is_decoded) {
      // Signature can't be deserialized back into its components
      return false;
    }

    auto sig_obj = sig_opt.value();

    // Step 2: Perform norms check
    const bool is_under_bounds = sig_obj.template check_bounds<Binf, B22>();
    if (!is_under_bounds) {
      // Signature is failing norms check
      return false;
    }

    std::array<uint8_t, raccoon_utils::get_pkey_byte_len<𝜅, k, raccoon_poly::N, 𝜈t>()> pk_bytes{};
    this->to_bytes(pk_bytes);

    // Step 3: Bind public key with message
    std::array<uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> 𝜇{};
    shake256::shake256_t hasher{};

    hasher.absorb(pk_bytes);
    hasher.finalize();
    hasher.squeeze(𝜇);

    hasher.reset();

    hasher.absorb(𝜇);
    hasher.absorb(msg);
    hasher.finalize();
    hasher.squeeze(𝜇);

    // Step 4: Generate uniform matrix A
    const auto A = raccoon_poly_mat::poly_mat_t<k, l>::template expandA<k, l, 𝜅>(this->seed);

    // Extract components of signature
    auto c_hash = sig_obj.get_c_hash();
    auto h = sig_obj.get_h();
    auto z = sig_obj.get_z();
    z.ntt();

    // Step 5: Compute challenge polynomial
    auto c_poly = raccoon_poly::poly_t::chal_poly<𝜅, 𝜔>(c_hash);
    c_poly.ntt();

    auto t = this->t;
    t = t << 𝜈t;
    t.ntt();

    // Step 6: Recompute noisy LWE commitment vector y
    auto y = A * z - t * c_poly;
    y.intt();

    // Step 7: Adjust LWE commitment vector with hint vector, reduced small moduli `q >> 𝜈w`
    y.template rounding_shr<𝜈w>();
    auto w = y.template add_mod<(field::Q >> 𝜈w)>(h);

    // Step 8: Recompute challenge hash
    std::array<uint8_t, c_hash.size()> c_hash_prime{};
    raccoon_challenge::chal_hash<k, 𝜅>(w, 𝜇, c_hash_prime);

    using c_hash_t = std::span<const uint8_t, c_hash.size()>;

    // Step 9: Check equality of commitment
    const auto is_equal = raccoon_utils::ct_eq_byte_array(c_hash_t(c_hash), c_hash_t(c_hash_prime));
    const auto is_verified = static_cast<bool>(is_equal >> (std::numeric_limits<decltype(is_equal)>::digits - 1));

    return is_verified;
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
    raccoon_serialization::decode_public_key<𝜅, k, 𝜈t>(bytes, pkey.get_seed(), pkey.get_t());
    return pkey;
  }
};

}
