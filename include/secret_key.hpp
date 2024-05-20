#pragma once
#include "challenge.hpp"
#include "mrng.hpp"
#include "params.hpp"
#include "poly.hpp"
#include "poly_mat.hpp"
#include "prng.hpp"
#include "public_key.hpp"
#include "signature.hpp"
#include "utils.hpp"

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

    const auto vk = raccoon_pkey::pkey_t<𝜅, k, 𝜈t>(seed, t_prime);
    const auto sk = raccoon_skey::skey_t<𝜅, k, l, d, 𝜈t>(vk, s);

    return sk;
  }

  // Given one (un)masked Raccoon secret key, this routine can be used for signing a message of arbitrary length, following algorithm 2 of the specification.
  //
  // When `d = 1`, it's the unmasked case, while for `d > 1`, signing process is masked.
  template<size_t 𝑢w, size_t 𝜈w, size_t rep, size_t 𝜔, size_t sig_byte_len, uint64_t Binf, uint64_t B22>
  inline constexpr raccoon_sig::sig_t<𝜅, k, l, 𝜈w, sig_byte_len> sign(std::span<const uint8_t> msg) const
    requires(raccoon_params::validate_sign_args(𝜅, k, l, d, 𝑢w, 𝜈w, 𝜈t, rep, 𝜔, sig_byte_len, Binf, B22))
  {
    auto s = this->s;
    auto t = this->pkey.get_t();

    t = t << 𝜈t;
    t.ntt();

    std::array<uint8_t, raccoon_utils::get_pkey_byte_len<𝜅, k, raccoon_poly::N, 𝜈t>()> pk_bytes{};
    this->pkey.to_bytes(pk_bytes);

    // Step 2: Bind public key with message
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

    // Step 3: Generate matrix A
    const auto A = raccoon_poly_mat::poly_mat_t<k, l>::template expandA<k, l, 𝜅>(this->pkey.get_seed());

    prng::prng_t prng{};
    mrng::mrng_t<d> mrng{};

    raccoon_sig::sig_t<𝜅, k, l, 𝜈w, sig_byte_len> sig{};

    while (true) {
      // Step 4: Generate masked zero vector [[r]]
      auto r = raccoon_poly_vec::poly_vec_t<l, d>::zero_encoding(mrng);

      // Step 5: Add masked noise to [[r]]
      r.template add_rep_noise<𝑢w, rep, 𝜅>(prng, mrng);

      // Step 6: Compute matrix vector multiplication, producing masked vector [[w]]
      r.ntt();
      auto w = A * r;
      w.intt();

      // Step 7: Add masked noise to vector [[w]]
      w.template add_rep_noise<𝑢w, rep, 𝜅>(prng, mrng);

      // Step 8: Collapse [[w]] into unmasked format
      auto w_prime = w.decode();

      // Step 9: Rounding and right shifting of unmasked vector w
      w_prime.template rounding_shr<𝜈w>();

      // Step 10: Compute challenge hash
      std::array<uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> c_hash{};
      raccoon_challenge::chal_hash<k, 𝜅>(w_prime, 𝜇, c_hash);

      // Step 11: Compute challenge polynomial
      auto c_poly = raccoon_poly::poly_t::chal_poly<𝜅, 𝜔>(c_hash);
      c_poly.ntt();

      // Step 12: Refresh masked secret key vector [[s]]
      s.refresh(mrng);

      // Step 13: Refresh masked vector [[r]]
      r.refresh(mrng);

      // Step 14: Compute masked response vector [[z]]
      auto z = s * c_poly + r;

      // Step 15: Refresh masked response vector [[z]], before collapsing it
      z.refresh(mrng);

      // Step 16: Collapse [[z]] into unmasked format
      auto z_prime = z.decode();

      // Step 17: Compute noisy LWE commitment vector y
      auto y = A * z_prime - t * c_poly;
      y.intt();
      z_prime.intt();

      // Step 18: Computes hint vector h, subtraction modulo `q >> 𝜈w`
      y.template rounding_shr<𝜈w>();
      auto h = w_prime.template sub_mod<(field::Q >> 𝜈w)>(y);

      // Step 19: Convert signature components into serialization friendly format
      sig = raccoon_sig::sig_t<𝜅, k, l, 𝜈w, sig_byte_len>(c_hash, h, z_prime);

      // Step 19: Attempt to serialize signature, given fixed space
      std::array<uint8_t, sig_byte_len> sig_bytes{};
      const bool is_encoded = sig.to_bytes(sig_bytes);
      if (!is_encoded) {
        // Signature can't be serialized within given fixed space, let's retry
        continue;
      }

      // Step 20: If serialization of signature passes, do a final round of sanity check on *raw* signature
      const bool is_under_bounds = sig.template check_bounds<Binf, B22>();
      if (!is_under_bounds) {
        // Signature is failing norms check, let's retry
        continue;
      }

      // Just signed the message successfully !
      break;
    }

    return sig;
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
