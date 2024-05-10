#pragma once
#include "bounds.hpp"
#include "challenge.hpp"
#include "gadgets.hpp"
#include "mrng.hpp"
#include "params.hpp"
#include "polynomial.hpp"
#include "prng.hpp"
#include "sampling.hpp"
#include "serialization.hpp"
#include "shake256.hpp"
#include "utils.hpp"

namespace raccoon {

// Given `𝜅/ 8` -bytes seed as input, this routine can be used for (un)masked Raccoon key generation, following algorithm 1 of the specification.
//
// When `d = 1`, it's the unmasked case, while for `d > 1`, key generation process is masked.
template<size_t 𝜅, size_t k, size_t l, size_t d, size_t 𝑢t, size_t 𝜈t, size_t rep>
static inline constexpr void
keygen(std::span<const uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> seed,
       std::span<uint8_t, raccoon_utils::get_pkey_byte_len<𝜅, k, polynomial::N, 𝜈t>()> pkey,
       std::span<uint8_t, raccoon_utils::get_skey_byte_len<𝜅, k, l, d, polynomial::N, 𝜈t>()> skey)
  requires(raccoon_params::validate_keygen_args(𝜅, k, l, d, 𝑢t, 𝜈t, rep))
{
  // Step 2: Generate matrix A
  std::array<polynomial::polynomial_t, k * l> A{};
  sampling::expandA<k, l, 𝜅>(seed, A);

  std::array<polynomial::polynomial_t, l * d> s{};
  auto _s = std::span(s);

  prng::prng_t prng{};
  mrng::mrng_t<d> mrng{};

  // Step 3: Generate masked zero vector [[s]]
  for (size_t i = 0; i < l; i++) {
    const size_t s_off = i * d;
    gadgets::zero_encoding<d>(std::span<polynomial::polynomial_t, d>(_s.subspan(s_off, d)), mrng);
  }

  // Step 4: Generate secret distribution [[s]]
  sampling::add_rep_noise<l, d, 𝑢t, rep, 𝜅>(_s, prng, mrng);

  // Convert [[s]] to NTT representation
  for (size_t i = 0; i < _s.size(); i++) {
    _s[i].ntt();
  }

  std::array<polynomial::polynomial_t, k * d> t{};
  auto _t = std::span(t);

  // Step 5: Compute matrix vector multiplication, producing masked vector [[t]]
  for (size_t row_idx = 0; row_idx < k; row_idx++) {
    for (size_t col_idx = 0; col_idx < l; col_idx++) {
      for (size_t shr_idx = 0; shr_idx < d; shr_idx++) {
        _t[row_idx * d + shr_idx] += A[row_idx * l + col_idx] * _s[col_idx * d + shr_idx];
      }
    }

    for (size_t shr_idx = 0; shr_idx < d; shr_idx++) {
      _t[row_idx * d + shr_idx].intt();
    }
  }

  // Step 6: Add masked noise to vector [[t]]
  sampling::add_rep_noise<k, d, 𝑢t, rep, 𝜅>(_t, prng, mrng);

  std::array<polynomial::polynomial_t, k> collapsed_t{};
  auto _collapsed_t = std::span(collapsed_t);

  // Step 7: Collapse [[t]] into unmasked format
  // Step 8: Rounding and right shifting of unmasked vector t
  for (size_t row_idx = 0; row_idx < _collapsed_t.size(); row_idx++) {
    _collapsed_t[row_idx] = gadgets::decode<d>(std::span<polynomial::polynomial_t, d>(_t.subspan(row_idx * d, d)));
    _collapsed_t[row_idx].template rounding_shr<𝜈t>();
  }

  // Serialize public key
  serialization::encode_public_key<𝜅, k, 𝜈t>(seed, _collapsed_t, pkey);

  constexpr size_t skoff0 = 0;
  constexpr size_t skoff1 = skoff0 + pkey.size();
  constexpr size_t skoff2 = skoff1 + (skey.size() - pkey.size());

  // Serialize secret key
  std::copy(pkey.begin(), pkey.end(), skey.template subspan<skoff0, skoff1 - skoff0>().begin());
  serialization::mask_compress<𝜅, l, d>(_s, skey.template subspan<skoff1, skoff2 - skoff1>(), prng);
}

// Given one (un)masked Raccoon secret key, this routine can be used for signing a message, following algorithm 2 of the specification.
//
// When `d = 1`, it's the unmasked case, while for `d > 1`, signing process is masked.
template<size_t 𝜅, size_t k, size_t l, size_t d, size_t 𝑢w, size_t 𝜈w, size_t 𝜈t, size_t rep, size_t 𝜔, size_t sig_byte_len, uint64_t Binf, uint64_t B22>
static inline constexpr void
sign(std::span<const uint8_t, raccoon_utils::get_skey_byte_len<𝜅, k, l, d, polynomial::N, 𝜈t>()> skey,
     std::span<const uint8_t> msg,
     std::span<uint8_t, sig_byte_len> sig)
  requires(raccoon_params::validate_sign_args(𝜅, k, l, d, 𝑢w, 𝜈w, 𝜈t, rep, 𝜔, sig_byte_len, Binf, B22))
{
  constexpr size_t skey_off0 = 0;
  constexpr size_t skey_off1 = skey_off0 + raccoon_utils::get_pkey_byte_len<𝜅, k, polynomial::N, 𝜈t>();
  constexpr size_t skey_off2 = skey.size();

  std::array<uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> seed{};
  std::array<polynomial::polynomial_t, k> t{};
  std::array<polynomial::polynomial_t, l * d> s{};
  auto _s = std::span(s);

  auto pkey = skey.template subspan<skey_off0, skey_off1 - skey_off0>();
  auto s_c = skey.template subspan<skey_off1, skey_off2 - skey_off1>();

  // Step 1: Decode secret key and public key into its components
  serialization::decode_public_key<𝜅, k, 𝜈t>(pkey, seed, t);

  // Scale public key vector `t` from Z𝑞t to Z𝑞 and compute its NTT representation, outside of the sign retry loop,
  // so that we don't have to repeat/ undo this step there.
  for (size_t row_idx = 0; row_idx < t.size(); row_idx++) {
    t[row_idx] = t[row_idx] << 𝜈t;
    t[row_idx].ntt();
  }

  serialization::mask_decompress<𝜅, l, d>(s_c, _s);

  std::array<uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> 𝜇{};
  auto _𝜇 = std::span(𝜇);

  // Step 2: Bind public key with message
  shake256::shake256_t hasher{};
  hasher.absorb(pkey);
  hasher.finalize();
  hasher.squeeze(_𝜇);
  hasher.reset();

  hasher.absorb(_𝜇);
  hasher.absorb(msg);
  hasher.finalize();
  hasher.squeeze(_𝜇);

  // Step 3: Generate matrix A
  std::array<polynomial::polynomial_t, k * l> A{};
  sampling::expandA<k, l, 𝜅>(seed, A);

  prng::prng_t prng{};
  mrng::mrng_t<d> mrng{};

  while (true) {
    std::array<polynomial::polynomial_t, _s.size()> r{};
    auto _r = std::span(r);

    // Step 4: Generate masked zero vector [[r]]
    for (size_t i = 0; i < l; i++) {
      const size_t s_off = i * d;
      gadgets::zero_encoding<d>(std::span<polynomial::polynomial_t, d>(_r.subspan(s_off, d)), mrng);
    }

    // Step 5: Add masked noise to [[r]]
    sampling::add_rep_noise<l, d, 𝑢w, rep, 𝜅>(_r, prng, mrng);

    // Convert [[r]] into NTT representation
    for (size_t i = 0; i < _r.size(); i++) {
      _r[i].ntt();
    }

    std::array<polynomial::polynomial_t, k * d> w{};
    auto _w = std::span(w);

    // Step 6: Compute matrix vector multiplication, producing masked vector [[w]]
    for (size_t row_idx = 0; row_idx < k; row_idx++) {
      for (size_t col_idx = 0; col_idx < l; col_idx++) {
        for (size_t shr_idx = 0; shr_idx < d; shr_idx++) {
          _w[row_idx * d + shr_idx] += A[row_idx * l + col_idx] * _r[col_idx * d + shr_idx];
        }
      }

      for (size_t shr_idx = 0; shr_idx < d; shr_idx++) {
        _w[row_idx * d + shr_idx].intt();
      }
    }

    // Step 7: Add masked noise to vector [[w]]
    sampling::add_rep_noise<k, d, 𝑢w, rep, 𝜅>(_w, prng, mrng);

    std::array<polynomial::polynomial_t, k> collapsed_w{};
    auto _collapsed_w = std::span(collapsed_w);

    // Step 8: Collapse [[w]] into unmasked format
    // Step 9: Rouding and right shifting of unmasked vector w, modulo `q >> 𝜈w`
    for (size_t row_idx = 0; row_idx < _collapsed_w.size(); row_idx++) {
      _collapsed_w[row_idx] = gadgets::decode<d>(std::span<polynomial::polynomial_t, d>(_w.subspan(row_idx * d, d)));
      _collapsed_w[row_idx].template rounding_shr<𝜈w>();
    }

    std::array<uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> c_hash{};

    // Step 10: Compute challenge hash
    challenge::chal_hash<k, 𝜅>(_collapsed_w, 𝜇, c_hash);

    // Step 11: Compute challenge polynomial
    auto c_poly = challenge::chal_poly<𝜅, 𝜔>(c_hash);
    c_poly.ntt();

    // Step 12: Refresh masked secret key vector [[s]]
    for (size_t row_idx = 0; row_idx < l; row_idx++) {
      gadgets::refresh<d>(std::span<polynomial::polynomial_t, d>(_s.subspan(row_idx * d, d)), mrng);
    }

    // Step 13: Refresh masked vector [[r]]
    for (size_t row_idx = 0; row_idx < l; row_idx++) {
      gadgets::refresh<d>(std::span<polynomial::polynomial_t, d>(_r.subspan(row_idx * d, d)), mrng);
    }

    std::array<polynomial::polynomial_t, _r.size()> z{};
    auto _z = std::span(z);

    // Step 14: Compute masked response vector [[z]]
    for (size_t i = 0; i < _z.size(); i++) {
      _z[i] = c_poly * _s[i] + _r[i];
    }

    // Step 15: Refresh masked response vector [[z]], before collapsing it
    for (size_t row_idx = 0; row_idx < l; row_idx++) {
      gadgets::refresh<d>(std::span<polynomial::polynomial_t, d>(_z.subspan(row_idx * d, d)), mrng);
    }

    std::array<polynomial::polynomial_t, l> collapsed_z{};
    auto _collapsed_z = std::span(collapsed_z);

    // Step 16: Collapse [[z]] into unmasked format
    for (size_t row_idx = 0; row_idx < _collapsed_z.size(); row_idx++) {
      _collapsed_z[row_idx] = gadgets::decode<d>(std::span<polynomial::polynomial_t, d>(_z.subspan(row_idx * d, d)));
    }

    std::array<polynomial::polynomial_t, _collapsed_w.size()> y{};
    auto _y = std::span(y);

    // Step 17: Compute noisy LWE commitment vector y
    for (size_t row_idx = 0; row_idx < k; row_idx++) {
      for (size_t col_idx = 0; col_idx < l; col_idx++) {
        _y[row_idx] += A[row_idx * l + col_idx] * _collapsed_z[col_idx];
      }
    }

    for (size_t row_idx = 0; row_idx < t.size(); row_idx++) {
      _y[row_idx] -= c_poly * t[row_idx];
      _y[row_idx].intt();

      // (partial) Step 18: Rouding and right shifting of LWE commitment vector y, modulo `q >> 𝜈w`
      _y[row_idx].template rounding_shr<𝜈w>();
    }

    constexpr uint64_t q_𝜈w = field::Q >> 𝜈w;

    std::array<polynomial::polynomial_t, _y.size()> h{};
    auto _h = std::span(h);

    // (partial) Step 18: Computes hint vector h, modulo `q >> 𝜈w`
    for (size_t row_idx = 0; row_idx < _h.size(); row_idx++) {
      _h[row_idx] = _collapsed_w[row_idx].template sub_mod<q_𝜈w>(_y[row_idx]);
    }

    std::array<int64_t, _h.size() * polynomial::N> centered_h{};
    auto _centered_h = std::span(centered_h);

    // (partial) Step 18: Center coefficients of hint vector h, around 0
    for (size_t row_idx = 0; row_idx < _h.size(); row_idx++) {
      const size_t offset = row_idx * polynomial::N;

      const auto centered = _h[row_idx].template center<q_𝜈w>();
      std::copy(centered.begin(), centered.end(), _centered_h.subspan(offset, centered.size()).begin());
    }

    std::array<int64_t, _collapsed_z.size() * polynomial::N> centered_z{};
    auto _centered_z = std::span(centered_z);

    // Center coefficients of unmasked response vector z, around 0
    for (size_t row_idx = 0; row_idx < _collapsed_z.size(); row_idx++) {
      _collapsed_z[row_idx].intt();

      const auto centered = _collapsed_z[row_idx].template center<field::Q>();

      const size_t offset = row_idx * polynomial::N;
      std::copy(centered.begin(), centered.end(), _centered_z.subspan(offset, centered.size()).begin());
    }

    // Step 19: Attempt to serialize signature, given fixed space
    const auto is_encoded = serialization::encode_sig<k, l, 𝜅, sig_byte_len>(c_hash, _centered_h, _centered_z, sig);
    if (!is_encoded) {
      // Signature can't be serialized within given fixed space, let's retry
      continue;
    }

    // Step 20: If serialization of signature passes, do a final round of sanity check on *raw* signature
    const auto is_under_bounds = checks::check_bounds<k, l, 𝜈w, Binf, B22>(_centered_h, _collapsed_z);
    if (!is_under_bounds) {
      // Signature is failing norms check, let's retry
      continue;
    }

    // Just signed the message successfully !
    break;
  }
}

// Given a Raccon signature, corresponding message (which was signed) and public key of the signer, this routine verifies
// the validity of the signature, returning boolean truth value in case of success, else returning false.
// This is an implementation of the algorithm 3 of the specification.
template<size_t 𝜅, size_t k, size_t l, size_t 𝜈w, size_t 𝜈t, size_t 𝜔, size_t sig_byte_len, uint64_t Binf, uint64_t B22>
static inline constexpr bool
verify(std::span<const uint8_t, raccoon_utils::get_pkey_byte_len<𝜅, k, polynomial::N, 𝜈t>()> pkey,
       std::span<const uint8_t> msg,
       std::span<const uint8_t, sig_byte_len> sig)
  requires(raccoon_params::validate_verify_args(𝜅, k, l, 𝜈w, 𝜈t, 𝜔, sig_byte_len, Binf, B22))
{
  std::array<uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> c_hash{};
  std::array<int64_t, k * polynomial::N> centered_h{};
  std::array<int64_t, l * polynomial::N> centered_z{};

  auto _centered_h = std::span(centered_h);
  auto _centered_z = std::span(centered_z);

  // Step 1: Attempt to decode signature into its components
  const auto is_decoded = serialization::decode_sig<k, l, 𝜅, sig_byte_len>(sig, c_hash, _centered_h, _centered_z);
  if (!is_decoded) {
    return false;
  }

  constexpr uint64_t q_𝜈w = field::Q >> 𝜈w;

  std::array<polynomial::polynomial_t, _centered_h.size() / polynomial::N> h{};
  std::array<polynomial::polynomial_t, _centered_z.size() / polynomial::N> z{};

  // Change the input range of the polynomial coefficients, preparing for step 2
  for (size_t row_idx = 0; row_idx < h.size(); row_idx++) {
    const size_t offset = row_idx * polynomial::N;
    h[row_idx] = polynomial::polynomial_t::from_centered<q_𝜈w>(std::span<int64_t, polynomial::N>(_centered_h.subspan(offset, polynomial::N)));
  }

  for (size_t row_idx = 0; row_idx < z.size(); row_idx++) {
    const size_t offset = row_idx * polynomial::N;
    z[row_idx] = polynomial::polynomial_t::from_centered<field::Q>(std::span<int64_t, polynomial::N>(_centered_z.subspan(offset, polynomial::N)));
  }

  // Step 2: Perform norms check
  const auto is_under_bounds = checks::check_bounds<k, l, 𝜈w, Binf, B22>(_centered_h, z);
  if (!is_under_bounds) {
    return false;
  }

  std::array<uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> seed{};
  std::array<polynomial::polynomial_t, k> t{};

  // Step 1: Decode public key into its components
  serialization::decode_public_key<𝜅, k, 𝜈t>(pkey, seed, t);

  std::array<uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> 𝜇{};

  // Step 3: Bind public key with message
  shake256::shake256_t hasher{};
  hasher.absorb(pkey);
  hasher.finalize();
  hasher.squeeze(𝜇);
  hasher.reset();

  hasher.absorb(𝜇);
  hasher.absorb(msg);
  hasher.finalize();
  hasher.squeeze(𝜇);

  // Step 4: Generate matrix A
  std::array<polynomial::polynomial_t, k * l> A{};
  sampling::expandA<k, l, 𝜅>(seed, A);

  // Step 5: Compute challenge polynomial
  auto c_poly = challenge::chal_poly<𝜅, 𝜔>(c_hash);
  c_poly.ntt();

  std::array<polynomial::polynomial_t, h.size()> y{};

  // Convert response vector z into NTT domain
  for (size_t row_idx = 0; row_idx < z.size(); row_idx++) {
    z[row_idx].ntt();
  }

  // Step 6: Recompute noisy LWE commitment vector y
  for (size_t row_idx = 0; row_idx < k; row_idx++) {
    for (size_t col_idx = 0; col_idx < l; col_idx++) {
      y[row_idx] += A[row_idx * l + col_idx] * z[col_idx];
    }
  }

  for (size_t row_idx = 0; row_idx < y.size(); row_idx++) {
    t[row_idx] = t[row_idx] << 𝜈t;
    t[row_idx].ntt();

    y[row_idx] -= c_poly * t[row_idx];
    y[row_idx].intt();

    y[row_idx].template rounding_shr<𝜈w>();
  }

  std::array<polynomial::polynomial_t, y.size()> w{};

  // Step 7: Adjust LWE commitment vector with hint vector, reduced small moduli q_𝜈w
  for (size_t row_idx = 0; row_idx < w.size(); row_idx++) {
    w[row_idx] = y[row_idx].template add_mod<q_𝜈w>(h[row_idx]);
  }

  // Step 8: Recompute challenge hash
  std::array<uint8_t, c_hash.size()> c_hash_prime{};
  challenge::chal_hash<k, 𝜅>(w, 𝜇, c_hash_prime);

  using c_hash_t = std::span<const uint8_t, c_hash.size()>;

  // Step 9: Check equality of commitment
  const auto is_equal = raccoon_utils::ct_eq_byte_array(c_hash_t(c_hash), c_hash_t(c_hash_prime));
  const auto is_verified = static_cast<bool>(is_equal >> (std::numeric_limits<decltype(is_equal)>::digits - 1));

  return is_verified;
}

}
