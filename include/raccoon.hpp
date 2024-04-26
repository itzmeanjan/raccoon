#pragma once
#include "gadgets.hpp"
#include "mrng.hpp"
#include "polynomial.hpp"
#include "prng.hpp"
#include "sampling.hpp"
#include "serialization.hpp"
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
  requires(d > 0)
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

}
