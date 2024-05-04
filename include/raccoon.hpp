#pragma once
#include "bounds.hpp"
#include "challenge.hpp"
#include "gadgets.hpp"
#include "mrng.hpp"
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

// Given one (un)masked Raccoon secret key, this routine can be used for signing a message, following algorithm 2 of the specification.
//
// When `d = 1`, it's the unmasked case, while for `d > 1`, signing process is masked.
template<size_t 𝜅, size_t k, size_t l, size_t d, size_t 𝑢w, size_t 𝜈w, size_t 𝜈t, size_t rep, size_t 𝜔, size_t sig_len, uint64_t 𝐵_∞, uint64_t 𝐵22>
static inline constexpr void
sign(std::span<const uint8_t, raccoon_utils::get_skey_byte_len<𝜅, k, l, d, polynomial::N, 𝜈t>()> skey,
     std::span<const uint8_t> msg,
     std::span<uint8_t, sig_len> sig)
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

  serialization::decode_public_key<𝜅, k, 𝜈t>(pkey, seed, t);
  serialization::mask_decompress<𝜅, l, d>(s_c, _s);

  std::array<uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> 𝜇{};
  auto _𝜇 = std::span(𝜇);

  shake256::shake256_t hasher{};
  hasher.absorb(pkey);
  hasher.finalize();
  hasher.squeeze(_𝜇);
  hasher.reset();

  hasher.absorb(_𝜇);
  hasher.absorb(msg);
  hasher.finalize();
  hasher.squeeze(_𝜇);

  std::array<polynomial::polynomial_t, k * l> A{};
  sampling::expandA<k, l, 𝜅>(seed, A);

  while (true) {
    std::array<polynomial::polynomial_t, _s.size()> r{};
    auto _r = std::span(r);

    prng::prng_t prng{};
    mrng::mrng_t<d> mrng{};

    for (size_t i = 0; i < l; i++) {
      const size_t s_off = i * d;
      gadgets::zero_encoding<d>(std::span<polynomial::polynomial_t, d>(_r.subspan(s_off, d)), mrng);
    }

    sampling::add_rep_noise<l, d, 𝑢w, rep, 𝜅>(_r, prng, mrng);

    for (size_t i = 0; i < _r.size(); i++) {
      _r[i].ntt();
    }

    std::array<polynomial::polynomial_t, k * d> w{};
    auto _w = std::span(w);

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

    sampling::add_rep_noise<k, d, 𝑢w, rep, 𝜅>(_w, prng, mrng);

    std::array<polynomial::polynomial_t, k> collapsed_w{};
    auto _collapsed_w = std::span(collapsed_w);

    for (size_t row_idx = 0; row_idx < _collapsed_w.size(); row_idx++) {
      _collapsed_w[row_idx] = gadgets::decode<d>(std::span<polynomial::polynomial_t, d>(_w.subspan(row_idx * d, d)));
      _collapsed_w[row_idx].template rounding_shr<𝜈w>();
    }

    std::array<uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> c_hash{};

    challenge::chal_hash<k, 𝜅>(_collapsed_w, 𝜇, c_hash);
    auto c_poly = challenge::chal_poly<𝜅, 𝜔>(c_hash);
    c_poly.ntt();

    for (size_t row_idx = 0; row_idx < l; row_idx++) {
      gadgets::refresh<d>(std::span<polynomial::polynomial_t, d>(_s.subspan(row_idx * d, d)), mrng);
      gadgets::refresh<d>(std::span<polynomial::polynomial_t, d>(_r.subspan(row_idx * d, d)), mrng);
    }

    std::array<polynomial::polynomial_t, _r.size()> z{};
    auto _z = std::span(z);

    for (size_t i = 0; i < _z.size(); i++) {
      _z[i] = c_poly * _s[i] + _r[i];
    }

    for (size_t row_idx = 0; row_idx < l; row_idx++) {
      gadgets::refresh<d>(std::span<polynomial::polynomial_t, d>(_z.subspan(row_idx * d, d)), mrng);
    }

    std::array<polynomial::polynomial_t, l> collapsed_z{};
    auto _collapsed_z = std::span(collapsed_z);

    for (size_t row_idx = 0; row_idx < _collapsed_z.size(); row_idx++) {
      _collapsed_z[row_idx] = gadgets::decode<d>(std::span<polynomial::polynomial_t, d>(_z.subspan(row_idx * d, d)));
    }

    c_poly.intt();
    auto shl_c_poly = c_poly << 𝜈t;
    shl_c_poly.ntt();

    std::array<polynomial::polynomial_t, _collapsed_w.size()> y{};
    auto _y = std::span(y);

    for (size_t row_idx = 0; row_idx < k; row_idx++) {
      for (size_t col_idx = 0; col_idx < l; col_idx++) {
        _y[row_idx] += A[row_idx * l + col_idx] * _collapsed_z[col_idx];
      }
    }

    for (size_t row_idx = 0; row_idx < t.size(); row_idx++) {
      t[row_idx].ntt();

      _y[row_idx] -= shl_c_poly * t[row_idx];
      _y[row_idx].intt();
      _y[row_idx].template rounding_shr<𝜈w>();
    }

    std::array<polynomial::polynomial_t, _y.size()> h{};
    auto _h = std::span(h);

    for (size_t row_idx = 0; row_idx < _h.size(); row_idx++) {
      _h[row_idx] = _collapsed_w[row_idx] - _y[row_idx];
    }

    std::array<int64_t, _h.size() * polynomial::N> centered_h{};
    auto _centered_h = std::span(centered_h);

    for (size_t row_idx = 0; row_idx < _h.size(); row_idx++) {
      const size_t offset = row_idx * polynomial::N;

      const auto centered = _h[row_idx].center();
      std::copy(centered.begin(), centered.end(), _centered_h.subspan(offset, centered.size()).begin());
    }

    std::array<int64_t, _collapsed_z.size() * polynomial::N> centered_z{};
    auto _centered_z = std::span(centered_z);

    for (size_t row_idx = 0; row_idx < _collapsed_z.size(); row_idx++) {
      _collapsed_z[row_idx].intt();

      const auto centered = _collapsed_z[row_idx].center();

      const size_t offset = row_idx * polynomial::N;
      std::copy(centered.begin(), centered.end(), _centered_z.subspan(offset, centered.size()).begin());
    }

    const auto is_encoded = serialization::encode_sig<k, l, 𝜅, sig_len>(c_hash, _centered_h, _centered_z, sig);
    if (!is_encoded) {
      continue;
    }

    const auto is_under_bounds = checks::check_bounds<k, l, 𝜈w, 𝐵_∞, 𝐵22>(_centered_h, _collapsed_z);
    if (!is_under_bounds) {
      continue;
    }

    break;
  }
}

}
