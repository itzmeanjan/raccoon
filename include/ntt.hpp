#pragma once
#include "field.hpp"
#include <algorithm>
#include <array>
#include <span>

namespace ntt {

// N is set to 512 for all parameter sets of Raccoon.
constexpr size_t LOG2N = 9;
constexpr size_t N = 1 << LOG2N;

// First primitive 1024 (=2*N) -th root of unity modulo q | q = 549824583172097
//
// Meaning, 358453792785495 ** 1024 == 1 (mod q)
constexpr field::zq_t ζ(358453792785495ul);

// Multiplicative inverse of N over Z_q | q = 549824583172097
constexpr auto INV_N = field::zq_t(N).inv();

// Given a 64 -bit unsigned integer, this routine extracts specified many contiguous bits from LSB ( least significant bits ) side & reverses their bit order,
// returning bit reversed `mbw` -bit wide number.
//
// Taken from https://github.com/itzmeanjan/kyber/blob/3cd41a5/include/ntt.hpp#L74-L93.
template<size_t mbw>
static inline constexpr size_t
bit_rev(const size_t v)
  requires(mbw == LOG2N)
{
  size_t v_rev = 0ul;

  for (size_t i = 0; i < mbw; i++) {
    const size_t bit = (v >> i) & 0b1;
    v_rev ^= bit << (mbw - 1ul - i);
  }

  return v_rev;
}

// Compile-time computes ζ ^ i | 0 <= i < N/2
constexpr auto ζ_EXP_first = []() {
  std::array<field::zq_t, N / 2> res{};

  for (size_t i = 0; i < res.size(); i++) {
    res[i] = ζ ^ bit_rev<LOG2N>(i);
  }

  return res;
}();

// Compile-time computes ζ ^ i | N/2 <= i < N
constexpr auto ζ_EXP_last = []() {
  std::array<field::zq_t, ζ_EXP_first.size()> res{};

  for (size_t i = ζ_EXP_first.size(); i < 2 * ζ_EXP_first.size(); i++) {
    res[i - ζ_EXP_first.size()] = ζ ^ bit_rev<LOG2N>(i);
  }

  return res;
}();

// Compile-time compute table holding powers of ζ, which is used for computing NTT over degree-511 polynomial s.t. coefficients ∈ Zq.
constexpr auto ζ_EXP = []() {
  std::array<field::zq_t, N> res{};
  auto _res = std::span(res);

  auto res_first = _res.subspan<0, ζ_EXP_first.size()>();
  auto res_last = _res.subspan<ζ_EXP_first.size(), ζ_EXP_last.size()>();

  std::copy(ζ_EXP_first.begin(), ζ_EXP_first.end(), res_first.begin());
  std::copy(ζ_EXP_last.begin(), ζ_EXP_last.end(), res_last.begin());

  return res;
}();

// Compile-time compute table holding negated powers of ζ, which is used for computing iNTT over degree-511 polynomial s.t. coefficients ∈ Zq.
static consteval std::array<field::zq_t, N>
compute_neg_powers_of_ζ()
{
  std::array<field::zq_t, N> res;

  for (size_t i = 0; i < N; i++) {
    res[i] = -ζ_EXP[i];
  }

  return res;
}

// Precomputed table of negated powers of ζ, used when computing iNTT.
constexpr auto ζ_NEG_EXP = compute_neg_powers_of_ζ();

// Given a polynomial f with 512 coefficients over Z_q, this routine computes number theoretic transform using Cooley-Tukey algorithm, producing polynomial f'
// s.t. its coefficients are placed in bit-reversed order.
//
// Note, this routine mutates input i.e. it's an in-place NTT implementation.
//
// Implementation inspired from https://github.com/itzmeanjan/dilithium/blob/609700fa83372d1b8f1543d0d7cb38785bee7975/include/ntt.hpp
static inline constexpr void
ntt(std::span<field::zq_t, N> poly)
{
  for (int64_t l = LOG2N - 1; l >= 0; l--) {
    const size_t len = 1ul << l;
    const size_t lenx2 = len << 1;
    const size_t k_beg = N >> (l + 1);

    for (size_t start = 0; start < poly.size(); start += lenx2) {
      const size_t k_now = k_beg + (start >> (l + 1));
      const field::zq_t ζ_exp = ζ_EXP[k_now];

      for (size_t i = start; i < start + len; i++) {
        auto tmp = ζ_exp * poly[i + len];

        poly[i + len] = poly[i] - tmp;
        poly[i] += tmp;
      }
    }
  }
}

// Given a polynomial f with 512 coefficients over Z_q, s.t. its coefficients are placed in bit-reversed order, this routine computes inverse number theoretic
// transform using Gentleman-Sande algorithm, producing polynomial f' s.t. its coefficients are placed in standard order.
//
// Note, this routine mutates input i.e. it's an in-place iNTT implementation.
//
// Implementation inspired from https://github.com/itzmeanjan/dilithium/blob/609700fa83372d1b8f1543d0d7cb38785bee7975/include/ntt.hpp
static inline constexpr void
intt(std::span<field::zq_t, N> poly)
{
  for (size_t l = 0; l < LOG2N; l++) {
    const size_t len = 1ul << l;
    const size_t lenx2 = len << 1;
    const size_t k_beg = (N >> l) - 1;

    for (size_t start = 0; start < poly.size(); start += lenx2) {
      const size_t k_now = k_beg - (start >> (l + 1));
      const field::zq_t neg_ζ_exp = ζ_NEG_EXP[k_now];

      for (size_t i = start; i < start + len; i++) {
        const auto tmp = poly[i];

        poly[i] += poly[i + len];
        poly[i + len] = tmp - poly[i + len];
        poly[i + len] *= neg_ζ_exp;
      }
    }
  }

  for (size_t i = 0; i < poly.size(); i++) {
    poly[i] *= INV_N;
  }
}

}
