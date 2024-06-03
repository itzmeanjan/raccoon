#pragma once
#include "raccoon/internals/math/field.hpp"
#include "raccoon/internals/rng/mrng.hpp"
#include "raccoon/internals/rng/prng.hpp"
#include "raccoon/internals/utility/utils.hpp"
#include "shake256.hpp"
#include "subtle.hpp"
#include <algorithm>
#include <array>
#include <cstdint>

namespace raccoon_poly {

// N is set to 512 for all parameter sets of Raccoon.
static constexpr size_t LOG2N = 9;
static constexpr size_t N = 1ul << LOG2N;

// First primitive 1024 (=2*N) -th root of unity modulo q | q = 549824583172097
//
// Meaning, 358453792785495 ** 1024 == 1 (mod q)
static constexpr field::zq_t ζ(358453792785495ul);

// Multiplicative inverse of N over Z_q | q = 549824583172097
static constexpr auto INV_N = []() {
  constexpr auto inv_n = field::zq_t(N).inv();
  static_assert(inv_n.second == field::is_invertible_t::yes, "N is not invertible for modulus Q");

  return inv_n.first;
}();

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
static constexpr auto ζ_EXP_first = []() {
  std::array<field::zq_t, N / 2> res{};

  for (size_t i = 0; i < res.size(); i++) {
    res[i] = ζ ^ bit_rev<LOG2N>(i);
  }

  return res;
}();

// Compile-time computes ζ ^ i | N/2 <= i < N
static constexpr auto ζ_EXP_last = []() {
  std::array<field::zq_t, ζ_EXP_first.size()> res{};

  for (size_t i = ζ_EXP_first.size(); i < 2 * ζ_EXP_first.size(); i++) {
    res[i - ζ_EXP_first.size()] = ζ ^ bit_rev<LOG2N>(i);
  }

  return res;
}();

// Compile-time compute table holding powers of ζ, which is used for computing NTT over degree-511 polynomial s.t. coefficients ∈ Zq.
static constexpr auto ζ_EXP = []() {
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
static constexpr auto ζ_NEG_EXP = compute_neg_powers_of_ζ();

// Degree 511 polynomial, defined over Zq
struct alignas(32) poly_t
{
private:
  std::array<field::zq_t, N> coeffs{};

  // Reduces input `x` modulo `q`, s.t. `x` ∈ [0, 2*q).
  template<uint64_t q>
  static inline constexpr uint64_t reduce_once_mod(const uint64_t x)
  {
    const auto t = x - q;
    const auto mask = -(t >> 63);
    const auto q_masked = q & mask;
    const auto reduced = t + q_masked;

    return reduced;
  }

public:
  // Constructor(s)
  inline constexpr poly_t() = default;

  // Accessor(s)
  inline constexpr field::zq_t& operator[](const size_t idx) { return this->coeffs[idx]; }
  inline constexpr const field::zq_t& operator[](const size_t idx) const { return this->coeffs[idx]; }

  // Number of coefficients in polynomial.
  inline constexpr size_t num_coeffs() const { return N; }

  // Sets all coefficients of the polynomial with same value.
  inline constexpr void fill_with(const field::zq_t v) { std::fill(this->coeffs.begin(), this->coeffs.end(), v); }

  // Addition of two polynomials.
  inline constexpr poly_t operator+(const poly_t& rhs) const
  {
    poly_t res{};

#if defined __clang__
#pragma clang loop unroll(enable) vectorize(enable) interleave(enable)
#elif defined __GNUG__
#pragma GCC unroll 64
#pragma GCC ivdep
#endif
    for (size_t i = 0; i < res.num_coeffs(); i++) {
      res[i] = (*this)[i] + rhs[i];
    }

    return res;
  }

  inline constexpr void operator+=(const poly_t& rhs) { *this = *this + rhs; }

  // Performs addition of two polynomials, reducing each cofficients by a small moduli `Q_prime` s.t. coefficients of input polynomials also ∈ [0, Q_prime).
  template<uint64_t Q_prime>
  inline constexpr poly_t add_mod(const poly_t& rhs) const
  {
    poly_t res{};

#if defined __clang__
#pragma clang loop unroll(enable) vectorize(enable) interleave(enable)
#endif
    for (size_t i = 0; i < res.num_coeffs(); i++) {
      const auto added = (*this)[i].raw() + rhs[i].raw();
      const auto reduced = reduce_once_mod<Q_prime>(added);

      res[i] = reduced;
    }

    return res;
  }

  // Subtraction of one polynomial from another one.
  inline constexpr poly_t operator-(const poly_t& rhs) const
  {
    poly_t res{};

#if defined __clang__
#pragma clang loop unroll(enable) vectorize(enable) interleave(enable)
#elif defined __GNUG__
#pragma GCC unroll 64
#pragma GCC ivdep
#endif
    for (size_t i = 0; i < res.num_coeffs(); i++) {
      res[i] = (*this)[i] - rhs[i];
    }

    return res;
  }

  inline constexpr void operator-=(const poly_t& rhs) { *this = *this - rhs; }

  // Subtracts one polynomial from another s.t. each of the coefficients ∈ [0, Q_prime) and resulting polynomial coefficients are reduced modulo `Q_prime`.
  template<uint64_t Q_prime>
  inline constexpr poly_t sub_mod(const poly_t& rhs) const
  {
    poly_t res{};

    for (size_t i = 0; i < res.num_coeffs(); i++) {
      const auto neg_rhs = Q_prime - rhs[i].raw();
      const auto subtracted = (*this)[i].raw() + neg_rhs;
      const auto reduced = reduce_once_mod<Q_prime>(subtracted);

      res[i] = reduced;
    }

    return res;
  }

  // Multiplies two polynomials, expecting both inputs are in their number theoretic representation.
  inline constexpr poly_t operator*(const poly_t& rhs) const
  {
    poly_t res{};

#if defined __clang__
#pragma clang loop unroll(enable) vectorize(enable) interleave(enable)
#elif defined __GNUG__
#pragma GCC unroll 8
#pragma GCC ivdep
#endif
    for (size_t i = 0; i < res.num_coeffs(); i++) {
      res[i] = (*this)[i] * rhs[i];
    }

    return res;
  }

  // Rounding shift right of each coefficient of the polynomial, following `Programming note` section on top of page 12 of Raccoon specification.
  template<size_t bit_offset>
  inline constexpr void rounding_shr()
  {
    constexpr uint64_t Q_prime = field::Q >> bit_offset;
    constexpr uint64_t rounding = 1ul << (bit_offset - 1);

    for (size_t i = 0; i < this->num_coeffs(); i++) {
      const auto x = this->coeffs[i].raw();
      const auto rounded = x + rounding;
      const auto shifted = rounded >> bit_offset;
      const auto reduced = reduce_once_mod<Q_prime>(shifted);

      this->coeffs[i] = reduced;
    }
  }

  // Shift each coefficient of polynomial leftwards by `offset` (<64) many bits s.t. resulting coefficients ∈ Zq.
  inline constexpr poly_t operator<<(const size_t offset) const
  {
    poly_t res{};

    for (size_t i = 0; i < res.num_coeffs(); i++) {
      res[i] = (*this)[i] << offset;
    }

    return res;
  }

  // [Constant-time] Checks for equality of two polynomials.
  inline constexpr bool operator==(const poly_t& rhs) const
  {
    bool res = true;
    for (size_t i = 0; i < rhs.num_coeffs(); i++) {
      res &= ((*this)[i] == rhs[i]);
    }

    return res;
  }

  // Centers the coefficients of a polynomial around 0, given that they ∈ [0, Q_prime] and resulting polynomial coeffiecients will be signed s.t. ∈ [-Q_prime/2,
  // Q_prime/2). Collects inspiration from https://github.com/masksign/raccoon/blob/e789b4b7/ref-py/polyr.py#L215-L218
  template<uint64_t Q_prime>
  inline constexpr std::array<int64_t, N> center() const
  {
    constexpr auto Q_prime_by_2 = Q_prime / 2;
    std::array<int64_t, N> centered_poly{};

    for (size_t i = 0; i < centered_poly.size(); i++) {
      const auto x = this->coeffs[i].raw();
      const auto is_ge = subtle::ct_ge<uint64_t, uint64_t>(x + Q_prime_by_2, Q_prime);
      const auto centered_x = static_cast<int64_t>(x) - static_cast<int64_t>(is_ge & Q_prime);

      centered_poly[i] = centered_x;
    }

    return centered_poly;
  }

  // Extends the coefficients of a polynomial in [0, Q_prime), given that input coefficients are currently centered around 0
  // i.e. they ∈ [-Q_prime/2, Q_prime/2).
  template<uint64_t Q_prime>
  static inline constexpr poly_t from_centered(std::span<const int64_t, N> centered)
  {
    poly_t extended{};

    for (size_t i = 0; i < centered.size(); i++) {
      const auto x = centered[i];

      const auto mask = static_cast<uint64_t>(x >> 63);
      const auto q_prime_masked = static_cast<int64_t>(Q_prime & mask);
      const auto extended_x = static_cast<uint64_t>(x + q_prime_masked);

      extended[i] = extended_x;
    }

    return extended;
  }

  // Applies number theoretic transform using Cooley-Tukey algorithm, producing polynomial f' s.t. its coefficients are placed in bit-reversed order.
  //
  // Note, this routine mutates input i.e. it's an in-place NTT implementation.
  // Implementation inspired from https://github.com/itzmeanjan/dilithium/blob/609700fa83372d1b8f1543d0d7cb38785bee7975/include/ntt.hpp
  inline constexpr void ntt()
  {
    for (int64_t l = LOG2N - 1; l >= 0; l--) {
      const size_t len = 1ul << l;
      const size_t lenx2 = len << 1;
      const size_t k_beg = N >> (l + 1);

      for (size_t start = 0; start < this->num_coeffs(); start += lenx2) {
        const size_t k_now = k_beg + (start >> (l + 1));
        const field::zq_t ζ_exp = ζ_EXP[k_now];

        for (size_t i = start; i < start + len; i++) {
          auto tmp = ζ_exp * (*this)[i + len];

          (*this)[i + len] = (*this)[i] - tmp;
          (*this)[i] += tmp;
        }
      }
    }
  }

  // Applies inverse number theoretic transform using Gentleman-Sande algorithm, producing polynomial f' s.t. its coefficients are placed in standard order.
  //
  // Note, this routine mutates input i.e. it's an in-place iNTT implementation. Also it expects the input polynomial to have coefficients placed in
  // bit-reversed order. Implementation inspired from https://github.com/itzmeanjan/dilithium/blob/609700fa83372d1b8f1543d0d7cb38785bee7975/include/ntt.hpp
  inline constexpr void intt()
  {
    for (size_t l = 0; l < LOG2N; l++) {
      const size_t len = 1ul << l;
      const size_t lenx2 = len << 1;
      const size_t k_beg = (N >> l) - 1;

      for (size_t start = 0; start < this->num_coeffs(); start += lenx2) {
        const size_t k_now = k_beg - (start >> (l + 1));
        const field::zq_t neg_ζ_exp = ζ_NEG_EXP[k_now];

        for (size_t i = start; i < start + len; i++) {
          const auto tmp = (*this)[i];

          (*this)[i] += (*this)[i + len];
          (*this)[i + len] = tmp - (*this)[i + len];
          (*this)[i + len] *= neg_ζ_exp;
        }
      }
    }

    for (size_t i = 0; i < this->num_coeffs(); i++) {
      (*this)[i] *= INV_N;
    }
  }

  // Given a 64 -bit header and `𝜅` -bits seed as input, this routine is used for mapping them to a degree n-1 polynomial f, following algorithm 5 of
  // https://raccoonfamily.org/wp-content/uploads/2023/07/raccoon.pdf.
  //
  // This routine is invoked when expanding seed for computing matrix A.
  template<size_t 𝜅>
  static inline constexpr poly_t sampleQ(std::span<const uint8_t, 8> hdr, std::span<const uint8_t, 𝜅 / 8> 𝜎)
  {
    poly_t res{};

    shake256::shake256_t xof{};
    xof.absorb(hdr);
    xof.absorb(𝜎);
    xof.finalize();

    for (size_t i = 0; i < res.num_coeffs(); i++) {
      uint64_t f_i = 0;

      do {
        std::array<uint8_t, (field::Q_BIT_WIDTH + 7) / 8> b{};
        xof.squeeze(b);

        constexpr uint64_t mask49 = (1ul << field::Q_BIT_WIDTH) - 1ul;

        const auto b_word = raccoon_utils::from_le_bytes<uint64_t>(b);
        f_i = b_word & mask49;
      } while (f_i >= field::Q);

      res[i] = f_i;
    }

    return res;
  }

  // Uniform random sampling of degree n-1 polynomial using a Masked Random Number Generator, following implementation @
  // https://github.com/masksign/raccoon/blob/e789b4b72a2b7e8a2205df49c487736985fc8417/ref-c/mask_random.c#L133-L154
  template<size_t d>
  static inline constexpr poly_t sample_polynomial(const size_t idx, mrng::mrng_t<d>& mrng)
    requires(d > 1)
  {
    poly_t res{};

    if (idx >= (d - 1)) [[unlikely]] {
      return res;
    }

    constexpr uint64_t mask49 = (1ul << field::Q_BIT_WIDTH) - 1ul;

    size_t coeff_idx = 0;
    while (coeff_idx < res.num_coeffs()) {
      const uint64_t v = mrng.get(idx);
      const uint64_t coeff = v & mask49;

      if (coeff < field::Q) {
        res[coeff_idx] = coeff;
        coeff_idx++;
      }
    }

    return res;
  }

  // Expands a `2 * 𝜅` -bit challenge hash into a polynomial such that exactly `𝜔` -many of coefficients are set to +1/ -1,
  // while others are set to 0, following algorithm 10 of the Raccoon specification.
  template<size_t 𝜅, size_t 𝜔>
  static inline constexpr poly_t chal_poly(std::span<const uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> c_hash)
  {
    poly_t c_poly{};

    std::array<const uint8_t, 8> hdr{ static_cast<uint8_t>('c'), static_cast<uint8_t>(𝜔) };

    shake256::shake256_t xof{};
    xof.absorb(hdr);
    xof.absorb(c_hash);
    xof.finalize();

    constexpr uint16_t mask = (1u << LOG2N) - 1;
    size_t non_zero_coeff_cnt = 0;

    while (non_zero_coeff_cnt < 𝜔) {
      std::array<uint8_t, sizeof(uint16_t)> b{};
      xof.squeeze(b);

      const auto b_word = raccoon_utils::from_le_bytes<uint16_t>(b);
      const auto b_0 = b_word & 0b1u;
      const auto i = static_cast<uint16_t>(b_word >> 1u) & mask;

      if (c_poly[i] == 0) {
        c_poly[i] = field::zq_t::one() - field::zq_t(2 * b_0);
        non_zero_coeff_cnt += 1;
      }
    }

    return c_poly;
  }

  // Generate a random degree 511 polynomial.
  static inline constexpr poly_t random(prng::prng_t& prng)
  {
    poly_t res{};

    for (size_t i = 0; i < res.num_coeffs(); i++) {
      res[i] = field::zq_t::random(prng);
    }

    return res;
  }
};

}
