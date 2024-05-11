#pragma once
#include "field.hpp"
#include "mrng.hpp"
#include "prng.hpp"
#include "shake256.hpp"
#include "subtle.hpp"
#include "utils.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>

namespace polynomial {

// N is set to 512 for all parameter sets of Raccoon.
constexpr size_t LOG2N = 9;
constexpr size_t N = 1ul << LOG2N;

// First primitive 1024 (=2*N) -th root of unity modulo q | q = 549824583172097
//
// Meaning, 358453792785495 ** 1024 == 1 (mod q)
constexpr field::zq_t ζ(358453792785495ul);

// Multiplicative inverse of N over Z_q | q = 549824583172097
constexpr auto INV_N = []() {
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

// Degree 511 polynomial over Zq | q = 549824583172097, with support for masking.
template<size_t d>
  requires(d > 0)
struct masked_poly_t
{
private:
  std::array<field::zq_t, N * d> coeffs{};

  // Uniform random sampling of polynomial using a Masked Random Number Generator, following implementation @
  // https://github.com/masksign/raccoon/blob/e789b4b72a2b7e8a2205df49c487736985fc8417/ref-c/mask_random.c#L133-L154
  static inline constexpr masked_poly_t<1> sample_polynomial(const size_t sidx, mrng::mrng_t<d>& mrng)
    requires(d > 1)
  {
    constexpr uint64_t mask49 = (1ul << field::Q_BIT_WIDTH) - 1ul;
    masked_poly_t<1> poly{};

    size_t cidx = 0;
    while (cidx < poly.coeffs.size()) {
      const auto v = mrng.get(sidx);
      const auto coeff = v & mask49;

      if (coeff < field::Q) {
        poly[{ 0, cidx }] = coeff;
        cidx++;
      }
    }

    return poly;
  }

public:
  // Constructor(s)
  inline constexpr masked_poly_t() = default;

  // Behaves like std::fill, filling (un)masked polynomial coefficients with same Zq value.
  inline constexpr void fill_with(const field::zq_t v)
  {
    for (size_t sidx = 0; sidx < d; sidx++) {
      for (size_t cidx = 0; cidx < N; cidx++) {
        (*this)[{ sidx, cidx }] = v;
      }
    }
  }

  // Access the polynomial coefficient at index (sidx, cidx), assuming `sidx < d` and `cidx < N`
  inline constexpr field::zq_t& operator[](const std::pair<size_t, size_t> idx) { return this->coeffs[(idx.first * N) + idx.second]; };
  inline constexpr const field::zq_t& operator[](const std::pair<size_t, size_t> idx) const { return this->coeffs[(idx.first * N) + idx.second]; };

  // Addition of two polynomials.
  inline constexpr masked_poly_t operator+(const masked_poly_t& rhs) const
  {
    masked_poly_t res{};

    for (size_t sidx = 0; sidx < d; sidx++) {
      for (size_t cidx = 0; cidx < N; cidx++) {
        res[{ sidx, cidx }] = (*this)[{ sidx, cidx }] + rhs[{ sidx, cidx }];
      }
    }

    return res;
  }

  inline constexpr void operator+=(const masked_poly_t& rhs) { *this = *this + rhs; }

  // Subtraction of one polynomial from another one.
  inline constexpr masked_poly_t operator-(const masked_poly_t& rhs) const
  {
    masked_poly_t res{};

    for (size_t sidx = 0; sidx < d; sidx++) {
      for (size_t cidx = 0; cidx < N; cidx++) {
        res[{ sidx, cidx }] = (*this)[{ sidx, cidx }] - rhs[{ sidx, cidx }];
      }
    }

    return res;
  }

  inline constexpr void operator-=(const masked_poly_t& rhs) { *this = *this - rhs; }

  // Multiplies two polynomials, assuming both inputs are in their number theoretic representation. Hence the computed output is also in NTT domain.
  inline constexpr masked_poly_t operator*(const masked_poly_t& rhs) const
  {
    masked_poly_t res{};

    for (size_t sidx = 0; sidx < d; sidx++) {
      for (size_t cidx = 0; cidx < N; cidx++) {
        res[{ sidx, cidx }] = (*this)[{ sidx, cidx }] * rhs[{ sidx, cidx }];
      }
    }

    return res;
  }

  // Given a 64 -bit header and `𝜅` -bits seed as input, this routine is used for mapping them to a polynomial f, following algorithm 5 of
  // https://raccoonfamily.org/wp-content/uploads/2023/07/raccoon.pdf.
  //
  // This routine is invoked when expanding seed for computing public matrix A.
  template<size_t 𝜅>
    requires(d == 1)
  inline constexpr void sampleQ(std::span<const uint8_t, 8> hdr, std::span<const uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> 𝜎)
  {
    shake256::shake256_t xof;
    xof.absorb(hdr);
    xof.absorb(𝜎);
    xof.finalize();

    for (size_t i = 0; i < this->coeffs.size(); i++) {
      uint64_t f_i = 0;

      do {
        std::array<uint8_t, (field::Q_BIT_WIDTH + 7) / 8> b{};
        xof.squeeze(b);

        constexpr uint64_t mask49 = (1ul << field::Q_BIT_WIDTH) - 1ul;

        const auto b_word = raccoon_utils::from_le_bytes<uint64_t>(b);
        f_i = b_word & mask49;
      } while (f_i >= field::Q);

      (*this)[{ 0, i }] = f_i;
    }
  }

  // Returns a masked (d -sharing) encoding of polynomial s.t. when decoded to its standard form, each of `n` coefficents
  // of the polynomials will have canonical value of 0.
  //
  // This is an implementation of algorithm 12 of the Raccoon specification.
  //
  // This implementation collects a lot of inspiration from https://github.com/masksign/raccoon/blob/e789b4b7/ref-c/racc_core.c#L71-L102
  inline constexpr void zero_encoding(mrng::mrng_t<d>& mrng)
  {
    this->fill_with(field::zq_t::zero());

    if constexpr (d > 1) {
      for (size_t sidx = 0; sidx < d; sidx += 2) {
        const auto r = masked_poly_t::sample_polynomial(sidx, mrng);

        for (size_t cidx = 0; cidx < N; cidx++) {
          (*this)[{ sidx, cidx }] += r[{ 0, cidx }];
        }
        for (size_t cidx = 0; cidx < N; cidx++) {
          (*this)[{ sidx + 1, cidx }] -= r[{ 0, cidx }];
        }
      }

      size_t d_idx = 2;
      while (d_idx < d) {
        for (size_t i = 0; i < d; i += 2 * d_idx) {
          for (size_t sidx = i; sidx < i + d_idx; sidx++) {
            const auto r = masked_poly_t::sample_polynomial(sidx, mrng);

            for (size_t cidx = 0; cidx < N; cidx++) {
              (*this)[{ sidx, cidx }] += r[{ 0, cidx }];
            }
            for (size_t cidx = 0; cidx < N; cidx++) {
              (*this)[{ sidx + d_idx, cidx }] -= r[{ 0, cidx }];
            }
          }
        }

        d_idx <<= 1;
      }
    }
  }

  // Returns a fresh d -sharing of the input polynomial, using `zero_encoding` as a subroutine.
  //
  // This is an implementation of algorithm 11 of the Raccoon specification.
  inline constexpr void refresh(mrng::mrng_t<d>& mrng)
  {
    masked_poly_t<d> z{};
    z.zero_encoding(mrng);

    (*this) += z;
  }

  // Returns the standard representation of a masked (d -sharing) polynomial.
  //
  // This is an implementation of algorithm 13 of the Raccoon specification.
  inline constexpr masked_poly_t<1> decode()
  {
    masked_poly_t<1> collapsed_poly{};

    for (size_t sidx = 0; sidx < d; sidx++) {
      for (size_t cidx = 0; cidx < N; cidx++) {
        collapsed_poly[{ 0, cidx }] += (*this)[{ sidx, cidx }];
      }
    }

    return collapsed_poly;
  }
};

// Degree 511 polynomial over Zq | q = 549824583172097
struct polynomial_t
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
  inline constexpr polynomial_t() = default;
  inline constexpr void copy_from(const polynomial_t& src) { std::copy(src.coeffs.begin(), src.coeffs.end(), this->coeffs.begin()); }

  // Access coefficients of the polynomial.
  inline constexpr field::zq_t& operator[](const size_t idx) { return this->coeffs[idx]; }
  inline constexpr const field::zq_t& operator[](const size_t idx) const { return this->coeffs[idx]; }

  inline constexpr size_t size() const { return N; }

  // Same as std::memset, but over polynomial coefficients.
  inline constexpr void fill_with(field::zq_t v) { std::fill(this->coeffs.begin(), this->coeffs.end(), v); }

  // Addition of two polynomials.
  inline constexpr polynomial_t operator+(const polynomial_t& rhs) const
  {
    polynomial_t res{};
    for (size_t i = 0; i < res.size(); i++) {
      res[i] = (*this)[i] + rhs[i];
    }

    return res;
  }

  inline constexpr void operator+=(const polynomial_t& rhs) { *this = *this + rhs; }

  // Performs addition of two polynomials modulo a small moduli `q_𝜈w` s.t. coefficients of input polynomials also ∈ [0, q_𝜈w).
  template<uint64_t q_𝜈w>
  inline constexpr polynomial_t add_mod(const polynomial_t& rhs) const
  {
    polynomial_t res{};
    for (size_t i = 0; i < res.size(); i++) {
      const auto added = (*this)[i].raw() + rhs[i].raw();
      res[i] = reduce_once_mod<q_𝜈w>(added);
    }

    return res;
  }

  // Subtraction of one polynomial from another one.
  inline constexpr polynomial_t operator-(const polynomial_t& rhs) const
  {
    polynomial_t res{};
    for (size_t i = 0; i < res.size(); i++) {
      res[i] = (*this)[i] - rhs[i];
    }

    return res;
  }

  inline constexpr void operator-=(const polynomial_t& rhs) { *this = *this - rhs; }

  // Subtracts one polynomial from another one s.t. each of their coefficients ∈ [0, q_𝜈w) and
  // resulting polynomial coefficients are also reduced modulo `q_𝜈w`.
  template<uint64_t q_𝜈w>
  inline constexpr polynomial_t sub_mod(const polynomial_t& rhs) const
  {
    polynomial_t res{};
    for (size_t i = 0; i < res.size(); i++) {
      const auto neg_rhs = q_𝜈w - rhs[i].raw();
      const auto subtracted = (*this)[i].raw() + neg_rhs;

      res[i] = reduce_once_mod<q_𝜈w>(subtracted);
    }

    return res;
  }

  // Checks for equality of two polynomials.
  inline constexpr bool operator==(const polynomial_t& rhs) const
  {
    bool res = true;
    for (size_t i = 0; i < rhs.size(); i++) {
      res &= (*this)[i] == rhs[i];
    }

    return res;
  }

  // Multiplies two polynomials such that both input and output are in their number theoretic representation.
  inline constexpr polynomial_t operator*(const polynomial_t& rhs) const
  {
    polynomial_t res{};
    for (size_t i = 0; i < res.size(); i++) {
      res[i] = (*this)[i] * rhs[i];
    }

    return res;
  }

  // Rounding shift right of each coefficient of the polynomial, following `Programming note` section on top of page 12 of Raccoon specification.
  template<size_t 𝜈t>
  inline constexpr void rounding_shr()
  {
    constexpr uint64_t q_𝜈t = field::Q >> 𝜈t;
    constexpr uint64_t rounding = 1ul << (𝜈t - 1);

    for (size_t i = 0; i < this->size(); i++) {
      const auto x = (this->coeffs[i].raw() + rounding) >> 𝜈t;
      this->coeffs[i] = reduce_once_mod<q_𝜈t>(x);
    }
  }

  // Shift each coefficient of polynomial leftwards by `offset` (<64) many bits s.t. resulting coefficients ∈ Zq.
  inline constexpr polynomial_t operator<<(const size_t offset) const
  {
    polynomial_t res{};
    for (size_t i = 0; i < res.size(); i++) {
      res[i] = (*this)[i] << offset;
    }

    return res;
  }

  // Centers the coefficients of a polynomial around 0, given that they ∈ [0, q] and resulting polynomial coeffiecients will be signed s.t. ∈ [-q/2, q/2).
  // Collects inspiration from https://github.com/masksign/raccoon/blob/e789b4b7/ref-py/polyr.py#L215-L218
  template<uint64_t q>
  inline constexpr std::array<int64_t, N> center() const
  {
    constexpr auto qby2 = q / 2;

    std::array<int64_t, N> centered_poly{};
    for (size_t i = 0; i < centered_poly.size(); i++) {
      const auto x = this->coeffs[i].raw();

      const auto is_ge = subtle::ct_ge<uint64_t, uint64_t>(x + qby2, q);
      const auto centered_x = static_cast<int64_t>(x) - static_cast<int64_t>(is_ge & q);
      centered_poly[i] = centered_x;
    }

    return centered_poly;
  }

  // Extends the coefficients of a polynomial in [0, q), given that they are currently centered around 0 i.e. they ∈ [-q/2, q/2).
  template<uint64_t q>
  static inline constexpr polynomial_t from_centered(std::span<const int64_t, N> centered)
  {
    polynomial_t extended{};
    for (size_t i = 0; i < centered.size(); i++) {
      const auto x = centered[i];

      const auto mask = static_cast<uint64_t>(x >> 63);
      const auto q_masked = static_cast<int64_t>(q & mask);
      const auto extended_x = static_cast<uint64_t>(x + q_masked);

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

      for (size_t start = 0; start < this->size(); start += lenx2) {
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

      for (size_t start = 0; start < this->size(); start += lenx2) {
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

    for (size_t i = 0; i < this->size(); i++) {
      (*this)[i] *= INV_N;
    }
  }

  // Given a 64 -bit header and `𝜅` -bits seed as input, this routine is used for mapping them to a degree n-1 polynomial f, following algorithm 5 of
  // https://raccoonfamily.org/wp-content/uploads/2023/07/raccoon.pdf.
  //
  // This routine is invoked when expanding seed for computing matrix A.
  template<size_t 𝜅>
  inline constexpr void sampleQ(std::span<const uint8_t, 8> hdr, std::span<const uint8_t, 𝜅 / 8> 𝜎)
  {
    shake256::shake256_t xof;
    xof.absorb(hdr);
    xof.absorb(𝜎);
    xof.finalize();

    for (size_t i = 0; i < this->size(); i++) {
      uint64_t f_i = 0;

      do {
        std::array<uint8_t, (field::Q_BIT_WIDTH + 7) / 8> b{};
        xof.squeeze(b);

        constexpr uint64_t mask49 = (1ul << field::Q_BIT_WIDTH) - 1ul;

        const auto b_word = raccoon_utils::from_le_bytes<uint64_t>(b);
        f_i = b_word & mask49;
      } while (f_i >= field::Q);

      (*this)[i] = f_i;
    }
  }

  // Uniform random sampling of degree n-1 polynomial using a Masked Random Number Generator, following implementation @
  // https://github.com/masksign/raccoon/blob/e789b4b72a2b7e8a2205df49c487736985fc8417/ref-c/mask_random.c#L133-L154
  template<size_t d>
  inline constexpr void sample_polynomial(const size_t idx, mrng::mrng_t<d>& mrng)
    requires(d > 1)
  {
    if (idx >= (d - 1)) {
      this->fill_with(0);
      return;
    }

    constexpr uint64_t mask49 = (1ul << field::Q_BIT_WIDTH) - 1ul;

    for (size_t i = 0; i < this->size(); i++) {
      uint64_t poly_i = 0;

      do {
        const auto v = mrng.get(idx);

        poly_i = v & mask49;
      } while (poly_i >= field::Q);

      (*this)[i] = poly_i;
    }
  }

  // Generate a random degree 511 polynomial.
  static inline constexpr polynomial_t random(prng::prng_t& prng)
  {
    polynomial_t res{};
    for (size_t i = 0; i < res.size(); i++) {
      res[i] = field::zq_t::random(prng);
    }

    return res;
  }
};

}
