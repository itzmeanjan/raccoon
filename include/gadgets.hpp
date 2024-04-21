#pragma once
#include "field.hpp"
#include "mrng.hpp"
#include "polynomial.hpp"
#include "utils.hpp"

// Refresh and Decoding Gadgets
namespace gadgets {

// Returns a polynomial s.t. each coefficients are set to 0.
template<size_t d>
static inline constexpr void
zero_encoding(std::span<polynomial::polynomial_t, d> masked_poly)
  requires(d == 1)
{
  masked_poly[0].fill_with(0);
}

// Returns a masked (d -sharing) encoding of polynomial s.t. when decoded to its standard form, each of `n` coefficents of the polynomials will have canonical
// value of 0.
//
// This is an implementation of algorithm 12 of the Raccoon specification.
//
// This implementation collects a lot of inspiration from
// https://github.com/masksign/raccoon/blob/e789b4b72a2b7e8a2205df49c487736985fc8417/ref-c/racc_core.c#L71-L102
template<size_t d>
static inline void
zero_encoding(std::span<polynomial::polynomial_t, d> masked_poly, mrng::mrng_t<d>& mrng)
  requires(raccoon_utils::is_power_of_2(d) && (d > 1))
{
  for (size_t i = 0; i < masked_poly.size(); i++) {
    masked_poly[i].fill_with(0);
  }

  if constexpr (masked_poly.size() > 1) {
    polynomial::polynomial_t r{};

    for (size_t i = 0; i < masked_poly.size(); i += 2) {
      r.sample_polynomial(i, mrng);

      masked_poly[i] += r;
      masked_poly[i + 1] -= r;
    }

    size_t d_idx = 2;
    while (d_idx < masked_poly.size()) {
      for (size_t i = 0; i < masked_poly.size(); i += 2 * d_idx) {
        for (size_t j = i; j < i + d_idx; j++) {
          r.sample_polynomial(j, mrng);

          masked_poly[j] += r;
          masked_poly[j + d_idx] -= r;
        }
      }

      d_idx <<= 1;
    }
  }
}

// Because this is requesting refresh of shares in an unmasked polynomial, it doesn't do anything.
template<size_t d>
static inline constexpr void
refresh(std::span<polynomial::polynomial_t, d> masked_poly)
  requires(d == 1)
{
  (void)masked_poly;
}

// Returns a fresh d -sharing of the input polynomial, using `zero_encoding` as a subroutine.
//
// This is an implementation of algorithm 11 of the Raccoon specification.
template<size_t d>
static inline void
refresh(std::span<polynomial::polynomial_t, d> masked_poly, mrng::mrng_t<d>& mrng)
  requires(d > 1)
{
  std::array<polynomial::polynomial_t, masked_poly.size()> z{};
  zero_encoding<d>(z, mrng);

  for (size_t i = 0; i < z.size(); i++) {
    masked_poly[i] += z[i];
  }
}

// Returns the standard representation of a masked (d -sharing) polynomial.
//
// This is an implementation of algorithm 13 of the Raccoon specification.
template<size_t d>
static inline polynomial::polynomial_t
decode(std::span<const polynomial::polynomial_t, d> masked_poly)
  requires(d > 0)
{
  polynomial::polynomial_t poly{};

  for (size_t i = 0; i < masked_poly.size(); i++) {
    poly += masked_poly[i];
  }

  return poly;
}

}
