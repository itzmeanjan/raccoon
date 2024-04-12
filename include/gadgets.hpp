#pragma once
#include "field.hpp"
#include "mrng.hpp"
#include "utils.hpp"
#include <algorithm>
#include <array>
#include <cstddef>

// Refresh and Decoding Gadgets
namespace gadgets {

// Returns a masked (d -sharing) encoding of degree `n` polynomial s.t. when decoded to its
// standard form, each of `n` coefficents of the polynomials will have canonical value of 0.
//
// This is an implementation of algorithm 12 of the Raccoon specification.
//
// This implementation collects a lot of inspiration from
// https://github.com/masksign/raccoon/blob/e789b4b72a2b7e8a2205df49c487736985fc8417/ref-c/racc_core.c#L71-L102
template<size_t d, size_t n>
static inline void
zero_encoding(std::span<field::zq_t, n * d> poly, mrng::mrng_t<d>& mrng)
  requires(raccoon_utils::is_power_of_2(d) && (d > 0))
{
  std::fill(poly.begin(), poly.end(), 0);

  if constexpr (d > 1) {
    std::array<field::zq_t, n> r{};

    for (size_t i = 0; i < d; i += 2) {
      mrng.sample_polynomial(i, r);

      for (size_t j = 0; j < n; j++) {
        poly[(i + 0) * n + j] += r[j];
        poly[(i + 1) * n + j] -= r[j];
      }
    }

    size_t d_idx = 2;
    while (d_idx < d) {
      for (size_t i = 0; i < d; i += 2 * d_idx) {
        for (size_t j = i; j < i + d_idx; j++) {
          mrng.sample_polynomial(j, r);

          for (size_t k = 0; k < n; k++) {
            poly[(j + 0) * n + k] += r[k];
            poly[(j + d_idx) * n + k] -= r[k];
          }
        }
      }
      d_idx <<= 1;
    }
  }
}

// Returns a fresh d -sharing of the input degree `n` polynomial, using `zero_encoding` as a subroutine.
//
// This is an implementation of algorithm 11 of the Raccoon specification.
template<size_t d, size_t n>
static inline void
refresh(std::span<field::zq_t, n * d> poly, mrng::mrng_t<d>& mrng)
{
  std::array<field::zq_t, poly.size()> z{};
  zero_encoding<d, n>(z, mrng);

  for (size_t i = 0; i < z.size(); i++) {
    poly[i] += z[i];
  }
}

}
