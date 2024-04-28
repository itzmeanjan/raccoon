#pragma once
#include "field.hpp"
#include "polynomial.hpp"

namespace checks {

// Performs norm bounds check on hint vector `h` and vector `z`, which are encoded into the signature,
// following section 2.4.4 (and algorithm 4) of the Raccoon specification.
//
// Though note, it doesn't implement step 1, 2 of algorithm 4, following implementation begins from step 3.
// Following implementation collects some inspiration from https://github.com/masksign/raccoon/blob/e789b4b7/ref-py/racc_core.py#L257-L299
template<size_t k, size_t l, size_t 𝜈w, uint64_t 𝐵_∞, uint64_t 𝐵22>
static inline constexpr bool
check_bounds(std::span<const int64_t, k * polynomial::N> h, std::span<const polynomial::polynomial_t, l> z)
{
  uint64_t h_inf_norm = 0;
  uint64_t h_sqr_norm = 0;

  for (size_t row_idx = 0; row_idx < k; row_idx++) {
    const size_t offset = row_idx * polynomial::N;

    for (size_t coeff_idx = 0; coeff_idx < polynomial::N; coeff_idx++) {
      const auto x = h[offset + coeff_idx];
      const auto abs_x = static_cast<uint64_t>(std::abs(x));

      h_inf_norm = std::max(h_inf_norm, abs_x);
      h_sqr_norm += abs_x * abs_x;
    }
  }

  constexpr field::zq_t qby2{ field::Q / 2 };

  field::zq_t z_inf_norm{};
  field::zq_t z_sqr_norm{};

  for (size_t row_idx = 0; row_idx < z.size(); row_idx++) {
    for (size_t coeff_idx = 0; coeff_idx < polynomial::N; coeff_idx++) {
      const auto x = z[row_idx][coeff_idx];

      const auto abs_x = x > qby2 ? -x : x;
      z_inf_norm = std::max(z_inf_norm, abs_x);

      const auto abs_x_shft = abs_x >> 32;
      z_sqr_norm += abs_x_shft * abs_x_shft;
    }
  }

  if (h_inf_norm > (𝐵_∞ >> 𝜈w)) {
    return false;
  }
  if (z_inf_norm > field::zq_t(𝐵_∞)) {
    return false;
  }

  const auto scaled_h_sqr_norm = h_sqr_norm * (1ul << ((2 * 𝜈w) - 64));
  if ((field::zq_t(scaled_h_sqr_norm) + z_sqr_norm) > field::zq_t(𝐵22)) {
    return false;
  }

  return true;
}

}
