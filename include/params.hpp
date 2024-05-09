#pragma once
#include "utils.hpp"

namespace raccoon_params {

// Validate (preferrably at compile-time) input arguments of Raccoon key generation algorithm
// to ensure that only values from Table {2, 3, 4} of the Raccoon specification are allowed.
static inline constexpr bool
validate_keygen_args(size_t 𝜅, size_t k, size_t l, size_t d, size_t 𝑢t, size_t 𝜈t, size_t rep)
{
  const auto is_d_valid = (d > 0) && raccoon_utils::is_power_of_2(d) && (d <= 32);

  bool is_𝑢t_valid = true;
  bool is_rep_valid = true;

  switch (d) {
    case 1:
      is_𝑢t_valid &= (𝑢t == 6);
      is_rep_valid &= (rep == 8);

      break;
    case 2:
      is_𝑢t_valid &= (𝑢t == 6);
      is_rep_valid &= (rep == 4);

      break;
    case 4:
      is_𝑢t_valid &= (𝑢t == 6);
      is_rep_valid &= (rep == 2);

      break;
    case 8:
      is_𝑢t_valid &= (𝑢t == 5);
      is_rep_valid &= (rep == 4);

      break;
    case 16:
      is_𝑢t_valid &= (𝑢t == 5);
      is_rep_valid &= (rep == 2);

      break;
    case 32:
      is_𝑢t_valid &= (𝑢t == 4);
      is_rep_valid &= (rep == 4);

      break;
  }

  const auto is_valid_raccoon128 = (𝜅 == 128) && (k == 5) && (l == 4) && (is_d_valid) && (is_𝑢t_valid) && (𝜈t == 42) && (is_rep_valid);
  return is_valid_raccoon128;
}

}
