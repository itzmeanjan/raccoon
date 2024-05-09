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
      switch (𝜅) {
        case 128:
        case 256:
          is_𝑢t_valid &= (𝑢t == 6);
          break;
        case 192:
          is_𝑢t_valid &= (𝑢t == 7);
          break;
      }
      is_rep_valid &= (rep == 8);

      break;
    case 2:
      switch (𝜅) {
        case 128:
        case 256:
          is_𝑢t_valid &= (𝑢t == 6);
          break;
        case 192:
          is_𝑢t_valid &= (𝑢t == 7);
          break;
      }
      is_rep_valid &= (rep == 4);

      break;
    case 4:
      switch (𝜅) {
        case 128:
        case 256:
          is_𝑢t_valid &= (𝑢t == 6);
          break;
        case 192:
          is_𝑢t_valid &= (𝑢t == 7);
          break;
      }
      is_rep_valid &= (rep == 2);

      break;
    case 8:
      switch (𝜅) {
        case 128:
        case 256:
          is_𝑢t_valid &= (𝑢t == 5);
          break;
        case 192:
          is_𝑢t_valid &= (𝑢t == 6);
          break;
      }
      is_rep_valid &= (rep == 4);

      break;
    case 16:
      switch (𝜅) {
        case 128:
        case 256:
          is_𝑢t_valid &= (𝑢t == 5);
          break;
        case 192:
          is_𝑢t_valid &= (𝑢t == 6);
          break;
      }
      is_rep_valid &= (rep == 2);

      break;
    case 32:
      switch (𝜅) {
        case 128:
        case 256:
          is_𝑢t_valid &= (𝑢t == 4);
          break;
        case 192:
          is_𝑢t_valid &= (𝑢t == 5);
          break;
      }
      is_rep_valid &= (rep == 4);

      break;
  }

  // From table 2 of the Raccoon specification
  const auto is_valid_raccoon128 = (𝜅 == 128) && (k == 5) && (l == 4) && (is_d_valid) && (is_𝑢t_valid) && (𝜈t == 42) && (is_rep_valid);
  // From table 3 of the Raccoon specification
  const auto is_valid_raccoon192 = (𝜅 == 192) && (k == 7) && (l == 5) && (is_d_valid) && (is_𝑢t_valid) && (𝜈t == 42) && (is_rep_valid);
  // From table 4 of the Raccoon specification
  const auto is_valid_raccoon256 = (𝜅 == 256) && (k == 9) && (l == 7) && (is_d_valid) && (is_𝑢t_valid) && (𝜈t == 42) && (is_rep_valid);

  return is_valid_raccoon128 || is_valid_raccoon192 || is_valid_raccoon256;
}

}
