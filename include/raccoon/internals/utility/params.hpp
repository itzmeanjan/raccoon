#pragma once
#include "utils.hpp"

namespace raccoon_params {

// Validate (preferrably at compile-time) input arguments of Raccoon key generation algorithm
// to ensure that only values from Table {2, 3, 4} of the Raccoon specification are allowed.
static inline constexpr bool
validate_keygen_args(const size_t 𝜅, const size_t k, const size_t l, const size_t d, const size_t 𝑢t, const size_t 𝜈t, const size_t rep)
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

// Validate (preferrably at compile-time) input arguments of Raccoon signing algorithm to ensure that
// only values from Table {2, 3, 4} of the Raccoon specification are allowed.
static inline constexpr bool
validate_sign_args(const size_t 𝜅,
                   const size_t k,
                   const size_t l,
                   const size_t d,
                   const size_t 𝑢w,
                   const size_t 𝜈w,
                   const size_t 𝜈t,
                   const size_t rep,
                   const size_t 𝜔,
                   const size_t sig_byte_len,
                   const uint64_t Binf,
                   const uint64_t B22)
{
  const auto is_d_valid = (d > 0) && raccoon_utils::is_power_of_2(d) && (d <= 32);

  bool is_𝑢w_valid = true;
  bool is_rep_valid = true;

  switch (d) {
    case 1:
      is_𝑢w_valid &= (𝑢w == 41);
      is_rep_valid &= (rep == 8);

      break;
    case 2:
      is_𝑢w_valid &= (𝑢w == 41);
      is_rep_valid &= (rep == 4);

      break;
    case 4:
      is_𝑢w_valid &= (𝑢w == 41);
      is_rep_valid &= (rep == 2);

      break;
    case 8:
      is_𝑢w_valid &= (𝑢w == 40);
      is_rep_valid &= (rep == 4);

      break;
    case 16:
      is_𝑢w_valid &= (𝑢w == 40);
      is_rep_valid &= (rep == 2);

      break;
    case 32:
      is_𝑢w_valid &= (𝑢w == 39);
      is_rep_valid &= (rep == 4);

      break;
  }

  const auto is_valid_raccoon128 = (𝜅 == 128) && (k == 5) && (l == 4) && (is_d_valid) && (is_𝑢w_valid) && (𝜈w == 44) && (𝜈t == 42) && (is_rep_valid) &&
                                   (𝜔 == 19) && (sig_byte_len == 11524) && (Binf == 41954689765971ul) &&
                                   (B22 == 14656575897ul); // From table 2 of the Raccoon specification
  const auto is_valid_raccoon192 = (𝜅 == 192) && (k == 7) && (l == 5) && (is_d_valid) && (is_𝑢w_valid) && (𝜈w == 44) && (𝜈t == 42) && (is_rep_valid) &&
                                   (𝜔 == 31) && (sig_byte_len == 14544) && (Binf == 47419426657048ul) &&
                                   (B22 == 24964497408ul); // From table 3 of the Raccoon specification
  const auto is_valid_raccoon256 = (𝜅 == 256) && (k == 9) && (l == 7) && (is_d_valid) && (is_𝑢w_valid) && (𝜈w == 44) && (𝜈t == 42) && (is_rep_valid) &&
                                   (𝜔 == 44) && (sig_byte_len == 20330) && (Binf == 50958538642039ul) &&
                                   (B22 == 38439957299ul); // From table 4 of the Raccoon specification

  return is_valid_raccoon128 || is_valid_raccoon192 || is_valid_raccoon256;
}

// Validate (preferrably at compile-time) input arguments of Raccoon signing algorithm to ensure that
// only values from Table {2, 3, 4} of the Raccoon specification are allowed.
static inline constexpr bool
validate_verify_args(const size_t 𝜅,
                     const size_t k,
                     const size_t l,
                     const size_t 𝜈w,
                     const size_t 𝜈t,
                     const size_t 𝜔,
                     const size_t sig_byte_len,
                     const uint64_t Binf,
                     const uint64_t B22)
{
  const auto is_valid_raccoon128 = (𝜅 == 128) && (k == 5) && (l == 4) && (𝜈w == 44) && (𝜈t == 42) && (𝜔 == 19) && (sig_byte_len == 11524) &&
                                   (Binf == 41954689765971ul) && (B22 == 14656575897ul); // From table 2 of the Raccoon specification
  const auto is_valid_raccoon192 = (𝜅 == 192) && (k == 7) && (l == 5) && (𝜈w == 44) && (𝜈t == 42) && (𝜔 == 31) && (sig_byte_len == 14544) &&
                                   (Binf == 47419426657048ul) && (B22 == 24964497408ul); // From table 3 of the Raccoon specification
  const auto is_valid_raccoon256 = (𝜅 == 256) && (k == 9) && (l == 7) && (𝜈w == 44) && (𝜈t == 42) && (𝜔 == 44) && (sig_byte_len == 20330) &&
                                   (Binf == 50958538642039ul) && (B22 == 38439957299ul); // From table 4 of the Raccoon specification

  return is_valid_raccoon128 || is_valid_raccoon192 || is_valid_raccoon256;
}

}
