#pragma once
#include "field.hpp"
#include <bit>
#include <cstdint>
#include <cstring>
#include <span>
#include <type_traits>

namespace raccoon_utils {

// Given a byte array of length n (>=0), this routine copies input bytes into destination word, of unsigned type T,
// while placing bytes following little-endian ordering.
template<typename T>
static inline T
from_le_bytes(std::span<const uint8_t> bytes)
  requires(std::is_unsigned_v<T>)
{
  T res = 0;
  const size_t copyable = std::min(sizeof(res), bytes.size());

  if constexpr (std::endian::native == std::endian::little) {
    std::memcpy(&res, bytes.data(), copyable);
  } else {
    for (size_t i = 0; i < copyable; i++) {
      res |= static_cast<T>(bytes[i]) << ((sizeof(res) - i - 1) * 8);
    }
  }

  return res;
}

// Given an unsigned integer as input, this routine returns TRUTH value only if `v` is power of 2, otherwise it returns FALSE.
template<typename T>
static inline constexpr bool
is_power_of_2(const T v)
  requires(std::is_unsigned_v<T>)
{
  return ((v) & (v - 1)) == 0;
}

// Compile-time compute Raccoon public key byte length.
template<size_t 𝜅, size_t k, size_t n, size_t 𝜈t>
static inline constexpr size_t
get_pkey_byte_len()
{
  return (𝜅 + k * n * (field::Q_BIT_WIDTH - 𝜈t)) / 8;
}

}
