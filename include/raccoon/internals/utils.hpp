#pragma once
#include "field.hpp"
#include "subtle.hpp"
#include <algorithm>
#include <bit>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <type_traits>

namespace raccoon_utils {

// Given a byte array of length n (>=0), this routine copies input bytes into destination word, of unsigned type T,
// while placing bytes following little-endian ordering.
template<typename T>
static inline constexpr T
from_le_bytes(std::span<const uint8_t> bytes)
  requires(std::is_unsigned_v<T> && (std::endian::native == std::endian::little))
{
  T res = 0;
  auto _res = std::span<uint8_t>(reinterpret_cast<uint8_t*>(&res), sizeof(res));

  const size_t copyable = std::min(sizeof(res), bytes.size());
  std::copy_n(bytes.begin(), copyable, _res.begin());

  return res;
}

// Given an unsigned integer as input, this routine copies source bytes, following little-endian order, into destination
// byte array of length n (>=0).
template<typename T>
static inline constexpr void
to_le_bytes(T v, std::span<uint8_t> bytes)
  requires(std::is_unsigned_v<T> && (std::endian::native == std::endian::little))
{
  auto _v = std::span<uint8_t>(reinterpret_cast<uint8_t*>(&v), sizeof(v));

  const size_t copyable = std::min(sizeof(v), bytes.size());
  std::copy_n(_v.begin(), copyable, bytes.begin());
}

// Given an unsigned integer as input, this routine returns TRUTH value only if `v` is power of 2, otherwise it returns FALSE.
template<typename T>
static inline constexpr bool
is_power_of_2(const T v)
  requires(std::is_unsigned_v<T>)
{
  return ((v) & (v - 1)) == 0;
}

// Given a power of 2 value `v`, this routine returns logarithm base-2 of v.
template<size_t v>
static inline constexpr size_t
log2()
  requires((v > 0) && is_power_of_2<decltype(v)>(v))
{
  return std::countr_zero(v);
}

// Compile-time compute Raccoon public key byte length.
template<size_t 𝜅, size_t k, size_t n, size_t 𝜈t>
static inline constexpr size_t
get_pkey_byte_len()
{
  return (𝜅 + k * n * (field::Q_BIT_WIDTH - 𝜈t)) / 8;
}

// Compile-time compute d -sharing Raccoon secret key byte length.
template<size_t 𝜅, size_t k, size_t l, size_t d, size_t n, size_t 𝜈t>
static inline constexpr size_t
get_skey_byte_len()
  requires(d > 0)
{
  return get_pkey_byte_len<𝜅, k, n, 𝜈t>() + ((d - 1) * 𝜅 + l * n * field::Q_BIT_WIDTH) / 8;
}

// Given two byte arrays of equal length as input, this routine can be used for constant-time checking equality of them.
// If a == b, it returns a 32 -bit unsigned integer s.t. all of its bits are set to 1.
// Else, it returns 32 -bit unsigned integer s.t. all of its bits are set to 0.
template<size_t len>
static inline constexpr uint32_t
ct_eq_byte_array(std::span<const uint8_t, len> a, std::span<const uint8_t, len> b)
{
  uint32_t res = std::numeric_limits<uint32_t>::max();
  for (size_t i = 0; i < a.size(); i++) {
    res &= subtle::ct_eq<uint8_t, uint32_t>(a[i], b[i]);
  }
  return res;
}

}
