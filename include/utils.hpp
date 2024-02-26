#pragma once
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

}
