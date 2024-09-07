#pragma once
#include "raccoon/internals/utility/force_inline.hpp"
#include <cstdint>
#include <utility>

#ifdef USE_INT128_TYPE
#undef USE_INT128_TYPE
#endif

#if defined __GNUG__ && defined __SIZEOF_INT128__ && defined PREFER_INT128_COMPILER_EXTENSION_TYPE
#define USE_INT128_TYPE
#endif

namespace u64 {

// Given two unsigned 64 -bit operands, this function computes a full 128 -bit multiplication result such that return value
// keeps result like (high 64 -bits, low 64 -bits).
//
// Collects inspiration from https://github.com/itzmeanjan/rescue-prime/blob/faa22ec080a8a7979cee0e4f8e06917c527d82d9/include/ff.hpp#L15-L70.
forceinline constexpr std::pair<uint64_t, uint64_t>
mul_full_u64(const uint64_t lhs, const uint64_t rhs)
{
#ifdef USE_INT128_TYPE

  __extension__ using uint128 = unsigned __int128;

  const auto res = static_cast<uint128>(lhs) * static_cast<uint128>(rhs);
  const uint64_t res_hi = static_cast<uint64_t>(res >> 64);
  const uint64_t res_lo = static_cast<uint64_t>(res);

  return { res_hi, res_lo };

#else

  constexpr uint64_t MASK32 = (1ul << 32) - 1;

  const uint64_t lhs_hi32 = lhs >> 32;
  const uint64_t lhs_lo32 = lhs & MASK32;

  const uint64_t rhs_hi32 = rhs >> 32;
  const uint64_t rhs_lo32 = rhs & MASK32;

  const uint64_t hi = lhs_hi32 * rhs_hi32;
  const uint64_t lo = lhs_lo32 * rhs_lo32;

  const uint64_t loxhi = lhs_lo32 * rhs_hi32;
  const uint64_t hixlo = lhs_hi32 * rhs_lo32;

  const uint64_t loxhi_hi32 = loxhi >> 32;
  const uint64_t loxhi_lo32 = loxhi & MASK32;

  const uint64_t hixlo_hi32 = hixlo >> 32;
  const uint64_t hixlo_lo32 = hixlo & MASK32;

  const uint64_t lo_hi32 = lo >> 32;
  const uint64_t carry = (lo_hi32 + loxhi_lo32 + hixlo_lo32) >> 32;

  const uint64_t res_hi = hi + loxhi_hi32 + hixlo_hi32 + carry;
  const uint64_t res_lo = lo + (loxhi_lo32 << 32) + (hixlo_lo32 << 32);

  return { res_hi, res_lo };

#endif
}

}
