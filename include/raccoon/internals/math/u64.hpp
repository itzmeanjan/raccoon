#pragma once
#include "raccoon/internals/utility/force_inline.hpp"
#include <cstdint>
#include <utility>

namespace u64 {

// Given two unsigned 64 -bit operands, this function computes a full 128 -bit multiplication result such that return value
// keeps result like (high 64 -bits, low 64 -bits).
forceinline constexpr std::pair<uint64_t, uint64_t>
mul_full_u64(const uint64_t lhs, const uint64_t rhs)
{
#ifdef __SIZEOF_INT128__

  __extension__ using uint128 = unsigned __int128;

  const auto res = static_cast<uint128>(lhs) * static_cast<uint128>(rhs);
  const uint64_t res_hi = static_cast<uint64_t>(res >> 64);
  const uint64_t res_lo = static_cast<uint64_t>(res);

  return { res_hi, res_lo };

#else

  constexpr uint64_t MASK32 = (1ul << 32) - 1;

  const uint64_t lhs_hi = lhs >> 32;
  const uint64_t lhs_lo = lhs & MASK32;

  const uint64_t rhs_hi = rhs >> 32;
  const uint64_t rhs_lo = rhs & MASK32;

  const uint64_t lo = lhs_lo * rhs_lo;
  const uint64_t mid = lhs_lo * rhs_hi + lhs_hi * rhs_lo;
  const uint64_t hi = lhs_hi * rhs_hi;

  const uint64_t mid_hi = mid >> 32;
  const uint64_t mid_lo = mid & MASK32;

  const uint64_t carry = ((lo >> 32) + mid_lo) >> 32;

  const uint64_t res_hi = hi + mid_hi + carry;
  const uint64_t res_lo = lo + (mid_lo << 32);

  return { res_hi, res_lo };

#endif
}

}
