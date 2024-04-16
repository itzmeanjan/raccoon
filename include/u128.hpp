#pragma once
#include "u64.hpp"
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <type_traits>

namespace u128 {

// Wrapper type for emulating some basic arithmetic operations involving 128 -bit unsigned integers i.e. uint128_t.
struct u128_t
{
private:
#ifdef __SIZEOF_INT128__
  __extension__ using uint128 = unsigned __int128;
  uint128 data = 0;
#else
  uint64_t hi = 0;
  uint64_t lo = 0;
#endif

  // Given a 128 -bit unsigned integer as input, this routine returns zero -based index ( counted from LSB side ) of most significant "set" ( i.e. bit value set
  // to 1 ) bit.
  //
  // Collects inspiration from https://github.com/abseil/abseil-cpp/blob/c14dfbf9c1759c39bf4343b9e54a43975fbba930/absl/numeric/int128.cc#L34-L48.
  inline constexpr size_t get_bit_index_of_set_msb() const
  {
#ifdef __SIZEOF_INT128__
    const auto hi = static_cast<uint64_t>(this->data >> 64);
    const auto lo = static_cast<uint64_t>(this->data >> 0);

    if (hi > 0) {
      return 127ul - std::countl_zero(hi);
    } else {
      return 63ul - std::countl_zero(lo);
    }
#else
    if (this->hi > 0) {
      return 127ul - std::countl_zero(this->hi);
    } else {
      return 63ul - std::countl_zero(this->lo);
    }
#endif
  }

  // Computes division/ modulo s.t. both operands are 128 -bit unsigned integers, using shift-subtract algorithm.
  //
  // Collects inspiration from https://github.com/abseil/abseil-cpp/blob/c14dfbf9c1759c39bf4343b9e54a43975fbba930/absl/numeric/int128.cc#L50-L89.
  static inline constexpr std::pair<u128_t, u128_t> divmod(u128_t dividend, u128_t divisor)
  {
    if (divisor > dividend) {
      return { u128_t(), dividend };
    }

    if (divisor == dividend) {
      return { u128_t::from(1ul), u128_t() };
    }

    auto quotient = u128_t();

    const auto shift = dividend.get_bit_index_of_set_msb() - divisor.get_bit_index_of_set_msb();
    divisor <<= shift;

    for (size_t i = 0; i <= shift; i++) {
      quotient <<= 1;

      if (dividend >= divisor) {
        dividend -= divisor;
        quotient |= u128_t::from(1ul);
      }

      divisor >>= 1;
    }

    return { quotient, dividend };
  }

public:
  // Default constructor, initializes all bits with default value 0.
  constexpr u128_t() = default;

// Explicit constructor, initializes with provided value.
#ifdef __SIZEOF_INT128__
  constexpr u128_t(const uint128 v) { this->data = v; }
#else
  constexpr u128_t(const uint64_t hi, const uint64_t lo)
  {
    this->hi = hi;
    this->lo = lo;
  }
#endif

  // Constructs `u128_t` from any unsigned integer (8/16/32/64 -bit) value.
  template<typename T>
  static constexpr u128_t from(const T v)
    requires(std::is_unsigned_v<T>)
  {
    u128_t res{};

#ifdef __SIZEOF_INT128__
    res.data = static_cast<uint128>(v);
#else
    res.hi = 0;
    res.lo = static_cast<uint64_t>(v);
#endif

    return res;
  }

  // Given one `u128_t` as input, extracts low 8/16/32/64 -bits as output value, based on template argument.
  template<typename T>
  inline constexpr T to() const
    requires(std::is_unsigned_v<T>)
  {
#ifdef __SIZEOF_INT128__
    return static_cast<T>(this->data);
#else
    return static_cast<T>(this->lo);
#endif
  }

  // Modulo addition
  inline constexpr u128_t operator+(const u128_t rhs) const
  {
#ifdef __SIZEOF_INT128__
    return u128_t(this->data + rhs.data);
#else
    constexpr uint64_t u64_max = std::numeric_limits<uint64_t>::max();

    const uint64_t lo = this->lo + rhs.lo;

    const uint64_t tmp = u64_max - rhs.lo;
    const auto carry = static_cast<uint64_t>(this->lo > tmp);

    const uint64_t hi = this->hi + rhs.hi + carry;

    return u128_t(hi, lo);
#endif
  }

  // Compound modulo addition
  inline constexpr void operator+=(const u128_t rhs) { *this = *this + rhs; }

  // Modulo negation
  inline constexpr u128_t operator-() const
  {
#ifdef __SIZEOF_INT128__
    return u128_t(-this->data);
#else
    const uint64_t lo = -this->lo;
    const uint64_t borrow = static_cast<uint64_t>(0ul < this->lo);
    const uint64_t hi = -(this->hi + borrow);

    return u128_t(hi, lo);
#endif
  }

  // Modulo subtraction
  inline constexpr u128_t operator-(const u128_t rhs) const { return *this + (-rhs); }

  // Compound modulo subtraction
  inline constexpr void operator-=(const u128_t rhs) { *this = *this - rhs; }

  // Modulo multiplication
  inline constexpr u128_t operator*(const u128_t rhs) const
  {
#ifdef __SIZEOF_INT128__
    return u128_t(this->data * rhs.data);
#else
    const auto lo128 = u64::mul_full_u64(this->lo, rhs.lo);

    const uint64_t lo = lo128.second;
    const uint64_t hi = this->lo * rhs.hi + this->hi * rhs.lo + lo128.first;

    return u128_t(hi, lo);
#endif
  }

  // Compound modulo multiplication
  inline constexpr void operator*=(const u128_t rhs) { *this = *this * rhs; }

  // Modulo division
  inline constexpr u128_t operator/(const u128_t rhs) const
  {
    const auto res = divmod(*this, rhs);
    return res.first;
  }

  // Compound modulo division
  inline constexpr void operator/=(const u128_t rhs) { *this = *this / rhs; }

  // Computes remainder after division
  inline constexpr u128_t operator%(const u128_t rhs) const
  {
    const auto res = divmod(*this, rhs);
    return res.second;
  }

  // Compound operation, computing remainder after division
  inline constexpr void operator%=(const u128_t rhs) { *this = *this % rhs; }

  // Left shift by n -bits s.t. n < 128
  inline constexpr u128_t operator<<(const size_t n) const
  {
#ifdef __SIZEOF_INT128__
    return u128_t(this->data << n);
#else
    if (n < 64ul) {
      const uint64_t moved_bits = this->lo >> (64ul - n);
      const uint64_t hi = (this->hi << n) | moved_bits;
      const uint64_t lo = this->lo << n;

      return u128_t(hi, lo);
    } else if (n == 64ul) {
      return u128_t(this->lo, 0ul);
    } else {
      const uint64_t moved_bits = this->lo << (n - 64ul);
      return u128_t(moved_bits, 0ul);
    }
#endif
  }

  // Compound operation, left shifting by n -bits s.t. n < 128
  inline constexpr void operator<<=(const size_t n) { *this = *this << n; }

  // Right shift by n -bits s.t. n < 128
  inline constexpr u128_t operator>>(const size_t n) const
  {
#ifdef __SIZEOF_INT128__
    return u128_t(this->data >> n);
#else
    if (n < 64ul) {
      const uint64_t mask = (1ul << n) - 1;
      const uint64_t moved_bits = this->hi & mask;

      const uint64_t hi = this->hi >> n;
      const uint64_t lo = (this->lo >> n) | (moved_bits) << (64ul - n);

      return u128_t(hi, lo);
    } else if (n == 64ul) {
      return u128_t(0ul, this->hi);
    } else {
      const uint64_t moved_bits = this->hi >> (n - 64ul);
      return u128_t(0ul, moved_bits);
    }
#endif
  }

  // Compound operation, right shifting by n -bits s.t. n < 128
  inline constexpr void operator>>=(const size_t n) { *this = *this >> n; }

  // Returns true if and only if, lhs > rhs
  inline constexpr bool operator>(const u128_t rhs) const
  {
#ifdef __SIZEOF_INT128__
    return this->data > rhs.data;
#else
    const bool flg0 = this->hi > rhs.hi;
    const bool flg1 = this->hi == rhs.hi;
    const bool flg2 = this->hi < rhs.hi;
    const bool flg3 = this->lo > rhs.lo;

    const bool flg = flg0 | (flg1 & flg3) | (!flg2 & !flg1);
    return flg;
#endif
  }

  // Returns true if and only if, lhs < rhs
  inline constexpr bool operator<(const u128_t rhs) const { return rhs > *this; }

  // Returns true if and only if, lhs == rhs
  inline constexpr bool operator==(const u128_t rhs) const
  {
#ifdef __SIZEOF_INT128__
    return this->data == rhs.data;
#else
    return (this->hi == rhs.hi) && (this->lo == rhs.lo);
#endif
  }

  // Returns true if and only if, lhs >= rhs
  inline constexpr bool operator>=(const u128_t rhs) const { return (*this > rhs) || (*this == rhs); }

  // Returns true if and only if, lhs <= rhs
  inline constexpr bool operator<=(const u128_t rhs) const { return (*this < rhs) || (*this == rhs); }

  // Bitwise XOR operation
  inline constexpr u128_t operator|(const u128_t rhs) const
  {
#ifdef __SIZEOF_INT128__
    return u128_t(this->data | rhs.data);
#else
    return u128_t(this->hi | rhs.hi, this->lo | rhs.lo);
#endif
  }

  // Compound bitwise XOR operation
  inline constexpr void operator|=(const u128_t rhs) { *this = *this | rhs; }

  // Bitwise AND operation
  inline constexpr u128_t operator&(const u128_t rhs) const
  {
#ifdef __SIZEOF_INT128__
    return u128_t(this->data & rhs.data);
#else
    return u128_t(this->hi & rhs.hi, this->lo & rhs.lo);
#endif
  }
};

}
