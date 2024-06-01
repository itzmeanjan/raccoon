#pragma once
#include "raccoon/internals/rng/prng.hpp"
#include "u128.hpp"
#include <cstdint>
#include <limits>
#include <tuple>

namespace field {

constexpr uint32_t Q1 = (1u << 24) - (1u << 18) + 1u;
constexpr uint32_t Q2 = (1u << 25) - (1u << 18) + 1u;

// Raccoon Modulus `Q` is a composite number defined in section 2.7.2 of https://raccoonfamily.org/wp-content/uploads/2023/07/raccoon.pdf
constexpr uint64_t Q = static_cast<uint64_t>(Q1) * static_cast<uint64_t>(Q2);

constexpr size_t Q_BIT_WIDTH = std::bit_width(Q);

// Precomputed Barrett Reduction Constant, see https://github.com/itzmeanjan/dilithium/blob/609700fa83372d1b8f1543d0d7cb38785bee7975/include/field.hpp#L16-L23
constexpr uint64_t R = ((u128::u128_t::from(1ul) << (2 * Q_BIT_WIDTH)) / u128::u128_t::from(Q)).to<uint64_t>();

// Data type denoting whether `a` is invertible for modulus Q or not.
enum class is_invertible_t : uint8_t
{
  yes = 0xff,
  no = 0x00,
};

// Modulo Arithmetic
struct zq_t
{
private:
  uint64_t v = 0;

  // Given a 64 -bit unsigned integer `v` such that `v` ∈ [0, 2*Q), this routine can be invoked for reducing `v` modulo Q.
  //
  // Collects inspiration from https://github.com/itzmeanjan/dilithium/blob/609700fa83372d1b8f1543d0d7cb38785bee7975/include/field.hpp#L239-L249
  static inline constexpr uint64_t reduce_once(const uint64_t v)
  {
    const auto t = v - Q;
    const auto mask = -(t >> 63);
    const auto q_masked = Q & mask;
    const auto reduced = t + q_masked;

    return reduced;
  }

  // Reduces the result of multiplying two 49 -bit Zq elements, resulting into a 98 -bit number,
  // using Barrett reduction algorithm, which avoids division by any value that is not a power
  // of 2 s.t. returned value will ∈ [0, Q).
  //
  // See https://www.nayuki.io/page/barrett-reduction-algorithm for Barrett reduction algorithm
  // Collects inspiration from https://github.com/itzmeanjan/dilithium/blob/609700fa83372d1b8f1543d0d7cb38785bee7975/include/field.hpp#L73-L134
  static inline constexpr uint64_t barrett_reduce(const u128::u128_t v)
  {
    // Input `v` which is to be reduced, has 98 -bits of significance, from LSB side.
    // Multiply 98 -bit `v` with 50 -bit R, producing 148 -bit `res`, represented as two 128 -bit words.

    const auto op0_hi = v >> 64;
    const auto op0_lo = v & u128::u128_t::from(std::numeric_limits<uint64_t>::max());

    const auto op1_hi = u128::u128_t();
    const auto op1_lo = u128::u128_t::from(R);

    const auto hi = op0_hi * op1_hi;
    const auto mid = op0_hi * op1_lo + op1_hi * op0_lo;
    const auto lo = op0_lo * op1_lo;

    const auto mid_hi = mid >> 64;
    const auto mid_lo = mid & u128::u128_t::from(std::numeric_limits<uint64_t>::max());

    const auto t0 = lo >> 64;
    const auto t1 = t0 + mid_lo;
    const auto carry = t1 >> 64;

    const auto res_hi = hi + mid_hi + carry; // Only low 20 -bits are part of result
    const auto res_lo = lo + (mid_lo << 64); // All 128 -bits are part of result

    // Let's drop low 98 -bits of 148 -bit result, keeping 50 remaining bits
    const auto res = ((res_hi & u128::u128_t::from(0xffffful)) << 30) | (res_lo >> (2 * Q_BIT_WIDTH));
    const auto t2 = res * u128::u128_t::from(Q);
    const auto t3 = (v - t2).to<uint64_t>();

    // t3 must ∈ [0, 2*Q)
    return reduce_once(t3);
  }

  // Extended GCD algorithm, finding a solution for `ax + by = g` s.t. x, y are provided as input, used for computing multiplicative inverse over field Zq.
  //
  // Collects inspiration from https://github.com/itzmeanjan/falcon/blob/cce934dcd092c95808c0bdaeb034312ee7754d7e/include/ff.hpp#L25-L60.
  static inline constexpr std::tuple<int64_t, int64_t, int64_t> xgcd(const uint64_t x, const uint64_t y)
  {
    int64_t old_a = 1, a = 0;
    int64_t old_b = 0, b = 1;
    int64_t old_g = x, g = y;

    while (g != 0) {
      const auto quotient = old_g / g;
      int64_t tmp = 0;

      tmp = old_a;
      old_a = a;
      a = tmp - quotient * a;

      tmp = old_b;
      old_b = b;
      b = tmp - quotient * b;

      tmp = old_g;
      old_g = g;
      g = tmp - quotient * g;
    }

    return { old_a, old_b, old_g }; // ax + by = g
  }

public:
  inline constexpr zq_t() = default;
  inline constexpr zq_t(const uint64_t v) { this->v = v; }

  static inline constexpr zq_t zero() { return zq_t(); }
  static inline constexpr zq_t one() { return zq_t(1); }

  // Modulo addition over field Zq
  inline constexpr zq_t operator+(const zq_t rhs) const { return reduce_once(this->v + rhs.v); }
  inline constexpr void operator+=(const zq_t rhs) { *this = *this + rhs; }

  // Modulo negation/ subtraction over field Zq
  inline constexpr zq_t operator-() const { return Q - this->v; }
  inline constexpr zq_t operator-(const zq_t rhs) const { return *this + (-rhs); }
  inline constexpr void operator-=(const zq_t rhs) { *this = *this - rhs; }

  // Modulo multiplication over field Zq
  inline constexpr zq_t operator*(const zq_t rhs) const { return barrett_reduce(u128::u128_t::from(this->v) * u128::u128_t::from(rhs.v)); }
  inline constexpr void operator*=(const zq_t rhs) { *this = *this * rhs; }

  // Shift operand rightwards by `offset` many bits, ensuring that `offset < 64`.
  inline constexpr zq_t operator>>(const size_t offset) const { return static_cast<uint64_t>(this->v >> offset); }

  // Shift operand leftwards by `offset` many bits s.t. returned value ∈ Zq.
  // Ensure that `offset < 64`.
  inline constexpr zq_t operator<<(const size_t offset) const { return barrett_reduce(u128::u128_t::from(this->v << offset)); }

  // Multiplicative inverse over field Zq
  inline constexpr std::pair<zq_t, is_invertible_t> inv() const
  {
    if (this->v == 0) {
      return { 0, is_invertible_t::no };
    }

    int64_t a, b, g;
    std::tie(a, b, g) = xgcd(this->v, Q);
    (void)b;

    if (g != 1) {
      return { 0, is_invertible_t::no };
    }

    a += a < 0 ? static_cast<int64_t>(Q) : 0;
    a -= a >= static_cast<int64_t>(Q) ? static_cast<int64_t>(Q) : 0;

    return { static_cast<uint64_t>(a), is_invertible_t::yes };
  }
  inline constexpr std::pair<zq_t, is_invertible_t> operator/(const zq_t rhs) const
  {
    const auto rhs_inv = rhs.inv();
    return { *this * rhs_inv.first, rhs_inv.second };
  }

  // Modulo exponentiation over field Zq
  inline constexpr zq_t operator^(const size_t n) const
  {
    zq_t base = *this;

    const zq_t br[]{ zq_t::one(), base };
    zq_t res = br[n & 0b1ul];

    const size_t zeros = std::countl_zero(n);
    const size_t till = 64ul - zeros;

    for (size_t i = 1; i < till; i++) {
      base = base * base;

      const zq_t br[]{ zq_t::one(), base };
      res = res * br[(n >> i) & 0b1ul];
    }

    return res;
  }

  // Comparison operators, see https://en.cppreference.com/w/cpp/language/default_comparisons
  inline constexpr auto operator<=>(const zq_t&) const = default;

  // Generates a random Zq element
  static inline zq_t random(prng::prng_t& prng)
  {
    uint64_t v = 0;
    prng.read(std::span(reinterpret_cast<uint8_t*>(&v), sizeof(v)));

    return barrett_reduce(u128::u128_t::from(v));
  }

  // Returns the underlying value held in canonical form.
  inline constexpr uint64_t raw() const { return this->v; }
};

}
