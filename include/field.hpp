// use rand::{thread_rng, Rng};
// use std::cmp::PartialEq;
// use std::mem;
// use std::ops::{Add, Div, Mul, Neg, Sub};

// const Q1: u32 = (1u32 << 24) - (1u32 << 18) + 1u32;
// const Q2: u32 = (1u32 << 25) - (1u32 << 18) + 1u32;
// const Q: u64 = Q1 as u64 * Q2 as u64;
// const RADIX_BIT_WIDTH: usize = (mem::size_of::<u64>() * 8) - Q.leading_zeros() as usize;
// const R: u64 = ((1u128 << (2 * RADIX_BIT_WIDTH as usize)) / Q as u128) as u64;

// #[derive(Debug, Clone, Copy, PartialEq)]
// pub struct Zq(u64);

// impl Zq {
//     /// Constructs a field element s.t. input is already reduced by prime modulo Q.
//     #[allow(dead_code)]
//     pub const fn new(v: u64) -> Zq {
//         Zq(v)
//     }

//     #[allow(dead_code)]
//     pub const fn one() -> Zq {
//         Zq(1)
//     }

//     #[allow(dead_code)]
//     pub const fn zero() -> Zq {
//         Zq(0)
//     }

//     fn xgcd(x: u64, y: u64) -> (i64, i64, i64) {
//         let (mut old_a, mut a) = (1i64, 0i64);
//         let (mut old_b, mut b) = (0i64, 1i64);
//         let (mut old_g, mut g) = (x as i64, y as i64);

//         while g != 0 {
//             let quotient = old_g / g;

//             (old_a, a) = (a, old_a - quotient * a);
//             (old_b, b) = (b, old_b - quotient * b);
//             (old_g, g) = (g, old_g - quotient * g);
//         }

//         (old_a, old_b, old_g) // ax + by = g
//     }

//     pub fn inv(self) -> Zq {
//         if self.0 == 0 {
//             // field element is not invertible
//             return Zq::zero();
//         }

//         let (mut a, _, c) = Zq::xgcd(self.0, Q);
//         if c != 1 {
//             // field element is not invertible
//             return Zq::zero();
//         }

//         a += if a < 0 { Q as i64 } else { 0 };
//         a -= if a >= Q as i64 { Q as i64 } else { 0 };

//         Zq(a as u64)
//     }

//     #[allow(dead_code)]
//     pub fn random() -> Zq {
//         let mut rng = thread_rng();
//         let res: u64 = rng.gen();

//         Zq(barrett_reduce(res as u128))
//     }
// }

// const fn reduce_once(v: u64) -> u64 {
//     let t = v.wrapping_sub(Q);
//     let mask = (t >> 63).wrapping_neg();
//     let q_masked = Q & mask;
//     let reduced = t.wrapping_add(q_masked);

//     reduced
// }

// const fn barrett_reduce(v: u128) -> u64 {
//     let op0_hi = v >> 64;
//     let op0_lo = (v as u64) as u128;

//     let op1_hi = 0u128;
//     let op1_lo = R as u128;

//     let hi = op0_hi * op1_hi;
//     let mid = op0_hi * op1_lo + op0_lo * op1_hi;
//     let lo = op0_lo * op1_lo;

//     let mid_hi = mid >> 64;
//     let mid_lo = (mid as u64) as u128;

//     let t0 = lo >> 64;
//     let t1 = t0 + mid_lo;
//     let carry = t1 >> 64;

//     let res_hi = hi + mid_hi + carry;
//     let res_lo = lo.wrapping_add(mid_lo << 64);

//     let res = ((res_hi & 0xfffffu128) << 30) | (res_lo >> (2 * RADIX_BIT_WIDTH));
//     let t2 = res * Q as u128;
//     let t3 = (v - t2) as u64;

//     reduce_once(t3)
// }

// impl Add for Zq {
//     type Output = Zq;

//     fn add(self, rhs: Self) -> Self::Output {
//         Zq(reduce_once(self.0 + rhs.0))
//     }
// }

// impl Mul for Zq {
//     type Output = Zq;

//     fn mul(self, rhs: Self) -> Self::Output {
//         Zq(barrett_reduce(self.0 as u128 * rhs.0 as u128))
//     }
// }

// impl Neg for Zq {
//     type Output = Zq;

//     fn neg(self) -> Self::Output {
//         Zq(Q - self.0)
//     }
// }

// impl Sub for Zq {
//     type Output = Zq;

//     fn sub(self, rhs: Self) -> Self::Output {
//         self + (-rhs)
//     }
// }

// impl Div for Zq {
//     type Output = Zq;

//     fn div(self, rhs: Self) -> Self::Output {
//         self * rhs.inv()
//     }
// }

#pragma once

#include "u128.hpp"
#include <cstdint>
#include <limits>

namespace field {

constexpr uint32_t Q1 = (1u << 24) - (1u << 18) + 1u;
constexpr uint32_t Q2 = (1u << 25) - (1u << 18) + 1u;
constexpr uint64_t Q = static_cast<uint64_t>(Q1) * static_cast<uint64_t>(Q2);

constexpr size_t Q_BIT_WIDTH = std::bit_width(Q);

constexpr uint64_t R = ((u128::u128_t::from(1ul) << (2 * Q_BIT_WIDTH)) / u128::u128_t::from(Q)).to<uint64_t>();

struct zq_t
{
private:
  uint64_t v = 0;

  // Given a 64 -bit unsigned integer `v` such that `v` ∈ [0, 2*Q), this routine can be invoked for reducing `v` modulo prime Q.
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

public:
  inline constexpr zq_t() = default;
  inline constexpr zq_t(const uint64_t v) { this->v = v; }

  static inline constexpr zq_t zero() { return zq_t(); }
  static inline constexpr zq_t one() { return zq_t(1); }

  // Modulo addition over prime field Zq
  inline constexpr zq_t operator+(const zq_t rhs) const { return reduce_once(this->v + rhs.v); }
  inline constexpr void operator+=(const zq_t rhs) { *this = *this + rhs; }

  // Modulo negation/ subtraction over prime field Zq
  inline constexpr zq_t operator-() const { return Q - this->v; }
  inline constexpr zq_t operator-(const zq_t rhs) const { return *this + (-rhs); }
  inline constexpr void operator-=(const zq_t rhs) { *this = *this - rhs; }

  // Modulo multiplication over prime field Zq
  inline constexpr zq_t operator*(const zq_t rhs) const { return barrett_reduce(u128::u128_t::from(this->v) * u128::u128_t::from(rhs.v)); }
  inline constexpr void operator*=(const zq_t rhs) { *this = *this * rhs; }
};

}
