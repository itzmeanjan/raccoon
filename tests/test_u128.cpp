#include "raccoon/internals/math/u128.hpp"
#include "raccoon/internals/rng/prng.hpp"
#include <gtest/gtest.h>

TEST(RaccoonSign, ArithmeticOverU128)
{
  constexpr size_t ITERATION_COUNT = 1ul << 20;
  prng::prng_t prng;

  size_t rotate_bit_offset = 0;

  for (size_t i = 0; i < ITERATION_COUNT; i++) {
    uint64_t low_a = 0, low_b = 0;

    prng.read(std::span<uint8_t, sizeof(low_a)>(reinterpret_cast<uint8_t*>(&low_a), sizeof(low_a)));
    prng.read(std::span<uint8_t, sizeof(low_b)>(reinterpret_cast<uint8_t*>(&low_b), sizeof(low_b)));

    const auto a = u128::u128_t::from(low_a);
    const auto b = u128::u128_t::from(low_b);

    // Addition, Subtraction and Negation
    const auto c = a + b;
    const auto d = c - a;
    const auto e = c - b;
    const auto f = d + e;

    EXPECT_EQ(d, b);
    EXPECT_EQ(e, a);
    EXPECT_EQ(f, c);

    // Multiplication, Division, Modulo Division
    const auto g = a * b;
    const auto h = g / c;
    const auto j = g % c;
    const auto k = h * c;
    const auto l = k + j;

    EXPECT_EQ(l, g);

    // Bitwise left and right shift
    const auto m = a.rotl(rotate_bit_offset);
    const auto n = m.rotr(rotate_bit_offset);

    EXPECT_EQ(a, n);

    rotate_bit_offset++;
    if (rotate_bit_offset > (sizeof(u128::u128_t) * 8)) {
      rotate_bit_offset = 0;
    }
  }
}
