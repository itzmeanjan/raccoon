#include "field.hpp"
#include <gtest/gtest.h>

TEST(RaccoonSign, ArithmeticOverZq)
{
  constexpr size_t itr_cnt = 1ul << 20;
  constexpr size_t exp = 1ul << 8;

  prng::prng_t prng;

  for (size_t i = 0; i < itr_cnt; i++) {
    const auto a = field::zq_t::random(prng);
    const auto b = field::zq_t::random(prng);

    // Addition, Subtraction and Negation
    const auto c = a + b;
    const auto d = c - b;
    const auto e = c - a;

    EXPECT_EQ(d, a);
    EXPECT_EQ(e, b);

    // Multiplication, Inversion and Division
    const auto f = a * b;
    const auto g = f / b;
    const auto h = f / a;

    if ((b != field::zq_t::zero()) && (g.second == field::is_invertible_t::yes)) {
      EXPECT_EQ(g.first, a);
    } else {
      EXPECT_EQ(g.first, field::zq_t::zero());
    }

    if ((a != field::zq_t::zero()) && (h.second == field::is_invertible_t::yes)) {
      EXPECT_EQ(h.first, b);
    } else {
      EXPECT_EQ(h.first, field::zq_t::zero());
    }

    // Exponentiation
    const auto j = std::max(a, b);
    const auto k = j ^ exp;

    auto l = field::zq_t::one();
    for (size_t i = 0; i < exp; i++) {
      l *= j;
    }

    EXPECT_EQ(k, l);
  }
}
