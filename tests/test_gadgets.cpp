#include "gadgets.hpp"
#include "polynomial.hpp"
#include <gtest/gtest.h>

template<size_t d>
static void
test_refresh_and_decoding_gadgets()
  requires(d > 0)
{
  constexpr polynomial::polynomial_t zero_poly{};
  std::array<polynomial::polynomial_t, d> encoded_poly{};

  mrng::mrng_t<d> mrng;

  gadgets::zero_encoding<d>(encoded_poly, mrng);
  EXPECT_EQ(gadgets::decode<d>(encoded_poly), zero_poly);

  gadgets::refresh<d>(encoded_poly, mrng);
  EXPECT_EQ(gadgets::decode<d>(encoded_poly), zero_poly);
}

TEST(RaccoonSign, RefreshAndDecodingGadgets)
{
  test_refresh_and_decoding_gadgets<1>();
  test_refresh_and_decoding_gadgets<2>();
  test_refresh_and_decoding_gadgets<4>();
  test_refresh_and_decoding_gadgets<8>();
  test_refresh_and_decoding_gadgets<16>();
  test_refresh_and_decoding_gadgets<32>();
}
