#include "gadgets.hpp"
#include <gtest/gtest.h>

template<size_t d, size_t n>
static void
test_refresh_and_decoding_gadgets()
  requires(d > 1)
{
  constexpr std::array<field::zq_t, n> zero_poly{};

  std::array<field::zq_t, n * d> encoded_poly{};
  std::array<field::zq_t, n> decoded_poly{};

  // Fill destination with some non-zero fixed value, so that we can check
  // if `decode` routine actually works or not
  std::fill(decoded_poly.begin(), decoded_poly.end(), 0x0f);

  mrng::mrng_t<d> mrng;

  gadgets::zero_encoding<d, n>(encoded_poly, mrng);
  gadgets::decode<d, n>(encoded_poly, decoded_poly);

  EXPECT_EQ(decoded_poly, zero_poly);

  std::fill(decoded_poly.begin(), decoded_poly.end(), 0xf0);

  gadgets::refresh<d, n>(encoded_poly, mrng);
  gadgets::decode<d, n>(encoded_poly, decoded_poly);

  EXPECT_EQ(decoded_poly, zero_poly);
}

TEST(RaccoonSign, RefreshAndDecodingGadgets)
{
  test_refresh_and_decoding_gadgets<2, 512>();
  test_refresh_and_decoding_gadgets<4, 512>();
  test_refresh_and_decoding_gadgets<8, 512>();
  test_refresh_and_decoding_gadgets<16, 512>();
  test_refresh_and_decoding_gadgets<32, 512>();
}
