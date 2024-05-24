#include "raccoon/internals/poly_vec.hpp"
#include <gtest/gtest.h>

template<size_t rows, size_t d>
static void
test_refresh_and_decoding_gadgets()
  requires(d > 0)
{
  const raccoon_poly_vec::poly_vec_t<rows, 1> zero{};
  raccoon_poly_vec::poly_vec_t<rows, d> v{};

  mrng::mrng_t<d> mrng{};

  v.zero_encoding(mrng);
  EXPECT_EQ(v.decode(), zero);

  v.refresh(mrng);
  EXPECT_EQ(v.decode(), zero);
}

TEST(RaccoonSign, RefreshAndDecodingGadgets)
{
  constexpr size_t rows = 7;

  test_refresh_and_decoding_gadgets<rows, 1>();
  test_refresh_and_decoding_gadgets<rows, 2>();
  test_refresh_and_decoding_gadgets<rows, 4>();
  test_refresh_and_decoding_gadgets<rows, 8>();
  test_refresh_and_decoding_gadgets<rows, 16>();
  test_refresh_and_decoding_gadgets<rows, 32>();
}
