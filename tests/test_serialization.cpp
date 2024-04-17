#include "ntt.hpp"
#include "serialization.hpp"
#include <gtest/gtest.h>
#include <iostream>

// Generate a valid random public key in form of `(seed, t)`, serialize it as bytes and finally attempt to deserialize it,
// ensuring both original and deserialized public key components match.
template<size_t 𝜅, size_t k, size_t n, size_t 𝜈t>
static void
test_encode_decode_public_key()
{
  std::array<uint8_t, 𝜅 / 8> exp_seed{};
  std::array<field::zq_t, k * n> exp_t{};

  std::array<uint8_t, raccoon_utils::get_pkey_byte_len<𝜅, k, n, 𝜈t>()> pkey{};

  std::array<uint8_t, 𝜅 / 8> comp_seed{};
  std::array<field::zq_t, k * n> comp_t{};

  constexpr uint64_t coeff_mask = (1ul << (field::Q_BIT_WIDTH - 𝜈t)) - 1;

  // Generate random `(seed, t)`
  prng::prng_t prng;

  prng.read(exp_seed);
  for (size_t i = 0; i < exp_t.size(); i++) {
    exp_t[i] = field::zq_t::random(prng).raw() & coeff_mask;
  }

  serialization::encode_public_key<𝜅, k, n, 𝜈t>(exp_seed, exp_t, pkey);
  serialization::decode_public_key<𝜅, k, n, 𝜈t>(pkey, comp_seed, comp_t);

  EXPECT_EQ(exp_seed, comp_seed);
  EXPECT_EQ(exp_t, comp_t);

  for (size_t i = 0; i < exp_t.size(); i++) {
    std::cout << exp_t[i].raw() << "\t" << comp_t[i].raw() << "\n";
  }
}

TEST(RaccoonSign, EncodeDecodePublicKey)
{
  test_encode_decode_public_key<128, 5, ntt::N, 42>();
  test_encode_decode_public_key<192, 7, ntt::N, 42>();
  test_encode_decode_public_key<256, 9, ntt::N, 42>();
}
