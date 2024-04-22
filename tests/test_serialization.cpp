#include "polynomial.hpp"
#include "prng.hpp"
#include "serialization.hpp"
#include <gtest/gtest.h>

// Generate a valid random public key in form of `(seed, t)`, serialize it as bytes and finally attempt to deserialize it,
// ensuring both original and deserialized public key components match.
template<size_t 𝜅, size_t k, size_t 𝜈t>
static void
test_encode_decode_public_key()
{
  std::array<uint8_t, 𝜅 / 8> exp_seed{};
  std::array<polynomial::polynomial_t, k> exp_t{};

  std::array<uint8_t, raccoon_utils::get_pkey_byte_len<𝜅, k, polynomial::N, 𝜈t>()> pkey{};

  std::array<uint8_t, 𝜅 / 8> comp_seed{};
  std::array<polynomial::polynomial_t, k> comp_t{};

  constexpr uint64_t coeff_mask = (1ul << (field::Q_BIT_WIDTH - 𝜈t)) - 1;

  // Generate random `(seed, t)`
  prng::prng_t prng;

  prng.read(exp_seed);
  for (size_t i = 0; i < exp_t.size(); i++) {
    for (size_t j = 0; j < polynomial::N; j++) {
      exp_t[i][j] = field::zq_t::random(prng).raw() & coeff_mask;
    }
  }

  serialization::encode_public_key<𝜅, k, 𝜈t>(exp_seed, exp_t, pkey);
  serialization::decode_public_key<𝜅, k, 𝜈t>(pkey, comp_seed, comp_t);

  EXPECT_EQ(exp_seed, comp_seed);
  EXPECT_EQ(exp_t, comp_t);
}

TEST(RaccoonSign, EncodeDecodePublicKey)
{
  test_encode_decode_public_key<128, 5, 42>();
  test_encode_decode_public_key<192, 7, 42>();
  test_encode_decode_public_key<256, 9, 42>();
}

template<size_t 𝜅, size_t l>
static void
test_unmasked_secret_key_vector_compression_decompression()
{
  // Because secret key vector is unmasked
  constexpr size_t d = 1;

  std::array<polynomial::polynomial_t, l * d> exp_s{};
  std::array<uint8_t, ((d - 1) * 𝜅 + l * polynomial::N * field::Q_BIT_WIDTH) / 8> s_c{};
  std::array<polynomial::polynomial_t, l * d> com_s{};

  prng::prng_t prng;

  for (size_t i = 0; i < exp_s.size(); i++) {
    for (size_t j = 0; j < exp_s[i].size(); j++) {
      exp_s[i][j] = field::zq_t::random(prng);
    }
  }

  serialization::mask_compress<𝜅, l, d>(exp_s, s_c, prng);
  serialization::mask_decompress<𝜅, l, d>(s_c, com_s);

  EXPECT_EQ(exp_s, com_s);
}

TEST(RaccoonSign, UnmaskedSecretKeyVectorCompressionAndDecompression)
{
  test_unmasked_secret_key_vector_compression_decompression<128, 5>();
  test_unmasked_secret_key_vector_compression_decompression<192, 7>();
  test_unmasked_secret_key_vector_compression_decompression<256, 9>();
}
