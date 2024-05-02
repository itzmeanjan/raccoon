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

template<size_t k, size_t l, size_t 𝜅, size_t sig_len>
static void
test_encode_decode_signature_all_zeros()
{
  std::array<uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> orig_c_hash{};
  std::array<int64_t, k * polynomial::N> orig_h{};
  std::array<int64_t, l * polynomial::N> orig_z{};
  std::array<uint8_t, sig_len> sig{};
  std::array<uint8_t, orig_c_hash.size()> comp_c_hash{};
  std::array<int64_t, orig_h.size()> comp_h{};
  std::array<int64_t, orig_z.size()> comp_z{};

  prng::prng_t prng;

  // prepare valid input data
  prng.read(orig_c_hash);
  std::fill(orig_h.begin(), orig_h.end(), 0);
  std::fill(orig_z.begin(), orig_z.end(), 0);

  // put garbage data into encoding output memory area
  prng.read(sig);

  // scramble decoding output memory area
  std::fill(comp_c_hash.begin(), comp_c_hash.end(), 0);
  std::fill(comp_h.begin(), comp_h.end(), std::numeric_limits<int64_t>::max());
  std::fill(comp_z.begin(), comp_z.end(), std::numeric_limits<int64_t>::max());

  const auto is_encoded = serialization::encode_sig<k, l, 𝜅, sig_len>(orig_c_hash, orig_h, orig_z, sig);
  const auto is_decoded = serialization::decode_sig<k, l, 𝜅, sig_len>(sig, comp_c_hash, comp_h, comp_z);

  EXPECT_TRUE(is_encoded);
  EXPECT_TRUE(is_decoded);
  EXPECT_EQ(orig_c_hash, comp_c_hash);
  EXPECT_EQ(orig_h, comp_h);
  EXPECT_EQ(orig_z, comp_z);
}

TEST(RaccoonSign, ZeroPolynomialSecretKeyEncodingAndDecoding)
{
  test_encode_decode_signature_all_zeros<5, 4, 128, 11524>();
  test_encode_decode_signature_all_zeros<7, 5, 192, 14544>();
  test_encode_decode_signature_all_zeros<9, 7, 256, 20330>();
}
