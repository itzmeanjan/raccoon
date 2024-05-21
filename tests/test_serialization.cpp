#include "field.hpp"
#include "serialization.hpp"
#include "signature.hpp"
#include <algorithm>
#include <gtest/gtest.h>

// Generate a valid random public key in form of `(seed, t)`, serialize it as bytes and finally attempt to deserialize it,
// ensuring both original and deserialized public key components match.
template<size_t 𝜅, size_t k, size_t 𝜈t>
static void
test_encode_decode_public_key()
{
  std::array<uint8_t, 𝜅 / 8> exp_seed{};
  raccoon_poly_vec::poly_vec_t<k, 1> exp_t{};

  std::array<uint8_t, raccoon_utils::get_pkey_byte_len<𝜅, k, raccoon_poly::N, 𝜈t>()> pkey{};

  std::array<uint8_t, 𝜅 / 8> comp_seed{};
  raccoon_poly_vec::poly_vec_t<k, 1> comp_t{};

  constexpr uint64_t coeff_mask = (1ul << (field::Q_BIT_WIDTH - 𝜈t)) - 1;

  // Generate random `(seed, t)`
  prng::prng_t prng;

  prng.read(exp_seed);
  for (size_t i = 0; i < exp_t.num_rows(); i++) {
    for (size_t j = 0; j < raccoon_poly::N; j++) {
      exp_t[i][0][j] = field::zq_t::random(prng).raw() & coeff_mask;
    }
  }

  raccoon_serialization::encode_public_key<𝜅, k, 𝜈t>(exp_seed, exp_t, pkey);
  raccoon_serialization::decode_public_key<𝜅, k, 𝜈t>(pkey, comp_seed, comp_t);

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
  // Because we can only test equality of vector `s`, for unmasked case
  constexpr size_t d = 1;

  raccoon_poly_vec::poly_vec_t<l, d> exp_s{};
  std::array<uint8_t, ((d - 1) * 𝜅 + l * raccoon_poly::N * field::Q_BIT_WIDTH) / 8> s_c{};

  prng::prng_t prng;

  for (size_t i = 0; i < exp_s.num_rows(); i++) {
    for (size_t j = 0; j < exp_s[i].num_shares(); j++) {
      exp_s[i][j] = raccoon_poly::poly_t::random(prng);
    }
  }

  raccoon_serialization::mask_compress<𝜅, l, d>(exp_s, s_c, prng);
  const auto comp_s = raccoon_serialization::mask_decompress<𝜅, l, d>(s_c);

  EXPECT_EQ(exp_s, comp_s);
}

TEST(RaccoonSign, UnmaskedSecretKeyVectorCompressionAndDecompression)
{
  test_unmasked_secret_key_vector_compression_decompression<128, 5>();
  test_unmasked_secret_key_vector_compression_decompression<192, 7>();
  test_unmasked_secret_key_vector_compression_decompression<256, 9>();
}

template<size_t k, size_t l, size_t 𝜅, size_t 𝜈w, size_t sig_byte_len>
static void
test_encode_decode_signature_all_zeros()
{
  std::array<uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> orig_c_hash{};
  raccoon_poly_vec::poly_vec_t<k, 1> orig_h{};
  raccoon_poly_vec::poly_vec_t<l, 1> orig_z{};
  std::array<uint8_t, sig_byte_len> sig_bytes{};

  prng::prng_t prng{};

  // prepare valid input data
  prng.read(orig_c_hash);

  // put garbage data into encoding output memory area
  prng.read(sig_bytes);

  const auto orig_sig = raccoon_sig::sig_t<𝜅, k, l, 𝜈w, sig_byte_len>(orig_c_hash, orig_h, orig_z);
  const bool is_encoded = orig_sig.to_bytes(sig_bytes);

  const auto decoded_sig_opt = raccoon_sig::sig_t<𝜅, k, l, 𝜈w, sig_byte_len>::from_bytes(sig_bytes);

  // ensure that signature got successfully decoded
  const bool is_decoded = decoded_sig_opt.has_value();
  EXPECT_TRUE(is_decoded);

  const auto decoded_sig = decoded_sig_opt.value();

  EXPECT_TRUE(is_encoded);
  EXPECT_TRUE(std::equal(orig_c_hash.begin(), orig_c_hash.end(), decoded_sig.get_c_hash().begin()));
  EXPECT_EQ(orig_h, decoded_sig.get_h());
  EXPECT_EQ(orig_z, decoded_sig.get_z());
}

TEST(RaccoonSign, ZeroPolynomialSecretKeyEncodingAndDecoding)
{
  test_encode_decode_signature_all_zeros<5, 4, 128, 44, 11524>();
  test_encode_decode_signature_all_zeros<7, 5, 192, 44, 14544>();
  test_encode_decode_signature_all_zeros<9, 7, 256, 44, 20330>();
}
