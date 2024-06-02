#include "raccoon/raccoon256.hpp"
#include <gtest/gtest.h>

// Test Raccoon-256 "key generation -> signing -> verification" flow for random messages of given byte length.
template<size_t d>
static void
test_raccoon256_signing(const size_t till_mlen)
{
  constexpr size_t sk_byte_len = raccoon256::raccoon256_skey_t<d>::get_byte_len();
  constexpr size_t pk_byte_len = raccoon256::raccoon256_pkey_t::get_byte_len();

  std::vector<uint8_t> seed(raccoon256::SEED_BYTE_LEN, 0);
  std::vector<uint8_t> sk_bytes(sk_byte_len, 0);
  std::vector<uint8_t> pk_bytes(pk_byte_len, 0);
  std::vector<uint8_t> sig_bytes(raccoon256::SIG_BYTE_LEN, 0);

  auto seed_span = std::span<uint8_t, raccoon256::SEED_BYTE_LEN>(seed);
  auto sk_bytes_span = std::span<uint8_t, sk_byte_len>(sk_bytes);
  auto pk_bytes_span = std::span<uint8_t, pk_byte_len>(pk_bytes);
  auto sig_bytes_span = std::span<uint8_t, raccoon256::SIG_BYTE_LEN>(sig_bytes);

  prng::prng_t prng;
  prng.read(seed_span);

  // Generate keypair
  auto skey = raccoon256::raccoon256_skey_t<d>::generate(seed_span);
  auto pkey = skey.get_pkey();

  // Serialize both keypair
  skey.as_bytes(sk_bytes_span);
  pkey.as_bytes(pk_bytes_span);

  // Deserialize keypair
  auto decoded_skey = raccoon256::raccoon256_skey_t<d>(sk_bytes_span);
  auto decoded_pkey = raccoon256::raccoon256_pkey_t(pk_bytes_span);

  // Sample a random message -> sign it using same keypair -> verify signature
  for (size_t mlen = 0; mlen <= till_mlen; mlen++) {
    std::vector<uint8_t> msg(mlen, 0);
    auto msg_span = std::span<uint8_t>(msg);

    // Sample random message
    prng.read(msg_span);

    // Refresh secret key, sign a random message using refreshed secret key
    decoded_skey.refresh();
    decoded_skey.sign(msg_span, sig_bytes_span);

    // Verify signature using public key
    const bool is_verified = decoded_pkey.verify(msg_span, sig_bytes_span);

    ASSERT_TRUE(is_verified);
  }
}

TEST(RaccoonSign, Raccoon256Signing)
{
  constexpr size_t min_mlen = 0;
  constexpr size_t max_mlen = 16;
  constexpr size_t step_by = 4;

  for (size_t mlen = min_mlen; mlen <= max_mlen; mlen += step_by) {
    test_raccoon256_signing<1>(mlen);
    test_raccoon256_signing<2>(mlen);
    test_raccoon256_signing<4>(mlen);
    test_raccoon256_signing<8>(mlen);
    test_raccoon256_signing<16>(mlen);
    test_raccoon256_signing<32>(mlen);
  }
}
