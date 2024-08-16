#include "raccoon/raccoon128.hpp"
#include "test_helper.hpp"
#include <gtest/gtest.h>

// Test Raccoon-128 "key generation -> signing -> verification" flow for random messages of given byte length.
template<size_t d>
static void
test_raccoon128_signing(const size_t till_mlen)
{
  constexpr size_t sk_byte_len = raccoon128::raccoon128_skey_t<d>::get_byte_len();
  constexpr size_t pk_byte_len = raccoon128::raccoon128_pkey_t::get_byte_len();

  std::vector<uint8_t> seed(raccoon128::SEED_BYTE_LEN, 0);
  std::vector<uint8_t> sk_bytes(sk_byte_len, 0);
  std::vector<uint8_t> pk_bytes(pk_byte_len, 0);
  std::vector<uint8_t> sig_bytes(raccoon128::SIG_BYTE_LEN, 0);
  std::vector<uint8_t> sig_bytes_copy(raccoon128::SIG_BYTE_LEN, 0);

  auto seed_span = std::span<uint8_t, raccoon128::SEED_BYTE_LEN>(seed);
  auto sk_bytes_span = std::span<uint8_t, sk_byte_len>(sk_bytes);
  auto pk_bytes_span = std::span<uint8_t, pk_byte_len>(pk_bytes);
  auto sig_bytes_span = std::span<uint8_t, raccoon128::SIG_BYTE_LEN>(sig_bytes);
  auto sig_bytes_copy_span = std::span<uint8_t, raccoon128::SIG_BYTE_LEN>(sig_bytes_copy);

  prng::prng_t prng;
  prng.read(seed_span);

  // Generate keypair
  auto skey = raccoon128::raccoon128_skey_t<d>::generate(seed_span);
  auto pkey = skey.get_pkey();

  // First serialize secret key and then deserialize it back
  skey.as_bytes(sk_bytes_span);
  auto decoded_skey = raccoon128::raccoon128_skey_t<d>(sk_bytes_span);

  // Sample a random message -> sign it using same keypair -> verify signature
  for (size_t mlen = 0; mlen <= till_mlen; mlen++) {
    // Serialize public key and again deserialize it back
    pkey.as_bytes(pk_bytes_span);
    auto decoded_pkey = raccoon128::raccoon128_pkey_t(pk_bytes_span);

    // Cause random bit flip in public key, effectively making it malformed
    random_bitflip(pk_bytes_span, prng);
    auto decoded_bad_pkey = raccoon128::raccoon128_pkey_t(pk_bytes_span);

    std::vector<uint8_t> msg(mlen, 0);
    std::vector<uint8_t> msg_copy(mlen, 0);

    auto msg_span = std::span<uint8_t>(msg);
    auto msg_copy_span = std::span<uint8_t>(msg_copy);

    // Sample random message
    prng.read(msg_span);

    // Refresh secret key, sign a random message using refreshed secret key
    decoded_skey.refresh();
    decoded_skey.sign(msg_span, sig_bytes_span);

    std::copy(msg_span.begin(), msg_span.end(), msg_copy_span.begin());
    std::copy(sig_bytes_span.begin(), sig_bytes_span.end(), sig_bytes_copy_span.begin());

    random_bitflip(msg_copy_span, prng);
    random_bitflip(sig_bytes_copy_span, prng);

    // Verify signature using public key
    const bool is_verified0 = decoded_pkey.verify(msg_span, sig_bytes_span);           // msg OK, sig OK, pubkey OK
    const bool is_verified1 = decoded_pkey.verify(msg_copy_span, sig_bytes_span);      // msg BAD, sig OK, pubkey OK
    const bool is_verified2 = decoded_pkey.verify(msg_span, sig_bytes_copy_span);      // msg OK, sig BAD, pubkey OK
    const bool is_verified3 = decoded_pkey.verify(msg_copy_span, sig_bytes_copy_span); // msg BAD, sig BAD, pubkey OK
    const bool is_verified4 = decoded_bad_pkey.verify(msg_span, sig_bytes_span);       // msg OK, sig OK, pubkey BAD

    ASSERT_TRUE(is_verified0);
    if (mlen > 0) {
      // If message length is non-zero, random message byte must have been mutated, hence signature verification must fail.
      ASSERT_FALSE(is_verified1);
    } else {
      // If we're signing empty message, no message bits were there to be mutated, hence signature verification must pass.
      ASSERT_TRUE(is_verified1);
    }
    ASSERT_FALSE(is_verified2);
    ASSERT_FALSE(is_verified3);
    ASSERT_FALSE(is_verified4);
  }
}

TEST(RaccoonSign, Raccoon128Signing)
{
  constexpr size_t min_mlen = 0;
  constexpr size_t max_mlen = 16;
  constexpr size_t step_by = 4;

  for (size_t mlen = min_mlen; mlen <= max_mlen; mlen += step_by) {
    test_raccoon128_signing<1>(mlen);
    test_raccoon128_signing<2>(mlen);
    test_raccoon128_signing<4>(mlen);
    test_raccoon128_signing<8>(mlen);
    test_raccoon128_signing<16>(mlen);
    test_raccoon128_signing<32>(mlen);
  }
}
