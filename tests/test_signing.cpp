#include "raccoon/internals/public_key.hpp"
#include "raccoon/internals/secret_key.hpp"
#include <gtest/gtest.h>

// Test key generation -> signing -> verification flow for random message of given byte length.
template<size_t 𝜅,
         size_t k,
         size_t l,
         size_t d,
         size_t 𝑢w,
         size_t 𝑢t,
         size_t 𝜈w,
         size_t 𝜈t,
         size_t rep,
         size_t 𝜔,
         size_t sig_byte_len,
         uint64_t Binf,
         uint64_t B22>
static void
test_signing(const size_t till_mlen)
{
  constexpr size_t seed_byte_len = 𝜅 / std::numeric_limits<uint8_t>::digits;
  constexpr size_t sk_byte_len = raccoon_utils::get_skey_byte_len<𝜅, k, l, d, raccoon_poly::N, 𝜈t>();
  constexpr size_t pk_byte_len = raccoon_utils::get_pkey_byte_len<𝜅, k, raccoon_poly::N, 𝜈t>();

  std::vector<uint8_t> seed(seed_byte_len, 0);
  std::vector<uint8_t> sk_bytes(sk_byte_len, 0);
  std::vector<uint8_t> pk_bytes(pk_byte_len, 0);
  std::vector<uint8_t> sig_bytes(sig_byte_len, 0);

  auto seed_span = std::span<uint8_t, seed_byte_len>(seed);
  auto sk_bytes_span = std::span<uint8_t, sk_byte_len>(sk_bytes);
  auto pk_bytes_span = std::span<uint8_t, pk_byte_len>(pk_bytes);
  auto sig_bytes_span = std::span<uint8_t, sig_byte_len>(sig_bytes);

  prng::prng_t prng;
  prng.read(seed_span);

  // Generate keypair
  auto skey = raccoon_skey::skey_t<𝜅, k, l, d, 𝜈t>::template generate<𝑢t, rep>(seed_span);
  auto pkey = skey.get_pkey();

  // Serialize both keypair
  skey.to_bytes(sk_bytes_span, prng);
  pkey.to_bytes(pk_bytes_span);

  // Deserialize keypair
  auto decoded_skey = raccoon_skey::skey_t<𝜅, k, l, d, 𝜈t>::from_bytes(sk_bytes_span);
  auto decoded_pkey = raccoon_pkey::pkey_t<𝜅, k, 𝜈t>::from_bytes(pk_bytes_span);

  // Sample a random message -> sign it using same keypair -> verify signature
  for (size_t mlen = 0; mlen <= till_mlen; mlen++) {
    std::vector<uint8_t> msg(mlen, 0);
    auto msg_span = std::span<uint8_t>(msg);

    // Sample random message
    prng.read(msg_span);

    // Refresh secret key, sign a random message using refreshed secret key and finally serialize signature
    decoded_skey.refresh();
    auto sig = decoded_skey.template sign<𝑢w, 𝜈w, rep, 𝜔, sig_byte_len, Binf, B22>(msg_span);
    sig.to_bytes(sig_bytes_span);

    // Verify signature using public key
    const auto is_verified = decoded_pkey.template verify<l, 𝜈w, 𝜔, sig_byte_len, Binf, B22>(msg_span, sig_bytes_span);

    ASSERT_TRUE(is_verified);
  }
}

TEST(RaccoonSign, Raccoon256Signing)
{
  constexpr size_t min_mlen = 0;
  constexpr size_t max_mlen = 16;
  constexpr size_t step_by = 4;

  constexpr size_t 𝜅 = 256;
  constexpr size_t k = 9;
  constexpr size_t l = 7;
  constexpr size_t 𝜈w = 44;
  constexpr size_t 𝜈t = 42;
  constexpr size_t 𝜔 = 44;
  constexpr size_t sig_byte_len = 20330;
  constexpr uint64_t Binf = 50958538642039ul;
  constexpr uint64_t B22 = 38439957299ul;

  for (size_t mlen = min_mlen; mlen <= max_mlen; mlen += step_by) {
    test_signing<𝜅, k, l, 1, 41, 6, 𝜈w, 𝜈t, 8, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 2, 41, 6, 𝜈w, 𝜈t, 4, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 4, 41, 6, 𝜈w, 𝜈t, 2, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 8, 40, 5, 𝜈w, 𝜈t, 4, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 16, 40, 5, 𝜈w, 𝜈t, 2, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 32, 39, 4, 𝜈w, 𝜈t, 4, 𝜔, sig_byte_len, Binf, B22>(mlen);
  }
}
