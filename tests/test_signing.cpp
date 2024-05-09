#include "raccoon.hpp"
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
test_signing(const size_t mlen)
{
  std::array<uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> seed{};
  std::vector<uint8_t> msg(mlen, 0);

  prng::prng_t prng;
  prng.read(seed);
  prng.read(msg);

  std::array<uint8_t, raccoon_utils::get_pkey_byte_len<𝜅, k, polynomial::N, 𝜈t>()> pkey{};
  std::array<uint8_t, raccoon_utils::get_skey_byte_len<𝜅, k, l, d, polynomial::N, 𝜈t>()> skey{};
  std::array<uint8_t, sig_byte_len> sig{};

  raccoon::keygen<𝜅, k, l, d, 𝑢t, 𝜈t, rep>(seed, pkey, skey);
  raccoon::sign<𝜅, k, l, d, 𝑢w, 𝜈w, 𝜈t, rep, 𝜔, sig_byte_len, Binf, B22>(skey, msg, sig);
  const auto is_verified = raccoon::verify<𝜅, k, l, 𝜈w, 𝜈t, 𝜔, sig_byte_len, Binf, B22>(pkey, msg, sig);

  ASSERT_TRUE(is_verified);
}

TEST(RaccoonSign, Raccoon128Signing)
{
  constexpr size_t min_mlen = 0;
  constexpr size_t max_mlen = 32;

  constexpr size_t 𝜅 = 128;
  constexpr size_t k = 5;
  constexpr size_t l = 4;
  constexpr size_t 𝜈w = 44;
  constexpr size_t 𝜈t = 42;
  constexpr size_t 𝜔 = 19;
  constexpr size_t sig_byte_len = 11524;
  constexpr uint64_t Binf = 41954689765971ul;
  constexpr uint64_t B22 = 14656575897ul;

  for (size_t mlen = min_mlen; mlen <= max_mlen; mlen++) {
    test_signing<𝜅, k, l, 1, 41, 6, 𝜈w, 𝜈t, 8, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 2, 41, 6, 𝜈w, 𝜈t, 4, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 4, 41, 6, 𝜈w, 𝜈t, 2, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 8, 40, 5, 𝜈w, 𝜈t, 4, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 16, 40, 5, 𝜈w, 𝜈t, 2, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 32, 39, 4, 𝜈w, 𝜈t, 4, 𝜔, sig_byte_len, Binf, B22>(mlen);
  }
}

TEST(RaccoonSign, Raccoon192Signing)
{
  constexpr size_t min_mlen = 0;
  constexpr size_t max_mlen = 32;

  constexpr size_t 𝜅 = 192;
  constexpr size_t k = 7;
  constexpr size_t l = 5;
  constexpr size_t 𝜈w = 44;
  constexpr size_t 𝜈t = 42;
  constexpr size_t 𝜔 = 31;
  constexpr size_t sig_byte_len = 14544;
  constexpr uint64_t Binf = 47419426657048ul;
  constexpr uint64_t B22 = 24964497408ul;

  for (size_t mlen = min_mlen; mlen <= max_mlen; mlen++) {
    test_signing<𝜅, k, l, 1, 41, 7, 𝜈w, 𝜈t, 8, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 2, 41, 7, 𝜈w, 𝜈t, 4, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 4, 41, 7, 𝜈w, 𝜈t, 2, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 8, 40, 6, 𝜈w, 𝜈t, 4, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 16, 40, 6, 𝜈w, 𝜈t, 2, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 32, 39, 5, 𝜈w, 𝜈t, 4, 𝜔, sig_byte_len, Binf, B22>(mlen);
  }
}

TEST(RaccoonSign, Raccoon256Signing)
{
  constexpr size_t min_mlen = 0;
  constexpr size_t max_mlen = 16;

  constexpr size_t 𝜅 = 256;
  constexpr size_t k = 9;
  constexpr size_t l = 7;
  constexpr size_t 𝜈w = 44;
  constexpr size_t 𝜈t = 42;
  constexpr size_t 𝜔 = 44;
  constexpr size_t sig_byte_len = 20330;
  constexpr uint64_t Binf = 50958538642039ul;
  constexpr uint64_t B22 = 38439957299ul;

  for (size_t mlen = min_mlen; mlen <= max_mlen; mlen++) {
    test_signing<𝜅, k, l, 1, 41, 6, 𝜈w, 𝜈t, 8, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 2, 41, 6, 𝜈w, 𝜈t, 4, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 4, 41, 6, 𝜈w, 𝜈t, 2, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 8, 40, 5, 𝜈w, 𝜈t, 4, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 16, 40, 5, 𝜈w, 𝜈t, 2, 𝜔, sig_byte_len, Binf, B22>(mlen);
    test_signing<𝜅, k, l, 32, 39, 4, 𝜈w, 𝜈t, 4, 𝜔, sig_byte_len, Binf, B22>(mlen);
  }
}
