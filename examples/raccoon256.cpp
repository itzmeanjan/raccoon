#include "raccoon/raccoon256.hpp"
#include <cassert>
#include <iostream>
#include <sstream>

// Given a bytearray of length N, this function converts it to human readable hex string of length N << 1 | N >= 0
static inline const std::string
to_hex(std::span<const uint8_t> bytes)
{
  std::stringstream ss;
  ss << std::hex;

  for (size_t i = 0; i < bytes.size(); i++) {
    ss << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(bytes[i]);
  }

  return ss.str();
}

// Compile with
// g++ -std=c++20 -Wall -Wextra -pedantic -O3 -march=native -I include -I ascon/include -I sha3/include -I subtle/include examples/raccoon256.cpp
int
main()
{
  constexpr size_t d = 32; // number of shares for masked polynomials
  std::cout << "Raccoon-256 with d = " << d << "\n";

  std::array<uint8_t, 32> seed{};
  std::array<uint8_t, 32> msg{};
  std::array<uint8_t, raccoon256::SIG_BYTE_LEN> sig{};

  // Pseudo random seed for new keypair generation and message to be signed
  prng::prng_t prng;
  prng.read(seed);
  prng.read(msg);

  std::cout << "Seed       : " << to_hex(seed) << "\n";

  // Generate a new Raccoon-256 keypair
  auto skey = raccoon256::raccoon256_skey_t<d>::generate(seed);
  auto pkey = skey.get_pkey();

  std::array<uint8_t, skey.get_byte_len()> sk_bytes{};
  std::array<uint8_t, pkey.get_byte_len()> pk_bytes{};

  skey.as_bytes(sk_bytes); // Byte serialize the secret key
  std::cout << "Secret Key : " << to_hex(sk_bytes) << "\n";

  pkey.as_bytes(pk_bytes); // Byte serialize the public key
  std::cout << "Public Key : " << to_hex(pk_bytes) << "\n";

  // Deserialize the secret key and the public key
  auto decoded_skey = raccoon256::raccoon256_skey_t<d>(sk_bytes);
  auto decoded_pkey = raccoon256::raccoon256_pkey_t(pk_bytes);

  // Refresh shares of the masked secret key
  decoded_skey.refresh();
  // Sign the message using refreshed secret key
  decoded_skey.sign(msg, sig);

  std::cout << "Message    : " << to_hex(msg) << "\n";
  std::cout << "Signature  : " << to_hex(sig) << "\n";

  // Verify the signature, given message and corresponding public key
  const bool is_verified = decoded_pkey.verify(msg, sig);
  assert(is_verified);
  std::cout << "Verified ? : " << std::boolalpha << is_verified << "\n";

  return 0;
}
