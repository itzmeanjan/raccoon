#pragma once
#include "internals/public_key.hpp"
#include "internals/secret_key.hpp"

// Raccoon-128 Signing Algorithm.
namespace raccoon128 {

// Raccoon-128 parameters, taken from table 2 of Raccoon specification, offering NIST Post-Quantum security strength category 1.
constexpr size_t 𝜅 = 128;
constexpr size_t k = 5;
constexpr size_t l = 4;
constexpr size_t 𝜈w = 44;
constexpr size_t 𝜈t = 42;
constexpr size_t 𝜔 = 19;
constexpr uint64_t Binf = 41954689765971ul;
constexpr uint64_t B22 = 14656575897ul;

constexpr std::array<size_t, 6> rep{ 8, 4, 2, 4, 2, 4 };
constexpr std::array<size_t, 6> 𝑢t{ 6, 6, 6, 5, 5, 4 };
constexpr std::array<size_t, 6> 𝑢w{ 41, 41, 41, 40, 40, 39 };

// Raccoon-128 public key byte length.
constexpr size_t PKEY_BYTE_LEN = raccoon_utils::get_pkey_byte_len<𝜅, k, raccoon_poly::N, 𝜈t>();

// Raccoon-128 signature byte length.
constexpr size_t SIG_BYTE_LEN = 11524ul;

// Raccoon-128 Public Key.
struct raccoon128_pkey_t
{
private:
  using pk128_t = raccoon_pkey::pkey_t<𝜅, k, 𝜈t>;
  pk128_t pk{};

public:
  explicit inline constexpr raccoon128_pkey_t(pk128_t pk)
    : pk(pk){};

  // Given a byte array as input, deserializes it to construct a Raccoon-128 public key.
  explicit inline constexpr raccoon128_pkey_t(std::span<const uint8_t, PKEY_BYTE_LEN> pk_bytes) { this->pk = pk128_t::from_bytes(pk_bytes); }

  // Given a Raccoon-128 public key object, serializes it as a byte array.
  inline constexpr void as_bytes(std::span<uint8_t, PKEY_BYTE_LEN> pk_bytes) const { this->pk.to_bytes(pk_bytes); }

  // Raccoon-128 public key byte length.
  inline constexpr size_t get_byte_len() const { return PKEY_BYTE_LEN; }

  // Given a (message, signature) pair as byte arrays, verifies the validity of signature, returning boolean truth value in case of success.
  inline constexpr bool verify(std::span<const uint8_t> msg, std::span<const uint8_t, SIG_BYTE_LEN> sig_bytes) const
  {
    return this->pk.verify<l, 𝜈w, 𝜔, sig_bytes.size(), Binf, B22>(msg, sig_bytes);
  }
};

// Raccoon-128 Secret Key with masking order (d-1) s.t. 0 < d <= 32.
template<size_t d>
struct raccoon128_skey_t
{
private:
  using sk128_t = raccoon_skey::skey_t<𝜅, k, l, d, 𝜈t>;
  sk128_t sk{};

public:
  explicit inline constexpr raccoon128_skey_t(sk128_t sk)
    : sk(sk){};

  // Given a byte array as input, deserializes it to construct a Raccoon-128 secret key.
  explicit inline constexpr raccoon128_skey_t(std::span<const uint8_t, sk128_t::get_byte_len()> sk_bytes) { this->sk = sk128_t::from_bytes(sk_bytes); }

  // Given a Raccoon-128 secret key object, serializes it as a byte array.
  inline constexpr void as_bytes(std::span<uint8_t, sk128_t::get_byte_len()> sk_bytes) const { this->sk.to_bytes(sk_bytes, {}); }

  // Raccoon-128 secret key byte length.
  inline constexpr size_t get_byte_len() const { return sk128_t::get_byte_len(); }

  // Generates a new Raccoon-128 keypair, given a 16 -bytes seed.
  static inline constexpr raccoon128_skey_t generate(std::span<const uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> seed)
  {
    return raccoon128_skey_t(sk128_t::template generate<𝑢t[raccoon_utils::log2<d>()], rep[raccoon_utils::log2<d>()]>(seed));
  }

  // Returns a copy of the Raccoon-128 public key held inside the secret key.
  inline constexpr raccoon128_pkey_t get_pkey() const { return raccoon128_pkey_t(this->sk.get_pkey()); }

  // Given a message, signs it, producing a byte serialized signature.
  inline constexpr void sign(std::span<const uint8_t> msg, std::span<uint8_t, SIG_BYTE_LEN> sig_bytes) const
  {
    auto sig = this->sk.template sign<𝑢w[raccoon_utils::log2<d>()], 𝜈w, rep[raccoon_utils::log2<d>()], 𝜔, sig_bytes.size(), Binf, B22>(msg);
    (void)sig.to_bytes(sig_bytes);
  }
};

}
