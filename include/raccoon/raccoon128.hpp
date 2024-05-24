#pragma once
#include "public_key.hpp"
#include "secret_key.hpp"

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

// Raccoon-128 Secret Key with masking order (d-1).
template<size_t d>
struct raccoon128_skey_t
{
private:
  using sk128_t = raccoon_skey::skey_t<𝜅, k, l, d, 𝜈t>;
  sk128_t sk{};

  // Compile-time lookup for value of `𝑢t`, for given number of shares i.e. `d`.
  static inline consteval size_t get_𝑢t()
  {
    size_t 𝑢t = 0;

    switch (d) {
      case 1:
      case 2:
      case 4:
        𝑢t = 6;
        break;
      case 8:
      case 16:
        𝑢t = 5;
        break;
      case 32:
        𝑢t = 4;
        break;
    }

    return 𝑢t;
  }

  // Compile-time lookup for value of `𝑢w`, for given number of shares i.e. `d`.
  static inline consteval size_t get_𝑢w()
  {
    size_t 𝑢w = 0;

    switch (d) {
      case 1:
      case 2:
      case 4:
        𝑢w = 41;
        break;
      case 8:
      case 16:
        𝑢w = 40;
        break;
      case 32:
        𝑢w = 39;
        break;
    }

    return 𝑢w;
  }

  // Compile-time lookup for value of `rep`, for given number of shares i.e. `d`.
  static inline consteval size_t get_rep()
  {
    size_t rep = 0;

    switch (d) {
      case 1:
        rep = 8;
        break;
      case 2:
        rep = 4;
        break;
      case 4:
        rep = 2;
        break;
      case 8:
        rep = 4;
        break;
      case 16:
        rep = 2;
        break;
      case 32:
        rep = 4;
        break;
    }

    return rep;
  }

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
    return raccoon128_skey_t(sk128_t::template generate<get_𝑢t(), get_rep()>(seed));
  }

  // Returns a copy of the Raccoon-128 public key held inside the secret key.
  inline constexpr raccoon128_pkey_t get_pkey() const { return raccoon128_pkey_t(this->sk.get_pkey()); }

  // Given a message, signs it, producing a byte serialized signature.
  inline constexpr void sign(std::span<const uint8_t> msg, std::span<uint8_t, SIG_BYTE_LEN> sig_bytes) const
  {
    auto sig = this->sk.template sign<get_𝑢w(), 𝜈w, get_rep(), 𝜔, sig_bytes.size(), Binf, B22>(msg);
    (void)sig.to_bytes(sig_bytes);
  }
};

}
