#pragma once
#include "internals/public_key.hpp"
#include "internals/secret_key.hpp"

// Raccoon-192 Signing Algorithm.
namespace raccoon192 {

// Raccoon-192 parameters, taken from table 3 of Raccoon specification, offering NIST Post-Quantum security strength category 3.
static constexpr size_t 𝜅 = 192;
static constexpr size_t k = 7;
static constexpr size_t l = 5;
static constexpr size_t 𝜈w = 44;
static constexpr size_t 𝜈t = 42;
static constexpr size_t 𝜔 = 31;
static constexpr uint64_t Binf = 47419426657048ul;
static constexpr uint64_t B22 = 24964497408ul;

static constexpr std::array<size_t, 6> rep{ 8, 4, 2, 4, 2, 4 };
static constexpr std::array<size_t, 6> 𝑢t{ 7, 7, 7, 6, 6, 5 };
static constexpr std::array<size_t, 6> 𝑢w{ 41, 41, 41, 40, 40, 39 };

// Raccoon-192 seed byte length, used in key generation.
static constexpr size_t SEED_BYTE_LEN = 𝜅 / std::numeric_limits<uint8_t>::digits;

// Raccoon-192 public key byte length.
static constexpr size_t PKEY_BYTE_LEN = raccoon_utils::get_pkey_byte_len<𝜅, k, raccoon_poly::N, 𝜈t>();

// Raccoon-192 signature byte length.
static constexpr size_t SIG_BYTE_LEN = 14544ul;

// Raccoon-192 Public Key.
struct raccoon192_pkey_t
{
private:
  using pk192_t = raccoon_pkey::pkey_t<𝜅, k, 𝜈t>;
  pk192_t pk{};

public:
  explicit constexpr raccoon192_pkey_t(pk192_t pk)
    : pk(pk){};

  // Given a byte array as input, deserializes it to construct a Raccoon-192 public key.
  explicit constexpr raccoon192_pkey_t(std::span<const uint8_t, PKEY_BYTE_LEN> pk_bytes) { this->pk = pk192_t::from_bytes(pk_bytes); }

  // Given a Raccoon-192 public key object, serializes it as a byte array.
  constexpr void as_bytes(std::span<uint8_t, PKEY_BYTE_LEN> pk_bytes) const { this->pk.to_bytes(pk_bytes); }

  // Raccoon-192 public key byte length.
  static constexpr size_t get_byte_len() { return PKEY_BYTE_LEN; }

  // Given a (message, signature) pair as byte arrays, verifies the validity of signature, returning boolean truth value in case of success.
  constexpr bool verify(std::span<const uint8_t> msg, std::span<const uint8_t, SIG_BYTE_LEN> sig_bytes) const
  {
    return this->pk.verify<l, 𝜈w, 𝜔, sig_bytes.size(), Binf, B22>(msg, sig_bytes);
  }
};

// Raccoon-192 Secret Key with masking order (d-1) s.t. 0 < d <= 32.
template<size_t d>
struct raccoon192_skey_t
{
private:
  using sk192_t = raccoon_skey::skey_t<𝜅, k, l, d, 𝜈t>;
  sk192_t sk{};

public:
  explicit constexpr raccoon192_skey_t(sk192_t sk)
    : sk(sk){};

  // Given a byte array as input, deserializes it to construct a Raccoon-192 secret key.
  explicit constexpr raccoon192_skey_t(std::span<const uint8_t, sk192_t::get_byte_len()> sk_bytes) { this->sk = sk192_t::from_bytes(sk_bytes); }

  // Given a Raccoon-192 secret key object, serializes it as a byte array.
  constexpr void as_bytes(std::span<uint8_t, sk192_t::get_byte_len()> sk_bytes) const
  {
    prng::prng_t prng;
    this->sk.to_bytes(sk_bytes, prng);
  }

  // Raccoon-192 secret key byte length.
  static constexpr size_t get_byte_len() { return sk192_t::get_byte_len(); }

  // Generates a new Raccoon-192 keypair, given a 16 -bytes seed.
  static constexpr raccoon192_skey_t generate(std::span<const uint8_t, SEED_BYTE_LEN> seed)
  {
    return raccoon192_skey_t(sk192_t::template generate<𝑢t[raccoon_utils::log2<d>()], rep[raccoon_utils::log2<d>()]>(seed));
  }

  // Returns a copy of the Raccoon-192 public key held inside the secret key.
  constexpr raccoon192_pkey_t get_pkey() const { return raccoon192_pkey_t(this->sk.get_pkey()); }

  // Given a message, signs it, producing a byte serialized signature.
  constexpr void sign(std::span<const uint8_t> msg, std::span<uint8_t, SIG_BYTE_LEN> sig_bytes) const
  {
    this->sk.template sign<𝑢w[raccoon_utils::log2<d>()], 𝜈w, rep[raccoon_utils::log2<d>()], 𝜔, sig_bytes.size(), Binf, B22>(msg, sig_bytes);
  }

  // Refresh the shares of masked secret key polynomial vector `[[s]]`
  constexpr void refresh() { this->sk.refresh(); }
};

}
