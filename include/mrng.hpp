#pragma once
#include "ascon/aead/ascon80pq.hpp"
#include "ascon/ascon_perm.hpp"
#include "ascon/utils.hpp"
#include "field.hpp"
#include "utils.hpp"
#include <algorithm>
#include <array>
#include <numeric>

// Masked Random Number Generator
namespace mrng {

// Masked Random Number Generator using Ascon80pq AEAD, following
// https://github.com/masksign/raccoon/blob/e789b4b72a2b7e8a2205df49c487736985fc8417/ref-c/mask_random.c#L13-L187
template<size_t d>
  requires((d > 1) && raccoon_utils::is_power_of_2(d))
struct mrng_t
{
private:
  std::array<ascon_perm::ascon_perm_t, d - 1> state{};

public:
  // Creates a Masked Random Number Generator instance, initializing (d-1) RNGs, ready to be squeezed.
  //
  // Following initialization function collects inspiration from
  // https://github.com/masksign/raccoon/blob/e789b4b72a2b7e8a2205df49c487736985fc8417/ref-c/mask_random.c#L81-L124
  inline mrng_t()
  {
    std::array<uint8_t, ascon80pq_aead::KEY_LEN> key;
    std::array<uint8_t, ascon80pq_aead::NONCE_LEN> nonce;

    auto _key = std::span(key);
    auto _nonce = std::span(nonce);

    std::iota(_key.begin(), _key.end(), 0);
    std::iota(_nonce.begin(), _nonce.end(), 0);

    const auto key0 = ascon_utils::from_be_bytes<uint64_t>(_key.template subspan<0, 8>());
    const auto key1 = ascon_utils::from_be_bytes<uint64_t>(_key.template subspan<8, 8>());
    const auto key2 = ascon_utils::from_be_bytes<uint32_t>(_key.template subspan<16, 4>());

    const auto nonce0 = ascon_utils::from_be_bytes<uint64_t>(_nonce.template subspan<0, 8>());
    const auto nonce1 = ascon_utils::from_be_bytes<uint64_t>(_nonce.template subspan<8, 8>());

    for (size_t i = 0; i < d - 1; i++) {
      auto i_share = this->state[i];

      i_share[0] = (ascon80pq_aead::IV << 32) | (key0 >> 32);
      i_share[1] = (key0 << 32) | (key1 >> 32);
      i_share[2] = (key1 << 32) | static_cast<uint64_t>(key2);
      i_share[3] = nonce0;
      i_share[4] = nonce1;
      i_share[3] += i; // Mutating nonce, using index of share 0 <= i < d

      i_share.template permute<ascon_perm::MAX_ROUNDS>();

      i_share[2] ^= (key0 >> 32);
      i_share[3] ^= (key0 << 32) | (key1 >> 32);
      i_share[4] ^= (key1 << 32) | static_cast<uint64_t>(key2);
      i_share[4] ^= 1; // Domain separator
    }
  }

  // Returns a 64 -bit random number, following implementation @
  // https://github.com/masksign/raccoon/blob/e789b4b72a2b7e8a2205df49c487736985fc8417/ref-c/mask_random.c#L126-L131
  inline uint64_t get(const size_t idx)
  {
    if (idx >= (d - 1)) {
      return 0;
    }

    const auto ret = this->state[idx][0];
    this->state[idx].template permute<6>();
    return ret;
  }
};

}
