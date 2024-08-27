#pragma once
#include "raccoon/internals/rng/prng.hpp"
#include "raccoon/internals/utility/force_inline.hpp"

// Given an arbitrary byte length data as input, this function flips a random bit of it, while sampling choice of random index from input PRNG.
forceinline constexpr void
random_bitflip(std::span<uint8_t> data, prng::prng_t& prng)
{
  if (data.empty()) {
    return;
  }

  size_t random_u64 = 0;
  prng.read(std::span<uint8_t, sizeof(random_u64)>(reinterpret_cast<uint8_t*>(&random_u64), sizeof(random_u64)));

  const size_t random_byte_idx = random_u64 % data.size();
  const size_t random_bit_idx = random_u64 % 8;

  const uint8_t hi_bit_mask = 0xffu << (random_bit_idx + 1);
  const uint8_t lo_bit_mask = 0xffu >> (std::numeric_limits<uint8_t>::digits - random_bit_idx);

  const uint8_t selected_byte = data[random_byte_idx];
  const uint8_t selected_bit = (selected_byte >> random_bit_idx) & 0b1u;
  const uint8_t selected_bit_flipped = (~selected_bit) & 0b1;
  const uint8_t flipped_byte = (selected_byte & hi_bit_mask) ^ (selected_bit_flipped << random_bit_idx) ^ (selected_byte & lo_bit_mask);

  data[random_byte_idx] = flipped_byte;
}
