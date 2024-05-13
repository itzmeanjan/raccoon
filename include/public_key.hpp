#pragma once
#include "poly_vec.hpp"
#include "polynomial.hpp"
#include "utils.hpp"
#include <algorithm>

namespace raccoon_pkey {

// Raccoon Public Key
template<size_t 𝜅, size_t k, size_t 𝜈t>
struct pkey_t
{
private:
  std::array<uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> seed{};
  poly_vec::poly_vec_t<k, 1> t{};

public:
  // Constructor(s)
  inline constexpr pkey_t() = default;
  inline constexpr pkey_t(std::span<const uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> seed, const poly_vec::poly_vec_t<k, 1>& t)
  {
    std::copy(seed.begin(), seed.end(), this->seed.begin());
    this->t = t;
  }

  // Accessor(s)
  inline constexpr std::span<const uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> get_seed() const { return this->seed; }
  inline constexpr std::span<uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> get_seed_mut() { return this->seed; }
  inline constexpr const poly_vec::poly_vec_t<k, 1>& get_t_mut() const { return this->t; }

  // Byte serializes the public key.
  inline constexpr void to_bytes(std::span<uint8_t, raccoon_utils::get_pkey_byte_len<𝜅, k, polynomial::N, 𝜈t>()> bytes) const
  {
    // Serialize `seed`
    std::copy_n(this->seed.begin(), this->seed.size(), bytes.begin());

    // Serialize `t`
    constexpr size_t coeff_sig_bitcnt = field::Q_BIT_WIDTH - 𝜈t;
    constexpr uint64_t coeff_sig_bitmask = (1ul << coeff_sig_bitcnt) - 1;

    constexpr size_t buf_max_sig_bitcnt = std::lcm(coeff_sig_bitcnt, std::numeric_limits<uint8_t>::digits);
    constexpr size_t buf_max_sig_bytes = buf_max_sig_bitcnt / std::numeric_limits<uint8_t>::digits;

    size_t r_idx = 0;
    size_t pkey_idx = this->seed.size();

    size_t buf_sig_bitcnt = 0;
    uint64_t buffer = 0;

    static_assert(buf_max_sig_bytes <= sizeof(buffer), "Can't serialize public key into bytes using this method !");

    while (r_idx < k) {
      for (size_t c_idx = 0; c_idx < polynomial::N; c_idx++) {
        if (buf_sig_bitcnt == buf_max_sig_bitcnt) {
          raccoon_utils::to_le_bytes(buffer, bytes.subspan(pkey_idx, buf_max_sig_bytes));

          pkey_idx += buf_max_sig_bytes;
          buf_sig_bitcnt = 0;
          buffer = 0;
        }

        buffer |= (this->t[r_idx][{ 0, c_idx }].raw() & coeff_sig_bitmask) << buf_sig_bitcnt;
        buf_sig_bitcnt += coeff_sig_bitcnt;
      }

      r_idx++;
    }

    if (buf_sig_bitcnt == buf_max_sig_bitcnt) {
      raccoon_utils::to_le_bytes(buffer, bytes.subspan(pkey_idx, buf_max_sig_bytes));

      pkey_idx += buf_max_sig_bytes;
      buf_sig_bitcnt = 0;
      buffer = 0;
    }
  }

  // Given a byte serialized public key, this routine helps in deserializing it, producing components (seed, t).
  static inline constexpr pkey_t from_bytes(std::span<const uint8_t, raccoon_utils::get_pkey_byte_len<𝜅, k, polynomial::N, 𝜈t>()> bytes)
  {
    pkey_t<𝜅, k, 𝜈t> pkey{};

    // Deserialize `seed`
    std::copy_n(bytes.begin(), pkey.seed.size(), pkey.seed.begin());

    // Deserialize `t`
    constexpr size_t coeff_sig_bitcnt = field::Q_BIT_WIDTH - 𝜈t;
    constexpr uint64_t coeff_sig_bitmask = (1ul << coeff_sig_bitcnt) - 1;

    constexpr size_t buf_max_sig_bitcnt = std::lcm(coeff_sig_bitcnt, std::numeric_limits<uint8_t>::digits);
    constexpr size_t buf_max_sig_bytes = buf_max_sig_bitcnt / std::numeric_limits<uint8_t>::digits;
    constexpr size_t dec_coeffs_per_round = buf_max_sig_bitcnt / coeff_sig_bitcnt;

    size_t t_idx = 0;
    size_t pkey_idx = pkey.seed.size();

    static_assert(buf_max_sig_bitcnt <= std::numeric_limits<uint64_t>::digits, "Can't deserialize public key from bytes using this method !");

    while (pkey_idx < bytes.size()) {
      auto buffer = raccoon_utils::from_le_bytes<uint64_t>(bytes.subspan(pkey_idx, buf_max_sig_bytes));
      pkey_idx += buf_max_sig_bytes;

      for (size_t i = 0; i < dec_coeffs_per_round; i++) {
        const size_t ridx = t_idx >> polynomial::LOG2N;
        const size_t cidx = t_idx & (polynomial::N - 1);

        pkey.t[ridx][{ 0, cidx }] = field::zq_t(buffer & coeff_sig_bitmask);
        buffer >>= coeff_sig_bitcnt;

        t_idx++;
      }
    }

    return pkey;
  }
};

}