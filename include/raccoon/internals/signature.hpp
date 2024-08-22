#pragma once
#include "raccoon/internals/math/field.hpp"
#include "raccoon/internals/polynomial/poly.hpp"
#include "raccoon/internals/polynomial/poly_vec.hpp"
#include "raccoon/internals/utility/serialization.hpp"
#include <algorithm>
#include <cstdint>
#include <optional>

namespace raccoon_sig {

// Raccoon Signature, with fixed byte length
template<size_t 𝜅, size_t k, size_t l, size_t 𝜈w, size_t sig_byte_len>
struct sig_t
{
private:
  std::array<uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> c_hash{};
  std::array<int64_t, k * raccoon_poly::N> h{};
  std::array<int64_t, l * raccoon_poly::N> z{};

public:
  // Constructor(s)
  constexpr sig_t() = default;
  constexpr sig_t(std::span<const uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> c_hash,
                  const raccoon_poly_vec::poly_vec_t<k, 1>& h,
                  const raccoon_poly_vec::poly_vec_t<l, 1>& z)
  {
    // First copy byte array `c_hash`
    std::copy(c_hash.begin(), c_hash.end(), this->c_hash.begin());

    // Then copy polynomial vector `h`
    auto h_span = std::span(this->h);
    for (size_t ridx = 0; ridx < h.num_rows(); ridx++) {
      const size_t offset = ridx * raccoon_poly::N;

      constexpr uint64_t Q_prime = field::Q >> 𝜈w;
      std::copy_n(h[ridx][0].template center<Q_prime>().begin(), raccoon_poly::N, h_span.subspan(offset, raccoon_poly::N).begin());
    }

    // Finally copy polynomial vector `z`
    auto z_span = std::span(this->z);
    for (size_t ridx = 0; ridx < z.num_rows(); ridx++) {
      const size_t offset = ridx * raccoon_poly::N;
      std::copy_n(z[ridx][0].template center<field::Q>().begin(), raccoon_poly::N, z_span.subspan(offset, raccoon_poly::N).begin());
    }
  }

  // Accessor(s)
  constexpr std::span<const uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> get_c_hash() const { return this->c_hash; }
  constexpr std::span<uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> get_c_hash() { return this->c_hash; }

  constexpr raccoon_poly_vec::poly_vec_t<k, 1> get_h() const
  {
    constexpr uint64_t Q_prime = field::Q >> 𝜈w;

    raccoon_poly_vec::poly_vec_t<k, 1> h{};
    const auto h_span = std::span(this->h);

    for (size_t ridx = 0; ridx < h.num_rows(); ridx++) {
      const size_t offset = ridx * raccoon_poly::N;
      h[ridx][0] = raccoon_poly::poly_t::from_centered<Q_prime>(std::span<const int64_t, raccoon_poly::N>(h_span.subspan(offset, raccoon_poly::N)));
    }

    return h;
  }

  constexpr raccoon_poly_vec::poly_vec_t<l, 1> get_z() const
  {
    raccoon_poly_vec::poly_vec_t<l, 1> z{};
    const auto z_span = std::span(this->z);

    for (size_t ridx = 0; ridx < z.num_rows(); ridx++) {
      const size_t offset = ridx * raccoon_poly::N;
      z[ridx][0] = raccoon_poly::poly_t::from_centered<field::Q>(std::span<const int64_t, raccoon_poly::N>(z_span.subspan(offset, raccoon_poly::N)));
    }

    return z;
  }

  // Returns byte length of the serialized signature.
  static constexpr size_t get_byte_len() { return sig_byte_len; }

  // Performs norm bounds check on hint vector `h` and response vector `z`, following section 2.4.4 (and algorithm 4) of the Raccoon specification.
  // If signature passes norms check, returns true, else return false.
  //
  // Though note, it doesn't implement step 1, 2 of algorithm 4; implementation begins from step 3.
  // Following implementation collects some inspiration from https://github.com/masksign/raccoon/blob/e789b4b7/ref-py/racc_core.py#L257-L299
  template<uint64_t Binf, uint64_t B22>
  constexpr bool check_bounds()
  {
    uint64_t h_inf_norm = 0;
    uint64_t h_sqr_norm = 0;

    size_t h_idx = 0;
    while (h_idx < this->h.size()) {
      const auto x = this->h[h_idx];
      const auto abs_x = static_cast<uint64_t>(std::abs(x));

      h_inf_norm = std::max(h_inf_norm, abs_x);
      h_sqr_norm += (abs_x * abs_x);

      h_idx++;
    }

    constexpr field::zq_t Qby2 = field::Q / 2;

    field::zq_t z_inf_norm = 0;
    field::zq_t z_sqr_norm = 0;

    // Lambda for converting a value x ∈ [-Q/2, Q/2), to [0, Q)
    const auto from_centered_to_Zq = [](const int64_t x) -> field::zq_t {
      const auto mask = static_cast<uint64_t>(x >> 63);
      const auto q_prime_masked = static_cast<int64_t>(field::Q & mask);
      const auto extended_x = static_cast<uint64_t>(x + q_prime_masked);

      return extended_x;
    };

    size_t z_idx = 0;
    while (z_idx < this->z.size()) {
      const auto x = from_centered_to_Zq(this->z[z_idx]);

      const auto abs_x = (x > Qby2) ? -x : x;
      z_inf_norm = std::max(z_inf_norm, abs_x);

      const auto abs_x_shft = abs_x >> 32;
      z_sqr_norm += (abs_x_shft * abs_x_shft);

      z_idx++;
    }

    if (h_inf_norm > (Binf >> 𝜈w)) {
      return false;
    }
    if (z_inf_norm > field::zq_t(Binf)) {
      return false;
    }

    static_assert((2 * 𝜈w) >= 64, "𝜈w must be >= 32");
    const auto scaled_h_sqr_norm = h_sqr_norm * (1ul << ((2 * 𝜈w) - 64));

    if ((field::zq_t(scaled_h_sqr_norm) + z_sqr_norm) > field::zq_t(B22)) {
      return false;
    }

    return true;
  }

  // Byte serializes the signature, returning true in case of successful serialization, else returns false.
  constexpr bool to_bytes(std::span<uint8_t, sig_byte_len> bytes) const
  {
    return raccoon_serialization::encode_sig<𝜅, k, l>(this->c_hash, this->h, this->z, bytes);
  }

  // Given a byte serialized signature, returns a valid signature object if it can be successfully decoded, else returns empty std::optional.
  static constexpr std::optional<sig_t> from_bytes(std::span<const uint8_t, sig_byte_len> bytes)
  {
    sig_t sig{};

    const auto ret = raccoon_serialization::decode_sig<𝜅, k, l>(bytes, sig.c_hash, sig.h, sig.z);
    if (ret) {
      return sig;
    } else {
      return std::nullopt;
    }
  }
};

}
