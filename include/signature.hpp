#pragma once
#include "field.hpp"
#include "poly.hpp"
#include "poly_vec.hpp"
#include <algorithm>
#include <cstdint>

namespace raccoon_sig {

// Raccoon Signature
template<size_t 𝜅, size_t k, size_t l, size_t 𝜈w>
struct sig_t
{
private:
  std::array<uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> c_hash{};
  std::array<int64_t, k * raccoon_poly::N> h{};
  std::array<int64_t, l * raccoon_poly::N> z{};

public:
  // Constructor(s)
  inline constexpr sig_t() = default;
  inline constexpr sig_t(std::span<const uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> c_hash,
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
  inline constexpr std::span<const uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> get_c_hash() const { return this->c_hash; }
  inline constexpr std::span<uint8_t, (2 * 𝜅) / std::numeric_limits<uint8_t>::digits> get_c_hash() { return this->c_hash; }

  inline constexpr raccoon_poly_vec::poly_vec_t<k, 1> get_h() const
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

  inline constexpr raccoon_poly_vec::poly_vec_t<l, 1> get_z() const
  {
    raccoon_poly_vec::poly_vec_t<l, 1> z{};
    const auto z_span = std::span(this->z);

    for (size_t ridx = 0; ridx < z.num_rows(); ridx++) {
      const size_t offset = ridx * raccoon_poly::N;
      z[ridx][0] = raccoon_poly::poly_t::from_centered<field::Q>(std::span<const int64_t, raccoon_poly::N>(z_span.subspan(offset, raccoon_poly::N)));
    }

    return z;
  }
};

}
