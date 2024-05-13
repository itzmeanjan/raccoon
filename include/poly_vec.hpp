#pragma once
#include "masked_poly.hpp"

namespace raccoon_poly_vec {

// A column vector of (un)masked polynomials of degree-511, defined over Zq
template<size_t rows, size_t d>
  requires(d > 0)
struct poly_vec_t
{
private:
  std::array<raccoon_masked_poly::masked_poly_t<d>, rows> elems{};

public:
  // Constructor(s)
  inline constexpr poly_vec_t() = default;

  // Accessor(s)
  inline constexpr raccoon_masked_poly::masked_poly_t<d>& operator[](const size_t idx) { return this->elems[idx]; }
  inline constexpr const raccoon_masked_poly::masked_poly_t<d>& operator[](const size_t idx) const { return this->elems[idx]; }

  // Number of rows in the column vector.
  inline constexpr size_t num_rows() const { return rows; }

  // Returns a column vector of masked (d -sharing) polynomials s.t. when decoded to its standard form, each of `n` coefficents of the those polynomials will
  // have canonical value of 0.
  static inline constexpr poly_vec_t zero_encoding(mrng::mrng_t<d>& mrng)
  {
    poly_vec_t<rows, d> vec{};

    for (size_t ridx = 0; ridx < vec.num_rows(); ridx++) {
      vec[ridx].zero_encoding(mrng);
    }

    return vec;
  }

  // Adds small uniform noise to each masked polynomial of the column vector. This function implements Sum of Uniforms (SU) distribution in masked domain,
  // following algorithm 8 of https://raccoonfamily.org/wp-content/uploads/2023/07/raccoon.pdf.
  template<size_t u, size_t rep, size_t 𝜅>
  inline constexpr void add_rep_noise(prng::prng_t& prng, mrng::mrng_t<d>& mrng)
  {
    for (size_t ridx = 0; ridx < this->num_rows(); ridx++) {
      (*this)[ridx].template add_rep_noise<u, rep, 𝜅>(ridx, prng, mrng);
    }
  }

  // Returns the standard representation of a masked (d -sharing) polynomial vector.
  //
  // This is an implementation of algorithm 13 of the Raccoon specification, extended to a vector.
  inline constexpr poly_vec_t<rows, 1> decode()
  {
    poly_vec_t<rows, 1> collapsed_vec{};

    for (size_t ridx = 0; ridx < collapsed_vec.num_rows(); ridx++) {
      collapsed_vec[ridx] = (*this)[ridx].decode();
    }

    return collapsed_vec;
  }

  // Rounding and right shift of each polynomial, while finally reducing by moduli `Q_prime = floor(Q / 2^bit_offset)`.
  template<size_t bit_offset>
    requires(d == 1)
  inline constexpr void rounding_shr()
  {
    for (size_t ridx = 0; ridx < this->num_rows(); ridx++) {
      (*this)[ridx].template rounding_shr<bit_offset>();
    }
  }

  // Apply element-wise Number Theoretic Transform.
  inline constexpr void ntt()
  {
    for (size_t ridx = 0; ridx < this->num_rows(); ridx++) {
      (*this)[ridx].ntt();
    }
  }

  // Apply element-wise Inverse Number Theoretic Transform.
  inline constexpr void intt()
  {
    for (size_t ridx = 0; ridx < this->num_rows(); ridx++) {
      (*this)[ridx].intt();
    }
  }
};
}
