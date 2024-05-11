#pragma once
#include "polynomial.hpp"
#include <array>

namespace poly_vec {

template<size_t rows, size_t d>
  requires(d > 0)
struct poly_vec_t
{
private:
  std::array<polynomial::masked_poly_t<d>, rows> elems{};

public:
  // Constructor(s)
  inline constexpr poly_vec_t() = default;

  // Access the element at row index `idx` of the column vector s.t. `idx < rows`.
  inline constexpr polynomial::masked_poly_t<d>& operator[](const size_t idx) { return this->elems[idx]; }
  inline constexpr const polynomial::masked_poly_t<d>& operator[](const size_t idx) const { return this->elems[idx]; }

  // Returns a column vector of masked (d -sharing) polynomials s.t. when decoded to its standard form,
  // each of `n` coefficents of the those polynomials will have canonical value of 0.
  static inline constexpr poly_vec_t zero_encoding(mrng::mrng_t<d>& mrng)
  {
    poly_vec_t<rows, d> vec{};

    for (size_t ridx = 0; ridx < rows; ridx++) {
      vec[ridx].zero_encoding(mrng);
    }

    return vec;
  }

  // Adds small uniform noise to each masked polynomial of the column vector.
  // This function implements Sum of Uniforms (SU) distribution in masked domain, following algorithm 8 of
  // https://raccoonfamily.org/wp-content/uploads/2023/07/raccoon.pdf.
  template<size_t u, size_t rep, size_t 𝜅>
  inline constexpr void add_rep_noise(prng::prng_t& prng, mrng::mrng_t<d>& mrng)
  {
    for (size_t ridx = 0; ridx < rows; ridx++) {
      (*this)[ridx].template add_rep_noise<u, rep, 𝜅>(ridx, prng, mrng);
    }
  }

  // Apply element-wise Number Theoretic Transform.
  inline constexpr void ntt()
  {
    for (size_t ridx = 0; ridx < rows; ridx++) {
      (*this)[ridx].ntt();
    }
  }

  // Apply element-wise Inverse Number Theoretic Transform.
  inline constexpr void intt()
  {
    for (size_t ridx = 0; ridx < rows; ridx++) {
      (*this)[ridx].intt();
    }
  }
};
}
