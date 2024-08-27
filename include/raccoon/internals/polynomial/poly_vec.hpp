#pragma once
#include "masked_poly.hpp"
#include "poly.hpp"

namespace raccoon_poly_vec {

// A column vector of (un)masked polynomials of degree-511, defined over Zq.
// Only when d = 1, it's the unmasked case.
template<size_t rows, size_t d>
  requires(d > 0)
struct poly_vec_t
{
private:
  std::array<raccoon_masked_poly::masked_poly_t<d>, rows> elems{};

public:
  // Constructor(s)
  constexpr poly_vec_t() = default;

  // Accessor(s)
  constexpr raccoon_masked_poly::masked_poly_t<d>& operator[](const size_t idx) { return this->elems[idx]; }
  constexpr const raccoon_masked_poly::masked_poly_t<d>& operator[](const size_t idx) const { return this->elems[idx]; }

  // Number of rows in the column vector.
  constexpr size_t num_rows() const { return rows; }

  // Addition of two (un)masked polynomial vectors.
  constexpr poly_vec_t operator+(const poly_vec_t& rhs) const
  {
    poly_vec_t res{};

    for (size_t ridx = 0; ridx < this->num_rows(); ridx++) {
      res[ridx] = (*this)[ridx] + rhs[ridx];
    }

    return res;
  }

  // Performs addition of two (un)masked polynomial vectors, reducing each cofficients by a small moduli `Q_prime`, assuming coefficients of input (un)masked
  // polynomial vectors also ∈ [0, Q_prime).
  template<uint64_t Q_prime>
  constexpr poly_vec_t add_mod(const poly_vec_t& rhs) const
  {
    poly_vec_t res{};

    for (size_t ridx = 0; ridx < res.num_rows(); ridx++) {
      res[ridx] = (*this)[ridx].template add_mod<Q_prime>(rhs[ridx]);
    }

    return res;
  }

  // Subtraction of one (un)masked polynomial vector from another one.
  constexpr poly_vec_t operator-(const poly_vec_t& rhs) const
  {
    poly_vec_t res{};

    for (size_t ridx = 0; ridx < res.num_rows(); ridx++) {
      res[ridx] = (*this)[ridx] - rhs[ridx];
    }

    return res;
  }

  // Subtracts one (un)masked polynomial vector from another one s.t. each of the coefficients ∈ [0, Q_prime) and resulting (un)masked polynomial vector's
  // coefficients are reduced modulo `Q_prime`.
  template<uint64_t Q_prime>
  constexpr poly_vec_t sub_mod(const poly_vec_t& rhs) const
  {
    poly_vec_t res{};

    for (size_t ridx = 0; ridx < res.num_rows(); ridx++) {
      res[ridx] = (*this)[ridx].template sub_mod<Q_prime>(rhs[ridx]);
    }

    return res;
  }

  // Multiplication by a polynomial s.t. both polynomial vector (LHS input) and polynomial (RHS input) are in their NTT representation.
  constexpr poly_vec_t operator*(const raccoon_poly::poly_t& rhs) const
  {
    poly_vec_t res{};

    for (size_t ridx = 0; ridx < this->num_rows(); ridx++) {
      for (size_t sidx = 0; sidx < d; sidx++) {
        res[ridx][sidx] = (*this)[ridx][sidx] * rhs;
      }
    }

    return res;
  }

  // Rounding and right shift of each polynomial, while finally reducing by moduli `Q_prime = floor(Q / 2^bit_offset)`.
  template<size_t bit_offset>
    requires(d == 1)
  constexpr void rounding_shr()
  {
    for (size_t ridx = 0; ridx < this->num_rows(); ridx++) {
      (*this)[ridx].template rounding_shr<bit_offset>();
    }
  }

  // Shift polynomial vector leftwards by `offset` (<64) many bits.
  constexpr poly_vec_t operator<<(const size_t offset) const
  {
    poly_vec_t res{};

    for (size_t ridx = 0; ridx < this->num_rows(); ridx++) {
      res[ridx] = (*this)[ridx] << offset;
    }

    return res;
  }

  // [Constant-time] Checks for equality of two (un)masked polynomial vectors.
  constexpr bool operator==(const poly_vec_t<rows, d>& rhs) const
  {
    bool res = true;
    for (size_t i = 0; i < rhs.num_rows(); i++) {
      res &= ((*this)[i] == rhs[i]);
    }

    return res;
  }

  // Apply element-wise Number Theoretic Transform.
  constexpr void ntt()
  {
    for (size_t ridx = 0; ridx < this->num_rows(); ridx++) {
      (*this)[ridx].ntt();
    }
  }

  // Apply element-wise Inverse Number Theoretic Transform.
  constexpr void intt()
  {
    for (size_t ridx = 0; ridx < this->num_rows(); ridx++) {
      (*this)[ridx].intt();
    }
  }

  // Returns a column vector of masked (d -sharing) polynomials s.t. when decoded to its standard form, each of `n` coefficents of the those polynomials will
  // have canonical value of 0.
  static constexpr poly_vec_t zero_encoding(mrng::mrng_t<d>& mrng)
  {
    poly_vec_t<rows, d> vec{};

    for (size_t ridx = 0; ridx < vec.num_rows(); ridx++) {
      vec[ridx].zero_encoding(mrng);
    }

    return vec;
  }

  // Returns a fresh d -sharing of the input polynomial vector, using `zero_encoding` as a subroutine.
  //
  // This is an implementation of algorithm 11 of the Raccoon specification, extended for masked polynomial vectors.
  constexpr void refresh(mrng::mrng_t<d>& mrng)
  {
    for (size_t ridx = 0; ridx < this->num_rows(); ridx++) {
      (*this)[ridx].refresh(mrng);
    }
  }

  // Returns the standard representation of a masked (d -sharing) polynomial vector.
  //
  // This is an implementation of algorithm 13 of the Raccoon specification, extended to a vector.
  constexpr poly_vec_t<rows, 1> decode()
  {
    poly_vec_t<rows, 1> collapsed_vec{};

    for (size_t ridx = 0; ridx < collapsed_vec.num_rows(); ridx++) {
      collapsed_vec[ridx] = (*this)[ridx].decode();
    }

    return collapsed_vec;
  }

  // Adds small uniform noise to each masked polynomial of the column vector. This function implements Sum of Uniforms (SU) distribution in masked domain,
  // following algorithm 8 of https://raccoonfamily.org/wp-content/uploads/2023/07/raccoon.pdf.
  template<size_t u, size_t rep, size_t 𝜅>
  constexpr void add_rep_noise(prng::prng_t& prng, mrng::mrng_t<d>& mrng)
  {
    for (size_t ridx = 0; ridx < this->num_rows(); ridx++) {
      (*this)[ridx].template add_rep_noise<u, rep, 𝜅>(ridx, prng, mrng);
    }
  }
};
}
