#pragma once
#include "poly_vec.hpp"
#include "polynomial.hpp"
#include <array>
#include <cstddef>

namespace poly_mat {

// A matrix of dimension `rows x cols` s.t. each of its elements are a degree 511 polynomial over Zq
template<size_t rows, size_t cols>
  requires((rows > 0) && (cols > 0))
struct poly_mat_t
{
private:
  std::array<polynomial::masked_poly_t<1>, rows * cols> elems{};

public:
  // Constructor(s)
  inline constexpr poly_mat_t() = default;

  // Access element at index (ridx, cidx) of the matrix s.t. `ridx < rows` and `cidx < cols`.
  inline constexpr polynomial::masked_poly_t<1>& operator[](const std::pair<size_t, size_t> idx) { return this->elems[idx.first * cols + idx.second]; }
  inline constexpr const polynomial::masked_poly_t<1>& operator[](const std::pair<size_t, size_t> idx) const
  {
    return this->elems[idx.first * cols + idx.second];
  }

  // Add two matrices of equal dimension
  inline constexpr poly_mat_t operator+(const poly_mat_t<rows, cols>& rhs) const
  {
    poly_mat_t<rows, cols> res{};

    for (size_t ridx = 0; ridx < rows; ridx++) {
      for (size_t cidx = 0; cidx < cols; cidx++) {
        res[{ ridx, cidx }] = (*this)[{ ridx, cidx }] + rhs[{ ridx, cidx }];
      }
    }

    return res;
  }

  inline constexpr void operator+=(const poly_mat_t<rows, cols>& rhs) { *this = *this + rhs; }

  // Subtract one matrix from another one s.t. both of them have equal dimension
  inline constexpr poly_mat_t operator-(const poly_mat_t<rows, cols>& rhs) const
  {
    poly_mat_t<rows, cols> res{};

    for (size_t ridx = 0; ridx < rows; ridx++) {
      for (size_t cidx = 0; cidx < cols; cidx++) {
        res[{ ridx, cidx }] = (*this)[{ ridx, cidx }] - rhs[{ ridx, cidx }];
      }
    }

    return res;
  }

  inline constexpr poly_mat_t operator-=(const poly_mat_t<rows, cols>& rhs) { *this = *this - rhs; }

  // Multiply a matrix by another vector of compatible dimension, assuming both of them are in their NTT representation.
  template<size_t d>
  inline constexpr poly_vec::poly_vec_t<rows, d> operator*(const poly_vec::poly_vec_t<cols, d>& rhs) const
  {
    poly_vec::poly_vec_t<rows, d> res{};

    for (size_t row_idx = 0; row_idx < rows; row_idx++) {
      for (size_t col_idx = 0; col_idx < cols; col_idx++) {
        for (size_t shr_idx = 0; shr_idx < d; shr_idx++) {

          // Multiply two equal degree polynomials in their NTT representation
          for (size_t coeff_idx = 0; coeff_idx < polynomial::N; coeff_idx++) {
            res[row_idx][{ shr_idx, coeff_idx }] += (*this)[{ row_idx, col_idx }][{ shr_idx, coeff_idx }] * rhs[col_idx][{ shr_idx, coeff_idx }];
          }
        }
      }
    }

    return res;
  }

  // Given `𝜅` -bits seed as input, this routine is used for generating public matrix A, following algorithm 6 of
  // https://raccoonfamily.org/wp-content/uploads/2023/07/raccoon.pdf.
  template<size_t k, size_t l, size_t 𝜅>
  static inline constexpr poly_mat_t<k, l> expandA(std::span<const uint8_t, 𝜅 / 8> seed)
  {
    poly_mat_t<k, l> A{};

    for (size_t ridx = 0; ridx < k; ridx++) {
      for (size_t cidx = 0; cidx < l; cidx++) {
        uint64_t hdr = 0;
        hdr |= (static_cast<uint64_t>(cidx) << 16) | (static_cast<uint64_t>(ridx) << 8) | (static_cast<uint64_t>('A') << 0);

        A[{ ridx, cidx }].template sampleQ<𝜅>(std::span<const uint8_t, sizeof(hdr)>(reinterpret_cast<uint8_t*>(&hdr), sizeof(hdr)), seed);
      }
    }

    return A;
  }
};

}
