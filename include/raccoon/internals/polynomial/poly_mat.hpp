#pragma once
#include "poly.hpp"
#include "poly_vec.hpp"

namespace raccoon_poly_mat {

// A matrix of dimension `rows x cols` s.t. each of its elements are a degree 511 polynomial, defined over Zq
template<size_t rows, size_t cols>
  requires((rows > 0) && (cols > 0))
struct poly_mat_t
{
private:
  std::array<raccoon_poly::poly_t, rows * cols> elems{};

public:
  // Constructor(s)
  inline constexpr poly_mat_t() = default;

  // Accessor(s) s.t. (row_idx, col_idx) | row_idx < rows && col_idx < cols
  inline constexpr raccoon_poly::poly_t& operator[](const std::pair<size_t, size_t> idx) { return this->elems[idx.first * cols + idx.second]; }
  inline constexpr const raccoon_poly::poly_t& operator[](const std::pair<size_t, size_t> idx) const { return this->elems[idx.first * cols + idx.second]; }

  inline constexpr size_t num_rows() const { return rows; }
  inline constexpr size_t num_cols() const { return cols; }

  // Multiply a matrix by another vector of compatible dimension, assuming both of them are in their NTT representation.
  template<size_t d>
  inline constexpr raccoon_poly_vec::poly_vec_t<rows, d> operator*(const raccoon_poly_vec::poly_vec_t<cols, d>& rhs) const
  {
    raccoon_poly_vec::poly_vec_t<rows, d> res{};

    for (size_t row_idx = 0; row_idx < this->num_rows(); row_idx++) {
      for (size_t col_idx = 0; col_idx < this->num_cols(); col_idx++) {
        for (size_t shr_idx = 0; shr_idx < d; shr_idx++) {
          res[row_idx][shr_idx] += (*this)[{ row_idx, col_idx }] * rhs[col_idx][shr_idx];
        }
      }
    }

    return res;
  }

  // Given `𝜅` -bits seed as input, this routine is used for generating public matrix A, following algorithm 6 of
  // https://raccoonfamily.org/wp-content/uploads/2023/07/raccoon.pdf.
  template<size_t k, size_t l, size_t 𝜅>
  static inline constexpr poly_mat_t<k, l> expandA(std::span<const uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> seed)
  {
    poly_mat_t<k, l> A{};

    for (size_t ridx = 0; ridx < k; ridx++) {
      for (size_t cidx = 0; cidx < l; cidx++) {
        std::array<const uint8_t, 8> hdr{ static_cast<uint8_t>('A'), static_cast<uint8_t>(ridx), static_cast<uint8_t>(cidx) };
        A[{ ridx, cidx }] = raccoon_poly::poly_t::sampleQ<𝜅>(hdr, seed);
      }
    }

    return A;
  }
};

}
