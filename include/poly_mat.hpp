#pragma once
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
  std::array<polynomial::polynomial_t, rows * cols> elems{};

public:
  // Constructor(s)
  inline constexpr poly_mat_t() = default;

  // Access element at index (ridx, cidx) of the matrix s.t. `ridx < rows` and `cidx < cols`.
  inline constexpr polynomial::polynomial_t& operator[](const std::pair<size_t, size_t> idx) { return this->elems[idx.first * cols + idx.second]; }
  inline constexpr const polynomial::polynomial_t& operator[](const std::pair<size_t, size_t> idx) const { return this->elems[idx.first * cols + idx.second]; }

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

  // Multiplies two matrices of compatible dimensions s.t. all element polynomials are expected to be in their number theoretic representation.
  template<size_t rhs_rows, size_t rhs_cols>
    requires(cols == rhs_rows)
  inline constexpr poly_mat_t<rows, rhs_cols> operator*(const poly_mat_t<rhs_rows, rhs_cols>& rhs) const
  {
    poly_mat_t<rows, rhs_cols> res{};

    for (size_t ridx = 0; ridx < rows; ridx++) {
      for (size_t cidx = 0; cidx < rhs_cols; cidx++) {
        polynomial::polynomial_t tmp{};

        for (size_t k = 0; k < cols; k++) {
          tmp += (*this)[{ ridx, k }] * rhs[{ k, cidx }];
        }

        res[{ ridx, cidx }] = tmp;
      }
    }

    return res;
  }
};

}
