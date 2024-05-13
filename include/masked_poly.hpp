#pragma once
#include "poly.hpp"

namespace masked_poly {

// (Un)masked degree-511 polynomial, defined over Zq
template<size_t d>
  requires(d > 0)
struct masked_poly_t
{
private:
  std::array<raccoon_poly::poly_t, d> shares{};

  // Given a 64 -bit header and `𝜅` -bits seed as input, this routine is used for uniform sampling a polynomial s.t. each of its
  // coefficients ∈ [-2^(u-1), 2^(u-1)), following algorithm 7 of https://raccoonfamily.org/wp-content/uploads/2023/07/raccoon.pdf.
  template<size_t u, size_t 𝜅>
  static inline constexpr std::array<int64_t, raccoon_poly::N> sampleU(std::span<const uint8_t, 8> hdr, std::span<const uint8_t, 𝜅 / 8> 𝜎)
    requires(u > 0)
  {
    std::array<int64_t, raccoon_poly::N> f{};

    shake256::shake256_t xof;
    xof.absorb(hdr);
    xof.absorb(𝜎);
    xof.finalize();

    constexpr uint64_t mask_msb = 1ul << (u - 1);
    constexpr uint64_t mask_lsb = mask_msb - 1;

    constexpr size_t squeezable_bytes = (u + 7) / 8;
    std::array<uint8_t, squeezable_bytes> b{};

    for (size_t i = 0; i < f.size(); i++) {
      xof.squeeze(b);

      const uint64_t b_word = raccoon_utils::from_le_bytes<uint64_t>(b);
      const auto msb = static_cast<int64_t>(b_word & mask_msb);
      const auto lsb = static_cast<int64_t>(b_word & mask_lsb);

      const auto f_i = lsb - msb;
      f[i] = f_i;
    }

    return f;
  }

public:
  // Constructor(s)
  inline constexpr masked_poly_t() = default;

  // Accessor(s)
  inline constexpr raccoon_poly::poly_t& operator[](const size_t idx) { return this->shares[idx]; };
  inline constexpr const raccoon_poly::poly_t& operator[](const size_t idx) const { return this->shares[idx]; };

  // Number of shares for (un)masked polynomial. In case it's unmasked, returns 1, else returns > 1.
  inline constexpr size_t num_shares() const { return d; }

  // Fills each of (un)masked polynomial coefficients with same Zq value.
  inline constexpr void fill_with(const field::zq_t v)
  {
    for (size_t sidx = 0; sidx < this->num_shares(); sidx++) {
      (*this)[sidx].fill_with(v);
    }
  }

  // Addition of two (un)masked polynomials.
  inline constexpr masked_poly_t operator+(const masked_poly_t& rhs) const
  {
    masked_poly_t res{};

    for (size_t sidx = 0; sidx < res.num_shares(); sidx++) {
      res[sidx] = (*this)[sidx] + rhs[sidx];
    }

    return res;
  }

  inline constexpr void operator+=(const masked_poly_t& rhs) { *this = *this + rhs; }

  // Performs addition of two (un)masked polynomials, reducing each cofficients by a small moduli `Q_prime`, assuming coefficients of input (un)masked
  // polynomials also ∈ [0, Q_prime).
  template<uint64_t Q_prime>
  inline constexpr masked_poly_t add_mod(const masked_poly_t& rhs) const
  {
    masked_poly_t<d> res{};

    for (size_t sidx = 0; sidx < res.num_shares(); sidx++) {
      res[sidx] = (*this)[sidx].template add_mod<Q_prime>(rhs[sidx]);
    }

    return res;
  }

  // Subtraction of one (un)masked polynomial from another one.
  inline constexpr masked_poly_t operator-(const masked_poly_t& rhs) const
  {
    masked_poly_t res{};

    for (size_t sidx = 0; sidx < res.num_shares(); sidx++) {
      res[sidx] = (*this)[sidx] - rhs[sidx];
    }

    return res;
  }

  inline constexpr void operator-=(const masked_poly_t& rhs) { *this = *this - rhs; }

  // Subtracts one (un)masked polynomial from another one s.t. each of the coefficients ∈ [0, Q_prime) and resulting (un)masked polynomial coefficients are
  // reduced modulo `Q_prime`.
  template<uint64_t Q_prime>
  inline constexpr masked_poly_t sub_mod(const masked_poly_t& rhs) const
  {
    masked_poly_t res{};

    for (size_t sidx = 0; sidx < res.num_shares(); sidx++) {
      res[sidx] = (*this)[sidx].template sub_mod<Q_prime>(rhs[sidx]);
    }

    return res;
  }

  // Multiplies two (un)masked polynomials, assuming both inputs are in their number theoretic representation. Hence the computed output is also in NTT domain.
  inline constexpr masked_poly_t operator*(const masked_poly_t& rhs) const
  {
    masked_poly_t res{};

    for (size_t sidx = 0; sidx < res.num_shares(); sidx++) {
      res[sidx] = (*this)[sidx] * rhs[sidx];
    }

    return res;
  }

  // Rouding shift right of (un)masked polynomial.
  template<size_t bit_offset>
  inline constexpr void rounding_shr()
  {
    for (size_t sidx = 0; sidx < this->num_shares(); sidx++) {
      (*this)[sidx].template rounding_shr<bit_offset>();
    }
  }

  // Shift (un)masked polynomial leftwards by `offset` (<64) many bits.
  inline constexpr masked_poly_t operator<<(const size_t offset) const
  {
    masked_poly_t res{};

    for (size_t sidx = 0; sidx < this->num_shares(); sidx++) {
      (*this)[sidx] = (*this)[sidx] << offset;
    }

    return res;
  }

  // Applies Number Theoretic Transform on (un)masked polynomial.
  inline constexpr void ntt()
  {
    for (size_t sidx = 0; sidx < this->num_shares(); sidx++) {
      (*this)[sidx].ntt();
    }
  }

  // Applies Inverse Number Theoretic Transform on (un)masked polynomial.
  inline constexpr void intt()
  {
    for (size_t sidx = 0; sidx < this->num_shares(); sidx++) {
      (*this)[sidx].intt();
    }
  }

  // Given a 64 -bit header and `𝜅` -bits seed as input, this routine is used for mapping them to an unmasked polynomial f, following algorithm 5 of
  // https://raccoonfamily.org/wp-content/uploads/2023/07/raccoon.pdf.
  //
  // This routine is invoked when expanding seed for computing public matrix A.
  template<size_t 𝜅>
    requires(d == 1)
  inline constexpr void sampleQ(std::span<const uint8_t, 8> hdr, std::span<const uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> 𝜎)
  {
    (*this)[d - 1].template sampleQ<𝜅>(hdr, 𝜎);
  }

  // Returns a masked (d -sharing) encoding of polynomial s.t. when decoded to its standard form, each of `n` coefficents
  // of the polynomials will have canonical value of 0.
  //
  // This is an implementation of algorithm 12 of the Raccoon specification.
  //
  // This implementation collects a lot of inspiration from https://github.com/masksign/raccoon/blob/e789b4b7/ref-c/racc_core.c#L71-L102
  inline constexpr void zero_encoding(mrng::mrng_t<d>& mrng)
  {
    this->fill_with(field::zq_t::zero());

    if constexpr (this->num_shares() > 1) {
      for (size_t sidx = 0; sidx < this->num_shares(); sidx += 2) {
        const auto r = raccoon_poly::poly_t::sample_polynomial(sidx, mrng);

        (*this)[sidx] += r;
        (*this)[sidx + 1] -= r;
      }

      size_t d_idx = 2;
      while (d_idx < this->num_shares()) {
        for (size_t i = 0; i < this->num_shares(); i += 2 * d_idx) {
          for (size_t sidx = i; sidx < i + d_idx; sidx++) {
            const auto r = raccoon_poly::poly_t::sample_polynomial(sidx, mrng);

            (*this)[sidx] += r;
            (*this)[sidx + d_idx] -= r;
          }
        }

        d_idx <<= 1;
      }
    }
  }

  // Returns a fresh d -sharing of the input polynomial, using `zero_encoding` as a subroutine.
  //
  // This is an implementation of algorithm 11 of the Raccoon specification.
  inline constexpr void refresh(mrng::mrng_t<d>& mrng)
  {
    masked_poly_t<d> z{};
    z.zero_encoding(mrng);

    (*this) += z;
  }

  // Returns the standard representation of a masked (d -sharing) polynomial.
  //
  // This is an implementation of algorithm 13 of the Raccoon specification.
  inline constexpr masked_poly_t<1> decode()
  {
    masked_poly_t<1> collapsed_poly{};

    for (size_t sidx = 0; sidx < d; sidx++) {
      collapsed_poly[0] += (*this)[sidx];
    }

    return collapsed_poly;
  }

  // Adds small uniform noise to each share of the `d` -sharing (masked) polynomial, while implementing
  // Sum of Uniforms (SU) distribution in masked domain, following algorithm 8 of https://raccoonfamily.org/wp-content/uploads/2023/07/raccoon.pdf.
  //
  // Each time noise is added, polynomial is refreshed and this operation is repeated `rep` -many times.
  template<size_t u, size_t rep, size_t 𝜅>
  inline constexpr void add_rep_noise(const size_t idx, prng::prng_t& prng, mrng::mrng_t<d>& mrng)
  {
    std::array<uint8_t, 𝜅 / std::numeric_limits<uint8_t>::digits> 𝜎{};

    for (size_t i_rep = 0; i_rep < rep; i_rep++) {
      for (size_t sidx = 0; sidx < this->num_shares(); sidx++) {
        prng.read(𝜎);

        uint64_t hdr_u = 0;
        hdr_u |= (static_cast<uint64_t>(sidx) << 24) | (static_cast<uint64_t>(idx) << 16) | (static_cast<uint64_t>(i_rep) << 8) | static_cast<uint64_t>('u');

        const auto poly_u = sampleU<u, 𝜅>(std::span<const uint8_t, sizeof(hdr_u)>(reinterpret_cast<uint8_t*>(&hdr_u), sizeof(hdr_u)), 𝜎);

        for (size_t coeff_idx = 0; coeff_idx < poly_u.size(); coeff_idx++) {
          const auto coeff = static_cast<int64_t>((*this)[sidx][coeff_idx].raw()) + poly_u[coeff_idx];

          const auto is_lt_zero = -(static_cast<uint64_t>(coeff) >> ((sizeof(coeff) * 8) - 1));
          const auto is_ge_q = subtle::ct_ge<uint64_t, uint64_t>(static_cast<uint64_t>(coeff & ~is_lt_zero), field::Q);

          const auto normalized_coeff = static_cast<uint64_t>(static_cast<int64_t>(field::Q & is_lt_zero) + coeff - static_cast<int64_t>(field::Q & is_ge_q));

          (*this)[sidx][coeff_idx] = field::zq_t(normalized_coeff);
        }
      }

      this->refresh(mrng);
    }
  }
};

}
