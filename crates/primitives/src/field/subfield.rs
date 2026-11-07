//! `K` and `E` behind one interface, for kernels generic over the field their data lives in.
//!
//! A committed column holds `K` words before a sumcheck's first fold and `E` values after it.
//!
//! A kernel written over [`Subfield`] runs on both, and its `K` instance stays in 64-bit arithmetic.

use super::{F64, F192, F192Unreduced};
#[cfg(all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx512f"))]
use super::{Weights8, dot_base};
use core::ops::{Add, Mul};

/// A subfield of `E`: `K`, or `E` itself.
///
/// Every product with an `E` value lands in `E`.
///
/// Products XOR-accumulate unreduced, and a sum reduces once at its end.
pub trait Subfield: Copy + Send + Sync + Add<Output = Self> + Mul<Output = Self> {
    /// The additive identity.
    const ZERO: Self;

    /// The product `self * e`.
    fn mul_e(self, e: F192) -> F192;

    /// The product `self * e`, unreduced.
    fn mul_e_unreduced(self, e: F192) -> F192Unreduced;

    /// `sum_i coeffs[i] * vals[i]`, unreduced.
    fn dot_unreduced(coeffs: &[F192], vals: &[Self]) -> F192Unreduced;

    /// `sum_i coeffs[i] * vals[i]` over packed coefficients, unreduced.
    ///
    /// `vals` holds exactly `coeffs.width()` values.
    #[cfg(all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx512f"))]
    fn dot_packed(coeffs: &PackedCoeffs, vals: &[Self]) -> F192Unreduced;

    /// `vals[i] * e` for eight values at once.
    fn mul_e8(vals: [Self; 8], e: F192) -> [F192; 8];

    /// `constant + sum_i coeffs[i] * vals[i]`, with one reduction for the whole slice.
    #[inline(always)]
    fn dot(coeffs: &[F192], vals: &[Self], constant: F192) -> F192 {
        // A reduced value reduces to itself, so the constant joins the sum unreduced.
        (Self::dot_unreduced(coeffs, vals) ^ F192Unreduced::from(constant)).reduce()
    }
}

impl Subfield for F64 {
    const ZERO: Self = Self::ZERO;

    #[inline(always)]
    fn mul_e(self, e: F192) -> F192 {
        e.mul_base(self)
    }

    #[inline(always)]
    fn mul_e_unreduced(self, e: F192) -> F192Unreduced {
        e.mul_base_unreduced(self)
    }

    #[inline(always)]
    fn dot_unreduced(coeffs: &[F192], vals: &[Self]) -> F192Unreduced {
        (coeffs.iter().zip(vals)).map(|(&w, &v)| w.mul_base_unreduced(v)).sum()
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx512f"))]
    #[inline(always)]
    fn dot_packed(coeffs: &PackedCoeffs, vals: &[Self]) -> F192Unreduced {
        dot_base(&coeffs.base, vals)
    }

    #[inline(always)]
    fn mul_e8(vals: [Self; 8], e: F192) -> [F192; 8] {
        super::mul_base8(e, vals)
    }
}

impl Subfield for F192 {
    const ZERO: Self = Self::ZERO;

    #[inline(always)]
    fn mul_e(self, e: F192) -> F192 {
        self * e
    }

    #[inline(always)]
    fn mul_e_unreduced(self, e: F192) -> F192Unreduced {
        self.mul_unreduced(e)
    }

    #[inline(always)]
    fn dot_unreduced(coeffs: &[F192], vals: &[Self]) -> F192Unreduced {
        (coeffs.iter().zip(vals)).map(|(&w, &v)| w.mul_unreduced(v)).sum()
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx512f"))]
    #[inline(always)]
    fn dot_packed(coeffs: &PackedCoeffs, vals: &[Self]) -> F192Unreduced {
        dot_base(&coeffs.ext, Self::coefficients(vals))
    }

    #[inline(always)]
    fn mul_e8(vals: [Self; 8], e: F192) -> [F192; 8] {
        let lo = super::mul4([vals[0], vals[1], vals[2], vals[3]], [e; 4]);
        let hi = super::mul4([vals[4], vals[5], vals[6], vals[7]], [e; 4]);
        [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3]]
    }
}

/// The width of a row of `n` values, padded with zeros to whole groups of eight.
pub const fn padded_width(n: usize) -> usize {
    n.next_multiple_of(8)
}

/// Coefficients packed for [`dot_base`], zero-padded to [`padded_width`].
///
/// Against `K` words they are packed as they are.
///
/// Against `E` values each coefficient `w` becomes `w, y*w, y^2*w`:
///
/// ```text
///     w * (c0 + c1*y + c2*y^2) = w*c0 + (y*w)*c1 + (y^2*w)*c2
/// ```
///
/// So an `E` product is three mixed ones, over the value's coefficients as stored.
///
/// AVX-512 only, where [`dot_base`] takes eight values in six CLMULs.
#[cfg(all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx512f"))]
#[derive(Clone, Debug)]
pub struct PackedCoeffs {
    /// The coefficients, for `K` values.
    base: Vec<Weights8>,
    /// Each coefficient times `1, y, y^2`, for `E` values.
    ext: Vec<Weights8>,
}

#[cfg(all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx512f"))]
impl PackedCoeffs {
    /// Packs `coeffs` for both fields.
    pub fn new(coeffs: &[F192]) -> Self {
        let mut padded = coeffs.to_vec();
        padded.resize(padded_width(coeffs.len()), F192::ZERO);
        let y2 = F192::Y * F192::Y;
        let ext: Vec<F192> = padded.iter().flat_map(|&w| [w, w * F192::Y, w * y2]).collect();
        let pack = |w: &[F192]| w.as_chunks::<8>().0.iter().map(Weights8::new).collect();
        Self {
            base: pack(&padded),
            ext: pack(&ext),
        }
    }

    /// The padded width a row needs.
    pub const fn width(&self) -> usize {
        8 * self.base.len()
    }
}
