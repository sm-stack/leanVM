//! The aarch64 register type of `E` that the RISC-V prover uses: carry-less products by PMULL, sums by NEON.

use super::{F192, F192Unreduced};
use crate::field::gf2_64::{F64, R64};
use crate::field::neon::xor3_u64;
use core::arch::aarch64::*;
use core::mem::MaybeUninit;
use core::mem::transmute;
use core::ops::{Add, BitXor, BitXorAssign, Mul};

/// Carry-less product of the low qwords.
#[inline(always)]
fn lo(a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
    // SAFETY: the module's cfg enables aes, and both sides of the reinterpret are 128 bits.
    unsafe { transmute::<u128, uint64x2_t>(vmull_p64(vgetq_lane_u64::<0>(a), vgetq_lane_u64::<0>(b))) }
}

/// Carry-less product of the high qwords.
#[inline(always)]
fn hi(a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
    // SAFETY: the module's cfg enables aes, and both sides of the reinterpret are 128 bits.
    unsafe { transmute::<u128, uint64x2_t>(vmull_high_p64(vreinterpretq_p64_u64(a), vreinterpretq_p64_u64(b))) }
}

/// Two-way XOR.
#[inline(always)]
fn xor(a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
    // SAFETY: NEON is part of the aarch64 baseline.
    unsafe { veorq_u64(a, b) }
}

/// An element as its two registers.
#[inline(always)]
fn split(e: F192) -> (uint64x2_t, uint64x2_t) {
    // SAFETY: NEON is part of the aarch64 baseline.
    unsafe { (vcombine_u64(vcreate_u64(e.c0), vcreate_u64(e.c1)), vdupq_n_u64(e.c2)) }
}

/// Reduce one 128-bit coefficient into its low qword.
///
/// Write the coefficient as `lo + hi * x^64`, with `x^64 = 0x1B`:
///
/// ```text
///     hi * 0x1B     = [a, s]      s has at most 4 bits
///     s  * 0x1B     = [b, 0]      at most 8 bits, so the fold ends here
///     result        = lo ^ a ^ b
/// ```
///
/// Two high-lane products and one three-way XOR.
#[inline(always)]
fn reduce_lane(d: uint64x2_t, r: uint64x2_t) -> uint64x2_t {
    let t = hi(d, r);
    // SAFETY: the module's cfg enables NEON; `xor3_u64` asks for nothing more.
    unsafe { xor3_u64(d, t, hi(t, r)) }
}

/// [`schoolbook`] of two elements already in their registers.
#[inline(always)]
fn products(a01: uint64x2_t, a22: uint64x2_t, b01: uint64x2_t, b22: uint64x2_t) -> [uint64x2_t; 3] {
    // SAFETY: NEON is part of the aarch64 baseline.
    let a10 = unsafe { vextq_u64::<1>(a01, a01) };
    // a_i b_j for every pair, named by (i, j).
    let (m00, m11) = (lo(a01, b01), hi(a01, b01));
    let (m10, m01) = (lo(a10, b01), hi(a10, b01));
    let (m02, m12) = (lo(a01, b22), hi(a01, b22));
    let (m20, m21) = (lo(a22, b01), hi(a22, b01));
    let m22 = lo(a22, b22);
    // Both y^3 terms land on y^0 and y^1.
    let y3 = xor(m12, m21);
    // SAFETY: the module's cfg enables NEON; `xor3_u64` asks for nothing more.
    unsafe {
        [
            xor(m00, y3),
            xor3_u64(m01, m10, xor(y3, m22)),
            xor3_u64(m02, m11, xor(m20, m22)),
        ]
    }
}

/// Three 128-bit coefficients as an unreduced element.
#[inline(always)]
fn unreduced(d: [uint64x2_t; 3]) -> F192Unreduced {
    F192Unreduced {
        coeffs: d.map(|d| {
            // SAFETY: `uint64x2_t` and `[u64; 2]` are both 16 plain bytes, valid for every bit pattern.
            unsafe { transmute::<uint64x2_t, [u64; 2]>(d) }
        }),
    }
}

/// One element in its two registers, for a kernel whose values stay there from load to store.
///
/// An [`F192`] is three integer words: every sum of two runs on the integer side, and every
/// product moves its operands over and its result back, which costs more than the product.
/// These sums and products stay in vector registers. Keep them as named values or tuples: an
/// array of them is a memory object.
#[derive(Clone, Copy)]
pub struct F192x1 {
    c01: uint64x2_t,
    c22: uint64x2_t,
}

/// An unreduced product of [`F192x1`] values, or a sum of them: its three 128-bit coefficients
/// in registers.
#[derive(Clone, Copy)]
pub struct F192x1Unreduced([uint64x2_t; 3]);

impl From<F192> for F192x1 {
    #[inline(always)]
    fn from(e: F192) -> Self {
        let (c01, c22) = split(e);
        Self { c01, c22 }
    }
}

impl F192x1 {
    /// The element at `e`, loaded into its registers.
    #[inline(always)]
    pub fn load(e: &F192) -> Self {
        let words = (e as *const F192).cast::<u64>();
        // SAFETY: `e` is three words, `c0` and `c1` adjacent under `repr(C)`.
        unsafe {
            Self {
                c01: vld1q_u64(words),
                c22: vld1q_dup_u64(words.add(2)),
            }
        }
    }

    /// Write the element to `out`, which need not be initialized.
    #[inline(always)]
    pub fn store(self, out: &mut MaybeUninit<F192>) {
        let words = out.as_mut_ptr().cast::<u64>();
        // SAFETY: `out` is three words, `c0` and `c1` adjacent under `repr(C)`.
        unsafe {
            vst1q_u64(words, self.c01);
            vst1q_lane_u64::<0>(words.add(2), self.c22);
        }
    }

    /// The product without the reduction.
    #[inline(always)]
    pub fn mul_unreduced(self, rhs: Self) -> F192x1Unreduced {
        F192x1Unreduced(products(self.c01, self.c22, rhs.c01, rhs.c22))
    }

    /// The mixed product by a base-field scalar, without the reduction.
    #[inline(always)]
    pub fn mul_base_unreduced(self, k: F64) -> F192x1Unreduced {
        // SAFETY: NEON is part of the aarch64 baseline.
        let kk = unsafe { vdupq_n_u64(k.0) };
        F192x1Unreduced([lo(self.c01, kk), hi(self.c01, kk), lo(self.c22, kk)])
    }
}

impl Add for F192x1 {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        Self {
            c01: xor(self.c01, rhs.c01),
            c22: xor(self.c22, rhs.c22),
        }
    }
}

impl Mul for F192x1 {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        self.mul_unreduced(rhs).reduce()
    }
}

impl F192x1Unreduced {
    #[inline(always)]
    pub fn zero() -> Self {
        // SAFETY: NEON is part of the aarch64 baseline.
        Self([unsafe { vdupq_n_u64(0) }; 3])
    }

    /// Reduce each coefficient, into the element's two registers.
    #[inline(always)]
    pub fn reduce(self) -> F192x1 {
        let [d0, d1, d2] = self.0;
        // SAFETY: NEON is part of the aarch64 baseline.
        unsafe {
            let r = vdupq_n_u64(R64);
            let (c0, c1, c2) = (reduce_lane(d0, r), reduce_lane(d1, r), reduce_lane(d2, r));
            F192x1 {
                c01: vzip1q_u64(c0, c1),
                c22: vdupq_laneq_u64::<0>(c2),
            }
        }
    }
}

impl BitXor for F192x1Unreduced {
    type Output = Self;
    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self {
        let ([a0, a1, a2], [b0, b1, b2]) = (self.0, rhs.0);
        Self([xor(a0, b0), xor(a1, b1), xor(a2, b2)])
    }
}

impl BitXorAssign for F192x1Unreduced {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl From<F192x1Unreduced> for F192Unreduced {
    #[inline(always)]
    fn from(u: F192x1Unreduced) -> Self {
        unreduced(u.0)
    }
}

impl From<F192x1> for F192 {
    #[inline(always)]
    fn from(e: F192x1) -> Self {
        // SAFETY: NEON is part of the aarch64 baseline.
        unsafe {
            Self::new(
                vgetq_lane_u64::<0>(e.c01),
                vgetq_lane_u64::<1>(e.c01),
                vgetq_lane_u64::<0>(e.c22),
            )
        }
    }
}
