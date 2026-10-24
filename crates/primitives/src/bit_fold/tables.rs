//! Byte tables: one 256-entry subset-sum table per byte of a row, one lookup per byte.
//!
//! The backend of every target without the x86 vector byte maps.
//!
//! On aarch64 with SHA3, pairs of lookups are summed by NEON `EOR3`.

use super::{BLOCK, F192};
#[cfg(all(target_arch = "aarch64", target_feature = "sha3"))]
use core::arch::aarch64::{
    vcombine_u64, vdup_n_u64, vdupq_n_u64, veor3q_u64, veorq_u64, vgetq_lane_u64, vld1_u64, vld1q_u64,
};

/// One subset-sum table per byte of a row: entry `[j][v]` sums the weights of the set bits of `v` at byte `j`.
fn lookup_tables(weights: &[F192]) -> Vec<[F192; 256]> {
    weights
        .as_chunks::<8>()
        .0
        .iter()
        .map(|w| {
            let mut sums = [F192::ZERO; 256];
            // Each entry adds its lowest set bit's weight to an entry already built.
            for v in 1..256usize {
                let low = v & v.wrapping_neg();
                sums[v] = sums[v ^ low] + w[low.trailing_zeros() as usize];
            }
            sums
        })
        .collect()
}

/// The fold of one row through the byte tables: one lookup and one sum per byte.
#[cfg(not(all(target_arch = "aarch64", target_feature = "sha3")))]
#[inline(always)]
fn fold_row<const CHUNKS: usize>(tables: &[[F192; 256]], row: &[u8; CHUNKS]) -> F192 {
    let tables: &[[F192; 256]; CHUNKS] = tables.try_into().expect("one table per byte");
    row.iter().zip(tables).map(|(&v, sums)| sums[usize::from(v)]).sum()
}

/// The fold of one row through the byte tables, two lookups per `EOR3`.
///
/// - The low two coefficients of an entry take one 16-byte load.
/// - The high coefficient takes an 8-byte load, never reading past the entry.
#[cfg(all(target_arch = "aarch64", target_feature = "sha3"))]
#[inline(always)]
fn fold_row<const CHUNKS: usize>(tables: &[[F192; 256]], row: &[u8; CHUNKS]) -> F192 {
    let tables: &[[F192; 256]; CHUNKS] = tables.try_into().expect("one table per byte");
    // An entry's coefficients, as the three words an element is laid out as.
    let words = |entry: &F192| core::ptr::from_ref(entry).cast::<u64>();
    // SAFETY: SHA3 is enabled at compile time, and every load stays within its entry's three words.
    unsafe {
        let mut lo = vdupq_n_u64(0);
        let mut hi = vdupq_n_u64(0);
        // Bytes in pairs: one EOR3 sums both lookups into each accumulator.
        for j in 0..CHUNKS / 2 {
            let a = words(&tables[2 * j][usize::from(row[2 * j])]);
            let b = words(&tables[2 * j + 1][usize::from(row[2 * j + 1])]);
            lo = veor3q_u64(lo, vld1q_u64(a), vld1q_u64(b));
            hi = veor3q_u64(
                hi,
                vcombine_u64(vld1_u64(a.add(2)), vdup_n_u64(0)),
                vcombine_u64(vld1_u64(b.add(2)), vdup_n_u64(0)),
            );
        }
        // An odd byte count leaves one lookup.
        if !CHUNKS.is_multiple_of(2) {
            let a = words(&tables[CHUNKS - 1][usize::from(row[CHUNKS - 1])]);
            lo = veorq_u64(lo, vld1q_u64(a));
            hi = veorq_u64(hi, vcombine_u64(vld1_u64(a.add(2)), vdup_n_u64(0)));
        }
        F192 {
            c0: vgetq_lane_u64::<0>(lo),
            c1: vgetq_lane_u64::<1>(lo),
            c2: vgetq_lane_u64::<0>(hi),
        }
    }
}

/// The byte tables of a row's weights.
#[derive(Clone, Debug)]
pub(super) struct Imp {
    /// One subset-sum table per byte of a row.
    tables: Vec<[F192; 256]>,
}

impl Imp {
    /// The tables of `weights`, one weight per bit of a row.
    pub(super) fn new(weights: &[F192]) -> Self {
        Self {
            tables: lookup_tables(weights),
        }
    }

    /// The tables of the 192 weights a value of `E` is folded through.
    pub(super) fn new_f192(weights: &[F192]) -> Self {
        Self::new(weights)
    }

    /// Folds each row of a block.
    #[inline]
    pub(super) fn fold_block<const CHUNKS: usize>(&self, rows: &[[u8; CHUNKS]], out: &mut [F192; BLOCK]) {
        for (o, row) in out.iter_mut().zip(rows) {
            *o = fold_row(&self.tables, row);
        }
    }

    /// A block of values as the map reads it: as they are.
    pub(super) const fn slice(xs: &[F192; BLOCK]) -> Sliced {
        *xs
    }

    /// Adds the map of each value of a sliced block to `out`.
    #[inline]
    pub(super) fn apply_sliced_add(&self, xs: &Sliced, out: &mut [F192]) {
        self.apply_add_f192(xs, out);
    }

    /// Adds the map of each value to `out`, a value folded as the 24 bytes it is.
    #[inline]
    pub(super) fn apply_add_f192(&self, xs: &[F192; BLOCK], out: &mut [F192]) {
        for (o, x) in out.iter_mut().zip(xs) {
            *o += fold_row(&self.tables, &x.to_le_bytes());
        }
    }
}

/// A block of values, as they are.
pub(super) type Sliced = [F192; BLOCK];
