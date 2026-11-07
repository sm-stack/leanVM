//! The sumcheck's fold and message kernels.
//!
//! A round's polynomial is `h(X) = u_0 + u_1 X + u_2 X^2`, with `h(0) + h(1)` the running claim.
//!
//! - The prover sends `u_0` and `u_2`.
//! - In characteristic 2 the verifier derives `u_1` from the claim and `u_2`.
//!
//! # Lane rounds
//!
//! The first `initial_k` rounds bind whole lanes, not adjacent words.
//!
//! The committed witness is lane-major: lane `l` is the stack block `q[l * H .. (l + 1) * H)`.
//! Here `H = 2^(log_n - initial_k)`, and the layout makes the stack's zero padding whole lanes the commitment omits.
//!
//! - Round `j` binds lane bit `j`, pairing block `2i` with block `2i + 1` of the current buffer.
//! - With an odd block count, the last block pairs with the absent zero padding.
//! - After these rounds one `H`-word block is left, and every later round folds adjacent pairs.
//!
//! # Unreduced sums
//!
//! Products accumulate unreduced, combined by XOR, and each sum is reduced once.
//! Reduction is linear, so the message equals the one with every product reduced.

use crate::whir::sumcheck::first_pass::{LaneWeight, WeightFold};
use crate::whir::sumcheck::{INITIAL_BASIS_CHUNK, NextRound, PAR_THRESHOLD, ROUND_CHUNK, SumcheckMessage};
use core::iter::Sum;
use core::ops::{BitXor, BitXorAssign};
use parallel::SendPtr;
use primitives::field::{F64, F192, F192Unreduced};
#[cfg(all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx2"))]
use primitives::field::{F192x4, F192x4Unreduced};
use primitives::multilinear::eq_table;
use primitives::stream::Stream;
use std::mem::MaybeUninit;

/// Words a lane round's fold stages in L1 before publishing them.
const STAGE: usize = INITIAL_BASIS_CHUNK;

/// A round message's two coefficients, unreduced.
#[derive(Clone, Copy, Debug, Default)]
struct MessageSums {
    /// The sum of `h(0)`'s products.
    u_0: F192Unreduced,
    /// The sum of `h(inf)`'s products.
    u_2: F192Unreduced,
}

impl MessageSums {
    /// The sum of `n_tasks` tasks' sums, on the calling thread when there are few pairs.
    ///
    /// The sums combine by XOR and reduction is linear, so both paths give the same message.
    #[inline]
    fn sum_tasks(n_tasks: usize, n_pairs: usize, task: impl Fn(usize) -> Self + Sync) -> Self {
        if n_pairs < PAR_THRESHOLD {
            (0..n_tasks).map(task).sum()
        } else {
            parallel::map_reduce(n_tasks, Self::default, task, BitXor::bitxor)
        }
    }

    /// The message, each coefficient reduced once.
    fn reduce(self) -> SumcheckMessage {
        SumcheckMessage {
            u_0: self.u_0.reduce(),
            u_2: self.u_2.reduce(),
        }
    }
}

impl BitXor for MessageSums {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self {
        Self {
            u_0: self.u_0 ^ rhs.u_0,
            u_2: self.u_2 ^ rhs.u_2,
        }
    }
}

impl BitXorAssign for MessageSums {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl Sum for MessageSums {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), BitXor::bitxor)
    }
}

/// A round message's sums, and the sum of the odd words' products that completes the inner product.
#[derive(Clone, Copy, Debug, Default)]
struct MessageAndOdd {
    /// The message's sums.
    message: MessageSums,
    /// The sum of `x1 * y1`.
    odd: F192Unreduced,
}

impl BitXor for MessageAndOdd {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self {
        Self {
            message: self.message ^ rhs.message,
            odd: self.odd ^ rhs.odd,
        }
    }
}

impl Sum for MessageAndOdd {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), BitXor::bitxor)
    }
}

/// A round's fold: the witness and the weight folded at the round's challenge, and the next round's message.
pub(super) struct Folded {
    /// The folded witness.
    pub(super) witness: Vec<F192>,
    /// The folded weight.
    pub(super) weight: Vec<F192>,
    /// The next round's message over them.
    pub(super) message: SumcheckMessage,
}

/// Folds each pair of a run at `r`, handing `x0 + r * (x0 + x1)` to `out` with its index.
///
/// That is the line through `x0` at 0 and `x1` at 1, evaluated at `r`.
/// It takes four pairs at a time in vector lanes where the target has them.
#[inline(always)]
fn fold_pairs(
    n: usize,
    x0: impl Fn(usize) -> F192,
    x1: impl Fn(usize) -> F192,
    r: F192,
    mut out: impl FnMut(usize, F192),
) {
    #[cfg(all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx2"))]
    let done = {
        let r4 = F192x4::splat(r);
        for i in (0..n / 4 * 4).step_by(4) {
            let (a, b) = (lanes(&x0, i), lanes(&x1, i));
            for (k, v) in <[F192; 4]>::from(a + r4 * (a + b)).into_iter().enumerate() {
                out(i + k, v);
            }
        }
        n / 4 * 4
    };
    #[cfg(not(all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx2")))]
    let done = 0;
    for i in done..n {
        let (a, b) = (x0(i), x1(i));
        out(i, a + r * (a + b));
    }
}

/// A round message's unreduced coefficients over a run of witness pairs `(x0, x1)` and weight pairs `(y0, y1)`.
///
/// The sum of `x0 * y0` is `h(0)`, and the sum of `(x0 + x1) * (y0 + y1)` is `h(inf)`.
#[inline(always)]
fn pair_terms(
    n: usize,
    x0: impl Fn(usize) -> F192,
    x1: impl Fn(usize) -> F192,
    y0: impl Fn(usize) -> F192,
    y1: impl Fn(usize) -> F192,
) -> MessageSums {
    pair_sums::<false>(n, x0, x1, y0, y1).message
}

/// Unreduced sums over a run of pairs: of `x0 * y0`, of `(x0 + x1) * (y0 + y1)`, and of `x1 * y1`.
///
/// The odd words' sum is computed only when `ODD` is set, and is zero otherwise.
/// It takes four pairs at a time in vector lanes where the target has them.
#[inline(always)]
fn pair_sums<const ODD: bool>(
    n: usize,
    x0: impl Fn(usize) -> F192,
    x1: impl Fn(usize) -> F192,
    y0: impl Fn(usize) -> F192,
    y1: impl Fn(usize) -> F192,
) -> MessageAndOdd {
    #[cfg(all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx2"))]
    let (done, mut sums) = {
        let (mut u_0, mut u_2, mut odd) = (
            F192x4Unreduced::zero(),
            F192x4Unreduced::zero(),
            F192x4Unreduced::zero(),
        );
        for i in (0..n / 4 * 4).step_by(4) {
            let (a0, a1, b0, b1) = (lanes(&x0, i), lanes(&x1, i), lanes(&y0, i), lanes(&y1, i));
            u_0 ^= a0.mul_unreduced(b0);
            u_2 ^= (a0 + a1).mul_unreduced(b0 + b1);
            if ODD {
                odd ^= a1.mul_unreduced(b1);
            }
        }
        let message = MessageSums {
            u_0: u_0.sum(),
            u_2: u_2.sum(),
        };
        (
            n / 4 * 4,
            MessageAndOdd {
                message,
                odd: odd.sum(),
            },
        )
    };
    #[cfg(not(all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx2")))]
    let (done, mut sums) = (0, MessageAndOdd::default());
    for i in done..n {
        sums.message.u_0 ^= x0(i).mul_unreduced(y0(i));
        sums.message.u_2 ^= (x0(i) + x1(i)).mul_unreduced(y0(i) + y1(i));
        if ODD {
            sums.odd ^= x1(i).mul_unreduced(y1(i));
        }
    }
    sums
}

/// Four consecutive values, one per lane.
#[cfg(all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx2"))]
#[inline(always)]
fn lanes(v: &impl Fn(usize) -> F192, i: usize) -> F192x4 {
    F192x4::from(std::array::from_fn(|k| v(i + k)))
}

/// The round message over a witness `f` and a weight `b`, both in `E`, pairing adjacent words.
pub(super) fn round_message(f: &[F192], b: &[F192]) -> SumcheckMessage {
    let n = f.len();
    debug_assert!(n.is_power_of_two() && n >= 2);
    debug_assert_eq!(b.len(), n);

    let half = n / 2;
    let task = |t: usize| {
        let base = t * ROUND_CHUNK;
        let (f, b) = (&f[2 * base..], &b[2 * base..]);
        pair_terms(
            ROUND_CHUNK.min(half - base),
            |j| f[2 * j],
            |j| f[2 * j + 1],
            |j| b[2 * j],
            |j| b[2 * j + 1],
        )
    };
    MessageSums::sum_tasks(half.div_ceil(ROUND_CHUNK), half, task).reduce()
}

/// The round message and the full inner product `sum_x f(x) * b(x)`, in one pass.
///
/// For an out-of-domain weight `b = eq(z, .)`, the inner product is the claimed evaluation `MLE(f)(z)`.
pub(super) fn round_message_and_sum(f: &[F192], b: &[F192]) -> (SumcheckMessage, F192) {
    let n = f.len();
    debug_assert!(n.is_power_of_two() && n >= 2);
    debug_assert_eq!(b.len(), n);

    let half = n / 2;
    // The message, and the odd elements' products: with the even ones', the inner product.
    let task = |t: usize| {
        let base = t * ROUND_CHUNK;
        let (f, b) = (&f[2 * base..], &b[2 * base..]);
        pair_sums::<true>(
            ROUND_CHUNK.min(half - base),
            |j| f[2 * j],
            |j| f[2 * j + 1],
            |j| b[2 * j],
            |j| b[2 * j + 1],
        )
    };
    let n_tasks = half.div_ceil(ROUND_CHUNK);
    let sums: MessageAndOdd = if half < PAR_THRESHOLD {
        (0..n_tasks).map(task).sum()
    } else {
        parallel::map_reduce(n_tasks, MessageAndOdd::default, task, BitXor::bitxor)
    };
    // The inner product is the even words' products, `h(0)`'s sum, plus the odd words'.
    let inner = (sums.message.u_0 ^ sums.odd).reduce();
    (sums.message.reduce(), inner)
}

/// The message sums over folded `E` buffers, pairing adjacent words.
///
/// A trailing odd word adds nothing, so when the fold leaves a single word the message is zero.
#[inline]
fn fold_msg_terms(nf: &[F192], nb: &[F192]) -> MessageSums {
    pair_terms(
        nf.len() / 2,
        |k| nf[2 * k],
        |k| nf[2 * k + 1],
        |k| nb[2 * k],
        |k| nb[2 * k + 1],
    )
}

/// Folds the witness and the weight at `r` by adjacent pairs, and builds the next round's message in the same pass.
pub(super) fn fold_and_message(f: &[F192], b: &[F192], r: F192) -> Folded {
    let n = f.len();
    debug_assert!(n.is_power_of_two() && n >= 2);
    debug_assert_eq!(b.len(), n);
    let half = n / 2;

    // Fold a window of pairs of the witness and of the weight.
    let fold = |base: usize, fc: &mut [MaybeUninit<F192>], bc: &mut [MaybeUninit<F192>]| {
        let (f, b) = (&f[2 * base..], &b[2 * base..]);
        fold_pairs(fc.len(), |j| f[2 * j], |j| f[2 * j + 1], r, |j, v| _ = fc[j].write(v));
        fold_pairs(bc.len(), |j| b[2 * j], |j| b[2 * j + 1], r, |j, v| _ = bc[j].write(v));
    };
    if half < PAR_THRESHOLD {
        let mut nf = Vec::with_capacity(half);
        let mut nb = Vec::with_capacity(half);
        fold(
            0,
            &mut nf.spare_capacity_mut()[..half],
            &mut nb.spare_capacity_mut()[..half],
        );
        // SAFETY: the fold wrote all `half` slots of both.
        unsafe {
            nf.set_len(half);
            nb.set_len(half);
        }
        let message = fold_msg_terms(&nf, &nb).reduce();
        return Folded {
            witness: nf,
            weight: nb,
            message,
        };
    }

    // Parallel path: `half` and `ROUND_CHUNK` are powers of two, and `half >= PAR_THRESHOLD >= ROUND_CHUNK`.
    // So every chunk is whole and starts at an even index: no message pair straddles two chunks.
    let mut nf = Box::new_uninit_slice(half);
    let mut nb = Box::new_uninit_slice(half);
    // Why: each chunk folds, then accumulates its message, so the folded values are still in L1 when multiplied.
    let nf_base = SendPtr(nf.as_mut_ptr());
    let nb_base = SendPtr(nb.as_mut_ptr());
    let sums = parallel::map_reduce(
        half.div_ceil(ROUND_CHUNK),
        MessageSums::default,
        |ci| {
            let base = ci * ROUND_CHUNK;
            let len = ROUND_CHUNK.min(half - base);
            // SAFETY: distinct `ci` own disjoint in-bounds `ROUND_CHUNK`-windows of `nf` and `nb`.
            // Both buffers stay borrowed for the whole dispatch.
            let fc = unsafe { nf_base.slice(base, len) };
            // SAFETY: as for `fc`, the same window of `nb`.
            let bc = unsafe { nb_base.slice(base, len) };
            fold(base, fc, bc);
            // SAFETY: the fold just wrote both windows.
            unsafe { fold_msg_terms(fc.assume_init_ref(), bc.assume_init_ref()) }
        },
        BitXor::bitxor,
    );
    // SAFETY: the tasks wrote every slot of both, one output per pair of inputs.
    let (nf, nb) = unsafe { (nf.assume_init().into_vec(), nb.assume_init().into_vec()) };
    Folded {
        witness: nf,
        weight: nb,
        message: sums.reduce(),
    }
}

/// The message sums over one pair of blocks, word `i` of one against word `i` of the other.
///
/// # Panics
///
/// If the four slices differ in length.
#[inline]
fn msg_terms_pair(f0: &[F192], f1: &[F192], b0: &[F192], b1: &[F192]) -> MessageSums {
    let n = f0.len();
    assert!(f1.len() == n && b0.len() == n && b1.len() == n);
    pair_terms(n, |i| f0[i], |i| f1[i], |i| b0[i], |i| b1[i])
}

/// The message sums over a block whose partner is the absent zero padding.
///
/// With `f1 = b1 = 0`, both `h(0)` and `h(inf)` are `sum f0 * b0`.
/// So a lone block is not a no-op, unlike a trailing odd word in an adjacent-pair round.
#[inline]
fn msg_terms_lone(f0: &[F192], b0: &[F192]) -> MessageSums {
    let mut u = F192Unreduced::ZERO;
    for (&x0, &y0) in f0.iter().zip(b0) {
        u ^= x0.mul_unreduced(y0);
    }
    MessageSums { u_0: u, u_2: u }
}

/// One lane round's witness fold, and the next round's message against the already folded weight `nb`.
///
/// # Arguments
///
/// - `n_out`: the number of output blocks, each of `block` words.
/// - `nb`: the folded weight, `n_out * block` words.
/// - `next`: what the next round pairs, blocks or the adjacent words of the single output block.
/// - `fold_window(out_blk, x0, stage)`: writes the folded witness of words `x0..x0 + stage.len()` of block `out_blk`.
///
/// A task owns one `ROUND_CHUNK` window of one output pair of blocks, the unit the next message is local to.
///
/// The witness folds into an L1 stage, which the message reads, and the stage goes out by streaming stores.
/// Why: nothing reads the destination again before the next round.
///
/// # Panics
///
/// If `nb` is not `n_out * block` words, or if the next round pairs words while more than one block is left.
pub(super) fn fold_witness_and_msg(
    n_out: usize,
    block: usize,
    nb: &[F192],
    next: NextRound,
    fold_window: impl Fn(usize, usize, &mut [F192]) + Sync,
) -> (Vec<F192>, SumcheckMessage) {
    assert_eq!(nb.len(), n_out * block);
    // Adjacent pairing next round is only possible once the lanes have collapsed to a single block.
    assert!(next == NextRound::Lanes || n_out == 1);

    let mut nf = Box::new_uninit_slice(n_out * block);
    let nf_base = SendPtr(nf.as_mut_ptr());
    let per = block.div_ceil(ROUND_CHUNK);
    let task = |t: usize| {
        let (i, c) = (t / per, t % per);
        let x0 = c * ROUND_CHUNK;
        let len = ROUND_CHUNK.min(block - x0);
        let stream = Stream::new();
        let mut stage = [[F192::ZERO; STAGE]; 2];
        let mut acc = MessageSums::default();
        for s in (0..len).step_by(STAGE) {
            let n = STAGE.min(len - s);
            let [lo, hi] = &mut stage;
            // Fold one output block's window into the stage, then publish it.
            let fold = |out_blk: usize, stage: &mut [F192]| -> &[F192] {
                let at = out_blk * block + x0 + s;
                fold_window(out_blk, x0 + s, stage);
                // SAFETY: distinct `(out_blk, x0 + s)` name disjoint in-bounds windows of `nf`.
                // `nf` stays borrowed for the whole dispatch.
                unsafe { stream.write(nf_base.slice(at, n), stage) };
                &nb[at..at + n]
            };
            let lo_b = fold(2 * i, &mut lo[..n]);
            // The next round pairs output block `2i` with `2i + 1`, or a lone last block with zeros.
            acc ^= if 2 * i + 1 < n_out {
                let hi_b = fold(2 * i + 1, &mut hi[..n]);
                msg_terms_pair(&lo[..n], &hi[..n], lo_b, hi_b)
            } else if next == NextRound::Words {
                // `ROUND_CHUNK`, `STAGE` and `block` are powers of two, so every slice starts at an even word.
                // Its length is even too unless the block is one word, so no message pair straddles two slices.
                fold_msg_terms(&lo[..n], lo_b)
            } else {
                msg_terms_lone(&lo[..n], lo_b)
            };
        }
        acc
    };
    let sums = MessageSums::sum_tasks(n_out.div_ceil(2) * per, nb.len() / 2, task);
    // SAFETY: the tasks wrote every window of every output block once.
    let nf = unsafe { nf.assume_init() }.into_vec();
    (nf, sums.reduce())
}

/// Folds the `K` witness over its lowest `|rs|` lane bits, and builds the next round's message against `nb`.
///
/// Output block `o` is `sum_j eq(rs, j) * f_(o * 2^|rs| + j)`, absent lanes counting as zero padding.
pub(super) fn fold_lanes_base(
    f: &[F64],
    block: usize,
    rs: &[F192],
    nb: &[F192],
    next: NextRound,
) -> (Vec<F192>, SumcheckMessage) {
    let n_lanes = f.len() / block;
    let weights: Vec<LaneWeight> = eq_table(rs).into_iter().map(LaneWeight::new).collect();
    let n_out = n_lanes.div_ceil(weights.len());
    fold_witness_and_msg(n_out, block, nb, next, |out_blk, x0, stage| {
        let mut acc = WeightFold::default();
        let first = out_blk * weights.len();
        for (e, lane) in weights.iter().zip(first..n_lanes) {
            let src = lane * block + x0;
            acc.add_base(e, &f[src..src + stage.len()]);
        }
        acc.write(stage);
    })
}

/// Writes window `x0..x0 + stage.len()` of output block `out_blk` of `src` folded by one lane bit at `r`.
///
/// Block `2 out_blk` folds with block `2 out_blk + 1`, or with the absent zero padding when it is the last.
#[inline]
pub(super) fn fold_block_pair(src: &[F192], block: usize, r: F192, out_blk: usize, x0: usize, stage: &mut [F192]) {
    let n = stage.len();
    let lo = &src[2 * out_blk * block + x0..][..n];
    if (2 * out_blk + 1) * block < src.len() {
        let hi = &src[(2 * out_blk + 1) * block + x0..][..n];
        fold_pairs(n, |i| lo[i], |i| hi[i], r, |i, v| stage[i] = v);
    } else {
        // No partner block: `x + r * (x + 0)`.
        for (d, &x) in stage.iter_mut().zip(lo) {
            *d = x + r * x;
        }
    }
}

/// An `E` vector of blocks folded by one lane bit at `r`: block `2i` with `2i + 1`, a lone last block with zeros.
pub(super) fn fold_blocks(b: &[F192], block: usize, r: F192) -> Vec<F192> {
    let n_out = (b.len() / block).div_ceil(2);
    let mut out = vec![F192::ZERO; n_out * block];
    let chunk = block.min(ROUND_CHUNK);
    let per = block / chunk;
    let fold = |i: usize, dst: &mut [F192]| fold_block_pair(b, block, r, i / per, (i % per) * chunk, dst);
    if out.len() < PAR_THRESHOLD {
        out.chunks_mut(chunk).enumerate().for_each(|(i, dst)| fold(i, dst));
    } else {
        parallel::chunks_mut(&mut out, chunk, fold);
    }
    out
}
