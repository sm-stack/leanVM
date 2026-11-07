//! The transpose of the encode, applied to sparse vectors of `E`.
//!
//! A query batch's induced weight is the encode matrix's transpose applied to the batch's weights on the domain.
//!
//! The transpose runs the layers in reverse, each butterfly transposed: `s = a + b`, then `a' = s` and `b' = t s + b`.

use crate::ntt::AdditiveNtt;
use crate::ntt::kernels::transposed_butterfly_lanes;
use parallel::SendPtr;
use primitives::field::{F64, F192};
use std::collections::HashMap;

/// Elements per cache-resident window of the layer-blocked run.
const TRANSPOSE_CHUNK: usize = 1 << 16;

/// Layers the gathered pass takes at most: a group is `2^6` rows.
const GATHER_LOG: usize = 6;

/// Residues one gathered task takes.
///
/// 32 residues of 64 rows of `E` is 48 KiB, which stays in L2.
const GATHER_RESIDUES: usize = 32;

impl AdditiveNtt {
    /// The transposed encode of a sparse input, its first `2^(dim - log_inv_rate)` outputs valid.
    ///
    /// The input is `values` at `positions`, repeated positions adding.
    ///
    /// # Algorithm
    ///
    /// 1. The first `k` transposed layers mix only within `2^k`-aligned windows, so only occupied windows run them.
    /// 2. The windows are written into a dense vector, the empty ones staying zero.
    /// 3. The remaining layers run densely down to layer `log_inv_rate`.
    /// 4. The lowest `log_inv_rate` layers are replaced by adding the blocks into the first one.
    ///
    /// # Returns
    ///
    /// A vector of `2^dim` elements whose first `2^(dim - log_inv_rate)` are the outputs; the rest are unspecified.
    pub(crate) fn transpose_sparse(&self, positions: &[usize], values: &[F192], log_inv_rate: usize) -> Vec<F192> {
        let log_d = self.log_domain_size();
        let _span = tracing::info_span!(
            "NTT",
            kind = "transpose induce",
            log_domain = log_d,
            nonzero = positions.len()
        )
        .entered();
        debug_assert!(log_inv_rate <= log_d);
        let n = 1usize << log_d;
        // Windows of `2^8` elements from a domain of `2^12` up; their layers stop before the block fold.
        let k = if log_d >= 12 { 8usize.min(log_d) } else { 0 };
        let prefix_steps = k.min(log_d - log_inv_rate);

        let mut data = vec![F192::ZERO; n];
        if k == 0 {
            for (&p, &v) in positions.iter().zip(values) {
                data[p] += v;
            }
        } else {
            // Group the nonzero inputs into windows of `2^k` elements.
            let wmask = (1usize << k) - 1;
            let mut windows: HashMap<usize, Vec<F192>> = HashMap::new();
            for (&p, &v) in positions.iter().zip(values) {
                let buf = windows.entry(p >> k).or_insert_with(|| vec![F192::ZERO; 1 << k]);
                buf[p & wmask] += v;
            }

            // The prefix layers inside each occupied window, in parallel since windows are disjoint.
            let mut windows: Vec<(usize, Vec<F192>)> = windows.into_iter().collect();
            parallel::chunks_mut(&mut windows, 1, |_, window| {
                let (w, buf) = &mut window[0];
                for s in 0..prefix_steps {
                    let layer = log_d - 1 - s;
                    let half = 1usize << s;
                    for (jb, block) in buf.chunks_mut(2 * half).enumerate() {
                        // The block's index in the whole domain: `((w << k) + jb * 2 half) >> (s + 1)`.
                        let t = self.twiddle(layer, (*w << (k - s - 1)) + jb);
                        let (top, bot) = block.split_at_mut(half);
                        transposed_butterflies(t, top, bot);
                    }
                }
            });

            // Densify the occupied windows; an empty window stays zero, which its prefix layers would leave it.
            for (w, buf) in &windows {
                data[(w << k)..((w + 1) << k)].copy_from_slice(buf);
            }
        }

        // The dense layers stop before the ones the block fold replaces.
        self.transposed_layers(&mut data, (log_inv_rate..(log_d - prefix_steps)).rev(), TRANSPOSE_CHUNK);
        fold_blocks(&mut data, log_inv_rate);
        data
    }

    /// The transposed-butterfly sweep over `layers`, which descend, in the order given.
    ///
    /// # Layer blocking
    ///
    /// - Layers descend, so a layer's blocks grow along the run, and the layers whose blocks fit a window are a prefix.
    /// - Blocks nest, so a window of `window_len` elements holds whole blocks of every layer in that prefix.
    /// - That prefix then runs back to back inside each window: one read and one write of memory instead of one per layer.
    ///
    /// # Parallelism
    ///
    /// - The blocked prefix runs one window per task.
    /// - A later layer runs one block per task once there are as many blocks as threads, and splits its rows otherwise.
    /// - When the layers left after that prefix are at most `GATHER_LOG` consecutive ones, one gathered pass runs them.
    fn transposed_layers(&self, data: &mut [F192], layers: impl Iterator<Item = usize>, window_len: usize) {
        let log_d = self.log_domain_size();
        let n_threads = parallel::num_threads();
        let layers: Vec<usize> = layers.collect();
        debug_assert!(layers.windows(2).all(|w| w[0] > w[1]), "layers descend");
        // Why the size floor: without a window per worker, the blocked run loses more parallelism than it saves traffic.
        let blocked = if data.len() >= window_len.saturating_mul(n_threads) {
            (layers.iter())
                .position(|&l| (1usize << (log_d - l)) > window_len)
                .unwrap_or(layers.len())
        } else {
            0
        };
        if blocked > 1 {
            parallel::chunks_mut(data, window_len, |c, window: &mut [F192]| {
                let base = c * window_len;
                for &layer in &layers[..blocked] {
                    let block_size = 1usize << (log_d - layer);
                    for (b, block) in window.chunks_mut(block_size).enumerate() {
                        let (top, bot) = block.split_at_mut(block_size >> 1);
                        transposed_butterflies(self.twiddle(layer, base / block_size + b), top, bot);
                    }
                }
            });
        }
        let rest = &layers[if blocked > 1 { blocked } else { 0 }..];

        // The layers left take the gathered pass when they are at most `GATHER_LOG` consecutive ones, ending at `low`.
        // The run may stop above layer zero: its `2^low` outer blocks are then independent.
        let g = rest.len();
        let low = rest.last().copied().unwrap_or(0);
        if (1..=GATHER_LOG).contains(&g) && rest.iter().copied().eq((low..low + g).rev()) {
            self.transposed_gathered(data, low, g);
            return;
        }
        for &layer in rest {
            let num_blocks = 1usize << layer;
            let block_size = 1usize << (log_d - layer);
            let half = block_size >> 1;
            if num_blocks >= n_threads {
                parallel::chunks_mut(data, block_size, |block, chunk: &mut [F192]| {
                    let (top, bot) = chunk.split_at_mut(half);
                    transposed_butterflies(self.twiddle(layer, block), top, bot);
                });
            } else {
                for (block, chunk) in data.chunks_mut(block_size).enumerate() {
                    let t = self.twiddle(layer, block);
                    let (top, bot) = chunk.split_at_mut(half);
                    let chunk_len = parallel::recommended_chunk_size(half);
                    parallel::chunks_mut2(top, bot, chunk_len, |_, top, bot| transposed_butterflies(t, top, bot));
                }
            }
        }
    }

    /// The transposed butterflies of layers `low + g - 1` down to `low`, in one gathered pass.
    ///
    /// - The `2^low` outer blocks are independent.
    /// - Within one, the rows `r + i * step` for `i < 2^g` pair only with each other, where `step = 2^(dim - low - g)`.
    /// - A task gathers a run of consecutive residues `r`, runs every layer on them in cache, and scatters them back.
    ///
    /// Its twiddles include the outer block's offset in the full domain.
    fn transposed_gathered(&self, data: &mut [F192], low: usize, g: usize) {
        let log_d = self.log_domain_size();
        let rows = 1usize << g;
        let step = 1usize << (log_d - low - g);
        let per_task = GATHER_RESIDUES.min(step);
        let base = SendPtr(data.as_mut_ptr());
        let tasks_per_block = step / per_task;
        parallel::for_each((1usize << low) * tasks_per_block, |task| {
            let outer = task / tasks_per_block;
            let r0 = outer * (1usize << (log_d - low)) + (task % tasks_per_block) * per_task;
            // Scratch index `i * per_task + j` holds row `r0 + j + i * step`.
            let mut scratch = [F192::ZERO; GATHER_RESIDUES << GATHER_LOG];
            let scratch = &mut scratch[..rows * per_task];

            // Gather: one contiguous run of residues per group row.
            for (i, dst) in scratch.chunks_exact_mut(per_task).enumerate() {
                // SAFETY: the rows `r0 + j + i * step`, `j < per_task`, lie inside this task's outer block.
                // Tasks own disjoint pairs of outer block and residue range, so no other task touches these rows.
                dst.copy_from_slice(unsafe { base.slice(r0 + i * step, per_task) });
            }

            // Relative layers g - 1 .. 0 pair group rows `half` apart.
            for layer in (0..g).rev() {
                let half = 1usize << (g - 1 - layer);
                for block in 0..1usize << layer {
                    let t = self.twiddle(low + layer, (outer << layer) + block);
                    let at = block * 2 * half * per_task;
                    let (top, bot) = scratch[at..at + 2 * half * per_task].split_at_mut(half * per_task);
                    transposed_butterflies(t, top, bot);
                }
            }

            // Scatter: every group row returns to its place.
            for (i, src) in scratch.chunks_exact(per_task).enumerate() {
                // SAFETY: as for the gather.
                unsafe { base.slice(r0 + i * step, per_task) }.copy_from_slice(src);
            }
        });
    }
}

/// The transposed butterfly `s = a + b; a' = s; b' = t*s + b` on every pair of a top and a bottom row.
///
/// An element of `E` is three words of `K` and `t` is in `K`, so the rows are lanes of `K` sharing one twiddle.
fn transposed_butterflies(t: F64, top: &mut [F192], bot: &mut [F192]) {
    transposed_butterfly_lanes(F192::coefficients_mut(top), F192::coefficients_mut(bot), t);
}

/// Add the `2^log_inv_rate` blocks of `data` into its first block, which is retained.
///
/// Through the omitted lowest `log_inv_rate` layers, a retained output depends only on top outputs, `a' = a + b`.
///
/// So those layers reduce to `N - n` additions and no product, for `N` inputs and `n` retained outputs.
fn fold_blocks(data: &mut [F192], log_inv_rate: usize) {
    if log_inv_rate == 0 {
        return;
    }
    let n = data.len() >> log_inv_rate;
    let (retained, rest) = data.split_at_mut(n);
    let chunk_len = parallel::recommended_chunk_size(n);
    parallel::chunks_mut(retained, chunk_len, |chunk, out| {
        let start = chunk * chunk_len;
        for block in rest.chunks_exact(n) {
            for (out, &value) in out.iter_mut().zip(&block[start..]) {
                *out += value;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::test_util::Rng;

    #[test]
    fn blocked_and_gathered_transposes_match_layer_by_layer() {
        // Invariant: the windowed prefix and the gathered tail compute the plain transposed NTT.
        let mut rng = Rng::new(0x7A55);
        // At most six layers are left to the gathered pass.
        // The shapes cover a nonzero lowest layer, several outer blocks and fewer than 32 residues.
        for (log_d, low) in [(12, 0), (12, 1), (12, 3), (12, 6), (8, 0), (8, 2), (8, 7)] {
            let ntt = AdditiveNtt::standard(log_d);
            let data: Vec<F192> = rng.ext_vec(1 << log_d);

            // Reference: one layer at a time, highest first, every block's butterflies in place.
            let mut want = data.clone();
            for layer in (low..log_d).rev() {
                let half = 1usize << (log_d - 1 - layer);
                for (block, chunk) in want.chunks_mut(2 * half).enumerate() {
                    let t = ntt.twiddle(layer, block);
                    let (top, bot) = chunk.split_at_mut(half);
                    for (a, b) in top.iter_mut().zip(bot.iter_mut()) {
                        let s = *a + *b;
                        (*a, *b) = (s, s.mul_base(t) + *b);
                    }
                }
            }

            let mut got = data;
            let gathered = GATHER_LOG.min(log_d - low);
            ntt.transposed_layers(&mut got, (low..log_d).rev(), 1 << (log_d - low - gathered));
            assert_eq!(got, want, "log_d={log_d}, low={low}");
        }
    }
}
