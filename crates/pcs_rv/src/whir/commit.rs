// CREDIT: https://github.com/succinctlabs/flock (flock-core), MIT OR Apache-2.0.
// Copyright (c) 2026 Bain Capital Crypto, LP and Ron Rothblum
// Modifications copyright 2026 Succinct Labs, Benedikt Bunz, William Wang
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The WHIR commitments, each Merkle-committed one leaf per codeword row.
//!
//! - L0 encodes the witness's words of `K`.
//! - Every deeper level encodes a folded witness over `E`, with twiddles in `K`.

use crate::merkle::{Hash, MerkleBuilder, MerkleTree, sorted_unique};
use crate::ntt::{AdditiveNtt, Pad, transpose_lane_major};
use crate::whir::query::Padding;
use fiat_shamir::ProverState;
use primitives::field::{F64, F192};
use std::sync::Arc;

/// The L0 commitment as its prover keeps it: the codeword and its Merkle tree.
///
/// The message itself is not kept: the caller holds it for opening.
pub(crate) struct BaseCommitment {
    /// The committed lanes' codeword, row-major: position `q` holds `n_lanes` words, lane-descending.
    codeword: Vec<F64>,
    /// The Merkle tree, one leaf per codeword position.
    tree: MerkleTree,
    /// The padding of a hiding commitment, lane block `u`'s `k` coefficients at `[u k, (u + 1) k)`; empty otherwise.
    pub(crate) pads: Vec<F64>,
}

impl BaseCommitment {
    /// Commit to the words of `K` of a `2^log_n`-word witness, one RS codeword per lane.
    ///
    /// # Layout
    ///
    /// - `message` is the witness's leading `n_lanes` lane blocks, each `2^(log_n - log_batch_size)` words.
    /// - `n_lanes` is read off the message length and lies in `1..=2^log_batch_size`.
    /// - Each lane is RS-encoded at rate `2^-log_inv_rate`.
    /// - A leaf is one codeword position across all `2^log_batch_size` lanes, `8 * 2^log_batch_size` bytes.
    ///
    /// # Absent lanes
    ///
    /// The stacked witness's zero tail is whole lanes, so those lanes are never encoded.
    /// The encoding is linear, so their codeword is zero.
    ///
    /// The leaf image is therefore the one a full-width commitment would hash, with those zeros leading it:
    ///
    /// ```text
    ///     codeword lane t  =  message block n_lanes - 1 - t
    ///     leaf image       =  [ 2^log_batch_size - n_lanes zeros | block n_lanes-1, ..., block 0 ]
    /// ```
    ///
    /// - The leading zeros' whole BLAKE2s blocks are one chaining value that every leaf shares.
    /// - Only the image's tail, the committed lanes, rides the proof.
    /// - A verifier derives `n_lanes` from the announced layout to read a row, and supplies the zeros itself.
    ///
    /// # Padding
    ///
    /// Non-empty `pads` make each lane's code longer by `k = pads.len() / n_lanes` coefficients.
    ///
    /// With `m = log_n - log_batch_size` and `r = log_inv_rate`, lane `u` encodes:
    ///
    /// ```text
    ///     P_u(X) + W_m(X + s) * R_u(X),   s = F64(2^(m + r))
    /// ```
    ///
    /// - `P_u` is the lane's `2^m` words as novel-basis coefficients.
    /// - `R_u` is its padding, `pads[u k..(u + 1) k]`.
    /// - `W_m(X + s) = W_m(X) + W_m(s)` and `X_{2^m + j} = W_m X_j`, so the lane is `2^m + k` coefficients on one domain.
    /// - The encode adds one butterfly layer pairing the message with the padding.
    /// - The factor `W_m(X + s)` vanishes nowhere on the domain, so any `k` symbols of a lane are uniform.
    ///
    /// # Panics
    ///
    /// - If `log_inv_rate` is 0, or the witness is no wider than the interleaving.
    /// - If the message is not between one and `2^log_batch_size` whole lane blocks.
    /// - Unless every lane has the same `k <= 2^m` padding coefficients.
    pub(crate) fn new(message: &[F64], log_n: usize, log_batch_size: usize, log_inv_rate: usize, pads: &[F64]) -> Self {
        assert!(log_inv_rate >= 1, "log_inv_rate must be >= 1 for a non-trivial RS code");
        assert!(log_n > log_batch_size, "witness must be wider than the interleaving");
        let log_rows = log_n - log_batch_size;
        let n_lanes = message.len() >> log_rows;
        assert_eq!(message.len(), n_lanes << log_rows, "message is whole lane blocks");
        assert!(
            n_lanes >= 1 && n_lanes <= 1usize << log_batch_size,
            "at most 2^log_batch_size lanes carry data"
        );
        let k_code = log_rows + log_inv_rate;
        let n_positions = 1usize << k_code;
        let codeword_len = n_positions * n_lanes;
        let k = pads.len() / n_lanes;
        assert_eq!(pads.len(), k * n_lanes, "every lane takes as many padding coefficients");
        assert!(k <= 1 << log_rows, "a lane's padding is at most its message's length");
        // Row `j` of the padding is coefficient `j` of every codeword lane's `R`, lane `t` being block `n_lanes - 1 - t`.
        let pad_rows: Vec<F64> = (0..k * n_lanes)
            .map(|w| pads[(n_lanes - 1 - w % n_lanes) * k + w / n_lanes])
            .collect();
        let pad = (k > 0).then(|| Pad {
            rows: &pad_rows,
            offset: Padding::new(log_rows, log_inv_rate).shift(),
        });
        let mut codeword = Box::new_uninit_slice(codeword_len);

        // Leaves are hashed as the encode finishes each block of rows.
        let builder = MerkleBuilder::new(n_positions, n_lanes, 1usize << log_batch_size);
        tracing::info_span!("NTT", kind = "base encode", log_domain = k_code, lanes = n_lanes).in_scope(|| {
            // SAFETY: every codeword word is written before it is read.
            // - The transpose writes every word of the message region, the first `message.len()` words.
            // - Its tiling asserts that it covers the whole region.
            // - The encode fills every other replica from that region before transforming it in place.
            let codeword = unsafe { primitives::write_only(&mut codeword) };
            transpose_lane_major(&mut codeword[..message.len()], message, n_lanes, log_rows);
            let ntt = AdditiveNtt::standard(k_code);
            ntt.encode_interleaved_in_place_with(codeword, n_lanes, log_inv_rate, pad, &|row, rows| {
                builder.absorb(row, rows);
            });
        });
        // SAFETY: the transpose and the encode above wrote every word of the codeword.
        let codeword = unsafe { codeword.assume_init() }.into_vec();
        let tree = tracing::info_span!("Merkle").in_scope(|| builder.finish());
        Self {
            codeword,
            tree,
            pads: pads.to_vec(),
        }
    }

    /// The Merkle root.
    pub(crate) fn root(&self) -> Hash {
        self.tree.root()
    }

    /// Codeword positions, one leaf each.
    pub(crate) const fn num_positions(&self) -> usize {
        self.tree.num_leaves()
    }

    /// The committed lanes.
    pub(crate) const fn n_lanes(&self) -> usize {
        self.codeword.len() / self.num_positions()
    }

    /// The committed lanes' words at a position, lane-descending.
    pub(crate) fn row(&self, position: usize) -> &[F64] {
        let n_lanes = self.n_lanes();
        &self.codeword[position * n_lanes..][..n_lanes]
    }

    /// Open the rows at `queries`: one hint with each distinct row once, and their paths.
    ///
    /// A stored row is the committed lanes alone: the leaf image's tail, its leading zeros the absent lanes.
    pub(crate) fn open(&self, ps: &mut ProverState, queries: &[usize]) {
        ps.prover_hint(&self.tree.prune(queries, |q| self.row(q)).to_hint());
    }
}

/// One deeper WHIR commitment level: its message and Merkle tree.
///
/// Each codeword row is one Merkle leaf of `num_interleaved` elements of `E`.
///
/// The codeword is not kept: an opened row is evaluated again from the message.
pub(crate) struct LevelCommitment {
    /// The folded witness this level commits, row-major, `num_interleaved` values a row.
    msg: Arc<Vec<F192>>,
    /// The transform over the level's codeword domain.
    ntt: AdditiveNtt,
    /// The Merkle tree, one leaf per codeword position.
    tree: MerkleTree,
    /// Elements of `E` in one row.
    num_interleaved: usize,
}

impl LevelCommitment {
    /// Commit a polynomial over `E` at one recursive WHIR level.
    ///
    /// - `poly` is row-major: `2^log_msg_cols` rows of `2^log_num_interleaved` values.
    /// - Each lane, one column of that layout, is RS-encoded at rate `2^-log_inv_rate` with twiddles in `K`.
    /// - Each codeword row is hashed as one Merkle leaf as the encode finishes it, then dropped.
    ///
    /// # Panics
    ///
    /// Panics unless `poly` holds exactly `2^(log_msg_cols + log_num_interleaved)` values.
    pub(crate) fn new(
        poly: Arc<Vec<F192>>,
        log_msg_cols: usize,
        log_num_interleaved: usize,
        log_inv_rate: usize,
    ) -> Self {
        let msg_cols = 1usize << log_msg_cols;
        let num_interleaved = 1usize << log_num_interleaved;
        let log_block_len = log_msg_cols + log_inv_rate;
        assert_eq!(poly.len(), num_interleaved * msg_cols);
        let ntt = AdditiveNtt::standard(log_block_len);

        // One leaf per row, each element of `E` as its three words of `K`.
        let row_words = 3 * num_interleaved;
        let builder = MerkleBuilder::new(1 << log_block_len, row_words, row_words);
        tracing::info_span!(
            "NTT",
            kind = "extension encode",
            log_domain = log_block_len,
            lanes = num_interleaved
        )
        .in_scope(|| {
            ntt.encode_rows_ext(&poly, num_interleaved, log_inv_rate, &|row, rows| {
                builder.absorb(row, rows);
            });
        });
        let tree = tracing::info_span!("Merkle").in_scope(|| builder.finish());

        Self {
            msg: poly,
            ntt,
            tree,
            num_interleaved,
        }
    }

    /// The Merkle root.
    pub(crate) fn root(&self) -> Hash {
        self.tree.root()
    }

    /// Codeword positions, one leaf each.
    pub(crate) const fn num_positions(&self) -> usize {
        self.tree.num_leaves()
    }

    /// Open the rows at `queries`, each evaluated once however often it repeats.
    ///
    /// The proof gets one hint with each distinct row once, and their paths.
    ///
    /// # Returns
    ///
    /// The rows in query order, repeats included.
    pub(crate) fn open(&self, ps: &mut ProverState, queries: &[usize]) -> Vec<Vec<F192>> {
        let positions = sorted_unique(queries);
        let rows = self.ntt.rows_at_ext(&self.msg, self.num_interleaved, &positions);
        let row = |q: usize| {
            let index = positions.binary_search(&q).expect("an opened position");
            &rows[index * self.num_interleaved..][..self.num_interleaved]
        };
        ps.prover_hint(
            &self
                .tree
                .prune(queries, |q| F192::coefficients(row(q)).to_vec())
                .to_hint(),
        );
        queries.iter().map(|&q| row(q).to_vec()).collect()
    }
}
