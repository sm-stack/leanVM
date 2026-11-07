//! The weight the opening's sumcheck folds against: the initial weight, read once, then a dense one.

use primitives::field::F192;
use primitives::multilinear::eq_table;

/// The opening's initial weight, never stored whole.
///
/// - The first pass reads it one aligned chunk at a time.
/// - The first fold reads it folded over its lane bits, which its claims give in closed form.
pub(crate) trait InitialWeight: Sync {
    /// Writes the weights of words `start..start + out.len()` into `out`.
    ///
    /// The window is one chunk of `INITIAL_BASIS_CHUNK` words, aligned to its size.
    /// When a lane block is smaller than a chunk, the window is one whole block.
    fn fill(&self, start: usize, out: &mut [F192]);

    /// The weight folded over its lowest `|rs|` lane bits at the challenges `rs`, absent lanes counting as zero.
    ///
    /// ```text
    ///     word x of output block o  =  sum_j eq(rs, j) * w((o * 2^|rs| + j) * block + x)
    /// ```
    ///
    /// - `block` is the lane block length, and bit `i` of `j` meets `rs[i]`.
    /// - The output has `ceil(n_lanes / 2^|rs|)` blocks.
    fn fold_lanes(&self, rs: &[F192]) -> Vec<F192>;
}

/// An initial weight held whole, its lane fold the definition.
///
/// A weight that is no stacked claim opens against one, as do the tests in place of a regenerated weight.
pub(crate) struct DenseWeight {
    /// The weight, one value per word.
    pub(crate) weight: Vec<F192>,
    /// The lane block length.
    pub(crate) block: usize,
}

impl InitialWeight for DenseWeight {
    fn fill(&self, start: usize, out: &mut [F192]) {
        out.copy_from_slice(&self.weight[start..start + out.len()]);
    }

    fn fold_lanes(&self, rs: &[F192]) -> Vec<F192> {
        let eq = eq_table(rs);
        let lanes = self.weight.len() / self.block;
        let mut out = vec![F192::ZERO; lanes.div_ceil(eq.len()) * self.block];
        for (word, o) in out.iter_mut().enumerate() {
            let (group, x) = (word / self.block, word % self.block);
            for (lane, &e) in (group * eq.len()..lanes).zip(&eq) {
                *o += e * self.weight[lane * self.block + x];
            }
        }
        out
    }
}

/// The weight the opening's sumcheck folds against.
pub(crate) enum Weight<'a> {
    /// The initial weight, read by the first pass and folded by the first fold.
    Initial(&'a dyn InitialWeight),
    /// One E value per word, in memory: every weight after the first fold.
    Dense(Vec<F192>),
}

impl Weight<'_> {
    /// The weight in memory.
    ///
    /// # Panics
    ///
    /// Panics before the first fold.
    pub(super) fn dense(&self) -> &Vec<F192> {
        match self {
            Weight::Dense(b) => b,
            Weight::Initial(_) => panic!("the initial weight is read folded"),
        }
    }

    /// The weight in memory, to update.
    ///
    /// # Panics
    ///
    /// Panics before the first fold.
    pub(super) fn dense_mut(&mut self) -> &mut Vec<F192> {
        match self {
            Weight::Dense(b) => b,
            Weight::Initial(_) => panic!("the initial weight is read folded"),
        }
    }
}
