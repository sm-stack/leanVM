// CREDIT: https://github.com/succinctlabs/flock (flock-core), MIT OR Apache-2.0.
//! Binary Merkle tree with Keccak-256: the commitment's tree, built by [`primitives::merkle`].
//!
//! The committer's half. What a proof carries lives in [`fiat_shamir::merkle`].
//!
//! A large tree is cut: its lowest levels are never stored, and a leaf group is rehashed from its rows when opened.

pub use fiat_shamir::merkle::{Hash, MerklePath, hash_leaf, hash_pair};
use primitives::cast_slice;
use primitives::field::F64;
use primitives::merkle::{Keccak, LeafHasher, level_start, lower_levels};

/// A Merkle tree filled one aligned block of leaves at a time, from any thread.
///
/// Leaf `i` is `zeros(leaf_words - row_words) ‖ row_i`.
///
/// Blocks must all have the same power-of-two size, and together cover every leaf once.
pub(crate) struct MerkleBuilder {
    inner: primitives::merkle::MerkleBuilder<Keccak>,
    /// Levels below it are never stored: see [`CutTree`].
    cut: usize,
}

impl MerkleBuilder {
    /// An empty tree of `num_leaves` leaves of `leaf_words`, each committing `row_words`.
    ///
    /// A tree of `CUT_FROM` leaves or more is cut, so its blocks must hold whole leaf groups.
    pub fn new(num_leaves: usize, row_words: usize, leaf_words: usize) -> Self {
        let cut = if num_leaves >= CUT_FROM { CUT } else { 0 };
        Self::with_bytes(num_leaves, 8 * row_words, 8 * leaf_words, cut)
    }

    fn with_bytes(num_leaves: usize, row_bytes: usize, leaf_bytes: usize, cut: usize) -> Self {
        Self {
            inner: primitives::merkle::MerkleBuilder::new(num_leaves, row_bytes, leaf_bytes, cut),
            cut,
        }
    }

    /// Hash the leaves `first_leaf ..` of the rows in `rows`, and climb their subtree.
    ///
    /// # Panics
    ///
    /// Panics unless the block is aligned, sized like every other, and new.
    pub fn absorb(&self, first_leaf: usize, rows: &[F64]) {
        self.inner.absorb(first_leaf, cast_slice(rows));
    }

    /// The finished tree, cut at the builder's level.
    ///
    /// # Panics
    ///
    /// Panics unless every leaf was absorbed.
    pub fn finish(self) -> CutTree {
        let num_leaves = self.inner.num_leaves();
        CutTree {
            nodes: self.inner.finish(),
            cut: self.cut,
            num_leaves,
        }
    }
}

/// Levels below which a large tree keeps nothing: groups of `2^CUT` leaves are rehashed from their rows when opened.
const CUT: usize = 4;

/// Trees of this many leaves or more are cut, so every block they are built from holds a leaf group.
const CUT_FROM: usize = 1 << 12;

/// A finished tree that keeps only the levels from `cut` up, in the flat layout of the full tree.
///
/// Opening a leaf group takes its rows again: the levels below `cut` are recomputed from them.
pub(crate) struct CutTree {
    nodes: Vec<Hash>,
    cut: usize,
    num_leaves: usize,
}

impl CutTree {
    pub fn root(&self) -> Hash {
        self.nodes[self.nodes.len() - 1]
    }

    /// Distinct groups the `positions` fall in, ascending.
    fn groups(&self, positions: &[usize]) -> Vec<usize> {
        let mut groups: Vec<usize> = positions.iter().map(|&q| q >> self.cut).collect();
        groups.sort_unstable();
        groups.dedup();
        groups
    }

    /// Every leaf of the groups `positions` fall in, ascending: the rows [`Self::open`] takes.
    pub(crate) fn group_positions(&self, positions: &[usize]) -> Vec<usize> {
        let groups = self.groups(positions);
        groups
            .iter()
            .flat_map(|&g| g << self.cut..(g + 1) << self.cut)
            .collect()
    }

    /// The paths of `positions`, with `row(q)` the row at `q`.
    ///
    /// `group_rows` are the full rows of [`Self::group_positions`], `row_words` each, back to back, hashed
    /// as the leaves `zeros(leaf_words - row_words) ‖ row`.
    pub fn open<'a>(
        &self,
        positions: &[usize],
        row_words: usize,
        leaf_words: usize,
        group_rows: &[F64],
        row: impl Fn(usize) -> &'a [F64],
    ) -> Vec<MerklePath> {
        let (groups, size) = (self.groups(positions), 1usize << self.cut);
        let n = groups.len() * size;
        assert_eq!(group_rows.len(), n * row_words, "the rows of every group");
        // All groups' leaves as one flat tree up to the cut: a group is aligned, so no climb mixes two.
        // An uncut tree stores every node, so it needs none of them.
        let local = if self.cut == 0 {
            Vec::new()
        } else {
            lower_levels(
                &LeafHasher::<Keccak>::new(8 * row_words, 8 * leaf_words),
                cast_slice(group_rows),
                self.cut,
            )
        };
        let node = |level: usize, i: usize| {
            if level >= self.cut {
                return self.nodes[level_start(self.num_leaves, level) - level_start(self.num_leaves, self.cut) + i];
            }
            let width = 1usize << (self.cut - level);
            let group = groups
                .binary_search(&(i / width))
                .expect("a sibling is in an opened group");
            local[level_start(n, level) + group * width + i % width]
        };
        fiat_shamir::merkle::open(self.num_leaves, positions, leaf_words, node, row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cut_tree_opens_like_the_full_tree() {
        // Invariant: opening through the cut tree gives the paths of the full tree.
        for (num_leaves, row_words, leaf_words) in [(256usize, 8usize, 16usize), (1 << 10, 24, 24), (32, 8, 8)] {
            let data: Vec<F64> = (0..row_words * num_leaves)
                .map(|i| F64(i as u64 * 0x9E37_79B9 + 1))
                .collect();
            let row = |q: usize| &data[q * row_words..][..row_words];
            let tree = |cut: usize| {
                let builder = MerkleBuilder::with_bytes(num_leaves, 8 * row_words, 8 * leaf_words, cut);
                builder.absorb(0, &data);
                builder.finish()
            };
            let (full, cut) = (tree(0), tree(CUT));
            assert_eq!(cut.root(), full.root());
            for positions in [
                vec![0usize],
                vec![5, 5, 6, 200 % num_leaves, num_leaves - 1],
                (0..num_leaves).step_by(7).collect(),
            ] {
                let group = cut.group_positions(&positions);
                let rows: Vec<F64> = group.iter().flat_map(|&q| row(q)).copied().collect();
                let node = |level: usize, i: usize| full.nodes[level_start(num_leaves, level) + i];
                assert_eq!(
                    cut.open(&positions, row_words, leaf_words, &rows, row),
                    fiat_shamir::merkle::open(num_leaves, &positions, leaf_words, node, row)
                );
            }
        }
    }
}
