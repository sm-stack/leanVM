// CREDIT: https://github.com/succinctlabs/flock (flock-core), MIT OR Apache-2.0.
//! Binary Merkle tree with BLAKE2s.
//!
//! The committer builds the tree with [`primitives::merkle`]; a proof carries pruned opening paths, which the verifier
//! checks against the root.
//!
//! # Layout
//!
//! For `n = 2^k` leaves, level `j` counted from the leaves:
//!
//! ```text
//!     tree[0 .. n]                  level 0, the leaf digests
//!     tree[n .. 3n/2]               level 1
//!     ...
//!     tree[2n - 2]                  the root
//!
//!     level j starts at 2n - 2n / 2^j
//! ```

use primitives::blake2s::{OUT_LEN, hash_many};
use primitives::field::F64;
use primitives::merkle::{Blake2s, LeafHasher};
use std::borrow::Cow;

/// A node of the tree: one BLAKE2s-256 digest.
pub type Hash = [u8; OUT_LEN];

/// Hash one leaf with standard BLAKE2s-256.
#[inline]
pub fn hash_leaf(data: &[u8]) -> Hash {
    primitives::blake2s::hash(data)
}

/// Hash two children into their parent.
#[inline]
pub fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    primitives::blake2s::hash(&buf)
}

/// A finished Merkle tree over a power of two of leaves.
///
/// Its nodes are stored level after level from the leaves, the root last.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MerkleTree(Vec<Hash>);

impl From<Vec<Hash>> for MerkleTree {
    /// The tree whose nodes are these, level after level from the leaves.
    fn from(nodes: Vec<Hash>) -> Self {
        Self(nodes)
    }
}

impl MerkleTree {
    /// The root.
    pub(crate) fn root(&self) -> Hash {
        *self.0.last().expect("a tree has a root")
    }

    /// The number of leaves.
    pub(crate) const fn num_leaves(&self) -> usize {
        self.0.len().div_ceil(2)
    }

    /// Open `positions`: one row per distinct position, and one octopus authenticating them all.
    ///
    /// - `row(q)` is the leaf at position `q`.
    /// - The octopus holds every sibling no queried subtree supplies.
    ///
    /// A sibling shared by several paths is stored once.
    /// So `q` queries in a tree of depth `d` store at most `q d` digests, what `q` independent paths would.
    pub(crate) fn prune<R: AsRef<[F64]>>(&self, positions: &[usize], row: impl Fn(usize) -> R) -> PrunedMerklePaths {
        let num_leaves = self.num_leaves();
        let sorted = sorted_unique(positions);
        debug_assert!(sorted.iter().all(|&p| p < num_leaves));

        let mut sibling_hashes = Vec::new();
        let mut active = sorted.clone();
        let (mut level_start, mut level_len) = (0usize, num_leaves);
        while level_len > 1 {
            let mut next = Vec::with_capacity(active.len());
            let mut i = 0;
            while i < active.len() {
                let p = active[i];
                // Both children active: they fold into the same parent, so no sibling is needed.
                // Otherwise the sibling has to be sent.
                if i + 1 < active.len() && active[i + 1] == (p ^ 1) {
                    i += 2;
                } else {
                    sibling_hashes.push(self.0[level_start + (p ^ 1)]);
                    i += 1;
                }
                next.push(p >> 1);
            }
            // `next` stays sorted and unique: sibling pairs collapse to one parent, and `p >> 1` is otherwise increasing.
            active = next;
            level_start += level_len;
            level_len >>= 1;
        }

        // The distinct rows, one after another.
        let mut rows = Vec::new();
        for &q in &sorted {
            rows.extend_from_slice(row(q).as_ref());
        }
        PrunedMerklePaths { rows, sibling_hashes }
    }
}

/// The words' little-endian byte image, which is how a leaf hashes them.
#[cfg_attr(
    target_endian = "little",
    expect(
        clippy::missing_const_for_fn,
        reason = "the big-endian path allocates the little-endian encoding"
    )
)]
pub(crate) fn words_as_bytes(words: &[F64]) -> Cow<'_, [u8]> {
    #[cfg(target_endian = "little")]
    {
        // SAFETY: F64 is transparent over u64, whose byte image is little-endian here.
        Cow::Borrowed(unsafe { std::slice::from_raw_parts(words.as_ptr().cast(), std::mem::size_of_val(words)) })
    }
    #[cfg(target_endian = "big")]
    {
        Cow::Owned(words.iter().flat_map(|w| w.0.to_le_bytes()).collect())
    }
}

/// Hash each pair of children into its parent, all pairs together, into `parents`.
fn hash_pairs(pairs: &[[Hash; 2]], parents: &mut Vec<Hash>) {
    parents.clear();
    parents.resize(pairs.len(), [0; 32]);
    hash_many::<{ 2 * OUT_LEN }>(pairs.as_flattened().as_flattened(), parents.as_flattened_mut());
}

/// Query positions with duplicates removed, ascending.
///
/// It is the order a phase stores its rows in, and the order its octopus is built and checked against.
pub(crate) fn sorted_unique(queries: &[usize]) -> Vec<usize> {
    let mut unique = queries.to_vec();
    unique.sort_unstable();
    unique.dedup();
    unique
}

/// One opening phase's Merkle data: the rows at each distinct queried position, ascending, and one octopus over them.
///
/// - A row is words of `K`, what a Merkle preimage is; a row of `w` elements of `E` is `3w` words.
/// - The phase never says how wide a row is: the caller announces it, which pins the leaf image the octopus checks.
/// - A row may be narrower than the image it hashes to, the missing words a zero prefix the caller also announces.
///
/// That prefix is what keeps an L0 commitment's absent lanes out of the proof.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PrunedMerklePaths {
    /// The distinct rows, ascending by position, one after another.
    pub rows: Vec<F64>,
    /// The octopus: every sibling no queried subtree supplies, bottom level first.
    pub sibling_hashes: Vec<Hash>,
}

impl PrunedMerklePaths {
    /// The paths as a transcript hint: every row's words, then every sibling, all little-endian.
    ///
    /// No length is written: the verifier knows how many rows and how wide.
    #[must_use]
    pub(crate) fn to_hint(&self) -> Vec<u8> {
        let mut hint = Vec::with_capacity(8 * self.rows.len() + 32 * self.sibling_hashes.len());
        for word in &self.rows {
            hint.extend_from_slice(&word.0.to_le_bytes());
        }
        hint.extend_from_slice(self.sibling_hashes.as_flattened());
        hint
    }

    /// The paths a hint holds, given its number of rows and their width in words.
    ///
    /// The siblings are the rest, whole digests.
    ///
    /// Returns nothing when the bytes do not split that way, so each paths value has one hint.
    #[must_use]
    pub(crate) fn from_hint(hint: &[u8], n_rows: usize, row_words: usize) -> Option<Self> {
        let (rows, siblings) = hint.split_at_checked(n_rows.checked_mul(row_words)?.checked_mul(8)?)?;
        let (words, []) = rows.as_chunks::<8>() else {
            unreachable!("the rows span whole words")
        };
        let (siblings, []) = siblings.as_chunks::<32>() else {
            return None;
        };
        Some(Self {
            rows: words.iter().map(|w| F64(u64::from_le_bytes(*w))).collect(),
            sibling_hashes: siblings.to_vec(),
        })
    }

    /// Authenticate this phase against `root`, and expand it into one opening per query, in query order.
    ///
    /// - It is the one way to consume a phase, so no row is read before the Merkle check runs.
    /// - Rebuilding every node on the queried paths recomputes the root and yields each query's full sibling path.
    /// - So the pruned form is checked and the unpruned form produced in one walk.
    ///
    /// # Returns
    ///
    /// Nothing on a wrong row count or width, an out-of-range query, a wrong sibling count, or another root.
    pub(crate) fn open(
        &self,
        root: &Hash,
        num_leaves: usize,
        queries: &[usize],
        row_words: usize,
        leaf_words: usize,
    ) -> Option<Openings> {
        if !num_leaves.is_power_of_two() || num_leaves == 0 || queries.is_empty() || row_words > leaf_words {
            return None;
        }
        let height = num_leaves.trailing_zeros() as usize;
        let sorted = sorted_unique(queries);
        if sorted.last().is_some_and(|&p| p >= num_leaves) || self.rows.len() != sorted.len() * row_words {
            return None;
        }

        // The rows, one after another, hashed as the committer hashed them: zero prefix shared, leaves batched.
        let bytes: Vec<u8> = self.rows.iter().flat_map(|word| word.0.to_le_bytes()).collect();
        let mut leaf_hashes = Box::new_uninit_slice(sorted.len());
        LeafHasher::<Blake2s>::new(8 * row_words, 8 * leaf_words).hash(&bytes, &mut leaf_hashes);
        // SAFETY: the hasher wrote one digest per row.
        let leaf_hashes = unsafe { leaf_hashes.assume_init() };

        // Rebuild every node on the queried paths bottom-up.
        // A stored sibling is pulled only where it is not itself a queried subtree.
        //
        // Every level's known nodes go into one buffer, level `l` at `starts[l]..starts[l + 1]`:
        // both children of each parent, ascending by index.
        let mut supplied = self.sibling_hashes.iter();
        let mut known: Vec<(usize, Hash)> = Vec::new();
        let mut starts = Vec::with_capacity(height + 1);
        let mut nodes: Vec<(usize, Hash)> = sorted.iter().copied().zip(leaf_hashes).collect();
        let (mut parents, mut pairs, mut digests) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..height {
            starts.push(known.len());
            parents.clear();
            pairs.clear();
            let mut i = 0;
            while i < nodes.len() {
                let idx = nodes[i].0;
                let paired = idx & 1 == 0 && nodes.get(i + 1).is_some_and(|&(j, _)| j == (idx | 1));
                let (left, right) = if paired {
                    (nodes[i].1, nodes[i + 1].1)
                } else if idx & 1 == 0 {
                    (nodes[i].1, *supplied.next()?)
                } else {
                    (*supplied.next()?, nodes[i].1)
                };
                parents.push(idx >> 1);
                pairs.push([left, right]);
                known.push((idx & !1, left));
                known.push((idx | 1, right));
                i += if paired { 2 } else { 1 };
            }
            hash_pairs(&pairs, &mut digests);
            nodes.clear();
            nodes.extend(parents.iter().copied().zip(digests.iter().copied()));
        }
        starts.push(known.len());
        // The last fold leaves exactly the root, and nothing may be left over.
        if supplied.next().is_some() || nodes.first().map(|n| n.1) != Some(*root) {
            return None;
        }

        // Each query's image and path, in query order.
        let mut openings = Openings {
            leaf_words,
            height,
            images: vec![F64::ZERO; queries.len() * leaf_words],
            paths: Vec::with_capacity(queries.len() * height),
        };
        for (q, image) in queries.iter().zip(openings.images.chunks_exact_mut(leaf_words)) {
            // The query's row is the image's tail, after the zero prefix.
            let slot = sorted.binary_search(q).ok()?;
            image[leaf_words - row_words..].copy_from_slice(&self.rows[slot * row_words..][..row_words]);

            // Its sibling at each level is a known node of that level.
            for (lvl, bounds) in starts.windows(2).enumerate() {
                let level = &known[bounds[0]..bounds[1]];
                let pos = level.binary_search_by_key(&((q >> lvl) ^ 1), |&(j, _)| j).ok()?;
                openings.paths.push(level[pos].1);
            }
        }
        Some(openings)
    }
}

/// A phase's openings, unpruned and in query order: each query's full leaf image and full sibling path.
///
/// Several queries repeat the siblings they share, which is what makes each one simple to consume:
/// recomputing the root is a walk up one path.
///
/// All images sit in one buffer and all paths in another, so a phase costs a fixed number of allocations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Openings {
    /// Words of a leaf image.
    pub leaf_words: usize,
    /// Siblings on a path: the tree's height.
    pub height: usize,
    /// The images, one after another, each with its zero prefix.
    pub images: Vec<F64>,
    /// The paths, one after another, each lowest sibling first.
    pub paths: Vec<Hash>,
}

impl Openings {
    /// The number of queries opened.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.images.len() / self.leaf_words
    }

    /// Whether no query was opened.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.images.is_empty()
    }

    /// Query `i`'s full leaf image, its zero prefix included.
    #[must_use]
    pub fn image(&self, i: usize) -> &[F64] {
        &self.images[i * self.leaf_words..][..self.leaf_words]
    }

    /// Each query's row: its leaf image with the zero prefix dropped, the last `row_words` words.
    #[must_use]
    pub fn rows(&self, row_words: usize) -> Vec<Vec<F64>> {
        (0..self.len())
            .map(|i| self.image(i)[self.leaf_words - row_words..].to_vec())
            .collect()
    }

    /// Query `i`'s siblings, lowest first.
    #[must_use]
    pub fn path(&self, i: usize) -> &[Hash] {
        &self.paths[i * self.height..][..self.height]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tree over these leaf digests, one parent at a time: the reference the builder is checked against.
    fn merkle_tree_sequential(leaves: impl Iterator<Item = Hash>) -> MerkleTree {
        let mut tree: Vec<Hash> = leaves.collect();
        let (mut start, mut len) = (0, tree.len());
        while len > 1 {
            for i in 0..len / 2 {
                tree.push(hash_pair(&tree[start + 2 * i], &tree[start + 2 * i + 1]));
            }
            (start, len) = (start + len, len / 2);
        }
        MerkleTree(tree)
    }

    /// A leaf's hash: its words' little-endian bytes.
    fn hash_words(image: &[F64]) -> Hash {
        hash_leaf(&image.iter().flat_map(|w| w.0.to_le_bytes()).collect::<Vec<u8>>())
    }

    /// The root a leaf image and its path reach, the direction at each level the index's bit.
    fn walk(image: &[F64], path: &[Hash], index: usize) -> Hash {
        (path.iter().enumerate()).fold(hash_words(image), |acc, (lvl, sibling)| {
            if index >> lvl & 1 == 0 {
                hash_pair(&acc, sibling)
            } else {
                hash_pair(sibling, &acc)
            }
        })
    }

    /// The tree whose leaves are these rows' words.
    fn tree_of(rows: &[Vec<F64>]) -> MerkleTree {
        merkle_tree_sequential(rows.iter().map(|r| hash_words(r)))
    }

    #[test]
    fn prune_open_roundtrip() {
        let (num_leaves, width, height) = (8usize, 4usize, 3usize);
        let rows: Vec<Vec<F64>> = (0..num_leaves)
            .map(|q| (0..width).map(|j| F64((q * width + j) as u64)).collect())
            .collect();
        let tree = tree_of(&rows);
        let root = tree.root();
        let queries = [5usize, 1, 5, 3, 1];

        let paths = tree.prune(&queries, |q| rows[q].clone());
        assert_eq!(paths.rows.len(), 3 * width, "one row per distinct query");

        let openings = paths.open(&root, num_leaves, &queries, width, width).expect("open");
        assert_eq!(openings.len(), queries.len());
        for (i, &q) in queries.iter().enumerate() {
            assert_eq!(openings.image(i), rows[q], "row must follow query order");
            assert_eq!(openings.path(i).len(), height);
            assert_eq!(
                walk(openings.image(i), openings.path(i), q),
                root,
                "each unpruned path must reach the root"
            );
        }
    }

    #[test]
    fn malformed_phases_are_rejected() {
        let (num_leaves, width) = (8usize, 4usize);
        let rows: Vec<Vec<F64>> = (0..num_leaves)
            .map(|q| (0..width).map(|j| F64((q * width + j) as u64)).collect())
            .collect();
        let tree = tree_of(&rows);
        let root = tree.root();
        let queries = [5usize, 1, 3];
        let good = tree.prune(&queries, |q| rows[q].clone());
        let open = |p: &PrunedMerklePaths, qs: &[usize], w: usize, n: usize| p.open(&root, n, qs, w, w);
        assert!(open(&good, &queries, width, num_leaves).is_some(), "honest phase");

        let mut extra = good.clone();
        extra.sibling_hashes.push([0u8; 32]);
        assert!(open(&extra, &queries, width, num_leaves).is_none(), "trailing sibling");

        let mut short = good.clone();
        short.sibling_hashes.pop();
        assert!(open(&short, &queries, width, num_leaves).is_none(), "missing sibling");

        let mut flipped = good.clone();
        flipped.sibling_hashes[0][0] ^= 1;
        assert!(
            open(&flipped, &queries, width, num_leaves).is_none(),
            "tampered sibling"
        );

        let mut bad_row = good.clone();
        bad_row.rows[0].0 ^= 1;
        assert!(open(&bad_row, &queries, width, num_leaves).is_none(), "tampered row");

        let mut wide = good.clone();
        wide.rows.push(F64(0));
        assert!(open(&wide, &queries, width, num_leaves).is_none(), "wrong row width");

        assert!(
            open(&good, &queries, width + 1, num_leaves).is_none(),
            "wrong announced width"
        );
        assert!(open(&good, &[5, 1], width, num_leaves).is_none(), "wrong query count");
        assert!(
            open(&good, &[9, 1, 3], width, num_leaves).is_none(),
            "out-of-range query"
        );
        assert!(open(&good, &queries, width, 7).is_none(), "non-power-of-two tree");
    }

    #[test]
    fn a_hint_holds_exactly_one_paths_value() {
        // Fixture: three distinct rows of four words in a tree of eight leaves.
        let rows: Vec<Vec<F64>> = (0..8).map(|q| (0..4).map(|j| F64(q * 4 + j)).collect()).collect();
        let tree = tree_of(&rows);
        let paths = tree.prune(&[5, 1, 3], |q| rows[q].clone());

        // The hint is the 3 * 4 words, then the siblings, nothing else.
        let hint = paths.to_hint();
        assert_eq!(hint.len(), 3 * 4 * 8 + 32 * paths.sibling_hashes.len());
        assert_eq!(PrunedMerklePaths::from_hint(&hint, 3, 4), Some(paths));

        // A byte short or over leaves a partial digest: no paths value.
        assert_eq!(PrunedMerklePaths::from_hint(&hint[1..], 3, 4), None);
        assert_eq!(
            PrunedMerklePaths::from_hint(&[hint.as_slice(), &[0]].concat(), 3, 4),
            None
        );
    }
}
