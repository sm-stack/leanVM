// CREDIT: https://github.com/succinctlabs/flock (flock-core), MIT OR Apache-2.0.
//! Binary Merkle trees built in cache-resident subtree blocks, over any leaf and node hash.
//!
//! Both layers' commitments build their trees here: the leanISA one over Keccak-256 ([`Keccak`]), the RISC-V one over
//! BLAKE2s-256 ([`Blake2s`]). What a proof carries, and how a verifier checks it, stays with each layer.
//!
//! Layout for `n = 2^k` leaves, level `j` counted from the leaves:
//!
//! ```text
//!     tree[0 .. n]                  level 0, the leaf digests
//!     tree[n .. 3n/2]               level 1
//!     ...
//!     tree[2n - 2]                  the root
//!
//!     level j starts at 2n - 2n / 2^j
//! ```
//!
//! - A node depends only on the aligned run of leaves below it.
//! - So one task hashes a block of leaves and climbs its subtree while the digests are in L1.
//! - The encode hands blocks over as it finishes them, so leaves are hashed while the rows are in L2.
//! - Above the blocks, the last block to finish a unit of nodes climbs it, so no pass waits on a barrier.
//!
//! A tree may be cut: the levels below the cut are never stored, and a group of leaves is rehashed from its rows when
//! opened ([`lower_levels`]).

use std::mem::MaybeUninit;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use parallel::SendPtr;

use crate::{blake2s, hash};

/// A node of the tree: a 32-byte digest.
pub type Digest = [u8; 32];

/// The hash a tree is built with: its leaves' hash and its nodes' hash.
pub trait TreeHash {
    /// The hash partway through a leaf image, after its whole blocks of leading zeros.
    type Prefix: Copy + Send + Sync;
    /// Bytes of a block, the unit a shared zero prefix is counted in.
    const BLOCK: usize;
    /// Inputs one batched step hashes together: a climb stops where a level would no longer fill one.
    const BATCH: usize;
    /// Whether an image continued from a prefix must be whole blocks; leaves that are not are hashed one at a time.
    const WHOLE_BLOCKS: bool;

    /// The hash after `n_blocks` all-zero blocks.
    fn zero_prefix(n_blocks: usize) -> Self::Prefix;

    /// The digests of many images continued from `prefix`, each by `len` bytes of `data`, into `out`.
    fn hash_many_from(prefix: &Self::Prefix, data: &[u8], len: usize, out: &mut [u8]);

    /// Each pair of 32-byte children in `children` hashed into its parent in `parents`.
    fn hash_pairs(children: &[u8], parents: &mut [u8]);

    /// The digest of one leaf image.
    fn hash(data: &[u8]) -> Digest;
}

/// Keccak-256 with Ethereum's padding: [`crate::hash`].
pub struct Keccak;

impl TreeHash for Keccak {
    type Prefix = [u64; hash::STATE_LANES];
    const BLOCK: usize = hash::RATE;
    const BATCH: usize = hash::LANES;
    const WHOLE_BLOCKS: bool = false;

    fn zero_prefix(n_blocks: usize) -> Self::Prefix {
        hash::zero_prefix_state(n_blocks)
    }

    fn hash_many_from(prefix: &Self::Prefix, data: &[u8], len: usize, out: &mut [u8]) {
        hash::hash_many_from_state(data, len, prefix, out);
    }

    fn hash_pairs(children: &[u8], parents: &mut [u8]) {
        hash::hash_many(children, 2 * hash::OUT_LEN, parents);
    }

    fn hash(data: &[u8]) -> Digest {
        hash::hash(data)
    }
}

/// Unkeyed BLAKE2s-256: [`crate::blake2s`].
pub struct Blake2s;

impl TreeHash for Blake2s {
    type Prefix = blake2s::ChainingValue;
    const BLOCK: usize = blake2s::BLOCK_LEN;
    const BATCH: usize = blake2s::BATCH;
    const WHOLE_BLOCKS: bool = true;

    fn zero_prefix(n_blocks: usize) -> Self::Prefix {
        blake2s::ChainingValue::zero_prefix(n_blocks)
    }

    fn hash_many_from(prefix: &Self::Prefix, data: &[u8], len: usize, out: &mut [u8]) {
        prefix.hash_many(data, len, out);
    }

    fn hash_pairs(children: &[u8], parents: &mut [u8]) {
        blake2s::hash_many::<{ 2 * blake2s::OUT_LEN }>(children, parents);
    }

    fn hash(data: &[u8]) -> Digest {
        blake2s::hash(data)
    }
}

/// Nodes one climb takes at most: 32 KiB of digests, which stay in L1.
const UNIT: usize = 1 << 10;

/// Bytes of the staging tile for leaves whose zero padding does not end on a block boundary.
const STAGE_TILE_BYTES: usize = 16 << 10;

/// Leaves a block of a cut tree hashes and climbs to the cut at a time, in a stack scratch that stays in L1.
const SCRATCH_LEAVES: usize = 256;

/// How rows become leaf digests, chosen once from the leaf shape: each leaf image is `zeros(leaf_bytes - row_bytes) ‖ row`.
///
/// Whole blocks of leading zeros are one prefix, hashed once for every leaf.
pub enum LeafHasher<H: TreeHash> {
    /// Past the shared prefix, each row is its own image, hashed where it lies.
    Direct { row_bytes: usize, prefix: H::Prefix },
    /// The rest of the padding does not fill a block, so rows are zero-extended in a tile first.
    Staged {
        row_bytes: usize,
        /// Bytes of the image past the zero blocks: the remaining padding, then the row.
        image: usize,
        prefix: H::Prefix,
    },
    /// Leaves of no whole number of blocks, for a hash that continues only whole blocks: one at a time.
    Single { row_bytes: usize, leaf_bytes: usize },
}

impl<H: TreeHash> LeafHasher<H> {
    /// The hasher for rows of `row_bytes` in leaf images of `leaf_bytes`.
    ///
    /// # Panics
    ///
    /// Panics unless `0 < row_bytes <= leaf_bytes`, and a staged image fits the tile.
    pub fn new(row_bytes: usize, leaf_bytes: usize) -> Self {
        assert!(0 < row_bytes && row_bytes <= leaf_bytes, "a leaf holds its row");
        if H::WHOLE_BLOCKS && !leaf_bytes.is_multiple_of(H::BLOCK) {
            assert!(
                row_bytes == leaf_bytes || leaf_bytes <= STAGE_TILE_BYTES,
                "a padded leaf fits the tile"
            );
            return Self::Single { row_bytes, leaf_bytes };
        }
        let zero_blocks = (leaf_bytes - row_bytes) / H::BLOCK;
        let prefix = H::zero_prefix(zero_blocks);
        let image = leaf_bytes - zero_blocks * H::BLOCK;
        if image == row_bytes {
            Self::Direct { row_bytes, prefix }
        } else {
            assert!(image <= STAGE_TILE_BYTES, "a padded leaf fits the tile");
            Self::Staged {
                row_bytes,
                image,
                prefix,
            }
        }
    }

    /// Bytes of a row.
    pub fn row_bytes(&self) -> usize {
        match *self {
            Self::Direct { row_bytes, .. } | Self::Staged { row_bytes, .. } | Self::Single { row_bytes, .. } => {
                row_bytes
            }
        }
    }

    /// Hash one leaf per row into `out`.
    pub fn hash(&self, rows: &[u8], out: &mut [MaybeUninit<Digest>]) {
        match *self {
            Self::Direct { row_bytes, ref prefix } => {
                H::hash_many_from(prefix, rows, row_bytes, digests_as_bytes(out));
            }
            Self::Staged {
                row_bytes,
                image,
                ref prefix,
            } => {
                // Images per tile: whole batches where the tile holds at least one.
                let per_tile = STAGE_TILE_BYTES / image;
                let per_tile = if per_tile >= H::BATCH {
                    per_tile - per_tile % H::BATCH
                } else {
                    per_tile
                };
                let mut tile = Tile::new();
                for (out, rows) in out.chunks_mut(per_tile).zip(rows.chunks(per_tile * row_bytes)) {
                    let images = tile.extend(rows, row_bytes, image);
                    H::hash_many_from(prefix, images, image, digests_as_bytes(out));
                }
            }
            Self::Single { row_bytes, leaf_bytes } if row_bytes == leaf_bytes => {
                for (slot, row) in out.iter_mut().zip(rows.chunks_exact(row_bytes)) {
                    slot.write(H::hash(row));
                }
            }
            Self::Single { row_bytes, leaf_bytes } => {
                let mut tile = Tile::new();
                for (slot, row) in out.iter_mut().zip(rows.chunks_exact(row_bytes)) {
                    slot.write(H::hash(tile.extend(row, row_bytes, leaf_bytes)));
                }
            }
        }
    }
}

/// A zeroed staging buffer.
struct Tile([u64; STAGE_TILE_BYTES / 8]);

impl Tile {
    fn new() -> Self {
        Self([0; STAGE_TILE_BYTES / 8])
    }

    /// Lay each `row_bytes` row at the end of its own `image`-byte slot, and return the slots.
    ///
    /// One tile serves one `(row_bytes, image)` shape, so the bytes before each row are never written and stay zero.
    fn extend(&mut self, rows: &[u8], row_bytes: usize, image: usize) -> &[u8] {
        let tile: &mut [u8] = crate::cast_slice_mut(&mut self.0);
        let n = rows.len() / row_bytes;
        for (slot, row) in tile.chunks_exact_mut(image).zip(rows.chunks_exact(row_bytes)) {
            slot[image - row_bytes..].copy_from_slice(row);
        }
        &tile[..n * image]
    }
}

/// A Merkle tree filled one aligned block of leaves at a time, from any thread.
///
/// - Leaf `i` hashes the image `zeros(leaf_bytes - row_bytes) ‖ row_i`.
/// - Blocks must all have the same power-of-two size, and together cover every leaf once.
pub struct MerkleBuilder<H: TreeHash> {
    nodes: Nodes<H>,
    /// Levels below it are never stored.
    cut: usize,
    leaves: LeafHasher<H>,
    progress: Progress,
}

impl<H: TreeHash> MerkleBuilder<H> {
    /// An empty tree of `num_leaves` leaves of `leaf_bytes`, each committing `row_bytes`, keeping the levels from `cut`.
    ///
    /// A cut tree's blocks must hold whole groups of `2^cut` leaves.
    ///
    /// # Panics
    ///
    /// Panics unless `num_leaves` is a power of two of at least `2^cut` leaves, and the leaf shape is one
    /// [`LeafHasher::new`] takes.
    pub fn new(num_leaves: usize, row_bytes: usize, leaf_bytes: usize, cut: usize) -> Self {
        assert!(num_leaves.is_power_of_two(), "num_leaves must be power of 2");
        assert!(num_leaves >> cut > 0, "a tree holds a whole leaf group");
        Self {
            nodes: Nodes::new(num_leaves, cut),
            cut,
            leaves: LeafHasher::new(row_bytes, leaf_bytes),
            progress: Progress::new(num_leaves),
        }
    }

    /// Leaves in the tree.
    pub fn num_leaves(&self) -> usize {
        self.nodes.num_leaves
    }

    /// Bytes of a row.
    pub fn row_bytes(&self) -> usize {
        self.leaves.row_bytes()
    }

    /// Hash the rows in `rows` as the leaves from `first_leaf` on, and climb their subtree.
    ///
    /// # Panics
    ///
    /// Panics unless the block is aligned, sized like every other, and new.
    pub fn absorb(&self, first_leaf: usize, rows: &[u8]) {
        let n = rows.len() / self.leaves.row_bytes();
        assert_eq!(rows.len(), n * self.leaves.row_bytes(), "whole rows");
        // Every shape check comes before the claim, so a claimed block is always written.
        let chunk = n.min(SCRATCH_LEAVES);
        if self.cut > 0 {
            assert!(n >= 1 << self.cut, "a block holds whole leaf groups");
            assert!(n.is_multiple_of(chunk), "a block holds whole chunks");
        }
        self.progress.claim(first_leaf, n);
        // SAFETY: the claim makes these leaves, and their subtree up to the unit, ours alone.
        unsafe {
            if self.cut == 0 {
                self.leaves.hash(rows, self.nodes.level_mut(0, first_leaf, n));
                return self.complete(0, first_leaf, n);
            }
            // The groups climb to the cut in a stack scratch, a chunk of leaves at a time, and only their tops are kept.
            let tops = n >> self.cut;
            let mut scratch = [MaybeUninit::<Digest>::uninit(); 2 * SCRATCH_LEAVES];
            for (k, rows) in rows.chunks_exact(chunk * self.leaves.row_bytes()).enumerate() {
                let (a, b) = scratch.split_at_mut(SCRATCH_LEAVES);
                self.leaves.hash(rows, &mut a[..chunk]);
                let (mut src, mut dst, mut m) = (a, b, chunk);
                for _ in 0..self.cut {
                    H::hash_pairs(digests_as_bytes(&mut src[..m]), digests_as_bytes(&mut dst[..m / 2]));
                    (src, dst, m) = (dst, src, m / 2);
                }
                self.nodes
                    .level_mut(self.cut, (first_leaf >> self.cut) + k * m, m)
                    .copy_from_slice(&src[..m]);
            }
            self.complete(self.cut, first_leaf >> self.cut, tops);
        }
    }

    /// Climb `n` finished nodes of `level` from node `first`, then hand them to their unit.
    ///
    /// - A whole level climbs straight to the root.
    /// - Otherwise the climb stops at the last level whose hashing still fills a whole batch.
    /// - The unit's last arrival climbs the unit in turn, and so on up to the root.
    ///
    /// # Safety
    ///
    /// The nodes are initialized, and no other caller holds them or their subtree.
    unsafe fn complete(&self, level: usize, first: usize, n: usize) {
        if n == self.nodes.width(level) {
            // SAFETY: forwarded, and the whole level climbs to the root.
            return unsafe { self.nodes.climb(level, 0, n, n.ilog2() as usize) };
        }
        let height = (n / H::BATCH).max(1).ilog2() as usize;
        // SAFETY: forwarded.
        unsafe { self.nodes.climb(level, first, n, height) };
        let (level, first, n) = (level + height, first >> height, n >> height);

        let unit = UNIT.min(self.nodes.width(level));
        if self.progress.arrive(level, first / unit, n, unit) {
            // SAFETY: every node of the unit is written, and only its last arrival gets here, after seeing every write.
            unsafe { self.complete(level, first - first % unit, unit) };
        }
    }

    /// The finished tree's levels from the cut up, in the flat layout of the full tree, the root last.
    ///
    /// # Panics
    ///
    /// Panics unless every leaf was absorbed.
    pub fn finish(self) -> Vec<Digest> {
        assert!(self.progress.all_claimed(), "every leaf absorbed");
        // SAFETY: every block was absorbed once, and the last arrivals climbed every level above.
        unsafe { self.nodes.assume_init() }
    }
}

/// The levels `0 .. height` above `rows`, aligned groups of `2^height` leaves side by side, in the flat layout.
///
/// It is what a cut tree keeps nothing of: level `j` starts at `2n - 2n / 2^j` for the `n` rows.
///
/// # Panics
///
/// Panics unless the rows are whole groups.
pub fn lower_levels<H: TreeHash>(leaves: &LeafHasher<H>, rows: &[u8], height: usize) -> Vec<Digest> {
    let n = rows.len() / leaves.row_bytes();
    assert!(
        rows.len() == n * leaves.row_bytes() && n.is_multiple_of(1 << height),
        "whole leaf groups"
    );
    if n == 0 {
        return Vec::new();
    }
    let mut nodes = Nodes::<H>::new(n, 0);
    // SAFETY: the nodes are ours alone, the climb writes every level it reads, and the levels kept are written.
    unsafe {
        leaves.hash(rows, nodes.level_mut(0, 0, n));
        nodes.climb(0, 0, n, height);
        nodes.tree.truncate(level_start(n, height));
        nodes.assume_init()
    }
}

/// Index of `level`'s first node in the flat tree of `num_leaves` leaves.
pub const fn level_start(num_leaves: usize, level: usize) -> usize {
    2 * num_leaves - ((2 * num_leaves) >> level)
}

/// The flat tree from level `cut` up, written at disjoint nodes by concurrent climbs.
struct Nodes<H> {
    tree: Vec<MaybeUninit<Digest>>,
    base: SendPtr<MaybeUninit<Digest>>,
    num_leaves: usize,
    cut: usize,
    hash: std::marker::PhantomData<fn() -> H>,
}

impl<H: TreeHash> Nodes<H> {
    fn new(num_leaves: usize, cut: usize) -> Self {
        let mut tree = Box::new_uninit_slice(((2 * num_leaves) >> cut) - 1).into_vec();
        let base = SendPtr(tree.as_mut_ptr());
        Self {
            tree,
            base,
            num_leaves,
            cut,
            hash: std::marker::PhantomData,
        }
    }

    /// Nodes on `level`.
    fn width(&self, level: usize) -> usize {
        self.num_leaves >> level
    }

    /// Index of `level`'s first node.
    fn start(&self, level: usize) -> usize {
        level_start(self.num_leaves, level) - level_start(self.num_leaves, self.cut)
    }

    /// Nodes `first .. first + n` of `level`.
    ///
    /// # Safety
    ///
    /// No other live slice overlaps them.
    #[allow(clippy::mut_from_ref)]
    unsafe fn level_mut(&self, level: usize, first: usize, n: usize) -> &mut [MaybeUninit<Digest>] {
        debug_assert!(self.cut <= level && first + n <= self.width(level));
        // SAFETY: in bounds, and exclusive by the caller.
        unsafe { self.base.slice(self.start(level) + first, n) }
    }

    /// Hash `n` nodes of `level`, from node `first`, `height` levels up.
    ///
    /// # Safety
    ///
    /// The nodes are initialized, and nothing else touches their subtree up to `height` levels above.
    unsafe fn climb(&self, level: usize, first: usize, n: usize, height: usize) {
        let (mut first, mut n) = (first, n);
        for j in level..level + height {
            // SAFETY: level `j` of the subtree is initialized, and level `j + 1` is ours to write.
            let (children, parents) = unsafe { (self.level_mut(j, first, n), self.level_mut(j + 1, first / 2, n / 2)) };
            H::hash_pairs(digests_as_bytes(children), digests_as_bytes(parents));
            (first, n) = (first / 2, n / 2);
        }
    }

    /// # Safety
    ///
    /// Every node is written.
    unsafe fn assume_init(self) -> Vec<Digest> {
        // SAFETY: forwarded.
        unsafe { self.tree.into_boxed_slice().assume_init() }.into_vec()
    }
}

/// Which blocks arrived, and how many nodes of each unit above them are finished.
struct Progress {
    /// One flag per block, sized by the first block to arrive.
    blocks: OnceLock<Box<[AtomicBool]>>,
    /// Per level, one counter per unit.
    units: Box<[Box<[AtomicUsize]>]>,
    num_leaves: usize,
}

impl Progress {
    fn new(num_leaves: usize) -> Self {
        let counters = |width: usize| (0..width.div_ceil(UNIT)).map(|_| AtomicUsize::new(0)).collect();
        Self {
            blocks: OnceLock::new(),
            units: (0..=num_leaves.ilog2()).map(|j| counters(num_leaves >> j)).collect(),
            num_leaves,
        }
    }

    /// Claim the block of `n` leaves at `first`.
    ///
    /// # Panics
    ///
    /// Panics unless the block is aligned, inside the tree, sized like every other, and new.
    fn claim(&self, first: usize, n: usize) {
        assert!(
            n.is_power_of_two() && first.is_multiple_of(n),
            "an aligned power-of-two block"
        );
        assert!(first + n <= self.num_leaves, "the block is inside the tree");
        let count = self.num_leaves / n;
        let blocks = self
            .blocks
            .get_or_init(|| (0..count).map(|_| AtomicBool::new(false)).collect());
        assert_eq!(blocks.len(), count, "blocks of one size");
        assert!(
            !blocks[first / n].swap(true, Ordering::AcqRel),
            "a block absorbed twice"
        );
    }

    /// Count `n` more finished nodes of unit `u` on `level`, true for the unit's last arrival.
    ///
    /// AcqRel: the last arrival sees every node the others wrote.
    fn arrive(&self, level: usize, u: usize, n: usize, unit: usize) -> bool {
        self.units[level][u].fetch_add(n, Ordering::AcqRel) + n == unit
    }

    fn all_claimed(&self) -> bool {
        self.blocks
            .get()
            .is_some_and(|b| b.iter().all(|f| f.load(Ordering::Acquire)))
    }
}

fn digests_as_bytes(out: &mut [MaybeUninit<Digest>]) -> &mut [u8] {
    // SAFETY: a digest is 32 bytes with no padding, and the hasher only writes.
    unsafe { std::slice::from_raw_parts_mut(out.as_mut_ptr().cast(), out.len() * 32) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_pair<H: TreeHash>(left: &Digest, right: &Digest) -> Digest {
        H::hash(&[*left, *right].concat())
    }

    /// Absorb all rows, in parallel blocks.
    fn absorb_all<H: TreeHash>(builder: &MerkleBuilder<H>, data: &[u8]) {
        let num_leaves = builder.num_leaves();
        assert_eq!(data.len(), num_leaves * builder.row_bytes(), "one row per leaf");
        // Enough blocks for every worker, each at most one unit.
        let log_tasks = (4 * parallel::num_threads()).next_power_of_two().ilog2();
        let log_block = num_leaves
            .ilog2()
            .saturating_sub(log_tasks)
            .min(UNIT.ilog2())
            .max(builder.cut as u32);
        let block_bytes = builder.row_bytes() << log_block;
        parallel::for_each(num_leaves >> log_block, |b| {
            builder.absorb(b << log_block, &data[b * block_bytes..][..block_bytes]);
        });
    }

    fn tree<H: TreeHash>(
        data: &[u8],
        num_leaves: usize,
        row_bytes: usize,
        leaf_bytes: usize,
        cut: usize,
    ) -> Vec<Digest> {
        let builder = MerkleBuilder::<H>::new(num_leaves, row_bytes, leaf_bytes, cut);
        absorb_all(&builder, data);
        builder.finish()
    }

    /// Per-leaf reference for the tree.
    fn sequential<H: TreeHash>(leaves: impl Iterator<Item = Digest>) -> Vec<Digest> {
        let mut tree: Vec<Digest> = leaves.collect();
        let (mut start, mut len) = (0, tree.len());
        while len > 1 {
            for i in 0..len / 2 {
                tree.push(hash_pair::<H>(&tree[start + 2 * i], &tree[start + 2 * i + 1]));
            }
            (start, len) = (start + len, len / 2);
        }
        tree
    }

    fn byte_tree_matches_sequential<H: TreeHash>() {
        // Leaf sizes on both sides of a block, whole blocks or not; leaf counts cross the batch, the block, and the
        // parallel top.
        for (num_leaves, leaf_size) in [
            (1usize, 32usize),
            (2, 48),
            (8, 32),
            (32, 64),
            (64, 128),
            (64, 136),
            (64, 272),
            (256, 192),
            (64, 256),
            (4096, 384),
            (4096, 512),
            (64, 1024),
            (8192, 16),
            (1 << 17, 64),
        ] {
            let data: Vec<u8> = (0..num_leaves * leaf_size)
                .map(|i| (i.wrapping_mul(131) ^ 0x5a) as u8)
                .collect();
            let want = sequential::<H>(data.chunks(leaf_size).map(H::hash));
            assert_eq!(
                tree::<H>(&data, num_leaves, leaf_size, leaf_size, 0),
                want,
                "num_leaves={num_leaves} leaf_size={leaf_size}"
            );
        }
    }

    fn padded_rows_tree_matches_full_width<H: TreeHash>() {
        // Invariant: each leaf hashes as its zero-extended row, however the prefix splits.
        for (num_leaves, row_words, leaf_words) in [
            // Nothing to pad.
            (8usize, 64usize, 64usize),
            (1024, 8, 8),
            // A shared prefix plus a partial block, staged.
            (2048, 37, 64),
            (256, 27, 64),
            (64, 1, 64),
            // A prefix of whole blocks for one hash or the other: the rows are hashed where they lie.
            (256, 30, 64),
            (256, 32, 64),
            (1 << 14, 47, 64),
            (1 << 14, 56, 64),
            // A prefix shorter than one block: nothing shared, still staged.
            (32, 5, 8),
            (256, 61, 64),
            // Leaves that are not a whole number of blocks.
            (16, 3, 5),
            (64, 7, 40),
        ] {
            let data: Vec<u8> = (0..8 * row_words * num_leaves)
                .map(|i| (i.wrapping_mul(0x9E37_79B9) >> 3) as u8 | 1)
                .collect();
            let want = sequential::<H>(data.chunks(8 * row_words).map(|row| {
                let mut image = vec![0u8; 8 * (leaf_words - row_words)];
                image.extend_from_slice(row);
                H::hash(&image)
            }));
            assert_eq!(
                tree::<H>(&data, num_leaves, 8 * row_words, 8 * leaf_words, 0),
                want,
                "num_leaves={num_leaves} row_words={row_words} leaf_words={leaf_words}"
            );
        }
    }

    fn blocks_of_any_size_build_one_tree<H: TreeHash>() {
        // Invariant: the tree does not depend on the block size the encode picks.
        let (num_leaves, row_bytes, cut) = (1usize << 12, 48usize, 4usize);
        let data: Vec<u8> = (0..row_bytes * num_leaves).map(|i| (i * 7 + 1) as u8).collect();
        let want = tree::<H>(&data, num_leaves, row_bytes, row_bytes, 0);
        for log_block in [0usize, 3, 5, 6, 9, 12] {
            let builder = MerkleBuilder::<H>::new(num_leaves, row_bytes, row_bytes, 0);
            // Blocks arrive out of order, as the encode's tasks finish.
            for b in (0..num_leaves >> log_block).rev() {
                let rows = row_bytes << log_block;
                builder.absorb(b << log_block, &data[b * rows..][..rows]);
            }
            assert_eq!(builder.finish(), want, "log_block={log_block}");
        }
        // A cut tree is the full tree without its lowest levels, whatever the block size.
        for log_block in [4usize, 5, 9, 12] {
            let builder = MerkleBuilder::<H>::new(num_leaves, row_bytes, row_bytes, cut);
            for b in (0..num_leaves >> log_block).rev() {
                let rows = row_bytes << log_block;
                builder.absorb(b << log_block, &data[b * rows..][..rows]);
            }
            assert_eq!(
                builder.finish(),
                want[level_start(num_leaves, cut)..],
                "log_block={log_block}"
            );
        }
        // The levels below the cut, rebuilt from a few groups' rows, are the full tree's.
        let groups = [3usize, 17, 200];
        let rows: Vec<u8> = groups
            .iter()
            .flat_map(|&g| &data[(g << cut) * row_bytes..][..row_bytes << cut])
            .copied()
            .collect();
        let local = lower_levels(&LeafHasher::<H>::new(row_bytes, row_bytes), &rows, cut);
        let n = groups.len() << cut;
        for level in 0..cut {
            let width = 1 << (cut - level);
            for (k, &g) in groups.iter().enumerate() {
                assert_eq!(
                    local[level_start(n, level) + k * width..][..width],
                    want[level_start(num_leaves, level) + g * width..][..width],
                    "level={level} group={g}"
                );
            }
        }
    }

    #[test]
    fn keccak_trees_are_their_definition() {
        byte_tree_matches_sequential::<Keccak>();
        padded_rows_tree_matches_full_width::<Keccak>();
        blocks_of_any_size_build_one_tree::<Keccak>();
    }

    #[test]
    fn blake2s_trees_are_their_definition() {
        byte_tree_matches_sequential::<Blake2s>();
        padded_rows_tree_matches_full_width::<Blake2s>();
        blocks_of_any_size_build_one_tree::<Blake2s>();
    }

    #[test]
    #[should_panic(expected = "every leaf absorbed")]
    fn a_missing_block_is_rejected() {
        let builder = MerkleBuilder::<Keccak>::new(16, 64, 64, 0);
        builder.absorb(0, &[0; 8 * 64]);
        let _ = builder.finish();
    }

    #[test]
    #[should_panic(expected = "a block absorbed twice")]
    fn a_repeated_block_is_rejected() {
        let builder = MerkleBuilder::<Blake2s>::new(16, 64, 64, 0);
        builder.absorb(8, &[0; 8 * 64]);
        builder.absorb(8, &[0; 8 * 64]);
    }
}
