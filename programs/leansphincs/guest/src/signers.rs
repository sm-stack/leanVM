//! The digest of a leanSPHINCS signer set: the claims an aggregate of leanSPHINCS signatures publishes.
//!
//! A claim says that a key signed a message. A set is written as groups of claims sharing their message, each group
//! a header block then its keys two to a block, and the digest is a chain of BLAKE2s compressions from the parameter
//! IV, one a block, its counter `t` saying what the block is:
//!
//! ```text
//! header   SCHEME, 0, message[0..4], 0, 0              t = START? | 0
//! keys     key_a[0..4], key_b[0..4] (zeros if absent)  t = START? | KEY | PAIR if key_b is a key
//! end      TAG, 0, 0, 0, 0, 0, 0, 0                    t = START? | END, the last block
//! ```
//!
//! `START` marks the chain's first block, so the empty set is the end block alone, and a group's odd last key is
//! alone in its block. A header's first six words are the group's label, and a key's four words are its root's two
//! then its public parameter's two.
//!
//! leanXMSS writes its sets in the same format under its own scheme word, with its leaf index for the zero, so one
//! recursion circuit reads either from labels and keys. The order of groups and keys is the writer's.

use crate::{Message, PublicKey};
#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
use leanvm_guest::blake2s_compress;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
use leanvm_guest::precompile::blake2s_compress;

/// leanSPHINCS's scheme word, a label's first.
pub const SCHEME: u64 = 2;

/// The counter bit of the chain's first block.
pub const START: u64 = 1;
/// The counter bit of a block of keys.
pub const KEY: u64 = 2;
/// The counter bit of the end block.
pub const END: u64 = 4;
/// The counter bit of a block of keys whose second key is one.
pub const PAIR: u64 = 8;

/// The end block's first word.
pub const TAG: u64 = u64::from_le_bytes(*b"claimset");

/// BLAKE2s's initialization vector with the parameter block (no key, a 32-byte digest) folded in, as words.
pub const IV: [u64; 4] = [
    0xBB67_AE85_6A09_E667 ^ 0x0101_0020,
    0xA54F_F53A_3C6E_F372,
    0x9B05_688C_510E_527F,
    0x5BE0_CD19_1F83_D9AB,
];

/// A group's label: the scheme, a zero where leanXMSS has its leaf index, and the message.
#[must_use]
pub const fn label(message: &Message) -> [u64; 6] {
    let [m0, m1, m2, m3] = *message;
    [SCHEME, 0, m0, m1, m2, m3]
}

/// A key's four words: its root, then its public parameter.
#[must_use]
pub const fn key_words(key: &PublicKey) -> [u64; 4] {
    let [r0, r1] = key.root;
    let [p0, p1] = key.public_param;
    [r0, r1, p0, p1]
}

/// A signer set's digest, written one group and one key at a time.
pub struct Stream {
    /// The output of the last block compressed.
    h: [u64; 4],
    /// Whether no block has been compressed yet.
    first: bool,
    /// A block's first key, waiting for its second.
    pending: Option<[u64; 4]>,
}

impl Default for Stream {
    fn default() -> Self {
        Self::new()
    }
}

impl Stream {
    /// The stream of the empty set.
    #[inline(always)]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            h: IV,
            first: true,
            pending: None,
        }
    }

    /// Compress one block.
    #[inline(always)]
    fn block(&mut self, m: &[u64; 8], code: u64, last: bool) {
        let t = code | if self.first { START } else { 0 };
        self.h = blake2s_compress(&self.h, m, t, last);
        self.first = false;
    }

    /// Write the block of keys waiting for its second key, if any.
    #[inline(always)]
    fn flush(&mut self) {
        if let Some([a0, a1, a2, a3]) = self.pending.take() {
            self.block(&[a0, a1, a2, a3, 0, 0, 0, 0], KEY, false);
        }
    }

    /// Open a group: the keys that follow signed `message`.
    #[inline(always)]
    pub fn group(&mut self, message: &Message) {
        self.flush();
        let [l0, l1, l2, l3, l4, l5] = label(message);
        self.block(&[l0, l1, l2, l3, l4, l5, 0, 0], 0, false);
    }

    /// Add a key to the open group, which a group must have been opened for.
    #[inline(always)]
    pub fn key(&mut self, key: &PublicKey) {
        let [b0, b1, b2, b3] = key_words(key);
        match self.pending.take() {
            None => self.pending = Some([b0, b1, b2, b3]),
            Some([a0, a1, a2, a3]) => self.block(&[a0, a1, a2, a3, b0, b1, b2, b3], KEY | PAIR, false),
        }
    }

    /// The set's digest.
    #[inline(always)]
    #[must_use]
    pub fn finish(mut self) -> [u64; 4] {
        self.flush();
        self.block(&[TAG, 0, 0, 0, 0, 0, 0, 0], END, true);
        self.h
    }
}
