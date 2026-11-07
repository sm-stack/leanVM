//! leanXMSS signer sets: the claims an aggregate publishes, their digest and their canonical form.
//!
//! The digest is the guest library's (`leanxmss::signers`), run natively. A set in any order has one; a root
//! publishes the canonical one ([`SignerSet::check`]): groups strictly increasing on `(leaf_index, message)`, each
//! non-empty with strictly increasing keys, words compared as integers, first word first. So a canonical set holds
//! each claim once.

use leanxmss::signers::{Stream, key_words, label};
use leanxmss::{LeafIndex, Message, PublicKey};
use thiserror::Error;

/// One claim: `key` signed `message` at `leaf_index`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XmssClaim {
    /// The leaf index.
    pub leaf_index: LeafIndex,
    /// The message.
    pub message: Message,
    /// The key.
    pub key: PublicKey,
}

/// The keys that signed one message at one leaf index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmssGroup {
    /// The leaf index.
    pub leaf_index: LeafIndex,
    /// The message.
    pub message: Message,
    /// The keys.
    pub keys: Vec<PublicKey>,
}

/// A set of leanXMSS claims, as an aggregate publishes it: its groups in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignerSet {
    /// The groups.
    pub groups: Vec<XmssGroup>,
}

/// Why a set is not canonical.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum SignerSetError {
    /// Two groups out of order, or of one leaf index and message.
    #[error("the groups are not strictly increasing on (leaf index, message)")]
    UnsortedGroups,
    /// A group with no key.
    #[error("a group has no key")]
    EmptyGroup,
    /// A group whose keys are out of order or repeated.
    #[error("a group's keys are not strictly increasing")]
    UnsortedKeys,
}

/// The order a canonical set lists its claims in.
const fn order(c: &XmssClaim) -> (LeafIndex, Message, [u64; 4]) {
    (c.leaf_index, c.message, key_words(&c.key))
}

impl SignerSet {
    /// The empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self { groups: Vec::new() }
    }

    /// The canonical set of these claims, each once.
    pub fn from_claims(claims: impl IntoIterator<Item = XmssClaim>) -> Self {
        let mut claims: Vec<XmssClaim> = claims.into_iter().collect();
        claims.sort_unstable_by_key(order);
        claims.dedup();
        let mut set = Self::new();
        for c in claims {
            match set.groups.last_mut() {
                Some(g) if (g.leaf_index, g.message) == (c.leaf_index, c.message) => g.keys.push(c.key),
                _ => set.groups.push(XmssGroup {
                    leaf_index: c.leaf_index,
                    message: c.message,
                    keys: vec![c.key],
                }),
            }
        }
        set
    }

    /// The canonical set of both sets' claims.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        Self::from_claims(self.claims().chain(other.claims()))
    }

    /// Every claim, in the set's order.
    pub fn claims(&self) -> impl Iterator<Item = XmssClaim> + '_ {
        self.groups.iter().flat_map(|g| {
            g.keys.iter().map(|&key| XmssClaim {
                leaf_index: g.leaf_index,
                message: g.message,
                key,
            })
        })
    }

    /// How many claims it holds, repeats included.
    #[must_use]
    pub fn n_claims(&self) -> usize {
        self.groups.iter().map(|g| g.keys.len()).sum()
    }

    /// Each group's label and its keys' words, in order: what a recursion circuit reads the set from.
    #[must_use]
    pub fn label_groups(&self) -> Vec<([u64; 6], Vec<[u64; 4]>)> {
        (self.groups.iter())
            .map(|g| (label(g.leaf_index, &g.message), g.keys.iter().map(key_words).collect()))
            .collect()
    }

    /// Its digest, as the guest computes it.
    #[must_use]
    pub fn digest(&self) -> [u64; 4] {
        let mut stream = Stream::new();
        for g in &self.groups {
            stream.group(g.leaf_index, &g.message);
            g.keys.iter().for_each(|k| stream.key(k));
        }
        stream.finish()
    }

    /// Check it is canonical: what a root's verifier asks of the set it publishes.
    ///
    /// # Errors
    ///
    /// The first rule it breaks.
    pub fn check(&self) -> Result<(), SignerSetError> {
        let groups = &self.groups;
        if !groups
            .windows(2)
            .all(|w| (w[0].leaf_index, w[0].message) < (w[1].leaf_index, w[1].message))
        {
            return Err(SignerSetError::UnsortedGroups);
        }
        if groups.iter().any(|g| g.keys.is_empty()) {
            return Err(SignerSetError::EmptyGroup);
        }
        if !(groups.iter()).all(|g| g.keys.windows(2).all(|w| key_words(&w[0]) < key_words(&w[1]))) {
            return Err(SignerSetError::UnsortedKeys);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leanvm_guest::blake2s_compress;
    use leanxmss::signers::{END, IV, KEY, PAIR, SCHEME, START, TAG};

    /// Key `i`: arbitrary words, increasing with `i`.
    const fn key(i: u64) -> PublicKey {
        PublicKey {
            merkle_root: [i, i ^ 0x5555],
            public_param: [i.wrapping_mul(0x9e37_79b9), 7],
        }
    }

    fn group(leaf_index: LeafIndex, message: u64, keys: &[u64]) -> XmssGroup {
        XmssGroup {
            leaf_index,
            message: [message, 0, 0, 1],
            keys: keys.iter().map(|&i| key(i)).collect(),
        }
    }

    /// Canonical: groups of three keys, one, and two.
    fn sample() -> SignerSet {
        SignerSet {
            groups: vec![group(3, 1, &[1, 2, 3]), group(3, 2, &[1]), group(4, 1, &[2, 5])],
        }
    }

    fn hex(words: [u64; 4]) -> String {
        words
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[test]
    fn the_iv_is_blake2s_256s() {
        // One full block, compressed as last from the IV, is BLAKE2s-256 of its 64 bytes.
        let block: [u64; 8] = std::array::from_fn(|i| (i as u64 + 1) * 0x0123_4567_89ab_cdef);
        let bytes: Vec<u8> = block.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(
            blake2s_compress(&IV, &block, 64, true),
            primitives::hash::digest_words(&primitives::hash::hash(&bytes))
        );
    }

    #[test]
    fn the_digest_is_the_specified_chain() {
        // Known answer: the sample's chain written out block by block, then pinned.
        let words = |i| key_words(&key(i));
        let [k1, k2, k3, k5] = [words(1), words(2), words(3), words(5)];
        let pair = |a: [u64; 4], b: [u64; 4]| [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]];
        let blocks: [([u64; 8], u64); 8] = [
            ([SCHEME, 3, 1, 0, 0, 1, 0, 0], START),
            (pair(k1, k2), KEY | PAIR),
            (pair(k3, [0; 4]), KEY),
            ([SCHEME, 3, 2, 0, 0, 1, 0, 0], 0),
            (pair(k1, [0; 4]), KEY),
            ([SCHEME, 4, 1, 0, 0, 1, 0, 0], 0),
            (pair(k2, k5), KEY | PAIR),
            ([TAG, 0, 0, 0, 0, 0, 0, 0], END),
        ];
        let chain = (blocks.iter().enumerate()).fold(IV, |h, (i, (m, t))| blake2s_compress(&h, m, *t, i == 7));
        let digest = sample().digest();
        assert_eq!(digest, chain);
        assert_eq!(
            hex(digest),
            "d16708b6f9dbd24f7ecdcda2acdff8f90b5d5046e1d299ef0aff257b7eb6d932"
        );

        // The empty set: the end block alone, as leanSPHINCS's.
        let empty = SignerSet::new().digest();
        assert_eq!(
            empty,
            blake2s_compress(&IV, &[TAG, 0, 0, 0, 0, 0, 0, 0], START | END, true)
        );
        assert_eq!(
            hex(empty),
            "0d2f066121d4b6e65fb356f1621afa61e44e56318d386ddb5872deffa9db83a1"
        );
    }

    #[test]
    fn distinct_sets_have_distinct_digests() {
        // Neighbours of the sample: a key moved between groups, a group split, a key dropped, the order changed.
        let base = sample();
        let mut variants = vec![SignerSet::new()];
        let mut moved = base.clone();
        let k = moved.groups[0].keys.pop().expect("a key");
        moved.groups[1].keys.push(k);
        variants.push(moved);
        let mut split = base.clone();
        let tail = split.groups[0].keys.split_off(2);
        let rest = XmssGroup {
            keys: tail,
            ..split.groups[0].clone()
        };
        split.groups.insert(1, rest);
        variants.push(split);
        let mut dropped = base.clone();
        dropped.groups[2].keys.pop();
        variants.push(dropped);
        let mut reordered = base.clone();
        reordered.groups.reverse();
        variants.push(reordered);
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(v.digest(), base.digest(), "variant {i}");
        }
    }

    #[test]
    fn check_refuses_every_noncanonical_set() {
        let canonical = sample();
        assert_eq!(canonical.check(), Ok(()));
        assert_eq!(SignerSet::new().check(), Ok(()));
        let refuses = |change: &dyn Fn(&mut SignerSet), error| {
            let mut s = canonical.clone();
            change(&mut s);
            assert_eq!(s.check(), Err(error));
        };
        refuses(&|s| s.groups.swap(0, 1), SignerSetError::UnsortedGroups);
        refuses(&|s| s.groups.push(s.groups[2].clone()), SignerSetError::UnsortedGroups);
        refuses(&|s| s.groups[1].keys.clear(), SignerSetError::EmptyGroup);
        refuses(&|s| s.groups[0].keys.swap(0, 1), SignerSetError::UnsortedKeys);
        refuses(&|s| s.groups[0].keys.insert(0, key(1)), SignerSetError::UnsortedKeys);
    }

    #[test]
    fn union_is_canonical() {
        // Two overlapping sets, out of order and with repeats: their union is canonical, holds each claim once,
        // and does not depend on the order.
        let a = SignerSet {
            groups: vec![group(4, 1, &[5, 2, 5]), group(3, 1, &[3, 1])],
        };
        let b = SignerSet {
            groups: vec![group(3, 2, &[1]), group(3, 1, &[2, 1]), group(4, 1, &[])],
        };
        let union = a.union(&b);
        assert_eq!(union, sample());
        assert_eq!(b.union(&a), union);
        assert_eq!(union.union(&SignerSet::new()), union);
        assert_eq!(SignerSet::from_claims([]), SignerSet::new());
        assert_eq!(
            union.label_groups()[2],
            ([SCHEME, 4, 1, 0, 0, 1], vec![key_words(&key(2)), key_words(&key(5))])
        );
    }
}
