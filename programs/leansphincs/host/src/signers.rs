//! leanSPHINCS signer sets: the claims an aggregate publishes, their digest and their canonical form.
//!
//! A set is its claims in order, written as groups that are runs of one message. The digest is the guest library's
//! (`leansphincs::signers`), run natively. A set in any order has one; a root publishes the canonical one
//! ([`SignerSet::check`]): claims strictly increasing on `(message, key)`, words compared as integers, first word
//! first. So a canonical set holds each claim once, and each message is one group.

use leansphincs::signers::{Stream, key_words, label};
use leansphincs::{Message, PublicKey};
use thiserror::Error;

/// One claim: `key` signed `message`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SphincsClaim {
    /// The key.
    pub key: PublicKey,
    /// The message.
    pub message: Message,
}

/// A set of leanSPHINCS claims, as an aggregate publishes it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignerSet {
    /// The claims.
    pub claims: Vec<SphincsClaim>,
}

/// Why a set is not canonical.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum SignerSetError {
    /// Two claims out of order, or equal.
    #[error("the claims are not strictly increasing on (message, key)")]
    UnsortedClaims,
}

/// The order a canonical set lists its claims in.
const fn order(c: &SphincsClaim) -> (Message, [u64; 4]) {
    (c.message, key_words(&c.key))
}

impl SignerSet {
    /// The empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self { claims: Vec::new() }
    }

    /// The canonical set of these claims, each once.
    pub fn from_claims(claims: impl IntoIterator<Item = SphincsClaim>) -> Self {
        let mut claims: Vec<SphincsClaim> = claims.into_iter().collect();
        claims.sort_unstable_by_key(order);
        claims.dedup();
        Self { claims }
    }

    /// The canonical set of both sets' claims.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        Self::from_claims(self.claims.iter().chain(&other.claims).copied())
    }

    /// The groups it is written as: the runs of claims of one message.
    pub fn groups(&self) -> impl Iterator<Item = &[SphincsClaim]> {
        self.claims.chunk_by(|a, b| a.message == b.message)
    }

    /// Each group's label and its keys' words, in order: what a recursion circuit reads the set from.
    #[must_use]
    pub fn label_groups(&self) -> Vec<([u64; 6], Vec<[u64; 4]>)> {
        (self.groups())
            .map(|run| (label(&run[0].message), run.iter().map(|c| key_words(&c.key)).collect()))
            .collect()
    }

    /// Its digest, as the guest computes it.
    #[must_use]
    pub fn digest(&self) -> [u64; 4] {
        let mut stream = Stream::new();
        for run in self.groups() {
            stream.group(&run[0].message);
            run.iter().for_each(|c| stream.key(&c.key));
        }
        stream.finish()
    }

    /// Check it is canonical: what a root's verifier asks of the set it publishes.
    ///
    /// # Errors
    ///
    /// [`SignerSetError::UnsortedClaims`] if two claims are out of order or equal.
    pub fn check(&self) -> Result<(), SignerSetError> {
        if !self.claims.windows(2).all(|w| order(&w[0]) < order(&w[1])) {
            return Err(SignerSetError::UnsortedClaims);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leansphincs::signers::{END, IV, KEY, PAIR, SCHEME, START, TAG};
    use leanvm_guest::blake2s_compress;

    /// Key `i`: arbitrary words, increasing with `i`.
    const fn key(i: u64) -> PublicKey {
        PublicKey {
            root: [i, i ^ 0x5555],
            public_param: [i.wrapping_mul(0x9e37_79b9), 7],
        }
    }

    fn claim(k: u64, message: u64) -> SphincsClaim {
        SphincsClaim {
            key: key(k),
            message: [message, 2, 0, 0],
        }
    }

    /// Canonical: message 1 by keys 1, 2 and 3, message 4 by key 1.
    fn sample() -> SignerSet {
        SignerSet {
            claims: vec![claim(1, 1), claim(2, 1), claim(3, 1), claim(1, 4)],
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
        let [k1, k2, k3] = [words(1), words(2), words(3)];
        let pair = |a: [u64; 4], b: [u64; 4]| [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]];
        let blocks: [([u64; 8], u64); 6] = [
            ([SCHEME, 0, 1, 2, 0, 0, 0, 0], START),
            (pair(k1, k2), KEY | PAIR),
            (pair(k3, [0; 4]), KEY),
            ([SCHEME, 0, 4, 2, 0, 0, 0, 0], 0),
            (pair(k1, [0; 4]), KEY),
            ([TAG, 0, 0, 0, 0, 0, 0, 0], END),
        ];
        let chain = (blocks.iter().enumerate()).fold(IV, |h, (i, (m, t))| blake2s_compress(&h, m, *t, i == 5));
        let digest = sample().digest();
        assert_eq!(digest, chain);
        assert_eq!(
            hex(digest),
            "690411581c55ce7536310c2bc947b364f134428a5576b6e2bec8f2e3147ea2ea"
        );

        // The empty set: the end block alone, as leanXMSS's.
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
        // Neighbours of the sample: a key's message changed, a claim dropped, a run split by another message.
        let base = sample();
        let mut variants = vec![SignerSet::new()];
        let mut moved = base.clone();
        moved.claims[2].message = moved.claims[3].message;
        variants.push(moved);
        let mut dropped = base.clone();
        dropped.claims.pop();
        variants.push(dropped);
        let mut split = base.clone();
        split.claims.swap(1, 3);
        variants.push(split);
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(v.digest(), base.digest(), "variant {i}");
        }
    }

    #[test]
    fn check_refuses_every_noncanonical_set() {
        let canonical = sample();
        assert_eq!(canonical.check(), Ok(()));
        assert_eq!(SignerSet::new().check(), Ok(()));
        let refuses = |change: &dyn Fn(&mut SignerSet)| {
            let mut s = canonical.clone();
            change(&mut s);
            assert_eq!(s.check(), Err(SignerSetError::UnsortedClaims));
        };
        // Keys out of order in a message, messages out of order, a repeated claim.
        refuses(&|s| s.claims.swap(0, 1));
        refuses(&|s| s.claims.swap(2, 3));
        refuses(&|s| s.claims.insert(0, claim(1, 1)));
    }

    #[test]
    fn union_is_canonical() {
        // Two overlapping sets, out of order and with repeats: their union is canonical, holds each claim once,
        // and does not depend on the order.
        let a = SignerSet {
            claims: vec![claim(1, 4), claim(3, 1), claim(1, 1), claim(1, 4)],
        };
        let b = SignerSet {
            claims: vec![claim(2, 1), claim(1, 1)],
        };
        let union = a.union(&b);
        assert_eq!(union, sample());
        assert_eq!(b.union(&a), union);
        assert_eq!(union.union(&SignerSet::new()), union);
        assert_eq!(SignerSet::from_claims([]), SignerSet::new());
        assert_eq!(
            union.label_groups(),
            [
                (
                    [SCHEME, 0, 1, 2, 0, 0],
                    vec![key_words(&key(1)), key_words(&key(2)), key_words(&key(3))]
                ),
                ([SCHEME, 0, 4, 2, 0, 0], vec![key_words(&key(1))]),
            ]
        );
    }
}
