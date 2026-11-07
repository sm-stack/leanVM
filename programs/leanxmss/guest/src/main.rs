//! Verify the leanXMSS signatures the advice holds, in groups: the number of groups, then for
//! each a leaf index, a message, a count, and that many public keys and signatures.
//!
//! Each group's signatures are verified at its leaf index and message, and the signer set they
//! form (`leanxmss::signers`: one group per advice group, in the advice's order) is digested as
//! they are read; that digest is the one value committed.
//!
//! A bad signature leaves the run without a proof.
#![no_std]
#![no_main]

use leanvm_guest::{commit, read, read_unchecked};
use leanxmss::signers::Stream;
use leanxmss::{LeafIndex, Message, PublicKey, Signature};

leanvm_guest::advice_words!(1 << 16);

#[unsafe(no_mangle)]
extern "C" fn main() {
    let mut signers = Stream::new();
    let n_groups = *read::<u64>();
    for _ in 0..n_groups {
        let leaf_index = *read::<u64>();
        // A leaf index past `2^32 - 1` would be published whole but verified truncated.
        let leaf = LeafIndex::try_from(leaf_index).expect("a leaf index below 2^32");
        let message = read::<Message>();
        signers.group(leaf, message);
        let n = *read::<u64>();
        for _ in 0..n {
            // Read in place. SAFETY: both types are `repr(C)` words, with no padding, and any
            // words are one (see their definitions).
            let public_key = unsafe { read_unchecked::<PublicKey>() };
            let signature = unsafe { read_unchecked::<Signature>() };

            leanxmss::verify(public_key, leaf, message, signature).expect("every signature verifies");

            signers.key(public_key);
        }
    }
    commit(&signers.finish());
}
