//! Verify the leanSPHINCS signatures the advice holds, in groups: the number of groups, then for
//! each a message, a count, and that many public keys and signatures.
//!
//! Each group's signatures are verified against its message, and the signer set they form
//! (`leansphincs::signers`: the claims in the advice's order) is digested as they are read;
//! that digest is the one value committed.
//!
//! A set is written as runs of claims of one message, so a group opens a run only if it has a
//! signature and its message is not the open run's: the digest is the set's whatever the
//! advice's grouping.
//!
//! A bad signature leaves the run without a proof.
#![no_std]
#![no_main]

use leansphincs::signers::Stream;
use leansphincs::{Message, PublicKey, Signature};
use leanvm_guest::{commit, read, read_unchecked};

leanvm_guest::advice_words!(1 << 16);

#[unsafe(no_mangle)]
extern "C" fn main() {
    let mut signers = Stream::new();
    // The message of the open run, if any.
    let mut open: Option<&Message> = None;
    let n_groups = *read::<u64>();
    for _ in 0..n_groups {
        let message = read::<Message>();
        let n = *read::<u64>();
        if n != 0 && open != Some(message) {
            signers.group(message);
            open = Some(message);
        }
        for _ in 0..n {
            // Read in place. SAFETY: both types are `repr(C)` words, with no padding, and any
            // words are one (see their definitions).
            let public_key = unsafe { read_unchecked::<PublicKey>() };
            let signature = unsafe { read_unchecked::<Signature>() };

            leansphincs::verify(public_key, message, signature).expect("every signature verifies");

            signers.key(public_key);
        }
    }
    commit(&signers.finish());
}
