//! Verify count-prefixed (public key, message, signature) triples and publish their members.
#![no_std]
#![no_main]

use leansphincs::{Message, PublicKey, Signature};
use leanvm_guest::{commit, members::Members, read, read_unchecked};

leanvm_guest::advice_words!(1 << 16);

#[unsafe(no_mangle)]
extern "C" fn main() {
    let n = *read::<u64>();
    let mut members = Members::new();
    for _ in 0..n {
        // SAFETY: these types are repr(C) words with no padding; all word patterns are representable.
        let key = unsafe { read_unchecked::<PublicKey>() };
        let message = read::<Message>();
        let signature = unsafe { read_unchecked::<Signature>() };
        leansphincs::verify(key, message, signature).expect("every signature verifies");
        members.push(leansphincs_members::member(key, message));
    }
    commit(&members.finish());
}
