//! The public statement of one verified leanSPHINCS signature.
#![no_std]

use leansphincs::{Message, PublicKey};

/// The signature-member hash domain, encoded as eight little-endian bytes.
pub const DOMAIN: u64 = u64::from_le_bytes(*b"sphmem01");

/// BLAKE2s-256 of `sphmem01`, the public key's root and parameter, then the message.
/// Every field after the tag consists of little-endian u64 words.
pub fn member(key: &PublicKey, message: &Message) -> [u64; 4] {
    leanvm_guest::hash_with(|s| {
        s.write([DOMAIN]);
        s.write(key.root);
        s.write(key.public_param);
        s.write(*message);
    })
}
