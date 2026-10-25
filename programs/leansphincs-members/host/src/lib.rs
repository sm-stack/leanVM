//! Advice and public members for the leanSPHINCS member-list guest.

use leansphincs::{Message, PublicKey, Signature};
pub use leansphincs_members::member;
use leanvm_guest::{Run, as_words_unchecked};

/// The guest built by `programs/build.sh`.
pub const ELF: &[u8] = include_bytes!("../../leansphincs-members.elf");

/// A signature batch and the exact ordered list the guest commits.
pub struct Batch {
    /// The advice and expected execution output.
    pub run: Run,
    /// One member per signature, retaining order and repetitions.
    pub members: Vec<[u64; 4]>,
}

/// Encode raw triples. Invalid signatures are rejected by the guest, not silently discarded.
pub fn batch(triples: &[(&PublicKey, &Message, &Signature)]) -> Batch {
    let mut advice = vec![triples.len() as u64];
    let mut members = Vec::with_capacity(triples.len());
    for &(key, message, signature) in triples {
        // SAFETY: both types are repr(C) words with no padding.
        advice.extend_from_slice(unsafe { as_words_unchecked(key) });
        advice.extend_from_slice(message);
        advice.extend_from_slice(unsafe { as_words_unchecked(signature) });
        members.push(member(key, message));
    }
    let expected = leanvm_guest::members::output(&members);
    Batch {
        run: Run { advice, expected },
        members,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leanvm::Program;
    use primitives::hash::{Hasher, digest_words};

    #[test]
    fn signature_members_match_bytes_and_guest_execution() {
        let (sk, key) = leansphincs::key_gen([7; 32]);
        let message = [11, 12, 13, 14];
        let signature = sk.sign(&message).unwrap();
        let batch = batch(&[(&key, &message, &signature), (&key, &message, &signature)]);
        let mut h = Hasher::new();
        h.update(b"sphmem01");
        for word in key.root.into_iter().chain(key.public_param).chain(message) {
            h.update(&word.to_le_bytes());
        }
        assert_eq!(batch.members, vec![digest_words(&h.finalize()); 2]);
        let program = Program::from_elf(ELF).unwrap();
        assert_eq!(program.execute(&batch.run.advice).unwrap().output, batch.run.expected);
        let mut changed = batch.run.advice.clone();
        changed[5] ^= 1;
        assert!(program.execute(&changed).is_err());
        let mut changed = batch.run.advice;
        changed[9] ^= 1;
        assert!(program.execute(&changed).is_err());
    }
}
