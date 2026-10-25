//! Mixed-program member lists, independent of the program's verifying-key digest.
//!
//! The written form is a domain header, members two per block, and an end block.
//! Counter bit 4 separates every compression from the claim-set written form.

use crate::blake2s::IV;
#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
use crate::blake2s_compress;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
use crate::precompile::blake2s_compress;

/// The list compression's domain bit.
pub const DOMAIN: u64 = 16;
/// The header and end block's first word, little endian.
pub const TAG: u64 = u64::from_le_bytes(*b"members1");

/// A streaming member list. Order and repetitions are part of its digest.
pub struct Members {
    h: [u64; 4],
    pending: Option<[u64; 4]>,
}

impl Default for Members {
    fn default() -> Self {
        Self::new()
    }
}

impl Members {
    /// Begin a list under its domain header.
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            h: blake2s_compress(&IV, &[TAG, 0, 0, 0, 0, 0, 0, 0], DOMAIN | 1, false),
            pending: None,
        }
    }

    /// Append one member.
    #[inline(always)]
    pub fn push(&mut self, member: [u64; 4]) {
        if let Some(a) = self.pending.take() {
            self.h = blake2s_compress(
                &self.h,
                &[a[0], a[1], a[2], a[3], member[0], member[1], member[2], member[3]],
                DOMAIN | 2 | 8,
                false,
            );
        } else {
            self.pending = Some(member);
        }
    }

    /// Finish the list digest. A guest commits this digest exactly once.
    #[inline(always)]
    pub fn finish(mut self) -> [u64; 4] {
        if let Some(a) = self.pending {
            self.h = blake2s_compress(&self.h, &[a[0], a[1], a[2], a[3], 0, 0, 0, 0], DOMAIN | 2, false);
        }
        blake2s_compress(&self.h, &[TAG, 0, 0, 0, 0, 0, 0, 0], DOMAIN | 4, true)
    }
}

/// Digest a member list without a program label.
pub fn digest(members: &[[u64; 4]]) -> [u64; 4] {
    let mut stream = Members::new();
    for &member in members {
        stream.push(member);
    }
    stream.finish()
}

/// The execution output of a guest committing this list's digest.
pub fn output(members: &[[u64; 4]]) -> [u64; 4] {
    let mut public = crate::PublicValues::new();
    public.commit(&digest(members));
    public.digest()
}

/// Publish a list as the guest's sole output commitment.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub fn commit_members(members: &[[u64; 4]]) {
    crate::commit(&digest(members));
}

/// Publish a single member using the same list convention.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub fn commit_member(member: &[u64; 4]) {
    commit_members(core::slice::from_ref(member));
}
