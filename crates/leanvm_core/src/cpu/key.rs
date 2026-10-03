//! The commitment to a program's decoded table and the public metadata that defines its run.

use super::layout::{Announcement, Sizes};
use super::{Claim, CpuError, DeferredClaims, Layout, Output, Program, ProgramPoint, Proof, ProofKind, VerifyError};
use crate::bus::{N_TUPLE_BITS, PublicColumns};
use crate::constraints::ConstraintError;
use crate::rv::{Region, RiscvProgram};
use fiat_shamir::arith::{Arith, Native, Verifier};
use fiat_shamir::{ProverState, SessionId, VerifierState};
use pcs::merkle::{Hash, Openings};
use pcs::ring_switch::inverse_frobenius_ladder;
use pcs::stack::{CommittedStack, StackClaim, StackCommitment, Statement};
use pcs::verifier::{OpeningVerifier, Recording};
use pcs::whir::Config;
use primitives::field::{F64, F192};
use primitives::hash::Hasher;
use primitives::multilinear::mle_eval_par;

/// The public key of a program, without its decoded bytecode or prover's commitment data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    root: Hash,
    sizes: Sizes,
    entry_pc: u64,
    image: Vec<u64>,
    digest: Hash,
}

/// The retained encoding of the program, opened by every proof of a run.
pub(super) struct ProgramCommitment {
    words: Vec<F64>,
    stack: CommittedStack,
}

impl VerifyingKey {
    pub(super) fn new(root: Hash, sizes: Sizes, entry_pc: u64, image: Vec<u64>) -> Self {
        let mut key = Self {
            root,
            sizes,
            entry_pc,
            image,
            digest: [0; 32],
        };
        let mut hash = Hasher::new();
        hash.update(Program::DIGEST_DOMAIN);
        hash.update(&key.to_bytes());
        key.digest = hash.finalize();
        key
    }

    /// The root, then five little-endian words (bytecode height, entry, RAM height, advice height, image length), then the image.
    pub fn to_bytes(&self) -> Vec<u8> {
        let header = [
            self.sizes.log_bytecode as u64,
            self.entry_pc,
            self.sizes.log_ram as u64,
            self.sizes.log_advice as u64,
            self.image.len() as u64,
        ];
        self.root
            .iter()
            .copied()
            .chain(header.iter().chain(&self.image).flat_map(|w| w.to_le_bytes()))
            .collect()
    }

    /// Decode a canonical key, refusing metadata outside the machine's regions or the program commitment's profile.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (root, rest) = bytes.split_first_chunk::<32>()?;
        let (words, tail) = rest.as_chunks::<8>();
        if !tail.is_empty() {
            return None;
        }
        let words: Vec<_> = words.iter().map(|w| u64::from_le_bytes(*w)).collect();
        let (&[bc, entry, ram, advice, len], image) = words.split_first_chunk::<5>()?;
        let (bc, ram, advice) = (
            usize::try_from(bc).ok()?,
            usize::try_from(ram).ok()?,
            usize::try_from(advice).ok()?,
        );
        if !(1..=Region::TEXT
            .max_log_words()
            .min(crate::commitment::MAX_MU - N_TUPLE_BITS))
            .contains(&bc)
            || image.len() as u64 != len
        {
            return None;
        }
        RiscvProgram::validate((1 << bc) - 1, entry, image.len(), ram, advice).ok()?;
        Some(Self::new(
            *root,
            Sizes {
                log_bytecode: bc,
                log_ram: ram,
                log_advice: advice,
            },
            entry,
            image.to_vec(),
        ))
    }

    /// BLAKE2s of the domain separator and the key's canonical encoding.
    pub const fn digest(&self) -> &Hash {
        &self.digest
    }
    /// The committed table's Merkle root.
    pub const fn root(&self) -> &Hash {
        &self.root
    }
    pub(crate) const fn sizes(&self) -> Sizes {
        self.sizes
    }
    pub(crate) const fn entry_pc(&self) -> u64 {
        self.entry_pc
    }
    pub(crate) fn image(&self) -> &[u64] {
        &self.image
    }
    pub(crate) fn session(&self) -> SessionId {
        SessionId::tagged(Program::SESSION_TAG, &self.digest)
    }
    pub(crate) fn zk_session(&self) -> SessionId {
        SessionId::tagged(Program::ZK_SESSION_TAG, &self.digest)
    }

    pub(crate) fn config(&self) -> Config {
        let n = (self.sizes.log_bytecode + N_TUPLE_BITS).max(crate::commitment::MIN_MU);
        Config::for_rate(n, 4).expect("a validated program commitment")
    }

    /// Verify without decoding the program or evaluating its bytecode table.
    pub fn verify(&self, output: Output, proof: &Proof) -> Result<(), VerifyError> {
        let claims = self.verify_core(output, proof)?;
        Ok(claims.check_circuits()?)
    }

    pub(crate) fn witness_core<V: OpeningVerifier<E = F192> + PublicColumns>(
        &self,
        output: Output,
        v: &mut V,
    ) -> Result<DeferredClaims, CpuError> {
        let announcement = Announcement::read(v)?;
        let layout = Layout::for_key(self, announcement.taus, ProofKind::Plain)?;
        let commitment = crate::commitment::Commitment::read(v, layout.shape, announcement.rate)?;
        let output = output.words().map(|w| F192::from(F64(w)));
        layout.verify_committed(v, &commitment, F192::from(F64(announcement.ts_final)), &output)
    }

    pub(crate) fn verify_core(&self, output: Output, proof: &Proof) -> Result<DeferredClaims, CpuError> {
        if proof.is_zero_knowledge() {
            let v = VerifierState::new(&self.zk_session(), output.words(), &proof.0);
            let (mut v, claims) = super::zero_knowledge::verify_core(self, output, v)?;
            self.verify_program(&mut v, self.root, &claims.program)?;
            v.check_eof()?;
            return Ok(claims);
        }
        let mut v = VerifierState::new(&self.session(), output.words(), &proof.0);
        let claims = self.witness_core(output, &mut v)?;
        self.verify_program(&mut v, self.root, &claims.program)?;
        v.check_eof()?;
        Ok(claims)
    }

    pub(crate) fn verify_recording(&self, output: Output, proof: &Proof) -> Result<Vec<Openings>, VerifyError> {
        let session = if proof.is_zero_knowledge() {
            self.zk_session()
        } else {
            self.session()
        };
        let mut v = Recording::new(VerifierState::new(&session, output.words(), &proof.0));
        let claims = if proof.is_zero_knowledge() {
            let (inner, claims) = super::zero_knowledge::verify_core(self, output, v)?;
            v = inner;
            claims
        } else {
            self.witness_core(output, &mut v)?
        };
        self.verify_program(&mut v, self.root, &claims.program)?;
        v.check_eof().map_err(CpuError::Transcript)?;
        claims.check_circuits()?;
        Ok(v.into_openings())
    }

    /// Close the bytecode terms against the key's commitment and the image term against its public words.
    #[expect(
        clippy::disallowed_methods,
        reason = "each opening value is read as a prover message before batching"
    )]
    pub(crate) fn verify_program<V: OpeningVerifier>(
        &self,
        v: &mut V,
        root: V::Root,
        claim: &Claim<ProgramPoint<V::E>, V::E>,
    ) -> Result<(), CpuError> {
        let points = self.points(v, &claim.point);
        let mut claims = Vec::new();
        let mut total = v.zero();
        for (i, (point, &mu)) in points.into_iter().zip(&claim.point.twist).enumerate() {
            let value = v.prover_message()?;
            let twisted = (0..i).fold(value, |x, _| v.square(x));
            total = v.mul_add(mu, twisted, total);
            claims.push(StackClaim::Point {
                offset: 0,
                low_point: point,
                value,
            });
        }
        let mut image_words: Vec<_> = self.image.iter().copied().map(F64).collect();
        let width = image_words.len().max(1).next_power_of_two();
        image_words.resize(width, F64::ZERO);
        let m = width.ilog2() as usize;
        let mut image = v.public_mle(&image_words, &claim.point.image_point[..m]);
        for &x in &claim.point.image_point[m..] {
            let factor = v.add_const(x, F192::ONE);
            image = v.mul(image, factor);
        }
        total = v.mul_add(claim.point.image_weight, image, total);
        v.ensure_eq(total, claim.value, || {
            CpuError::Constraint(ConstraintError::FinalMismatch)
        })?;
        let config = self.config();
        let n = (self.sizes.log_bytecode + N_TUPLE_BITS).max(crate::commitment::MIN_MU);
        let lanes = (1usize << (self.sizes.log_bytecode + N_TUPLE_BITS)).div_ceil(1 << (n - config.initial_k()));
        StackCommitment::new(root, n, lanes, config)
            .verify(
                v,
                Statement {
                    points: &claims,
                    rings: &[],
                },
            )
            .map_err(CpuError::Open)
    }

    pub(super) fn points<A: Arith>(&self, a: &mut A, point: &ProgramPoint<A::E>) -> Vec<Vec<A::E>> {
        let (chi, alpha) = point.bytecode.split_at(self.sizes.log_bytecode);
        let ladders: Vec<_> = chi.iter().map(|&x| inverse_frobenius_ladder(a, x, 1)).collect();
        (0..point.twist.len())
            .map(|i| ladders.iter().map(|l| l[i]).chain(alpha.iter().copied()).collect())
            .collect()
    }
}

impl ProgramCommitment {
    pub(super) fn new(rv: &RiscvProgram) -> Self {
        let mut words = super::Lookup::Bytecode.table(rv);
        let vars = crate::log2_strict_usize(words.len()).max(crate::commitment::MIN_MU);
        let config = Config::for_rate(vars, 4).expect("the program fits the commitment");
        let lane = 1 << (vars - config.initial_k());
        words.resize(words.len().div_ceil(lane) * lane, F64::ZERO);
        let stack = CommittedStack::new(&words, vars, config);
        Self { words, stack }
    }
    pub(super) fn root(&self) -> Hash {
        self.stack.root()
    }

    #[expect(clippy::disallowed_methods, reason = "each point value is sent before opening")]
    pub(super) fn open(&self, ps: &mut ProverState, key: &VerifyingKey, claim: &Claim<ProgramPoint>) {
        let points: Vec<_> = key
            .points(&mut Native, &claim.point)
            .into_iter()
            .map(|point| {
                let value = mle_eval_par(&self.words[..1 << point.len()], &point);
                ps.prover_message(&value);
                StackClaim::Point {
                    offset: 0,
                    low_point: point,
                    value,
                }
            })
            .collect();
        self.stack.open(
            ps,
            &self.words,
            Statement {
                points: &points,
                rings: &[],
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rv::asm::{Addi, Asm, Reg};
    use crate::{Prover, Rate};

    fn program(value: i32) -> Program {
        let text = Asm::new().i(Addi, Reg::A0, Reg::ZERO, value).exit().finish();
        Program::new(&text, Region::TEXT.base(), vec![17, 19], 2, 0).unwrap()
    }

    #[test]
    fn keys_bind_the_program_and_survive_encoding() {
        let p = program(5);
        let key = p.verifying_key();
        assert_eq!(key, program(5).verifying_key());
        assert_eq!(VerifyingKey::from_bytes(&key.to_bytes()).as_ref(), Some(key));
        let run = Prover::new(Rate::MIN).prove(&p, &[]).unwrap();
        key.verify(run.output, &run.proof).unwrap();
        assert!(program(6).verifying_key().verify(run.output, &run.proof).is_err());
        for at in [0, 40, 72] {
            let mut bytes = key.to_bytes();
            bytes[at] ^= 4;
            if let Some(forged) = VerifyingKey::from_bytes(&bytes) {
                assert!(forged.verify(run.output, &run.proof).is_err(), "key byte {at}");
            }
        }
        let mut proof = run.proof.clone();
        let last = proof.0.narg.len() - 1;
        proof.0.narg[last] ^= 1;
        assert!(key.verify(run.output, &proof).is_err());
        for len in 0..72 {
            assert!(VerifyingKey::from_bytes(&key.to_bytes()[..len]).is_none());
        }
        let mut invalid = key.to_bytes();
        invalid[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(VerifyingKey::from_bytes(&invalid).is_none());
    }
}
