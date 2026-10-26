//! Settle a mixed root's fixed-polynomial claims by PCS openings, not by evaluating the polynomials.
//!
//! A mixed tree has one fixed polynomial per tier. Each is
//! committed at [`SEAL_LOG_INV_RATE`]; built trees cache their genuine roots, and loaded trees authenticate them with the class. A root's fixed
//! claims (`W(r) = v`, read from its verified statement) are then proven by one opening per polynomial, in a
//! transcript of its own:
//!
//! - session: [`SEAL_DOMAIN`] and the authenticated class-key digest for mixed trees;
//!   the tree's session tag and commitment roots for same-program trees;
//! - instance: the root statement and a hash of the complete root proof;
//! - prefix: every root fixed-column evaluation in canonical column order.
//!
//! So the claims are bound before the opening's challenges, and the verifier builds them from the root it verified,
//! never from the seal. The opening of a public polynomial at a public point needs no witness: anyone holding the
//! class's polynomials can make it.

use super::*;
use fiat_shamir::{LengthPrefixed, ProofTranscript, ProverState, SessionId, VerifierState};
use pcs::merkle::Hash;
use pcs::stack::{CommittedStack, StackClaim, StackCommitment, Statement};
use pcs::whir::Config;

/// The seal transcript's domain.
const SEAL_DOMAIN: &[u8] = b"leanvm/mixed-tree-seal/v3";

/// The rate the fixed polynomials are committed at, a base-two logarithm: lower than the trees' own rate keeps the
/// prover's codeword small, higher would shorten the opening.
pub const SEAL_LOG_INV_RATE: usize = 2;

/// A committed fixed polynomial's stack: its size, its configuration and how many lane blocks are committed.
fn stack_shape(len: usize) -> Result<(usize, Config, usize), TreeError> {
    let log_n = crate::log2_strict_usize(len).max(crate::commitment::MIN_MU);
    let config = Config::for_rate(log_n, SEAL_LOG_INV_RATE).map_err(|_| TreeError::TooLarge)?;
    let lane = 1usize << (log_n - config.initial_k());
    Ok((log_n, config, len.div_ceil(lane)))
}

/// The complete root proof is bound before hinted fixed values and PCS challenges.
/// Its bus points depend on its transcript, so binding only the statement is insufficient.
fn instance(root: &TreeProof) -> Vec<u64> {
    let digest = primitives::hash::hash(&root.to_bytes());
    root.limbs()
        .as_flattened()
        .iter()
        .copied()
        .chain(primitives::hash::digest_words(&digest))
        .collect()
}

/// The roots of a mixed class's committed fixed polynomials, in tier order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealRoots(pub Vec<Hash>);

/// A prover's commitments to a mixed class's fixed polynomials.
pub struct SealProver {
    /// Each committed polynomial, its padded words and its stack.
    stacks: Vec<(DensePoly, Vec<F64>, CommittedStack)>,
}

impl SealProver {
    /// The commitment roots, to authenticate with the class.
    #[must_use]
    pub fn roots(&self) -> SealRoots {
        SealRoots(self.stacks.iter().map(|(_, _, s)| s.root()).collect())
    }
}

/// The seal's session binds the class key, or the same-program tree's session tag and roots.
fn session(tree: &Tree<'_>, roots: &SealRoots) -> Result<SessionId, TreeError> {
    tree.check_seal_roots(roots)?;
    if tree.design.mixed {
        return Ok(SessionId::tagged(SEAL_DOMAIN, &tree.class_key_digest_for(roots)?));
    }
    let mut tag = tree.design.session_tag(SEAL_DOMAIN);
    for root in &roots.0 {
        tag.extend_from_slice(root);
    }
    Ok(SessionId::new(&tag))
}

impl Tree<'_> {
    /// Commit this tree's fixed polynomials, once, for sealing roots.
    ///
    /// # Errors
    ///
    /// A polynomial too large to commit.
    pub fn seal_prover(&self) -> Result<SealProver, TreeError> {
        self.require_prover()?;
        let prover = self.seal_prover_over(&self.tables)?;
        let _ = self.fixed_roots.set(prover.roots());
        Ok(prover)
    }

    pub(super) fn check_seal_roots(&self, roots: &SealRoots) -> Result<(), TreeError> {
        let expected = if self.verifier_only {
            &self
                .class_key
                .get()
                .expect("loaded trees have an authenticated class key")
                .0
        } else {
            if self.fixed_roots.get().is_none() {
                self.seal_prover()?;
            }
            self.fixed_roots.get().expect("seal_prover caches the genuine roots")
        };
        if roots != expected {
            return Err(TreeError::SealRoots);
        }
        Ok(())
    }

    /// Commitments to the fixed polynomials of `tables`, which a test may forge.
    pub(super) fn seal_prover_over(&self, tables: &DenseTables) -> Result<SealProver, TreeError> {
        self.require_prover()?;
        let _span = info_span!("seal commitments").entered();
        let stacks = (self.design.statement.polys().filter(|p| p.is_fixed()))
            .map(|poly| {
                let mut words = tables.0[poly.index()].clone();
                let (log_n, config, lanes) = stack_shape(words.len())?;
                words.resize(lanes << (log_n - config.initial_k()), F64::ZERO);
                let stack = CommittedStack::new(&words, log_n, config);
                Ok((poly, words, stack))
            })
            .collect::<Result<_, TreeError>>()?;
        Ok(SealProver { stacks })
    }

    /// The seal of a root: one opening per used tier, including the root's own columns.
    ///
    /// # Errors
    ///
    /// A root that is not of this tree.
    #[expect(
        clippy::disallowed_methods,
        reason = "root proof and statement are bound as the instance, values are absorbed before opening challenges"
    )]
    pub fn seal(&self, prover: &SealProver, root: &TreeProof) -> Result<ProofTranscript, TreeError> {
        self.require_prover()?;
        let _span = info_span!("seal").entered();
        let d = &self.design;
        let position = self.known(root)?;
        let evaluations = self.keys[position]
            .verify_fixed(&root.limbs(), &d.session(), d.rate, &root.proof, None)
            .map_err(|e| TreeError::Root(e.into()))?;
        let mut ps = ProverState::new(&session(self, &prover.roots())?, &LengthPrefixed(&instance(root)));
        ps.prover_message(&(evaluations.len() as u64));
        for evaluation in &evaluations {
            ps.prover_message(&evaluation.value);
        }
        for (tier, claims) in self.seal_claims(root, position, &evaluations)?.into_iter().enumerate() {
            if claims.is_empty() {
                continue;
            }
            let (_, words, stack) = &prover.stacks[tier];
            stack.open(
                &mut ps,
                words,
                Statement {
                    points: &claims,
                    rings: &[],
                },
            );
        }
        Ok(ps.proof().clone())
    }

    /// [`Tree::verify_claims`], the root's fixed-polynomial claims settled by `seal` against the class's `roots`.
    ///
    /// # Errors
    ///
    /// As [`Tree::verify_claims`], and a seal that does not open every fixed claim against `roots`.
    pub fn verify_claims_sealed(
        &self,
        root: &TreeProof,
        claims: &ClaimSet,
        roots: &SealRoots,
        seal: &ProofTranscript,
    ) -> Result<(), TreeError> {
        self.check_seal_roots(roots)?;
        let position = self.check_claims_statement(root, claims)?;
        self.settle_sealed(root, position, roots, seal)
    }

    /// [`Tree::verify`], the root's fixed-polynomial claims settled by `seal` against the tree's `roots`.
    ///
    /// # Errors
    ///
    /// As [`Tree::verify`], and a seal that does not open every fixed claim against `roots`.
    pub fn verify_sealed(
        &self,
        root: &TreeProof,
        outputs: &[Output],
        roots: &SealRoots,
        seal: &ProofTranscript,
    ) -> Result<(), TreeError> {
        self.check_seal_roots(roots)?;
        let position = self.verify_unsettled(root, outputs)?;
        self.settle_sealed(root, position, roots, seal)
    }

    /// Settle a verified root's claims: the fixed polynomials' by `seal`, every other as [`Tree::settle`] does.
    #[expect(
        clippy::disallowed_methods,
        reason = "every claim is constructed from the verified root statement, bound as the instance before challenges"
    )]
    fn settle_sealed(
        &self,
        root: &TreeProof,
        position: usize,
        roots: &SealRoots,
        seal: &ProofTranscript,
    ) -> Result<(), TreeError> {
        let d = &self.design;
        let statement = root.statement(d.statement);
        let session = session(self, roots)?;
        let mut v = VerifierState::new(&session, &LengthPrefixed(&instance(root)), seal);
        let count: u64 = v.prover_message().map_err(|_| TreeError::MixedClass)?;
        // Exactly one value per fixed column, in column-index order; no allocation from an untrusted count.
        if count != crate::rec::fixed::FixedColumn::COUNT as u64 {
            return Err(TreeError::MixedClass);
        }
        let values = (0..count)
            .map(|_| v.prover_message())
            .collect::<Result<Vec<F192>, _>>()
            .map_err(|_| TreeError::MixedClass)?;
        let evaluations = self.keys[position]
            .verify_fixed(&root.limbs(), &d.session(), d.rate, &root.proof, Some(&values))
            .map_err(|e| TreeError::Root(e.into()))?;
        self.settle_with(&statement, position, false)?;
        for (tier, claims) in self.seal_claims(root, position, &evaluations)?.into_iter().enumerate() {
            if claims.is_empty() {
                continue;
            }
            let poly = DensePoly::at(2 + tier);
            let (log_n, config, lanes) = stack_shape(1 << d.vars.0[poly.index()])?;
            StackCommitment::new(roots.0[tier], log_n, lanes, config)
                .verify(
                    &mut v,
                    Statement {
                        points: &claims,
                        rings: &[],
                    },
                )
                .map_err(|_| TreeError::Claim(FalseClaim::Dense(poly)))?;
        }
        v.check_eof().map_err(|_| TreeError::MixedClass)?;
        Ok(())
    }

    /// The opening set is computed from the verified statement, never from a seal bitmap.
    /// A zero usage bit means every carried term's scale was zero in the verified circuit;
    /// the published evaluation is canonically zero. Fresh child-column claims set their
    /// tier's bit unconditionally. OR propagation prevents a used tier disappearing.
    /// The root's own columns are also opened, irrespective of its carried usage bits.
    fn seal_claims(
        &self,
        root: &TreeProof,
        position: usize,
        evaluations: &[crate::rec::proof::FixedEvaluation],
    ) -> Result<Vec<Vec<StackClaim>>, TreeError> {
        let d = &self.design;
        let statement = root.statement(d.statement);
        let mut claims = vec![Vec::new(); d.tiers.len()];
        for (tier, out) in claims.iter_mut().enumerate() {
            let used = statement.usage(tier);
            let poly = DensePoly::at(2 + tier);
            if used == F192::ONE {
                out.push(StackClaim::Point {
                    offset: 0,
                    low_point: statement.dense_point()[..d.vars.0[poly.index()]].to_vec(),
                    value: statement.dense_value(poly),
                });
            } else if used != F192::ZERO || statement.dense_value(poly) != F192::ZERO {
                return Err(TreeError::MixedClass);
            }
        }
        let tier = d.places[position].tier;
        let layout = &d.tiers[tier].fixed;
        let local = position - d.tiers[tier].places.start;
        for e in evaluations {
            let offset = (local << layout.kappa()) + (layout.block(e.column) << layout.tau(e.column));
            claims[tier].push(StackClaim::Point {
                offset,
                low_point: e.point.clone(),
                value: e.value,
            });
        }
        Ok(claims)
    }
}
