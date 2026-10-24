//! Program classes and claim-set trees whose first-level circuits take a verifying key as witness.

use super::*;
use crate::cpu::layout::Sizes;
use crate::rec::circuit::{Builder, Dw, Kw, PARAM_IV};
use crate::rv::asm::{Asm, Reg};
use crate::{ProgramError, Prover, Region, VerifyingKey};

/// Public bounds shared by every leaf program of one mixed tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramClass {
    /// The padded decoded bytecode dimension.
    pub log_bytecode: usize,
    /// The RAM dimension.
    pub log_ram: usize,
    /// The advice dimension.
    pub log_advice: usize,
    /// The padded image length, a nonzero power of two.
    pub image_words: usize,
}

/// A proof of an individual statement, identified by its program key.
#[derive(Clone, Copy)]
pub struct MixedLeaf<'a> {
    /// The program's verifying key.
    pub key: &'a VerifyingKey,
    /// The proof of a run.
    pub proof: &'a Proof,
    /// The output the run claims.
    pub output: Output,
}

impl ProgramClass {
    /// Normalize a smaller program and image to this class before proving it.
    pub fn normalize(self, program: &Program) -> Result<Program, ProgramError> {
        if !self.image_words.is_power_of_two() {
            return Err(ProgramError::RamSize);
        }
        program.padded(self.log_bytecode, self.log_ram, self.log_advice, self.image_words)
    }

    /// A prover padding each table to at least the supplied leaf shape.
    pub fn prover(self, shape: LeafShape) -> Prover {
        Prover::new(shape.rate()).with_floor(shape.taus().map(|height| 1 << height))
    }

    fn accepts(self, key: &VerifyingKey) -> bool {
        key.sizes()
            == Sizes {
                log_bytecode: self.log_bytecode,
                log_ram: self.log_ram,
                log_advice: self.log_advice,
            }
            && key.image().len() == self.image_words
    }
}

impl MixedLeaf<'_> {
    /// The singleton claim this leaf publishes: the VK digest labels its output.
    pub fn claims(self) -> ClaimSet {
        let [a, b, c, d] = primitives::hash::digest_words(self.key.digest());
        ClaimSet {
            groups: vec![ClaimGroup {
                label: [a, b, c, d, 0, 0],
                members: vec![*self.output.words()],
            }],
        }
    }
}

impl Tree<'static> {
    /// Build a mixed-program claim-set tree from class data alone.
    ///
    /// Zero-knowledge leaves are refused in this mode; same-program trees retain their zero-knowledge support.
    pub fn mixed(class: ProgramClass, shape: TreeShape) -> Result<Self, TreeError> {
        if shape.claims.is_none() || shape.leaf.is_zero_knowledge() {
            return Err(TreeError::MixedClass);
        }
        Self::build(&Self::mixed_placeholder(class)?, shape, true)
    }

    /// The class's placeholder program, which fixes a mixed tree's layout and session.
    pub(super) fn mixed_placeholder(class: ProgramClass) -> Result<Program, TreeError> {
        let text = Asm::new().li(Reg::A0, 0).exit().finish();
        let placeholder = Program::new(&text, Region::TEXT.base(), vec![], 0, 0).map_err(|_| TreeError::MixedClass)?;
        class.normalize(&placeholder).map_err(|_| TreeError::MixedClass)
    }

    /// The class's placeholder rebuilt from its commitment's root, without encoding the program again.
    pub(super) fn mixed_placeholder_with_root(
        class: ProgramClass,
        root: pcs::merkle::Hash,
    ) -> Result<Program, TreeError> {
        if !class.image_words.is_power_of_two() {
            return Err(TreeError::MixedClass);
        }
        let text = Asm::new().li(Reg::A0, 0).exit().finish();
        let placeholder =
            Program::uncommitted(&text, Region::TEXT.base(), vec![], 0, 0).map_err(|_| TreeError::MixedClass)?;
        (placeholder.padded_with_root(
            class.log_bytecode,
            class.log_ram,
            class.log_advice,
            class.image_words,
            root,
        ))
        .map_err(|_| TreeError::MixedClass)
    }
}

impl Tree<'_> {
    /// Aggregate individual program statements, declaring their union or a subset.
    pub fn aggregate_programs(
        &self,
        leaves: &[MixedLeaf<'_>],
        declare: Option<&ClaimSet>,
    ) -> Result<Aggregate, TreeError> {
        self.require_prover()?;
        if !self.design.mixed {
            return Err(TreeError::MixedClass);
        }
        if leaves.len() != self.design.arity_0 {
            return Err(TreeError::Children {
                expected: self.design.arity_0,
                got: leaves.len(),
            });
        }
        let key = self.design.leaf.program().verifying_key();
        let sizes = key.sizes();
        let class = ProgramClass {
            log_bytecode: sizes.log_bytecode,
            log_ram: sizes.log_ram,
            log_advice: sizes.log_advice,
            image_words: key.image().len(),
        };
        let sets: Vec<_> = leaves.iter().map(|l| l.claims()).collect();
        let mut items = Vec::new();
        for (index, leaf) in leaves.iter().enumerate() {
            if !class.accepts(leaf.key) || LeafShape::announced(leaf.proof) != Some(self.shape.leaf) {
                return Err(TreeError::ForeignLeaf { index });
            }
            let openings = leaf
                .key
                .verify_recording(leaf.output, leaf.proof)
                .map_err(|error| TreeError::Leaf { index, error })?;
            items.push(LeafWitness {
                key: Some(leaf.key),
                proof: &leaf.proof.0,
                openings,
                output: *leaf.output.words(),
                set: sets[index].digest(),
            });
        }
        let refs: Vec<_> = sets.iter().collect();
        let (union, claims) = self.fill(0, &refs, declare)?;
        let inputs = NodeInputs::Prove {
            items: &items,
            tables: &self.tables,
            union: Some(&union),
        };
        let rows = self.design.first_rows(&inputs);
        Ok(Aggregate {
            proof: self.prove_rows(rows)?,
            claims,
        })
    }
}

pub(super) fn singleton_rows(b: &mut Builder, digest: Dw, output: [Kw; 4]) -> Dw {
    let [d0, d1, d2, d3] = b.d_to_k(digest);
    let zero = b.k_const(0);
    let iv = b.d_const(PARAM_IV);
    let header = b.leaf_block(
        iv,
        [d0, d1, d2, d3, zero, zero, zero, zero],
        multiset::code::START,
        false,
    );
    let members = b.leaf_block(
        header,
        [output[0], output[1], output[2], output[3], zero, zero, zero, zero],
        multiset::code::MEMBER,
        false,
    );
    let tag = b.k_const(multiset::code::TAG);
    b.leaf_block(
        members,
        [tag, zero, zero, zero, zero, zero, zero, zero],
        multiset::code::END,
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rec::circuit::Finished;
    use crate::rv::asm::Ld;
    use crate::tables::TableId;
    use std::sync::OnceLock;
    use zk::Randomness;

    struct Fixture {
        tree: Tree<'static>,
        programs: [Program; 2],
        runs: [ProvenRun; 2],
        class: ProgramClass,
        shape: TreeShape,
    }

    fn fixture() -> &'static Fixture {
        static F: OnceLock<Fixture> = OnceLock::new();
        F.get_or_init(|| {
            let a = Program::from_elf(include_bytes!("../../../../../programs/fibonacci/fibonacci.elf")).unwrap();
            let b = Program::from_elf(include_bytes!("../../../../../programs/preimage/preimage.elf")).unwrap();
            let class = ProgramClass {
                log_bytecode: a.rv().entries().len().max(b.rv().entries().len()).ilog2() as usize,
                log_ram: a.rv().log_ram().max(b.rv().log_ram()),
                log_advice: a.rv().log_advice().max(b.rv().log_advice()),
                image_words: a.rv().image().len().max(b.rv().image().len()).next_power_of_two(),
            };
            let programs = [class.normalize(&a).unwrap(), class.normalize(&b).unwrap()];
            let mut stats = programs[0].measure(&[2700]).unwrap();
            let other = programs[1].measure(&[0]).unwrap();
            stats.counts = crate::tables::PerTable::from_fn(|t| stats.counts[t].max(other.counts[t]));
            stats.counts[TableId::ALU] *= 2;
            let leaf = LeafShape::measured(&stats, Rate::MIN);
            let prover = class.prover(leaf);
            let runs = [
                prover.prove(&programs[0], &[2700]).unwrap(),
                prover.prove(&programs[1], &[0]).unwrap(),
            ];
            assert_eq!(LeafShape::of(&runs[0].proof).unwrap(), leaf);
            assert_eq!(LeafShape::of(&runs[1].proof).unwrap(), leaf);
            let shape = TreeShape {
                leaf,
                arity_0: 2,
                arity: 2,
                rate: Rate::MIN,
                claims: Some(ClaimShape {
                    capacity: Capacity { claims: 8, groups: 4 },
                    small: None,
                }),
            };
            let tree = Tree::mixed(class, shape).unwrap();
            Fixture {
                tree,
                programs,
                runs,
                class,
                shape,
            }
        })
    }

    impl Fixture {
        fn leaves(&self) -> [MixedLeaf<'_>; 2] {
            std::array::from_fn(|i| MixedLeaf {
                key: self.programs[i].verifying_key(),
                proof: &self.runs[i].proof,
                output: self.runs[i].output,
            })
        }
    }

    #[test]
    fn two_tier_mixed_roots_and_fake_large_wrap() {
        let f = fixture();
        let mut shape = f.shape;
        shape.arity = 3;
        shape.claims = Some(ClaimShape {
            capacity: Capacity { claims: 24, groups: 8 },
            small: Some(Tier {
                arity: 2,
                capacity: Capacity { claims: 8, groups: 4 },
            }),
        });
        let tree = Tree::mixed(f.class, shape).unwrap();
        let first = tree.aggregate_programs(&f.leaves(), None).unwrap();
        let large = tree.aggregate(&[&first, &first, &first], None).unwrap();
        let subset = f.leaves()[0].claims();
        let wrap = tree.wrap(0, &large).unwrap();
        assert_eq!(tree.design.places[tree.known(&wrap.proof).unwrap()].level, Level::Wrap);
        let narrowed = tree.aggregate(&[&large], Some(&subset)).unwrap();
        let prover = tree.seal_prover().unwrap();
        let roots = prover.roots();
        assert_eq!(roots.0.len(), 2);
        let bytes = tree.mixed_verifier_bytes(&roots).unwrap();
        let digest = Tree::mixed_class_key_digest(&bytes);
        let loaded = Tree::mixed_from_bytes(f.class, shape, &bytes, &digest).unwrap();
        let trusted = Tree::mixed_from_trusted_bytes(f.class, shape, &bytes, &digest).unwrap();
        let mut wrong_digest = digest;
        wrong_digest[0] ^= 1;
        let wrong_session = Tree::mixed_from_trusted_bytes(f.class, shape, &bytes, &wrong_digest).unwrap();
        for (index, root) in [&first, &large, &wrap, &narrowed].into_iter().enumerate() {
            let seal = tree.seal(&prover, &root.proof).unwrap();
            wrong_session.verify_claims(&root.proof, &root.claims).unwrap();
            let result = wrong_session.verify_claims_sealed(&root.proof, &root.claims, &roots, &seal);
            if index == 0 {
                assert!(seal.narg.is_empty());
                result.unwrap();
            } else {
                assert!(!seal.narg.is_empty(), "node and wrap roots carry fixed claims");
                assert!(result.is_err(), "a wrong digest must refuse the node or wrap seal");
            }
            for verifier in [&tree, &loaded, &trusted] {
                verifier.verify_claims(&root.proof, &root.claims).unwrap();
                verifier
                    .verify_claims_sealed(&root.proof, &root.claims, &roots, &seal)
                    .unwrap();
            }
        }
        let mut forged = subset;
        forged.groups[0].members[0][0] ^= 1;
        super::super::tests::claim_sets::assert_fake_large_wrap_refused(&tree, &large, &forged);
    }

    #[test]
    fn mixed_verifier_refuses_other_modes_and_classes_direct_and_sealed() {
        let f = fixture();
        let receiver_roots = f.tree.seal_prover().unwrap().roots();
        let mut output_shape = f.shape;
        output_shape.claims = None;
        let outputs = Tree::new(&f.programs[0], output_shape).unwrap();
        let leaf = Leaf::new(&f.runs[0].proof, f.runs[0].output);
        let output_root = outputs.prove_first(&[leaf, leaf]).unwrap();
        outputs
            .verify(&output_root, &[f.runs[0].output, f.runs[0].output])
            .unwrap();
        let output_sealer = outputs.seal_prover().unwrap();
        let output_seal = outputs.seal(&output_sealer, &output_root).unwrap();
        assert!(f.tree.verify_claims(&output_root, &f.leaves()[0].claims()).is_err());
        assert!(
            f.tree
                .verify_claims_sealed(&output_root, &f.leaves()[0].claims(), &receiver_roots, &output_seal)
                .is_err()
        );

        let set = f.leaves()[0].claims();
        let text = Asm::new()
            .li(Reg::T0, Region::ADVICE.base())
            .load(Ld, Reg::A0, 0, Reg::T0)
            .load(Ld, Reg::A1, 8, Reg::T0)
            .load(Ld, Reg::A2, 16, Reg::T0)
            .load(Ld, Reg::A3, 24, Reg::T0)
            .exit()
            .finish();
        let p = Program::new(&text, Region::TEXT.base(), vec![], 0, 2).unwrap();
        let p = f.class.normalize(&p).unwrap();
        let run = f.class.prover(f.shape.leaf).prove(&p, &chain(&set.digest())).unwrap();
        let guest = Tree::new(&p, f.shape).unwrap();
        let leaf = ClaimLeaf::new(Leaf::new(&run.proof, run.output), &set);
        let root = guest.aggregate_leaves(&[leaf, leaf], None).unwrap();
        guest.verify_claims(&root.proof, &root.claims).unwrap();
        let sealer = guest.seal_prover().unwrap();
        let seal = guest.seal(&sealer, &root.proof).unwrap();
        guest
            .verify_claims_sealed(&root.proof, &root.claims, &sealer.roots(), &seal)
            .unwrap();
        assert!(f.tree.verify_claims(&root.proof, &root.claims).is_err());
        assert!(
            f.tree
                .verify_claims_sealed(&root.proof, &root.claims, &receiver_roots, &seal)
                .is_err()
        );

        let mut class = f.class;
        class.log_advice += 1;
        let other = Tree::mixed(class, f.shape).unwrap();
        let p = class.normalize(&f.programs[0]).unwrap();
        let run = class.prover(f.shape.leaf).prove(&p, &[2700]).unwrap();
        let leaf = MixedLeaf {
            key: p.verifying_key(),
            proof: &run.proof,
            output: run.output,
        };
        let root = other.aggregate_programs(&[leaf, leaf], None).unwrap();
        other.verify_claims(&root.proof, &root.claims).unwrap();
        let sealer = other.seal_prover().unwrap();
        let seal = other.seal(&sealer, &root.proof).unwrap();
        other
            .verify_claims_sealed(&root.proof, &root.claims, &sealer.roots(), &seal)
            .unwrap();
        assert!(f.tree.verify_claims(&root.proof, &root.claims).is_err());
        assert!(
            f.tree
                .verify_claims_sealed(&root.proof, &root.claims, &receiver_roots, &seal)
                .is_err()
        );
    }

    #[test]
    fn mixed_entry_rows_refuse_alignment_range_and_halt_without_decoding() {
        let f = fixture();
        let key = f.programs[0].verifying_key();
        let run = &f.runs[0];
        let openings = key.verify_recording(run.output, &run.proof).unwrap();
        let halt = Region::TEXT.address((1 << f.class.log_bytecode) - 1);
        for entry in [
            key.entry_pc(),
            key.entry_pc() + 1,
            Region::TEXT.base() - 4,
            Region::TEXT.address(1 << f.class.log_bytecode),
            halt,
        ] {
            let key = key.with_unchecked_entry(entry);
            let mut b = Builder::new();
            let output = run.output.words().map(|w| b.free_k(w));
            f.tree
                .design
                .leaf
                .verify_mixed(&mut b, output, ProofSource::Proof(&run.proof.0, &openings), Some(&key));
            let failures = b.finish().failures;
            if entry == f.programs[0].verifying_key().entry_pc() {
                assert!(failures.is_empty());
            } else {
                assert!(
                    failures.iter().any(|f| f.scope().first().is_some_and(|s| s == "entry")),
                    "entry {entry:#x}: {failures:?}"
                );
            }
        }
    }

    #[test]
    fn mixed_union_rows_refuse_uncovered_and_swapped_claims() {
        let f = fixture();
        let leaves = f.leaves();
        let sets: Vec<_> = leaves.iter().map(|l| l.claims()).collect();
        let refs: Vec<_> = sets.iter().collect();
        let items: Vec<_> = leaves
            .iter()
            .zip(&sets)
            .map(|(leaf, set)| LeafWitness {
                key: Some(leaf.key),
                proof: &leaf.proof.0,
                openings: leaf.key.verify_recording(leaf.output, leaf.proof).unwrap(),
                output: *leaf.output.words(),
                set: set.digest(),
            })
            .collect();
        let shape = f.tree.design.union_shape(0).unwrap();
        let honest = ClaimSet::from_claims(sets.iter().flat_map(ClaimSet::claims));
        let mut uncovered = sets[0].clone();
        uncovered.groups[0].label[0] ^= 1;
        let mut swapped = sets[0].clone();
        swapped.groups[0].members[0] = *leaves[1].output.words();
        for (declared, good) in [(&honest, true), (&uncovered, false), (&swapped, false)] {
            let fill = super::super::union::tests::unbacked(&shape, &refs, declared);
            let rows = f.tree.design.first_rows(&NodeInputs::Prove {
                items: &items,
                tables: &f.tree.tables,
                union: Some(&fill),
            });
            let reduction = rows
                .claim_values()
                .prove(&f.tree.design.session(), &f.tree.design.vars, &f.tree.tables);
            let result = rows.reduce(&f.tree.design, ProofSource::Proof(&reduction, &[]));
            assert_eq!(result.failures.is_empty(), good, "{:#?}", result.failures);
        }
    }

    #[test]
    fn class_keys_authenticate_shape_columns_and_seal_roots() {
        let f = fixture();
        let roots = f.tree.seal_prover().unwrap().roots();
        let bytes = f.tree.mixed_verifier_bytes(&roots).unwrap();
        let pin = Tree::mixed_class_key_digest(&bytes);
        let loaded = Tree::mixed_from_bytes(f.class, f.shape, &bytes, &pin).unwrap();
        assert_eq!(loaded.mixed_verifier_bytes(&roots).unwrap(), bytes);
        let mut other_class = f.class;
        other_class.log_advice += 1;
        assert!(Tree::mixed_from_bytes(other_class, f.shape, &bytes, &pin).is_err());
        assert!(Tree::mixed_from_trusted_bytes(other_class, f.shape, &bytes, &pin).is_err());
        let mut other_shape = f.shape;
        other_shape.arity += 1;
        assert!(Tree::mixed_from_bytes(f.class, other_shape, &bytes, &pin).is_err());
        assert!(Tree::mixed_from_trusted_bytes(f.class, other_shape, &bytes, &pin).is_err());
        for at in [8, bytes.len() / 2, bytes.len() - 1] {
            let mut bad = bytes.clone();
            bad[at] ^= 1;
            assert!(matches!(
                Tree::mixed_from_bytes(f.class, f.shape, &bad, &pin),
                Err(TreeError::ClassKeyDigest)
            ));
        }
        // Re-pin malformed encodings to exercise the parser rather than only authentication.
        let header = 8 + (4 + crate::N_TABLES + 7 + 1) * 8;
        let tier_count = header + 8 + 32 + 32;
        let tier_heights = tier_count + 8;
        let key_count = tier_heights + Table::ALL.len() * 8;
        let column_count = key_count + 8 + 8 + Table::ALL.len() * 8;
        for at in [
            header,
            tier_count,
            tier_heights,
            key_count,
            column_count,
            column_count + 8,
        ] {
            let mut bad = bytes.clone();
            bad[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            let result = std::panic::catch_unwind(|| {
                Tree::mixed_from_bytes(f.class, f.shape, &bad, &Tree::mixed_class_key_digest(&bad))
            });
            assert!(result.is_ok_and(|r| r.is_err()), "malformed word at {at}");
            let result = std::panic::catch_unwind(|| Tree::mixed_from_trusted_bytes(f.class, f.shape, &bad, &pin));
            assert!(result.is_ok_and(|r| r.is_err()), "trusted malformed word at {at}");
        }
        for end in [0, 7, 8, header, column_count, bytes.len() - 1] {
            let short = &bytes[..end];
            assert!(Tree::mixed_from_trusted_bytes(f.class, f.shape, short, &pin).is_err());
            assert!(Tree::mixed_from_bytes(f.class, f.shape, short, &Tree::mixed_class_key_digest(short)).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Tree::mixed_from_trusted_bytes(f.class, f.shape, &trailing, &pin).is_err());
        assert!(Tree::mixed_from_bytes(f.class, f.shape, &trailing, &Tree::mixed_class_key_digest(&trailing)).is_err());
        let root = f.tree.aggregate_programs(&f.leaves(), None).unwrap();
        let sealer = f.tree.seal_prover().unwrap();
        let seal = f.tree.seal(&sealer, &root.proof).unwrap();
        loaded.verify_claims(&root.proof, &root.claims).unwrap();
        loaded
            .verify_claims_sealed(&root.proof, &root.claims, &roots, &seal)
            .unwrap();
        let mut wrong_roots = roots;
        wrong_roots.0[0][0] ^= 1;
        assert!(
            loaded
                .verify_claims_sealed(&root.proof, &root.claims, &wrong_roots, &seal)
                .is_err()
        );
    }

    #[test]
    fn trusted_loader_agrees_with_checked_direct_and_sealed_verification() {
        let f = fixture();
        let sealer = f.tree.seal_prover().unwrap();
        let roots = sealer.roots();
        let bytes = f.tree.mixed_verifier_bytes(&roots).unwrap();
        let digest = Tree::mixed_class_key_digest(&bytes);
        let checked = Tree::mixed_from_bytes(f.class, f.shape, &bytes, &digest).unwrap();
        let trusted = Tree::mixed_from_trusted_bytes(f.class, f.shape, &bytes, &digest).unwrap();
        assert_eq!(checked.seal_roots(), trusted.seal_roots());
        assert_eq!(trusted.mixed_verifier_bytes(&roots).unwrap(), bytes);
        let first = f.tree.aggregate_programs(&f.leaves(), None).unwrap();
        let node = f.tree.aggregate(&[&first, &first], None).unwrap();
        for root in [&first, &node] {
            let seal = f.tree.seal(&sealer, &root.proof).unwrap();
            let mut wrong_claims = root.claims.clone();
            wrong_claims.groups[0].members[0][0] ^= 1;
            let mut bad_proof = root.proof.clone();
            bad_proof.words[1] += F192::ONE;
            let mut bad_seal = seal.clone();
            bad_seal.narg.push(0);
            let mut bad_roots = roots.clone();
            bad_roots.0[0][0] ^= 1;
            for verifier in [&checked, &trusted] {
                verifier.verify_claims(&root.proof, &root.claims).unwrap();
                verifier
                    .verify_claims_sealed(&root.proof, &root.claims, &roots, &seal)
                    .unwrap();
                assert!(verifier.verify_claims(&root.proof, &wrong_claims).is_err());
                assert!(verifier.verify_claims(&bad_proof, &root.claims).is_err());
                assert!(
                    verifier
                        .verify_claims_sealed(&root.proof, &wrong_claims, &roots, &seal)
                        .is_err()
                );
                assert!(
                    verifier
                        .verify_claims_sealed(&bad_proof, &root.claims, &roots, &seal)
                        .is_err()
                );
                assert!(
                    verifier
                        .verify_claims_sealed(&root.proof, &root.claims, &roots, &bad_seal)
                        .is_err()
                );
                assert!(
                    verifier
                        .verify_claims_sealed(&root.proof, &root.claims, &bad_roots, &seal)
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn trusted_loader_wrong_digest_rejects_node_seals_but_not_empty_first_seals() {
        let f = fixture();
        let sealer = f.tree.seal_prover().unwrap();
        let roots = sealer.roots();
        let bytes = f.tree.mixed_verifier_bytes(&roots).unwrap();
        let mut digest = Tree::mixed_class_key_digest(&bytes);
        digest[0] ^= 1;
        assert!(matches!(
            Tree::mixed_from_bytes(f.class, f.shape, &bytes, &digest),
            Err(TreeError::ClassKeyDigest)
        ));
        let trusted = Tree::mixed_from_trusted_bytes(f.class, f.shape, &bytes, &digest).unwrap();
        let first = f.tree.aggregate_programs(&f.leaves(), None).unwrap();
        // A v2 first-level seal has no opening, so no challenge-dependent check binds its session.
        let first_seal = f.tree.seal(&sealer, &first.proof).unwrap();
        assert!(first_seal.narg.is_empty() && first_seal.hints.is_empty());
        trusted
            .verify_claims_sealed(&first.proof, &first.claims, &roots, &first_seal)
            .unwrap();
        let node = f.tree.aggregate(&[&first, &first], None).unwrap();
        let seal = f.tree.seal(&sealer, &node.proof).unwrap();
        trusted.verify_claims(&node.proof, &node.claims).unwrap();
        assert!(
            trusted
                .verify_claims_sealed(&node.proof, &node.claims, &roots, &seal)
                .is_err()
        );
    }

    #[test]
    fn loaded_verifiers_refuse_every_prover_entry_point() {
        let f = fixture();
        let roots = f.tree.seal_prover().unwrap().roots();
        let bytes = f.tree.mixed_verifier_bytes(&roots).unwrap();
        let digest = Tree::mixed_class_key_digest(&bytes);
        let checked = Tree::mixed_from_bytes(f.class, f.shape, &bytes, &digest).unwrap();
        let trusted = Tree::mixed_from_trusted_bytes(f.class, f.shape, &bytes, &digest).unwrap();
        let aggregate = f.tree.aggregate_programs(&f.leaves(), None).unwrap();
        let prover = f.tree.seal_prover().unwrap();
        for tree in [&checked, &trusted] {
            assert!(matches!(tree.prove(&[]), Err(TreeError::VerifierOnly)));
            assert!(matches!(tree.prove_first(&[]), Err(TreeError::VerifierOnly)));
            assert!(matches!(tree.prove_node(&[]), Err(TreeError::VerifierOnly)));
            assert!(matches!(tree.aggregate(&[], None), Err(TreeError::VerifierOnly)));
            assert!(matches!(tree.aggregate_leaves(&[], None), Err(TreeError::VerifierOnly)));
            assert!(matches!(
                tree.aggregate_programs(&[], None),
                Err(TreeError::VerifierOnly)
            ));
            assert!(matches!(tree.seal_prover(), Err(TreeError::VerifierOnly)));
            assert!(matches!(
                tree.seal(&prover, &aggregate.proof),
                Err(TreeError::VerifierOnly)
            ));
            assert!(matches!(
                Prover::new(Rate::MIN).prove(tree.design.leaf.program(), &[]),
                Err(crate::ProveError::VerifierOnly)
            ));
            assert!(matches!(
                Prover::new(Rate::MIN)
                    .zero_knowledge(Randomness::Fixed([0; 32]))
                    .prove(tree.design.leaf.program(), &[]),
                Err(crate::ProveError::VerifierOnly)
            ));
        }
    }

    #[test]
    fn sealed_roots_agree_with_direct_settlement_and_bind_their_inputs() {
        let f = fixture();
        let prover = f.tree.seal_prover().unwrap();
        let roots = prover.roots();
        assert_eq!(roots.0.len(), 1, "one tier: Fixed only");
        let first = f.tree.aggregate_programs(&f.leaves(), None).unwrap();
        let node = f.tree.aggregate(&[&first, &first], None).unwrap();
        for a in [&first, &node] {
            f.tree.verify_claims(&a.proof, &a.claims).unwrap();
            let seal = f.tree.seal(&prover, &a.proof).unwrap();
            f.tree.verify_claims_sealed(&a.proof, &a.claims, &roots, &seal).unwrap();
        }
        let node_seal = f.tree.seal(&prover, &node.proof).unwrap();
        assert!(!node_seal.narg.is_empty(), "a node root has a fixed claim to open");

        // Other roots, another root's seal, a truncated or altered seal: all refused.
        let mut other = roots.clone();
        other.0[0][0] ^= 1;
        assert!(
            f.tree
                .verify_claims_sealed(&node.proof, &node.claims, &other, &node_seal)
                .is_err()
        );
        let first_seal = f.tree.seal(&prover, &first.proof).unwrap();
        assert!(
            f.tree
                .verify_claims_sealed(&node.proof, &node.claims, &roots, &first_seal)
                .is_err()
        );
        let mut short = node_seal.clone();
        short.narg.truncate(short.narg.len() - 1);
        assert!(
            f.tree
                .verify_claims_sealed(&node.proof, &node.claims, &roots, &short)
                .is_err()
        );
        for at in [0, node_seal.narg.len() / 2, node_seal.narg.len() - 1] {
            let mut bad = node_seal.clone();
            bad.narg[at] ^= 1;
            assert!(
                f.tree
                    .verify_claims_sealed(&node.proof, &node.claims, &roots, &bad)
                    .is_err(),
                "byte {at}"
            );
        }
        assert!(
            f.tree
                .verify_claims_sealed(&node.proof, &node.claims, &SealRoots(vec![]), &node_seal)
                .is_err()
        );
    }

    #[test]
    fn mixed_guests_union_discard_and_keep_class_fixed_keys() {
        let f = fixture();
        let aggregate = f.tree.aggregate_programs(&f.leaves(), None).unwrap();
        f.tree.verify_claims(&aggregate.proof, &aggregate.claims).unwrap();
        let copy = Tree::mixed(f.class, f.shape).unwrap();
        assert_eq!(f.tree.design.session(), copy.design.session());
        for (a, b) in f.tree.keys.iter().zip(&copy.keys) {
            assert!(a.circuit() == b.circuit());
        }
        copy.verify_claims(&aggregate.proof, &aggregate.claims).unwrap();
        let part = f.leaves()[0].claims();
        let narrowed = f.tree.aggregate(&[&aggregate], Some(&part)).unwrap();
        f.tree.verify_claims(&narrowed.proof, &part).unwrap();
        assert!(f.tree.verify_claims(&narrowed.proof, &aggregate.claims).is_err());
        assert!(f.tree.aggregate(&[&narrowed], Some(&aggregate.claims)).is_err());
        assert!(f.tree.verify_claims(&aggregate.proof, &ClaimSet::default()).is_err());
    }

    #[test]
    fn a_non_default_entry_is_bound_in_rows() {
        let f = fixture();
        let text = Asm::new().li(Reg::A0, 9).li(Reg::A0, 5).exit().finish();
        let p = Program::new(&text, Region::TEXT.address(1), vec![], 0, 0).unwrap();
        let p = f.class.normalize(&p).unwrap();
        let run = f.class.prover(f.shape.leaf).prove(&p, &[]).unwrap();
        let openings = p.verifying_key().verify_recording(run.output, &run.proof).unwrap();
        let mut b = Builder::new();
        let output = run.output.words().map(|w| b.free_k(w));
        f.tree.design.leaf.verify_mixed(
            &mut b,
            output,
            ProofSource::Proof(&run.proof.0, &openings),
            Some(p.verifying_key()),
        );
        assert!(b.finish().failures.is_empty());
    }

    #[test]
    fn wrong_keys_outputs_and_uncovered_claims_are_refused() {
        let f = fixture();
        let mut leaves = f.leaves();
        leaves[0].output = f.runs[1].output;
        assert!(f.tree.aggregate_programs(&leaves, None).is_err());
        let mut leaves = f.leaves();
        leaves[0].key = leaves[1].key;
        assert!(f.tree.aggregate_programs(&leaves, None).is_err());
        let leaves = f.leaves();
        let mut uncovered = leaves[0].claims();
        uncovered.groups[0].label[0] ^= 1;
        assert!(f.tree.aggregate_programs(&leaves, Some(&uncovered)).is_err());
        let mut swapped = leaves[0].claims();
        swapped.groups[0].members[0] = *leaves[1].output.words();
        assert!(f.tree.aggregate_programs(&leaves, Some(&swapped)).is_err());
        for at in [0, 40, 72] {
            let mut bytes = leaves[0].key.to_bytes();
            bytes[at] ^= 4;
            let key = VerifyingKey::from_bytes(&bytes).expect("the tamper keeps valid metadata");
            let mut forged = leaves;
            forged[0].key = &key;
            assert!(f.tree.aggregate_programs(&forged, None).is_err());
        }
        let zk = TreeShape {
            leaf: f.shape.leaf.zero_knowledge(),
            ..f.shape
        };
        assert!(matches!(Tree::mixed(f.class, zk), Err(TreeError::MixedClass)));
    }

    #[test]
    fn rows_bind_dynamic_keys_without_native_prechecks() {
        let f = fixture();
        let key = f.programs[0].verifying_key();
        let output = f.runs[0].output;
        let openings = key.verify_recording(output, &f.runs[0].proof).unwrap();
        let check = |key: &VerifyingKey, output: Output| {
            let mut b = Builder::new();
            let output = output.words().map(|w| b.free_k(w));
            let (core, digest) = f.tree.design.leaf.verify_mixed(
                &mut b,
                output,
                ProofSource::Proof(&f.runs[0].proof.0, &openings),
                Some(key),
            );
            assert_eq!(b.d(digest), primitives::hash::digest_words(key.digest()));
            let Finished { failures, .. } = b.finish();
            (failures, core)
        };
        assert!(check(key, output).0.is_empty());
        let mut b = Builder::new();
        let digest = b.free_d(primitives::hash::digest_words(key.digest()));
        let words = output.words().map(|w| b.free_k(w));
        let set = singleton_rows(&mut b, digest, words);
        assert_eq!(b.d(set), f.leaves()[0].claims().digest());
        assert!(b.finish().failures.is_empty());
        assert!(!check(f.programs[1].verifying_key(), output).0.is_empty());
        assert!(!check(key, f.runs[1].output).0.is_empty());
        for at in [0, 40, 72] {
            let mut bytes = key.to_bytes();
            bytes[at] ^= 4;
            let key = VerifyingKey::from_bytes(&bytes).expect("the tamper keeps valid metadata");
            assert!(!check(&key, output).0.is_empty());
        }
    }
}
