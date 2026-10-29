//! Program classes and claim-set trees whose first-level circuits take a verifying key as witness.

use super::*;
use crate::cpu::layout::Sizes;
use crate::rec::circuit::{Builder, Dw, Ew, Kw, PARAM_IV};
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
    /// The maximum number of members in one leaf list, at least one.
    pub max_members: usize,
}

/// One leaf class of a mixed tree. Its position chooses the first-level circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeafClass {
    /// Program normalization bounds and member-list capacity.
    pub program: ProgramClass,
    /// The exact announcement accepted by this class's circuit.
    pub shape: LeafShape,
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
    /// The ordered member list committed by the guest.
    pub members: &'a [[u64; 4]],
}

impl ProgramClass {
    /// Normalize a smaller program and image to this class before proving it.
    pub fn normalize(self, program: &Program) -> Result<Program, ProgramError> {
        if !self.image_words.is_power_of_two() {
            return Err(ProgramError::ImageSize);
        }
        program.padded(self.log_bytecode, self.log_ram, self.log_advice, self.image_words)
    }

    /// A prover padding each table to at least the supplied leaf shape, with fresh OS randomness for a ZK shape.
    pub fn prover(self, shape: LeafShape) -> Prover {
        let prover = Prover::new(shape.rate()).with_floor(shape.taus().map(|height| 1 << height));
        if shape.is_zero_knowledge() {
            prover.zero_knowledge(zk::Randomness::Os)
        } else {
            prover
        }
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
    /// The group this leaf publishes: its VK digest labels the committed members.
    pub fn claims(self) -> ClaimSet {
        let [a, b, c, d] = primitives::hash::digest_words(self.key.digest());
        ClaimSet {
            groups: vec![ClaimGroup {
                label: [a, b, c, d, 0, 0],
                members: self.members.to_vec(),
            }],
        }
    }
}

/// Where mixed classes verify zero-knowledge leaves. The caller pins this with the class shape.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ZkPlacement {
    /// Dedicated First tiers and SMALL LeafWrap circuits.
    #[default]
    Isolated,
    /// First circuits share the base tier, including its padded heights; no LeafWrap circuits.
    Shared,
}

impl ZkPlacement {
    pub(super) const fn isolated(self) -> bool {
        matches!(self, Self::Isolated)
    }
}

impl Tree<'static> {
    /// Build a mixed-program claim-set tree from class data alone.
    ///
    /// A zero-knowledge class uses a dedicated first level and a small-tier wrap.
    pub fn mixed(class: ProgramClass, shape: TreeShape) -> Result<Self, TreeError> {
        if shape.claims.is_none() || class.max_members == 0 {
            return Err(TreeError::MixedClass);
        }
        Self::mixed_classes(
            &[LeafClass {
                program: class,
                shape: shape.leaf,
            }],
            shape,
        )
    }

    /// Build one tree with an ordered set of leaf classes. `shape.leaf` must equal the first class's shape.
    /// Plain first levels share the small tier's heights; each ZK first level has a dedicated tier and small-tier wrap.
    /// Each circuit has its own authenticated kind.
    pub fn mixed_classes(classes: &[LeafClass], shape: TreeShape) -> Result<Self, TreeError> {
        Self::mixed_classes_with(classes, shape, ZkPlacement::Isolated)
    }

    /// Build mixed classes with caller-selected ZK placement. Shared First circuits use the base tier's
    /// heights and can be Node children directly, with or without a separate large aggregation tier.
    pub fn mixed_classes_with(
        classes: &[LeafClass],
        shape: TreeShape,
        placement: ZkPlacement,
    ) -> Result<Self, TreeError> {
        let first = classes.first().ok_or(TreeError::MixedClass)?;
        if shape.claims.is_none() || first.shape != shape.leaf || classes.iter().any(|c| c.program.max_members == 0) {
            return Err(TreeError::MixedClass);
        }
        let program = Self::mixed_placeholder(first.program)?;
        let extra = classes[1..]
            .iter()
            .map(|c| Ok((Self::mixed_placeholder(c.program)?, c.shape, c.program.max_members)))
            .collect::<Result<Vec<_>, TreeError>>()?;
        Self::build_zk_mode(
            &program,
            shape,
            Some(first.program.max_members),
            &extra,
            placement.isolated(),
        )
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
        self.aggregate_programs_at(0, leaves, declare)
    }

    /// Prove the first-level circuit of `class`, whose leaves must all have that class's exact shape.
    pub fn aggregate_programs_at(
        &self,
        class: usize,
        leaves: &[MixedLeaf<'_>],
        declare: Option<&ClaimSet>,
    ) -> Result<Aggregate, TreeError> {
        let class_index = class;
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
        let position = self.design.first_place(class).ok_or(TreeError::MixedClass)?;
        let (leaf_shape, max_members) = if class == 0 {
            (&self.design.leaf, self.design.max_members)
        } else {
            let (leaf, max) = self.design.extra_leaves.get(class - 1).ok_or(TreeError::MixedClass)?;
            (leaf, *max)
        };
        let key = leaf_shape.program().verifying_key();
        let sizes = key.sizes();
        let class = ProgramClass {
            max_members,
            log_bytecode: sizes.log_bytecode,
            log_ram: sizes.log_ram,
            log_advice: sizes.log_advice,
            image_words: key.image().len(),
        };
        let sets: Vec<_> = leaves.iter().map(|l| l.claims()).collect();
        let mut items = Vec::new();
        for (index, leaf) in leaves.iter().enumerate() {
            if leaf.members.is_empty() || leaf.members.len() > class.max_members {
                return Err(TreeError::Capacity);
            }
            if leanvm_guest::members::output(leaf.members) != *leaf.output.words() {
                return Err(TreeError::LeafClaims { index });
            }
            if !class.accepts(leaf.key) || LeafShape::announced(leaf.proof) != Some(leaf_shape.shape()) {
                return Err(TreeError::ForeignLeaf { index });
            }
            let openings = leaf
                .key
                .verify_recording(leaf.output, leaf.proof)
                .map_err(|error| TreeError::Leaf { index, error })?;
            items.push(LeafWitness {
                key: Some(leaf.key),
                members: leaf.members,
                proof: &leaf.proof.0,
                openings,
                output: *leaf.output.words(),
                set: sets[index].digest(),
            });
        }
        let refs: Vec<_> = sets.iter().collect();
        let (union, claims) = self.fill(position, &refs, declare)?;
        let inputs = NodeInputs::Prove {
            items: &items,
            tables: &self.tables,
            union: Some(&union),
        };
        let rows = self.design.first_rows_at(position, &inputs);
        let first = Aggregate {
            proof: self.prove_rows(rows)?,
            claims,
        };
        let tier = self.design.places[position].tier;
        if tier != SMALL {
            self.wrap_at(0, &first, Level::LeafWrap(class_index), tier)
        } else {
            Ok(first)
        }
    }
}

/// Read a bounded nonempty member list once, binding both its output and its VK-labelled group digest.
pub(super) fn member_rows(
    b: &mut Builder,
    digest: Dw,
    output: [Kw; 4],
    max_members: usize,
    members: Option<&[[u64; 4]]>,
) -> Dw {
    use fiat_shamir::arith::Arith;
    use leanvm_guest::members::{DOMAIN, TAG};

    fn choose(b: &mut Builder, bit: Ew, yes: Dw, no: Dw) -> Dw {
        let y = b.d_to_halves(yes);
        let n = b.d_to_halves(no);
        let selected = std::array::from_fn::<_, 2, _>(|i| {
            let delta = b.add(y[i], n[i]);
            b.mul_add(bit, delta, n[i])
        });
        b.halves_to_d(selected[0], selected[1])
    }

    let zero = b.k_const(0);
    let z = b.zero();
    let one = b.one();
    let iv = b.d_const(PARAM_IV);
    let tag = b.k_const(TAG);
    let mut list = b.leaf_block(iv, [tag, zero, zero, zero, zero, zero, zero, zero], DOMAIN | 1, false);
    let [d0, d1, d2, d3] = b.d_to_k(digest);
    let mut group = b.leaf_block(
        iv,
        [d0, d1, d2, d3, zero, zero, zero, zero],
        multiset::code::START,
        false,
    );
    let mut previous = one;
    for pair in 0..max_members.div_ceil(2) {
        let present: [Ew; 2] = std::array::from_fn(|j| {
            let index = 2 * pair + j;
            let bit = b.free_k(u64::from(members.is_some_and(|m| index < m.len())));
            let e = b.k_to_e1(bit);
            let square = b.square(e);
            b.eq(square, e);
            if index >= max_members {
                b.eq(e, z);
            }
            let missing_previous = b.add(previous, one);
            let gap = b.mul(e, missing_previous);
            b.eq(gap, z);
            if index == 0 {
                b.eq(e, one);
            }
            previous = e;
            e
        });
        let block: [Kw; 8] = std::array::from_fn(|j| {
            let index = 2 * pair + j / 4;
            let word = b.free_k(members.and_then(|m| m.get(index)).map_or(0, |m| m[j % 4]));
            let e = b.k_to_e1(word);
            let absent = b.add(present[j / 4], one);
            let padding = b.mul(e, absent);
            b.eq(padding, z);
            word
        });
        // PAIR is a constrained bit, not an alternative interpretation selected by the prover.
        let pair_bit = b.e_to_k(present[1])[0];
        let one_word = b.k_const(1);
        let counter = b.pack(&[zero, one_word, zero, pair_bit]);
        let tf = b.k_to_d([counter, zero, zero, zero]);
        let next_group = b.block(group, block, tf);
        group = choose(b, present[0], next_group, group);
        let list_counter = b.pack(&[zero, one_word, zero, pair_bit, one_word]);
        let tf = b.k_to_d([list_counter, zero, zero, zero]);
        let next_list = b.block(list, block, tf);
        list = choose(b, present[0], next_list, list);
    }
    let end = b.leaf_block(list, [tag, zero, zero, zero, zero, zero, zero, zero], DOMAIN | 4, true);
    let words = b.d_to_k(end);
    let expected = b.chain(&words);
    let output = b.k_to_d(output);
    b.eq(expected, output);
    let tag = b.k_const(multiset::code::TAG);
    b.leaf_block(
        group,
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
        members: [[u64; 4]; 2],
        class: ProgramClass,
        shape: TreeShape,
    }

    fn fixture() -> &'static Fixture {
        static F: OnceLock<Fixture> = OnceLock::new();
        F.get_or_init(|| {
            let a = Program::from_elf(include_bytes!(
                "../../../../../programs/fibonacci-members/fibonacci-members.elf"
            ))
            .unwrap();
            let b = Program::from_elf(include_bytes!(
                "../../../../../programs/preimage-members/preimage-members.elf"
            ))
            .unwrap();
            let class = ProgramClass {
                max_members: 4,
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
            let old_a = Program::from_elf(include_bytes!("../../../../../programs/fibonacci/fibonacci.elf")).unwrap();
            let old_b = Program::from_elf(include_bytes!("../../../../../programs/preimage/preimage.elf")).unwrap();
            let members = [
                old_a.execute(&[2700]).unwrap().output,
                old_b.execute(&[0]).unwrap().output,
            ];
            Fixture {
                members,
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
                members: std::slice::from_ref(&self.members[i]),
            })
        }
    }

    #[test]
    fn normalization_reports_invalid_image_lengths() {
        let f = fixture();
        for image_words in [0, 3] {
            let class = ProgramClass { image_words, ..f.class };
            assert!(matches!(class.normalize(&f.programs[0]), Err(ProgramError::ImageSize)));
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
        for root in [&first, &large, &wrap, &narrowed] {
            let seal = tree.seal(&prover, &root.proof).unwrap();
            assert!(matches!(
                wrong_session.verify_claims(&root.proof, &root.claims),
                Err(TreeError::SealRequired)
            ));
            let result = wrong_session.verify_claims_sealed(&root.proof, &root.claims, &roots, &seal);
            assert!(!seal.narg.is_empty());
            assert!(result.is_err(), "a wrong digest must refuse every v3 seal");
            for verifier in [&tree, &loaded, &trusted] {
                if verifier.verifier_only {
                    assert!(matches!(
                        verifier.verify_claims(&root.proof, &root.claims),
                        Err(TreeError::SealRequired)
                    ));
                } else {
                    verifier.verify_claims(&root.proof, &root.claims).unwrap();
                }
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
            members: &f.members[..1],
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
                members: leaf.members,
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
    fn built_trees_refuse_foreign_seal_provers_and_roots() {
        let f = fixture();
        let first = f.tree.aggregate_programs(&f.leaves(), None).unwrap();
        let mut other_class = f.class;
        other_class.log_advice += 1;
        let other = Tree::mixed(other_class, f.shape).unwrap();
        let foreign = other.seal_prover().unwrap();
        let genuine = f.tree.seal_prover().unwrap();
        let roots = genuine.roots();
        let seal = f.tree.seal(&genuine, &first.proof).unwrap();
        assert_eq!(foreign.roots().0.len(), roots.0.len());
        assert_ne!(foreign.roots(), roots);
        assert!(matches!(f.tree.seal(&foreign, &first.proof), Err(TreeError::SealRoots)));
        assert_eq!(
            f.tree
                .verify_claims_sealed(&first.proof, &first.claims, &foreign.roots(), &seal),
            Err(TreeError::SealRoots)
        );
        assert!(matches!(
            f.tree.mixed_verifier_bytes(&foreign.roots()),
            Err(TreeError::SealRoots)
        ));
        f.tree
            .verify_claims_sealed(&first.proof, &first.claims, &roots, &seal)
            .unwrap();
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
        let header = 8 + (2 + 5 + crate::N_TABLES + 2 + 6 + 1) * 8;
        let tier_count = header + 8 + 32 + 32;
        let tier_heights = tier_count + 8;
        let key_count = tier_heights + Table::ALL.len() * 8;
        let circuit_start = key_count + 8;
        for at in [
            header,
            tier_count,
            tier_heights,
            key_count,
            circuit_start,
            circuit_start + 8,
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
        for end in [0, 7, 8, header, circuit_start, bytes.len() - 1] {
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
        assert!(matches!(
            loaded.verify_claims(&root.proof, &root.claims),
            Err(TreeError::SealRequired)
        ));
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
                if verifier.verifier_only {
                    assert!(matches!(
                        verifier.verify_claims(&root.proof, &root.claims),
                        Err(TreeError::SealRequired)
                    ));
                } else {
                    verifier.verify_claims(&root.proof, &root.claims).unwrap();
                }
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
    fn trusted_loader_wrong_digest_rejects_first_and_node_seals() {
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
        // V3 authenticates the root's own columns, even for a first level.
        let first_seal = f.tree.seal(&sealer, &first.proof).unwrap();
        assert!(!first_seal.narg.is_empty());
        assert!(
            trusted
                .verify_claims_sealed(&first.proof, &first.claims, &roots, &first_seal)
                .is_err()
        );
        let node = f.tree.aggregate(&[&first, &first], None).unwrap();
        let seal = f.tree.seal(&sealer, &node.proof).unwrap();
        assert!(matches!(
            trusted.verify_claims(&node.proof, &node.claims),
            Err(TreeError::SealRequired)
        ));
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
        assert!(Tree::mixed(f.class, zk).is_ok());
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
        let set = member_rows(&mut b, digest, words, f.class.max_members, Some(&f.members[..1]));
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

#[cfg(test)]
mod member_tests {
    //! Member-list and multi-class regression tests, including witnesses bypassing native prechecks.
    use super::*;
    use crate::rec::circuit::Finished;
    use crate::tables::TableId;
    use std::sync::OnceLock;

    fn constant_list(members: &[[u64; 4]]) -> Program {
        constant_output(leanvm_guest::members::output(members))
    }

    fn constant_output(output: [u64; 4]) -> Program {
        let mut a = Asm::new();
        a.li(Reg::T0, 9000)
            .label("loop")
            .i(crate::rv::asm::Addi, Reg::T0, Reg::T0, -1)
            .branch(crate::rv::asm::Bne, Reg::T0, Reg::ZERO, "loop");
        for (reg, value) in [Reg::A0, Reg::A1, Reg::A2, Reg::A3].into_iter().zip(output) {
            a.li(reg, value);
        }
        a.exit();
        Program::new(&a.finish(), Region::TEXT.base(), vec![], 0, 0).unwrap()
    }

    fn class(program: &Program, advice: &[u64]) -> (Program, LeafClass) {
        let rv = program.rv();
        let bounds = ProgramClass {
            log_bytecode: (rv.entries().len().ilog2() as usize).max(10),
            log_ram: rv.log_ram(),
            log_advice: rv.log_advice(),
            image_words: rv.image().len().max(1).next_power_of_two(),
            max_members: 4,
        };
        let program = bounds.normalize(program).unwrap();
        let mut stats = program.measure(advice).unwrap();
        stats.counts[TableId::ALU] *= 2;
        let shape = LeafShape::measured(&stats, Rate::MIN);
        (program, LeafClass { program: bounds, shape })
    }

    struct Fixture {
        tree: Tree<'static>,
        classes: [LeafClass; 2],
        programs: [Program; 2],
        runs: [ProvenRun; 2],
        members: [Vec<[u64; 4]>; 2],
    }

    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let members = vec![[1, 2, 3, 4], [2, 3, 4, 5], [2, 3, 4, 5], [3, 4, 5, 6]];
            let (sk, key) = leansphincs::key_gen([3; 32]);
            let messages = [[1; 4], [2; 4]];
            let sigs = messages.map(|m| sk.sign(&m).unwrap());
            let batch =
                leansphincs_members_host::batch(&[(&key, &messages[0], &sigs[0]), (&key, &messages[1], &sigs[1])]);
            let (small, a) = class(&constant_list(&members), &[]);
            let (large, b) = class(
                &Program::from_elf(leansphincs_members_host::ELF).unwrap(),
                &batch.run.advice,
            );
            assert_ne!(a.shape, b.shape);
            let runs = [
                a.program.prover(a.shape).prove(&small, &[]).unwrap(),
                b.program.prover(b.shape).prove(&large, &batch.run.advice).unwrap(),
            ];
            let shape = TreeShape {
                leaf: a.shape,
                arity_0: 1,
                arity: 2,
                rate: Rate::MIN,
                claims: Some(ClaimShape {
                    capacity: Capacity { claims: 8, groups: 4 },
                    small: Some(Tier {
                        arity: 2,
                        capacity: Capacity { claims: 5, groups: 2 },
                    }),
                }),
            };
            let classes = [a, b];
            let tree = Tree::mixed_classes(&classes, shape).unwrap();
            Fixture {
                tree,
                classes,
                programs: [small, large],
                runs,
                members: [members, batch.members],
            }
        })
    }

    impl Fixture {
        fn leaf(&self, i: usize) -> MixedLeaf<'_> {
            MixedLeaf {
                key: self.programs[i].verifying_key(),
                proof: &self.runs[i].proof,
                output: self.runs[i].output,
                members: &self.members[i],
            }
        }
        fn first(&self, i: usize) -> Aggregate {
            self.tree.aggregate_programs_at(i, &[self.leaf(i)], None).unwrap()
        }
    }

    fn verify_both(tree: &Tree<'_>, sealer: &SealProver, root: &Aggregate) {
        tree.verify_claims(&root.proof, &root.claims).unwrap();
        let seal = tree.seal(sealer, &root.proof).unwrap();
        tree.verify_claims_sealed(&root.proof, &root.claims, &sealer.roots(), &seal)
            .unwrap();
    }

    #[test]
    fn member_classes_fold_deduplicate_close_and_load() {
        let f = fixture();
        let sealer = f.tree.seal_prover().unwrap();
        let firsts = [f.first(0), f.first(1)];
        assert_eq!(firsts[0].claims.n_claims(), 3);
        assert_eq!(firsts[0].claims.groups.len(), 1);
        assert_eq!(firsts[1].proof.kind(), Kind::First);
        for first in &firsts {
            verify_both(&f.tree, &sealer, first);
        }
        let mut acc = Accumulator::default();
        assert!(acc.close().is_none());
        f.tree.fold(&mut acc, &firsts[0]).unwrap();
        assert_eq!(acc.root().unwrap().proof, firsts[0].proof);
        f.tree.fold(&mut acc, &firsts[1]).unwrap();
        f.tree.fold(&mut acc, &firsts[0]).unwrap();
        assert_eq!(acc.root().unwrap().claims.n_claims(), 5);
        assert_eq!(acc.root().unwrap().claims.groups.len(), 2);
        let more = [[9; 4], [10; 4], [11; 4], [12; 4]];
        let p = f.classes[0].program.normalize(&constant_list(&more)).unwrap();
        let run = f.classes[0].program.prover(f.classes[0].shape).prove(&p, &[]).unwrap();
        let next = f
            .tree
            .aggregate_programs_at(
                0,
                &[MixedLeaf {
                    key: p.verifying_key(),
                    proof: &run.proof,
                    output: run.output,
                    members: &more,
                }],
                None,
            )
            .unwrap();
        let before = acc.root().unwrap().proof.clone();
        assert_eq!(f.tree.fold(&mut acc, &next), Err(TreeError::Capacity));
        assert_eq!(acc.root().unwrap().proof, before);
        let root = acc.close().unwrap();
        assert!(acc.root().is_none());
        verify_both(&f.tree, &sealer, &root);
        let bytes = f.tree.mixed_verifier_bytes(&sealer.roots()).unwrap();
        let digest = Tree::mixed_class_key_digest(&bytes);
        let loaded = Tree::mixed_classes_from_bytes(&f.classes, f.tree.shape, &bytes, &digest).unwrap();
        let trusted = Tree::mixed_classes_from_trusted_bytes(&f.classes, f.tree.shape, &bytes, &digest).unwrap();
        let seal = f.tree.seal(&sealer, &root.proof).unwrap();
        for verifier in [&loaded, &trusted] {
            assert!(matches!(
                verifier.verify_claims(&root.proof, &root.claims),
                Err(TreeError::SealRequired)
            ));
            verifier
                .verify_claims_sealed(&root.proof, &root.claims, verifier.seal_roots().unwrap(), &seal)
                .unwrap();
        }
        let mut wrong_pin = digest;
        wrong_pin[0] ^= 1;
        let misconfigured =
            Tree::mixed_classes_from_trusted_bytes(&f.classes, f.tree.shape, &bytes, &wrong_pin).unwrap();
        for first in &firsts {
            let empty = f.tree.seal(&sealer, &first.proof).unwrap();
            assert!(
                misconfigured
                    .verify_claims_sealed(&first.proof, &first.claims, &sealer.roots(), &empty)
                    .is_err()
            );
        }
        assert!(
            misconfigured
                .verify_claims_sealed(&root.proof, &root.claims, &sealer.roots(), &seal)
                .is_err()
        );
        let mut changed = f.classes;
        changed[1].program.max_members += 1;
        assert!(Tree::mixed_classes_from_bytes(&changed, f.tree.shape, &bytes, &digest).is_err());
        let mut wrong = f.classes;
        wrong.swap(0, 1);
        assert!(Tree::mixed_classes_from_bytes(&wrong, f.tree.shape, &bytes, &digest).is_err());
        assert!(Tree::mixed_from_bytes(f.classes[0].program, f.tree.shape, &bytes, &digest).is_err());
        // One-member leaves use the same list convention and union rows.
        let one = &more[..1];
        let p = f.classes[0].program.normalize(&constant_list(one)).unwrap();
        let run = f.classes[0].program.prover(f.classes[0].shape).prove(&p, &[]).unwrap();
        let first = f
            .tree
            .aggregate_programs_at(
                0,
                &[MixedLeaf {
                    key: p.verifying_key(),
                    proof: &run.proof,
                    output: run.output,
                    members: one,
                }],
                None,
            )
            .unwrap();
        verify_both(&f.tree, &sealer, &first);
    }

    // Bypass aggregate_programs' list and shape prechecks, then execute the union and reduction rows.
    fn row_failures(f: &Fixture, position: usize, leaf: MixedLeaf<'_>, declared: &ClaimSet) -> Vec<Unsatisfied> {
        let set = leaf.claims();
        let shape = f.tree.design.union_shape(position).unwrap();
        let fill = super::super::union::tests::unbacked(&shape, &[&set], declared);
        let items = [LeafWitness {
            key: Some(leaf.key),
            members: leaf.members,
            proof: &leaf.proof.0,
            openings: leaf.key.verify_recording(leaf.output, leaf.proof).unwrap(),
            output: *leaf.output.words(),
            set: set.digest(),
        }];
        let rows = f.tree.design.first_rows_at(
            position,
            &NodeInputs::Prove {
                items: &items,
                tables: &f.tree.tables,
                union: Some(&fill),
            },
        );
        let reduction = rows
            .claim_values()
            .prove(&f.tree.design.session(), &f.tree.design.vars, &f.tree.tables);
        rows.reduce(&f.tree.design, ProofSource::Proof(&reduction, &[]))
            .failures
    }

    #[test]
    fn member_list_forgeries_fail_union_rows_and_both_root_paths() {
        let f = fixture();
        let honest = f.first(0);
        let sealer = f.tree.seal_prover().unwrap();
        let seal = f.tree.seal(&sealer, &honest.proof).unwrap();
        let mut unlisted = f.members[0].clone();
        unlisted[0][0] ^= 1;
        let mut mislabeled = honest.claims.clone();
        mislabeled.groups[0].label[0] ^= 1;
        for (members, declared) in [(&unlisted[..], None), (&f.members[0][..], Some(mislabeled))] {
            let leaf = MixedLeaf { members, ..f.leaf(0) };
            let declared = declared.unwrap_or_else(|| ClaimSet::from_claims(leaf.claims().claims()));
            assert!(!row_failures(f, 0, leaf, &declared).is_empty());
            assert!(f.tree.verify_claims(&honest.proof, &declared).is_err());
            assert!(
                f.tree
                    .verify_claims_sealed(&honest.proof, &declared, &sealer.roots(), &seal)
                    .is_err()
            );
        }
        // A genuine execution committing five members cannot be truncated into a four-member class.
        let too_many = [[11; 4], [12; 4], [13; 4], [14; 4], [15; 4]];
        let set_as_list = [honest.claims.digest()];
        for (members, output) in [
            (&too_many[..], leanvm_guest::members::output(&too_many)),
            (&set_as_list[..], chain(&honest.claims.digest())),
        ] {
            let p = f.classes[0].program.normalize(&constant_output(output)).unwrap();
            let run = f.classes[0].program.prover(f.classes[0].shape).prove(&p, &[]).unwrap();
            let leaf = MixedLeaf {
                key: p.verifying_key(),
                proof: &run.proof,
                output: run.output,
                members,
            };
            let declared = ClaimSet::from_claims(leaf.claims().claims());
            assert!(!row_failures(f, 0, leaf, &declared).is_empty());
            assert!(f.tree.verify_claims(&honest.proof, &declared).is_err());
            assert!(
                f.tree
                    .verify_claims_sealed(&honest.proof, &declared, &sealer.roots(), &seal)
                    .is_err()
            );
        }
        let list = leanvm_guest::members::digest(&f.members[0]);
        assert_ne!(list, f.leaf(0).claims().digest());
        // A list output cannot authorize a set digest chosen by the prover, in the reverse direction either.
        let mut listed_as_set = honest.claims.clone();
        listed_as_set.groups[0].label[..4].copy_from_slice(&list);
        let shape = f.tree.design.union_shape(0).unwrap();
        let fill = UnionFill::new(&shape, &[&listed_as_set], &listed_as_set).unwrap();
        let mut b = Builder::new();
        let digest = b.free_d(list);
        shape.rows(&mut b, &f.tree.design.session(), &[digest], Some(&fill));
        assert!(!b.finish().failures.is_empty());
        assert!(f.tree.verify_claims(&honest.proof, &listed_as_set).is_err());
        assert!(
            f.tree
                .verify_claims_sealed(&honest.proof, &listed_as_set, &sealer.roots(), &seal)
                .is_err()
        );
    }

    #[test]
    fn leaf_shape_is_bound_by_its_kind_and_fixed_polynomial() {
        let f = fixture();
        let d = &f.tree.design;
        // A VK does not bind the execution table heights. A different valid announcement must fail in rows.
        let mut heights = f.classes[0].shape.heights();
        heights[TableId::ALU] += 1;
        let shape = LeafShape::plain(heights, Rate::MIN).unwrap();
        let run = f.classes[0].program.prover(shape).prove(&f.programs[0], &[]).unwrap();
        let leaf = MixedLeaf {
            key: f.programs[0].verifying_key(),
            proof: &run.proof,
            output: run.output,
            members: &f.members[0],
        };
        assert!(matches!(
            f.tree.aggregate_programs_at(0, &[leaf], None),
            Err(TreeError::ForeignLeaf { index: 0 })
        ));
        let declared = ClaimSet::from_claims(leaf.claims().claims());
        assert!(!row_failures(f, 0, leaf, &declared).is_empty());

        // An attacker supplies its own same-height first-level circuit under the other leaf class's kind.
        // Its own proof is valid, and the honest node's rows accept its columns. Only authenticated Fixed closes it.
        let honest = f.first(0);
        let foreign_position = d.place(SMALL, Level::First(1)).unwrap();
        let mut words = honest.proof.words.clone();
        words[0] = F192::new(d.code(foreign_position) as u64, 0, 0);
        let mut b = Builder::new();
        for word in words {
            let w = b.free_e(word);
            b.expose(w);
        }
        let Finished {
            mut circuit,
            assignment,
            failures,
        } = b.finish();
        assert!(failures.is_empty());
        circuit.floor = d.tiers[SMALL].taus;
        let fake = CircuitKey::new(circuit).unwrap();
        let child = TreeProof::new(
            d.code(foreign_position),
            &assignment,
            fake.prove(&assignment, &d.session(), d.rate),
            d.rate,
        );
        assert!(f.tree.read(&child, foreign_position).is_err());
        let openings = fake.verify(&child.limbs(), &d.session(), d.rate, &child.proof).unwrap();
        let mut tables = f.tree.tables.clone();
        let columns: Vec<_> = d.tiers[SMALL]
            .places
            .clone()
            .map(|p| {
                if p == foreign_position {
                    fake.fixed()
                } else {
                    f.tree.keys[p].fixed()
                }
            })
            .collect();
        tables.0[DensePoly::Fixed.index()] = d.tiers[SMALL].fixed.polynomial(&columns);
        let statement = child.statement(d.statement);
        let items: Vec<_> = (0..2)
            .map(|_| ChildWitness {
                statement: &statement,
                proof: &child.proof,
                openings: openings.clone(),
                columns: fake.fixed(),
            })
            .collect();
        let position = d.place(SMALL, Level::Node(2)).unwrap();
        let (union, claims) = f.tree.fill(position, &[&honest.claims, &honest.claims], None).unwrap();
        let rows = d.node_rows(
            &NodeInputs::Prove {
                items: &items,
                tables: &tables,
                union: Some(&union),
            },
            position,
        );
        let reduction = rows.claim_values().prove(&d.session(), &d.vars, &tables);
        let Finished {
            assignment, failures, ..
        } = rows.reduce(d, ProofSource::Proof(&reduction, &[]));
        assert!(failures.is_empty(), "{failures:?}");
        let root = TreeProof::new(
            d.code(position),
            &assignment,
            f.tree.keys[position].prove(&assignment, &d.session(), d.rate),
            d.rate,
        );
        f.tree.read(&root, position).unwrap();
        let refusal = TreeError::Claim(FalseClaim::Dense(DensePoly::Fixed));
        assert_eq!(f.tree.verify_claims(&root, &claims), Err(refusal.clone()));
        let sealer = f.tree.seal_prover().unwrap();
        let seal = f.tree.seal(&sealer, &root).unwrap();
        assert_eq!(
            f.tree.verify_claims_sealed(&root, &claims, &sealer.roots(), &seal),
            Err(refusal)
        );
    }

    #[test]
    fn member_list_rows_match_sdk_for_odd_even_and_empty_boundaries() {
        let label = [7, 8, 9, 10];
        for max in 1..=5 {
            for count in 0..=max {
                let members: Vec<_> = (0..count).map(|i| [i as u64, 3, 4, 5]).collect();
                let mut b = Builder::new();
                let digest = b.free_d(label);
                let output = leanvm_guest::members::output(&members).map(|w| b.free_k(w));
                let group = member_rows(&mut b, digest, output, max, Some(&members));
                let expected = ClaimSet {
                    groups: vec![ClaimGroup {
                        label: [7, 8, 9, 10, 0, 0],
                        members,
                    }],
                };
                if count != 0 {
                    assert_eq!(b.d(group), expected.digest());
                }
                assert_eq!(b.finish().failures.is_empty(), count != 0);
            }
        }
    }
}

#[cfg(test)]
mod zk_tests {
    //! Mixed ZK witnesses, isolated first levels and their authenticated wraps.
    use super::*;
    use crate::rv::asm::{Addi, Bne, Ld};
    use crate::tables::TableId;
    use zk::Randomness;

    fn program(members: &[[u64; 4]]) -> Program {
        let mut a = Asm::new();
        // The witnessed entry differs from the placeholder's. Advice is used internally but is not the output.
        a.i(Addi, Reg::T2, Reg::ZERO, 0)
            .li(Reg::T0, Region::ADVICE.base())
            .load(Ld, Reg::T2, 0, Reg::T0)
            .li(Reg::T1, 9000)
            .label("loop")
            .i(Addi, Reg::T1, Reg::T1, -1)
            .branch(Bne, Reg::T1, Reg::ZERO, "loop");
        for (reg, value) in [Reg::A0, Reg::A1, Reg::A2, Reg::A3]
            .into_iter()
            .zip(leanvm_guest::members::output(members))
        {
            a.li(reg, value);
        }
        Program::new(&a.exit().finish(), Region::TEXT.base() + 4, vec![3, 5], 2, 0).unwrap()
    }

    fn class(p: &Program, advice: &[u64]) -> (Program, LeafClass) {
        let rv = p.rv();
        let bounds = ProgramClass {
            log_bytecode: (rv.entries().len().ilog2() as usize).max(10),
            log_ram: rv.log_ram(),
            log_advice: rv.log_advice(),
            image_words: rv.image().len().max(1).next_power_of_two(),
            max_members: 4,
        };
        let p = bounds.normalize(p).unwrap();
        let mut stats = p.measure(advice).unwrap();
        stats.counts[TableId::ALU] *= 2;
        (
            p,
            LeafClass {
                program: bounds,
                shape: LeafShape::measured(&stats, Rate::MIN),
            },
        )
    }

    fn raw_first(tree: &Tree<'_>, class: usize, leaf: MixedLeaf<'_>) -> Aggregate {
        let position = tree.design.first_place(class).unwrap();
        let set = leaf.claims();
        let (union, claims) = tree.fill(position, &[&set], None).unwrap();
        let items = [LeafWitness {
            key: Some(leaf.key),
            members: leaf.members,
            proof: &leaf.proof.0,
            openings: leaf.key.verify_recording(leaf.output, leaf.proof).unwrap(),
            output: *leaf.output.words(),
            set: set.digest(),
        }];
        let rows = tree.design.first_rows_at(
            position,
            &NodeInputs::Prove {
                items: &items,
                tables: &tree.tables,
                union: Some(&union),
            },
        );
        Aggregate {
            proof: tree.prove_rows(rows).unwrap(),
            claims,
        }
    }

    #[test]
    fn mixed_zk_classes_wrap_fold_seal_and_refuse_foreign_leaves() {
        let members = [[1, 2, 3, 4], [5, 6, 7, 8]];
        let (program, plain_class) = class(&program(&members), &[37]);
        let (sk, pk) = leansphincs::key_gen([7; 32]);
        let message = [8; 4];
        let signature = sk.sign(&message).unwrap();
        let batch = leansphincs_members_host::batch(&[(&pk, &message, &signature)]);
        let (signature_program, signature_class) = class(
            &Program::from_elf(leansphincs_members_host::ELF).unwrap(),
            &batch.run.advice,
        );
        let zk_class = LeafClass {
            shape: plain_class.shape.zero_knowledge(),
            ..plain_class
        };
        let classes = [plain_class, signature_class, zk_class];
        let shape = TreeShape {
            leaf: plain_class.shape,
            arity_0: 1,
            arity: 2,
            rate: Rate::MIN,
            claims: Some(ClaimShape {
                capacity: Capacity { claims: 16, groups: 4 },
                small: Some(Tier {
                    arity: 2,
                    capacity: Capacity { claims: 8, groups: 4 },
                }),
            }),
        };
        let tree = Tree::mixed_classes(&classes, shape).unwrap();
        assert_eq!(tree.design.tiers.len(), 3);
        let plain = plain_class
            .program
            .prover(plain_class.shape)
            .prove(&program, &[37])
            .unwrap();
        let hidden = zk_class
            .program
            .prover(zk_class.shape)
            .zero_knowledge(Randomness::Fixed([19; 32]))
            .prove(&program, &[41])
            .unwrap();
        assert_eq!(LeafShape::of(&hidden.proof).unwrap(), zk_class.shape);
        let signed = signature_class
            .program
            .prover(signature_class.shape)
            .prove(&signature_program, &batch.run.advice)
            .unwrap();
        let plain_leaf = MixedLeaf {
            key: program.verifying_key(),
            proof: &plain.proof,
            output: plain.output,
            members: &members,
        };
        let zk_leaf = MixedLeaf {
            proof: &hidden.proof,
            output: hidden.output,
            ..plain_leaf
        };
        assert!(tree.aggregate_programs_at(2, &[plain_leaf], None).is_err());
        assert!(tree.aggregate_programs_at(0, &[zk_leaf], None).is_err());
        let mut key_bytes = program.verifying_key().to_bytes();
        key_bytes[0] ^= 1;
        let bad_key = VerifyingKey::from_bytes(&key_bytes).unwrap();
        assert!(
            tree.aggregate_programs_at(
                2,
                &[MixedLeaf {
                    key: &bad_key,
                    ..zk_leaf
                }],
                None
            )
            .is_err()
        );
        let wrong = [[9, 2, 3, 4], members[1]];
        assert!(
            tree.aggregate_programs_at(
                2,
                &[MixedLeaf {
                    members: &wrong,
                    ..zk_leaf
                }],
                None
            )
            .is_err()
        );
        // Bypass the native prechecks: the verifier rows themselves bind key, session, kind and list.
        for (class, offered, expected_failure) in [
            (2, zk_leaf, false),
            (
                2,
                MixedLeaf {
                    key: &bad_key,
                    ..zk_leaf
                },
                true,
            ),
            (
                2,
                MixedLeaf {
                    members: &wrong,
                    ..zk_leaf
                },
                true,
            ),
            (2, plain_leaf, true),
            (0, zk_leaf, true),
        ] {
            let leaf_shape = if class == 0 {
                &tree.design.leaf
            } else {
                &tree.design.extra_leaves[class - 1].0
            };
            let honest = if offered.proof.is_zero_knowledge() {
                zk_leaf
            } else {
                plain_leaf
            };
            let openings = honest.key.verify_recording(honest.output, honest.proof).unwrap();
            let mut b = crate::rec::circuit::Builder::new();
            let output = offered.output.words().map(|w| b.free_k(w));
            let (_, digest) = leaf_shape.verify_mixed(
                &mut b,
                output,
                ProofSource::Proof(&offered.proof.0, &openings),
                Some(offered.key),
            );
            member_rows(&mut b, digest, output, 4, Some(offered.members));
            assert_eq!(!b.finish().failures.is_empty(), expected_failure);
        }
        let raw = raw_first(&tree, 2, zk_leaf);
        assert_ne!(tree.design.places[tree.known(&raw.proof).unwrap()].tier, SMALL);
        assert!(tree.aggregate(&[&raw], None).is_err());
        let wrapped = tree.aggregate_programs_at(2, &[zk_leaf], None).unwrap();
        assert_eq!(
            tree.design.places[tree.known(&wrapped.proof).unwrap()].level,
            Level::LeafWrap(2)
        );
        let first = tree.aggregate_programs_at(0, &[plain_leaf], None).unwrap();
        let signature = tree
            .aggregate_programs_at(
                1,
                &[MixedLeaf {
                    key: signature_program.verifying_key(),
                    proof: &signed.proof,
                    output: signed.output,
                    members: &batch.members,
                }],
                None,
            )
            .unwrap();
        let mut acc = Accumulator::default();
        for a in [&first, &signature, &wrapped] {
            tree.fold(&mut acc, a).unwrap();
        }
        let root = acc.close().unwrap();
        let sealer = tree.seal_prover().unwrap();
        let roots = sealer.roots();
        let seal = tree.seal(&sealer, &root.proof).unwrap();
        let bytes = tree.mixed_verifier_bytes(&roots).unwrap();
        assert_eq!(&bytes[..8], b"LVMXCK04");
        let digest = Tree::mixed_class_key_digest(&bytes);
        for verifier in [
            Tree::mixed_classes_from_bytes(&classes, shape, &bytes, &digest).unwrap(),
            Tree::mixed_classes_from_trusted_bytes(&classes, shape, &bytes, &digest).unwrap(),
        ] {
            assert!(matches!(
                verifier.verify_claims(&root.proof, &root.claims),
                Err(TreeError::SealRequired)
            ));
            verifier
                .verify_claims_sealed(&root.proof, &root.claims, &roots, &seal)
                .unwrap();
            assert!(matches!(
                verifier.verify_claims(&wrapped.proof, &wrapped.claims),
                Err(TreeError::SealRequired)
            ));
        }
        // Carried usage excludes the root's own columns (the seal adds those separately).
        let usage = |a: &Aggregate| {
            let statement = a.proof.statement(tree.design.statement);
            (0..3).map(|t| statement.usage(t)).collect::<Vec<_>>()
        };
        assert_eq!(usage(&raw), vec![F192::ZERO; 3]);
        assert_eq!(usage(&wrapped), vec![F192::ZERO, F192::ZERO, F192::ONE]);
        assert_eq!(usage(&root), vec![F192::ONE, F192::ZERO, F192::ONE]);
        let plain_node = tree.aggregate(&[&first, &signature], None).unwrap();
        assert_eq!(usage(&plain_node), vec![F192::ONE, F192::ZERO, F192::ZERO]);
        let loaded = Tree::mixed_classes_from_bytes(&classes, shape, &bytes, &digest).unwrap();
        assert!(
            loaded.tables.0.is_empty(),
            "compact loading allocates no polynomial tables"
        );
        assert!(bytes.len() < 2000);
        for root in [&raw, &wrapped, &plain_node] {
            let seal = tree.seal(&sealer, &root.proof).unwrap();
            loaded
                .verify_claims_sealed(&root.proof, &root.claims, &roots, &seal)
                .unwrap();
            let mut altered = seal.clone();
            altered.narg[8] ^= 1; // Root fixed-column evaluation: native or PCS checking must refuse.
            assert!(
                loaded
                    .verify_claims_sealed(&root.proof, &root.claims, &roots, &altered)
                    .is_err()
            );
            let mut pin = digest;
            pin[0] ^= 1;
            let wrong = Tree::mixed_classes_from_trusted_bytes(&classes, shape, &bytes, &pin).unwrap();
            assert!(
                wrong
                    .verify_claims_sealed(&root.proof, &root.claims, &roots, &seal)
                    .is_err()
            );
        }
        // The plain node uses one opening: its root columns and recursive claim share the small tier.
        let seal = tree.seal(&sealer, &plain_node.proof).unwrap();
        let count = u64::from_le_bytes(seal.narg[..8].try_into().unwrap()) as usize;
        let prefix = 8 + 24 * count;
        let mut dropped = seal.clone();
        dropped.narg.truncate(prefix);
        dropped.hints.clear();
        assert!(
            loaded
                .verify_claims_sealed(&plain_node.proof, &plain_node.claims, &roots, &dropped)
                .is_err()
        );
        let mut added = seal.clone();
        added.narg.extend_from_slice(&seal.narg[prefix..]);
        added.hints.extend_from_slice(&seal.hints);
        assert!(
            loaded
                .verify_claims_sealed(&plain_node.proof, &plain_node.claims, &roots, &added)
                .is_err()
        );
        let seal = tree.seal(&sealer, &root.proof).unwrap();
        for tier in 0..3 {
            let mut forged = root.proof.clone();
            let at = tree
                .design
                .statement
                .range(super::super::statement::Section::Usage)
                .start
                + tier;
            forged.words[at] += F192::ONE;
            assert!(tree.verify_claims(&forged, &root.claims).is_err());
            assert!(
                loaded
                    .verify_claims_sealed(&forged, &root.claims, &roots, &seal)
                    .is_err()
            );
        }
        // Class zero can itself be ZK, including a tree without a large aggregation tier.
        let single_shape = TreeShape {
            leaf: zk_class.shape,
            claims: Some(ClaimShape::new(Capacity { claims: 8, groups: 4 })),
            ..shape
        };
        let single = Tree::mixed_classes(&[zk_class], single_shape).unwrap();
        let first = single.aggregate_programs_at(0, &[zk_leaf], None).unwrap();
        single.verify_claims(&first.proof, &first.claims).unwrap();
        assert!(single.aggregate(&[&raw_first(&single, 0, zk_leaf)], None).is_err());
        // Distinct ZK classes keep distinct fixed roots, even when their leaf shapes coincide.
        let pair_classes = [zk_class, zk_class];
        let pair = Tree::mixed_classes(&pair_classes, single_shape).unwrap();
        let a = pair.aggregate_programs_at(0, &[zk_leaf], None).unwrap();
        let b = pair.aggregate_programs_at(1, &[zk_leaf], None).unwrap();
        let root = pair.aggregate(&[&a, &b], None).unwrap();
        let sealer = pair.seal_prover().unwrap();
        let roots = sealer.roots();
        let seal = pair.seal(&sealer, &root.proof).unwrap();
        let pair_bytes = pair.mixed_verifier_bytes(&roots).unwrap();
        let pair_digest = Tree::mixed_class_key_digest(&pair_bytes);
        let loaded = Tree::mixed_classes_from_bytes(&pair_classes, single_shape, &pair_bytes, &pair_digest).unwrap();
        assert!(matches!(
            loaded.verify_claims(&root.proof, &root.claims),
            Err(TreeError::SealRequired)
        ));
        loaded
            .verify_claims_sealed(&root.proof, &root.claims, &roots, &seal)
            .unwrap();
        let mut wrong_classes = classes;
        wrong_classes[2].shape = plain_class.shape;
        assert!(Tree::mixed_classes_from_bytes(&wrong_classes, shape, &bytes, &digest).is_err());
    }

    #[test]
    fn public_zk_placement_round_trips_and_pins_the_caller() {
        let members = [[1, 2, 3, 4]];
        let (program, plain) = class(&program(&members), &[37]);
        let hidden = LeafClass {
            shape: plain.shape.zero_knowledge(),
            ..plain
        };
        let classes = [plain, hidden];
        let run = hidden.program.prover(hidden.shape).prove(&program, &[37]).unwrap();
        let leaf = MixedLeaf {
            key: program.verifying_key(),
            proof: &run.proof,
            output: run.output,
            members: &members,
        };
        let other_members = [[9, 10, 11, 12]];
        let other_program = plain.program.normalize(&self::program(&other_members)).unwrap();
        let other_run = plain.program.prover(plain.shape).prove(&other_program, &[37]).unwrap();
        let other_leaf = MixedLeaf {
            key: other_program.verifying_key(),
            proof: &other_run.proof,
            output: other_run.output,
            members: &other_members,
        };
        for small in [
            None,
            Some(Tier {
                arity: 2,
                capacity: Capacity { claims: 2, groups: 2 },
            }),
        ] {
            let shape = TreeShape {
                leaf: plain.shape,
                arity_0: 1,
                arity: 2,
                rate: Rate::MIN,
                claims: Some(ClaimShape {
                    capacity: Capacity { claims: 8, groups: 4 },
                    small,
                }),
            };
            for placement in [ZkPlacement::Shared, ZkPlacement::Isolated] {
                let tree = Tree::mixed_classes_with(&classes, shape, placement).unwrap();
                let isolated = placement == ZkPlacement::Isolated;
                assert_eq!(
                    tree.design.tiers.len(),
                    1 + usize::from(small.is_some()) + usize::from(isolated)
                );
                assert_eq!(
                    tree.design.places.iter().any(|p| matches!(p.level, Level::LeafWrap(_))),
                    isolated
                );
                let first = tree.aggregate_programs_at(1, &[leaf], None).unwrap();
                let root = tree.aggregate(&[&first, &first], None).unwrap();
                let wide = small.map(|_| {
                    let second = tree.aggregate_programs_at(0, &[other_leaf], None).unwrap();
                    let large = tree.aggregate(&[&first, &second], None).unwrap();
                    assert_eq!(tree.design.places[tree.known(&large.proof).unwrap()].tier, LARGE);
                    // Feeding a LARGE child through another Node exercises its SMALL Wrap too.
                    tree.aggregate(&[&large, &first], None).unwrap()
                });
                let prover = tree.seal_prover().unwrap();
                let roots = prover.roots();
                let bytes = tree.mixed_verifier_bytes(&roots).unwrap();
                let digest = Tree::mixed_class_key_digest(&bytes);
                for trusted in [false, true] {
                    let load = |p| {
                        if trusted {
                            Tree::mixed_classes_from_trusted_bytes_with(&classes, shape, p, &bytes, &digest)
                        } else {
                            Tree::mixed_classes_from_bytes_with(&classes, shape, p, &bytes, &digest)
                        }
                    };
                    let loaded = load(placement).unwrap();
                    assert_eq!(loaded.mixed_verifier_bytes(&roots).unwrap(), bytes);
                    let other = if isolated {
                        ZkPlacement::Shared
                    } else {
                        ZkPlacement::Isolated
                    };
                    assert!(matches!(load(other), Err(TreeError::MixedClass)));
                    for root in [&first, &root].into_iter().chain(wide.iter()) {
                        let seal = tree.seal(&prover, &root.proof).unwrap();
                        loaded
                            .verify_claims_sealed(&root.proof, &root.claims, &roots, &seal)
                            .unwrap();
                    }
                }
                if !isolated {
                    let position = tree.known(&root.proof).unwrap();
                    let evaluations = tree.keys[position]
                        .verify_fixed(
                            &root.proof.limbs(),
                            &tree.design.session(),
                            shape.rate,
                            &root.proof.proof,
                            None,
                        )
                        .unwrap();
                    let claims = tree.seal_claims(&root.proof, position, &evaluations).unwrap();
                    assert_eq!(claims.iter().filter(|c| !c.is_empty()).count(), 1);
                }
            }
        }
    }
}
