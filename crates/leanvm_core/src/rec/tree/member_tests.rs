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
        let batch = leansphincs_members_host::batch(&[(&key, &messages[0], &sigs[0]), (&key, &messages[1], &sigs[1])]);
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
        verifier.verify_claims(&root.proof, &root.claims).unwrap();
        verifier
            .verify_claims_sealed(&root.proof, &root.claims, verifier.seal_roots().unwrap(), &seal)
            .unwrap();
    }
    let mut wrong_pin = digest;
    wrong_pin[0] ^= 1;
    let misconfigured = Tree::mixed_classes_from_trusted_bytes(&f.classes, f.tree.shape, &bytes, &wrong_pin).unwrap();
    for first in &firsts {
        let empty = f.tree.seal(&sealer, &first.proof).unwrap();
        misconfigured
            .verify_claims_sealed(&first.proof, &first.claims, &sealer.roots(), &empty)
            .unwrap();
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
    // One-member leaves use precisely the same list convention and union rows.
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

// Deliberately bypass aggregate_programs' list and shape prechecks, then execute the union and reduction rows.
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
