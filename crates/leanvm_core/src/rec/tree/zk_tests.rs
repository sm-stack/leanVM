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
#[ignore = "8-thread monorepo-shape measurement; run explicitly with --nocapture"]
fn measure_mixed_zk_layouts() {
    use bench::Plan;
    use std::{num::NonZeroUsize, time::Duration};
    parallel::init_with_threads(NonZeroUsize::new(8).unwrap()).unwrap();
    let plan = Plan::new(3, Duration::ZERO);
    let rate = Rate::MIN;
    let plain_class = LeafClass {
        program: ProgramClass {
            log_bytecode: 12,
            log_ram: 17,
            log_advice: 13,
            image_words: 64,
            max_members: 128,
        },
        shape: LeafShape::plain(
            crate::PerTable::from_fn(|t: TableId| [16, 8, 8, 10, 10, 10, 8, 6, 6, 8, 6][t.index()]),
            rate,
        )
        .unwrap(),
    };
    let sig_class = LeafClass {
        program: ProgramClass {
            log_bytecode: 13,
            log_ram: 17,
            log_advice: 16,
            image_words: 64,
            max_members: 128,
        },
        shape: LeafShape::plain(
            crate::PerTable::from_fn(|t: TableId| [20, 4, 15, 18, 18, 16, 4, 4, 4, 16, 3][t.index()]),
            rate,
        )
        .unwrap(),
    };
    let zk_class = LeafClass {
        shape: plain_class.shape.zero_knowledge(),
        ..plain_class
    };
    let members: Vec<_> = (0..16).map(|i| [i, 17, 18, 19]).collect();
    let program = plain_class.program.normalize(&program(&members)).unwrap();
    let signed: Vec<_> = (0..100u64)
        .map(|i| {
            let mut seed = [0; 32];
            seed[..8].copy_from_slice(&i.to_le_bytes());
            let (sk, pk) = leansphincs::key_gen(seed);
            let message = [7, 8, 9, i];
            let signature = sk.sign(&message).unwrap();
            (pk, message, signature)
        })
        .collect();
    let triples: Vec<_> = signed.iter().map(|(k, m, s)| (k, m, s)).collect();
    let batch = leansphincs_members_host::batch(&triples);
    let sig_program = sig_class
        .program
        .normalize(&Program::from_elf(leansphincs_members_host::ELF).unwrap())
        .unwrap();
    let (hidden, timing) =
        plan.warm_then_measure(|| zk_class.program.prover(zk_class.shape).prove(&program, &[41]).unwrap());
    println!(
        "ZK_LEAF ms={} bytes={}",
        timing.mean() * 1000.,
        hidden.proof.to_bytes().len()
    );
    let plain = plain_class
        .program
        .prover(plain_class.shape)
        .prove(&program, &[37])
        .unwrap();
    let sig = sig_class
        .program
        .prover(sig_class.shape)
        .prove(&sig_program, &batch.run.advice)
        .unwrap();
    for log_rate in [2, 3] {
        let shape = LeafShape::plain(plain_class.shape.heights(), Rate::new(log_rate).unwrap())
            .unwrap()
            .zero_knowledge();
        let (run, timing) =
            plan.warm_then_measure(|| plain_class.program.prover(shape).prove(&program, &[41]).unwrap());
        program.verifying_key().verify(run.output, &run.proof).unwrap();
        println!(
            "ZK_RATE log_rate={log_rate} ms={} bytes={}",
            timing.mean() * 1000.,
            run.proof.to_bytes().len()
        );
    }
    let leaves = [
        MixedLeaf {
            key: program.verifying_key(),
            proof: &plain.proof,
            output: plain.output,
            members: &members,
        },
        MixedLeaf {
            key: sig_program.verifying_key(),
            proof: &sig.proof,
            output: sig.output,
            members: &batch.members,
        },
        MixedLeaf {
            key: program.verifying_key(),
            proof: &hidden.proof,
            output: hidden.output,
            members: &members,
        },
    ];
    for (name, classes, split) in [
        ("plain", vec![plain_class, sig_class], true),
        ("shared-zk", vec![plain_class, sig_class, zk_class], false),
        ("isolated-zk", vec![plain_class, sig_class, zk_class], true),
    ] {
        let shape = TreeShape {
            leaf: plain_class.shape,
            arity_0: 1,
            arity: 2,
            rate,
            claims: Some(ClaimShape {
                capacity: Capacity {
                    claims: 16385,
                    groups: 1024,
                },
                small: Some(Tier {
                    arity: 2,
                    capacity: Capacity {
                        claims: 257,
                        groups: 64,
                    },
                }),
            }),
        };
        let placeholder = Tree::mixed_placeholder(classes[0].program).unwrap();
        let extra: Vec<_> = classes[1..]
            .iter()
            .map(|c| {
                (
                    Tree::mixed_placeholder(c.program).unwrap(),
                    c.shape,
                    c.program.max_members,
                )
            })
            .collect();
        let tree = Tree::build_zk_mode(&placeholder, shape, Some(128), &extra, split).unwrap();
        println!("MODE {name}");
        for (i, place) in tree.design.places.iter().enumerate() {
            let stats = tree.circuit_stats(i);
            println!(
                "CIRCUIT level={:?} tier={} committed={} tables={:?}",
                place.level,
                place.tier,
                stats.committed,
                stats
                    .tables
                    .iter()
                    .map(|t| (t.name, t.rows, t.height_log))
                    .collect::<Vec<_>>()
            );
        }
        let (first, t0) = plan.warm_then_measure(|| tree.aggregate_programs_at(0, &[leaves[0]], None).unwrap());
        let (signed, t1) = plan.warm_then_measure(|| tree.aggregate_programs_at(1, &[leaves[1]], None).unwrap());
        let (plain_root, fold) = plan.warm_then_measure(|| tree.aggregate(&[&first, &signed], None).unwrap());
        println!(
            "PLAIN first_ms={} signature_ms={} fold_ms={}",
            t0.mean() * 1000.,
            t1.mean() * 1000.,
            fold.mean() * 1000.
        );
        let root = if classes.len() == 3 {
            let (raw, first_time) = plan.warm_then_measure(|| raw_first(&tree, 2, leaves[2]));
            let wrapped = if split {
                let tier = tree.design.places[tree.known(&raw.proof).unwrap()].tier;
                let (wrapped, timing) =
                    plan.warm_then_measure(|| tree.wrap_at(0, &raw, Level::LeafWrap(2), tier).unwrap());
                println!("WRAP ms={}", timing.mean() * 1000.);
                wrapped
            } else {
                raw
            };
            println!("ZK_FIRST ms={}", first_time.mean() * 1000.);
            tree.aggregate(&[&plain_root, &wrapped], None).unwrap()
        } else {
            plain_root
        };
        let sealer = tree.seal_prover().unwrap();
        let roots = sealer.roots();
        let key = tree.mixed_verifier_bytes(&roots).unwrap();
        let pin = Tree::mixed_class_key_digest(&key);
        let seal = tree.seal(&sealer, &root.proof).unwrap();
        let (_, direct) = plan.warm_then_measure(|| tree.verify_claims(&root.proof, &root.claims).unwrap());
        let (_, sealed) = plan.warm_then_measure(|| {
            tree.verify_claims_sealed(&root.proof, &root.claims, &roots, &seal)
                .unwrap();
        });
        println!(
            "KEY bytes={} digest={}",
            key.len(),
            pin.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        println!(
            "VERIFY direct_ms={} sealed_ms={} root_bytes={} seal_bytes={}",
            direct.mean() * 1000.,
            sealed.mean() * 1000.,
            root.proof.to_bytes().len(),
            seal.to_bytes().len()
        );
    }
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
