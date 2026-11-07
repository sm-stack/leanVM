//! Generate or verify conformance fixtures: `fixtures export|verify compact|shared|endian|endian-zk DIRECTORY`.
use std::{num::NonZeroUsize, path::Path};
#[path = "../tests/fixtures/shared_zk.rs"]
mod shared_fixture;

fn main() {
    parallel::init_with_threads(NonZeroUsize::new(2).unwrap()).unwrap();
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        4,
        "fixtures export|verify compact|shared|endian|endian-zk DIRECTORY"
    );
    let verify = match args[1].as_str() {
        "verify" => true,
        "export" => false,
        _ => panic!("expected export or verify"),
    };
    assert!(
        verify || cfg!(target_endian = "little"),
        "fixture generation requires a little-endian prover"
    );
    let dir = Path::new(&args[3]);
    match args[2].as_str() {
        "compact" => compact::run(dir, verify),
        "shared" => shared::run(dir, verify),
        "endian" => endian::run(dir, verify, false),
        "endian-zk" => endian::run(dir, verify, true),
        _ => panic!("unknown fixture suite"),
    }
}

mod compact {
    use leanvm::aggregate::{
        Capacity, ClaimShape, LeafClass, LeafShape, MixedLeaf, ProgramClass, Tier, Tree, TreeShape,
    };
    use leanvm::asm::{Addi, Asm, Bne, Reg};
    use leanvm::{CircuitId, N_CIRCUITS, PerTable, Program, ProofTranscript, Rate, Region, TableId};
    use std::path::Path;
    pub(super) fn run(dir: &Path, verify: bool) {
        let capacity = 16385;
        let rate = Rate::MIN;
        let plain = LeafClass {
            program: ProgramClass {
                log_bytecode: 12,
                log_ram: 17,
                log_advice: 13,
                image_words: 64,
                max_members: 128,
            },
            shape: LeafShape::plain(
                PerTable::from_fn(|t: TableId| [16, 8, 8, 10, 10, 10, 8, 6, 6, 8, 6][t.index()]),
                rate,
            )
            .unwrap(),
        };
        let signature = LeafClass {
            program: ProgramClass {
                log_bytecode: 13,
                log_ram: 17,
                log_advice: 16,
                image_words: 64,
                max_members: 128,
            },
            shape: LeafShape::plain(
                PerTable::from_fn(|t: TableId| [20, 4, 15, 18, 18, 16, 4, 4, 4, 16, 3][t.index()]),
                rate,
            )
            .unwrap(),
        };
        let hidden = LeafClass {
            shape: LeafShape::plain(plain.shape.heights(), Rate::new(2).unwrap())
                .unwrap()
                .zero_knowledge(),
            ..plain
        };
        let classes = [plain, signature, hidden];
        let shape = TreeShape {
            leaf: plain.shape,
            arity_0: 1,
            arity: 2,
            rate,
            claims: Some(ClaimShape {
                capacity: Capacity {
                    claims: capacity,
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
        if verify {
            verify_fixtures(dir, &classes, shape);
            return;
        }
        let tree = Tree::mixed_classes(&classes, shape).unwrap();
        std::fs::create_dir_all(dir).unwrap();
        let sealer = tree.seal_prover().unwrap();
        let roots = sealer.roots();
        let bytes = tree.mixed_verifier_bytes(&roots).unwrap();
        let pin = Tree::mixed_class_key_digest(&bytes);
        std::fs::write(dir.join("class-key.bin"), &bytes).unwrap();
        std::fs::write(dir.join("class-key.digest"), pin).unwrap();
        let verifier = Tree::mixed_classes_from_bytes(&classes, shape, &bytes, &pin).unwrap();
        let mut firsts = Vec::new();
        for i in 0..4u64 {
            let members: Vec<_> = (0..if i == 3 { 16 } else { 128 }).map(|j| [i, j, 2, 3]).collect();
            let mut a = Asm::new();
            a.li(Reg::T0, 9000)
                .label("loop")
                .i(Addi, Reg::T0, Reg::T0, -1)
                .branch(Bne, Reg::T0, Reg::ZERO, "loop");
            for (r, w) in [Reg::A0, Reg::A1, Reg::A2, Reg::A3]
                .into_iter()
                .zip(leanvm_guest::members::output(&members))
            {
                a.li(r, w);
            }
            let p = plain
                .program
                .normalize(&Program::new(&a.exit().finish(), Region::TEXT.base(), vec![], 0, 0).unwrap())
                .unwrap();
            let class = if i == 3 { 2 } else { 0 };
            let run = classes[class]
                .program
                .prover(classes[class].shape)
                .prove(&p, &[])
                .unwrap();
            firsts.push(
                tree.aggregate_programs_at(
                    class,
                    &[MixedLeaf {
                        key: p.verifying_key(),
                        proof: &run.proof,
                        output: run.output,
                        members: &members,
                    }],
                    None,
                )
                .unwrap(),
            );
        }
        let small = tree.aggregate(&[&firsts[0], &firsts[1]], None).unwrap();
        let large = tree.aggregate(&[&small, &firsts[2]], None).unwrap();
        let mixed = tree.aggregate(&[&firsts[0], &firsts[3]], None).unwrap();
        let cases = [
            ("plain-small", &small),
            ("plain-large", &large),
            ("mixed-zk", &mixed),
            ("one-zk", &firsts[3]),
        ];
        let mut manifest = String::from("name\texpected\tkey\tdigest\troot\tclaims\tseal\n");
        for (name, root) in cases {
            let seal = tree.seal(&sealer, &root.proof).unwrap();
            verifier
                .verify_claims_sealed(&root.proof, &root.claims, &roots, &seal)
                .unwrap();
            let case = dir.join(name);
            std::fs::create_dir_all(&case).unwrap();
            std::fs::write(case.join("root.bin"), root.proof.to_bytes()).unwrap();
            std::fs::write(case.join("claims.bin"), root.claims.to_bytes()).unwrap();
            std::fs::write(case.join("seal.bin"), seal.to_bytes()).unwrap();
            manifest.push_str(&format!(
                "{name}\taccept\tclass-key.bin\tclass-key.digest\t{name}/root.bin\t{name}/claims.bin\t{name}/seal.bin\n"
            ));
        }
        let base = dir.join("plain-small");
        let seal = ProofTranscript::from_bytes(&std::fs::read(base.join("seal.bin")).unwrap()).unwrap();
        let count = u64::from_le_bytes(seal.narg[..8].try_into().unwrap()) as usize;
        let prefix = 8 + 24 * count;
        let mut dropped = seal.clone();
        dropped.narg.truncate(prefix);
        dropped.hints.clear();
        let mut added = seal.clone();
        added.narg.extend_from_slice(&seal.narg[prefix..]);
        added.hints.extend_from_slice(&seal.hints);
        std::fs::write(dir.join("opening-dropped.bin"), dropped.to_bytes()).unwrap();
        std::fs::write(dir.join("opening-added.bin"), added.to_bytes()).unwrap();
        let mut root = std::fs::read(base.join("root.bin")).unwrap();
        let words = u32::from_le_bytes(root[7..11].try_into().unwrap()) as usize;
        let tiers = 3;
        let usage = words - 2 * CircuitId::MAX_K_LOG - 2 * N_CIRCUITS - tiers;
        root[11 + 24 * (usage + 2)] ^= 1;
        std::fs::write(dir.join("tier-bit-flipped.bin"), root).unwrap();
        let mut wrong = pin;
        wrong[0] ^= 1;
        std::fs::write(dir.join("wrong.digest"), wrong).unwrap();
        for (name, digest, root, seal) in [
            (
                "opening-dropped",
                "class-key.digest",
                "plain-small/root.bin",
                "opening-dropped.bin",
            ),
            (
                "opening-added",
                "class-key.digest",
                "plain-small/root.bin",
                "opening-added.bin",
            ),
            (
                "tier-bit-flipped",
                "class-key.digest",
                "tier-bit-flipped.bin",
                "plain-small/seal.bin",
            ),
            (
                "wrong-digest",
                "wrong.digest",
                "plain-small/root.bin",
                "plain-small/seal.bin",
            ),
        ] {
            manifest.push_str(&format!(
                "{name}\treject\tclass-key.bin\t{digest}\t{root}\tplain-small/claims.bin\t{seal}\n"
            ));
        }
        std::fs::write(dir.join("verdicts.tsv"), manifest).unwrap();
        verify_fixtures(dir, &classes, shape);
    }

    fn verify_fixtures(dir: &Path, classes: &[LeafClass], shape: TreeShape) {
        use leanvm::aggregate::{ClaimSet, TreeProof};
        for line in std::fs::read_to_string(dir.join("verdicts.tsv"))
            .unwrap()
            .lines()
            .skip(1)
        {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 7);
            let read = |i: usize| std::fs::read(dir.join(fields[i])).unwrap();
            let pin: [u8; 32] = read(3).try_into().unwrap();
            let tree = Tree::mixed_classes_from_trusted_bytes(classes, shape, &read(2), &pin).unwrap();
            let root = TreeProof::from_bytes(&read(4)).unwrap();
            let claims = ClaimSet::from_bytes(&read(5)).unwrap();
            let seal = ProofTranscript::from_bytes(&read(6)).unwrap();
            let accepted = tree
                .verify_claims_sealed(&root, &claims, tree.seal_roots().unwrap(), &seal)
                .is_ok();
            assert_eq!(accepted, fields[1] == "accept", "{}", fields[0]);
            println!("FIXTURE {} {}", fields[0], fields[1]);
        }
    }
}

mod shared {
    use super::shared_fixture as fixture;
    use leanvm::aggregate::{MixedLeaf, Tree, ZkPlacement};
    use leanvm::asm::{Addi, Asm, Bne, Reg};
    use leanvm::{CircuitId, N_CIRCUITS, Program, ProofTranscript, Region};
    use std::path::Path;

    pub(super) fn run(dir: &Path, verify: bool) {
        if verify {
            fixture::verify(dir);
            return;
        }
        std::fs::create_dir_all(dir).unwrap();
        let (classes, shape) = fixture::config();
        let mut leaves = Vec::new();
        // Eight 64-member plain leaves, four 100-signature leaves, four 64-member ZK leaves: 1168 claims.
        for i in 0..16u64 {
            let class = if i < 8 {
                0
            } else if i < 12 {
                1
            } else {
                2
            };
            let (program, advice, members) = if class == 1 {
                let triples: Vec<_> = (0..100u64)
                    .map(|j| {
                        let mut seed = [0; 32];
                        seed[..8].copy_from_slice(&(100 * i + j).to_le_bytes());
                        let (sk, pk) = leansphincs::key_gen(seed);
                        let message = [i, j, 2, 3];
                        let signature = sk.sign(&message).unwrap();
                        (pk, message, signature)
                    })
                    .collect();
                let refs: Vec<_> = triples.iter().map(|(k, m, s)| (k, m, s)).collect();
                let batch = leansphincs_members_host::batch(&refs);
                (
                    Program::from_elf(leansphincs_members_host::ELF).unwrap(),
                    batch.run.advice,
                    batch.members,
                )
            } else {
                let members: Vec<_> = (0..64).map(|j| [i, j, 2, 3]).collect();
                let mut a = Asm::new();
                a.li(Reg::T0, 9000)
                    .label("loop")
                    .i(Addi, Reg::T0, Reg::T0, -1)
                    .branch(Bne, Reg::T0, Reg::ZERO, "loop");
                for (r, w) in [Reg::A0, Reg::A1, Reg::A2, Reg::A3]
                    .into_iter()
                    .zip(leanvm_guest::members::output(&members))
                {
                    a.li(r, w);
                }
                (
                    Program::new(&a.exit().finish(), Region::TEXT.base(), vec![], 0, 0).unwrap(),
                    vec![],
                    members,
                )
            };
            let program = classes[class].program.normalize(&program).unwrap();
            let run = classes[class]
                .program
                .prover(classes[class].shape)
                .prove(&program, &advice)
                .unwrap();
            leaves.push((class, program, run, members));
        }
        for placement in [ZkPlacement::Isolated, ZkPlacement::Shared] {
            let tree = Tree::mixed_classes_with(&classes, shape, placement).unwrap();
            let sealer = tree.seal_prover().unwrap();
            let roots = sealer.roots();
            let bytes = tree.mixed_verifier_bytes(&roots).unwrap();
            let digest = Tree::mixed_class_key_digest(&bytes);
            let mut root = None;
            for (class, program, run, members) in &leaves {
                let leaf = MixedLeaf {
                    key: program.verifying_key(),
                    proof: &run.proof,
                    output: run.output,
                    members,
                };
                let first = tree.aggregate_programs_at(*class, &[leaf], None).unwrap();
                root = Some(match root {
                    None => first,
                    Some(previous) => tree.aggregate(&[&previous, &first], None).unwrap(),
                });
            }
            let root = root.unwrap();
            assert_eq!(root.claims.claims().count(), 1168);
            assert_eq!(root.claims.groups.len(), 13);
            let seal = tree.seal(&sealer, &root.proof).unwrap();
            let verifier = Tree::mixed_classes_from_bytes_with(&classes, shape, placement, &bytes, &digest).unwrap();
            verifier
                .verify_claims_sealed(&root.proof, &root.claims, &roots, &seal)
                .unwrap();
            if placement == ZkPlacement::Isolated {
                std::fs::write(dir.join("isolated-key.bin"), bytes).unwrap();
                std::fs::write(dir.join("isolated-key.digest"), digest).unwrap();
                continue;
            }
            std::fs::write(dir.join("class-key.bin"), bytes).unwrap();
            std::fs::write(dir.join("class-key.digest"), digest).unwrap();
            std::fs::write(dir.join("root.bin"), root.proof.to_bytes()).unwrap();
            std::fs::write(dir.join("claims.bin"), root.claims.to_bytes()).unwrap();
            std::fs::write(dir.join("seal.bin"), seal.to_bytes()).unwrap();
            let mut wrong = digest;
            wrong[0] ^= 1;
            std::fs::write(dir.join("wrong.digest"), wrong).unwrap();
            let mut bad_root = root.proof.to_bytes();
            let words = u32::from_le_bytes(bad_root[7..11].try_into().unwrap()) as usize;
            let usage = words - 2 * CircuitId::MAX_K_LOG - 2 * N_CIRCUITS - 1;
            bad_root[11 + 24 * usage] ^= 1;
            std::fs::write(dir.join("tier-bit-flipped.bin"), bad_root).unwrap();
            let mut dropped = seal.clone();
            let count = u64::from_le_bytes(dropped.narg[..8].try_into().unwrap()) as usize;
            dropped.narg.truncate(8 + 24 * count);
            dropped.hints.clear();
            std::fs::write(dir.join("opening-dropped.bin"), dropped.to_bytes()).unwrap();
            assert!(ProofTranscript::from_bytes(&dropped.to_bytes()).is_some());
        }
        std::fs::write(
            dir.join("verdicts.tsv"),
            concat!(
                "name\texpected\tkey\tdigest\troot\tclaims\tseal\n",
                "mixed\taccept\tclass-key.bin\tclass-key.digest\troot.bin\tclaims.bin\tseal.bin\n",
                "isolated-key\treject\tisolated-key.bin\tisolated-key.digest\troot.bin\tclaims.bin\tseal.bin\n",
                "tier-bit-flipped\treject\tclass-key.bin\tclass-key.digest\ttier-bit-flipped.bin\tclaims.bin\tseal.bin\n",
                "opening-dropped\treject\tclass-key.bin\tclass-key.digest\troot.bin\tclaims.bin\topening-dropped.bin\n",
                "wrong-digest\treject\tclass-key.bin\twrong.digest\troot.bin\tclaims.bin\tseal.bin\n"
            ),
        )
        .unwrap();
        fixture::verify(dir);
    }
}

mod endian {
    use leanvm::aggregate::{
        Capacity, ClaimSet, ClaimShape, LeafClass, LeafShape, MixedLeaf, ProgramClass, Tree, TreeProof, TreeShape,
    };
    use leanvm::asm::{Addi, Asm, Bne, Reg};
    use leanvm::{Output, Program, Proof, ProofTranscript, Rate, Region, TableId, VerifyingKey};
    use std::path::Path;

    pub(super) fn run(path: &Path, verify: bool, zk: bool) {
        let members = [[0x0123_4567_89ab_cdef, 2, 3, 4], [5, 6, 7, 8]];
        let output = Output::new(leanvm_guest::members::output(&members));
        let mut asm = Asm::new();
        asm.li(Reg::T0, 9000)
            .label("loop")
            .i(Addi, Reg::T0, Reg::T0, -1)
            .branch(Bne, Reg::T0, Reg::ZERO, "loop");
        for (reg, &word) in [Reg::A0, Reg::A1, Reg::A2, Reg::A3].into_iter().zip(output.words()) {
            asm.li(reg, word);
        }
        let program = Program::new(&asm.exit().finish(), Region::TEXT.base(), vec![], 0, 0).unwrap();
        let class = ProgramClass {
            log_bytecode: (program.rv().entries().len().ilog2() as usize).max(10),
            log_ram: program.rv().log_ram(),
            log_advice: program.rv().log_advice(),
            image_words: 1,
            max_members: 2,
        };
        let program = class.normalize(&program).unwrap();
        let mut stats = program.measure(&[]).unwrap();
        stats.counts[TableId::ALU] *= 2;
        let leaf = LeafShape::measured(&stats, Rate::MIN);
        let mut classes = vec![LeafClass {
            program: class,
            shape: leaf,
        }];
        if zk {
            classes.push(LeafClass {
                program: class,
                shape: leaf.zero_knowledge(),
            });
        }
        let selected = usize::from(zk);
        let shape = TreeShape {
            leaf,
            arity_0: 1,
            arity: 2,
            rate: Rate::MIN,
            claims: Some(ClaimShape {
                capacity: Capacity { claims: 8, groups: 2 },
                small: None,
            }),
        };
        let read = |name| std::fs::read(path.join(name)).unwrap();
        if !verify {
            std::fs::create_dir_all(path).unwrap();
            let write = |name, bytes| std::fs::write(path.join(name), bytes).unwrap();
            let run = class.prover(classes[selected].shape).prove(&program, &[]).unwrap();
            let tree = Tree::mixed_classes(&classes, shape).unwrap();
            let first = tree
                .aggregate_programs_at(
                    selected,
                    &[MixedLeaf {
                        key: program.verifying_key(),
                        proof: &run.proof,
                        output,
                        members: &members,
                    }],
                    None,
                )
                .unwrap();
            // A node root carries fixed claims; its seal is nonempty.
            let root = tree.aggregate(&[&first, &first], None).unwrap();
            let sealer = tree.seal_prover().unwrap();
            let roots = sealer.roots();
            let key = tree.mixed_verifier_bytes(&roots).unwrap();
            let seal = tree.seal(&sealer, &root.proof).unwrap();
            write("class-key.digest", Tree::mixed_class_key_digest(&key).to_vec());
            write("class-key.bin", key);
            write("root.bin", root.proof.to_bytes());
            write("claims.bin", root.claims.to_bytes());
            write("seal.bin", seal.to_bytes());
            write("program-key.bin", program.verifying_key().to_bytes());
            write("leaf.bin", run.proof.to_bytes());
            write(
                "claim-digest.bin",
                root.claims.digest().into_iter().flat_map(u64::to_le_bytes).collect(),
            );
        }
        let key = read("class-key.bin");
        let pin = read("class-key.digest").try_into().unwrap();
        let proof_bytes = read("root.bin");
        let proof = TreeProof::from_bytes(&proof_bytes).unwrap();
        assert_eq!(proof.to_bytes(), proof_bytes);
        let claim_bytes = read("claims.bin");
        let claims = ClaimSet::from_bytes(&claim_bytes).unwrap();
        assert_eq!(claims.to_bytes(), claim_bytes);
        assert_eq!(
            claims
                .digest()
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>(),
            read("claim-digest.bin")
        );
        let seal_bytes = read("seal.bin");
        let seal = ProofTranscript::from_bytes(&seal_bytes).unwrap();
        assert_eq!(seal.to_bytes(), seal_bytes);
        let vk_bytes = read("program-key.bin");
        let vk = VerifyingKey::from_bytes(&vk_bytes).unwrap();
        assert_eq!(vk.to_bytes(), vk_bytes);
        vk.verify(output, &Proof::from_bytes(&read("leaf.bin")).unwrap())
            .unwrap();
        for tree in [
            Tree::mixed_classes_from_bytes(&classes, shape, &key, &pin).unwrap(),
            Tree::mixed_classes_from_trusted_bytes(&classes, shape, &key, &pin).unwrap(),
        ] {
            assert!(matches!(
                tree.verify_claims(&proof, &claims),
                Err(leanvm::aggregate::TreeError::SealRequired)
            ));
            tree.verify_claims_sealed(&proof, &claims, tree.seal_roots().unwrap(), &seal)
                .unwrap();
            let mut damaged = seal_bytes.clone();
            *damaged.last_mut().unwrap() ^= 1;
            if let Some(damaged) = ProofTranscript::from_bytes(&damaged) {
                assert!(
                    tree.verify_claims_sealed(&proof, &claims, tree.seal_roots().unwrap(), &damaged)
                        .is_err()
                );
            }
        }
        println!("verified leaf and sealed node root; canonical bytes and claim digest agree");
    }
}
