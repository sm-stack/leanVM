//! Reproducible eight-thread class-key/seal measurements and Go-port fixtures.
//! Usage: compact_class_key DIRECTORY [claim-bound=16385] [verify|plain].
//! `plain` measures a two-class control with the private class omitted.
use bench::{Counting, Jemalloc, Plan, measure_heap};
use leanvm::aggregate::{Capacity, ClaimShape, LeafClass, LeafShape, MixedLeaf, ProgramClass, Tier, Tree, TreeShape};
use leanvm::asm::{Addi, Asm, Bne, Reg};
use leanvm::{CircuitId, N_CIRCUITS, PerTable, Program, ProofTranscript, Rate, Region, TableId};
use std::{num::NonZeroUsize, path::Path, time::Duration};
#[global_allocator]
static ALLOCATOR: Counting<Jemalloc> = Counting(Jemalloc);
fn main() {
    parallel::init_with_threads(NonZeroUsize::new(8).unwrap()).unwrap();
    let args: Vec<_> = std::env::args().collect();
    let dir = Path::new(args.get(1).expect("fixture directory"));
    std::fs::create_dir_all(dir).unwrap();
    let capacity = args.get(2).map_or(16385, |s| s.parse().unwrap());
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
    let no_zk = args.get(3).is_some_and(|s| s == "plain");
    let classes = if no_zk {
        vec![plain, signature]
    } else {
        vec![plain, signature, hidden]
    };
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
    if args.get(3).is_some_and(|s| s == "verify") {
        verify_fixtures(dir, &classes, shape);
        return;
    }
    let tree = Tree::mixed_classes(&classes, shape).unwrap();
    let plan = Plan::new(3, Duration::ZERO);
    let sealer = tree.seal_prover().unwrap();
    let roots = sealer.roots();
    let bytes = tree.mixed_verifier_bytes(&roots).unwrap();
    let pin = Tree::mixed_class_key_digest(&bytes);
    std::fs::write(dir.join("class-key.bin"), &bytes).unwrap();
    std::fs::write(dir.join("class-key.digest"), pin).unwrap();
    let (_, load) = plan.warm_then_measure(|| Tree::mixed_classes_from_bytes(&classes, shape, &bytes, &pin).unwrap());
    let (verifier, heap) = measure_heap(|| Tree::mixed_classes_from_bytes(&classes, shape, &bytes, &pin).unwrap());
    let (_, trusted) =
        plan.warm_then_measure(|| Tree::mixed_classes_from_trusted_bytes(&classes, shape, &bytes, &pin).unwrap());
    println!(
        "KEY capacity={capacity} bytes={} digest={} load_ms={} trusted_ms={} load_peak={}",
        bytes.len(),
        pin.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        load.mean() * 1000.,
        trusted.mean() * 1000.,
        heap.peak
    );
    let mut firsts = Vec::new();
    for i in 0..if no_zk { 3u64 } else { 4u64 } {
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
    let mixed = (!no_zk).then(|| tree.aggregate(&[&firsts[0], &firsts[3]], None).unwrap());
    let mut cases = vec![("plain-small", &small), ("plain-large", &large)];
    if let Some(ref mixed) = mixed {
        cases.extend([("mixed-zk", mixed), ("one-zk", &firsts[3])]);
    }
    let mut manifest = String::from("name\texpected\tkey\tdigest\troot\tclaims\tseal\n");
    for (name, root) in cases {
        let (seal, timing) = plan.warm_then_measure(|| tree.seal(&sealer, &root.proof).unwrap());
        let (_, verify) = plan.warm_then_measure(|| {
            verifier
                .verify_claims_sealed(&root.proof, &root.claims, &roots, &seal)
                .unwrap();
        });
        let case = dir.join(name);
        std::fs::create_dir_all(&case).unwrap();
        std::fs::write(case.join("root.bin"), root.proof.to_bytes()).unwrap();
        std::fs::write(case.join("claims.bin"), root.claims.to_bytes()).unwrap();
        std::fs::write(case.join("seal.bin"), seal.to_bytes()).unwrap();
        manifest.push_str(&format!(
            "{name}\taccept\tclass-key.bin\tclass-key.digest\t{name}/root.bin\t{name}/claims.bin\t{name}/seal.bin\n"
        ));
        println!(
            "ROOT name={name} root_bytes={} seal_bytes={} seal_ms={} verify_ms={}",
            root.proof.to_bytes().len(),
            seal.to_bytes().len(),
            timing.mean() * 1000.,
            verify.mean() * 1000.
        );
    }
    if no_zk {
        return;
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
