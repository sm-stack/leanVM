//! Export mixed-program roots and compare their class-fixed native costs.

use bench::Plan;
use leanvm::aggregate::{
    Capacity, ClaimSet, ClaimShape, Leaf, LeafShape, MixedLeaf, ProgramClass, Tree, TreeProof, TreeShape,
};
use leanvm::asm::{Asm, Reg};
use leanvm::{PerTable, Program, ProofTranscript, Rate, Region, TableId};
use std::num::NonZeroUsize;
use std::path::Path;
use std::time::Duration;

#[global_allocator]
static ALLOCATOR: bench::Jemalloc = bench::Jemalloc;

fn write_class(path: &Path, class: ProgramClass, shape: TreeShape) {
    let capacity = shape.claims.unwrap().capacity;
    let words = [
        2,
        class.log_bytecode as u64,
        class.log_ram as u64,
        class.log_advice as u64,
        class.image_words as u64,
        u64::from(shape.leaf.rate().log_inv_rate()),
        shape.arity_0 as u64,
        shape.arity as u64,
        u64::from(shape.rate.log_inv_rate()),
        capacity.claims as u64,
        capacity.groups as u64,
    ];
    let words = words
        .into_iter()
        .chain(shape.leaf.heights().into_values().map(|h| h as u64))
        .chain([class.max_members as u64]);
    std::fs::write(path, words.flat_map(u64::to_le_bytes).collect::<Vec<_>>()).unwrap();
}

fn read_class(path: &Path) -> (ProgramClass, TreeShape) {
    let bytes = std::fs::read(path).unwrap();
    let (chunks, rest) = bytes.as_chunks::<8>();
    assert!(rest.is_empty());
    let words: Vec<_> = chunks
        .iter()
        .map(|&w| usize::try_from(u64::from_le_bytes(w)).unwrap())
        .collect();
    assert_eq!(words.len(), 12 + leanvm::N_TABLES);
    assert_eq!(words[0], 2);
    let class = ProgramClass {
        max_members: words[11 + leanvm::N_TABLES],
        log_bytecode: words[1],
        log_ram: words[2],
        log_advice: words[3],
        image_words: words[4],
    };
    let rate = |word: usize| Rate::new(u8::try_from(word).unwrap()).unwrap();
    let heights = PerTable::from_fn(|t: TableId| words[11 + t.index()]);
    let shape = TreeShape {
        leaf: LeafShape::plain(heights, rate(words[5])).unwrap(),
        arity_0: words[6],
        arity: words[7],
        rate: rate(words[8]),
        claims: Some(ClaimShape {
            capacity: Capacity {
                claims: words[9],
                groups: words[10],
            },
            small: None,
        }),
    };
    (class, shape)
}

fn main() {
    parallel::init_with_threads(NonZeroUsize::new(16).unwrap()).unwrap();
    let args: Vec<_> = std::env::args().collect();
    let plan = Plan::new(3, Duration::ZERO);
    if args.get(1).is_some_and(|a| a == "--verify") {
        let path = Path::new(args.get(2).expect("directory"));
        let parent = path.parent().expect("case directory inside class directory");
        let (class, shape) = read_class(&parent.join("class.bin"));
        let key = std::fs::read(parent.join("class-key.bin")).unwrap();
        let hex = args.get(3).expect("pinned class-key digest (64 hex characters)");
        assert_eq!(hex.len(), 64);
        let pin: [u8; 32] = std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap());
        let (tree, load) = plan.warm_then_measure(|| Tree::mixed_from_bytes(class, shape, &key, &pin).unwrap());
        let proof = TreeProof::from_bytes(&std::fs::read(path.join("root.bin")).unwrap()).unwrap();
        let claims = ClaimSet::from_bytes(&std::fs::read(path.join("claims.bin")).unwrap()).unwrap();
        let seal = ProofTranscript::from_bytes(&std::fs::read(path.join("seal.bin")).unwrap()).unwrap();
        let (_, direct) = plan.warm_then_measure(|| tree.verify_claims(&proof, &claims).unwrap());
        let (_, sealed) = plan.warm_then_measure(|| {
            tree.verify_claims_sealed(&proof, &claims, tree.seal_roots().unwrap(), &seal)
                .unwrap();
        });
        println!(
            "class_key_bytes={} load_ms={:.4} direct_ms={:.4} sealed_ms={:.4}",
            key.len(),
            load.mean() * 1000.0,
            direct.mean() * 1000.0,
            sealed.mean() * 1000.0
        );
        return;
    }
    let directory = Path::new(args.get(1).map_or("mixed-program-tree", String::as_str));
    let fibonacci = Program::from_elf(include_bytes!(
        "../../../programs/fibonacci-members/fibonacci-members.elf"
    ))
    .unwrap();
    let preimage = Program::from_elf(include_bytes!(
        "../../../programs/preimage-members/preimage-members.elf"
    ))
    .unwrap();
    let constant = |value| {
        let output = leanvm_guest::members::output(&[[value, 0, 0, 0]]);
        let mut asm = Asm::new();
        for (r, v) in [Reg::A0, Reg::A1, Reg::A2, Reg::A3].into_iter().zip(output) {
            asm.li(r, v);
        }
        let text = asm.exit().finish();
        Program::new(&text, Region::TEXT.base(), vec![], 0, 0).unwrap()
    };
    let originals = [fibonacci, preimage, constant(17), constant(19)];
    let class = ProgramClass {
        max_members: 4,
        log_bytecode: originals
            .iter()
            .map(|p| p.rv().entries().len().ilog2() as usize)
            .max()
            .unwrap(),
        log_ram: originals.iter().map(|p| p.rv().log_ram()).max().unwrap(),
        log_advice: originals.iter().map(|p| p.rv().log_advice()).max().unwrap(),
        image_words: originals
            .iter()
            .map(|p| p.rv().image().len())
            .max()
            .unwrap()
            .next_power_of_two(),
    };
    let programs: Vec<_> = originals.iter().map(|p| class.normalize(p).unwrap()).collect();
    let mut stats = programs[0].measure(&[2703]).unwrap();
    for (i, p) in programs.iter().enumerate().skip(1) {
        let other = p.measure(if i == 1 { &[8, 7] } else { &[] }).unwrap();
        stats.counts = PerTable::from_fn(|t| stats.counts[t].max(other.counts[t]));
    }
    stats.counts[TableId::ALU] *= 2;
    let leaf = LeafShape::measured(&stats, Rate::MIN);
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
    let prover = class.prover(leaf);
    let (tree, setup) = plan.warm_then_measure(|| Tree::mixed(class, shape).unwrap());
    println!(
        "mixed class_setup_ms={:.4} first_committed={} node_committed={}",
        setup.mean() * 1000.0,
        tree.stats(leanvm::aggregate::Kind::First).committed,
        tree.stats(leanvm::aggregate::Kind::Node).committed
    );
    let (sealer, commitment_time) = plan.warm_then_measure(|| tree.seal_prover().unwrap());
    let roots = sealer.roots();
    let key = tree.mixed_verifier_bytes(&roots).unwrap();
    let pin = Tree::mixed_class_key_digest(&key);
    let pin_hex: String = pin.iter().map(|b| format!("{b:02x}")).collect();
    let (verifier, load) = plan.warm_then_measure(|| Tree::mixed_from_bytes(class, shape, &key, &pin).unwrap());
    std::fs::create_dir_all(directory).unwrap();
    write_class(&directory.join("class.bin"), class, shape);
    std::fs::write(directory.join("class-key.bin"), &key).unwrap();
    std::fs::write(directory.join("class-key.digest"), &pin_hex).unwrap();
    println!(
        "class_key_bytes={} load_ms={:.4} seal_commit_ms={:.4} class_digest={pin_hex}",
        key.len(),
        load.mean() * 1000.0,
        commitment_time.mean() * 1000.0
    );
    for distinct in [1, 2, 4] {
        let indices: Vec<_> = (0..4).map(|i| i % distinct).collect();
        let runs: Vec<_> = indices
            .iter()
            .enumerate()
            .map(|(i, &p)| {
                let advice = match p {
                    0 => vec![2700 + i as u64],
                    1 => vec![8, 7 + i as u64],
                    _ => vec![],
                };
                prover.prove(&programs[p], &advice).unwrap()
            })
            .collect();
        let members: Vec<_> = indices
            .iter()
            .enumerate()
            .map(|(i, &p)| match p {
                0 => {
                    let n = 2700 + i as u64;
                    let (mut a, mut b) = (0u64, 1u64);
                    for _ in 0..n {
                        (a, b) = (b, a.wrapping_add(b));
                    }
                    let mut v = leanvm_guest::PublicValues::new();
                    v.commit(&[n, a]);
                    v.digest()
                }
                1 => {
                    let mut h = leanvm_guest::Blake2s::new();
                    h.update(&(7 + i as u64).to_le_bytes());
                    let mut v = leanvm_guest::PublicValues::new();
                    v.commit(&h.finalize_words());
                    v.digest()
                }
                _ => [if p == 2 { 17 } else { 19 }, 0, 0, 0],
            })
            .collect();
        let leaves: Vec<_> = runs
            .iter()
            .zip(&indices)
            .zip(&members)
            .map(|((r, &p), member)| MixedLeaf {
                members: std::slice::from_ref(member),
                key: programs[p].verifying_key(),
                proof: &r.proof,
                output: r.output,
            })
            .collect();
        let (firsts, first_time) = plan.warm_then_measure(|| {
            [
                tree.aggregate_programs(&leaves[..2], None).unwrap(),
                tree.aggregate_programs(&leaves[2..], None).unwrap(),
            ]
        });
        let (root, node_time) = plan.warm_then_measure(|| tree.aggregate(&[&firsts[0], &firsts[1]], None).unwrap());
        let (_, verify) = Plan::new(7, Duration::ZERO)
            .warm_then_measure(|| verifier.verify_claims(&root.proof, &root.claims).unwrap());
        let path = directory.join(format!("distinct-{distinct}"));
        std::fs::create_dir_all(&path).unwrap();
        let (seal, seal_time) = plan.warm_then_measure(|| tree.seal(&sealer, &root.proof).unwrap());
        let (_, sealed_time) = plan.warm_then_measure(|| {
            verifier
                .verify_claims_sealed(&root.proof, &root.claims, &roots, &seal)
                .unwrap();
        });
        let seal_bytes = seal.to_bytes();
        std::fs::write(path.join("seal.bin"), &seal_bytes).unwrap();
        println!(
            "distinct={distinct} seal_ms={:.4} seal_bytes={} direct_ms={:.4} sealed_ms={:.4}",
            seal_time.mean() * 1000.0,
            seal_bytes.len(),
            verify.mean() * 1000.0,
            sealed_time.mean() * 1000.0
        );
        std::fs::write(path.join("root.bin"), root.proof.to_bytes()).unwrap();
        std::fs::write(path.join("claims.bin"), root.claims.to_bytes()).unwrap();
        println!(
            "mixed distinct={distinct} claims={} first_ms_per_node={:.4} node_ms={:.4} root_bytes={} verify_ms={:.4} verify_ci={} settled_program_polynomials=0",
            root.claims.n_claims(),
            first_time.mean() * 500.0,
            node_time.mean() * 1000.0,
            root.proof.to_bytes().len(),
            verify.mean() * 1000.0,
            verify.spread()
        );
        if distinct == 1 {
            let positional = TreeShape { claims: None, ..shape };
            let (same, same_setup) = plan.warm_then_measure(|| Tree::new(&programs[0], positional).unwrap());
            let leaves: Vec<_> = runs.iter().map(|r| Leaf::new(&r.proof, r.output)).collect();
            let (firsts, first_time) = plan.warm_then_measure(|| {
                [
                    same.prove_first(&leaves[..2]).unwrap(),
                    same.prove_first(&leaves[2..]).unwrap(),
                ]
            });
            let (root, node_time) = plan.warm_then_measure(|| same.prove_node(&firsts).unwrap());
            let outputs: Vec<_> = runs.iter().map(|r| r.output).collect();
            let (_, verify) = plan.warm_then_measure(|| same.verify(&root, &outputs).unwrap());
            println!(
                "same-program positional setup_ms={:.4} first_ms_per_node={:.4} node_ms={:.4} root_bytes={} verify_ms={:.4}",
                same_setup.mean() * 1000.0,
                first_time.mean() * 500.0,
                node_time.mean() * 1000.0,
                root.to_bytes().len(),
                verify.mean() * 1000.0
            );
        }
    }
}
