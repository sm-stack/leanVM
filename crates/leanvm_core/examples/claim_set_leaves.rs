//! Measure member-list trees with two leaf classes and a shared-class comparison.
//! Usage: claim_set_leaves [signatures=100] [claim-bound=4097] [output-directory].
use bench::Plan;
use leanvm::aggregate::{
    Accumulator, Capacity, ClaimShape, LeafClass, LeafShape, MixedLeaf, ProgramClass, Tier, Tree, TreeShape,
};
use leanvm::asm::{Addi, Asm, Bne, Reg};
use leanvm::{PerTable, Program, Rate, Region, TableId};
use std::{num::NonZeroUsize, path::Path, time::Duration};

#[global_allocator]
static ALLOCATOR: bench::Jemalloc = bench::Jemalloc;

fn bounds(p: &Program) -> ProgramClass {
    let s = p.rv();
    ProgramClass {
        log_bytecode: s.entries().len().ilog2() as usize,
        log_ram: s.log_ram(),
        log_advice: s.log_advice(),
        image_words: s.image().len().max(1).next_power_of_two(),
        max_members: 128,
    }
}

fn shape(p: &Program, advice: &[u64]) -> LeafShape {
    let mut stats = p.measure(advice).unwrap();
    println!("leaf cycles={} advice_words={}", stats.cycles(), advice.len());
    stats.counts[TableId::ALU] *= 2;
    LeafShape::measured(&stats, Rate::MIN)
}

fn parts(bytes: &[u8], classes: usize, tiers: usize) {
    let word = |at| usize::try_from(u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())).unwrap();
    let descriptor = 8 + 16 + classes * 144 + 48 + if tiers == 2 { 24 } else { 0 } + 8;
    let roots = 8 + 32 * tiers;
    let templates = 32 * classes;
    let tier_bytes = 8 + 48 * tiers;
    let at = descriptor + roots + templates + tier_bytes;
    let circuits = word(at);
    assert_eq!(at + 8 + circuits * 56, bytes.len());
    println!(
        "key_parts descriptor={descriptor} seal_roots={roots} templates={templates} tiers={tier_bytes} circuits={circuits}"
    );
}

fn main() {
    parallel::init_with_threads(NonZeroUsize::new(16).unwrap()).unwrap();
    let args: Vec<_> = std::env::args().collect();
    let n: usize = args.get(1).map_or(100, |s| s.parse().unwrap());
    let capacity: usize = args.get(2).map_or(4097, |s| s.parse().unwrap());
    assert!((1..=128).contains(&n));
    let directory = Path::new(args.get(3).map_or("claim-set-leaves", String::as_str));
    let signed: Vec<_> = (0..n)
        .map(|i| {
            let mut seed = [0; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let (sk, key) = leansphincs::key_gen(seed);
            let message = [7, 8, 9, i as u64];
            let sig = sk.sign(&message).unwrap();
            (key, message, sig)
        })
        .collect();
    let triples: Vec<_> = signed.iter().map(|(k, m, s)| (k, m, s)).collect();
    let batch = leansphincs_members_host::batch(&triples);
    let originals = [
        Program::from_elf(include_bytes!(
            "../../../programs/fibonacci-members/fibonacci-members.elf"
        ))
        .unwrap(),
        Program::from_elf(leansphincs_members_host::ELF).unwrap(),
    ];
    let small_advice = [2700];
    let advice = [&small_advice[..], &batch.run.advice[..]];
    let mut public = leanvm_guest::PublicValues::new();
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..2700 {
        (a, b) = (b, a.wrapping_add(b));
    }
    public.commit(&[2700, a]);
    let small_members = [public.digest()];
    let members = [&small_members[..], &batch.members[..]];
    let mut classes = Vec::new();
    for (p, advice) in originals.iter().zip(advice) {
        let program = bounds(p);
        let p = program.normalize(p).unwrap();
        classes.push(LeafClass {
            program,
            shape: shape(&p, advice),
        });
    }
    let plan = Plan::new(1, Duration::ZERO);
    for shared in [false, true] {
        let label = if shared { "one-class" } else { "two-class" };
        let mut cs = classes.clone();
        if shared {
            let a = cs[0].program;
            let b = cs[1].program;
            let program = ProgramClass {
                log_bytecode: a.log_bytecode.max(b.log_bytecode),
                log_ram: a.log_ram.max(b.log_ram),
                log_advice: a.log_advice.max(b.log_advice),
                image_words: a.image_words.max(b.image_words),
                max_members: 128,
            };
            let heights = PerTable::from_fn(|t| cs[0].shape.heights()[t].max(cs[1].shape.heights()[t]));
            cs = vec![LeafClass {
                program,
                shape: LeafShape::plain(heights, Rate::MIN).unwrap(),
            }];
        }
        let programs: Vec<_> = originals
            .iter()
            .enumerate()
            .map(|(i, p)| cs[if shared { 0 } else { i }].program.normalize(p).unwrap())
            .collect();
        let shape = TreeShape {
            leaf: cs[0].shape,
            arity_0: 1,
            arity: 2,
            rate: Rate::MIN,
            claims: Some(ClaimShape {
                capacity: Capacity {
                    claims: capacity,
                    groups: 16,
                },
                small: Some(Tier {
                    arity: 2,
                    capacity: Capacity {
                        claims: capacity.min(257),
                        groups: 16,
                    },
                }),
            }),
        };
        println!("START mode={label} signatures={n} claim_bound={capacity} threads=16");
        let (tree, setup) = plan.warm_then_measure(|| Tree::mixed_classes(&cs, shape).expect("class fits"));
        let (sealer, seal_setup) = plan.warm_then_measure(|| tree.seal_prover().unwrap());
        let roots = sealer.roots();
        let key = tree.mixed_verifier_bytes(&roots).unwrap();
        let pin = Tree::mixed_class_key_digest(&key);
        parts(&key, cs.len(), 2);
        let (loaded, load) = plan.warm_then_measure(|| Tree::mixed_classes_from_bytes(&cs, shape, &key, &pin).unwrap());
        let (_, trusted_load) =
            plan.warm_then_measure(|| Tree::mixed_classes_from_trusted_bytes(&cs, shape, &key, &pin).unwrap());
        println!(
            "CLASS mode={label} key_bytes={} setup_ms={:.3} load_ms={:.3} trusted_load_ms={:.3} seal_setup_ms={:.3}",
            key.len(),
            setup.mean() * 1000.,
            load.mean() * 1000.,
            trusted_load.mean() * 1000.,
            seal_setup.mean() * 1000.
        );
        let mut firsts = Vec::new();
        for i in 0..2 {
            let class = if shared { 0 } else { i };
            let prover = cs[class].program.prover(cs[class].shape);
            let (run, time) = plan.warm_then_measure(|| prover.prove(&programs[i], advice[i]).unwrap());
            let leaf = MixedLeaf {
                key: programs[i].verifying_key(),
                proof: &run.proof,
                output: run.output,
                members: members[i],
            };
            let (first, first_time) =
                plan.warm_then_measure(|| tree.aggregate_programs_at(class, &[leaf], None).unwrap());
            println!(
                "LEAF mode={label} index={i} prove_ms={:.3} proof_bytes={} first_ms={:.3} first_bytes={}",
                time.mean() * 1000.,
                run.proof.to_bytes().len(),
                first_time.mean() * 1000.,
                first.proof.to_bytes().len()
            );
            firsts.push(first);
        }
        let mut prefix = tree.aggregate(&[&firsts[0], &firsts[1]], None).unwrap();
        let mut next = firsts[0].clone();
        // Seed two additional user-program groups so the measured fold crosses the small tier's capacity.
        // Their preparation is untimed; the measured small and signature leaf cases above remain unchanged.
        if capacity >= n + 258 {
            for group in 0..2 {
                let members: Vec<_> = (0..128).map(|i| [group + 20, i, 0, 0]).collect();
                let output = leanvm_guest::members::output(&members);
                let mut a = Asm::new();
                a.li(Reg::T0, 8000)
                    .label("loop")
                    .i(Addi, Reg::T0, Reg::T0, -1)
                    .branch(Bne, Reg::T0, Reg::ZERO, "loop");
                for (r, v) in [Reg::A0, Reg::A1, Reg::A2, Reg::A3].into_iter().zip(output) {
                    a.li(r, v);
                }
                let p = Program::new(&a.exit().finish(), Region::TEXT.base(), vec![], 0, 0).unwrap();
                let p = cs[0].program.normalize(&p).unwrap();
                let run = cs[0].program.prover(cs[0].shape).prove(&p, &[]).unwrap();
                next = tree
                    .aggregate_programs_at(
                        0,
                        &[MixedLeaf {
                            key: p.verifying_key(),
                            proof: &run.proof,
                            output: run.output,
                            members: &members,
                        }],
                        None,
                    )
                    .unwrap();
                if group == 0 {
                    prefix = tree.aggregate(&[&prefix, &next], None).unwrap();
                }
            }
        }
        let (root, fold) = plan.warm_then_measure(|| {
            let mut acc = Accumulator::default();
            tree.fold(&mut acc, &prefix).unwrap();
            tree.fold(&mut acc, &next).unwrap();
            acc.close().unwrap()
        });
        println!(
            "ROOT_SET mode={label} claims={} groups={} crosses_small_tier={}",
            root.claims.n_claims(),
            root.claims.groups.len(),
            root.claims.n_claims() >= 257
        );
        let (seal, sealing) = plan.warm_then_measure(|| tree.seal(&sealer, &root.proof).unwrap());
        let (_, direct) = plan.warm_then_measure(|| tree.verify_claims(&root.proof, &root.claims).unwrap());
        let (_, sealed) = plan.warm_then_measure(|| {
            loaded
                .verify_claims_sealed(&root.proof, &root.claims, &roots, &seal)
                .unwrap();
        });
        println!(
            "ROOT mode={label} fold_ms={:.3} root_bytes={} seal_bytes={} sealing_ms={:.3} direct_ms={:.3} sealed_ms={:.3}",
            fold.mean() * 1000.,
            root.proof.to_bytes().len(),
            seal.to_bytes().len(),
            sealing.mean() * 1000.,
            direct.mean() * 1000.,
            sealed.mean() * 1000.
        );
        let out = directory.join(label);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("class-key.bin"), key).unwrap();
        std::fs::write(
            out.join("class-key.digest"),
            pin.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        )
        .unwrap();
        std::fs::write(out.join("root.bin"), root.proof.to_bytes()).unwrap();
        std::fs::write(out.join("claims.bin"), root.claims.to_bytes()).unwrap();
        std::fs::write(out.join("seal.bin"), seal.to_bytes()).unwrap();
    }
}
