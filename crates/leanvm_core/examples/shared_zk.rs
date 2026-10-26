//! Eight-thread shared/isolated measurements and frozen mixed-signature-ZK fixtures.
//! Run: shared_zk DIRECTORY [verify]. Measurements run at normal process priority.
#[path = "../tests/fixtures/shared_zk.rs"]
mod fixture;
use bench::Plan;
use leanvm::aggregate::{MixedLeaf, Tree, ZkPlacement};
use leanvm::asm::{Addi, Asm, Bne, Reg};
use leanvm::{CircuitId, N_CIRCUITS, Program, ProofTranscript, Region};
use std::{num::NonZeroUsize, path::Path, time::Duration};

fn main() {
    parallel::init_with_threads(NonZeroUsize::new(8).unwrap()).unwrap();
    let args: Vec<_> = std::env::args().collect();
    let dir = Path::new(args.get(1).expect("fixture directory"));
    if args.get(2).is_some_and(|s| s == "verify") {
        fixture::verify(dir);
        return;
    }
    std::fs::create_dir_all(dir).unwrap();
    let (classes, shape) = fixture::config();
    let plan = Plan::new(3, Duration::ZERO);
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
        let mut timings = [[0.0; 2]; 3];
        let mut counts = [0usize; 3];
        let mut root = None;
        for (class, program, run, members) in &leaves {
            let leaf = MixedLeaf {
                key: program.verifying_key(),
                proof: &run.proof,
                output: run.output,
                members,
            };
            let (first, timing) = plan.warm_then_measure(|| tree.aggregate_programs_at(*class, &[leaf], None).unwrap());
            timings[*class][0] += timing.mean();
            counts[*class] += 1;
            root = Some(match root {
                None => first,
                Some(previous) => {
                    let (next, timing) = plan.warm_then_measure(|| tree.aggregate(&[&previous, &first], None).unwrap());
                    timings[*class][1] += timing.mean();
                    next
                }
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
        for class in 0..3 {
            // The initial plain leaf has no fold, so exclude it from that denominator.
            let folds = counts[class] - usize::from(class == 0);
            println!(
                "TIME placement={placement:?} class={class} first_ms={} fold_ms={}",
                timings[class][0] * 1000. / counts[class] as f64,
                timings[class][1] * 1000. / folds as f64
            );
        }
        println!(
            "SIZE placement={placement:?} key={} root={} seal={} total={} digest={}",
            bytes.len(),
            root.proof.to_bytes().len(),
            seal.to_bytes().len(),
            root.proof.to_bytes().len() + seal.to_bytes().len(),
            digest.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
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
