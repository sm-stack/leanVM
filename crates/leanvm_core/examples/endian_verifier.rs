//! Export on little endian, then verify the same bytes on a big-endian host.
//! Usage: endian_verifier export|verify DIRECTORY [zk].
use leanvm::aggregate::{
    Capacity, ClaimSet, ClaimShape, LeafClass, LeafShape, MixedLeaf, ProgramClass, Tree, TreeProof, TreeShape,
};
use leanvm::asm::{Addi, Asm, Bne, Reg};
use leanvm::{Output, Program, Proof, ProofTranscript, Rate, Region, TableId, VerifyingKey};
use std::{num::NonZeroUsize, path::Path};

fn main() {
    parallel::init_with_threads(NonZeroUsize::new(2).unwrap()).unwrap();
    let args: Vec<_> = std::env::args().collect();
    let mode = args.get(1).expect("export or verify");
    assert!(mode == "export" || mode == "verify");
    #[cfg(target_endian = "big")]
    assert_ne!(mode, "export", "export uses the little-endian prover");
    let path = Path::new(args.get(2).expect("fixture directory"));
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
    let zk = args.get(3).is_some_and(|s| s == "zk");
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
    if mode == "export" {
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
        tree.verify_claims(&proof, &claims).unwrap();
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
