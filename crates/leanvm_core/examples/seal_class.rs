//! Spike: seal the exported mixed roots, verify them sealed, and write the seals and the class's seal roots.
use leanvm::aggregate::{Capacity, ClaimSet, ClaimShape, LeafShape, ProgramClass, Tree, TreeProof, TreeShape};
use leanvm::{PerTable, Rate, TableId};
use std::time::Instant;

fn main() {
    let dir = std::path::PathBuf::from(std::env::args().nth(1).unwrap());
    let w: Vec<usize> = std::fs::read(dir.join("distinct-4/class.bin")).unwrap().chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()) as usize).collect();
    let class = ProgramClass { log_bytecode: w[1], log_ram: w[2], log_advice: w[3], image_words: w[4] };
    let rate = |x: usize| Rate::new(x as u8).unwrap();
    let shape = TreeShape {
        leaf: LeafShape::plain(PerTable::from_fn(|t: TableId| w[11 + t.index()]), rate(w[5])).unwrap(),
        arity_0: w[6], arity: w[7], rate: rate(w[8]),
        claims: Some(ClaimShape { capacity: Capacity { claims: w[9], groups: w[10] }, small: None }),
    };
    let tree = Tree::mixed(class, shape).unwrap();
    let t = Instant::now();
    let prover = tree.seal_prover().unwrap();
    println!("seal commitments (log inv rate {}): {:?}", leanvm::aggregate::SEAL_LOG_INV_RATE, t.elapsed());
    let roots = prover.roots();
    let mut root_bytes = Vec::new();
    for r in &roots.0 { root_bytes.extend_from_slice(r); }
    std::fs::write(dir.join("seal-roots.bin"), &root_bytes).unwrap();
    for d in ["distinct-1", "distinct-2", "distinct-4"] {
        let p = dir.join(d);
        let root = TreeProof::from_bytes(&std::fs::read(p.join("root.bin")).unwrap()).unwrap();
        let claims = ClaimSet::from_bytes(&std::fs::read(p.join("claims.bin")).unwrap()).unwrap();
        let t = Instant::now();
        let seal = tree.seal(&prover, &root).unwrap();
        let prove = t.elapsed();
        let t = Instant::now();
        tree.verify_claims(&root, &claims).unwrap();
        let direct = t.elapsed();
        let t = Instant::now();
        tree.verify_claims_sealed(&root, &claims, &roots, &seal).unwrap();
        let sealed = t.elapsed();
        let bytes = seal.to_bytes();
        std::fs::write(p.join("seal.bin"), &bytes).unwrap();
        println!("{d}: seal {} bytes ({:.1} KiB), sealing {prove:?}, verify direct {direct:?}, sealed {sealed:?}",
            bytes.len(), bytes.len() as f64 / 1024.0);
    }
}
