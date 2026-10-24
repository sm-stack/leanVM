//! Spike: the size of a mixed class's verifier data.
use leanvm::aggregate::{Capacity, ClaimShape, LeafShape, ProgramClass, Tree, TreeShape};
use leanvm::{PerTable, Rate, TableId};

fn main() {
    let bytes = std::fs::read(std::env::args().nth(1).unwrap()).unwrap();
    let w: Vec<usize> = bytes
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()) as usize)
        .collect();
    let class = ProgramClass {
        log_bytecode: w[1],
        log_ram: w[2],
        log_advice: w[3],
        image_words: w[4],
    };
    let rate = |x: usize| Rate::new(x as u8).unwrap();
    let shape = TreeShape {
        leaf: LeafShape::plain(PerTable::from_fn(|t: TableId| w[11 + t.index()]), rate(w[5])).unwrap(),
        arity_0: w[6],
        arity: w[7],
        rate: rate(w[8]),
        claims: Some(ClaimShape {
            capacity: Capacity {
                claims: w[9],
                groups: w[10],
            },
            small: None,
        }),
    };
    let t = std::time::Instant::now();
    let tree = Tree::mixed(class, shape).unwrap();
    println!("setup {:?}", t.elapsed());
    let bytes = tree.mixed_verifier_bytes().unwrap();
    let dir = std::path::Path::new(&std::env::args().nth(2).unwrap()).to_path_buf();
    std::fs::write(dir.join("verifier.bin"), &bytes).unwrap();
    println!(
        "verifier bytes {} ({:.1} MiB)",
        bytes.len(),
        bytes.len() as f64 / 1048576.0
    );
    let t = std::time::Instant::now();
    let loaded = Tree::mixed_from_bytes(class, shape, &bytes).unwrap();
    println!("load {:?}", t.elapsed());
    for d in ["distinct-1", "distinct-2", "distinct-4"] {
        let p = dir.join(d);
        let root = leanvm::aggregate::TreeProof::from_bytes(&std::fs::read(p.join("root.bin")).unwrap()).unwrap();
        let claims = leanvm::aggregate::ClaimSet::from_bytes(&std::fs::read(p.join("claims.bin")).unwrap()).unwrap();
        let t = std::time::Instant::now();
        loaded.verify_claims(&root, &claims).unwrap();
        println!("{d}: loaded tree verifies in {:?}", t.elapsed());
        tree.verify_claims(&root, &claims).unwrap();
    }
    // A flipped word in a fixed column, and a truncation, are refused or fail verification.
    let root =
        leanvm::aggregate::TreeProof::from_bytes(&std::fs::read(dir.join("distinct-4/root.bin")).unwrap()).unwrap();
    let claims =
        leanvm::aggregate::ClaimSet::from_bytes(&std::fs::read(dir.join("distinct-4/claims.bin")).unwrap()).unwrap();
    for at in [8, 39, bytes.len() / 3, bytes.len() / 2, bytes.len() - 8] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        let r = Tree::mixed_from_bytes(class, shape, &bad).map(|t| t.verify_claims(&root, &claims));
        println!(
            "flip at {at}: {}",
            match r {
                Err(_) => "refused at load".into(),
                Ok(Err(e)) => format!("verify refused: {e}"),
                Ok(Ok(())) => "ACCEPTED".into(),
            }
        );
    }
    assert!(Tree::mixed_from_bytes(class, shape, &bytes[..bytes.len() - 8]).is_err());
    let (circuits, fixed, dense) = tree.verifier_data_words();
    println!(
        "circuits {circuits}, fixed column words {fixed} ({:.1} MiB), dense table words {dense:?} ({:.1} MiB)",
        fixed as f64 * 8.0 / 1048576.0,
        dense.iter().sum::<usize>() as f64 * 8.0 / 1048576.0
    );
}
