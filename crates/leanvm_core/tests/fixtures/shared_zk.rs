use leanvm::aggregate::{Capacity, ClaimShape, LeafClass, LeafShape, ProgramClass, Tree, TreeShape, ZkPlacement};
use leanvm::{PerTable, ProofTranscript, Rate, TableId};
use std::path::Path;

pub fn config() -> ([LeafClass; 3], TreeShape) {
    let capacity = 4097;
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
        rate: Rate::new(3).unwrap(),
        claims: Some(ClaimShape {
            capacity: Capacity {
                claims: capacity,
                groups: 64,
            },
            small: None,
        }),
    };
    (classes, shape)
}

pub fn verify(dir: &Path) {
    use leanvm::aggregate::{ClaimSet, TreeProof};
    let (classes, shape) = config();
    for line in std::fs::read_to_string(dir.join("verdicts.tsv"))
        .unwrap()
        .lines()
        .skip(1)
    {
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 7);
        let read = |i: usize| std::fs::read(dir.join(f[i])).unwrap();
        let digest: [u8; 32] = read(3).try_into().unwrap();
        for trusted in [false, true] {
            let bytes = read(2);
            let result = if trusted {
                Tree::mixed_classes_from_trusted_bytes_with(&classes, shape, ZkPlacement::Shared, &bytes, &digest)
            } else {
                Tree::mixed_classes_from_bytes_with(&classes, shape, ZkPlacement::Shared, &bytes, &digest)
            };
            let accepted = result.is_ok_and(|tree| {
                let root = TreeProof::from_bytes(&read(4)).unwrap();
                let claims = ClaimSet::from_bytes(&read(5)).unwrap();
                assert_eq!(claims.claims().count(), 1168);
                assert_eq!(claims.groups.len(), 13);
                let seal = ProofTranscript::from_bytes(&read(6)).unwrap();
                tree.verify_claims_sealed(&root, &claims, tree.seal_roots().unwrap(), &seal)
                    .is_ok()
            });
            assert_eq!(accepted, f[1] == "accept", "{} trusted={trusted}", f[0]);
        }
        println!("FIXTURE {} {}", f[0], f[1]);
    }
}
