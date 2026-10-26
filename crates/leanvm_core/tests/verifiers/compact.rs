//! Frozen Go-port fixtures, including adversarial opening lists and usage bits.
use leanvm::aggregate::{Capacity, ClaimShape, LeafClass, LeafShape, ProgramClass, Tier, Tree, TreeShape};
use leanvm::{PerTable, ProofTranscript, Rate, TableId};
use std::path::Path;

#[test]
fn compact_class_key_differential_fixtures() {
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
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/mixed-class-key-v4");
    verify_fixtures(&dir, &classes, shape);
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
