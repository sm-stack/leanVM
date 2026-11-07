# Shared compact-key fixtures

Three ordered leaf classes use capacity `(4097,64)`, no small tier, arities 1/2, tree log inverse rate 3 and Shared ZK placement. Class bounds and heights are defined in `crates/leanvm_core/tests/fixtures/shared_zk.rs`. The root covers plain programs, the signature-member guest and ZK programs.

See the [format specification](../../doc/compact-class-key.md). `verdicts.tsv` gives the expected verdict and relative artifact paths for each case. Digest files contain 32 raw bytes. Other files use the public Rust API's byte encoding. The isolated-key case supplies its genuine digest so placement checking must reject it.

```sh
cargo test --release -p leanvm --test verifiers shared_zk_differential_fixtures
cargo run --release -p leanvm --example fixtures -- verify shared conformance/mixed-class-key-v4-shared-zk
cargo run --release -p leanvm --example fixtures -- export shared target/shared-fixture
```

Regeneration verifies fresh artifacts before returning; proof randomness can change proof bytes while the class key remains deterministic. Claims are a separate artifact from the root and seal.
