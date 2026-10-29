# Isolated compact-key fixtures

Three ordered leaf classes use capacity `(16385,1024)`, SMALL `(257,64)`, arities 1/2, tree log inverse rate 1 and Isolated ZK placement. Class bounds and heights are defined in the `compact` suite of `crates/leanvm_core/examples/fixtures.rs`.

See the [format specification](../../doc/compact-class-key.md). `verdicts.tsv` gives the expected verdict and relative artifact paths for each case. Digest files contain 32 raw bytes. Other files use the public Rust API's byte encoding.

```sh
cargo test --release -p leanvm --test verifiers compact_class_key_differential_fixtures
cargo run --release -p leanvm --example fixtures -- verify compact conformance/mixed-class-key-v4
cargo run --release -p leanvm --example fixtures -- export compact target/compact-fixture
```

The suite covers SMALL/LARGE plain roots and ZK roots, plus dropped/added openings, a changed usage bit and a wrong digest. Regeneration verifies fresh artifacts before returning; proof randomness can change proof bytes while the class key remains deterministic.
