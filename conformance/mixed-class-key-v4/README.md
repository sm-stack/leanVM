# Compact class-key v4 fixtures

The exact monorepo three-class shape at capacity `(16385, 1024)`, SMALL `(257, 64)`.
See [the protocol specification](../../doc/compact-class-key.md) for encodings, class descriptors and soundness assumptions.

`verdicts.tsv` is the complete eight-case manifest. Its paths are relative to this directory.
All `.bin` files contain the public Rust API's byte encoding; `.digest` files contain 32 raw bytes.
Valid cases share the authenticated key. Mutations share unmodified artifacts where possible.

Run the frozen suite with:

```sh
cargo test --release -p leanvm --test verifiers compact_class_key_differential_fixtures
cargo run --release -p leanvm --example compact_class_key -- conformance/mixed-class-key-v4 16385 verify
```

Generate fresh proofs in a separate directory with `compact_class_key DIRECTORY 16385`.
Proof randomness can change proof sizes and bytes. The class key is deterministic.
The generator includes the signature-member class in the key; the fixture leaves use the plain program
and private program classes. Actual signature-member proofs are exercised by the unit suite.
