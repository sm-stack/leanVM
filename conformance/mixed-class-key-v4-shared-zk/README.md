# Shared-ZK compact-key fixtures

Exact requested monorepo class: three ordered leaf classes, arities 1/2, tree rate 1/8,
capacity `(4097,64)`, no small tier, Shared placement, seal rate 1/4.
The root covers eight plain, four signature-member and four ZK leaves: 1168 claims.
See [the report](../../doc/shared-zk-placement.md) and [byte-level format](../../doc/compact-class-key.md).

`verdicts.tsv` lists name, expected verdict, key, digest, root, claims and seal, tab-separated.
Paths are relative to this directory. Digests are raw 32 bytes; all other artifacts use public API encodings.
The isolated-key mutation includes its genuine digest so descriptor checking, not a stale pin, rejects it.

```sh
cargo test --release -p leanvm --test verifiers shared_zk_differential_fixtures
cargo run --release -p leanvm --example shared_zk -- conformance/mixed-class-key-v4-shared-zk verify
```

Generate fresh artifacts with `shared_zk DIRECTORY`; proofs and sizes may vary with randomness.
Root + seal totals exclude the separate claims encoding and application framing.
