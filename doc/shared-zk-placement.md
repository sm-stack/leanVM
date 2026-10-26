# Public shared ZK placement

Base: `fc3fc9ec`, branch `op-stack/claim-set-leaves`. API implementation: `04d373c7`. The implementation exposes the existing shared circuit design and accepts caller-pinned placement in both loaders; it does not alter circuits, proof domains or isolated artifacts. See [the byte-level specification and APIs](compact-class-key.md#caller-pinned-zk-placement).

## API and behavior

Use `Tree::mixed_classes_with(&classes, shape, ZkPlacement::Shared)` and the corresponding `mixed_classes_from_bytes_with` or `mixed_classes_from_trusted_bytes_with`, with placement before the bytes/digest arguments. Existing methods remain Isolated wrappers. `ZkPlacement` is exported under `leanvm::aggregate`; its `Default` is `Isolated`.

Both loaders compare the caller's descriptor, including placement, before constructing any circuit design. A correctly hashed isolated key cannot be loaded by a Shared caller, and vice versa. Trusted loading does not authenticate bytes or their digest association; it retains the existing external-authentication requirement.

Shared mode is supported both with `small: None` and with a small/large configuration. All First circuits, including ZK, occupy tier 0, and there are no LeafWraps. Raw shared ZK First roots are accepted directly as Node children. Each First still closes program claims in-circuit and carries zero recursive tier usage; a Node adds its child tier and ORs inherited usage. In one-tier Shared mode, both the recursive claim and the root's column claims use the same polynomial, producing exactly one seal opening. The native root verifier and seal checks are unchanged. No soundness bypass was found or introduced; this is an implementation argument and regression coverage, not an independent cryptographic audit.

With two aggregation tiers, Shared raises the padded SMALL heights to include ZK verification. It does not remove the LARGE tier or its existing Wrap. Isolated remains useful there. For class lists without ZK, placement still changes the descriptor/key digest, although the circuit sessions can coincide because the ZK-specific session suffix is absent.

## Frozen class and workload

The class records exactly match the attachment's bounds/heights/rates, in plain, signature-member, ZK order. They also match the three class records in the local monorepo's `rust/op-leanvm-tree/src/class.rs`. That file still had the previous tree shape when read, so this fixture uses the **explicit new shape in the request**: arities 1/2, tree log inverse rate 3, claim capacity 4097, 64 groups, `small: None`, seal log inverse rate 2. The ZK leaf log inverse rate is 2; the other leaves use 1.

The workload has 16 leaves and 1168 distinct claims: eight plain program leaves with 64 members each, four actual leanSPHINCS signature-member guest leaves with 100 signatures each, and four ZK program leaves with 64 members each. The generic programs are assembled examples publishing distinct fixed member lists; their ZK proofs use fresh randomness. The signature leaves execute the checked-in guest ELF. These are protocol fixtures, not a privacy benchmark of application advice.

Leaves are proven once and reused for both placement measurements. They are aggregated in plain/signature/ZK order with a left fold. There are 13 VK groups: twelve generic programs plus the signature guest. The final declared set is the complete union, without narrowing.

## Measurements

Rust 1.95 release, eight pool threads, direct executable invocation at normal priority (no `taskpolicy` wrapper). Each First/fold operation has one warmup and three measured passes, no cooldown; reported means average those passes over the leaves of a class. There are 8/4/4 First operations and 7/4/4 folds respectively. Leaf proof production, signature generation, key construction and sealing are excluded from these timings. **First means `aggregate_programs_at`, including its automatic LeafWrap in Isolated ZK mode**, not the raw ZK First circuit alone. Isolated ran before Shared; these are local timing observations, not a controlled significance claim about small differences.

| Leaf class | Isolated First ms | Shared First ms | Isolated fold ms | Shared fold ms |
| --- | ---: | ---: | ---: | ---: |
| Plain | 202.395 | 223.168 | 215.954 | 228.392 |
| Signature | 209.271 | 226.353 | 229.914 | 247.557 |
| ZK | 423.486 | 237.110 | 229.740 | 239.786 |

| Placement | Key bytes | Root bytes | Seal bytes | Root + seal bytes |
| --- | ---: | ---: | ---: | ---: |
| Isolated | 1072 | 160763 | 360404 | 521167 |
| Shared | 936 | 160715 | 194284 | **354999** |

Shared root + seal is 35,133 bytes below the supplied 390,132-byte budget. **That total excludes claims and application framing.** The uncompressed fixture `claims.bin` is 38,056 bytes; including it gives 393,055 bytes, 2,923 above that budget before framing. If the monorepo also posts this full claims encoding in those blobs, shared placement alone does not meet that broader payload limit. The attachment's root+seal comparison is met. Proof sizes can vary with randomness and workload.

The locally measured isolated total is 521,167 bytes, not the attachment's 549.5 KB. The report uses the actual emitted artifacts; it does not substitute that earlier number for this workload/run. No Cannon execution or new step/memory measurement was performed here.

Shared digest:

```text
7da486eb212493df9593d444446659925963892196008510f7a12159d67b9a18
```

Isolated digest at this same new shape:

```text
4f75ab48d342994d863e2104dd35ff2d51f96bd9fc5cb14510ee5377ee3cce0b
```

Reproduce with `cargo run --release -p leanvm --example shared_zk -- DIRECTORY`. The generator verifies its own verdicts. Use `DIRECTORY verify` to verify frozen files without building the tree or proving leaves.

## Conformance and portability

[`conformance/mixed-class-key-v4-shared-zk`](../conformance/mixed-class-key-v4-shared-zk) uses the existing seven-column `verdicts.tsv` layout. Every case runs through both loader variants with caller placement Shared:

| Case | Verdict | Reason |
| --- | --- | --- |
| mixed | accept | Complete plain/signature/ZK union |
| isolated-key | reject | Correct isolated digest supplied, but caller descriptor says Shared |
| tier-bit-flipped | reject | Authenticated root usage changed |
| opening-dropped | reject | Retains 102-value prefix, removes the only PCS opening |
| wrong-digest | reject | Checked loader rejects hash mismatch; trusted loader loads but seal verification fails |

`public_zk_placement_round_trips_and_pins_the_caller` covers both placements, both loaders, opposite-placement refusal, First and Node verification, absence/presence of LeafWrap, and one derived opening in Shared mode, with and without a small tier, including a union that crosses the SMALL capacity and a subsequent LARGE-child Wrap. The existing isolated fixture test now **regenerates** its class key and compares every byte and its digest against the original `fc3fc9ec` fixture, in addition to running the original eight verdicts. The new frozen suite runs in the same native integration-test binary and in `scripts/check-big-endian.sh` under s390x QEMU.

A real Rust 1.95 release build passed for `mips64-unknown-linux-gnuabi64`, whose target configuration reports `target_arch="mips64"` and `target_endian="big"`. Because this tier-3 target has no distributed standard library, std was built from the matching `rust-src` with scoped `RUSTC_BOOTSTRAP=1`:

```sh
rustup component add rust-src
RUSTFLAGS='-C target-cpu=generic' RUSTC_BOOTSTRAP=1 \
  cargo build -Z build-std=std,panic_abort --release -p leanvm --lib \
  --target mips64-unknown-linux-gnuabi64
```

This generates MIPS64 machine code in the library archive; it is not `cargo check`, a linked kona-client, or a Cannon run. CI now runs this build with Rust 1.95 and also executes both old and new compact fixture suites under s390x QEMU.

## Check results

- `rustup run 1.95 cargo test --workspace --release`: **552 passed, 0 failed, 5 ignored**. The ignored cases are the existing two ACT4 tests requiring generated ELF files, the opt-in large ZK measurement, and two guest-only SDK doctests.
- Final `rustup run 1.95 cargo test --release -p leanvm --lib --test verifiers`: **304 passed, 0 failed, 3 ignored**, including the extended LARGE/Wrap path.
- `cargo clippy --workspace --all-targets --release -- -D warnings`: passed (native Rust 1.99.1).
- `cargo fmt --all -- --check`: passed.
- MIPS64 real release library build: passed with Rust 1.95 and matching built std.
- s390x real release build and QEMU: all **five new** and **eight old** fixture verdicts matched expectations. The new cases run through both checked and trusted loaders.
- Original isolated fixture directory is unchanged, and its class key/digest were regenerated byte-for-byte in the native integration test. No guest/runtime or guest ELF changes are included.

Local build/test/measurement logs are retained under `.context/shared-zk/`. No monorepo files, Go verifier code, or upstream resources were changed.
