# Big-endian verification

The claim-set-leaves fork supports the portable verifier on big-endian hosts. The regression target is
`s390x-unknown-linux-gnu` under QEMU, with an additional library build for `powerpc64-unknown-linux-gnu`.
These checks exercise the endian boundary used by Cannon's MIPS64 client; they do not substitute for the
monorepo's actual `kona-client` build or a Cannon run.

## Fix and scope

At base `59c25ccc`, the core's member-list validation depends on `leanvm_guest`. Its byte-streaming BLAKE2s
asserted little-endian memory order. A dev-profile `cargo check` passed, but release `cargo build` **and
release `cargo check`** failed with E0080. Thus the failure is not exclusive to linking.

Keep the shared SDK implementation and its existing little-endian fast path. On big-endian hosts, write each
byte into its little-endian position within the numeric message word. This fixes both byte updates and mixed
byte/word updates without changing the wire format or duplicating member-list hashing in the verifier.
Moving the implementation to another crate is unnecessary for this fix.

The audit found a second bug: `Template::write<T>` stored a sub-word integer at a native byte offset. On a
big-endian host that changes the wrong part of the numeric word. Its big-endian path now encodes each integer
little endian, recursively for arrays; its little-endian raw store is unchanged. This also repairs native
signature hashing through `Template::chain`. The accepted types and alignment/bounds checks are unchanged.

## Endianness audit

The table covers word/byte reinterpretations in the SDK, core and verifier dependencies, including the
portable prover paths compiled into those libraries. File locations refer to this patch. No `to_ne_bytes`,
`from_ne_bytes` or bytemuck-style wire views occur in these paths. Architecture-specific SIMD views are grouped
separately; the tested big-endian targets use portable kernels.

| File:line | Path / representation | Verdict | Action |
|---|---|---|---|
| `sdk/src/blake2s.rs:143` | `Blake2s::put_bytes`, byte updates and unaligned word updates | Bug in former `m_bytes`: native byte image required little endian | Preserve LE copy; explicitly place bytes on BE |
| `sdk/src/blake2s.rs:197` | `Template::write<T>`, including native chain counters and arrays | Bug: a native sub-word store changes the wrong word bits on BE | Encode each scalar LE on BE; recursively handle arrays |
| `sdk/src/blake2s.rs:418` | `Stream::message`, `[u64; 8]` to `[MaybeUninit<u64>; 8]` | Correct: same numeric word type, no byte-order conversion | None |
| `sdk/src/blake2s.rs:65,99,106,555` | Word updates, final output, portable compression's u32 lanes | Correct: numeric assignments, shifts/masks and explicit byte extraction | Byte/word split and boundary tests |
| `sdk/src/io.rs:38,71` | `as_words_unchecked`, `PublicValues::commit` | Correct under `Words`' safety contract: exclusively u64 words, no padding; subsequent encoding is LE | Preserve contract; member-output vectors |
| `sdk/src/io.rs:131,176,193,211,256,264` | Public block pointers, advice reads and guest commit | Numeric u64 views; guest-only in production, public-block logic also tested natively | No byte conversion required |
| `sdk/src/ext.rs:41` | `*const u64` to `*[u64; 3]` | Correct: same-width numeric limbs; no byte view | Existing portable field test runs on BE |
| `sdk/src/members.rs:14,31,76,85` | List domain, compression inputs, digest and public output | Correct: numeric words and explicit LE domain; output previously inherited the BLAKE2s build failure | Frozen empty/odd/even list and output vectors |
| `programs/leansphincs-members/guest/src/lib.rs:7,11` | `member`, domain + key + message | Correct: word stream in specified field order | Frozen independent 72-byte BLAKE2s vector |
| `programs/leansphincs-members/host/src/lib.rs:23` | Advice key/signature views | Correct: repr(C) u64-only structs satisfy `as_words_unchecked` | Existing guest execution test also runs on BE |
| `crates/primitives/src/hash/batch.rs:80` | Unaligned u32 read from input bytes | Correct: immediately applies `u32::from_le`; output uses LE bytes | Unchanged |
| `crates/primitives/src/hash/mod.rs:137,224` | Scalar block and digest parsing | Correct: explicit `from_le_bytes` / `to_le_bytes` | SDK tests compare against this implementation on BE |
| `crates/pcs/src/merkle.rs:183` | u64 staging allocation viewed as bytes | Correct: only used as byte storage; numeric values are never read | None |
| `crates/pcs/src/merkle.rs:489,502` | F64 rows to bytes; digest arrays to bytes | Correct: BE row branch allocates explicit LE encoding; digests already consist of u8 | Cross-host root/key verification |
| `crates/pcs/src/merkle.rs:540,568,600` | Opening rows in hints and verifier hashing | Correct: explicit LE numeric encoding/decoding | Cross-host leaf and tree verification |
| `crates/primitives/src/field/gf2_64.rs:40,47`; `gf2_64x3/mod.rs:62,97,104` | F64/u64 and F192/F64 slice views | Correct: transparent u64 / repr(C) triples of u64; same limb width and order. Wire encoding is explicit LE | None |
| `crates/primitives/src/bit_fold/tables.rs:48`; `crates/pcs/src/stack/weight.rs:106` | F192 limb pointers and scratch F64 triples | Correct: numeric u64-sized limbs, not byte images | None |
| `crates/pcs/src/ntt/mod.rs:137,713,1031`; `crates/leanvm_core/src/rec/hash.rs:63` | Word slices, aligned F64 storage, word-port pointers | Correct: numeric word views, no narrowing to bytes | None |
| `crates/primitives/src/stream.rs:39,47` | Generic copy through byte pointers | Correct: copies representation unchanged between identical types; no serialization | None |
| `crates/flock/src/witness.rs:10,16` | Packed witness words to bytes | Prover-only LE requirement; BE already panics explicitly instead of computing wrong values | Retain existing `packed witness generation requires a little-endian target` guard |
| `crates/fiat_shamir/src/{codec,duplex,proof,pow}.rs` | Fields, lengths, sponge lanes and nonces | Correct: explicit LE encoding, no raw word/byte view | Cross-host transcript verification |
| `crates/leanvm_core/src/{envelope.rs,cpu/key.rs:52,rec/tree/embed.rs:64,rec/tree/multiset.rs:209}` | Proof headers, VK, class key, ClaimSet digest/encoding | Correct: explicit LE encoding and numeric compression inputs | Checked/trusted load, VK verification, canonical round trips and claim digest comparison |
| `crates/primitives/src/{bits,hash/arm,hash/x86,field/*,bit_fold/*}.rs`; `crates/pcs/src/{ntt/kernels,whir/sumcheck/first_pass}.rs`; `crates/flock/src/{gadgets,lincheck,zerocheck/*}.rs` | SIMD register loads, stores and bit casts | x86/AArch64-specialized; absent from the MIPS64/PPC64/s390x portable paths. Same-width numeric layouts above cover their portable replacements | No SIMD changes; compile the modified SDK on x86 too |
| `crates/parallel/src/{lib.rs:78,pool.rs:293}` | Chunk slices and erased closure lifetime | Not word/byte serialization; unchanged pointee type and pointer representation | None |

`Template` supports native big-endian callers after this patch. Packed Flock witness generation remains
little-endian-only with the explicit panic above. This is a verifier-portability change, not a promise of a
complete big-endian prover.

## Checks

On Linux, install Rust 1.95, `rustup target add s390x-unknown-linux-gnu`, and
`apt-get install gcc-s390x-linux-gnu libc6-dev-s390x-cross qemu-user`, then run:

```sh
scripts/check-big-endian.sh
```

The Rust workflow runs this script on every PR. It sets generic CPU flags and caps builds and tests at two
jobs. It exports a leaf proof and a **node** root with a nonempty seal on the native little-endian host, then:

```sh
cargo build --release -p leanvm --lib --target s390x-unknown-linux-gnu
cargo test --release -p leanvm_guest -p leansphincs-members-host --target s390x-unknown-linux-gnu
cargo run --release -p leanvm --example endian_verifier --target s390x-unknown-linux-gnu -- verify target/endian-fixture
```

The script configures `s390x-linux-gnu-gcc` and `qemu-s390x -L /usr/s390x-linux-gnu`. The fixture is trusted test
input generated by the CI job, not a production class-key provisioning mechanism. Both loader variants verify
the same root directly and with its seal; the test also rejects a damaged seal, verifies the leaf through
`VerifyingKey::verify`, compares ClaimSet digests, and round-trips the canonical VK/root/claim/seal bytes.
The verifier does not regenerate the tree or its class key.

A codegen-only check needs no cross linker:

```sh
RUSTFLAGS='-C target-cpu=generic' rustup run 1.95 cargo build --release -p leanvm --lib --target powerpc64-unknown-linux-gnu
```

Executed locally in the existing Rust 1.95 Docker image under s390x QEMU: **19 tests passed** (17 SDK, 2
signature-member host), followed by successful leaf/direct/sealed-node verification. The SDK's two guest-only
doctests remain ignored. This is actual emulated big-endian execution, not only a cross compilation. No new
MIPS64/Cannon measurement was performed in this workspace.

The native release workspace suite passes **547 tests, 0 failures, 4 ignored**. New regression tests are
`byte_and_word_updates_match_across_blocks`, `template_nested_arrays_encode_each_integer_little_endian`,
`member_list_and_output_vectors`, and `signature_member_little_endian_vector`. Existing template rewrites,
chains, streaming words and signature execution tests also run in QEMU. Native all-target clippy uses Rust
1.99.1; tests, the cross builds and formatting use Rust 1.95.

An extra Rust 1.95 PowerPC64 SDK **all-target** clippy attempt encounters a pre-existing
`missing_const_for_fn` warning in `primitives::field::portable::square_wide`, a dev dependency, with warnings
denied. The SDK library's big-endian clippy check is run separately. This does not affect either release cross
build or the emulated tests; no unrelated field-kernel change is included.

## Compatibility evidence

Compared base `59c25ccc` with the SDK fix using
`claim_set_leaves 100 4097 DIRECTORY`. Both the two-class and one-common-class outputs are byte-identical:
`class-key.bin`, `class-key.digest`, `root.bin`, `claims.bin`, and `seal.bin` (10 files total).
The two-class key is 60,027,800 bytes. Its class-key digest, **before and after**, is:

```text
05860eb91c53a9508a9c81c8cc0bc92e501e1ffb3cabed422dc5a3618adcb96d
```

All 14 guests were rebuilt with the pinned `nightly-2026-10-03` through `programs/build.sh`.
Each ELF's `.text` section matches its checked-in base byte for byte; the rebuilt ELF files themselves also
have no Git diff. No format version, seal session, member domain, class descriptor or pinned key changed.
The local evidence is retained in `.context/be-port/`: before/after guest-section SHA256 manifests,
`format-comparison.json`, the fixture, and build/test logs.
