# Mixed-program aggregation trees

This branch starts from upstream `riscv-exploration` at `06e5c9cd6981103786f9d0a17324241b559a50d3`. It ports committed-program [PR #418](https://github.com/leanEthereum/leanVM/pull/418) into the current generic verifier and adds a mixed-program mode to the existing claim-set aggregation tree. The implementation is experimental and has no formal soundness proof.

## Program identity

Previously `Program::digest` hashed the decoded bytecode table and initial RAM image, and a recursion circuit embedded that program's session as constants. Its deferred bytecode and image claims reached the root, which evaluated the program's tables itself. Building and verifying a tree therefore required one specific program.

`Program::new` now commits the stacked decoded table at inverse-rate logarithm 4. `VerifyingKey` contains the root, bytecode dimension, entry address, RAM and advice dimensions, and the image with its length. Its digest is BLAKE2s of the versioned domain separator and the canonical little-endian encoding. A standalone verifier needs that key, the output, and the proof. It reconstructs the proof layout from metadata without decoding or allocating bytecode. The extra program opening follows the witness opening. It opens the Frobenius-conjugate bytecode points used by the existing deferred program claim and combines their values with the image evaluation. Every value is bound into the transcript before the opening's batching challenges.

The original PR's authorship is preserved in its two ported commits. The conflict resolutions retain the modern bus/table residual, generic arithmetic verifier, and zero-knowledge recorder instead of restoring the deleted Python verifier or the old public API crate. The moved stacked PCS accepts point-only statements. The recursion verifier consumes the additional opening. New proof-envelope versions refuse proofs of the previous statement format.

## Shape classes and normalization

`ProgramClass` specifies the bytecode dimension, RAM dimension, advice dimension, and padded image length. The image length is a nonzero power of two. `TreeShape` additionally fixes every leaf table's height, the leaf and tree rates, arities, and claim-set capacities and tiers. These together are the class. No leaf program or key is an input to `Tree::mixed`.

`ProgramClass::normalize` pads shorter decoded programs with illegal entries and smaller images with zeros before key generation. It can enlarge the RAM and advice regions to the class dimensions. The resulting normalized VK digest is the identity to claim; an existing proof under an unnormalized key cannot be relabeled. This deliberately chooses explicit normalization over circuits supporting many different byte lengths and dynamic hash counters. Enlarged advice and memory bounds are part of that identity. A prover can pad table heights through the existing filler planner; the ALU floor must allow the other tables' closing jumps. Proofs that announce a different final shape are refused.

## First-level checks

A mixed first-level circuit reads the key's root, entry address and image as witness words. All size fields and the image length are class constants. It constrains the entry's alignment, address range and exclusion of the halt slot, hashes the complete canonical key encoding in rows, derives its Fiat-Shamir `SessionId` with the same duplex framing as the native implementation, and seeds the leaf transcript from that computed identifier and the claimed output.

The shared core verifies the leaf proof. Its initial-state bus contribution is adjusted for the constrained entry address rather than the class placeholder's address. The halt address and memory dimensions are class constants. The first-level circuit closes the bytecode claim against the witnessed key's root using the same PCS verifier, evaluates the image term from the constrained image words, and checks EOF. It carries only the circuit matrix claims upward. Neither the bytecode nor image claim is deferred to the root in mixed mode.

The root commitment and metadata are collision-bound to the claim's VK digest. Substituting another key changes the session and therefore every dependent challenge. Keeping the session while substituting the bytecode opening or image requires breaking the hash binding, opening soundness, or the checked residual identity. As with any committed-program key, an application must associate an authorized digest with a key generated from its intended validated guest; an arbitrary unauthenticated commitment does not establish that an external ELF has that identity.

## Claim sets

A mixed leaf publishes exactly one claim. Its six-word label is `(vk_digest[0], vk_digest[1], vk_digest[2], vk_digest[3], 0, 0)`, and its four-word member is the program's output. The circuit computes this singleton's claim-set digest from the same key digest and output it verified. Native verification is a prover convenience; the first-level rows impose these bindings themselves.

The existing union rows prove that every declared claim is selected from the children's canonical claim sets. A node may publish their union or a subset, so included statements can be discarded. A claim discarded from a proof cannot be restored using that proof alone. Swapping complete leaf triples is an allowed reordering of a set. Swapping an output or key between their claims is a false statement and is refused. A root binds the canonical set passed to `verify_claims`.

## Root work

A mixed tree's node reduction omits bytecode and image polynomials. Its root verifier checks the root recursion proof, the canonical claim set and its digest, the class's fixed recursion polynomial or polynomials, and the fixed flock circuit matrices. It receives no leaf key or decoded program. Its polynomial work depends on the class and tier, not on the number of distinct leaf programs. Processing the supplied claim set naturally depends on that set's length.

Same-program output trees and guest-published claim-set trees remain available. Their zero-knowledge leaves remain supported. Mixed trees currently refuse zero-knowledge leaves with `TreeError::MixedClass`; extending the dynamic metadata path through the recorder is a separate task.

## Upstream interactions and future setup

[PR #522](https://github.com/leanEthereum/leanVM/pull/522) adds guest assumptions and same-program assumption resolution. It changes the leaf statement and first-level witness construction; any port must bind each assumption to its own authenticated key and resolve it before publishing the unconditional singleton. Treating an unresolved conditional output as an unconditional application claim would be unsound.

[PR #553](https://github.com/leanEthereum/leanVM/pull/553) replaces the recursion machine with a generated RISC-V verifier and changes the ISA and proof format. It deletes the row builder used here, so the mixed first-level implementation would require a semantic port into the generated verifier. The program commitment, class bounds, key witness binding, singleton claims, and root settlement requirements still apply.

Precomputing class setup would require a stable encoding of the complete class and its fixed circuit data, an authenticated class identifier, and loading or regenerating exactly the same keys. Committing the recursion fixed polynomials would require new authenticated openings in place of their deferred native evaluations, including a sound treatment of the self-referential node circuit. Neither is implemented here. No Go verifier or OP Stack integration is included.

## Exporting verification inputs

Run `rustup run 1.95 cargo run --release -p leanvm --example committed_program -- .context/exports/plain` to export the ELF, key, proof and four output words for the two Fibonacci sizes and preimage. The key and output encodings are little-endian.

Run `rustup run 1.95 cargo run --release -p leanvm --example mixed_program_tree -- .context/exports/trees` to measure one class over four leaves with one, two and four distinct programs. Each case exports `root.bin`, `claims.bin` and `class.bin`. The class file is the example's versioned, little-endian encoding of the bounds, rates, arities, capacity and leaf table heights. It is an artifact format for this example, not a separately stabilized wire protocol.

Run the same example with `--verify .context/exports/trees/distinct-4` to rebuild the verifier from only those three files. No leaf key, proof or ELF is needed. Setup is measured separately from root verification. The same-program comparison in the report is a positional output tree over four Fibonacci proofs at the same padded leaf shape; it has no claim-set union.

## Native measurements

Measured on an Apple M4 Pro using `rustc 1.98.1 (48a229cea 2026-09-01)`, release builds with `target-cpu=native`, and the benchmark harness's jemalloc allocator. Base and branch measurements ran sequentially with no concurrent builds. Each measurement uses one warmup and three measured passes, except mixed root verification, which uses seven. There is no cooldown. These are native timings, not Cannon step counts or MIPS64 execution measurements.

### Stage 1: standalone proofs

The base is the exact upstream commit recorded above, with an untracked measurement harness and no source changes. Base verifier setup reconstructs `Program` from the ELF; committed verifier setup decodes `VerifyingKey` from its bytes. Program setup is reported separately. The additional PCS opening increases proof size while replacing program polynomial evaluation during verification. Times are milliseconds; proof and key sizes are bytes.

| Guest | Cycles | Mode | Key bytes | Proof bytes | Program setup ms | Prove ms | Verifier setup ms | Verify ms |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fibonacci small | 16,330 | Base | N/A | 259,270 | 0.9075 | 24.0475 | 0.8623 | 1.9044 |
| Fibonacci small | 16,330 | Committed | 328 | 336,906 | 2.0414 | 27.4609 | 0.0006 | 1.3962 |
| Fibonacci large | 131,050 | Base | N/A | 308,902 | 0.8880 | 67.1689 | 1.0455 | 1.9143 |
| Fibonacci large | 131,050 | Committed | 328 | 385,522 | 1.0245 | 67.3010 | 0.0006 | 1.4735 |
| Preimage, 256 bytes | 3,353 | Base | N/A | 247,922 | 0.9061 | 13.0444 | 0.8744 | 1.6861 |
| Preimage, 256 bytes | 3,353 | Committed | 456 | 324,990 | 1.1083 | 16.3913 | 0.0007 | 1.3764 |

### Stage 2: four-leaf trees

One common class covers Fibonacci, preimage and two assembled constant-output programs. Every case has four distinct statements, two first-level proofs of arity two, and one node proof of arity two. The first-level column is the measured time for the two first-level proofs divided by two; it includes the aggregation API's native leaf validation. The node column is one node proof. The class uses bytecode/RAM/advice logarithms `(12, 17, 13)`, a 64-word image, inverse-rate logarithm 1 for leaves and recursion, claim/group capacities `(8, 4)`, and table row logarithms `(15, 4, 4, 6, 7, 5, 4, 4, 4, 3, 3)` in schema order. Both first-level and node circuits commit 10,258,432 witness words. Mixed class setup takes 43.9391 ms and has no program argument. The same-program comparison uses the same padded Fibonacci leaf shape with positional output semantics, so it does not perform claim-set union.

| Mode | Distinct programs | Class setup ms | First level ms/node | Node ms | Root bytes | Root verify ms | Root program polynomials |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Mixed claim set | 1 | 43.9391 | 136.6748 | 130.2043 | 269,631 | 1.9234 | 0 |
| Mixed claim set | 2 | Same class | 131.2922 | 132.0035 | 268,863 | 1.8958 | 0 |
| Mixed claim set | 4 | Same class | 132.1316 | 129.6774 | 269,215 | 1.8946 | 0 |
| Same-program positional | 1 | 40.7098 | 133.4027 | 134.1861 | 269,663 | 2.0019 | Existing bytecode/image settlement |

The seven-pass root verification confidence intervals are ±4.2%, ±3.9% and ±2.7% for the mixed cases. Their timings support the structural property: mixed root settlement has zero program polynomials regardless of distinct-program count. They do not establish a latency improvement between the mixed cases. Root sizes can differ because their proof paths and encodings depend on challenges. All three exported roots were separately verified by loading only `class.bin`, `claims.bin` and `root.bin`.

## Validation and remaining risks

`rustup run 1.95 cargo test --workspace --release` passes: 526 passed, zero failed, four existing ignored tests. The four new mixed-mode tests cover two guest programs, identical class circuit keys, union and discard, cross-builder root verification, incorrect outputs and labels, swapped key/output associations, uncovered claims, tampered root/entry/image, direct circuit-row checks that bypass native prechecks, and a valid non-default entry address. Existing same-program and zero-knowledge tests also pass.

The following checks pass on Rust 1.95:

- `cargo check -p leanvm --examples`.
- `cargo clippy --workspace --all-targets --release -- -D warnings`.
- `cargo doc --release --workspace --no-deps` with the repository's warning policy.
- `RUSTFLAGS='-C target-cpu=generic' cargo check -p leanvm --target powerpc64-unknown-linux-gnu`.
- The x86 AVX-512 workspace cross-check from `AGENTS.md`, run in Docker with `gcc-x86-64-linux-gnu` for jemalloc's C build. A native macOS workspace cross-check lacks that C compiler; the Docker check completes the full workspace.
- `cargo fmt --all -- --check` and `git diff --check`.

The Python verifier was removed by this upstream base and is not restored. Architectural conformance fixtures and the ignored tests were not generated or run. Big-endian validation is a compile check; proving there remains explicitly unsupported by the packed witness implementation. Actual MIPS64/Cannon compatibility, step counts, memory use and performance must be measured with the exported artifacts. The current class setup still evaluates recursion fixed polynomials, which may remain expensive in Cannon. Normalization changes program identity and requires proving under the normalized key. Mixed zero-knowledge leaves are explicitly unsupported. Application code must authenticate the complete class and authorized VK digests. The prose argument above relies on the existing PCS, transcript and recursion soundness assumptions; it is not an independent cryptographic audit or formal proof. No unresolved soundness exception was used to complete the implementation.

## Topic commits

Branch: `op-stack/mixed-program-tree`. The first two commits preserve Kevaundray Wedderburn's authorship. The MSRV declaration, stable API substitutions, endian conversion and portable arithmetic are separate topics. No push, pull request or upstream comment was made.

| Commit | Change |
| --- | --- |
| `045d3dd0` | Port committed-program keys, proofs and native/recursive verification to the modern layout. |
| `8559b374` | Preserve the upstream key decoder's `as_chunks` cleanup. |
| `609f186b` | Lower workspace MSRV from 1.97 to 1.95 for downstream git dependencies. |
| `1605c08b` | Replace three unstable lowest-bit operations with Rust 1.95 equivalents. |
| `e6e97311` | Canonical little-endian word hashing and an explicit refusal of packed big-endian proving. |
| `10ee3515` | Accelerate portable carry-less multiplication, squaring and three-limb Karatsuba products. |
| `4001fb2c` | Export standalone committed proofs and native measurements. |
| `362b2a0e` | Add normalized program classes, witnessed keys, in-circuit binding and mixed claim-set trees. |
| `6448ccbf` | Export class data, mixed roots and claims, with a file-only verifier path. |

The final documentation commit records this design, benchmark tables and validation report.
