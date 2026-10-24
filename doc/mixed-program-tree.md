# Mixed-program aggregation trees

This branch starts from upstream `riscv-exploration` at `06e5c9cd6981103786f9d0a17324241b559a50d3`. It ports committed-program [PR #418](https://github.com/leanEthereum/leanVM/pull/418) into the current generic verifier and adds a mixed-program mode to the existing claim-set aggregation tree. The implementation is experimental and has no formal soundness proof.

## Program identity

Previously `Program::digest` hashed the decoded bytecode table and initial RAM image, and a recursion circuit embedded that program's session as constants. Its deferred bytecode and image claims reached the root, which evaluated the program's tables itself. Building and verifying a tree therefore required one specific program.

`Program::new` now commits the stacked decoded table at inverse-rate logarithm 4. `VerifyingKey` contains the root, bytecode dimension, entry address, RAM and advice dimensions, and the image with its length. Its digest is BLAKE2s of the versioned domain separator and the canonical little-endian encoding. A standalone verifier needs that key, the output, and the proof. It reconstructs the proof layout from metadata without decoding or allocating bytecode. The extra program opening follows the witness opening. It opens the Frobenius-conjugate bytecode points used by the existing deferred program claim and combines their values with the image evaluation. Every value is bound into the transcript before the opening's batching challenges.

The original PR's authorship is preserved in its two ported commits. The conflict resolutions retain the modern bus/table residual, generic arithmetic verifier, and zero-knowledge recorder instead of restoring the deleted Python verifier or the old public API crate. The moved stacked PCS accepts point-only statements. The recursion verifier consumes the additional opening. New proof-envelope versions refuse proofs of the previous statement format.

## Shape classes and normalization

`ProgramClass` specifies the bytecode dimension, RAM dimension, advice dimension, and padded image length. The image length is a nonzero power of two. `TreeShape` additionally fixes every leaf table's height, the leaf and tree rates, arities, and claim-set capacities and tiers. These together are the class. No leaf program or key is an input to `Tree::mixed`.

`ProgramClass::normalize` pads shorter decoded programs with illegal entries and smaller images with zeros before key generation. It can enlarge the RAM and advice regions to the class dimensions. The resulting normalized VK digest is the identity to claim; an existing proof under an unnormalized key cannot be relabeled. This deliberately chooses explicit normalization over circuits supporting many different byte lengths and dynamic hash counters. Enlarged advice and memory bounds are part of that identity: a memory access that trapped under the original bounds can succeed after normalization. The authorized identity is therefore `(ELF, class)`, not ELF alone. An authorizer must regenerate the normalized key from the intended ELF and class and compare its digest with the authorized claim label. A prover can pad table heights through the existing filler planner; the ALU floor must allow the other tables' closing jumps. Proofs that announce a different final shape are refused.

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

The class-key and seal implementation below replaces setup and deferred fixed-polynomial evaluation. It does not remove the native recursion verifier's own fixed-column evaluations. No Go verifier or OP Stack integration is included. The upstream PRs were checked on 2026-10-25: #522 remains open at `461ab229da3a2f1232dce68e74756ee26ca142d6`, #553 at `0c5a8f3dc422b0e8ef4947fb62a579603fb8ae24`. Neither is merged into this branch.

## Authenticated class keys

`Tree::mixed_verifier_bytes(&roots)` serializes the complete class key. Generate the roots with `tree.seal_prover().roots()` from a trusted `Tree::mixed(class, shape)` setup. The consumer pins `BLAKE2s-256(b"leanvm/mixed-class-key/v1" || encoding)`, with no terminator, length prefix, keyed mode or personalization in this hash. `Tree::mixed_class_key_digest` computes it. A digest supplied beside untrusted data is not an authentication mechanism: distribute the expected digest through the application's trusted configuration. Authentication covers verifier columns and roots as well as dimensions. The loader does not regenerate the circuits or prove that supplied columns and roots are consistent with the intended circuits; the trusted setup must establish that.

`Tree::mixed_from_bytes(class, shape, bytes, &expected_digest)` first checks this pin, then compares the encoded descriptor with the caller's expected class and shape, validates structural lengths and heights, and refuses trailing data. The same bytes encode identically on big-endian hosts. Loaded trees expose their authenticated roots through `seal_roots()`. Passing different roots to their sealed verifier is refused. A native builder can explicitly use another root set, but that changes its class-key digest and seal session; applications must pin the genuine roots.

### Loading bytes authenticated by an outer mechanism

`Tree::mixed_from_bytes` remains the default and recommended path. `Tree::mixed_from_trusted_bytes(class: ProgramClass, shape: TreeShape, bytes: &[u8], digest: &Hash) -> Result<Tree<'static>, TreeError>` skips the BLAKE2s pass and uses the caller's digest as the seal-session identity. It shares the checked loader's entire structural parser: expected descriptor, lengths, heights, exact consumption and verifier-only restrictions. It does not hash the bytes in either debug or release builds.

Use the trusted loader only when an outer mechanism guarantees the exact bytes and their association with the supplied BLAKE2s class-key digest. Valid examples are bytes and their digest embedded together in a trusted binary or absolute prestate, or an oracle lookup under a pinned content hash whose association with this class-key digest was established during trusted setup. A keccak256-addressed oracle authenticates the bytes under its keccak256 key; it does not by itself prove their BLAKE2s digest equals the separately supplied seal identity. Pin that association as well. With untrusted bytes, this method accepts forged verifier data even if the supplied digest names a genuine class key. A correct seal is not a substitute for authenticating the artifact.

Structural loading can succeed with an incorrect digest. Direct verification does not use that digest and cannot detect this mistake. Seals with PCS openings made under the genuine digest fail under the changed session. Node and wrap roots carry fixed claims, so their existing seals fail with the wrong digest. The explicit v2 exception is a first-level root: its seal has no opening and no challenge-dependent check, so it still verifies with a wrong digest. This is harmless when the class-key bytes are genuine: first-level roots carry no fixed claims, their program claims close in-circuit, and the root recursion proof is checked against circuit keys from those outer-authenticated bytes. Soundness rests entirely on the bytes being genuine. The supplied digest is assumed correct and is not checked against the bytes in release builds (or debug builds); it only binds the seal session. Detecting a wrong digest is a misconfiguration check, not a soundness requirement. Seal v2 is unchanged.

We measured the authenticated branch `4919edc3` in Cannon using the example's four-program class: `mixed_from_bytes` took **1.76B steps**, and loading plus `verify_claims_sealed` took **4.22B steps**, the same total for one and four distinct programs. Compared with the spike's 0.33B-step loader, approximately 1.43B steps were the BLAKE2s pass over the class key. These are our measurements on `4919edc3`, not measurements of the trusted loader. Native nodes can keep using the checked loader once at startup; the trusted path avoids a redundant pass when Cannon's prestate or pinned oracle already supplies the required authentication. Class-key v1 and seal v2 encodings are unchanged by the loader API.

### Class-key v1 wire format

All integers below are unsigned 64-bit little-endian, without padding. Hashes are raw 32-byte BLAKE2s outputs, not word-reversed. Field words encode the polynomial-basis `GF(2^64)` element as a little-endian u64; every bit pattern is canonical. The format is mixed, plain-leaf mode only, so no variable mode or zero-knowledge flag is present. Changing circuit schemas or protocol semantics requires a new version and pin.

| Offset | Bytes | Value |
| --- | ---: | --- |
| 0 | 8 | ASCII `LVMXCK01` |
| 8 | 32 | bytecode log, RAM log, advice log, image word count |
| 40 | 88 | eleven leaf table logs: ALU, LOAD, STORE, LD, SD, SHIFT, MUL, MULH, DIV, HASH, EXT |
| 128 | 56 | leaf inverse-rate log, first arity, largest arity, tree inverse-rate log, claim capacity, group capacity, small-tier flag (0 or 1) |
| 184 | 0 or 24 | if the flag is 1: small arity, small claim capacity, small group capacity |
| 184 or 208 | 8 | seal inverse-rate log, exactly 2 |
| 192 or 216 | 8 | root count, exactly the tier count (1 or 2) |
| following | 32 per root | Fixed root, then Wide root if two tiers |
| following | 32 | placeholder program's bytecode commitment root |
| following | 8 | tier count, exactly 1 or 2 |
| following | 48 per tier | recursion table logs in order EMUL, EXK, HASH, SPLIT, CAST, PUB; small tier first |
| following | 8 | circuit count |
| following | variable | circuit records below, concatenated |

The circuit order is First, small-tier Node(2) through Node(small arity), Wrap, then large-tier Node(largest arity) for two tiers. For one tier it is First then Node(2) through Node(largest arity), without Wrap. Thus the counts are small arity + 2 and largest arity respectively. Every circuit record has: statement length (8 bytes), its six table logs (48), column count (8, exactly 102), then 102 column records. A column record is its length (8) followed by exactly that many field words (8 bytes each). Every length must equal `2^table_log` for its column's table; circuit heights and statement length must equal the reconstructed design's.

The 102 columns are next-wire columns by global slot index, then four public constant limbs. Slot ranges are EMUL 0..3, EXK 4..7, HASH 8..23, SPLIT 24..88, CAST 89..96, PUB 97. Columns 98..101 are the four PUB constant limbs. There are no optional extensions, internal padding bytes, or trailing bytes. `embed.rs`, `table.rs` and `fixed.rs` are the authoritative definitions. Structural decoding is not circuit validation. All dimensions and layout conventions, including `FixedLayout` and the circuit ordering, are protocol data for a Go port.

### Seals

A seal opens a root's deferred Fixed and, for two tiers, Wide evaluations against the class's authenticated commitments. Mixed sessions are `SessionId::tagged(b"leanvm/mixed-tree-seal/v2", class_key_digest)`, using the existing Fiat-Shamir `SessionId` framing: concatenate the domain bytes and the 32 digest bytes, initialize the BLAKE2s duplex with `DERIVATION_IV` for `irtf-cfrg-fiat-shamir/session-id`, absorb that concatenation and squeeze 32 bytes. This is not a plain BLAKE2s hash; a Go port must match `fiat_shamir/src/lib.rs` and the duplex framing exactly. The digest covers the complete shape, roots and verifier data, so no independent tree tag is needed in mixed mode. Same-program trees use the v2 domain with their tree session tag and roots. This changes compatibility with the unversioned spike artifacts; regenerate their keys and seals.

The instance is `LengthPrefixed(root.limbs().as_flattened())`, the complete root statement in existing transcript encoding. The native verifier first validates the root recursion proof, mode, claim-set digest and all non-fixed deferred claims, including the circuit matrices. It builds each opening statement itself from that authenticated root: the polynomial identifier, point prefix of the design's dimension, value, stack size, lane count and WHIR configuration. None of those is selected by the seal. It then verifies the openings in Fixed, Wide order and checks EOF. All claims are therefore bound before the seal's batching and query challenges. A root substitution or a different class key changes the transcript. The seal is not a signature or evidence that its creator owns a witness; anyone with the public polynomials can seal. A first-level root carries no deferred fixed claim, so its seal is empty and the root proof alone supplies the relevant authentication.

This closes the recursive fixed claims, including the large circuit behind a wrap. A prover that substitutes a fake circuit's fixed polynomial can satisfy local recursion rows, but cannot open that polynomial under the authenticated class roots. Commitments to forged polynomials only yield another class key, which the consumer's pin refuses. The native root proof still evaluates its own fixed columns directly. The seal's soundness inherits PCS opening soundness, BLAKE2s binding, the transcript's challenge assumptions and the existing recursion reduction argument.

### Verifier-only objects

A loaded tree contains verifier stubs, not proving circuits. `prove`, `prove_first`, `prove_node`, `aggregate`, `aggregate_leaves`, `aggregate_programs`, `seal_prover` and `seal` return `TreeError::VerifierOnly` before touching their witnesses. Private proving paths enforce the same guard. A `Program` without its commitment returns `ProveError::VerifierOnly` from plain and zero-knowledge proving, including execution/witness/opening helpers. Executing or measuring a program is independent of owning its proving commitment.

## Exporting verification inputs

Run `rustup run 1.95 cargo run --release -p leanvm --example committed_program -- .context/exports/plain` for standalone inputs. Run `rustup run 1.95 cargo run --release -p leanvm --example mixed_program_tree -- .context/exports/hardened` for the mixed class. The parent directory contains `class-key.bin`, `class-key.digest` (hex text for distribution through a trusted channel), and `class.bin` (the example's convenience expected-class/shape descriptor). Each `distinct-1`, `distinct-2`, `distinct-4` directory contains `root.bin`, `claims.bin`, and `seal.bin`. The class key already contains everything authenticated, including seal roots; `class.bin` is not a second authority.

Use `--verify .context/exports/hardened/distinct-4 <trusted-64-hex-digit-class-key-digest>` to load the class key and verify both direct and sealed paths using only files. Supply the pin from trusted configuration, not by trusting an attacker's accompanying digest file. This example's convenience descriptor supports its one-tier class; the library class-key format and loader support two tiers. The same-program comparison is a positional output tree and has no claim-set union.

## Cannon measurements on the spikes

These numbers were measured by us in the OP Stack workspace on the supplied setup/seal spikes, before this hardening. They are not new measurements of the authenticated loader. Source: `sp1-proof-claims/.context/leanvm-fork-hardening/CANNON-RESULTS.md`, dated 2026-10-25. Class logs `(12,17,13)`, image 64 words, leaf/tree inverse-rate log 1, arities 2+2, capacity `(8,4)`, standard Cannon without dclmul, about 131 MiB memory.

| Operation | Cannon steps |
| --- | ---: |
| Plain Fibonacci 16k / 131k, preimage | 0.65B / 0.67B / 0.64B |
| Original class setup | 9.99B |
| Original setup + root verify, 1 or 4 distinct programs | 16.21B |
| Embedded load v1 (recommitted placeholder) | 4.94B |
| Embedded load v2 | 0.33B |
| Embedded direct verify including load | 6.55B |
| Embedded sealed verify including load | 2.79B |

The last total is load 0.33B, root recursion proof and set 1.94B, matrix/other claims 0.45B, and seal 0.07B. The spike key was 24.1 MiB, native load 13 ms, setup 59 ms, commitments 30 ms once, sealing 19 ms, seal about 162 KiB. Approximately 95% of the 1.94B root stage was fixed-column evaluation. The hardened loader also hashes the full key and validates its schema; Cannon must be rerun with the new files before making performance claims about it.

## Earlier native measurements at e6780cb8

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

## Earlier validation at e6780cb8 and remaining risks

`rustup run 1.95 cargo test --workspace --release` passes: 526 passed, zero failed, four existing ignored tests. The four new mixed-mode tests cover two guest programs, identical class circuit keys, union and discard, cross-builder root verification, incorrect outputs and labels, swapped key/output associations, uncovered claims, tampered root/entry/image, direct circuit-row checks that bypass native prechecks, and a valid non-default entry address. Existing same-program and zero-knowledge tests also pass.

The following checks pass on Rust 1.95:

- `cargo check -p leanvm --examples`.
- `cargo clippy --workspace --all-targets --release -- -D warnings`.
- `cargo doc --release --workspace --no-deps` with the repository's warning policy.
- `RUSTFLAGS='-C target-cpu=generic' cargo check -p leanvm --target powerpc64-unknown-linux-gnu`.
- The x86 AVX-512 workspace cross-check from `AGENTS.md`, run in Docker with `gcc-x86-64-linux-gnu` for jemalloc's C build. A native macOS workspace cross-check lacks that C compiler; the Docker check completes the full workspace.
- `cargo fmt --all -- --check` and `git diff --check`.

The Python verifier was removed by this upstream base and is not restored. Architectural conformance fixtures and the ignored tests were not generated or run. Big-endian validation is a compile check; proving there remains explicitly unsupported by the packed witness implementation. The hardened artifacts still require new MIPS64/Cannon compatibility and performance measurements. The native root proof still evaluates its own fixed columns, which remain expensive in Cannon. Normalization changes program identity and requires proving under the normalized key. Mixed zero-knowledge leaves are explicitly unsupported. Application code must authenticate the complete class and authorized VK digests. The prose argument above relies on the existing PCS, transcript and recursion soundness assumptions; it is not an independent cryptographic audit or formal proof. No unresolved soundness exception was used to complete the implementation.

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

## Stretch E: native root fixed-column openings, design only

A-D's mixed, two-tier and forgery tests pass. E is deliberately a written design: removing the root's columns needs a new native arithmetic adapter, an explicit hint encoding, and a new class-key version, not just another point added to the existing seal. The current root statement does not carry these evaluations. Merely skipping `column_mle` would remove the root circuit's wiring checks and be unsound.

Introduce a sealed-native verifier adapter implementing `Verifier`, `OpeningVerifier` and `PublicColumns`. It delegates transcript arithmetic to the existing verifier but, when `column.fixed` identifies a `FixedColumn`, consumes one canonical F192 evaluation from a separate, exactly counted hint stream and records `(tier, circuit index, column, point, value)`. Each consumed value must be closed by the seal before success is returned. Keep the direct native adapter unchanged as an oracle. The root proof's existing Fiat-Shamir transcript must stay byte-identical; the hint stream must not insert new challenges into it. Do not expose provisional core success as a verified root.

A column with height log `tau` occupies offset `o`, a multiple of `2^tau`, in a circuit block of `2^kappa` words. Let `j` be the circuit's index within its tier and `q` the log of the padded circuit count. Its exact point on the tier polynomial is `p || bits_le(o >> tau, kappa - tau) || bits_le(j, q)`, with `p` the column's `tau` bus coordinates. This is a restriction of the same multilinear table, not a rescaled evaluation: the Boolean high coordinates select precisely that column and circuit. Reconstruct `tau`, `o`, `kappa`, `j` and `q` from authenticated heights, `FixedLayout` and the verified root kind; never take them from hints. Route small-tier points to Fixed, large-tier points to Wide. Keep the existing deferred root claims as additional points on those same commitments.

The public constant limbs require care. `FixedHints::evaluate` already separates each public column into its fixed constant part and the statement's contribution, `sum_z eq(z,p) * limb_j(statement[z])`. The new native path must do the same: open only the fixed constants and evaluate statement contributions locally. It cannot mark the combined `FixedColumns::public_values` vector as wholly fixed. Refactor bus-column descriptors to identify fixed parts without holding their dense vectors; genuinely public non-fixed columns continue to evaluate locally.

Use a new seal domain and a versioned sealed-root envelope containing the root proof plus the ordered evaluation hints and seal. Before any opening challenge, absorb the verified root statement and the entire deterministic claim list, including column/circuit identities, points and values, into the seal instance. Binding a digest of the root proof as well is a conservative way to bind the bus challenges which produced those points. Reconstruct the list from the native adapter; reject missing, extra or reordered hints and check both transcripts' EOF. Batch point claims per authenticated Fixed/Wide stack using `Statement.points`. Do not add the hints to an unbound PCS statement and rely on the old root-statement-only instance: that instance does not contain the new values.

A v2 compact class key can then hold the descriptor, authenticated roots, tier heights and circuit statement/layout metadata, while a separate full proving artifact retains columns. The authenticated digest must cover every verifier layout and commitment parameter. Generate both from the same trusted setup and test agreement. The existing v1 direct verifier continues to require its full columns; compact sealed-only keys must explicitly refuse direct verification instead of fabricating zero columns. This separates capability by construction and avoids making direct verification accidentally depend on unauthenticated hints.

Acceptance tests must compare direct and compact-sealed verification for every root kind in one and two tiers, with first-level roots now requiring native fixed-column openings too. Mutate each hint, point, column, circuit selector, tier selector and length; swap root proofs or class keys; replay an old seal; test truncated and extra hints. Reuse the fake child and fake large-under-wrap attacks, including commitments to forged columns. Check that the root proof's transcript remains identical and that all fixed-column evaluations were actually intercepted. Only then benchmark compact key bytes, load cost, total seal size and Cannon steps. No speedup or compact-key size is claimed by this delivery.

## Hardening validation and native measurements

On 2026-10-25, Rust 1.95.0 (`59807616e`), Apple M4 Pro, release `target-cpu=native`, jemalloc and an explicitly initialized 16-thread pool:

- `rustup run 1.95 cargo test --workspace --release`: 533 passed, zero failed, four existing ignored tests. The new test names and adversarial coverage are listed in [the review packet](mixed-program-tree-review.md).
- `rustup run 1.95 cargo clippy --workspace --all-targets --release -- -D warnings`: passed.
- `rustup run 1.95 cargo fmt --all -- --check` and `git diff --check`: passed.
- `RUSTFLAGS='-C target-cpu=generic' rustup run 1.95 cargo check -p leanvm --target powerpc64-unknown-linux-gnu`: passed. This is a compile check, not a big-endian execution test.
- `rustup run 1.95 cargo doc --release --workspace --no-deps`: passed with the repository's warning policy.
- All three exported cases reloaded from files and passed direct and sealed verification. Python `hashlib.blake2s` independently reproduced the exported class-key digest.

The class is the same one-tier example described above. The key is **25,282,600 bytes (24.111 MiB)**. Its pinned digest is `de82c3471f61accaa408d475404d7cd911edf04f23873a5d0f4fb9a2344ae171`. Setup took 46.2620 ms; seal commitments took 18.9061 ms once. Authenticated load, including hashing the complete key and reconstructing its verifier tables, took 41.9793 ms in the export run and 41.48 to 41.61 ms in the independent file-only runs. This is slower than the spike's unauthenticated native load; Cannon's loader cost must be remeasured.

Each timing uses `bench::Plan` with one warmup and three measured passes, no cooldown. Export-run direct verification uses seven measured passes. The table separates sealing measured during export from verification measured in fresh file-only processes, each loading and authenticating the same key. No other build or test was running during these measurements.

| Distinct programs | Sealing ms | Seal bytes | File-only load ms | Direct verify ms | Sealed verify ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 20.3742 | 165,744 | 41.4804 | 2.1369 | 2.1179 |
| 2 | 22.7535 | 166,096 | 41.6143 | 2.2324 | 2.2298 |
| 4 | 20.1239 | 166,192 | 41.5016 | 2.2623 | 2.2138 |

The export run's direct/sealed means were respectively 2.2261/2.0777 ms, 9.5790/2.5027 ms, and 2.0958/2.3348 ms. The two-program direct mean had 20 ms and 36 ms outliers and a ±127.1% interval; the fresh file-only measurements above are recorded separately rather than hiding those samples. These small native differences do not establish a verification speedup. Raw logs are `.context/hardening-native-measurements.log` and `.context/hardening-file-verification.log`; exported files are `.context/exports/hardened/`.

D is complete: a two-tier mixed class aggregates, wraps/narrows, loads, seals and verifies on both paths. Its fake large-under-wrap attack is refused, including a seal made against forged polynomials. E is a design only, for the protocol and representation changes explained above. F is [the external review packet](mixed-program-tree-review.md). The supplied Cannon measurements remain spike-only evidence. No new push, PR or upstream comment was made for this hardening task.

### Hardening commits

| Commit | Change |
| --- | --- |
| `8eb5f992` | Apply the supplied verifier-embedding spike unchanged. |
| `926f050a` | Apply the supplied Fixed/Wide sealing spike unchanged. |
| `6d8600f4` | Return typed errors from verifier-only tree and Program proving entry points. |
| `a50e234c` | Authenticate the complete class key, bind seal sessions to its digest, validate decoding and consolidate exports. |
| `a6e3c109` | Add entry/union row tests, cross-mode rejection and two-tier mixed forgery coverage. |

The following documentation commit contains the v1 wire format, seal binding, normalization authorization rule, measured results, E design and external review packet. The review range is `e6780cb8..HEAD` on `op-stack/mixed-program-tree`.
