# Mixed-program member-list trees

This fork extends the committed-program tree at `da5c9648`. A tree can now authenticate multiple leaf classes and carry both arbitrary-program statements and leanSPHINCS signature members. No OP Stack code or native root fixed-column-opening optimization is included.

## One output convention

Every mixed leaf publishes an **ordered, nonempty list of at most K four-word members**. Its output is BLAKE2s-256 of the list digest's 32 little-endian bytes. There is no prover-controlled choice between interpreting an output as a member and interpreting it as a list digest. An old guest must be ported; a one-member leaf uses the same convention as a batch.

The guest does not know its VK. It computes only the member-list digest. The first-level circuit reads the list, checks its output commitment, computes the VK digest from the witnessed key and constructs one group whose label is `(vk_digest_words[0..4], 0, 0)`. The very same member wires feed the list chain and the group chain. The union rows then authenticate and combine these groups. Order and repetitions matter to the leaf output; the root's canonical claim set sorts and deduplicates members and merges equal labels.

We chose one convention instead of a label mode bit. A mode chosen by the prover would permit reinterpretation of arbitrary program hashes. A mode authenticated in the label could be sound, but would introduce two application statement types without a benefit here.

### Exact list digest

Use BLAKE2s compression with the ordinary unkeyed 32-byte parameter IV. Each message block is eight little-endian u64 words. The counter below is a framing code, **not a byte length**. Only the end block has the final flag set.

| Block | Eight words | Counter |
| --- | --- | ---: |
| Header | `u64::from_le_bytes(*b"members1"), 0, 0, 0, 0, 0, 0, 0` | 17 (`16 | START`) |
| Two members | first four words, second four words | 26 (`16 | MEMBER | PAIR`) |
| Odd last member | four member words, four zeros | 18 (`16 | MEMBER`) |
| End | same words as Header | 20 (`16 | END`), final |

Counter bit 4 is set on every list compression and clear on every claim-set compression. Thus a list cannot be parsed as a set, or a set as a list, without breaking the hash binding. `Members` can hash an empty list, but mixed first-level circuits require at least one member.

The group uses the existing written form: VK-label header at counter 1, member blocks at 10 or 2, and a `claimset` end at counter 4 with final set. Its first four header words are the constrained VK digest, followed by four zeros. The first-level circuit constrains presence bits to a nonempty prefix of at most K members, zeros every absent word, and binds whether the last block contains one or two members. It does not trust a native precheck to impose this relation.

### Guest and native APIs

The SDK exposes `members::Members::{new,push,finish}`, `members::{digest,output}`, and guest-only `members::{commit_members,commit_member}`. A guest must commit the list digest exactly once. A one-member port retaining an old public-value digest can use:

```rust,ignore
let mut values = leanvm_guest::PublicValues::new();
values.commit(&application_values);
leanvm_guest::members::commit_member(&values.digest());
```

`programs/fibonacci-members` and `programs/preimage-members` demonstrate this port; the original guests and signer-set guest remain available. A `MixedLeaf` contains `key`, `proof`, `output` and `members: &[[u64; 4]]`. Its `claims()` returns the VK-labelled group. Native aggregation checks the list bound, output, key dimensions and proof announcement before recording the proof. The rows independently enforce the cryptographic bindings.

## Leaf classes and circuit kinds

`LeafClass { program: ProgramClass, shape: LeafShape }` describes one leaf circuit. `ProgramClass` contains `log_bytecode`, `log_ram`, `log_advice`, `image_words` (a nonzero power of two), and `max_members` (K, at least one). `Tree::mixed_classes(&classes, shape)` takes an ordered, nonempty list; `shape.leaf` must equal `classes[0].shape`. `Tree::mixed(class, shape)` remains a single-class convenience constructor. A class may use `LeafShape::zero_knowledge()`. `ProgramClass::prover(shape)` then selects fresh OS randomness automatically. See [ZK leaves](mixed-program-tree-zk.md) for the design, measurements and privacy limits.

There is one first-level circuit per class, verifying `shape.arity_0` leaves of that class. `aggregate_programs_at(class_index, leaves, declare)` chooses it; `aggregate_programs` chooses class zero. Each circuit pins its own announcement, normalized key dimensions and K. Nodes accept small-tier first levels, wrapped ZK first levels and other small-tier nodes. The class key includes every circuit's verifier columns, and the fixed-polynomial opening binds the selected kind to those columns. A valid proof from another class cannot replace them even if the recursion heights match.

Plain first-level circuits share the small recursion tier's padded heights. Each ZK class instead has a dedicated first-level tier at its own minimum heights and a `LeafWrap(class)` circuit in the small tier. `aggregate_programs_at` automatically proves both and returns the wrap, preserving callers' folding API. `first_stats(class_index)` reports the actual first-level circuit, including its dedicated heights. The wrap carries the same claim set and authenticates the first level's fixed-polynomial claim. Every tier has its own fixed polynomial and seal root. All classes still share first-level arity.

A kind code is `(((tier << tier_shift) | local_circuit_index) << 1) | is_node`. `is_node` is zero for every first-level class and one for Node/Wrap/LeafWrap. `tier_shift` is the maximum `ceil(log2(circuit_count))` over the recursion tiers. Native decoding checks that the low bit agrees with the circuit position; rows constrain the complete code to a valid kind and use the remaining local bits to select the fixed-polynomial block. First-level roots carry no deferred Fixed/Wide claims, regardless of class index.

### Normalization and identity

Normalize each program with its leaf class before proving. Padding adds illegal bytecode entries, zero image words and possibly larger RAM/advice bounds. It also moves halt to the last slot of the class-sized text: a computed jump that formerly trapped can terminate there, subject to the final `a7 = 93` check. Application authorization must regenerate the key from `(ELF, leaf class)` and authorize its VK digest, not an unauthenticated externally supplied commitment.

The VK digest binds the program commitment root, entry and normalization dimensions/image. It does **not** encode the leaf proof's table heights or K; two classes sharing normalization bounds can share a VK. Those additional constraints are authenticated by the class key and enforced by the class's circuit kind. This distinction is intentional.

## leanSPHINCS signature members

`programs/leansphincs-members` reads a count followed by triples in this order: public key, four-word message, signature. It checks every signature with the existing leanSPHINCS library before appending its member. One invalid signature aborts the run. The existing `programs/leansphincs` signer-set guest is unchanged.

The member is standard BLAKE2s-256 of exactly 72 bytes:

```
ASCII "sphmem01" (8 bytes)
public key root[0..2] (16 bytes)
public key public_param[0..2] (16 bytes)
message[0..4] (32 bytes)
```

All words are little-endian; the 32-byte hash becomes four little-endian u64 member words. There are no length fields or terminators. `leansphincs_members_host::member(&key, &message)` recomputes it. `batch(&[(&key, &message, &signature), ...])` builds advice, expected output and the exact ordered member list. This function does not silently discard invalid signatures; the guest checks them. The guest's advice capacity is 2^16 words. K is enforced by the class circuit, not supplied by the guest as an authorization choice.

Signature users all trust this one authorized guest: reviewers must check advice layout, the exact signature verification call and error handling, key/message field order and encoding, the member domain, list accumulation, and the one final commitment. A consumer must recompute the member from its intended key and message; seeing a hash alone does not establish which application message was authorized.

## Folding and closing

```rust,ignore
let mut acc = Accumulator::default();
let first = tree.aggregate_programs_at(class_index, &leaves, None)?;
tree.fold(&mut acc, &first)?;
let root = acc.close().expect("nonempty batch");
let seal = tree.seal(&sealer, &root.proof)?;
```

The first fold verifies and retains its child. Later folds prove the canonical union of the existing root and the next child, with no declaration override. Repeated members deduplicate. Capacity failure leaves the accumulator unchanged: close and seal it, then retry the child in a new batch. `close()` on an empty accumulator returns `None`, not a fabricated empty proof. A one-child batch closes to its verified child unchanged. Closing resets the accumulator.

`Capacity.claims` is an **exclusive** bound: use 4097 to hold 4096 claims. The group bound is inclusive. The general `aggregate(..., Some(subset))` API still supports deliberate narrowing; `fold` always retains the full union.

## Class-key v2 format

This revision is incompatible with v1 artifacts. The pin is `BLAKE2s-256(b"leanvm/mixed-class-key/v2" || encoding)`. All integers are u64 little-endian, all hashes are raw 32-byte outputs, and there are no optional extensions, padding bytes or trailing data.

| Order / offset | Bytes | Value |
| --- | ---: | --- |
| 0 | 8 | ASCII `LVMXCK02` |
| 8 | 8 | leaf-class count N, at least one |
| 16 | 136 × N | ordered leaf-class records below |
| next | 48 | first arity, largest node arity, tree inverse-rate log, claim bound, group bound, small-tier flag (0 or 1) |
| next | 0 or 24 | if flag=1: small arity, small claim bound, small group bound |
| next | 8 | seal inverse-rate log, exactly 2 |
| next | 8 | seal root count T, exactly 1 or 2 according to the tier flag |
| next | 32 × T | Fixed root, then Wide root if two tiers |
| next | 32 × N | template program commitment roots, in leaf-class order |
| next | 8 | recursion tier count, exactly T |
| next | 48 × T | EMUL, EXK, HASH, SPLIT, CAST, PUB height logs per tier |
| next | 8 | circuit count |
| next | variable | circuit records, in order |

A leaf-class record is five words (bytecode log, RAM log, advice log, image word count, K), eleven leaf table logs (ALU, LOAD, STORE, LD, SD, SHIFT, MUL, MULH, DIV, HASH, EXT), and its inverse-rate log. It is exactly 136 bytes.

Circuit order is First(0)..First(N−1), small-tier Node(2)..Node(small arity), Wrap, large-tier Node(largest arity) for two tiers. The count is N + small arity + 1. With one tier it is First(0)..First(N−1), Node(2)..Node(largest arity), count N + largest arity − 1. Each circuit record contains statement length (8 bytes), six height logs (48), column count (8, exactly 102), then 102 column records: word count (8) followed by that many field words. Each count must be `2^table_log` for the column's table. Heights and statement length must equal the reconstructed design.

The 102 columns are next-wire columns by slot index, then four PUB constant limbs. Slot ranges: EMUL 0..3, EXK 4..7, HASH 8..23, SPLIT 24..88, CAST 89..96, PUB 97; columns 98..101 hold PUB's constants. Field words are polynomial-basis GF(2^64) elements encoded as u64 little-endian.

`mixed_classes_from_bytes(&classes, shape, bytes, &pin)` checks the complete digest and expected descriptors before loading. `mixed_classes_from_trusted_bytes` performs the same structural checks but skips hashing. Single-class loader APIs delegate to these. Reordering, removing or changing a class changes the expected artifact. Loaded objects are verifier-only; unpadded row counts are unavailable and reported as zero, while padded heights and committed word counts remain available.

## Class-key v3 for ZK classes

Classes without ZK retain the exact v2 encoding, circuit sessions and key bytes. A list containing a ZK class uses `LVMXCK03` and digest domain `leanvm/mixed-class-key/v3`. After the magic comes a placement word (1 for isolated ZK first levels), then the class count. Each class record adds one word after its rate: 0 for plain, 1 for ZK (144 bytes per record). The remaining record syntax is v2's.

The tier/root count is the base aggregation tier count plus the number of ZK classes. Circuit order is: plain First classes in class order, small Node circuits, the existing large-tier Wrap if present, LeafWrap circuits in ZK class order, the large Node if present, then dedicated ZK First circuits in class order. Heights are reconstructed and checked against this design. Fixed roots are in tier order. The statement/reduction carries one fixed-polynomial evaluation per tier.

ZK-containing tree sessions add `/zk-leaves/1`, the placement byte and ordered class-kind bytes. Tree envelopes remain version 21; seal sessions remain v2. The internal measurement-only shared layout uses placement 0 and a different session; public loaders refuse it. It is not a supported interchange format.

## Authentication and seals

A trusted setup must generate genuine circuits, columns and roots. Parsing does not prove that these are the intended circuits. Pin the complete class-key digest through trusted application configuration. Built trees derive/cache genuine roots from their own polynomials; loaded trees use their authenticated roots. Both reject substituted roots and foreign seal provers.

The trusted loader's soundness rests entirely on the bytes being genuine. The outer mechanism must authenticate the exact bytes and their association with the supplied class-key digest, for example a binary/prestate embedding both or a pinned content-addressed oracle with that association established during setup. A keccak256 oracle key alone does not prove the separately supplied BLAKE2s digest. The supplied digest is assumed correct and is not checked against bytes in debug or release builds. Prefer the checked loader.

Seal v2 is retained: `SessionId::tagged(b"leanvm/mixed-tree-seal/v2", class_key_digest)`. Its instance is the root statement's length-prefixed limbs. Node and wrap roots open their fixed claims under this session. A wrong digest invalidates existing node/wrap seals. Every first-level root has an empty seal, including nonzero class indices, so a wrong digest is not detected there. This is harmless with genuine bytes: there are no fixed claims, program claims close in-circuit, and the recursion proof is verified against authenticated circuit keys. Digest mismatch detection is a configuration check, not the soundness foundation.

The root proof still evaluates its own fixed columns natively. Sealing only replaces settlement of the recursive Fixed/Wide claims. It is public computation, not a signature or attestation.

## Migration and handoff

The member-list migration from v1 required regenerating tree keys, tree proofs and seals. Adding ZK support does not change existing no-ZK artifacts. Tree envelopes use version 21 and tree sessions use `leanvm-tree-18`; mixed sessions include `/mixed-members/2`, K and the ordered additional leaf descriptors. Standalone committed-program proof/key encodings are unchanged. Same-program recursion remains supported but its tree keys also change with the kind encoding.

A consumer pins (1) the class-key v2/v3 digest and expected ordered classes/tree shape, and (2) authorized normalized program VK digests, including the leanSPHINCS member guest. A claim is now `(VK digest padded to six words, four-word member)`, not `(VK digest, execution output)`. Port existing applications to the universal list-output convention. Keep signature-message authorization and any freshness/replay policy at the application layer.

The sequencer calls the signature host's `batch`, normalizes the member guest with its `ProgramClass`, then uses `class.program.prover(class.shape).prove(&program, &batch.run.advice)`. It forms `MixedLeaf` with `batch.members`, proves first-level nodes with `aggregate_programs_at`, folds them, closes, and calls `seal`. Consumers verify with `verify_claims` or `verify_claims_sealed`. The file-based examples and review packet describe the exact formats; no monorepo integration is part of this branch.

## Measurements

`cargo run --release -p leanvm --example claim_set_leaves -- 100 4097 <directory>` measures a two-class tree and a common-class comparison on 16 threads, one warmup and one measured pass, without cooldown. The large guest verifies 100 raw signatures; capacity is 4096 claims and 16 groups. It exports class keys, root claims/proofs and seals, and reports each class-key part, setup/load, leaf/first/node proving and verification times. The shared-class comparison normalizes both programs to common bounds and a common leaf shape.

### Native measurement, 2026-10-25

Apple M4 Pro, 24 GiB RAM, Rust 1.95 release, `target-cpu=native`, jemalloc, 16 total pool threads. One warmup and one measured pass per operation, no cooldown, on a shared development machine: these are observed samples, not confidence intervals or a controlled speedup claim. In particular, the large leaf uses the same bounds/shape in both cases; its timing difference should not be attributed to the number of classes. No size fallback was needed.

Both trees have first arity 1, node arity 2, inverse-rate log 1, a small tier of 256 claims and a large tier of 4096 claims, each with up to 16 groups. The final measured root has 357 claims in four groups: one Fibonacci member, 100 signature members and two untimed 128-member user-program groups, so the measured fold actually enters the large recursion tier. Fold time includes checking/seeding its prefix and the final node proof.

| Measurement | Two leaf classes | One common leaf class |
| --- | ---: | ---: |
| Class key bytes | 60,027,800 | 50,016,128 |
| Class setup (ms) | 130.594 | 113.728 |
| Checked load (ms) | 104.405 | 85.151 |
| Trusted load (ms) | 35.497 | 24.677 |
| Seal commitment setup (ms) | 50.346 | 47.929 |
| Small leaf prove (ms) | 28.696 | 592.292 |
| Small leaf proof bytes | 331,434 | 448,070 |
| 100-signature leaf prove (ms) | 1,112.221 | 748.614 |
| Signature leaf proof bytes | 446,694 | 446,694 |
| Small first-level node (ms) | 81.859 | 83.136 |
| Signature first-level node (ms) | 79.605 | 79.777 |
| Large-tier fold (ms) | 158.792 | 155.389 |
| Root proof bytes | 278,615 | 278,295 |
| Seal bytes | 338,952 | 339,048 |
| Sealing (ms) | 57.503 | 46.150 |
| Direct verification (ms) | 3.932 | 2.325 |
| Sealed verification (ms) | 2.712 | 2.434 |

Class-key byte breakdown (circuit records include their own lengths and headers):

| Part | Two classes | One class |
| --- | ---: | ---: |
| Magic and descriptor | 368 | 232 |
| Seal-root count and roots | 72 | 72 |
| Template commitment roots | 64 | 32 |
| Tier count and heights | 104 | 104 |
| Circuit count | 8 | 8 |
| First(0) | 10,011,504 | 10,011,504 |
| First(1) | 10,011,504 | — |
| Small Node(2) | 10,011,504 | 10,011,504 |
| Wrap | 10,011,504 | 10,011,504 |
| Large Node(2) | 19,981,168 | 19,981,168 |

The small guest executes 16,437 cycles with one advice word. The signature guest executes 936,575 cycles with 62,501 advice words. Normalization bounds `(bytecode log, RAM log, advice log, image words, K)` are `(12,17,13,64,128)` and `(13,17,16,64,128)`. Leaf table logs in the wire-format order are `[15,4,4,6,7,4,4,4,4,3,3]` and `[20,4,15,18,18,16,4,4,4,16,3]`. The common-class comparison uses the latter bounds and heights for both programs. The ALU floor leaves room for padding other tables; the signature class has LD/SD at 2^18 as requested.

Historical Cannon measurements supplied by the application team on `4919edc3`: checked load 1.76B steps, load plus sealed verify 4.22B steps for either one or four programs; the no-digest spike loader was 0.33B steps. These do not measure this revision. New class keys, list circuits and kinds require fresh Go/Cannon implementation and measurements.
## Stretch E: native root fixed-column openings, design only

A-D's mixed, two-tier and forgery tests pass. E is deliberately a written design: removing the root's columns needs a new native arithmetic adapter, an explicit hint encoding, and a new class-key version, not just another point added to the existing seal. The current root statement does not carry these evaluations. Merely skipping `column_mle` would remove the root circuit's wiring checks and be unsound.

Introduce a sealed-native verifier adapter implementing `Verifier`, `OpeningVerifier` and `PublicColumns`. It delegates transcript arithmetic to the existing verifier but, when `column.fixed` identifies a `FixedColumn`, consumes one canonical F192 evaluation from a separate, exactly counted hint stream and records `(tier, circuit index, column, point, value)`. Each consumed value must be closed by the seal before success is returned. Keep the direct native adapter unchanged as an oracle. The root proof's existing Fiat-Shamir transcript must stay byte-identical; the hint stream must not insert new challenges into it. Do not expose provisional core success as a verified root.

A column with height log `tau` occupies offset `o`, a multiple of `2^tau`, in a circuit block of `2^kappa` words. Let `j` be the circuit's index within its tier and `q` the log of the padded circuit count. Its exact point on the tier polynomial is `p || bits_le(o >> tau, kappa - tau) || bits_le(j, q)`, with `p` the column's `tau` bus coordinates. This is a restriction of the same multilinear table, not a rescaled evaluation: the Boolean high coordinates select precisely that column and circuit. Reconstruct `tau`, `o`, `kappa`, `j` and `q` from authenticated heights, `FixedLayout` and the verified root kind; never take them from hints. Route small-tier points to Fixed, large-tier points to Wide. Keep the existing deferred root claims as additional points on those same commitments.

The public constant limbs require care. `FixedHints::evaluate` already separates each public column into its fixed constant part and the statement's contribution, `sum_z eq(z,p) * limb_j(statement[z])`. The new native path must do the same: open only the fixed constants and evaluate statement contributions locally. It cannot mark the combined `FixedColumns::public_values` vector as wholly fixed. Refactor bus-column descriptors to identify fixed parts without holding their dense vectors; genuinely public non-fixed columns continue to evaluate locally.

Use a new seal domain and a versioned sealed-root envelope containing the root proof plus the ordered evaluation hints and seal. Before any opening challenge, absorb the verified root statement and the entire deterministic claim list, including column/circuit identities, points and values, into the seal instance. Binding a digest of the root proof as well is a conservative way to bind the bus challenges which produced those points. Reconstruct the list from the native adapter; reject missing, extra or reordered hints and check both transcripts' EOF. Batch point claims per authenticated Fixed/Wide stack using `Statement.points`. Do not add the hints to an unbound PCS statement and rely on the old root-statement-only instance: that instance does not contain the new values.

A v2 compact class key can then hold the descriptor, authenticated roots, tier heights and circuit statement/layout metadata, while a separate full proving artifact retains columns. The authenticated digest must cover every verifier layout and commitment parameter. Generate both from the same trusted setup and test agreement. The existing v1 direct verifier continues to require its full columns; compact sealed-only keys must explicitly refuse direct verification instead of fabricating zero columns. This separates capability by construction and avoids making direct verification accidentally depend on unauthenticated hints.

Acceptance tests must compare direct and compact-sealed verification for every root kind in one and two tiers, with first-level roots now requiring native fixed-column openings too. Mutate each hint, point, column, circuit selector, tier selector and length; swap root proofs or class keys; replay an old seal; test truncated and extra hints. Reuse the fake child and fake large-under-wrap attacks, including commitments to forged columns. Check that the root proof's transcript remains identical and that all fixed-column evaluations were actually intercepted. Only then benchmark compact key bytes, load cost, total seal size and Cannon steps. No speedup or compact-key size is claimed by this delivery.

Big-endian build, emulated verifier tests, and the word/byte audit are documented in [big-endian.md](big-endian.md).
