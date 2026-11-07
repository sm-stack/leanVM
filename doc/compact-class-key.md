# Mixed claim-set trees and compact class keys

This specification defines mixed member-list trees, class-key v4 (`LVMXCK04`), tree envelope `LVMT` version 22, and seal v3. The tree, reduction and seal domains are `leanvm-tree-19`, `leanvm-tree-reduction-6` and `leanvm/mixed-tree-seal/v3`. Earlier class-key and tree formats are not accepted.

## One output convention

Every mixed leaf publishes an **ordered, nonempty list of at most K four-word members**. Its output is BLAKE2s-256 of the list digest's 32 little-endian bytes. There is no prover-controlled choice between interpreting an output as a member and interpreting it as a list digest. A one-member leaf uses the same convention as a batch.

The guest does not know its VK. It computes only the member-list digest. The first-level circuit reads the list, checks its output commitment, computes the VK digest from the witnessed key and constructs one group whose label is `(vk_digest_words[0..4], 0, 0)`. The same member wires feed the list chain and the group chain. The union rows then authenticate and combine these groups. Order and repetitions matter to the leaf output; the root's canonical claim set sorts and deduplicates members and merges equal labels.

### Exact list digest

Use BLAKE2s compression with the ordinary unkeyed 32-byte parameter IV. Each message block is eight little-endian u64 words. The counter below is a framing code, **not a byte length**. Only the end block has the final flag set.

| Block | Eight words | Counter |
| --- | --- | ---: |
| Header | `u64::from_le_bytes(*b"members1"), 0, 0, 0, 0, 0, 0, 0` | 17 (`16 | START`) |
| Two members | first four words, second four words | 26 (`16 | MEMBER | PAIR`) |
| Odd last member | four member words, four zeros | 18 (`16 | MEMBER`) |
| End | same words as Header | 20 (`16 | END`), final |

Counter bit 4 is set on every list compression and clear on every claim-set compression. Thus a list cannot be parsed as a set, or a set as a list, without breaking the hash binding. `Members` can hash an empty list, but mixed first-level circuits require at least one member.

The group encoding uses VK-label header at counter 1, member blocks at 10 or 2, and a `claimset` end at counter 4 with final set. Its first four header words are the constrained VK digest, followed by four zeros. The first-level circuit constrains presence bits to a nonempty prefix of at most K members, zeros every absent word, and binds whether the last block contains one or two members. It does not trust a native precheck to impose this relation.

### Guest and native APIs

The SDK exposes `members::Members::{new,push,finish}`, `members::{digest,output}`, and guest-only `members::{commit_members,commit_member}`. A guest must commit the list digest exactly once. A one-member port retaining an old public-value digest can use:

```rust,ignore
let mut values = leanvm_guest::PublicValues::new();
values.commit(&application_values);
leanvm_guest::members::commit_member(&values.digest());
```

`programs/fibonacci-members` and `programs/preimage-members` demonstrate this port; the original guests and signer-set guest remain available. A `MixedLeaf` contains `key`, `proof`, `output` and `members: &[[u64; 4]]`. Its `claims()` returns the VK-labelled group. Native aggregation checks the list bound, output, key dimensions and proof announcement before recording the proof. The rows independently enforce the cryptographic bindings.

## Leaf classes and circuit kinds

`LeafClass { program: ProgramClass, shape: LeafShape }` describes one leaf circuit. `ProgramClass` contains `log_bytecode`, `log_ram`, `log_advice`, `image_words` (a nonzero power of two), and `max_members` (K, at least one). `Tree::mixed_classes(&classes, shape)` takes an ordered, nonempty list; `shape.leaf` must equal `classes[0].shape`. `Tree::mixed(class, shape)` remains a single-class convenience constructor. A class may use `LeafShape::zero_knowledge()`. `ProgramClass::prover(shape)` then selects fresh OS randomness automatically. See [Privacy and randomness](#privacy-and-randomness) for what remains public.

There is one first-level circuit per class, verifying `shape.arity_0` leaves of that class. `aggregate_programs_at(class_index, leaves, declare)` chooses it; `aggregate_programs` chooses class zero. Each circuit pins its own announcement, normalized key dimensions and K. Nodes accept small-tier first levels, wrapped ZK first levels and other small-tier nodes. The class key authenticates the fixed-polynomial commitments, whose openings bind the selected kind to its circuit columns. A valid proof from another class cannot replace them even if the recursion heights match.

ZK placement is selected when building or loading the tree; see [Caller-pinned ZK placement](#caller-pinned-zk-placement). All classes share first-level arity.

A kind code is `(((tier << tier_shift) | local_circuit_index) << 1) | is_node`. `is_node` is zero for every first-level class and one for Node/Wrap/LeafWrap. `tier_shift` is the maximum `ceil(log2(circuit_count))` over the recursion tiers. Native decoding checks that the low bit agrees with the circuit position; rows constrain the complete code to a valid kind and use the remaining local bits to select the fixed-polynomial block. First-level roots carry no recursive fixed-polynomial claims, regardless of class index; their seals still authenticate their own circuit columns.

### Normalization and identity

Normalize each program with its leaf class before proving. Padding adds illegal bytecode entries, zero image words and possibly larger RAM/advice bounds. It also moves halt to the last slot of the class-sized text: a computed jump that formerly trapped can terminate there, subject to the final `a7 = 93` check. Application authorization must regenerate the key from `(ELF, leaf class)` and authorize its VK digest, not an unauthenticated externally supplied commitment.

The VK digest binds the program commitment root, entry and normalization dimensions/image. It does **not** encode the leaf proof's table heights or K; two classes sharing normalization bounds can share a VK. Those additional constraints are authenticated by the class key and enforced by the class's circuit kind.

## leanSPHINCS signature members

`programs/leansphincs-members` reads a count followed by triples in this order: public key, four-word message, signature. It checks every signature with the existing leanSPHINCS library before appending its member. One invalid signature aborts the run. `programs/leansphincs` is a separate signer-set guest.

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

## Privacy and randomness

The sequencer receives the ZK leaf proof, normalized public program key, output and ordered members. Members are public by design, as are the program identity, class, padded dimensions and proof size. Applications must ensure the chosen output/members do not reveal the secret they intend to hide. Choose the padded class independently of secrets; zero knowledge does not hide an application-dependent choice of class or public output. `ProgramClass::prover` sets a height floor, not a ceiling: ensure all supported secret inputs fit that floor, and check the announced shape before releasing a proof. Aggregation refuses a different announcement, but cannot undo disclosure of a larger standalone proof already sent.

Aggregation nodes need not be zero knowledge: their witness contains the already-ZK leaf proof and public data, not the leaf's private advice. This does not turn plain leaves in the same tree into private leaves. It also does not protect witness data exposed by the prover's process, logs, timing, storage or host memory.

ZK proving uses `Randomness::Os`. `Prover::prove` draws a new OS seed for every ZK proof, even when the `Prover` is reused or copied. Entropy failure panics rather than falling back to deterministic randomness. `Randomness::Fixed` is available only to zk's own unit tests or with the explicit development feature `zk/test-util`; core tests enable that feature through a dev dependency. Reusing a fixed seed reuses pad keys and can reveal differences between witnesses. Do not enable this feature in production. Low-level `Seed::stream(purpose)` intentionally restarts a purpose's deterministic stream; it is an internal building block, not a safe reusable source for separate proofs. No seed is accepted by the normal production `Prover` API.

## What is authenticated

Trusted artifact generation builds the real circuits, stacks each tier's fixed columns and commits them at seal log inverse rate 2. The application pins the complete class-key digest. Parsing is not a proof of correct circuit generation; the trusted-byte loader requires external authentication of the exact artifact and its association with that digest.

The compact key contains dimensions and commitment roots, **no fixed-column rows**. A loaded `Tree` holds no dense polynomial tables. `verify_claims_sealed` verifies using seal-provided evaluations authenticated by PCS. Direct `verify_claims` on a loaded verifier returns `TreeError::SealRequired`. Prover-built trees still support direct verification and all existing proving operations. Neither loader enables proving.

### Carried tier usage

A statement carries one field-valued Boolean per tier.

- A First circuit exposes all usage bits as zero: it verifies leaves, not recursion circuits.
- A Node verifying SMALL children sets SMALL usage to one. The SMALL Wrap that verifies a LARGE child sets LARGE usage to one. A LeafWrap sets its dedicated First tier's usage to one.
- Each then ORs in every verified child's usage bits. In characteristic two, `OR(a,b) = a+b+ab`. Child bits are constrained by `b*(1+b)=0`; a First child's bits are additionally constrained to zero using its authenticated first/node bit.
- A carried fixed claim's reduction scale is that child's usage bit. Fresh child-column claims always have unit scale and set the appropriate tier's bit.
- The circuit exposes each fixed evaluation multiplied by its resulting usage bit, so an unused tier's published evaluation is canonically zero.

These operations are circuit constraints, not decisions made by the honest sealer. The child statement is in the verified child proof's instance; its transcript digest binds the reduction instance. Thus a zero root usage bit means there was no nonzero-weight fixed claim for that tier anywhere in the recursive reduction. A malicious witness cannot remove a used tier by choosing an opening list. The reduction may internally evaluate a zero-weight polynomial, but that evaluation contributes nothing to the identity and is not a root claim.

Usage is conservative over children actually verified. An absent union slot verifies a repeated child, so usage need not describe only the final declared subset. Narrowing a declared set cannot remove cryptographic obligations. All bits are the OR of the verification history, not an application claim about which public members remain.

### The root's own columns

The root verifier checks the recursion commitment, hash reduction, bus, constraints and PCS opening, plus the hash circuit's matrix identity. Its public-column arithmetic obtains each fixed-column value from the seal rather than from a row array. For a PUB constant column it adds the statement contribution itself:

`sum_{z < statement_len} eq(z, bus_point[..tau_PUB]) * statement_limb[z]`.

Genuine PUB constants are zero on those statement rows. The sealer supplies only the constant-column evaluation, never this public contribution. The verifier records the column identity, point and supplied value; accepting this intermediate check alone would be unsound.

Every recorded evaluation is then opened against the root tier's authenticated fixed commitment, at the root circuit's block. For local circuit index `j`, fixed-stack width `kappa`, column height `tau` and aligned column offset `offset_c`, the PCS claim is:

```
StackClaim::Point {
    offset: (j << kappa) + offset_c,
    low_point: bus_point[..tau],
    value: supplied_fixed_value,
}
```

This is the same stacked polynomial that authenticates children inside recursion. No separate per-circuit commitment is needed. Circuit/column selectors are fixed Boolean block offsets, derived by the verifier.

The **entire serialized root proof** is hashed into the seal instance, in addition to its statement. The root's bus points depend on that proof, so binding only the statement would not fix these PCS claims before the seal's challenges. All supplied root evaluations are absorbed before any PCS challenge. Consequently the sealer cannot adapt either points or values after seeing those challenges. A false root either fails native algebra/PCS checks, or demands a false opening against an authenticated fixed commitment. The same reasoning applies to a root fabricated for a different circuit with matching heights.

The argument assumes the binding and soundness properties of the transcript, hash and PCS.

## Exact class-key format

All integers below are unsigned little-endian u64. Hashes are raw 32 bytes. No optional extension bytes, padding or trailing bytes are allowed. The pin is:

`BLAKE2s-256(ASCII "leanvm/mixed-class-key/v4" || complete_key_bytes)`.

| Order | Length | Value |
| --- | ---: | --- |
| Magic | 8 | ASCII `LVMXCK04` |
| Placement | 8 | caller-pinned placement: 0 Shared, 1 Isolated (default) |
| Class count | 8 | N, nonzero |
| Classes | 144 × N | records below, in caller-specified order |
| Tree descriptor | 48 | first arity, largest node arity, tree log inverse rate, exclusive claim capacity, group capacity, small-tier flag |
| Small tier | 0 or 24 | if flag 1: arity, exclusive claim capacity, group capacity |
| Seal rate | 8 | exactly 2 |
| Seal root count | 8 | T = base aggregation tiers + (Isolated ? number of ZK classes : 0) |
| Seal roots | 32 × T | in tier order |
| Template program roots | 32 × N | in class order |
| Tier count | 8 | exactly T |
| Tier heights | 48 × T | EMUL, EXK, HASH, SPLIT, CAST, PUB log heights |
| Circuit count | 8 | exactly the circuit count reconstructed from the descriptor |
| Circuits | 56 × count | statement length, then six log heights in the same table order |

Each class record is: bytecode log, RAM log, advice log, image words, max members, eleven leaf table logs (ALU, LOAD, STORE, LD, SD, SHIFT, MUL, MULH, DIV, HASH, EXT), leaf log inverse rate, proof kind (0 plain, 1 ZK). There is no column count or column data after a circuit's heights.

In Isolated mode, circuit order is: plain First classes in class order; SMALL Nodes in increasing arity; the SMALL Wrap for LARGE children if present; LeafWrap circuits in ZK class order; the LARGE Node if present; dedicated ZK First circuits in class order. Each dedicated tier holds exactly its one First. All circuits in a tier share heights. Tier zero is SMALL; tier one is LARGE when configured; ZK tiers follow the base tiers.

Fixed-column stacking uses these indices: indices 0..=97 are Next columns in global slot order, 98..=101 are PUB constants. EMUL slots are 0..=3, EXK 4..=7, HASH 8..=23, SPLIT 24..=88, CAST 89..=96, PUB 97. Columns are stably sorted by decreasing height (ties by column index), placed consecutively at aligned offsets, and the circuit block is zero-padded to `2^kappa`, where `kappa = ceil(log2(sum column lengths))`. A tier concatenates its circuit blocks in local circuit order and zero-pads circuit count to a power of two. All data elements are polynomial-basis GF(2^64) words. The compact key authenticates the resulting PCS roots, not these rows themselves.

## Caller-pinned ZK placement

`ZkPlacement::{Isolated, Shared}` is exported by `leanvm::aggregate`. The explicit APIs are:

```rust
Tree::mixed_classes_with(classes: &[LeafClass], shape: TreeShape, placement: ZkPlacement)
Tree::mixed_classes_from_bytes_with(classes: &[LeafClass], shape: TreeShape,
    placement: ZkPlacement, bytes: &[u8], expected_digest: &Hash)
Tree::mixed_classes_from_trusted_bytes_with(classes: &[LeafClass], shape: TreeShape,
    placement: ZkPlacement, bytes: &[u8], digest: &Hash)
// Each returns Result<Tree<'static>, TreeError> for a class built/loaded without borrowed programs.
```

The methods without `_with` select Isolated placement, including the single-class convenience methods. Both explicit loaders reconstruct the expected descriptor from the **caller** placement, reject any differing word, count tiers using that placement and construct the design with it. Even a correctly hashed key for the other placement fails with `MixedClass`. The trusted loader retains the same genuine-bytes/digest-association obligation.

Let `B=1` if `small=None`, otherwise `B=2`, and let `Z` be the number of ZK classes. Isolated has `T=B+Z`; Shared has `T=B`. Shared circuit order is **all First classes, including ZK, in class order**; base-tier Nodes in increasing arity (2 through `arity` for one tier, or 2 through `small.arity` for two); if `small` exists, the SMALL Wrap for LARGE children and then the one LARGE Node. There are **no LeafWraps and no dedicated ZK tiers**. Every First occupies tier 0. The global circuit record order, local indices and kind encodings follow that list. One-tier shared classes have `N+(arity-1)` circuits, all in tier 0.

Shared First circuits share padded tier heights, including ZK verifier rows. `aggregate_programs_at` returns that First directly; it is both a valid final root and a legal Node child. Isolated aggregation returns a LeafWrap. With `small` configured Shared is also supported: all Firsts still share SMALL; the LARGE Node/SMALL Wrap path applies. Its cost is higher SMALL padding, which is the reason Isolated remains the default.

For any class list containing ZK, the `/zk-leaves/1` tree tag contains the placement byte **0 or 1**, followed by all class-kind bytes in order. Dimensions and statement length in the rest of the tag follow the chosen design. No-ZK class lists still omit that suffix (their circuit sessions can coincide), but their v4 descriptors and key digests distinguish caller placement. Seal session v3 binds the full class-key digest.

The circuits enforce tier usage: each First publishes zero carried usage; every Node verifies its children against the class-selected fixed columns and sets tier 0 usage, ORing inherited usage. Shared ZK Firsts need no special bypass. In a shared single-tier Node root, the carried fixed claim and all root-own column claims target the same authenticated polynomial, so seal v3 has **exactly one** stack opening. A raw First also has one opening for its own columns. Dropping that opening fails verification.

## Statement and root bytes

The root envelope is `"LVMT" || u16le(22)`. Its body is:

```
u8(log_inverse_rate)
u32le(statement_field_element_count)
24 bytes per statement field element, c0 || c1 || c2 (each u64le)
ProofTranscript bytes
```

Kind is `(((tier << tier_shift) | local_index) << 1) | is_node`; `tier_shift` is the maximum ceil(log2(circuit count in a tier)). First has low bit zero, Node/Wrap/LeafWrap one. The first statement element's high limbs must be zero.

Let `T` be tier count, `P=2+T`, `D` the maximum dense-polynomial variable count, `M=CircuitId::MAX_K_LOG=14`, and `C=N_CIRCUITS=21`. Statement sections, in field elements:

| Section | Width |
| --- | ---: |
| Kind | 1 |
| Claim-set digest (two 128-bit halves, high limbs zero) | 2 |
| Dense reduction point | D |
| Dense values: bytecode, image, then one fixed value per tier | P |
| **Tier usage, in tier order** | **T** |
| Matrix row point | M |
| Matrix column point | M |
| Two matrix values per circuit, in existing CircuitId order | 2 × C |

Thus `S=3+D+P+T+2M+2C`. An unused tier must publish both usage zero and fixed value zero. For mixed trees bytecode/image claims close in First circuits; the inherited statement slots are retained. For mixed trees, `D=max(first_class.log_bytecode+4, ceil(log2(max(first_class.image_words,1))), max_t(kappa_t+ceil(log2(circuit_count_t))))`. The reduction includes a one-tier placeholder Wide dimension of zero even though that extra slot is absent from the statement.

The tree session uses `leanvm-tree-19` and includes the statement length. Mixed tags retain `/mixed-members/2`, and ZK-containing tags retain `/zk-leaves/1`, placement and ordered proof-kind bytes. Reduction uses `SessionId::tagged(b"leanvm-tree-reduction-6", tree_session_bytes)`.

The exact tree tag concatenation (no framing except the lengths explicitly listed) is:

1. ASCII `leanvm-tree-19`, then the first template program digest (32 bytes).
2. For mixed trees: ASCII `/mixed-members/2`. If any class is ZK, append ASCII `/zk-leaves/1`, one placement byte (0 Shared, 1 Isolated), then one proof-kind byte per class in order (0 plain, 1 ZK). Append `u64le(first_max_members)`, `u64le(N-1)`. For each remaining class append its template digest (32 bytes), eleven `u64le` leaf heights, `u64le(max_members)`, then one leaf-rate byte. For same-program trees, this whole step is instead ASCII `/deferred-program/1`.
3. Eleven first-class leaf heights as u64le; `u64le(arity_0)`, `u64le(arity)`, `u64le(S)`; three u64le claim semantics words `(1, claims, groups)` (or `(0,0,0)` for output trees); the three small-tier u64le words `(arity,claims,groups)` iff present; every tier's six u64le heights, in tier order.
4. One first-leaf-rate byte and one tree-rate byte.

`SessionId::new(tag)` is the existing BLAKE2s duplex derivation: initialize with the 32-byte ASCII IV `irtf-cfrg-fiat-shamir/session-id`, absorb the tag, squeeze 32 bytes. It is **not** plain BLAKE2s hashing. `SessionId::tagged(a,b)` is `SessionId::new(a || b)`. The key carries each template's authenticated program root.

## Exact seal transcript

The seal is a `ProofTranscript`: `u64le(narg_byte_len) || narg || hints`. The hints stream retains the existing length-prefixed hint framing; it is not an independently trusted opening list.

For mixed trees, the session is `SessionId::tagged(b"leanvm/mixed-tree-seal/v3", class_key_digest)`. The instance is `LengthPrefixed` over u64 words:

1. All root statement elements as four limbs `[c0,c1,c2,0]`, in statement order.
2. Four little-endian u64 words of `BLAKE2s-256(root.to_bytes())`.

The prefix is the word count `4*S+4`, encoded by the existing LengthPrefixed codec. The proof hash includes the envelope, rate, statement and recursion proof bytes. Same-program trees derive the seal session from the tree descriptor and fixed roots, and use the same instance.

NARG begins with `u64le(102)`, followed by **102 field elements (24 bytes each)**, the root's fixed-column evaluations in column-index order 0..=101. This count must be exact. The root verifier uses each supplied value by column index, independently derives its bus point, and adds the public statement's contribution only for constant columns. It must perform all normal root checks before accepting the resulting deferred claims.

Then, for tiers in increasing order, form this ordered list of PCS point claims:

1. If the verified usage bit is 1: the carried dense claim, at offset 0, point `dense_point[..tier_vars]`, and that tier's dense value.
2. If this is the root's tier: its 102 fixed-column claims, in column-index order, at the offsets and points specified above.

**Open the tier once iff this list is nonempty**, using the existing `CommittedStack::open`/`StackCommitment::verify`, with these point claims and no ring claims. The list itself is not serialized; the verifier derives it. A tier used recursively and by the root gets one combined opening. A tier used by neither gets no opening. The verifier must check EOF for both NARG and hints. Dropped openings fail reading/authentication; added openings fail EOF. The tier-usage words cannot be taken from the seal or selected by its author.

All tiers use the seal stack shape: `log_n=max(log2(fixed_polynomial_len), MIN_MU)`, `Config::for_rate(log_n,2)`, lane width `2^(log_n-initial_k)`, and lane count `ceil(fixed_polynomial_len/lane_width)`. WHIR/stack framing uses the PCS codecs.

A raw First root carries no recursive fixed claims but still opens its own circuit columns. A wrong trusted-loader digest invalidates an existing seal for every root kind. Raw ZK First roots remain acceptable as final roots; Nodes still require SMALL children, reached through LeafWrap.

## Conformance

The checked-in suites use `verdicts.tsv` with seven tab-separated fields: `name`, `expected`, `key`, `digest`, `root`, `claims`, `seal`. File paths are relative to the manifest directory. Digest files contain 32 raw bytes; keys, roots, claims and seals use the encodings above. A verifier must match each expected `accept` or `reject` verdict.

- [`mixed-class-key-v4`](../conformance/mixed-class-key-v4/README.md) covers isolated placement, SMALL and LARGE roots, ZK roots, opening removal/addition, tier-bit tampering and a wrong digest.
- [`mixed-class-key-v4-shared-zk`](../conformance/mixed-class-key-v4-shared-zk/README.md) covers a shared single-tier root with plain, signature and ZK leaves, opposite-placement refusal, tier-bit tampering, opening removal and a wrong digest.

Generate fresh fixtures in a separate directory; proof randomness can change root and seal bytes. The class key is deterministic. Run the `fixtures` example with `export` or `verify` and a suite name:

```sh
cargo run --release -p leanvm --example fixtures -- export compact target/compact-fixture
cargo run --release -p leanvm --example fixtures -- verify compact conformance/mixed-class-key-v4
cargo run --release -p leanvm --example fixtures -- export shared target/shared-fixture
cargo run --release -p leanvm --example fixtures -- verify shared conformance/mixed-class-key-v4-shared-zk
```

[Big-endian verification](big-endian.md) describes cross-compilation and execution of the same artifacts. The fixture command performs no timing; performance benchmarks belong in the CLI or `benches/`.
