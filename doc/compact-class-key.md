# Compact class key v4 and selective seal v3

Implementation commit: `2877ada5` on `op-stack/claim-set-leaves`. This protocol replaces the formats at `3e269bd4`. It uses class-key `LVMXCK04`, tree envelope `LVMT` version 22, tree session `leanvm-tree-19`, reduction session `leanvm-tree-reduction-6`, and seal session `leanvm/mixed-tree-seal/v3`. Old keys, tree proofs and seals are not accepted. Standalone plain/ZK leaf formats, program keys, member conventions, class bounds and guest code are unchanged.

## What is authenticated

Trusted artifact generation builds the real circuits, stacks each tier's fixed columns and commits them at seal log inverse rate 2. The application pins the complete class-key digest. Parsing is not a proof of correct circuit generation; the trusted-byte loader requires external authentication of the exact artifact and its association with that digest.

The compact key contains dimensions and commitment roots, **no fixed-column rows**. A loaded `Tree` holds no dense polynomial tables and only empty, distinct column markers. Distinct markers matter: the bus caches public evaluations by column identity. `verify_claims_sealed` verifies using seal-provided evaluations authenticated by PCS. Direct `verify_claims` on a loaded verifier returns `TreeError::SealRequired`. Prover-built trees still support direct verification and all existing proving operations. Neither loader enables proving.

### Carried tier usage

A statement carries one field-valued Boolean per tier (not a packed machine word). This is a bitmap expressed as individual field elements, so there is no 64-tier encoding limit.

- A First circuit exposes all usage bits as zero: it verifies leaves, not recursion circuits.
- A Node verifying SMALL children sets SMALL usage to one. The SMALL Wrap that verifies a LARGE child sets LARGE usage to one. A LeafWrap sets its dedicated First tier's usage to one.
- Each then ORs in every verified child's usage bits. In characteristic two, `OR(a,b) = a+b+ab`. Child bits are constrained by `b*(1+b)=0`; a First child's bits are additionally constrained to zero using its authenticated first/node bit.
- A carried fixed claim's reduction scale is that child's usage bit. Fresh child-column claims always have unit scale and set the appropriate tier's bit.
- The circuit exposes each fixed evaluation multiplied by its resulting usage bit, so an unused tier's published evaluation is canonically zero.

These operations are circuit constraints, not decisions made by the honest sealer. The child statement is in the verified child proof's instance; its transcript digest binds the reduction instance. Thus a zero root usage bit means there was no nonzero-weight fixed claim for that tier anywhere in the recursive reduction. A malicious witness cannot remove a used tier by choosing an opening list. The reduction may internally evaluate a zero-weight polynomial, but that evaluation contributes nothing to the identity and is not a root claim.

Usage is conservative over children actually verified. An absent union slot still verifies a repeated child, as before, so usage need not describe only the final declared subset. Narrowing a declared set cannot remove cryptographic obligations. All bits are the OR of the verification history, not an application claim about which public members remain.

### The root's own columns

The root verifier still checks the recursion commitment, hash reduction, bus, constraints and PCS opening, plus the hash circuit's matrix identity. Its public-column arithmetic obtains each fixed-column value from the seal rather than from a row array. For a PUB constant column it adds the statement contribution itself:

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

This is the same stacked polynomial that authenticates children inside recursion. No separate per-circuit commitment is needed. Circuit/column selectors are fixed Boolean block offsets, not supplied by the sealer.

The **entire serialized root proof** is hashed into the seal instance, in addition to its statement. The root's bus points depend on that proof, so binding only the statement would not fix these new PCS claims before the seal's challenges. All supplied root evaluations are absorbed before any PCS challenge. Consequently the sealer cannot adapt either points or values after seeing those challenges. A false root either fails native algebra/PCS checks, or demands a false opening against an authenticated fixed commitment. The same reasoning applies to a root fabricated for a different circuit with matching heights.

This is a protocol argument under the underlying transcript/hash/PCS assumptions, not an independent security audit or a quantitative composed soundness proof.

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

In Isolated mode, circuit order remains: plain First classes in class order; SMALL Nodes in increasing arity; the SMALL Wrap for LARGE children if present; LeafWrap circuits in ZK class order; the LARGE Node if present; dedicated ZK First circuits in class order. Each dedicated tier holds exactly its one First. All circuits in a tier share heights. Tier zero is SMALL; tier one is LARGE when configured; ZK tiers follow the base tiers.

Fixed-column stacking is unchanged: indices 0–97 are Next columns in global slot order, 98–101 are PUB constants. EMUL slots are 0–3, EXK 4–7, HASH 8–23, SPLIT 24–88, CAST 89–96, PUB 97. Columns are stably sorted by decreasing height (ties by column index), placed consecutively at aligned offsets, and the circuit block is zero-padded to `2^kappa`, where `kappa = ceil(log2(sum column lengths))`. A tier concatenates its circuit blocks in local circuit order and zero-pads circuit count to a power of two. All data elements are polynomial-basis GF(2^64) words. The compact key authenticates the resulting PCS roots, not these rows themselves.

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

The methods without `_with` retain Isolated behavior, including the single-class convenience methods. No existing key, digest, session or fixture changes. The placement word at key byte offset 8 was already in v4; Shared makes its existing value 0 publicly usable, without a format/domain bump. Both explicit loaders reconstruct the expected descriptor from the **caller** placement, reject any differing word, count tiers using that placement and construct the design with it. Even a correctly hashed key for the other placement fails with `MixedClass`. The trusted loader retains the same genuine-bytes/digest-association obligation.

Let `B=1` if `small=None`, otherwise `B=2`, and let `Z` be the number of ZK classes. Isolated has `T=B+Z`; Shared has `T=B`. Shared circuit order is **all First classes, including ZK, in class order**; base-tier Nodes in increasing arity (2 through `arity` for one tier, or 2 through `small.arity` for two); if `small` exists, the SMALL Wrap for LARGE children and then the one LARGE Node. There are **no LeafWraps and no dedicated ZK tiers**. Every First occupies tier 0. The global circuit record order, local indices and kind encodings follow that list. One-tier shared classes have `N+(arity-1)` circuits, all in tier 0.

Shared First circuits share padded tier heights, including ZK verifier rows. `aggregate_programs_at` returns that First directly; it is both a valid final root and a legal Node child. For Isolated, the existing LeafWrap behavior is unchanged. With `small` configured Shared is also supported: all Firsts still share SMALL; the existing LARGE Node/SMALL Wrap path remains. Its cost is higher SMALL padding, which is the reason Isolated remains the default.

For any class list containing ZK, the existing `/zk-leaves/1` tree tag contains the placement byte **0 or 1**, followed by all class-kind bytes in order. Dimensions and statement length in the rest of the tag follow the chosen design. No-ZK class lists still omit that suffix (their circuit sessions can coincide), but their v4 descriptors and key digests distinguish caller placement. Seal session v3 binds the full class-key digest as before.

The circuit soundness mechanism is unchanged: each First publishes zero carried usage; every Node verifies its children against the class-selected fixed columns and sets tier 0 usage, ORing inherited usage. Shared ZK Firsts need no special bypass. In a shared single-tier Node root, the carried fixed claim and all root-own column claims target the same authenticated polynomial, so seal v3 has **exactly one** stack opening. A raw First also has one opening for its own columns. Dropping that opening cannot succeed; no empty-seal exception is introduced.

See [the shared placement report and fixtures](shared-zk-placement.md) for the exact new monorepo class, measurements, compatibility checks and big-endian results.

## Statement and root bytes

The root envelope is `"LVMT" || u16le(22)`. Its body is unchanged structurally:

```
u8(log_inverse_rate)
u32le(statement_field_element_count)
24 bytes per statement field element, c0 || c1 || c2 (each u64le)
ProofTranscript bytes
```

Kind is still `(((tier << tier_shift) | local_index) << 1) | is_node`; `tier_shift` is the maximum ceil(log2(circuit count in a tier)). First has low bit zero, Node/Wrap/LeafWrap one. The first statement element's high limbs must be zero.

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

Thus `S=3+D+P+T+2M+2C`. An unused tier must publish both usage zero and fixed value zero. For mixed trees bytecode/image claims still close in First circuits; the inherited statement slots are retained. For mixed trees, `D=max(first_class.log_bytecode+4, ceil(log2(max(first_class.image_words,1))), max_t(kappa_t+ceil(log2(circuit_count_t))))`. The reduction retains the original one-tier placeholder Wide dimension of zero even though that extra slot is absent from the statement.

Tree session construction is unchanged except `leanvm-tree-18` becomes `leanvm-tree-19` and the new statement length is included. Mixed tags retain `/mixed-members/2`, and ZK-containing tags retain `/zk-leaves/1`, placement and ordered proof-kind bytes. Reduction uses `SessionId::tagged(b"leanvm-tree-reduction-6", tree_session_bytes)`.

The exact tree tag concatenation (no framing except the lengths explicitly listed) is:

1. ASCII `leanvm-tree-19`, then the first template program digest (32 bytes).
2. For mixed trees: ASCII `/mixed-members/2`. If any class is ZK, append ASCII `/zk-leaves/1`, one placement byte (0 Shared, 1 Isolated), then one proof-kind byte per class in order (0 plain, 1 ZK). Append `u64le(first_max_members)`, `u64le(N-1)`. For each remaining class append its template digest (32 bytes), eleven `u64le` leaf heights, `u64le(max_members)`, then one leaf-rate byte. For same-program trees, this whole step is instead ASCII `/deferred-program/1`.
3. Eleven first-class leaf heights as u64le; `u64le(arity_0)`, `u64le(arity)`, `u64le(S)`; three u64le claim semantics words `(1, claims, groups)` (or `(0,0,0)` for output trees); the three small-tier u64le words `(arity,claims,groups)` iff present; every tier's six u64le heights, in tier order.
4. One first-leaf-rate byte and one tree-rate byte.

`SessionId::new(tag)` is the existing BLAKE2s duplex derivation: initialize with the 32-byte ASCII IV `irtf-cfrg-fiat-shamir/session-id`, absorb the tag, squeeze 32 bytes. It is **not** plain BLAKE2s hashing. `SessionId::tagged(a,b)` is `SessionId::new(a || b)`. Template program digest generation is unchanged; the key carries each template's authenticated program roots as before.

## Exact seal transcript

The seal is still a `ProofTranscript`: `u64le(narg_byte_len) || narg || hints`. The hints stream retains the existing length-prefixed hint framing; it is not an independently trusted opening list.

For mixed trees, the session is `SessionId::tagged(b"leanvm/mixed-tree-seal/v3", class_key_digest)`. The instance is `LengthPrefixed` over u64 words:

1. All root statement elements as four limbs `[c0,c1,c2,0]`, in statement order.
2. Four little-endian u64 words of `BLAKE2s-256(root.to_bytes())`.

The prefix is the word count `4*S+4`, encoded by the existing LengthPrefixed codec. The proof hash includes the envelope, rate, statement and recursion proof bytes. Same-program trees retain their existing session construction from the tree descriptor and fixed roots under the bumped seal domain, and use the same new instance.

NARG begins with `u64le(102)`, followed by **102 field elements (24 bytes each)**, the root's fixed-column evaluations in column-index order 0–101. This count must be exact. The root verifier uses each supplied value by column index, independently derives its bus point, and adds the public statement's contribution only for constant columns. It must perform all normal root checks before accepting the resulting deferred claims.

Then, for tiers in increasing order, form this ordered list of PCS point claims:

1. If the verified usage bit is 1: the carried dense claim, at offset 0, point `dense_point[..tier_vars]`, and that tier's dense value.
2. If this is the root's tier: its 102 fixed-column claims, in column-index order, at the offsets and points specified above.

**Open the tier once iff this list is nonempty**, using the existing `CommittedStack::open`/`StackCommitment::verify`, with these point claims and no ring claims. The list itself is not serialized; the verifier derives it. A tier used recursively and by the root gets one combined opening. A tier used by neither gets no opening. The verifier must check EOF for both NARG and hints. Dropped openings fail reading/authentication; added openings fail EOF. The tier-usage words cannot be taken from the seal or selected by its author.

All tiers use the existing seal stack shape: `log_n=max(log2(fixed_polynomial_len), MIN_MU)`, `Config::for_rate(log_n,2)`, lane width `2^(log_n-initial_k)`, and lane count `ceil(fixed_polynomial_len/lane_width)`. Existing WHIR/stack framing and field/hash encoding are unchanged.

**There is no empty-first-level-seal exception anymore.** A raw First root carries no recursive fixed claims but still opens its own circuit columns. A wrong trusted-loader digest invalidates an existing seal for every root kind. Raw ZK First roots remain acceptable as final roots; Nodes still require SMALL children, reached through LeafWrap.

## Go-port checklist and fixtures

Update magic/version/domain checks, add the usage section, reconstruct compact circuit stubs without column arrays, and defer root public-column values to the seal's canonical prefix. Authenticate those values through the derived opening lists, bind the full root proof hash, and reject trailing data. A verifier that merely skips native column evaluation is unsound. Direct verification without a seal is no longer available from a compact key.

The fixtures use the exact three requested classes, ZK leaf rate 2, eight threads and tree capacity `(16385,1024)`, SMALL `(257,64)`, arities 1/2 and tree rate 1. The example `compact_class_key` generates and verifies them. Assembly guests publish fixed lists: two disjoint 128-member leaves fit SMALL exactly (256 members), adding a third forces LARGE, and a 16-member ZK leaf exercises LeafWrap. These are differential verification fixtures, not a privacy benchmark of an application guest. Real signature-member and private-advice ZK proofs remain covered in the unit suite.

`verdicts.tsv` lists `name, expected, key, digest, root, claims, seal`, tab-separated, with paths relative to its directory. Digest files contain raw 32 bytes. Tampered cases share the valid key/claims/root where appropriate. `opening-dropped` removes the sole SMALL PCS opening, retaining the 102-value prefix; `opening-added` repeats that opening; `tier-bit-flipped` flips the unused ZK bit of the valid plain SMALL root; `wrong-digest` flips one digest byte and exercises the trusted loader so rejection must happen during sealed verification.

## Measurements

Measured locally with Rust 1.95 release builds and exactly eight pool threads, one warmup and three measured passes per operation, no cooldown. Baseline is `3e269bd4`; the new revision is this protocol. Times are sample means, not Cannon steps. Runs are sequential per build and capacity; desktop load/thermal variation remains, so small timing differences are not significance claims. The sealing timer includes native verification of the root and its column evaluations, but excludes the one-time class commitment. Verification excludes loading the key. Proof sizes can vary with proof randomness.

The load peak is the counting allocator's additional peak live heap during checked loading (64 KiB per-thread accounting granularity), **not RSS**. It excludes the already-resident input key and caller's other allocations. A compact loader still constructs small template program metadata; it allocates no per-row circuit columns or dense fixed tables.

| Capacity | Revision | Key bytes | Checked load ms | Trusted load ms | Load peak bytes |
| --- | --- | ---: | ---: | ---: | ---: |
| 16385 | before | 116251536 | 303.972 | 86.957 | 388587717 |
| 16385 | after | 1288 | 0.910 | 0.892 | 3330517 |
| 65536 | before | 235821968 | 631.228 | 188.087 | 910811333 |
| 65536 | after | 1288 | 0.663 | 0.660 | 3330517 |

| Capacity | Root | Root bytes before → after | Seal bytes before → after | Seal ms before → after | Verify ms before → after |
| --- | --- | ---: | ---: | ---: | ---: |
| 16385 | plain-small | 257243 → 257059 | 523588 → 193996 | 159.13 → 144.57 | 4.102 → 4.044 |
| 16385 | plain-large | 300111 → 300311 | 522820 → 367556 | 235.80 → 214.53 | 6.301 → 4.647 |
| 16385 | mixed-zk | 257051 → 256771 | 524100 → 351908 | 232.88 → 209.07 | 5.182 → 4.644 |
| 16385 | one-zk | 256763 → 256291 | 524196 → 353572 | 231.23 → 163.18 | 5.351 → 4.530 |
| 65536 | plain-small | 257267 → 257659 | 548712 → 194572 | 443.36 → 151.35 | 5.407 → 4.281 |
| 65536 | plain-large | 297167 → 296631 | 549832 → 393384 | 479.89 → 425.27 | 9.698 → 4.980 |
| 65536 | mixed-zk | 256419 → 257307 | 548584 → 352676 | 513.80 → 166.34 | 5.730 → 4.704 |
| 65536 | one-zk | 256051 → 257051 | 548328 → 351780 | 517.42 → 154.08 | 5.389 → 4.643 |

The three-class baseline at capacity 65536 is 235,821,968 bytes; the earlier ~212 MB estimate did not describe this exact three-class artifact. SMALL plain roots open only SMALL; LARGE plain roots open SMALL and LARGE; both ZK cases open SMALL and the dedicated ZK tier. The compact key stays 1,288 bytes when capacity changes; its heights, commitments and digest still change.

| Capacity | Revision | Class-key digest (hex) |
| --- | --- | --- |
| 16385 | before | `ce8d9001f1e1045fa84bb62c4378e0cface1cc09a92c2c91ece6f440606d0e8a` |
| 16385 | after | `5345ead055078db8baf0dc0db0c605ccd9f32a26c8c7626b3f28d007a3d9d7ee` |
| 65536 | before | `b56ab464bdec5929422a46694c98708d94ab49aedea075f97bd0471a6f673426` |
| 65536 | after | `2f5568929c2083e0a6b253c0401a8457190388f0affa72e39895d90b33019214` |

Reproduce with `cargo run --release -p leanvm --example compact_class_key -- DIRECTORY 16385` (or `65536`). The same example was copied to the baseline worktree for measurement, using its original checked loader/seal implementation. Use `DIRECTORY 16385 verify` for verification only. Checked-in fixtures are in [`conformance/mixed-class-key-v4`](../conformance/mixed-class-key-v4); all four valid cases accept and all four mutations reject. The monorepo, Go verifier and Cannon were not changed or benchmarked here.

### Two-class control without ZK

Omitting only the private-program class at capacity `(16385,1024)` gives this size control. It uses the same plain proofs and capacity boundaries; control timings are not compared because other checks were running.

| Artifact | Before, no ZK class | After, no ZK class | After, with ZK class |
| --- | ---: | ---: | ---: |
| Class key bytes | 92,550,040 | 920 | 1,288 |
| SMALL plain root bytes | 256,811 | 257,019 | 257,059 |
| SMALL plain seal bytes | 346,808 | 175,192 | 193,996 |
| LARGE plain root bytes | 301,279 | 301,007 | 300,311 |
| LARGE plain seal bytes | 347,192 | 348,528 | 367,556 |

A ZK-capable key still changes the SMALL circuit stack (it includes LeafWrap), so plain seals need not be byte-identical to those from a key with no ZK class. They no longer open the dedicated ZK tier. The SMALL seal is smaller than the old no-ZK baseline because it also omits unused LARGE. The LARGE no-ZK case is roughly unchanged in size: it needs both base tiers and now also authenticates the root columns. Reproduce the control with `compact_class_key DIRECTORY 16385 plain`.

## Validation and limitations

- `rustup run 1.95 cargo test --workspace --release`: 550 passed, zero failed, five ignored. Ignored: two ACT4 tests requiring generated external ELF files, the opt-in large ZK layout benchmark, and two guest-only SDK doctests.
- After the lint-only rewrite, `rustup run 1.95 cargo test --release -p leanvm --lib --test verifiers`: 302 passed, zero failed, three ignored.
- `cargo clippy --workspace --all-targets --release -- -D warnings`: passed with native Rust 1.99.1.
- `cargo fmt --all -- --check`: passed.
- Rust 1.95 **release code generation**, not only `cargo check`, passed for `s390x-unknown-linux-gnu` and `powerpc64-unknown-linux-gnu`.
- s390x QEMU: all 17 SDK and two signature-member host tests passed; native-generated plain and ZK leaf/sealed-node fixtures verified; all eight frozen compact fixtures matched their verdicts. `scripts/check-big-endian.sh` now runs that compact suite too.
- All 14 checked-in guest ELF `.text` sections match `3e269bd4` byte for byte. No guest/runtime sources changed, so regeneration was unnecessary.

Relevant regression tests include `compact_class_key_differential_fixtures`, `mixed_zk_classes_wrap_fold_seal_and_refuse_foreign_leaves` (usage propagation, direct/compact parity, root-value tampering, opening removal/addition, all tier bits and wrong digests), `trusted_loader_wrong_digest_rejects_first_and_node_seals`, `class_keys_authenticate_shape_columns_and_seal_roots` (including malformed/truncated compact encodings), and `leaf_shape_is_bound_by_its_kind_and_fixed_polynomial` (forged same-height circuits). The first-level wrong-digest case now rejects, intentionally changing seal v2 behavior.

The trust boundary remains artifact provisioning: the circuit commitments and descriptor must be genuine and pinned. A digest supplied alongside attacker-chosen bytes authenticates nothing. Native measurements and s390x execution are not a Cannon/MIPS64 benchmark or a Go differential execution result. These fixtures enable those downstream checks; the Go implementation must adopt the specified protocol before accepting them.
