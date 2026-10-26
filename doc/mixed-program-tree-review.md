# Mixed member-list trees: review packet

## Compact-key revision (current)

[The v4/v3 protocol and soundness argument](compact-class-key.md) supersedes this packet's historical format and empty-seal descriptions below. Tier usage is constrained in the recursion circuits: Boolean child bits, OR propagation, unit usage for fresh child-column claims, and zero published fixed values for unused tiers. Seals open exactly the used tiers plus the root's own tier. They authenticate 102 root-column evaluations, with the complete root proof hashed into the instance before opening challenges. Loaded keys carry no rows and refuse direct verification.

The trusted loader assumes externally authenticated genuine key bytes and the correct associated digest. It does not check that association in release builds. A wrong digest now invalidates existing seals even for First roots, because their own columns require an opening. This removes the previous empty-first-level exception. Correct dimensions alone do not establish that the commitments describe the intended circuits; provisioning still needs the pinned, trusted artifact. See the frozen eight-case differential fixtures and measurement/check report in the protocol document. This is not an independent cryptographic audit.

## Historical member-list and ZK revisions

Scope: the member-list SDK and guest, multi-class first-level circuits, class-key v2, running-root API, and migration from `da5c9648`. This is an implementation review packet, not a formal soundness proof.

## Threat model and authorization

The attacker chooses leaf keys, images, entries, advice, proofs, member lists, labels, declared sets, recursion witnesses, fake same-height circuits, class-key bytes and seals. A valid PCS opening under an attacker-chosen polynomial does not authenticate that polynomial. The application separately authorizes the genuine class-key artifact and each normalized program identity. Neither parsing nor a self-reported digest supplies that authorization.

The trusted-byte loader adds an explicit caller obligation: authenticate the exact bytes and their association with the supplied digest outside the loader. Soundness rests on genuine bytes. A wrong digest changes the seal session and breaks existing node/wrap seals, but an empty first-level seal does not detect it, for any leaf class. First-level roots have no fixed claims; program claims close in-circuit and the recursion proof checks the authenticated circuit key. Keep the checked loader as default.

## Bindings to trace

| Binding | Enforcement |
| --- | --- |
| Label ↔ witnessed key digest | `riscv.rs::verify_mixed` hashes the constrained root/entry/image under class-fixed dimensions; `mixed.rs::member_rows` puts those digest wires into the group header. |
| Member list ↔ leaf output | One domain-separated list convention, bounded monotone presence bits, zero absent words, shared member wires for list and group; list digest is hashed into the verified execution output. There is no witness mode selector. |
| Leaf proof ↔ leaf shape ↔ kind | Each `ProofShape` checks its announcement; `Level::First(class)` selects that shape; the kind selects its authenticated fixed-polynomial block. Complete kind codes are constrained to legal values. |
| Member ↔ public key/message | Signature guest verifies every triple, then hashes `sphmem01 || root || public_param || message`, all fixed-width little-endian words, into the member. |
| Child claims ↔ published union | Existing union rows bind digests, label/member tuples and selections before random challenges; canonical root sets deduplicate. `fold` offers no narrowing override. |
| First/node classification ↔ carried fixed claims | Kind low bit says first versus node/wrap; native position lookup checks it and rows constrain the entire kind. Every first-level class suppresses absent fixed claims, not just position zero. |
| Circuit columns ↔ trusted class | Built roots are derived/cache-pinned; loaded columns and roots are authenticated by the class-key v2 digest. Seal openings close Fixed/Wide against these roots. |

A VK does not contain execution-table heights or K. Classes can share a VK when their normalization bounds coincide. Therefore a proof's VK cannot substitute for the class/kind checks. Normalization enlarges memory/advice bounds and moves halt; authorize the ELF together with the intended class. The kind-code change also changes same-program tree sessions and envelopes.

## Concentrated signature trust

Every signature user trusts the authorized leanSPHINCS member guest. Review its raw triple layout, public-key field order, signature verification and failure path, exact member hash, list append for every successful signature, and the sole final commitment. The host's `member` helper is convenience, not the authority: the guest must execute the same relation. Consumers must recompute members from their intended keys/messages and authorize the normalized guest VK. A signature hash alone does not establish application freshness, message semantics, or replay protection.

## Regression coverage

- `signature_members_match_bytes_and_guest_execution`: independent standard BLAKE2s byte encoding; two signatures; altered public key, message and signature trap. The prior signer-set guest remains unchanged.
- `member_classes_fold_deduplicate_close_and_load`: K-member list with repetitions, one-member list, two leaf classes including actual leanSPHINCS proofs, repeated leaves of one program merging into one group, multiple folds including the large-tier wrap path, capacity rollback, empty/single-child close, checked/trusted v2 reload, reordered/missing/modified classes refused; wrong-digest empty seals remain valid for both first-level kinds, while the node seal fails; direct and sealed verification.
- `member_list_forgeries_fail_union_rows_and_both_root_paths`: native prechecks deliberately bypassed; unlisted members, different label, wrong list-output digest, list/set domain confusion, and over-K lists execute the union and reduction rows and fail. Claimed forged sets also fail direct and sealed root verification. Empty lists are disallowed by circuit prefix constraints.
- `leaf_shape_is_bound_by_its_kind_and_fixed_polynomial`: same VK with a different valid proof announcement fails in rows; fake same-height first-level circuit under another class's kind passes its own proof and the upper node's local rows, but authenticated root settlement rejects it on both direct and sealed paths.
- Existing singleton-era mixed tamper tests now use member-list guests. Parser tests use v2 offsets and exercise both loaders on truncated, malformed, substituted and trailing data. Wrong-digest node/wrap rejection and the empty-seal exception remain covered.
- `member_list_rows_match_sdk_for_odd_even_and_empty_boundaries`: SDK/row agreement for every nonempty length up to five across bounds 1–5; empty lists fail the circuit constraints.
- Same-program session pins were updated for the explicit `leanvm-tree-18` protocol change, retaining exact layout checks and exact child-index error checks.

## Design decisions and limits

All classes use one output convention. The alternative of a label-authenticated mode is unnecessary here; a prover-controlled mode would be unsound. Plain first levels share small-tier heights. Each ZK class has a dedicated first level and a small-tier LeafWrap; unwrapped ZK first levels are refused as small-tier children. The reduction and seal authenticate one fixed polynomial per tier. Adding ZK leaves retains the old plain padded heights at the measured shape, with small additional kind/statement rows. All classes currently share first-level arity.

Member order and duplicates are bound by the execution output, while declared root sets are canonical unions/subsets. The general aggregation API still supports intentional narrowing; only the running-root `fold` API promises full retention. The claim capacity is exclusive. An accumulator's failed fold retains its previous root; closing empty state returns no proof.

Class-key v1, tree-envelope v20 and previous circuit keys are not compatible with this revision. Consumers must port the list relation, v2 descriptors, all first-level kinds, the kind low bit, and the new tree session/envelope before accepting roots. Standalone proof/key formats remain unchanged. No Go, Cannon or OP Stack changes were made. Big-endian validation includes release codegen and QEMU verification of native-generated plain and ZK fixtures; proof production on big-endian machines remains unsupported. Small adversarial tests do not establish a composed quantitative soundness bound.

## Upstream interactions

Checked read-only via GitHub on 2026-10-25; all remain open:

- [Issue #417](https://github.com/leanEthereum/leanVM/issues/417): committed-program/mixed aggregation design discussion. This branch chooses committed keys and in-circuit closure for mixed programs; its claim-list convention and multi-class encoding are fork-specific.
- [PR #418](https://github.com/leanEthereum/leanVM/pull/418), head `ad897fd6bb0f1e2f788898796f6115d8c5ee0d8b`: the original committed-key change is already ported into this fork's later verifier. A future merge must reconcile key/session/PCS framing, not reapply the old implementation mechanically.
- [PR #522](https://github.com/leanEthereum/leanVM/pull/522), head `461ab229da3a2f1232dce68e74756ee26ca142d6`: conditional guest proof verification requires resolving authenticated assumptions before publishing unconditional members. This branch has no assumption-resolution extension.
- [PR #553](https://github.com/leanEthereum/leanVM/pull/553), head `0c5a8f3dc422b0e8ef4947fb62a579603fb8ae24`: replaces the recursion machine and changes ISA/proof semantics. The member-list, class-kind, key and seal bindings require a semantic port into its generated verifier, with new artifacts and pins.

No upstream comments or PRs were made. Native root fixed-column openings remain the separate unimplemented design in the main document.

## ZK extension from d2f36540

See [design, privacy and measurements](mixed-program-tree-zk.md). Review the witnessed entry passed as a public recorder value, ZK session derived from the witnessed VK digest, outer key commitment verification, and the program opening against the witnessed root/image. Members remain public and bound to the verified output. Kind separation uses the leaf envelope, announcement/kind, session and authenticated circuit descriptor; a VK alone does not distinguish plain from ZK.

The ZK-only class-key v3 descriptor includes all class kinds and placement; no-ZK class keys stay byte-identical v2. LeafWrap states the same set and introduces the dedicated tier's fixed claim. Subsequent nodes carry it through reduction; seals authenticate every tier root. Seal v2 and its empty-first-level exception remain unchanged. The trusted loader still requires genuine externally authenticated bytes, including every added tier; a digest is not a substitute for this authentication.

`mixed_zk_classes_wrap_fold_seal_and_refuse_foreign_leaves` combines plain, actual leanSPHINCS-member and ZK leaves; checks direct/sealed roots and checked/trusted reload; bypasses native prechecks to reject wrong keys, members and both kind substitutions in rows; refuses an unwrapped ZK first level. It also tests a ZK class zero without a large aggregation tier. `os_draws_a_fresh_seed_for_each_proof` checks fresh OS draws. Fixed seeds require the development-only `zk/test-util` feature outside zk's own tests. These are regression checks, not a formal privacy proof or security audit.
