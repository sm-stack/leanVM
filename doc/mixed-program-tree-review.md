# Mixed-program tree review packet

This packet covers the OP Stack fork's mixed-program construction and the class-key/seal hardening on `op-stack/mixed-program-tree`. It is a review aid, not a formal soundness proof or independent audit. The format and measurements are in [mixed-program-tree.md](mixed-program-tree.md).

## Threat model and trust boundary

The attacker chooses leaf programs, bytecode commitments, initial images, entries, advice, proofs, declared claim sets, recursion witnesses, root proofs, class-key bytes and seals. It can combine or discard claims and construct fake circuits with the same heights as genuine circuits. It may supply a forged fixed polynomial and a perfectly valid PCS opening against that polynomial's own root. It cannot choose the application's expected class-key digest or authorized program identities. The verifier must reject malformed proofs or any output not justified by an authorized normalized program execution, subject to upstream proof-system soundness.

There are two separate authorization decisions. A trusted class setup generates the genuine circuits, verifier columns and seal roots, and distributes the class-key digest. The application regenerates each program key from its intended ELF and the same class and authorizes that key digest. Parsing a class key or a program key does not establish either authorization. In particular, a perfectly well-formed attacker-generated circuit key is not trusted merely because its digest can be computed. Normalization expands RAM and advice bounds and can make formerly trapping accesses valid; identity is `(ELF, class)`.

## Binding inventory

| Binding | Enforcement and review target |
| --- | --- |
| Program commitment and metadata to key digest | `cpu/key.rs`: versioned canonical little-endian encoding includes root, dimensions, entry and padded image. |
| Key digest to leaf session | `rec/verifier/riscv.rs`: rows compute the digest and dynamic session from witnessed key words; class dimensions are constants. Entry alignment, range and halt exclusion are constrained. |
| Key root to executed bytecode | `cpu/program.rs` and `rec/verifier/riscv.rs`: PCS opening closes the bytecode claim against that root; image evaluation uses the same constrained image as the digest. |
| Verified leaf to singleton | `rec/tree/mixed.rs`: label is the four digest words followed by two zeros; member is the verified output. The singleton digest is built in rows. |
| Children to declared set | `rec/tree/union/`: coverage rows enforce that each declared claim belongs to a verified child's set. Discard is permitted; invention or key/output reassociation is not. |
| Root statement to public claims | `rec/tree/mod.rs`, `statement.rs`, `multiset.rs`: root circuit/mode validation and canonical set digest equality precede settlement. |
| Genuine recursive circuit to deferred claims | `rec/fixed.rs`, `tree/design.rs`, `tree/reduce/`: fixed columns name wiring and constants; tier and circuit selectors route claims into Fixed or Wide. |
| Complete class artifact to trusted identity | `tree/embed.rs`: BLAKE2s over domain and every encoding byte; expected class/shape and exact lengths checked; loaded roots cannot be replaced. |
| Seal to class key and root | `tree/seal.rs`: v2 mixed session contains the class-key digest; complete root statement is the instance before challenges. Opening claims and commitment configurations are rebuilt by the verifier. |
| Root to genuine Fixed/Wide polynomials | `tree/seal.rs`: WHIR openings under authenticated roots replace only direct deferred fixed evaluations. Matrix and other claims still settle natively; root recursion proof still checks its own columns. |

A fake large circuit under a genuine small wrap is the key adversarial case. A forged Wide polynomial lets all local rows hold and the wrap's core proof verify. The final direct settlement refuses it. An opening of the forged Wide polynomial also fails under genuine class roots. This is why checking only the wrap's core proof is insufficient.

The optional `Tree::mixed_from_trusted_bytes` introduces an explicit caller obligation: the outer mechanism must authenticate both the exact class-key bytes and their association with the supplied BLAKE2s class-key digest, including when transport uses a pinned keccak256 oracle key. It shares structural validation but does not authenticate verifier data; keep `mixed_from_bytes` for untrusted inputs. A wrong supplied digest invalidates existing node and wrap seals carrying fixed claims, but direct verification and a first-level root's empty v2 seal do not detect it. The first-level exception is harmless: there are no fixed claims to settle, program claims close in-circuit, and the root recursion proof is verified against the circuit keys from the outer-authenticated bytes. Soundness rests entirely on genuine bytes; the supplied digest is assumed correct, is not checked against those bytes in release builds, and only binds the seal session. Its mismatch is a misconfiguration check, not a soundness requirement. Seal v2 is preserved.

## Inherited assumptions

The argument assumes the upstream RISC-V arithmetization enforces execution, bus consistency, initial state and exits; the flock reductions and circuit matrices are sound; ring switching, stacked WHIR and the PCS are binding/opening-sound with their configured parameters; BLAKE2s and Fiat-Shamir framing give the required collision resistance and challenge unpredictability; and the recursive claim reduction remains sound through arbitrary depth and both tiers. Review the reduction's degree bounds and challenge ordering rather than treating passing tests as a proof. The seal adds another PCS use and therefore its error probability must be included in a composed soundness bound.

The trusted artifact setup must generate roots for the exact fixed polynomials described by the verifier columns and class. Loading does not recompute those commitments or reconstruct the circuits. Digest authentication replaces that work. Consumers must keep the trusted pin distinct from untrusted artifact transport. The seal is public computation, not an attestation by a trusted prover.

## Review scope and commits

The initial implementation is based on upstream `06e5c9cd6981103786f9d0a17324241b559a50d3`. Review `045d3dd0` and `8559b374` for the committed-program port; `e6e97311` and `10ee3515` for endian and portable field arithmetic; `362b2a0e` for mixed first-level verification and union binding. `e6780cb8` is the previously pushed baseline and report.

The supplied spikes are preserved as `8eb5f992` (verifier embedding) and `926f050a` (Fixed/Wide seal). `6d8600f4` guards verifier-only proving paths, including plain and zero-knowledge Program helpers. `a50e234c` authenticates class keys and seal sessions; `a6e3c109` adds row-level and two-tier adversarial coverage. The main report gives the full hardening commit table; review the complete `e6780cb8..HEAD` diff as well as each topic.

Start at `crates/leanvm_core/src/rec/tree/embed.rs` and `seal.rs`, then follow the verifier into `rec/proof.rs`, `bus/coord.rs`, `rec/fixed.rs`, `rec/verifier/recursion.rs` and `rec/tree/reduce/`. Program identity and first-level checks are in `cpu/key.rs`, `cpu/program.rs`, `rec/verifier/riscv.rs` and `rec/tree/mixed.rs`. `cpu/prover.rs`, `cpu/program.rs` and `cpu/zero_knowledge.rs` contain proving guards. Serialization dependencies include `crates/fiat_shamir/src/` codecs/session framing and `crates/pcs/src/stack.rs`. Other abbreviated core paths above are relative to `crates/leanvm_core/src/`.

## Adversarial evidence

New regression tests in `rec::tree::mixed::tests`:

- `class_keys_authenticate_shape_columns_and_seal_roots`: trusted-pin mismatch, expected class/shape mismatch, repinned malformed dimensions/lengths, truncation/trailing data, direct/sealed load agreement, substituted roots.
- `loaded_verifiers_refuse_every_prover_entry_point`: all public tree proving paths and plain/zero-knowledge Program proving return verifier-only errors.
- `mixed_entry_rows_refuse_alignment_range_and_halt_without_decoding`: direct in-crate key construction bypasses the decoder and requires an entry-scope row failure.
- `mixed_union_rows_refuse_uncovered_and_swapped_claims`: bypasses native union validation and checks reduction/union rows, with an honest control.
- `mixed_verifier_refuses_other_modes_and_classes_direct_and_sealed`: valid output-tree, guest-claim-set and other-class roots are refused by the mixed verifier.
- `two_tier_mixed_roots_and_fake_large_wrap`: first, large and narrowed/wrapped roots agree on direct/sealed and built/loaded verification; the existing fake-large-circuit attack is reused for mixed mode.

The trusted-loader follow-up adds `trusted_loader_agrees_with_checked_direct_and_sealed_verification` (genuine first/node roots plus altered claims, proofs, seals and roots) and `trusted_loader_wrong_digest_rejects_node_seals_but_not_empty_first_seals` (the explicit v2 exception). `two_tier_mixed_roots_and_fake_large_wrap` also compares both loaders on large nodes, an actual `Level::Wrap` root and a narrowed small node, and checks that their seals fail under a wrong digest on the trusted path. The class-key parser and verifier-only guard tests above now exercise the trusted loader too.

The spike's `sealed_roots_agree_with_direct_settlement_and_bind_their_inputs` also covers node roots, changed roots, swapped seals, truncation and byte tampering. Existing same-program fixed/wide forgery tests remain in `rec/tree/mod.rs`. Tamper loops now require valid decoding rather than silently skipping a malformed candidate.

## Known gaps and integration risks

There is no formal cryptographic audit, no composed quantitative soundness bound in this patch, and no Go port or OP Stack integration. Mixed zero-knowledge leaves remain refused. Resource policy for very large but trusted classes belongs to the consumer; the loader hashes the complete input and structural checks do not replace a transport size limit. The small fixture tests are not proof of correctness at every admissible shape. Ignored architectural and long-running tests are reported separately from the normal workspace suite.

Native root fixed-column evaluation remains: the sealed path still loads about 24 MiB for the example class. The stretch design is documented separately in the main report and is not implemented. New Cannon measurements must account for hashing the authenticated artifact and the changed seal session; the supplied spike counts cannot be assigned to this revision.

[Upstream #522](https://github.com/leanEthereum/leanVM/pull/522) requires a separate treatment of conditional proofs: resolve authenticated assumptions before exposing an unconditional singleton. [Upstream #553](https://github.com/leanEthereum/leanVM/pull/553) removes this recursion machine and changes the ISA/proof format. Porting either is a protocol change requiring new artifact versions and trusted pins, not a mechanical merge of this key encoding.
