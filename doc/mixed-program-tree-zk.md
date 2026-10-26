# Zero-knowledge leaves in mixed member trees

This extension starts at `d2f36540` on `op-stack/claim-set-leaves`. It changes no OP Stack code or guest instructions. Plain classes keep their existing class-key bytes. Adding a ZK class requires a newly authenticated v3 class key; existing consumers need not move their pin otherwise.

## Verification and placement

A ZK class is `LeafClass { program, shape: plain_shape.zero_knowledge() }`. Normalize its program as usual, then use `class.program.prover(class.shape).prove(&program, advice)`. This selects `Randomness::Os` for ZK shapes. `aggregate_programs_at(class, leaves, declare)` has the same signature and returns a small-tier proof suitable for normal folding.

The mixed first-level verifier hashes the witnessed program root, entry, fixed dimensions and image into the VK digest. It derives the **ZK** leaf session from that digest. `Layout::record_core_at` supplies the constrained witnessed entry as a public recorder value, rather than the placeholder program's entry. The recorder makes the core verifier's hidden values a linear graph over pad keys; the outer Spartan/key-commitment proof is checked in rows. Deferred core claims are made plain, and the program opening is verified against the witnessed root and image. The existing list/output and VK-labelled member bindings then apply unchanged.

The leaf envelope (`LVMZ` versus plain), expected shape kind, leaf session and authenticated class circuit all separate plain from ZK. The VK itself intentionally does not include the proof kind: both proof forms can prove the same normalized program.

Each ZK class has its own first-level tier, with the minimum padded heights that fit its verifier. A small-tier `LeafWrap(class)` verifies that first-level proof and states its identical claim set. The public aggregation method produces both. Nodes refuse a raw dedicated-tier first level where a small-tier child is required. Each tier has its own fixed polynomial; the reduction carries its evaluation and the seal authenticates it against that tier's root. The same code supports multiple ZK classes, with one tier per class.

The class-key v3 format and tree session include class kinds and placement; [the format specification](mixed-program-tree.md#class-key-v3-for-zk-classes) gives their ordering. Seal v2 is unchanged. First-level roots have no fixed claims and empty seals, so an incorrect trusted-loader digest is not detected there; program claims close in-circuit and genuine class-key bytes authenticate the recursion circuit. Public ZK aggregation returns a wrap, which does carry fixed claims. The trusted loader's soundness still rests entirely on genuine externally authenticated bytes, not on detecting a digest misconfiguration.

The comparison-only shared placement is reachable through a private builder in the ignored measurement test. It places all first levels in the small tier; public loading rejects its placement flag. It is not a second public API.

## Privacy, randomness and maturity

The sequencer receives the ZK leaf proof, normalized public program key, output and ordered members. Members are public by design, as are the program identity, class, padded dimensions and proof size. Applications must ensure the chosen output/members do not reveal the secret they intend to hide. Choose the padded class independently of secrets; zero knowledge does not hide an application-dependent choice of class or public output. `ProgramClass::prover` sets a height floor, not a ceiling: ensure all supported secret inputs fit that floor, and check the announced shape before releasing a proof. Aggregation refuses a different announcement, but cannot undo disclosure of a larger standalone proof already sent.

Aggregation nodes need not be zero knowledge: their witness contains the already-ZK leaf proof and public data, not the leaf's private advice. This does not turn plain leaves in the same tree into private leaves. It also does not protect witness data exposed by the prover's process, logs, timing, storage or host memory.

Production uses `Randomness::Os`. `Prover::prove` draws a new OS seed for every ZK proof, even when the `Prover` is reused or copied. Entropy failure panics rather than falling back to deterministic randomness. `Randomness::Fixed` is available only to zk's own unit tests or with the explicit development feature `zk/test-util`; core tests enable that feature through a dev dependency. Reusing a fixed seed reuses pad keys and can reveal differences between witnesses. Do not enable this feature in production. Low-level `Seed::stream(purpose)` intentionally restarts a purpose's deterministic stream; it is an internal building block, not a safe reusable source for separate proofs. No seed is accepted by the normal production `Prover` API.

Opt-in ZK proofs, native verification, same-program recursion and mixed claim-set recursion are implemented. The README's previous “planned” statement was stale and is updated. This remains experimental: the project is not production-ready, the composed system has no security-audit claim here, and these tests are not a formal zero-knowledge proof or quantitative soundness analysis. Continuations and big-endian proof production remain unsupported. Class keys remain large; compact keys/native root fixed-column opening improvements are separate work. No Cannon timing or OP Stack integration is claimed by this change.

## Reproducing measurements

Run:

```sh
rustup run 1.95 cargo test --release -p leanvm --lib measure_mixed_zk_layouts -- --ignored --nocapture
```

The ignored test selects exactly eight pool threads, one warmup and three measured passes, no cooldown. It uses the system allocator, Rust 1.95 release with `target-cpu=native`, on Apple M4 Pro (24 GiB). Timings are development-machine observations, not controlled throughput guarantees. Proof sizes can vary with fresh randomness and Merkle query overlap.

The class bounds, leaf table heights, rate and tree capacities are exactly those in the request: plain/ZK `(12,17,13,64,128)` with `[16,8,8,10,10,10,8,6,6,8,6]`; signature `(13,17,16,64,128)` with `[20,4,15,18,18,16,4,4,4,16,3]`; leaf/tree log inverse rate 1, first arity 1, node arity 2, large capacity `(16385,1024)`, small `(257,64)`. The program is a local assembly fixture reading private advice and publishing 16 fixed members, at a nondefault entry with a nonempty image. It is not the monorepo's echo ELF. The signature leaf verifies 100 real leanSPHINCS signatures. The announced shape, not the fixture's shorter execution, determines its padded proof work.

## Measurement results (2026-10-26)

Mean milliseconds, three samples per operation; raw pass times are in the local log. The process ran after the build/test jobs completed. Ordinary machine noise, cache/allocator history and fixed mode order still apply; differences of a few milliseconds are not established speedups.

| ZK leaf log inverse rate | Prove ms | Proof bytes | Below 512 KiB? |
| --- | ---: | ---: | --- |
| 1 | 70.16 | 532,378 | no |
| 2 | 67.42 | 424,642 | yes |
| 3 | 107.85 | 385,586 | yes |

Rate 2 brings this padded shape comfortably below 524,288 bytes without changing its table heights. It must be selected in the ZK leaf class, so it changes a ZK-containing class key. The measurements below retain the requested rate 1. The nonmonotonic rate-1/rate-2 timing is an observation, not a claim that increasing the rate is free. Validate size on the application's actual guest/shape.

| Layout | Plain first ms | Signature first ms | Plain + signature fold ms | ZK first ms | ZK wrap ms | Small-tier committed words |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| plain | 90.26 | 97.74 | 99.12 | — | — | 5,981,184 |
| shared-zk | 98.72 | 97.31 | 110.27 | 112.46 | — | 7,227,392 |
| isolated-zk | 82.00 | 86.31 | 108.00 | 118.08 | 84.02 | 5,981,184 |

The fold column measures only the aggregation of the two already-produced first levels. `ZK first + wrap` is the work behind the public ZK aggregation call. Plain small-tier heights stay `[17,16,14,10,14,10]` with isolated ZK; shared ZK raises them to `[18,16,14,11,14,10]`. Thus isolation preserves plain padded proof work exactly at this shape; shared placement adds **20.84%** committed words. Raw row counts are not all identical: the added kind and carried fixed evaluation add a few statement/selection/reduction rows. No-ZK trees retain even their exact bytes. Timing equality after adding a ZK class is not promised.

**Recommendation:** retain isolated first levels as the public default when avoiding a penalty on plain-only batches is the priority. Shared placement makes the ZK first-level path cheaper by avoiding an approximately 84 ms wrap, and is potentially better for ZK-heavy traffic. These samples do **not** establish a 50% crossover. A crude model using equal plain/signature shares and one binary fold per leaf puts the crossover near 15% ZK, but that extrapolation is sensitive to timing noise and omits large-tier transitions and sealing. Measure actual batch mixes before adopting a threshold. The shared option remains measurement-only.

### First-level and wrap rows

Each entry is `rows / height log`. Table order is the recursion machine's, not the leaf CPU's.

| Circuit | EMUL | EXK | HASH | SPLIT | CAST | PUB | Committed words |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| shared-zk First(2) | 250,905 / 18 | 45,937 / 16 | 14,539 / 14 | 1,776 / 11 | 14,934 / 14 | 641 / 10 | 7,227,392 |
| isolated-zk First(2) | 250,905 / 18 | 45,937 / 16 | 14,539 / 14 | 1,776 / 11 | 14,934 / 14 | 642 / 10 | 7,227,392 |
| isolated-zk LeafWrap(2) | 27,893 / 17 | 22,417 / 16 | 7,310 / 14 | 438 / 10 | 4,402 / 14 | 552 / 10 | 5,981,184 |

### Class keys and native roots

| Layout | Class-key bytes | Direct verify ms | Sealed verify ms | Root bytes | Seal bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| plain | 92,550,040 | 2.467 | 2.225 | 258,059 | 347,160 |
| shared-zk | 126,195,664 | 2.777 | 2.383 | 275,147 | 365,260 |
| isolated-zk | 117,300,112 | 2.921 | 2.648 | 255,995 | 523,396 |

The ZK-containing roots combine plain, signature and ZK claims. The no-ZK root contains plain and signature claims. Sealed verification times exclude class-key load and sealing. Isolation adds a third fixed commitment and opening, explaining its larger seal. The request’s 512 KiB cap applies to the leaf; transport must budget root and seal separately. Class-key pins:

- `plain`: `5926b5cf98b4e8565baa6983e30d151eec347ae24bc2b7a59be553e9bae9b5e8`
- `shared-zk`: `52f606f13488138e5c6cefb4280faf541116b9bb8c0ee66a08b24a8a114a70ac`
- `isolated-zk`: `697cec4161e1dee68a34a72200824ae1e9d6aa97422b14d5c29105b776b4efef`

The shared comparison key is reported for reproducibility only; public loaders reject it. The no-ZK key here is for the larger requested monorepo capacity, so its digest differs from the smaller compatibility example below.

## Compatibility and checks

The release workspace suite on Rust 1.95 passes **549 tests**, with five ignored (the opt-in measurement, two external ACT4 tests and two SDK doctests). The ignored eight-thread measurement is run separately. `mixed_zk_classes_wrap_fold_seal_and_refuse_foreign_leaves` covers the three requested classes, row-level tampering and both proof kinds, checked/trusted reload, raw-first refusal, ZK class zero and two separate ZK classes. Existing plain and same-program ZK tests remain enabled.

Native all-target workspace Clippy (`-D warnings`, Rust 1.99.1) and fmt pass. The x86_64 Linux AVX-512 all-target Rust Clippy check also passes. On this Mac it uses `JEMALLOC_OVERRIDE` pointing at an existing native archive to skip jemalloc's C build, because no Linux C cross compiler is installed; Clippy does not link, and this is not an x86 binary build/run result.

Both **powerpc64** and **s390x** release library codegen builds pass. The s390x QEMU run passes 17 SDK tests and two signature-member host tests, then verifies native-generated plain and ZK leaf/root/claim/seal fixtures through both loaders. Canonical bytes and claim digests agree. The ZK fixture includes a dedicated first level, its small wrap and a node with nonempty seal. Big-endian proof production is not supported.

The `claim_set_leaves 100 4097` example's one-class and two-class exports are byte-identical to the saved pre-change artifacts: class key, digest, root, claims and seal. The two-class key is **60,027,800 bytes**, with unchanged digest:

```
05860eb91c53a9508a9c81c8cc0bc92e501e1ffb3cabed422dc5a3618adcb96d
```

The one-class key is 50,016,128 bytes, digest:

```
fa61cd1e5130cd279130f4283c0c033f367322815baa06f6cf31197d5cc895fd
```

All fourteen checked-in guest ELF `.text` sections match `d2f36540` byte-for-byte (SHA-256 and lengths recorded). No guest or SDK implementation was edited, so fixtures did not need rebuilding. Raw local logs, measurements, comparison results and guest text hashes are retained in `.context/zk-mixed/`; build caches may be removed afterward.
