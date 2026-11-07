<h1 align="center">leanVM</h1>

<p align="center">
  <img src="./doc/images/banner.svg" alt="leanVM">
</p>

<h3 align="center">minimal hash-based zkVM, for post-quantum Ethereum</h3>

<p align="center">
  <a href="https://github.com/leanEthereum/leanVM/releases/download/doc-latest/leanVM.pdf"><img src="https://img.shields.io/badge/Documentation-PDF-blue?style=for-the-badge&logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xNCAySDZjLTEuMSAwLTIgLjktMiAydjE2YzAgMS4xLjg5IDIgMS45OSAySDE4YzEuMSAwIDItLjkgMi0yVjhsLTYtNnpNOC41IDE0LjVoMS4yNWMuOTcgMCAxLjc1LS43OCAxLjc1LTEuNzVTMTAuNzIgMTEgOS43NSAxMUg3LjV2Nmgxdi0yLjV6bTAtMVYxMmgxLjI1Yy40MSAwIC43NS4zNC43NS43NXMtLjM0Ljc1LS43NS43NUg4LjV6bTUuNSAzLjVoMnYtMWgtMnYtMWgydi0xaC0ydi0xLjVjMC0uMjguMjItLjUuNS0uNUgxN3YtMWgtMmMtLjgzIDAtMS41LjY3LTEuNSAxLjVWMTd6TTEzIDlWMy41TDE4LjUgOUgxM3oiLz48L3N2Zz4=" alt="Documentation"></a>
  <a href="./python-verifier/verifier.py"><img src="https://img.shields.io/badge/verifier-python-yellow?style=for-the-badge&logo=python&logoColor=white" alt="Python verifier"></a>
</p>

<table align="center">
  <tr>
    <td><a href="#leanxmss-aggregation">leanXMSS aggregation</a></td>
    <td align="right"><b>965/s</b></td>
  </tr>
  <tr>
    <td><a href="#leansphincs-aggregation">leanSPHINCS aggregation</a></td>
    <td align="right"><b>440/s</b></td>
  </tr>
  <tr>
    <td><a href="#data-availability">leanDA commitment</a></td>
    <td align="right"><b>2,6 MiB/s</b></td>
  </tr>
</table>
<table align="center">
  <tr>
    <td><a href="#recursion">2-to-1 recursion</a></td>
    <td align="right"><b>0.21s</b></td>
  </tr>
  <tr>
    <td><a href="#hashing">proving KECCAK</a></td>
    <td align="right"><b>560K/s</b></td>
  </tr>
  <tr>
    <td><a href="#fibonacci">cheap cycles</a></td>
    <td align="right"><b>6,2M/s</b></td>
  </tr>
</table>

## security

leanVM is designed for security:

 * 128-bit ROM (64-bit QROM) soundness
 * no proximity gap conjecture
 * end-to-end formal verification
 * a traditional hash function

**warning**: Formal verification is [in progress](https://github.com/Verified-zkEVM/leanerVM). leanVM is not (yet) production ready.

## work in progress

Expect leanVM to change significantly:

* **hash**: Keccak-256 is a placeholder: SHA2, BLAKE2s and BLAKE3 are actively considered.
* **ISA**: A migration from leanISA to RISC-V (rv64im) is planned.
* **zk**: Support for zero-knowledge is planned.

**note**: Prior to binary fields leanVM used [KoalaBear](https://crates.io/crates/p3-koala-bear) and [Poseidon](https://eprint.iacr.org/2019/458). The historical design is in [this branch](https://github.com/leanEthereum/leanVM/tree/koalabear).

## benchmarks

**machine**: M4 Max MacBook Pro (12 performance cores, 4 efficiency cores, 48GB RAM)

**note**: The Metal GPU was not used.

### leanXMSS aggregation

The leanXMSS parameters are specified in [leanXMSS.pdf](https://github.com/leanEthereum/leanVM/releases/download/doc-latest/leanXMSS.pdf), with a [(ROM) security proof in Lean 4](formal/lean_xmss/LeanXmss/Statement.lean). **This is not the definitive parameter set.**

```bash
cargo leanvm aggregate --xmss 1500 --log-inv-rate 2 --repeat 3
```

```
aaggregation, 1,500 leanXMSS signatures
  cycles (VM steps)           : 1,227,023 = 2^20.227
    details                   : XOR 2^18.099 (22.9%)  KECCAK 2^18.094 (22.8%)  MUL 2^17.955 (20.7%)  SET 2^17.46 (14.7%)  DEREF 2^17.38 (13.9%)  JUMP 2^15.91 (5.0%)  MEMORY 2^23.147  BYTECODE 2^18.899  TOTAL_COMMITTED 2^26.993
  proof size                  : 265.1 KiB
  proving time                : 1.554 s ± 4.2%      peak memory 9.646 GiB
  per signature               : 965.372 signatures/s
  verifying                   : 7.364 ms
```

### leanSPHINCS aggregation

The leanSPHINCS parameters are specified in [leanSPHINCS.pdf](https://github.com/leanEthereum/leanVM/releases/download/doc-latest/leanSPHINCS.pdf), with a [(ROM) security proof in Lean 4](formal/lean_sphincs/README.md). **This is not the definitive parameter set.**

```bash
cargo leanvm aggregate --sphincs 530 --log-inv-rate 1 --repeat 3
```

```
aggregation, 530 leanSPHINCS signatures
  cycles (VM steps)           : 2,464,998 = 2^21.233
    details                   : XOR 2^19.929 (40.5%)  MUL 2^19.399 (28.0%)  SET 2^18.124 (11.6%)  KECCAK 2^17.994 (10.6%)  DEREF 2^17.259 (6.4%)  JUMP 2^16.141 (2.9%)  MEMORY 2^23.152  BYTECODE 2^18.899  TOTAL_COMMITTED 2^26.983
  proof size                  : 372.9 KiB
  proving time                : 1.193 s ± 4.7%      peak memory 7.501 GiB
  per signature               : 444.43 signatures/s
  verifying                   : 7.92 ms
```

### data availability

```bash
cargo leanvm aggregate --blobs 16 --log-inv-rate 1 --repeat 3
```

```
aggregation, 16 blobs
  cycles (VM steps)           : 3,019,625 = 2^21.526
    details                   : XOR 2^20.098 (37.2%)  MUL 2^19.811 (30.5%)  DEREF 2^19.201 (20.0%)  JUMP 2^18.052 (9.0%)  SET 2^16.056 (2.3%)  KECCAK 2^15.088 (1.2%)  MEMORY 2^21.817  BYTECODE 2^18.899  TOTAL_COMMITTED 2^26.494
  proof size                  : 340.2 KiB
  proving time                : 0.762 s ± 3.3%      peak memory 5.968 GiB
  blob throughput             : 20.993 blobs/s, 2.624 MiB/s
  verifying                   : 7.904 ms
```

### recursion

```bash
cargo leanvm recursion --n 2 --xmss-per-leaf 1500 --leaf-log-inv-rate 2 --log-inv-rate 1 --repeat 3
```

```
recursion 2→1, over leaves of 900 leanXMSS signatures
  cycles (VM steps)           : 542,049 = 2^19.048
    details                   : MUL 2^17.622 (37.2%)  XOR 2^17.183 (27.5%)  DEREF 2^16.839 (21.6%)  SET 2^15.214 (7.0%)  JUMP 2^14.526 (4.4%)  KECCAK 2^13.63 (2.3%)  MEMORY 2^19.78  BYTECODE 2^18.467  TOTAL_COMMITTED 2^24.02
  proof size                  : 216.9 KiB
  proving time                : 0.309 s ± 1.6%      peak memory 2.315 GiB
  verifying                   : 9.176 ms
```

### Proving KECCAK

```bash
cargo leanvm hash --log-n 17 --repeat 3
```

```
Keccak GKR batch proving, 131,072 permutations, a state committed every 12 rounds
  witness                         :     14.8 ms ± 87.7%    6.3%
  commit                          :     17.7 ms ± 34.5%    7.5%
  output claim                    :      2.1 ms ± 20.4%    0.9%
  layers and openings             :    177.0 ms ± 4.1%   75.4%
  pcs opening                     :     23.2 ms ± 7.0%    9.9%
  ------------------------------------------
  prove TOTAL (witness included)  :    234.8 ms ± 10.4%
  verify                          :      4.2 ms
  throughput                      :        558,291 permutations/s ± 10.4%
  proof size                      :       290.2 KiB  (1562 scalars, 253.6 KiB of Merkle openings)
```

### Fibonacci

```bash
cargo leanvm fibonacci --n 2000000 --log-inv-rate 1 --repeat 3
```

```
Fibonacci (in the exponent, i.e. modulo 2^64 - 1), N = 2,000,000
  cycles (VM steps)           : 2,040,016
    details                   : MUL 2^20.944 (98.9%)  SET 2^13.288 (0.5%)  DEREF 2^12.967 (0.4%)  JUMP 2^10.968 (0.1%)  XOR 2^10.966 (0.1%)  MEMORY 2^20.959  BYTECODE 2^10.017  TOTAL_COMMITTED 2^25.261
  proof size                  : 311.2 KiB
  proving                     : 0.326 s ± 7.1%   6,257,419 cycles/s      peak memory 2.46 GiB
  verifying                   : 5.963 ms
```

## the RISC-V machine

`leanvm::rv` proves RISC-V (rv64im) plus custom instructions for the BLAKE2s compression and the 192-bit field product, with [Flock](https://github.com/succinctlabs/flock/tree/main) proving each instruction class's Boolean circuit. Its proofs use BLAKE2s and share no format with the leanISA proofs above. Zero-knowledge leaf proofs are opt-in; see [privacy and randomness](doc/compact-class-key.md#privacy-and-randomness).

A program is a guest: a `no_std` Rust program built for `riscv64im-unknown-none-elf` against the SDK in [`sdk`](./sdk/src/lib.rs). Its `main` does all its I/O: `leanvm_guest::read::<T>()` takes the next value from the advice (a region of memory the prover fills, which the statement says nothing about), in place with no copy or decoding, and `leanvm_guest::commit(&value)` makes a value public. The run's output is the BLAKE2s digest of everything committed, in order, which a verifier recomputes from the public values. Everything else in a guest is ordinary Rust. The SDK's linker script fixes the memory map. Each program lives in its own folder, `programs/<name>/guest`, a standalone package that `cargo build --release` builds there (a dated nightly toolchain, pinned by its `rust-toolchain.toml`, for `-Zbuild-std`); a program whose advice takes work to make also has a host, `programs/<name>/host`, its code off the VM. `programs/build.sh` builds every guest and refreshes its checked-in `programs/<name>/<name>.elf`; then prove and verify a run:

```bash
cargo leanvm rv guest programs/preimage/preimage.elf --advice 5,0x6f6c6c6568
```

The statement a proof makes is the program (an ELF file) and its four output words, the digest of what it committed; everything a guest reads from its advice it has to check itself, which is what makes a proof a proof of knowledge (`preimage` commits the digest of a message only the prover has).

Benchmarks (the timing subcommands use 16 threads unless `LEANVM_NUM_THREADS` is set):

```bash
cargo leanvm rv fibonacci --n 2000000 --log-inv-rate 1 --repeat 3
cargo leanvm rv guest programs/blake2s/blake2s.elf --advice 10000 --repeat 3    # BLAKE2s in plain Rust
cargo leanvm rv guest programs/hash/hash.elf --advice 50000 --repeat 3          # BLAKE2s through the precompile
cargo leanvm rv leanxmss --n 400 --repeat 3
cargo leanvm rv leansphincs --n 104 --repeat 3
cargo leanvm rv leanda --blobs 1 --repeat 3
cargo leanvm rv falcon --n 28 --repeat 3
cargo leanvm rv stateproof --n 21 --repeat 3
cargo leanvm rv shielded --n 1035 --repeat 3
cargo leanvm rv aggregate --program leanxmss --n 400 --leaves 16 --arity0 4 --arity 4 --repeat 3
cargo leanvm rv bench --cycles-only --markdown    # exact cycle and witness counts, no proof
BENCH_REPEAT=3 FLOCK_N_LOG=18 cargo bench -p leanvm_rv --bench class_batch -- hash
```

The workloads check leanXMSS and leanSPHINCS signatures, leanDA blobs, Falcon-512 signatures, Ethereum L1 state proofs (`eth_getProof`) and shielded transfers, each at the most one proof holds (continuations are not implemented). `rv aggregate` proves an aggregation tree over leaf proofs, at `--leaf-log-inv-rate` for the leaves and `--log-inv-rate` for the tree; `--signers` makes it a signer-set tree. Mobile proving benchmarks are in [`bench-mobile`](bench-mobile/README.md), and the [benchmark website](./site/benchmarks/index.html) reads one JSON snapshot of the desktop and mobile results.

## SNARK machinery

- 192-bit binary field (degree-3 tower over the 64-bit field)
- [WHIR](https://eprint.iacr.org/2024/1586) PCS, aka [Ligerito](https://eprint.iacr.org/2025/1187)
- [Hashcaster 2](https://github.com/levs57/hashcaster2) proving Keccak via GKR and RMFE
- [Binius](https://github.com/IrreducibleOSS/binius)/[Binius64](https://github.com/binius-zk/binius64) ring switching, M3 arithmetisation, and more (see [DP23](https://eprint.iacr.org/2023/1784) and [DP24](https://eprint.iacr.org/2024/504))
