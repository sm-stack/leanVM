# Big-endian verification

The portable verifier supports big-endian hosts. CI generates MIPS64 machine code and runs the s390x verifier under QEMU. Proof generation uses little-endian Flock witness packing and is not supported on big-endian hosts.

Wire values are encoded explicitly in little endian. The SDK's byte-streaming BLAKE2s and `Template::write` place bytes within numeric words rather than relying on native byte order. Merkle rows, transcript fields, keys and proofs use the same encoding on every host. Guest code uses the RISC-V implementation of these operations.

## Build and execute

Install Rust 1.95, the s390x target, its C cross compiler and QEMU, then run the check script:

```sh
rustup target add s390x-unknown-linux-gnu
sudo apt-get install gcc-s390x-linux-gnu libc6-dev-s390x-cross qemu-user
scripts/check-big-endian.sh
```

The script sets generic CPU flags and builds release machine code. It exports plain and ZK leaf/root fixtures on the native little-endian host, verifies them under QEMU, and runs the SDK and signature-member host tests. It also verifies the checked-in isolated and shared compact-key suites. Both loader variants must agree on the valid fixtures and reject the tampered cases. Compact keys refuse direct verification with `SealRequired`.

To run a frozen suite separately:

```sh
CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_LINKER=s390x-linux-gnu-gcc \
CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_RUNNER='qemu-s390x -L /usr/s390x-linux-gnu' \
RUSTFLAGS='-C target-cpu=generic' \
cargo run --release -p leanvm --example fixtures --target s390x-unknown-linux-gnu \
  -- verify shared conformance/mixed-class-key-v4-shared-zk
```

## MIPS64 code generation

The tier-3 MIPS64 target needs a standard library built from the matching compiler sources. CI scopes `RUSTC_BOOTSTRAP` to that build with pinned Rust 1.95:

```sh
rustup component add rust-src --toolchain 1.95
RUSTFLAGS='-C target-cpu=generic' RUSTC_BOOTSTRAP=1 \
rustup run 1.95 cargo build -Z build-std=std,panic_abort --release -p leanvm --lib \
  --target mips64-unknown-linux-gnuabi64
```

This generates a MIPS64 library archive. The application must separately link and test its client executable. Use a real release build: a development-profile `cargo check` may not evaluate inline constants that reject an unsupported target.
