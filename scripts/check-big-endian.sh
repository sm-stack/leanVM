#!/bin/sh
# Codegen and execution are required: a dev-profile `cargo check` can miss inline-const failures.
# Install the target, its C cross compiler and QEMU first; see doc/big-endian.md.
set -eu
cd "$(dirname "$0")/.."
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
export RUST_TEST_THREADS=${RUST_TEST_THREADS:-2}
export RUSTFLAGS='-C target-cpu=generic'
target=${BIG_ENDIAN_TARGET:-s390x-unknown-linux-gnu}
fixture=${BIG_ENDIAN_FIXTURE:-target/endian-fixture}
rustc --print cfg --target "$target" | grep -qx 'target_endian="big"'
case "$target" in
    s390x-unknown-linux-gnu)
        export CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_LINKER=${CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_LINKER:-s390x-linux-gnu-gcc}
        export CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_RUNNER=${CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_RUNNER:-"qemu-s390x -L /usr/s390x-linux-gnu"}
        ;;
    *) echo "Set the Cargo linker and runner for $target explicitly." ;;
esac
cargo run --release -p leanvm --example endian_verifier -- export "$fixture"
cargo run --release -p leanvm --example endian_verifier -- export "$fixture-zk" zk
cargo build --release -p leanvm --lib --target "$target"
cargo test --release -p leanvm_guest -p leansphincs-members-host --target "$target"
cargo run --release -p leanvm --example endian_verifier --target "$target" -- verify "$fixture"
cargo run --release -p leanvm --example endian_verifier --target "$target" -- verify "$fixture-zk" zk
cargo run --release -p leanvm --example compact_class_key --target "$target" -- conformance/mixed-class-key-v4 16385 verify
