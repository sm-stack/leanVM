//! Native verification of hand-assembled RISC-V programs and Rust guests.

mod act4;
mod compact;
mod corrupted;
mod deferred;
mod guests;
mod programs;

#[path = "../fixtures/shared_zk.rs"]
mod shared_zk_fixture;

#[test]
fn shared_zk_differential_fixtures() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/mixed-class-key-v4-shared-zk");
    shared_zk_fixture::verify(&dir);
}
