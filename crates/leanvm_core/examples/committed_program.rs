//! Export a small guest proof and its verification inputs, with native measurements.

use bench::Plan;
use leanvm::{Program, Prover, Rate, VerifyingKey};
use std::path::PathBuf;
use std::time::Duration;

#[global_allocator]
static ALLOCATOR: bench::Jemalloc = bench::Jemalloc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "committed-program".into()));
    let prover = Prover::new(Rate::MIN);
    let plan = Plan::new(3, Duration::ZERO);
    let fibonacci = include_bytes!("../../../programs/fibonacci/fibonacci.elf").as_slice();
    let preimage = include_bytes!("../../../programs/preimage/preimage.elf").as_slice();
    let mut preimage_advice = vec![256];
    preimage_advice.extend((0..32u64).map(|i| i.wrapping_mul(0x0101_0101_0101_0101)));
    for (name, elf, advice) in [
        ("fibonacci-small", fibonacci, vec![2700]),
        ("fibonacci-large", fibonacci, vec![21820]),
        ("preimage", preimage, preimage_advice),
    ] {
        let (program, setup) = plan.warm_then_measure(|| Program::from_elf(elf).expect("a checked-in guest"));
        let (run, proving) = plan.warm_then_measure(|| prover.prove(&program, &advice).expect("the guest exits"));
        let key_bytes = program.verifying_key().to_bytes();
        let (key, verifier_setup) =
            plan.warm_then_measure(|| VerifyingKey::from_bytes(&key_bytes).expect("a key's encoding"));
        let (_, verifying) = plan.warm_then_measure(|| key.verify(run.output, &run.proof).expect("the proof verifies"));
        let path = directory.join(name);
        std::fs::create_dir_all(&path)?;
        std::fs::write(path.join("program.elf"), elf)?;
        std::fs::write(path.join("key.bin"), &key_bytes)?;
        std::fs::write(path.join("proof.bin"), run.proof.to_bytes())?;
        std::fs::write(
            path.join("output.bin"),
            run.output
                .words()
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<_>>(),
        )?;
        println!(
            "{name}: cycles={} key_bytes={} proof_bytes={} setup_ms={:.4} prove_ms={:.4} verifier_setup_ms={:.4} verify_ms={:.4}",
            run.stats.cycles(),
            key_bytes.len(),
            run.proof.to_bytes().len(),
            setup.mean() * 1000.0,
            proving.mean() * 1000.0,
            verifier_setup.mean() * 1000.0,
            verifying.mean() * 1000.0
        );
    }
    Ok(())
}
