//! Prove a guest and verify its serialized proof with a standalone program key.
use leanvm::{Program, Proof, Prover, Rate, VerifyingKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let elf = include_bytes!("../../../programs/fibonacci/fibonacci.elf");
    let program = Program::from_elf(elf)?;
    let run = Prover::new(Rate::MIN).prove(&program, &[2700])?;
    let proof = Proof::from_bytes(&run.proof.to_bytes())?;
    let key = VerifyingKey::from_bytes(&program.verifying_key().to_bytes()).ok_or("invalid program key")?;
    key.verify(run.output, &proof)?;
    Ok(())
}
