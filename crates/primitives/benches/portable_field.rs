//! Portable carry-less arithmetic, compared with the bit-by-bit reference.

use bench::Plan;
use primitives::field::gf2_64::software::{clmul, clmul_fast, spread};
use std::hint::black_box;

fn main() {
    const ROUNDS: usize = 256;
    let mut state = 1u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let inputs: Vec<_> = (0..16_384).map(|_| (next(), next())).collect();
    for (name, product) in [
        ("bit loop", clmul as fn(u64, u64) -> u128),
        ("bmul Karatsuba", clmul_fast),
    ] {
        let (_, timing) = Plan::from_env().warm_then_measure(|_| {
            let mut sum = 0;
            for _ in 0..ROUNDS {
                for &(a, b) in black_box(&inputs) {
                    sum ^= product(black_box(a), black_box(b));
                }
            }
            black_box(sum)
        });
        println!(
            "{name}: {:.2} ns/product{}",
            timing.mean() * 1e9 / (ROUNDS * inputs.len()) as f64,
            timing.spread()
        );
    }
    let (_, timing) = Plan::from_env().warm_then_measure(|_| {
        let mut sum = 0;
        for _ in 0..ROUNDS {
            for &(a, _) in black_box(&inputs) {
                sum ^= spread(black_box(a));
            }
        }
        black_box(sum)
    });
    println!(
        "spread: {:.2} ns/square{}",
        timing.mean() * 1e9 / (ROUNDS * inputs.len()) as f64,
        timing.spread()
    );
}
