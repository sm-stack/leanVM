//! The benchmark harness of the CLI and the `benches/` targets.
//!
//! - Repeated timing with warmup, cooldown and confidence intervals.
//! - The heap the global allocator counts, and the allocator itself.
//! - The trace tree `--tracing` prints, and the prover's stage times.
//! - Bencher Metric Format output.
//!
//! Nothing the prover or verifier links.

mod bencher;
mod heap;
mod plan;
mod pretty;
mod timing;
mod trace;

pub use bencher::{Metric, bencher_json, json_requested};
pub use heap::{Counting, Heap, Jemalloc, measure_heap, peak_rss_bytes};
pub use plan::{Plan, env_usize};
pub use pretty::{pretty_bytes, pretty_f64, pretty_integer};
pub use timing::Timing;
pub use trace::{
    Stage, TraceSuppressed, init_tracing, init_tracing_from_env, suppress_tracing, take_stages, time_stages,
};
