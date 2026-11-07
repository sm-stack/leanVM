//! Measures in Bencher Metric Format, the JSON CI's comparisons read.
//!
//! The format: <https://bencher.dev/docs/reference/bencher-metric-format/>.

use crate::Timing;
use std::fmt::Display;

/// One measure of one benchmark: a value, and for a timing the fastest and slowest pass.
pub struct Metric {
    /// The reported value.
    value: f64,
    /// The fastest and slowest pass, for a timing.
    bounds: Option<(f64, f64)>,
}

impl Metric {
    /// An exact count, with no bounds.
    #[must_use]
    pub const fn exact(value: usize) -> Self {
        Self {
            value: value as f64,
            bounds: None,
        }
    }

    /// A timing in nanoseconds, bounded by its fastest and slowest pass.
    #[must_use]
    pub fn nanoseconds(timing: &Timing) -> Self {
        Self::timed(timing, |secs| (secs * 1e9).round())
    }

    /// A timing in nanoseconds per operation, for passes of `ops` operations each.
    ///
    /// Kept to the picosecond, since a field operation takes a few nanoseconds or less.
    #[must_use]
    pub fn nanoseconds_per_op(timing: &Timing, ops: usize) -> Self {
        Self::timed(timing, |secs| (secs * 1e12 / ops as f64).round() / 1e3)
    }

    /// A timing's mean and extremes, each converted by `ns`.
    fn timed(timing: &Timing, ns: impl Fn(f64) -> f64) -> Self {
        let samples = timing.samples();
        Self {
            value: ns(timing.mean()),
            bounds: Some((
                ns(samples.iter().copied().fold(f64::INFINITY, f64::min)),
                ns(samples.iter().copied().fold(0.0, f64::max)),
            )),
        }
    }
}

/// Benchmarks and their measures as Bencher Metric Format JSON.
///
/// Each entry is a benchmark's name and its named measures.
#[must_use]
pub fn bencher_json<M: Display>(report: &[(String, Vec<(M, Metric)>)]) -> String {
    let benchmarks: Vec<String> = report
        .iter()
        .map(|(name, metrics)| {
            // One JSON member per measure: the value, and a timing's bounds.
            let measures: Vec<String> = metrics
                .iter()
                .map(|(measure, m)| match m.bounds {
                    None => format!("\"{measure}\": {{\"value\": {}}}", m.value),
                    Some((lo, hi)) => format!(
                        "\"{measure}\": {{\"value\": {}, \"lower_value\": {lo}, \"upper_value\": {hi}}}",
                        m.value
                    ),
                })
                .collect();
            format!("  \"{name}\": {{{}}}", measures.join(", "))
        })
        .collect();
    format!("{{\n{}\n}}", benchmarks.join(",\n"))
}

/// Whether the process was asked for JSON with `--json`, as CI runs the `benches/` targets.
#[must_use]
pub fn json_requested() -> bool {
    std::env::args().any(|arg| arg == "--json")
}
