//! How a benchmark repeats and paces its passes, with one line of live progress.

use crate::{Timing, suppress_tracing};
use std::io::{IsTerminal, Write};
use std::time::{Duration, Instant};

/// How a benchmark repeats and paces its measured passes.
///
/// Every pass but the final measured one runs with the trace tree suppressed.
///
/// So `--tracing` prints one tree, for the pass the reported numbers describe.
#[derive(Clone, Copy, Debug)]
pub struct Plan {
    /// Measured passes to average; at least one.
    repeat: usize,
    /// Idle time before each measured pass, so a thermally limited host recovers its clocks.
    cooldown: Duration,
}

impl Default for Plan {
    fn default() -> Self {
        Self::new(1, Duration::ZERO)
    }
}

impl Plan {
    /// A plan of `repeat` measured passes, each preceded by `cooldown` idle.
    ///
    /// # Panics
    ///
    /// Panics when `repeat` is zero.
    #[must_use]
    pub fn new(repeat: usize, cooldown: Duration) -> Self {
        assert!(repeat >= 1, "a benchmark needs at least one measured pass");
        Self { repeat, cooldown }
    }

    /// The plan `BENCH_REPEAT` and `BENCH_COOLDOWN` (in seconds) describe.
    ///
    /// The `benches/` targets read it, since `cargo bench` gives them no command line of their own.
    ///
    /// The defaults match the CLI's.
    #[must_use]
    pub fn from_env() -> Self {
        let cooldown = Duration::from_secs(env_usize("BENCH_COOLDOWN", 2) as u64);
        Self::new(env_usize("BENCH_REPEAT", 1), cooldown)
    }

    /// The same number of measured passes, with no cooldown.
    #[must_use]
    pub const fn without_cooldown(self) -> Self {
        Self {
            cooldown: Duration::ZERO,
            ..self
        }
    }

    /// The number of measured passes.
    #[must_use]
    pub const fn repeat(&self) -> usize {
        self.repeat
    }

    /// Runs `f` once untimed to warm up, then the measured passes.
    ///
    /// Returns the last pass's result and every measured pass's time.
    pub fn warm_then_measure<T>(&self, mut f: impl FnMut() -> T) -> (T, Timing) {
        let progress = Progress::new();
        progress.status("[warming]");
        // The warmup's result is freed before the first measured pass allocates.
        // Every measured pass then sees the same steady-state footprint.
        {
            let _quiet = suppress_tracing();
            drop(f());
        }
        self.run(f, progress, true)
    }

    /// Runs the measured passes, with no warmup and no per-pass output.
    pub fn measure_quiet<T>(&self, f: impl FnMut() -> T) -> (T, Timing) {
        self.run(f, Progress::new(), false)
    }

    /// Runs the measured passes, echoing each one's time to `progress` when `echo` is set.
    fn run<T>(&self, mut f: impl FnMut() -> T, mut progress: Progress, echo: bool) -> (T, Timing) {
        let mut timing = Timing::default();
        let mut last = None;
        for pass in 0..self.repeat {
            // The previous pass's result is freed before this one allocates.
            drop(last.take());
            self.cool_down(&progress);
            // Only the final pass is traced.
            let quiet = (pass + 1 < self.repeat).then(suppress_tracing);
            let start = Instant::now();
            let out = f();
            let secs = start.elapsed().as_secs_f64();
            drop(quiet);
            timing.push(secs);
            if echo && self.repeat > 1 {
                progress.push(secs);
            }
            last = Some(out);
        }
        progress.finish();
        (last.expect("a plan has at least one measured pass"), timing)
    }

    /// Sleeps for the cooldown, a second at a time, counting down on the progress line.
    fn cool_down(&self, progress: &Progress) {
        let mut left = self.cooldown;
        while !left.is_zero() {
            progress.status(&format!("[cooldown {}s]", left.as_secs_f64().ceil() as u64));
            let step = Duration::from_secs(1).min(left);
            std::thread::sleep(step);
            left -= step;
        }
    }
}

/// Reads a `usize` benchmark knob from the environment, `default` when unset.
///
/// # Panics
///
/// Panics when the variable is set but is not an integer.
#[must_use]
pub fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .map(|s| s.parse().unwrap_or_else(|_| panic!("{key} must be an integer")))
        .unwrap_or(default)
}

/// One line of live progress on stderr.
///
/// - Measured pass times accumulate on it.
/// - Transient status (warming, cooling) follows them and is erased again.
/// - Off a terminal it only appends, with no escape codes, and skips the transient parts.
struct Progress {
    /// Whether stderr is a terminal, which can erase a line.
    tty: bool,
    /// The pass times printed so far.
    parts: String,
}

/// The label the progress line starts with, aligned with the reports' other lines.
const PROGRESS_LABEL: &str = "  passes                      : ";

impl Progress {
    /// An empty progress line.
    fn new() -> Self {
        Self {
            tty: std::io::stderr().is_terminal(),
            parts: String::new(),
        }
    }

    /// Redraws the line: the pass times, then `transient`.
    fn draw(&self, transient: &str) {
        if self.tty {
            eprint!("\r\x1b[2K{PROGRESS_LABEL}{}{transient}", self.parts);
            let _ = std::io::stderr().flush();
        }
    }

    /// Shows a transient status after the pass times.
    fn status(&self, msg: &str) {
        if self.parts.is_empty() {
            self.draw(msg);
        } else {
            self.draw(&format!("  {msg}"));
        }
    }

    /// Appends one measured pass's time.
    fn push(&mut self, secs: f64) {
        let first = self.parts.is_empty();
        if !first {
            self.parts.push_str("  ");
        }
        self.parts.push_str(&format!("{secs:.3} s"));
        if self.tty {
            self.draw("");
            return;
        }
        // Off a terminal, print only what is new.
        if first {
            eprint!("{PROGRESS_LABEL}");
        } else {
            eprint!("  ");
        }
        eprint!("{secs:.3} s");
        let _ = std::io::stderr().flush();
    }

    /// Ends the line, or erases it when it shows no pass.
    fn finish(self) {
        if !self.parts.is_empty() {
            eprintln!();
        } else if self.tty {
            eprint!("\r\x1b[2K");
            let _ = std::io::stderr().flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warmup_pass_is_not_measured() {
        // Fixture state: three measured passes.
        //
        //     calls:  1 (warmup)  2  3  4
        //     timed:          no  yes yes yes
        let mut calls = 0;
        let (last, timing) = Plan::new(3, Duration::ZERO).warm_then_measure(|| {
            calls += 1;
            calls
        });
        assert_eq!(calls, 4, "one warmup plus three measured passes");
        assert_eq!(last, 4);
        assert_eq!(timing.samples().len(), 3);
    }
}
