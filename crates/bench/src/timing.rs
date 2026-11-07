//! Wall-clock samples and their 95% confidence interval.

use std::fmt::{self, Display, Formatter};

/// Wall-clock samples from one repeated measurement, in seconds.
#[derive(Clone, Debug, Default)]
pub struct Timing {
    /// One duration per measured pass, in seconds.
    samples: Vec<f64>,
}

impl Timing {
    /// Records one measured pass.
    pub fn push(&mut self, secs: f64) {
        self.samples.push(secs);
    }

    /// Every measured pass, in seconds, in the order they ran.
    #[must_use]
    pub fn samples(&self) -> &[f64] {
        &self.samples
    }

    /// The mean duration, in seconds.
    #[must_use]
    pub fn mean(&self) -> f64 {
        Interval::of(&self.samples).mean
    }

    /// The suffix appended to every reported duration: `" ± 0.4%"` over several samples, nothing over one.
    #[must_use]
    pub const fn spread(&self) -> Spread<'_> {
        Spread(self)
    }
}

/// The relative half-width of a timing's confidence interval, as its report prints it.
pub struct Spread<'a>(&'a Timing);

impl Display for Spread<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // One sample has no spread, and a zero mean has no relative one.
        let interval = Interval::of(&self.0.samples);
        if self.0.samples.len() < 2 || interval.mean == 0.0 {
            return Ok(());
        }
        write!(f, " ± {:.1}%", 100.0 * interval.half_width / interval.mean)
    }
}

/// A mean and the half-width of its two-sided 95% confidence interval.
#[derive(Clone, Copy, Debug)]
struct Interval {
    /// The sample mean.
    mean: f64,
    /// Half the interval's width; zero for a single sample.
    half_width: f64,
}

impl Interval {
    /// The interval of `samples`, with Student's t for `n - 1` degrees of freedom.
    ///
    /// A small sample count is then not reported as tighter than it is.
    fn of(samples: &[f64]) -> Self {
        let n = samples.len();
        assert!(n > 0, "an interval needs at least one sample");
        let mean = samples.iter().sum::<f64>() / n as f64;
        // One sample says nothing about the spread.
        if n < 2 {
            return Self { mean, half_width: 0.0 };
        }
        // The unbiased variance, then the standard error of the mean.
        let variance = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64;
        let std_err = (variance / n as f64).sqrt();
        Self {
            mean,
            half_width: t_critical_95(n - 1) * std_err,
        }
    }
}

/// The two-sided 95% critical value of Student's t with `df` degrees of freedom.
///
/// The Cornish-Fisher expansion around the normal quantile, within 0.5% for `df >= 3`.
fn t_critical_95(df: usize) -> f64 {
    // The normal distribution's 97.5% quantile.
    let z = 1.959_964_f64;
    let df = df as f64;
    // The first two correction terms of the expansion in `1 / df`.
    z + (z.powi(3) + z) / (4.0 * df)
        + 3.0f64.mul_add(z, 16.0f64.mul_add(z.powi(3), 5.0 * z.powi(5))) / (96.0 * df.powi(2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spread_edge_cases() {
        // One sample: its own mean, no interval, no suffix.
        let mut t = Timing::default();
        t.push(1.5);
        assert_eq!(t.mean(), 1.5);
        assert_eq!(Interval::of(t.samples()).half_width, 0.0);
        assert_eq!(t.spread().to_string(), "");

        // Four equal samples: a zero-width interval, still printed.
        let mut t = Timing::default();
        for _ in 0..4 {
            t.push(2.0);
        }
        assert_eq!(t.mean(), 2.0);
        assert_eq!(Interval::of(t.samples()).half_width, 0.0);
        assert_eq!(t.spread().to_string(), " ± 0.0%");
    }

    #[test]
    fn ci_shrinks_as_samples_accumulate() {
        // Alternating 1.0 and 1.2: the same spread, more samples.
        let half_width = |n: usize| {
            let samples: Vec<f64> = (0..n).map(|i| if i.is_multiple_of(2) { 1.0 } else { 1.2 }).collect();
            Interval::of(&samples).half_width
        };
        assert!(half_width(16) < half_width(4), "more samples must tighten the interval");
    }
}
