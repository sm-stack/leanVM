//! A degree-two sumcheck round as the provers compute it.

use std::iter::Sum;
use std::ops::Add;

use primitives::field::F192;

/// A degree-two round polynomial `G` at the points a prover sums: `G(1)` and its leading coefficient `G(inf)`.
///
/// The claim the round continues fixes `G(0)`, so these two are all a round adds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RoundEvals {
    /// `G(1)`.
    pub(crate) at_one: F192,

    /// `G(inf)`, the leading coefficient.
    pub(crate) at_inf: F192,
}

impl RoundEvals {
    /// The zero polynomial's.
    pub(crate) const ZERO: Self = Self {
        at_one: F192::ZERO,
        at_inf: F192::ZERO,
    };

    /// `G`'s coefficients, lowest first, given `G(0)`.
    ///
    /// ```text
    ///     G(X) = G(0) (1 + X) + G(1) X + G(inf) X (1 + X)
    ///          = G(0) + (G(0) + G(1) + G(inf)) X + G(inf) X^2        in characteristic 2
    /// ```
    pub(crate) fn coefficients(self, at_zero: F192) -> [F192; 3] {
        [at_zero, at_zero + self.at_one + self.at_inf, self.at_inf]
    }
}

impl Add for RoundEvals {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            at_one: self.at_one + rhs.at_one,
            at_inf: self.at_inf + rhs.at_inf,
        }
    }
}

impl Sum for RoundEvals {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, Add::add)
    }
}
