// CREDIT: https://github.com/succinctlabs/flock (the skip domain's Lagrange weights), MIT OR Apache-2.0.
//! The univariate skip's domain, and the interpolations at the skip challenge its verifiers and its prover share.

use fiat_shamir::arith::Arith;
use primitives::field::gf2_64::{reduce, software::clmul};
use primitives::field::{F192, PHI8_TABLE};
use primitives::multilinear::eq_table;

use super::K_SKIP;
use crate::lincheck::outer_product;

/// The skip domain `S`: the first `2^k_skip` nodes of the phi_8 table.
///
/// It is a subspace over GF(2), since phi_8 is linear on its index.
/// Its coset `Lambda = S + phi_8(2^k_skip)` holds the zerocheck's first message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkipDomain {
    k_skip: usize,
}

impl SkipDomain {
    /// The domain the zerocheck skips and the lincheck interpolates over.
    pub const FLOCK: Self = Self { k_skip: K_SKIP };

    /// The domain of `2^k_skip` nodes.
    ///
    /// # Panics
    ///
    /// If `S` and `Lambda` do not fit the phi_8 table.
    pub(crate) const fn new(k_skip: usize) -> Self {
        assert!(k_skip < 8, "the window fits the phi_8 table");
        Self { k_skip }
    }

    /// The base-two logarithm of its size.
    pub(crate) const fn k_skip(self) -> usize {
        self.k_skip
    }

    /// Its size, and the zerocheck's first message's.
    pub(crate) const fn size(self) -> usize {
        1 << self.k_skip
    }

    /// The coefficients `c_j` of `V_S(X) = prod_{s in S} (X + s) = sum_j c_j X^(2^j)`, lowest first.
    ///
    /// Adding a basis element `a` to a subspace takes `V` to `V(X)^2 + V(a) V(X)`, since `V(X + a) = V(X) + V(a)`.
    fn vanishing_coefficients(self) -> Vec<F192> {
        // The zero subspace's polynomial is `X`.
        let mut c = vec![F192::ZERO; self.k_skip + 1];
        c[0] = F192::ONE;
        // Add the basis elements `phi_8(2^j)` one at a time.
        for j in 0..self.k_skip {
            let a = PHI8_TABLE[1 << j];
            let at_a = linearized(&c, a);
            // `V(X)^2` shifts every coefficient up a power; `V(a) V(X)` scales them in place.
            for k in (0..=j + 1).rev() {
                let squared = if k == 0 { F192::ZERO } else { c[k - 1].square() };
                c[k] = squared + at_a * c[k];
            }
        }
        c
    }

    /// `V_S(z)`: `k_skip` squarings and as many products by constants of `K`.
    pub fn vanishing<A: Arith>(self, a: &mut A, z: A::E) -> A::E {
        let c = self.vanishing_coefficients();
        // `z^(2^j)` for every `j`, by squaring.
        let mut powers = vec![z];
        for j in 0..self.k_skip {
            powers.push(a.square(powers[j]));
        }
        debug_assert_eq!(c[self.k_skip], F192::ONE, "the vanishing polynomial is monic");
        (c[..self.k_skip].iter().zip(&powers)).fold(powers[self.k_skip], |acc, (&cj, &p)| a.mul_const_add(p, cj, acc))
    }

    /// `1 / (z + s_i)` over `S`, which the Lagrange sum over `S` takes.
    pub(crate) fn inverses<A: Arith>(self, a: &mut A, z: A::E) -> Vec<A::E> {
        inverses_at(a, z, &PHI8_TABLE[..self.size()])
    }

    /// The first round's message, known on `Lambda` and zero on `S`, interpolated at `z` over the window `S + Lambda`.
    ///
    /// Its value, `l` the domain's size:
    ///
    /// ```text
    ///     D_2l * V_S(z) * V_Lambda(z) * sum_i values_i / (z + lambda_i)        V_Lambda(z) = V_S(z) + V_S(phi_8(l))
    /// ```
    pub(crate) fn first_round_at<A: Arith>(self, a: &mut A, z: A::E, vanishing: A::E, values: &[A::E]) -> A::E {
        let size = self.size();
        // The coset's vanishing polynomial is the domain's shifted by a constant, `V_S` being linear.
        let lambda = &PHI8_TABLE[size..2 * size];
        let offset = linearized(&self.vanishing_coefficients(), lambda[0]);
        let on_lambda = a.add_const(vanishing, offset);
        let both = a.mul(vanishing, on_lambda);
        let scaled = a.mul_const(both, window_denominator(2 * size));
        let inverses = inverses_at(a, z, lambda);
        lagrange_sum(a, scaled, &inverses, values)
    }

    /// `D_l * V_S(z)`, `l` the domain's size: the scale of the Lagrange sum over `S`.
    pub(crate) fn lagrange_scale<A: Arith>(self, a: &mut A, vanishing: A::E) -> A::E {
        a.mul_const(vanishing, window_denominator(self.size()))
    }

    /// `sum_i L_i(z) values_i` over `S`, `L_i` its Lagrange basis: `D_l * V_S(z) * sum_i values_i / (z + s_i)`.
    pub fn lagrange_at<A: Arith>(self, a: &mut A, z: A::E, vanishing: A::E, values: &[A::E]) -> A::E {
        let scaled = self.lagrange_scale(a, vanishing);
        let inverses = self.inverses(a, z);
        lagrange_sum(a, scaled, &inverses, values)
    }

    /// The Lagrange basis of `S` at `z`, the prover's form: `L_i(z) = D_l * prod_{k != i} (z + s_k)`.
    pub(crate) fn lagrange_weights(self, z: F192) -> Vec<F192> {
        window_lagrange_weights(self.k_skip, z)
    }

    /// The eq table of a skip point's inner half: the Lagrange basis at `z_skip` on the low index bits.
    ///
    /// ```text
    ///     out[i_skip + i_rest 2^k_skip] = L_(i_skip)(z_skip) * eq(x_inner_rest, i_rest)
    /// ```
    pub fn inner_eq_table(self, z_skip: F192, x_inner_rest: &[F192]) -> Vec<F192> {
        outer_product(&eq_table(x_inner_rest), &self.lagrange_weights(z_skip))
    }
}

/// A linearized polynomial `sum_j c_j x^(2^j)` at `x`.
fn linearized(c: &[F192], x: F192) -> F192 {
    let (mut power, mut acc) = (x, F192::ZERO);
    for &cj in c {
        acc += cj * power;
        power = power.square();
    }
    acc
}

/// `1 / (z + node)` for each node.
fn inverses_at<A: Arith>(a: &mut A, z: A::E, nodes: &[F192]) -> Vec<A::E> {
    (nodes.iter())
        .map(|&node| {
            let difference = a.add_const(z, node);
            a.inv(difference)
        })
        .collect()
}

/// `scale * sum_i values_i * inverses_i`: a Lagrange sum, given its nodes' inverses at the point.
pub(crate) fn lagrange_sum<A: Arith>(a: &mut A, scale: A::E, inverses: &[A::E], values: &[A::E]) -> A::E {
    assert_eq!(inverses.len(), values.len(), "a value per node");
    let zero = a.zero();
    let sum = (inverses.iter().zip(values)).fold(zero, |acc, (&h, &value)| a.mul_add(value, h, acc));
    a.mul(scale, sum)
}

/// The Lagrange basis of the first `2^log_size` nodes of the phi_8 table at `z`.
///
/// Prefix and suffix products of the differences give every weight.
///
/// No inverse is taken, so the weights are exact at a node too.
fn window_lagrange_weights(log_size: usize, z: F192) -> Vec<F192> {
    let n = 1 << log_size;
    let nodes = &PHI8_TABLE[..n];
    // Prefix products: weight `i` holds `prod_{k < i} (z + s_k)`.
    let mut weights = vec![window_denominator(n); n];
    for i in 1..n {
        weights[i] = weights[i - 1] * (z + nodes[i - 1]);
    }
    // Suffix products: weight `i` takes `prod_{k > i} (z + s_k)`.
    let mut suffix = z + nodes[n - 1];
    for i in (1..n - 1).rev() {
        weights[i] *= suffix;
        suffix *= z + nodes[i];
    }
    if n > 1 {
        weights[0] *= suffix;
    }
    weights
}

/// `D_l = 1 / prod_{k != 0} phi_8(k)`: the barycentric weight of every node of an aligned window of `l` nodes.
///
/// One value serves the whole window:
///
/// ```text
///     prod_{k != i} (s_i + s_k) = prod_{k != i} phi_8(i ^ k) = prod_{j != 0} phi_8(j)
/// ```
///
/// - `phi_8` is GF(2)-linear on its index, so `s_i + s_k = phi_8(i ^ k)` and a coset's offset cancels.
/// - `k -> i ^ k` permutes the window's nonzero indices.
fn window_denominator(size: usize) -> F192 {
    debug_assert!(size.is_power_of_two() && size <= PHI8_TABLE.len());
    DENOMINATORS[size.trailing_zeros() as usize]
}

/// The barycentric weight of every window size, at compile time.
///
/// The nodes lie in `K`, so the product and its inverse stay there.
///
/// The inverse is Fermat's: `a^(2^64 - 2)`, by squarings.
const DENOMINATORS: [F192; 9] = {
    const fn mul(a: u64, b: u64) -> u64 {
        reduce(clmul(a, b))
    }
    let mut out = [F192::ZERO; 9];
    let mut log = 0;
    while log < out.len() {
        let mut product = 1;
        let mut k = 1;
        while k < 1 << log {
            product = mul(product, PHI8_TABLE[k].c0);
            k += 1;
        }
        let (mut inverse, mut bit) = (1, 1);
        while bit < 64 {
            product = mul(product, product);
            inverse = mul(inverse, product);
            bit += 1;
        }
        out[log] = F192::new(inverse, 0, 0);
        log += 1;
    }
    out
};

#[cfg(test)]
mod tests {
    use super::*;
    use fiat_shamir::arith::Native;
    use primitives::test_util::Rng;

    /// `1 / prod_{k != i} (s_i + s_k)` over a window's nodes, by its definition.
    fn per_node_denominator(nodes: &[F192], i: usize) -> F192 {
        let others = nodes.iter().enumerate().filter(|&(k, _)| k != i);
        others.fold(F192::ONE, |acc, (_, &node)| acc * (nodes[i] + node)).inv()
    }

    #[test]
    fn every_aligned_window_shares_one_denominator() {
        // Invariant: every node of every aligned window of the phi_8 table has the same barycentric denominator.
        //
        // It holds only while the table is the image of a basis, which this pins.
        for log_size in 1..=8 {
            let size = 1usize << log_size;
            for base in (0..PHI8_TABLE.len()).step_by(size) {
                let nodes = &PHI8_TABLE[base..base + size];
                for i in 0..size {
                    assert_eq!(
                        per_node_denominator(nodes, i),
                        window_denominator(size),
                        "size {size}, base {base}, node {i}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_lagrange_weights_are_the_definition() {
        // Invariant: `L_i(z) = prod_{k != i} (z + s_k) / (s_i + s_k)`, at random points and at every node.
        let mut rng = Rng::new(0xBA7C_E417);
        for log_size in 0..=8 {
            let nodes = &PHI8_TABLE[..1 << log_size];
            let points = rng.ext_vec(4).into_iter().chain(nodes.iter().copied());
            for z in points {
                let want: Vec<F192> = (0..nodes.len())
                    .map(|i| {
                        let others = nodes.iter().enumerate().filter(|&(k, _)| k != i);
                        others.fold(per_node_denominator(nodes, i), |acc, (_, &node)| acc * (z + node))
                    })
                    .collect();
                assert_eq!(window_lagrange_weights(log_size, z), want, "log_size {log_size}");
            }
        }
    }

    #[test]
    fn the_first_round_is_the_whole_windows_interpolant() {
        // Invariant: the first round, known on Lambda and zero on S, is the whole window's interpolant.
        //
        // Fixture state: every domain size, random values on Lambda, four random points each.
        let mut rng = Rng::new(0x0C0B_14ED);
        for k_skip in 0..8 {
            let domain = SkipDomain::new(k_skip);
            let values = rng.ext_vec(domain.size());
            for z in rng.ext_vec(4) {
                // The window's Lagrange weights at `z`, zero on S, so only Lambda's half counts.
                let window = window_lagrange_weights(k_skip + 1, z)[domain.size()..]
                    .iter()
                    .zip(&values)
                    .fold(F192::ZERO, |acc, (&w, &v)| acc + w * v);
                let vanishing = domain.vanishing(&mut Native, z);
                assert_eq!(
                    domain.first_round_at(&mut Native, z, vanishing, &values),
                    window,
                    "k_skip {k_skip}"
                );
            }
        }
    }

    #[test]
    fn the_lagrange_sum_is_the_skip_domains() {
        // Invariant: the vanishing polynomial and the Lagrange sum over S are the domain's, by their definitions.
        //
        // Fixture state: every domain size, four random points each.
        let mut rng = Rng::new(0x5_1EB);
        for k_skip in 0..8 {
            let domain = SkipDomain::new(k_skip);
            let values = rng.ext_vec(domain.size());
            for z in rng.ext_vec(4) {
                // `V_S(z)` as the product over the nodes.
                let vanishing = (PHI8_TABLE[..domain.size()].iter()).fold(F192::ONE, |acc, &s| acc * (z + s));
                assert_eq!(domain.vanishing(&mut Native, z), vanishing, "k_skip {k_skip}");
                let lagrange =
                    (domain.lagrange_weights(z).iter().zip(&values)).fold(F192::ZERO, |acc, (&w, &v)| acc + w * v);
                assert_eq!(
                    domain.lagrange_at(&mut Native, z, vanishing, &values),
                    lagrange,
                    "k_skip {k_skip}"
                );
            }
        }
    }
}
