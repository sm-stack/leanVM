//! Native root verification with deferred, seal-authenticated fixed-column evaluations.
//!
//! This is the native counterpart of `Rows::hinting`. Accepting its result alone is
//! UNSOUND: every returned evaluation must be opened against the authenticated tier
//! commitment, at the column block and root circuit's local index. The seal binds
//! the entire root proof and all hinted values before its opening challenges.
use super::*;
use crate::bus::PublicColumn;
use crate::rec::fixed::FixedColumn;
use fiat_shamir::TranscriptError;
use fiat_shamir::arith::Arith;
use pcs::merkle::Hash;
use primitives::multilinear::mle_eval_par;

pub(crate) struct FixedEvaluation {
    pub(crate) column: FixedColumn,
    pub(crate) point: Vec<F192>,
    pub(crate) value: F192,
}
struct RootVerifier<'a, 'b> {
    vs: VerifierState<'a>,
    statement: &'b [Limbs],
    supplied: Option<&'b [F192]>,
    evaluations: Vec<FixedEvaluation>,
    missing: bool,
}
impl PublicColumns for RootVerifier<'_, '_> {
    fn column_mle(&mut self, column: &PublicColumn, point: &[F192]) -> F192 {
        let fixed = column.fixed.expect("root bus columns are tagged");
        let value = self.supplied.map_or_else(
            || mle_eval_par(&column.values, point),
            |values| {
                *values.get(fixed.index()).unwrap_or_else(|| {
                    self.missing = true;
                    &F192::ZERO
                })
            },
        );
        self.evaluations.push(FixedEvaluation {
            column: fixed,
            point: point.to_vec(),
            value,
        });
        match fixed {
            FixedColumn::Next(_) => value,
            FixedColumn::Constant(limb) => {
                // Constants are zero on statement rows; add precisely the public statement's share.
                let statement = self.statement.iter().enumerate().fold(F192::ZERO, |acc, (row, word)| {
                    let weight = point.iter().enumerate().fold(F192::ONE, |w, (bit, &p)| {
                        w * if row >> bit & 1 == 1 { p } else { p + F192::ONE }
                    });
                    acc + weight.mul_base(F64(word[limb]))
                });
                value + statement
            }
        }
    }
}
impl CircuitKey {
    pub(crate) fn verify_fixed(
        &self,
        statement: &[Limbs],
        session: &SessionId,
        rate: Rate,
        proof: &ProofTranscript,
        values: Option<&[F192]>,
    ) -> Result<Vec<FixedEvaluation>, RecError> {
        if statement.len() != self.circuit.statement_len {
            return Err(RecError::StatementLength {
                expected: self.circuit.statement_len,
                got: statement.len(),
            });
        }
        let mut v = RootVerifier {
            vs: VerifierState::new(session, &LengthPrefixed(statement.as_flattened()), proof),
            statement,
            supplied: values,
            evaluations: Vec::new(),
            missing: false,
        };
        let constants = std::array::from_fn(|j| self.fixed.public(FixedColumn::Constant(j)));
        let blocks = BusBlocks::new(&self.fixed, constants, &self.layout);
        let matrices = TableArgument::new(&self.layout, blocks).verify_core(&mut v, rate)?;
        matrices.check(hash::CIRCUIT.circuit()).map_err(FlockError::Lincheck)?;
        // Canonical wire order is column index, independent of the verifier's bus walk/cache.
        v.evaluations.sort_by_key(|e| e.column.index());
        if v.missing
            || v.evaluations.len() != FixedColumn::COUNT
            || v.evaluations.iter().enumerate().any(|(i, e)| e.column.index() != i)
            || values.is_some_and(|x| x.len() != FixedColumn::COUNT)
        {
            return Err(TranscriptError::Malformed {
                index: v.evaluations.len(),
            }
            .into());
        }
        Ok(v.evaluations)
    }
}
impl Arith for RootVerifier<'_, '_> {
    type E = F192;

    fn constant(&mut self, c: F192) -> F192 {
        self.vs.constant(c)
    }

    fn mul_add(&mut self, a: F192, b: F192, d: F192) -> F192 {
        self.vs.mul_add(a, b, d)
    }

    fn add(&mut self, a: F192, d: F192) -> F192 {
        self.vs.add(a, d)
    }

    fn mul_const_add(&mut self, a: F192, c: F192, d: F192) -> F192 {
        self.vs.mul_const_add(a, c, d)
    }

    fn inv(&mut self, a: F192) -> F192 {
        self.vs.inv(a)
    }

    fn frobenius2(&mut self, a: F192) -> F192 {
        self.vs.frobenius2(a)
    }

    fn public_mle(&mut self, values: &[F64], point: &[F192]) -> F192 {
        self.vs.public_mle(values, point)
    }
}

impl Verifier for RootVerifier<'_, '_> {
    fn prover_message(&mut self) -> Result<F192, TranscriptError> {
        Verifier::prover_message(&mut self.vs)
    }

    fn verifier_message(&mut self) -> F192 {
        Verifier::verifier_message(&mut self.vs)
    }

    fn check_pow(&mut self, bits: u32) -> Result<(), TranscriptError> {
        self.vs.check_pow(bits)
    }

    fn ensure_eq<Er>(&mut self, a: F192, b: F192, err: impl FnOnce() -> Er) -> Result<(), Er> {
        self.vs.ensure_eq(a, b, err)
    }

    fn check_eof(&mut self) -> Result<(), TranscriptError> {
        self.vs.check_eof()
    }

    fn set_hidden(&mut self, hidden: bool) {
        self.vs.set_hidden(hidden);
    }

    fn is_hidden(&self) -> bool {
        self.vs.is_hidden()
    }
}

impl OpeningVerifier for RootVerifier<'_, '_> {
    type Root = Hash;
    type K = F64;
    type Query = usize;
    fn next_root(&mut self) -> Result<Hash, TranscriptError> {
        self.vs.next_root()
    }
    fn sample_queries(&mut self, depth: usize, count: usize) -> Vec<usize> {
        self.vs.sample_queries(depth, count)
    }
    fn open_rows(
        &mut self,
        root: &Hash,
        depth: usize,
        queries: &[usize],
        row_words: usize,
        leaf_words: usize,
    ) -> Result<Vec<Vec<F64>>, TranscriptError> {
        self.vs.open_rows(root, depth, queries, row_words, leaf_words)
    }
    fn mul_k_add(&mut self, a: F192, k: F64, d: F192) -> F192 {
        self.vs.mul_k_add(a, k, d)
    }
    fn e_of_limbs(&mut self, limbs: [F64; 3]) -> F192 {
        self.vs.e_of_limbs(limbs)
    }
    fn query_point(&mut self, query: &usize) -> F192 {
        self.vs.query_point(query)
    }
}
