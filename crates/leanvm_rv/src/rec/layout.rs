//! What both sides derive from a circuit alone: each table's height and where every column sits in the stack.

use super::RecError;
use super::circuit::Circuit;
use super::table::{PerRecTable, Table};
use crate::bus::ColumnClaim;
use crate::commitment::StackClaim;
use crate::constraints::{Air, BitColumns, Claims};
use crate::stacking;
use crate::stacking::{Placement, Source, StackShape, Window};
use std::ops::Range;

/// Each table's height and every column's place in the stack.
///
/// The stack holds the hash table's packed witness, then every owned table's columns in table order.
/// The hash table's first columns are ports of that witness and take no place of their own.
#[derive(Clone, Debug)]
pub(crate) struct RecLayout {
    /// Each table's base-two logarithm of rows, the public table's included.
    pub(crate) taus: PerRecTable<usize>,
    pub(crate) placements: Vec<Placement>,
    pub(crate) shape: StackShape,
}

impl RecLayout {
    /// The global column of the hash table's packed witness.
    pub(crate) const HASH_WITNESS: usize = Self::witness_column(Table::Hash);

    /// How many tables have a flock circuit among their relations: each one's packed witness is a global column, in
    /// table order, before the owned tables' columns.
    const N_WITNESSES: usize = Self::witness_column(Table::Pub);

    /// The most rows a table holds, as a base-two logarithm: a slot's key keeps the row in its low 32 bits.
    pub(crate) const MAX_TAU: usize = 32;

    /// Each owned table's first global column and its number of columns, in table order.
    pub(crate) const TABLE_COLUMNS: [(usize, usize); Table::OWNED.len()] = {
        let mut spans = [(0, 0); Table::OWNED.len()];
        let mut next = Self::N_WITNESSES;
        let mut t = 0;
        while t < spans.len() {
            spans[t] = (next, Table::OWNED[t].n_cols());
            next += spans[t].1;
            t += 1;
        }
        spans
    };

    /// The layout of a circuit: each table at the least power of two holding its rows, and at least its floor.
    ///
    /// # Errors
    ///
    /// Returns an error if a table has more rows than its keys name, or the witness exceeds one commitment.
    pub(crate) fn new(circuit: &Circuit) -> Result<Self, RecError> {
        Self::from_taus(circuit.heights())
    }

    /// The layout of a circuit of the given heights.
    ///
    /// # Errors
    ///
    /// Returns an error if a table has more rows than its keys name, or the witness exceeds one commitment.
    pub(crate) fn from_taus(taus: PerRecTable<usize>) -> Result<Self, RecError> {
        if let Some((table, &tau)) = taus.iter().find(|&(_, &tau)| tau > Self::MAX_TAU) {
            return Err(RecError::TooManyRows { table, tau });
        }
        let (placements, shape) = stacking::placements_of(&Self::sources(&taus));
        if shape.mu > crate::commitment::MAX_MU {
            return Err(RecError::TooLong { mu: shape.mu });
        }
        Ok(Self {
            taus,
            placements,
            shape,
        })
    }

    /// Every global column's source: each circuit's packed witness, then each owned table's ports and committed
    /// columns.
    fn sources(taus: &PerRecTable<usize>) -> Vec<Source> {
        let witness = |table: Table| table.circuit().expect("a table with a circuit");
        let mut sources: Vec<Source> = (Self::circuit_tables())
            .map(|table| Source::Committed(taus[table] + witness(table).stride_log()))
            .collect();
        for table in Table::OWNED {
            debug_assert_eq!(sources.len(), Self::columns(table).start);
            sources.extend((0..table.n_cols()).map(|c| {
                if c < table.n_ports() {
                    Source::Port {
                        column: Self::witness_column(table),
                        port: c,
                        stride_log: witness(table).stride_log(),
                    }
                } else {
                    Source::Committed(taus[table])
                }
            }));
        }
        sources
    }

    /// The global column of a table's circuit's packed witness: how many tables before it have a circuit.
    const fn witness_column(table: Table) -> usize {
        let mut column = 0;
        let mut t = 0;
        while t < table as usize {
            if Table::ALL[t].circuit().is_some() {
                column += 1;
            }
            t += 1;
        }
        column
    }

    /// The tables with a flock circuit among their relations, in table order.
    fn circuit_tables() -> impl Iterator<Item = Table> {
        Table::ALL.into_iter().filter(|t| t.circuit().is_some())
    }

    /// Each circuit's flock batch, its shape and `log2` of its table's height, in table order.
    pub(crate) fn batches(&self) -> Vec<(flock::reduction::Shape, usize)> {
        (Self::circuit_tables())
            .map(|table| {
                (
                    table.circuit().expect("a table with a circuit").shape(),
                    self.tau(table),
                )
            })
            .collect()
    }

    /// An owned table's global columns.
    pub(crate) const fn columns(table: Table) -> Range<usize> {
        let (base, n) = Self::TABLE_COLUMNS[table as usize];
        base..base + n
    }

    /// A table's base-two logarithm of rows.
    pub(crate) fn tau(&self, table: Table) -> usize {
        self.taus[table]
    }

    /// The packed witness's window in the stack.
    pub(crate) fn hash_window(&self) -> Window {
        self.placements[Self::HASH_WITNESS]
            .window()
            .expect("the packed witness is committed")
    }

    /// The constraint batch's airs, one per owned table, each with its summand in table order.
    pub(crate) fn airs<S>(&self, summands: Vec<S>) -> Vec<Air<S>> {
        (Table::OWNED.into_iter().zip(summands))
            .map(|(table, summand)| Air {
                tau: self.tau(table),
                n_cols: table.n_cols(),
                n_public: 0,
                bits: BitColumns::default(),
                summand,
            })
            .collect()
    }

    /// Every column claim the opening discharges, the bus's then each owned table's, located in the stack.
    ///
    /// A port's claim is a strided evaluation of its packed witness.
    pub(crate) fn opening_claims<E: Copy>(&self, bus: Vec<ColumnClaim<E>>, tables: &[Claims<E>]) -> Vec<StackClaim<E>> {
        let mut claims = bus;
        for (&(base, _), table) in Self::TABLE_COLUMNS.iter().zip(tables) {
            claims.extend(table.evals.iter().enumerate().map(|(c, &value)| ColumnClaim {
                col: base + c,
                point: table.chi.clone(),
                value,
            }));
        }
        (claims.into_iter())
            .filter_map(|c| self.placements[c.col].claim(c.point, c.value))
            .collect()
    }
}
