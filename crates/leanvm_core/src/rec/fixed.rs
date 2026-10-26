//! The columns of a circuit's bus that its wiring alone fixes.
//!
//! - Each slot's `next` column holds the key of the next slot of its wire class, its own key on a padding row.
//! - The public table's four constant columns hold each constant row's limbs, zero on the statement's rows.
//!
//! Two circuits of the same heights differ exactly where these columns do, so the columns name the circuit.
//!
//! A circuit's fixed columns stack into its fixed polynomial, and the circuits' stacks into the nodes' `W_node`.

use super::bus::SlotKey;
use super::circuit::{Circuit, Limbs, PubSource};
use super::table::{PerRecTable, Table};
use crate::bus::PublicColumn;
use primitives::field::F64;
use std::sync::Arc;

/// How many slots all tables have together.
const N_SLOTS: usize = Table::Pub.first_slot() + Table::Pub.n_slots();

/// One fixed column of a circuit's bus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FixedColumn {
    /// The `next` column of a slot, by its index among all tables' slots.
    Next(usize),
    /// Limb `j` of the public table's constants.
    Constant(usize),
}

/// A circuit's fixed columns, each at its table's height, in stacking order.
///
/// Every column is its own allocation, which a bus block shares.
#[derive(Clone, Debug)]
pub(crate) struct FixedColumns {
    /// The columns, in stacking order.
    columns: Vec<Arc<Vec<F64>>>,
}

impl FixedColumn {
    /// How many fixed columns a circuit has.
    pub(crate) const COUNT: usize = N_SLOTS + 4;

    /// The column at an index of the stacking order: every slot's `next`, then the four constant limbs.
    pub(crate) const fn at(index: usize) -> Self {
        if index < N_SLOTS {
            Self::Next(index)
        } else {
            Self::Constant(index - N_SLOTS)
        }
    }

    /// Its index in the stacking order.
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Next(slot) => slot,
            Self::Constant(j) => N_SLOTS + j,
        }
    }

    /// The table whose height the column has.
    pub(crate) fn table(self) -> Table {
        match self {
            Self::Next(slot) => (Table::ALL.into_iter().rev())
                .find(|t| t.first_slot() <= slot)
                .expect("slot 0 is the first table's"),
            Self::Constant(_) => Table::Pub,
        }
    }
}

impl FixedColumns {
    /// Markers only: compact verifiers never evaluate these absent columns locally.
    pub(crate) fn absent() -> Self {
        // Bus evaluation caches by Arc identity: distinct columns need distinct markers.
        Self {
            columns: (0..FixedColumn::COUNT).map(|_| Arc::new(Vec::new())).collect(),
        }
    }

    /// The fixed columns of a circuit at its heights.
    ///
    /// The slots of a wire class, in table, row and slot order, form one cycle: each slot's `next` is the following one's key.
    pub(crate) fn new(circuit: &Circuit) -> Self {
        let taus = &circuit.heights();
        let mut next: Vec<Vec<F64>> = (Table::ALL.into_iter())
            .flat_map(|t| {
                let height = 1 << taus[t];
                (0..t.n_slots()).map(move |s| (0..height).map(|z| SlotKey::new(t, s, z).to_f64()).collect())
            })
            .collect();
        let mut link = |from: SlotKey, to: SlotKey| next[from.global_slot()][from.row()] = to.to_f64();

        // Each class's first and last slot so far: every slot links the last to itself.
        let mut ends: Vec<Option<(SlotKey, SlotKey)>> = vec![None; circuit.n_classes()];
        for t in Table::ALL {
            let n = t.n_slots();
            for (i, &class) in circuit.classes.of(t).iter().enumerate() {
                let key = SlotKey::new(t, i % n, i / n);
                match &mut ends[class as usize] {
                    Some((_, last)) => {
                        link(*last, key);
                        *last = key;
                    }
                    end @ None => *end = Some((key, key)),
                }
            }
        }
        // The last slot closes the cycle back to the first.
        for (first, last) in ends.into_iter().flatten() {
            link(last, first);
        }

        let mut constants: [Vec<F64>; 4] = std::array::from_fn(|_| vec![F64::ZERO; 1 << taus[Table::Pub]]);
        for (z, source) in circuit.pubs.iter().enumerate() {
            if let PubSource::Const(v) = *source {
                for (column, &v) in constants.iter_mut().zip(&v) {
                    column[z] = F64(v);
                }
            }
        }
        Self {
            columns: next.into_iter().chain(constants).map(Arc::new).collect(),
        }
    }

    /// Zero columns at the given heights: what a circuit built from shapes alone reads, whose rows never depend on them.
    pub(crate) fn zeros(taus: &PerRecTable<usize>) -> Self {
        let columns = (0..FixedColumn::COUNT)
            .map(|c| Arc::new(vec![F64::ZERO; 1 << taus[FixedColumn::at(c).table()]]))
            .collect();
        Self { columns }
    }

    /// A column.
    pub(crate) fn get(&self, column: FixedColumn) -> &Arc<Vec<F64>> {
        &self.columns[column.index()]
    }

    /// A column as a bus coordinate reads it, naming which fixed column it is.
    pub(crate) fn public(&self, column: FixedColumn) -> PublicColumn {
        PublicColumn::fixed(Arc::clone(self.get(column)), column)
    }

    /// The public table's four value columns: the constants, with the statement's words on their rows, which come first.
    pub(crate) fn public_values(&self, statement: &[Limbs]) -> [PublicColumn; 4] {
        std::array::from_fn(|j| {
            let mut column = self.get(FixedColumn::Constant(j)).to_vec();
            for (cell, word) in column.iter_mut().zip(statement) {
                *cell = F64(word[j]);
            }
            PublicColumn::new(Arc::new(column))
        })
    }
}

/// Where each fixed column sits in one circuit's stack: the circuit's fixed polynomial over `kappa_fix` variables.
///
/// - Columns are stacked largest first, each at an offset that is a multiple of its length.
/// - The circuits of a tier share their heights, so their stacks share this layout.
/// - The tier's polynomial stacks its circuits' stacks by their kind's index, whose bits select the circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FixedLayout {
    /// Each column's variables.
    taus: Vec<usize>,
    /// Each column's offset in the stack.
    offsets: Vec<usize>,
    /// The stack's variables, `kappa_fix`.
    kappa: usize,
}

impl FixedLayout {
    /// The stack of a circuit's fixed columns at the given table heights.
    pub(crate) fn new(taus: &PerRecTable<usize>) -> Self {
        let taus: Vec<usize> = (0..FixedColumn::COUNT)
            .map(|c| taus[FixedColumn::at(c).table()])
            .collect();
        let kappas: Vec<Option<usize>> = taus.iter().copied().map(Some).collect();
        let (offsets, placed) = crate::stacking::stack_offsets(&kappas);
        Self {
            taus,
            offsets,
            kappa: crate::log2_ceil_usize(placed.max(1)),
        }
    }

    /// The stack's variables.
    pub(crate) const fn kappa(&self) -> usize {
        self.kappa
    }

    /// A column's variables.
    pub(crate) fn tau(&self, column: FixedColumn) -> usize {
        self.taus[column.index()]
    }

    /// A column's offset in the stack, as the bits of its block's index: `offset >> tau`, over `kappa_fix - tau` bits.
    pub(crate) fn block(&self, column: FixedColumn) -> usize {
        self.offsets[column.index()] >> self.tau(column)
    }

    /// The stack of a circuit's fixed columns, zero between them.
    fn stack(&self, columns: &FixedColumns) -> Vec<F64> {
        let mut out = vec![F64::ZERO; 1 << self.kappa];
        for (c, &offset) in self.offsets.iter().enumerate() {
            let column = columns.get(FixedColumn::at(c));
            out[offset..offset + column.len()].copy_from_slice(column);
        }
        out
    }

    /// The fixed polynomial of the circuits' columns, in order, zero for the indices past the last.
    pub(crate) fn polynomial(&self, columns: &[&FixedColumns]) -> Vec<F64> {
        let mut out: Vec<F64> = columns.iter().flat_map(|c| self.stack(c)).collect();
        out.resize(out.len().next_power_of_two(), F64::ZERO);
        out
    }
}
