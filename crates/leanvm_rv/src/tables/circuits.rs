//! The tables' circuits, each proven by flock over a packed witness of its own.
//!
//! A table has up to two circuits:
//!
//! - its class's function, which the extension-field table lacks;
//! - its clock, which orders its memory accesses.
//!
//! A packed witness is one more committed column of the stacked witness.
//!
//! - Instance `j` of its batch is row `j` of its table.
//! - The stacked opening discharges flock's claims, through one ring-switched region per circuit.
//!
//! A bus word and a packed word are both 64 bits.
//!
//! So the words a row puts on the bus are its instance's port words.
//!
//! The table's columns for them are virtual: their claims are routed to those words.

use super::{Fill, N_CLASS_CIRCUITS, N_TABLES, PerTable, TableId};
use crate::cpu::{Payloads, RowRef, Trace};
use crate::rv::RiscvProgram;
use flock::circuit::Circuit;
use flock::reduction::{Instance, Shape, min_n_blocks_log};
use flock::{BatchRows, Tables};
use primitives::field::F64;
use std::sync::OnceLock;

pub use flock::zerocheck::MIN_CUBE_LOG;

/// The most input ports a circuit with a word-level witness has.
const MAX_INPUT_WORDS: usize = {
    let mut max = 0;
    let mut t = 0;
    while t < N_TABLES {
        let spec = TableId::ALL[t].spec();
        let clock = 1 + spec.n_accesses() + spec.clock.inputs.len();
        if clock > max {
            max = clock;
        }
        if let Some(class) = spec.class_circuit()
            && class.inputs.len() > max
        {
            max = class.inputs.len();
        }
        t += 1;
    }
    max
};

/// One argument proving part of a table's row relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Relation {
    /// A flock circuit over ports of its own packed witness: proven by the batched reduction right after the
    /// commitment, which leaves a ring-switched claim on the witness and a claim on the circuit's matrices.
    Circuit(CircuitId),
    /// Degree-2 forms over the table's columns that vanish on every row, folded into the table sumcheck at powers of
    /// its challenge past the bus forms'.
    Identities,
}

/// How many circuits the tables have.
///
/// Protocol order is every class circuit in table order, then every clock circuit.
pub const N_CIRCUITS: usize = N_CLASS_CIRCUITS + N_TABLES;

/// Which of a table's two circuits: its class's function, which the extension-field table lacks, or its clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Part {
    /// Instruction semantics.
    Class,
    /// Memory access ordering.
    Clock,
}

/// One of the tables' circuits: a table's class circuit, or its clock circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CircuitId {
    table: TableId,
    part: Part,
}

impl CircuitId {
    /// Every circuit, in protocol order.
    pub const ALL: [Self; N_CIRCUITS] = {
        let mut all = [Self::clock(TableId::ALU); N_CIRCUITS];
        let mut t = 0;
        while t < N_TABLES {
            let table = TableId::ALL[t];
            if let Some(class) = Self::class(table) {
                all[class.index()] = class;
            }
            all[Self::clock(table).index()] = Self::clock(table);
            t += 1;
        }
        all
    };

    /// The most variables any circuit has per instance.
    pub const MAX_K_LOG: usize = {
        let mut max = 0;
        let mut f = 0;
        while f < N_CIRCUITS {
            if Self::ALL[f].k_log() > max {
                max = Self::ALL[f].k_log();
            }
            f += 1;
        }
        max
    };

    /// The class circuit of `table`, if its class has one.
    pub const fn class(table: TableId) -> Option<Self> {
        if table.spec().has_circuit() {
            Some(Self {
                table,
                part: Part::Class,
            })
        } else {
            None
        }
    }

    /// The clock circuit of `table`.
    pub const fn clock(table: TableId) -> Self {
        Self {
            table,
            part: Part::Clock,
        }
    }

    /// The table whose rows are the witness's instances.
    pub const fn table(self) -> TableId {
        self.table
    }

    /// Which of the table's circuits it is.
    pub const fn part(self) -> Part {
        self.part
    }

    /// Its position in protocol order: the class circuits in table order, then the clock circuits in table order.
    pub const fn index(self) -> usize {
        match self.part {
            Part::Class => {
                let mut before = 0;
                let mut t = 0;
                while t < self.table.index() {
                    if TableId::ALL[t].spec().has_circuit() {
                        before += 1;
                    }
                    t += 1;
                }
                before
            }
            Part::Clock => N_CLASS_CIRCUITS + self.table.index(),
        }
    }

    /// `log2` of the bits one instance occupies.
    pub const fn k_log(self) -> usize {
        let spec = self.table.spec();
        match (self.part, spec.class_circuit()) {
            (Part::Class, Some(circuit)) => circuit.k_log,
            (Part::Class, None) => unreachable!(),
            (Part::Clock, _) => spec.clock.k_log,
        }
    }

    /// `log2` of an instance's packed words: the stride between consecutive instances' same-port words.
    pub const fn stride_log(self) -> usize {
        self.k_log() - F64::DEGREE.ilog2() as usize
    }

    /// What the verifier's replay of the witness's reduction reads of its circuit short of its matrices.
    ///
    /// - The instance's size.
    /// - The constant wire's column, the first after the port words.
    ///
    /// The table's spec fixes both, so the replay builds no circuit, and building the circuit checks them.
    pub const fn shape(self) -> Shape {
        let spec = self.table.spec();
        let n_ports = match (self.part, spec.class_circuit()) {
            (Part::Class, Some(circuit)) => circuit.inputs.len() + circuit.outputs.len(),
            (Part::Class, None) => unreachable!(),
            // The clock, each access's previous timestamp and the clock's own inputs, then the step and its own outputs.
            (Part::Clock, _) => spec.n_accesses() + 2 + spec.clock.inputs.len() + spec.clock.outputs.len(),
        };
        Shape {
            k_log: self.k_log(),
            const_pin_col: 64 * n_ports,
        }
    }

    /// The witness's gate list, built once.
    pub fn circuit(self) -> &'static Circuit {
        static CIRCUITS: [OnceLock<Circuit>; N_CIRCUITS] = [const { OnceLock::new() }; N_CIRCUITS];
        CIRCUITS[self.index()].get_or_init(|| {
            let (spec, part) = (self.table.spec(), self.part);
            let (circuit, n_inputs) = match spec.class_circuit() {
                Some(circuit) if part == Part::Class => ((circuit.build)(), circuit.inputs.len()),
                _ => (spec.clock_circuit(), 1 + spec.n_accesses() + spec.clock.inputs.len()),
            };
            let shape = self.shape();
            assert_eq!(
                circuit.k_log(),
                shape.k_log,
                "{}'s {part:?} block size moved",
                spec.name
            );
            assert_eq!(
                circuit.const_pos(),
                shape.const_pin_col,
                "{}'s {part:?} constant wire moved",
                spec.name
            );
            assert_eq!(
                circuit.n_input_words(),
                n_inputs,
                "{}'s {part:?} input ports moved",
                spec.name
            );
            circuit
        })
    }
}

/// `log2` of the batch proving a table's rows on one circuit, given `log2` of its bits per instance.
///
/// - At least flock's floor of eight instances.
/// - At least what the zerocheck's cube of `2^13` bits needs.
pub const fn batch_log(k_log: usize, n_rows: usize) -> usize {
    let natural = min_n_blocks_log(if n_rows > 1 { n_rows } else { 1 });
    let floor = MIN_CUBE_LOG.saturating_sub(k_log);
    if natural > floor { natural } else { floor }
}

impl CircuitId {
    /// Each packed witness's shape and `log2` of its batch, its table's height `2^taus`, in protocol order.
    ///
    /// The verifier's replay of the reductions reads these alone, and builds no circuit.
    pub fn batches(taus: &PerTable<usize>) -> [(Shape, usize); N_CIRCUITS] {
        Self::ALL.map(|f| (f.shape(), taus[f.table()]))
    }

    /// The witness's batch, one instance per row of its table, its `z` straight into `window`, its committed column.
    ///
    /// The reduction keeps the rest, so it needs no second witness pass.
    pub(crate) fn tables(self, trace: &Trace, p: &RiscvProgram, window: &mut [F64]) -> Tables {
        let table = trace.table(self.table);
        match table.payloads {
            Payloads::None => self.tables_of(table.rows, |r| RowRef::plain(r), p, window),
            // Why: the witness walk takes a slice, so a payload is paired with its row first.
            _ => {
                let refs: Vec<RowRef> = (0..table.rows.len()).map(|i| table.row(i)).collect();
                self.tables_of(&refs, |r| *r, p, window)
            }
        }
    }

    /// The batch for the reduction: `column` is the witness's committed column, its `z`, and `tables` the rest.
    ///
    /// A table's padding rows are alike, so its batch ends in an identical tail the zerocheck sums once.
    pub(crate) fn instance<'a>(self, column: &'a [F64], n_blocks_log: usize, tables: &'a Tables) -> Instance<'a> {
        Instance::new(self.circuit().block(), n_blocks_log, F64::as_bits(column), tables)
    }

    /// The witness's batch from its table's rows, each seen through `view`.
    fn tables_of<S: Sync>(
        self,
        rows: &[S],
        view: impl for<'r> Fn(&'r S) -> RowRef<'r> + Sync,
        p: &RiscvProgram,
        window: &mut [F64],
    ) -> Tables {
        let (part, spec) = (self.part, self.table.spec());
        let n_blocks_log = spec.n_blocks_log(rows.len());
        assert_eq!(
            rows.len(),
            1 << n_blocks_log,
            "a table's rows fill its batch (cpu::filler)"
        );
        let circuit = self.circuit();
        let ports = self.table.class_table().ports(part);
        let n_inputs = circuit.n_input_words();
        let slots = spec.slots();
        // The row's input words, one per input port.
        let input_words = |row: &S, words: &mut [u64]| {
            let row = view(row);
            let at = p.fetch(row.row.index as usize);
            for (word, &port) in words.iter_mut().zip(ports) {
                *word = port.value(row, at, &slots);
            }
        };
        // What the circuit computed is what the interpreter did, or the bus would carry one and flock prove the other.
        let check = |_: usize, row: &S, z: &[u64]| {
            let row = view(row);
            let at = p.fetch(row.row.index as usize);
            for (k, &port) in ports.iter().enumerate().skip(n_inputs) {
                let expected = port.value(row, at, &slots);
                assert_eq!(
                    z[k], expected,
                    "{}'s {part:?} circuit disagrees with the interpreter on {port:?}",
                    spec.name
                );
            }
        };
        let z = F64::as_bits_mut(window);
        let instances = BatchRows::new(rows, &rows[0], n_blocks_log);
        let fill = match (part, spec.class_circuit()) {
            (Part::Class, Some(class)) => class.fill,
            _ => Fill::Walk,
        };
        // A clock circuit, and a class with a word-level witness, skip the walk of the gate list;
        // the others walk it 64 instances at a time.
        match (part, fill) {
            // A clock circuit's inputs are the clock and the previous timestamps, read straight off the row, then the
            // circuit's own, which it takes through their ports.
            (Part::Clock, _) => circuit.witness_by_instance(
                z,
                instances,
                |row, z, az, bz| {
                    let mut words = [0u64; MAX_INPUT_WORDS];
                    let words = &mut words[..n_inputs];
                    if spec.clock.inputs.is_empty() {
                        let row = view(row);
                        words[0] = row.row.ts;
                        words[1..].copy_from_slice(&row.prev()[..slots.len()]);
                    } else {
                        input_words(row, words);
                    }
                    (spec.clock.witness)(&slots, words, z, az, bz);
                },
                check,
            ),
            (Part::Class, Fill::Walk) => circuit.witness_by_walk(z, instances, input_words, check),
            (Part::Class, Fill::Instance(instance)) => circuit.witness_by_instance(
                z,
                instances,
                |row, z, az, bz| {
                    let mut words = [0u64; MAX_INPUT_WORDS];
                    let words = &mut words[..n_inputs];
                    input_words(row, words);
                    instance(words, z, az, bz);
                },
                check,
            ),
            // Eight rows share a native arithmetic call.
            (Part::Class, Fill::Batch8(batch)) => circuit.witness_by_batch8(
                z,
                instances,
                |rows, z, az, bz| {
                    let mut words = [[0u64; MAX_INPUT_WORDS]; 8];
                    for (row, words) in rows.into_iter().zip(&mut words) {
                        input_words(row, &mut words[..n_inputs]);
                    }
                    let inputs = std::array::from_fn(|i| &words[i][..n_inputs]);
                    batch(&inputs, z, az, bz);
                },
                check,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::ClassTable;

    #[test]
    fn the_circuits_are_the_tables_circuit_relations_in_protocol_order() {
        // Invariant: the flock batch, the ring-switched witnesses and the matrix claims follow `CircuitId::ALL`, which
        // lists every table's circuit relations, the class circuits in table order and then the clock circuits, each at
        // its own index.
        let mut relations: Vec<CircuitId> = (ClassTable::all().values())
            .flat_map(ClassTable::relations)
            .filter_map(|r| match r {
                Relation::Circuit(f) => Some(f),
                Relation::Identities => None,
            })
            .collect();
        relations.sort_by_key(|f| (f.part() == Part::Clock, f.table().index()));
        assert_eq!(relations, CircuitId::ALL);
        for (i, f) in CircuitId::ALL.into_iter().enumerate() {
            assert_eq!(f.index(), i, "{f:?}");
        }
    }
}
