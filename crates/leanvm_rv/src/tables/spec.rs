//! Instruction-class specifications in protocol table order.

use super::clock::Clock;
use super::{ClassTable, N_TABLES, TableId, Word};
use crate::bus::BusForm;
use crate::rv;
use crate::rv::{Alu, Class, Div, Ext, Hash, Ld, Load, Mul, Mulh, Sd, Shift, Store};
use flock::circuit::Circuit;

/// The register an access names: the entry's first source, its second source, or its destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Register {
    /// `rs1`, whose value is `v1`.
    Rs1,
    /// `rs2`, whose value is `v2`.
    Rs2,
    /// `rd`, the cell the entry writes.
    Rd,
}

/// What one group of a row's accesses touches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// A register read back as found: `v1`, `v2`, or the address the destination holds.
    Read(Register),
    /// The destination register receiving the row's result.
    WriteRd,
    /// One RAM cell at the address the circuit computes, read, or read and rewritten.
    Cell {
        /// Whether the row writes a new value over the cell.
        rewritten: bool,
    },
    /// RAM words `0..words` from the first source's value on, word `k` at `v1 ^ 8k`, those in `out..out + n_out`
    /// rewritten.
    Block {
        /// How many words.
        words: usize,
        /// The first word rewritten.
        out: usize,
        /// How many words are rewritten.
        n_out: usize,
    },
    /// The extension-field operands' limbs: each operand's three, then the destination's, which are rewritten.
    Limbs,
}

impl Access {
    /// How many accesses the group makes, each in a clock slot of its own.
    pub const fn len(self) -> usize {
        match self {
            Self::Read(_) | Self::WriteRd | Self::Cell { .. } => 1,
            Self::Block { words, .. } => words,
            Self::Limbs => Ext::LIMBS,
        }
    }
}

/// An access group and the clock slot of its first access; its others take the slots that follow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slotted {
    /// The group.
    pub access: Access,
    /// The clock slot of its first access.
    pub slot: u32,
}

impl Slotted {
    /// The register reads and writes, each at its slot of the clock.
    const RS1: Self = Self::at(Access::Read(Register::Rs1), Clock::REG_SLOTS[0]);
    const RS2: Self = Self::at(Access::Read(Register::Rs2), Clock::REG_SLOTS[1]);
    const RD: Self = Self::at(Access::WriteRd, Clock::REG_SLOTS[2]);
    const POINTER: Self = Self::at(Access::Read(Register::Rd), Clock::REG_SLOTS[2]);

    /// A load's or a store's cell.
    const fn cell(rewritten: bool) -> Self {
        Self::at(Access::Cell { rewritten }, Clock::RAM_SLOT)
    }

    const fn at(access: Access, slot: u32) -> Self {
        Self { access, slot }
    }
}

/// One instance's `z`, `A·z` and `B·z` from its input words, into zeroed buffers.
pub type InstanceWitness = fn(&[u64], &mut [u64], &mut [u64], &mut [u64]);

/// Eight instances' packed witness by native word arithmetic.
pub type BatchWitness = fn(&[&[u64]; 8], &mut [u64], &mut [u64], &mut [u64]);

/// How a class circuit's witness is generated.
#[derive(Clone, Copy, Debug)]
pub enum Fill {
    /// The generic walk of the gate list, 64 instances at a time.
    Walk,
    /// Word arithmetic one instance at a time, checked against the walk.
    Instance(InstanceWitness),
    /// Word arithmetic eight instances at a time, checked against the walk.
    Batch8(BatchWitness),
}

/// A class's flock circuit: its size, its ports, and how its witness is generated.
pub struct ClassCircuit {
    /// The circuit's gate list.
    pub build: fn() -> Circuit,

    /// Base-two logarithm of the circuit's bits per instance.
    pub k_log: usize,

    /// The words the circuit reads, in port order.
    pub inputs: &'static [Word],

    /// The words the circuit gives, in port order after the inputs.
    pub outputs: &'static [Word],

    /// How the witness is generated.
    pub fill: Fill,
}

/// How a table proves its class's function on every row.
pub enum ClassRelation {
    /// A flock circuit over ports of its own packed witness.
    Circuit(ClassCircuit),
    /// Degree-2 forms over the table's columns, in local column indices, that vanish on every row: the table
    /// sumcheck folds them in.
    Identities(fn(&ClassTable) -> Vec<BusForm>),
}

/// One instance of a clock circuit's witness by word arithmetic, from the row's slots and its input words (the clock,
/// each access's previous timestamp, then the circuit's own inputs), into zeroed buffers.
pub type ClockWitness = fn(&[u32], &[u64], &mut [u64], &mut [u64], &mut [u64]);

/// A table's clock circuit, which orders its memory accesses: its size, its own ports, and its gate list and witness.
pub struct ClockCircuit {
    /// Base-two logarithm of the circuit's bits per instance.
    pub k_log: usize,

    /// Words the circuit reads past the timestamps: what a class with no circuit checks of its operands.
    pub inputs: &'static [Word],

    /// Words the circuit gives past the step.
    pub outputs: &'static [Word],

    /// The gate list over the row's access slots.
    pub build: fn(&[u32]) -> Circuit,

    /// The witness by word arithmetic.
    pub witness: ClockWitness,
}

impl ClockCircuit {
    /// The clock circuit of a table whose accesses are all it orders.
    const fn plain(k_log: usize) -> Self {
        Self {
            k_log,
            inputs: &[],
            outputs: &[],
            build: Clock::circuit,
            witness: Clock::witness_of_words,
        }
    }
}

/// Register accesses, memory shape, and circuit ports of one instruction class.
pub struct ClassSpec {
    /// Instruction class executed by this table.
    pub class: Class,

    /// Table name used in diagnostics and reports.
    pub name: &'static str,

    /// Whether branches and jumps move the successor by the circuit's jump.
    pub control: bool,

    /// The row's accesses, in the order of their columns and bus tuples: the registers', then RAM's.
    pub accesses: &'static [Slotted],

    /// Whether a doubleword is moved unchanged through a shared column.
    pub copies: bool,

    /// How the table proves the class's function.
    pub relation: ClassRelation,

    /// The table's clock circuit.
    pub clock: ClockCircuit,
}

impl ClassSpec {
    /// Arithmetic, comparisons, logic, branches, and jumps.
    pub const ALU: Self = Self {
        class: Class::Alu,
        name: "ALU",
        control: true,
        accesses: &[Slotted::RS1, Slotted::RS2, Slotted::RD],
        copies: false,
        relation: ClassRelation::Circuit(ClassCircuit {
            build: <Alu as rv::circuits::ClassCircuit>::circuit,
            k_log: 10,
            inputs: &[Word::V1, Word::V2, Word::Imm, Word::Flags, Word::Dt, Word::Pc4],
            outputs: &[Word::Out, Word::Jump],
            fill: Fill::Instance(Alu::witness),
        }),
        clock: ClockCircuit::plain(9),
    };

    /// Byte, halfword, and word loads with extension to 64 bits.
    pub const LOAD: Self = Self {
        class: Class::Load,
        name: "LOAD",
        control: false,
        accesses: &[Slotted::RS1, Slotted::RD, Slotted::cell(false)],
        copies: false,
        relation: ClassRelation::Circuit(ClassCircuit {
            build: <Load as rv::circuits::ClassCircuit>::circuit,
            k_log: 10,
            inputs: &[Word::V1, Word::Imm, Word::Flags, Word::Cell(0)],
            outputs: &[Word::Address, Word::Out],
            fill: Fill::Instance(Load::witness),
        }),
        clock: ClockCircuit::plain(9),
    };

    /// Byte, halfword, and word stores into a memory cell.
    pub const STORE: Self = Self {
        class: Class::Store,
        name: "STORE",
        control: false,
        accesses: &[Slotted::RS1, Slotted::RS2, Slotted::cell(true)],
        copies: false,
        relation: ClassRelation::Circuit(ClassCircuit {
            build: <Store as rv::circuits::ClassCircuit>::circuit,
            k_log: 10,
            inputs: &[Word::V1, Word::V2, Word::Imm, Word::Flags, Word::Cell(0)],
            outputs: &[Word::Address, Word::CellNew(0)],
            fill: Fill::Instance(Store::witness),
        }),
        clock: ClockCircuit::plain(9),
    };

    /// `ld`: the cell at `v1 + imm` is what `rd` receives.
    pub const LD: Self = Self {
        class: Class::Ld,
        name: "LD",
        control: false,
        accesses: &[Slotted::RS1, Slotted::RD, Slotted::cell(false)],
        copies: true,
        relation: ClassRelation::Circuit(ClassCircuit {
            build: <Ld as rv::circuits::ClassCircuit>::circuit,
            k_log: 8,
            inputs: &[Word::V1, Word::Imm],
            outputs: &[Word::Address],
            fill: Fill::Instance(Ld::witness),
        }),
        clock: ClockCircuit::plain(9),
    };

    /// `sd`: `v2` is what the cell at `v1 + imm` receives.
    pub const SD: Self = Self {
        class: Class::Sd,
        name: "SD",
        control: false,
        accesses: &[Slotted::RS1, Slotted::RS2, Slotted::cell(true)],
        copies: true,
        relation: ClassRelation::Circuit(ClassCircuit {
            build: <Sd as rv::circuits::ClassCircuit>::circuit,
            k_log: 8,
            inputs: &[Word::V1, Word::Imm],
            outputs: &[Word::Address],
            fill: Fill::Instance(Ld::witness),
        }),
        clock: ClockCircuit::plain(9),
    };

    /// Logical and arithmetic shifts, including 32-bit word forms.
    pub const SHIFT: Self = Self {
        class: Class::Shift,
        name: "SHIFT",
        control: false,
        accesses: &[Slotted::RS1, Slotted::RS2, Slotted::RD],
        copies: false,
        relation: ClassRelation::Circuit(ClassCircuit {
            build: <Shift as rv::circuits::ClassCircuit>::circuit,
            k_log: 10,
            inputs: &[Word::V1, Word::V2, Word::Imm, Word::Flags],
            outputs: &[Word::Out],
            fill: Fill::Instance(Shift::witness),
        }),
        clock: ClockCircuit::plain(9),
    };

    /// Low half of a register product.
    pub const MUL: Self = Self {
        class: Class::Mul,
        name: "MUL",
        control: false,
        accesses: &[Slotted::RS1, Slotted::RS2, Slotted::RD],
        copies: false,
        relation: ClassRelation::Circuit(ClassCircuit {
            build: <Mul as rv::circuits::ClassCircuit>::circuit,
            k_log: 12,
            inputs: &[Word::V1, Word::V2, Word::Flags],
            outputs: &[Word::Out],
            fill: if cfg!(all(target_arch = "x86_64", target_feature = "avx2")) {
                Fill::Batch8(Mul::witness_batch)
            } else {
                Fill::Walk
            },
        }),
        clock: ClockCircuit::plain(9),
    };

    /// High half of a register product with signedness selectors.
    pub const MULH: Self = Self {
        class: Class::Mulh,
        name: "MULH",
        control: false,
        accesses: &[Slotted::RS1, Slotted::RS2, Slotted::RD],
        copies: false,
        relation: ClassRelation::Circuit(ClassCircuit {
            build: <Mulh as rv::circuits::ClassCircuit>::circuit,
            k_log: 13,
            inputs: &[Word::V1, Word::V2, Word::Flags],
            outputs: &[Word::Out],
            fill: Fill::Instance(Mulh::witness),
        }),
        clock: ClockCircuit::plain(9),
    };

    /// Quotients and remainders with prover-supplied magnitude hints.
    pub const DIV: Self = Self {
        class: Class::Div,
        name: "DIV",
        control: false,
        accesses: &[Slotted::RS1, Slotted::RS2, Slotted::RD],
        copies: false,
        relation: ClassRelation::Circuit(ClassCircuit {
            build: <Div as rv::circuits::ClassCircuit>::circuit,
            k_log: 13,
            inputs: &[Word::V1, Word::V2, Word::Flags, Word::HintQ, Word::HintR],
            outputs: &[Word::Out, Word::Bad],
            fill: Fill::Walk,
        }),
        clock: ClockCircuit::plain(9),
    };

    /// BLAKE2s compression over sixteen memory words, rewriting the four output words.
    pub const HASH: Self = Self {
        class: Class::Hash,
        name: "HASH",
        control: false,
        accesses: &[
            Slotted::RS1,
            Slotted::RS2,
            Slotted::at(
                Access::Block {
                    words: Hash::WORDS,
                    out: Hash::OUT as usize / 8,
                    n_out: 4,
                },
                Clock::block_slot(0),
            ),
        ],
        copies: false,
        relation: ClassRelation::Circuit(ClassCircuit {
            build: <Hash as rv::circuits::ClassCircuit>::circuit,
            k_log: 14,
            inputs: &[
                Word::V2,
                Word::Flags,
                Word::Cell(0),
                Word::Cell(1),
                Word::Cell(2),
                Word::Cell(3),
                Word::Cell(8),
                Word::Cell(9),
                Word::Cell(10),
                Word::Cell(11),
                Word::Cell(12),
                Word::Cell(13),
                Word::Cell(14),
                Word::Cell(15),
            ],
            outputs: &[Word::CellNew(4), Word::CellNew(5), Word::CellNew(6), Word::CellNew(7)],
            fill: Fill::Instance(rv::circuits::blake2s_witness),
        }),
        clock: ClockCircuit::plain(11),
    };

    /// Extension-field multiplication, optionally accumulating or using a base-field operand.
    ///
    /// No class circuit: the limbs are committed columns, and the table's identities (`ClassTable::extension_product`) say
    /// the product.
    ///
    /// The clock circuit splits the flags into their bits and computes the limbs' addresses ([`Ext::clock_circuit`]).
    pub const EXT: Self = Self {
        class: Class::Ext,
        name: "EXT",
        control: false,
        accesses: &[
            Slotted::RS1,
            Slotted::RS2,
            Slotted::POINTER,
            Slotted::at(Access::Limbs, Clock::limb_slot(0)),
        ],
        copies: false,
        relation: ClassRelation::Identities(ClassTable::extension_product),
        clock: ClockCircuit {
            k_log: 12,
            inputs: &[Word::V1, Word::V2, Word::Dest, Word::Flags],
            outputs: &[
                Word::FlagBit(0),
                Word::FlagBit(1),
                Word::LimbAddress(1),
                Word::LimbAddress(2),
                Word::LimbAddress(4),
                Word::LimbAddress(5),
                Word::LimbAddress(7),
                Word::LimbAddress(8),
            ],
            build: Ext::clock_circuit,
            witness: Ext::clock_witness,
        },
    };

    /// Check that register accesses and copy semantics match the circuit ports.
    pub(super) fn assert_valid(&self) {
        // Invariant: a register access exists exactly when its value is a word of one of the table's circuits, or a column a doubleword load or store moves.
        let has = |word: Word| self.words().any(|w| w == word);
        assert_eq!(
            self.reads_rs2() && !self.copies,
            has(Word::V2),
            "{}: rs2 read",
            self.name
        );
        assert_eq!(
            self.writes_rd() && !self.copies,
            has(Word::Out),
            "{}: rd write",
            self.name
        );
        assert_eq!(self.reads_rd(), has(Word::Dest), "{}: rd read", self.name);
        assert!(
            !(self.reads_rd() && self.writes_rd()),
            "{}: rd is read or written, not both",
            self.name
        );
        // Every row reads `rs1` first, and the register accesses come before RAM's.
        let registers = self
            .accesses
            .iter()
            .take_while(|a| matches!(a.access, Access::Read(_) | Access::WriteRd));
        assert!(
            self.accesses.first().map(|a| a.access) == Some(Access::Read(Register::Rs1))
                && registers.count() == self.registers().len(),
            "{}: access order",
            self.name
        );
        // A class with branches and jumps gates the bytecode's offset in its circuit, and reads `pc + 4` for its indirect jump.
        assert!(
            self.control == (has(Word::Dt) && has(Word::Jump)) && self.control == has(Word::Pc4),
            "{}: control flow",
            self.name
        );
        // A doubleword load moves its cell to `rd`, a doubleword store `v2` to its cell, and its circuit gives the address alone.
        if self.copies {
            let moves = match self.cell() {
                Some(false) => self.writes_rd() && !self.reads_rs2(),
                Some(true) => self.reads_rs2() && !self.writes_rd(),
                None => false,
            };
            let ports = [Word::V1, Word::Imm, Word::Address];
            assert!(
                moves && !self.control && !self.reads_rd() && self.ports().eq(ports),
                "{}: a copy",
                self.name
            );
        }
    }

    /// Whether the row makes the access.
    const fn makes(&self, access: Access) -> bool {
        let mut i = 0;
        while i < self.accesses.len() {
            if matches!(
                (self.accesses[i].access, access),
                (Access::Read(Register::Rs1), Access::Read(Register::Rs1))
                    | (Access::Read(Register::Rs2), Access::Read(Register::Rs2))
                    | (Access::Read(Register::Rd), Access::Read(Register::Rd))
                    | (Access::WriteRd, Access::WriteRd)
                    | (Access::Limbs, Access::Limbs)
            ) {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Whether the second source register is read.
    pub const fn reads_rs2(&self) -> bool {
        self.makes(Access::Read(Register::Rs2))
    }

    /// Whether the destination register receives a result.
    pub const fn writes_rd(&self) -> bool {
        self.makes(Access::WriteRd)
    }

    /// Whether the destination register supplies an address.
    pub const fn reads_rd(&self) -> bool {
        self.makes(Access::Read(Register::Rd))
    }

    /// The one cell a load or a store accesses, if the row has it: whether it is rewritten.
    pub const fn cell(&self) -> Option<bool> {
        let mut i = 0;
        while i < self.accesses.len() {
            if let Access::Cell { rewritten } = self.accesses[i].access {
                return Some(rewritten);
            }
            i += 1;
        }
        None
    }

    /// The hash block the row accesses, if it has one: its words, its first rewritten word, how many are rewritten.
    pub const fn block(&self) -> Option<(usize, usize, usize)> {
        let mut i = 0;
        while i < self.accesses.len() {
            if let Access::Block { words, out, n_out } = self.accesses[i].access {
                return Some((words, out, n_out));
            }
            i += 1;
        }
        None
    }

    /// Whether the row accesses the extension-field operands' limbs.
    pub const fn has_limbs(&self) -> bool {
        self.makes(Access::Limbs)
    }

    /// Indices of accessed registers, in previous-timestamp column order.
    ///
    /// The indices select the first source, second source, and destination register.
    pub const fn registers(&self) -> &'static [usize] {
        match (self.reads_rs2(), self.writes_rd() || self.reads_rd()) {
            (true, true) => &[0, 1, 2],
            (true, false) => &[0, 1],
            (false, true) => &[0, 2],
            (false, false) => &[0],
        }
    }

    /// Accesses per row: the registers', then RAM's.
    pub const fn n_accesses(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < self.accesses.len() {
            n += self.accesses[i].access.len();
            i += 1;
        }
        n
    }

    /// Smallest power-of-two height accepted by each of the table's circuits.
    ///
    /// A batch has at least eight instances and a zerocheck cube of at least 2^13 bits.
    pub const fn min_rows(&self) -> usize {
        1 << self.n_blocks_log(1)
    }

    /// `log2` of the batch proving `n_rows` of the table's rows: a power of two, at least flock's floor of eight instances and at
    /// least what the zerocheck's cube needs for each of the table's circuits.
    pub const fn n_blocks_log(&self, n_rows: usize) -> usize {
        let smallest = match self.class_circuit() {
            Some(circuit) if circuit.k_log < self.clock.k_log => circuit.k_log,
            _ => self.clock.k_log,
        };
        super::batch_log(smallest, n_rows)
    }

    /// The height the table is proven at when the run makes `rows` of its rows: the next power of two at or above its floor.
    pub const fn provable_height(&self, rows: usize) -> usize {
        let floor = self.min_rows();
        if rows > floor { rows.next_power_of_two() } else { floor }
    }

    /// Whether the table can be proven over `rows` rows: a power of two at or above its floor.
    pub const fn is_provable_height(&self, rows: usize) -> bool {
        rows.is_power_of_two() && rows >= self.min_rows()
    }

    /// The clock slots of the row's accesses, in the order of their columns.
    pub fn slots(&self) -> Vec<u32> {
        (self.accesses.iter())
            .flat_map(|a| (0..a.access.len() as u32).map(move |k| a.slot + k))
            .collect()
    }

    /// The class's flock circuit, if the class has one; otherwise its table's identities prove it.
    pub const fn class_circuit(&self) -> Option<&ClassCircuit> {
        match &self.relation {
            ClassRelation::Circuit(circuit) => Some(circuit),
            ClassRelation::Identities(_) => None,
        }
    }

    /// Whether the class is a flock circuit; otherwise its table's identities prove it.
    pub const fn has_circuit(&self) -> bool {
        self.class_circuit().is_some()
    }

    /// The class circuit's port words, inputs then outputs: none for a class with no circuit.
    pub fn ports(&self) -> impl Iterator<Item = Word> + '_ {
        (self.class_circuit().into_iter())
            .flat_map(|c| c.inputs.iter().chain(c.outputs))
            .copied()
    }

    /// The table's clock circuit.
    pub fn clock_circuit(&self) -> Circuit {
        (self.clock.build)(&self.slots())
    }

    /// The clock circuit's port words: the clock, each access's previous timestamp and [`Self::clock_inputs`], then
    /// the step and [`Self::clock_outputs`].
    pub fn clock_ports(&self) -> Vec<Word> {
        let prev = (0..self.n_accesses()).map(|i| Word::Prev(i as u8));
        let inputs = std::iter::once(Word::Clock)
            .chain(prev)
            .chain(self.clock.inputs.iter().copied());
        inputs
            .chain([Word::Step])
            .chain(self.clock.outputs.iter().copied())
            .collect()
    }

    /// Every word of the table's circuits: its class circuit's, then its clock circuit's own.
    pub(super) fn words(&self) -> impl Iterator<Item = Word> + '_ {
        self.ports()
            .chain(self.clock.inputs.iter().chain(self.clock.outputs).copied())
    }
}

/// Bytecode slot binding a circuit's verdict to a public zero.
///
/// It follows all decoded instruction fields.
pub const BAD_SLOT: usize = 10;

/// Bytecode slot binding the exit selector.
pub const EXIT_SLOT: usize = 11;

/// How many tables have a class circuit.
pub const N_CLASS_CIRCUITS: usize = {
    let mut n = 0;
    let mut t = 0;
    while t < N_TABLES {
        if TableId::ALL[t].spec().has_circuit() {
            n += 1;
        }
        t += 1;
    }
    n
};
