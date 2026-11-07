//! Whole witnesses for tests and benchmarks, behind the development-only `test-util` feature.
//!
//! A proof writes a witness's bits straight into its column of the commitment.
//!
//! A test owns them instead, so these allocate the bits, then run the generators a proof runs.

use crate::circuit::{Circuit, Gate, Slot};
use crate::reduction::{Block, Instance, live_instances};
use crate::witness::{BatchRows, Tables};

/// One circuit's witness over a batch of instances, its bits owned.
///
/// Each table packs 64 bits a word, `2^k_log / 64` words per instance, instance-major.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Witness {
    /// The witness bits.
    pub z: Vec<u64>,

    /// The left factor of every constraint, `A z`.
    pub az: Vec<u64>,

    /// The right factor of every constraint, `B z`.
    pub bz: Vec<u64>,
}

impl Witness {
    /// The witness of `rows`, by the 64-lane walk of the gate list.
    ///
    /// `input_words(row, words)` writes a row's input port words.
    pub fn by_walk<S: Sync>(
        circuit: &Circuit,
        rows: BatchRows<'_, S>,
        input_words: impl Fn(&S, &mut [u64]) + Sync,
    ) -> Self {
        Self::generate(circuit, rows, |z| {
            circuit.witness_by_walk(z, rows, input_words, |_, _, _| {})
        })
    }

    /// The witness of `rows`, one instance at a time by `instance(row, z, a, b)`.
    pub fn by_instance<S: Sync>(
        circuit: &Circuit,
        rows: BatchRows<'_, S>,
        instance: impl Fn(&S, &mut [u64], &mut [u64], &mut [u64]) + Sync,
    ) -> Self {
        Self::generate(circuit, rows, |z| {
            circuit.witness_by_instance(z, rows, instance, |_, _, _| {})
        })
    }

    /// The witness of `rows`, eight instances at a time by `batch(rows, z, a, b)`.
    pub fn by_batch8<S: Sync>(
        circuit: &Circuit,
        rows: BatchRows<'_, S>,
        batch: impl Fn([&S; 8], &mut [u64], &mut [u64], &mut [u64]) + Sync,
    ) -> Self {
        Self::generate(circuit, rows, |z| {
            circuit.witness_by_batch8(z, rows, batch, |_, _, _| {})
        })
    }

    /// The witness of `rows`, each instance by the reference walk of the gate list, one bit at a time.
    ///
    /// Each row is its instance's input port words.
    pub fn by_reference<S: AsRef<[u64]> + Sync>(circuit: &Circuit, rows: BatchRows<'_, S>) -> Self {
        Self::by_instance(circuit, rows, |row, z, az, bz| {
            reference_walk(circuit, row.as_ref(), z, az, bz);
        })
    }

    /// One instance's witness on `inputs`, its input port words, by the reference walk.
    pub fn of_instance(circuit: &Circuit, inputs: &[u64]) -> Self {
        // One instance's three tables, zeroed: the walk only sets bits.
        let words = (1 << circuit.k_log()) / 64;
        let mut witness = Self {
            z: vec![0; words],
            az: vec![0; words],
            bz: vec![0; words],
        };
        reference_walk(circuit, inputs, &mut witness.z, &mut witness.az, &mut witness.bz);
        witness
    }

    /// The witness as one circuit's batch of `2^n_blocks_log` instances for the reduction.
    pub fn instance<'a>(&'a self, block: Block<'a>, n_blocks_log: usize) -> Instance<'a> {
        Instance {
            block,
            n_blocks_log,
            live: live_instances(&self.z, block.k_log),
            z: &self.z,
            az: &self.az,
            bz: &self.bz,
        }
    }

    /// The witness of `rows` on `circuit`, its bits allocated here and written by `fill`.
    fn generate<S>(circuit: &Circuit, rows: BatchRows<'_, S>, fill: impl FnOnce(&mut [u64]) -> Tables) -> Self {
        let mut z = Box::<[u64]>::new_uninit_slice(circuit.batch(rows.n_blocks_log()).total_words());
        // SAFETY: every generator writes all of the bits and reads none of them first.
        let Tables { az, bz } = fill(unsafe { primitives::write_only(&mut z) });
        Self {
            // SAFETY: the generator wrote every word.
            z: unsafe { z.assume_init() }.into_vec(),
            az,
            bz,
        }
    }
}

/// One instance's `z`, `A z` and `B z`, by one walk of the gate list on bits.
///
/// It is the reference every generator is pinned to.
///
/// `inputs` are the input ports' words, and the three tables come zeroed.
fn reference_walk(circuit: &Circuit, inputs: &[u64], z: &mut [u64], az: &mut [u64], bz: &mut [u64]) {
    assert_eq!(inputs.len(), circuit.n_input_words());
    let const_pos = circuit.const_pos();
    // Set the bit at a slot of one table.
    let set = |table: &mut [u64], slot: Slot, v: bool| {
        let i = slot.index();
        table[i / 64] |= u64::from(v) << (i % 64);
    };
    // Wire `i` is gate `i`'s value.
    let mut wires: Vec<bool> = Vec::with_capacity(circuit.gates.len());
    for &gate in &circuit.gates {
        let v = match gate {
            // An input bit or the constant: `z * 1 = z`.
            Gate::Free(s) => {
                let i = s.index();
                let v = i == const_pos || (inputs[i / 64] >> (i % 64)) & 1 == 1;
                set(z, s, v);
                set(az, s, v);
                set(bz, s, true);
                v
            }
            // Free: no row.
            Gate::Xor(x, y) => wires[x.index()] ^ wires[y.index()],
            // A product: `x * y = z`.
            Gate::And(x, y, s) => {
                let (x, y) = (wires[x.index()], wires[y.index()]);
                set(z, s, x & y);
                set(az, s, x);
                set(bz, s, y);
                x & y
            }
            // A committed copy: `x * 1 = z`.
            Gate::Copy(x, s) => {
                let v = wires[x.index()];
                set(z, s, v);
                set(az, s, v);
                set(bz, s, true);
                v
            }
        };
        wires.push(v);
    }
}
