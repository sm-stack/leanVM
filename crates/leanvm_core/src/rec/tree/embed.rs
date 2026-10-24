//! Spike: a mixed class's verifier data as bytes, so a verifier that cannot afford the class setup loads it instead.
//!
//! The setup's result is a function of the class alone. The bytes hold what its search and circuit construction
//! produce: each tier's converged heights, and each circuit's statement length, heights and fixed columns. Loading
//! rebuilds the design from the class and those heights, and gives each key a stub circuit carrying only its statement
//! length and heights, which is all a proof's verification reads of it. A loaded tree verifies; it refuses to prove.
//!
//! The bytes carry no authentication: whoever loads them must know they are the class's, for instance by a hash pinned
//! next to the class.

use super::*;

/// The encoding's tag and version.
const MAGIC: u64 = u64::from_le_bytes(*b"LVMXVK02");

/// A little-endian word reader over the encoding.
struct Words<'a>(&'a [u8]);

impl Words<'_> {
    fn next(&mut self) -> Result<u64, TreeError> {
        let (word, rest) = self.0.split_first_chunk::<8>().ok_or(TreeError::MixedClass)?;
        self.0 = rest;
        Ok(u64::from_le_bytes(*word))
    }

    fn usize(&mut self) -> Result<usize, TreeError> {
        usize::try_from(self.next()?).map_err(|_| TreeError::MixedClass)
    }

    fn heights(&mut self) -> Result<PerRecTable<usize>, TreeError> {
        let mut values = [0; Table::ALL.len()];
        for v in &mut values {
            *v = self.usize()?;
        }
        Ok(PerRecTable::from_fn(|t: Table| values[t as usize]))
    }
}

fn put(out: &mut Vec<u8>, word: u64) {
    out.extend_from_slice(&word.to_le_bytes());
}

fn put_heights(out: &mut Vec<u8>, heights: &PerRecTable<usize>) {
    for t in Table::ALL {
        put(out, heights[t] as u64);
    }
}

impl Tree<'static> {
    /// The verifier data of a mixed tree, to be loaded by [`Tree::mixed_from_bytes`] for the same class and shape.
    ///
    /// # Errors
    ///
    /// A tree that is not mixed.
    pub fn mixed_verifier_bytes(&self) -> Result<Vec<u8>, TreeError> {
        if !self.design.mixed {
            return Err(TreeError::MixedClass);
        }
        let mut out = Vec::new();
        put(&mut out, MAGIC);
        out.extend_from_slice(self.design.leaf.program().verifying_key().root());
        put(&mut out, self.design.tiers.len() as u64);
        for tier in &self.design.tiers {
            put_heights(&mut out, &tier.taus);
        }
        put(&mut out, self.keys.len() as u64);
        for key in &self.keys {
            put(&mut out, key.circuit().statement_len as u64);
            put_heights(&mut out, &key.circuit().heights());
            let columns = key.fixed().columns();
            put(&mut out, columns.len() as u64);
            for column in columns {
                put(&mut out, column.len() as u64);
                out.reserve(8 * column.len());
                for w in column.iter() {
                    put(&mut out, w.0);
                }
            }
        }
        Ok(out)
    }

    /// A verifier-only mixed tree of this class and shape, from [`Tree::mixed_verifier_bytes`].
    ///
    /// # Errors
    ///
    /// Bytes that are not an encoding of this class's verifier data.
    pub fn mixed_from_bytes(class: ProgramClass, shape: TreeShape, bytes: &[u8]) -> Result<Self, TreeError> {
        if shape.claims.is_none() || shape.leaf.is_zero_knowledge() {
            return Err(TreeError::MixedClass);
        }
        shape.check()?;
        let mut r = Words(bytes);
        if r.next()? != MAGIC {
            return Err(TreeError::MixedClass);
        }
        let (root, rest) = r.0.split_first_chunk::<32>().ok_or(TreeError::MixedClass)?;
        r.0 = rest;
        let root = *root;
        let tiers = r.usize()?;
        if tiers != shape.claims.map_or(1, |c| c.tiers()) {
            return Err(TreeError::MixedClass);
        }
        let taus = (0..tiers).map(|_| r.heights()).collect::<Result<Vec<_>, _>>()?;
        let placeholder = Self::mixed_placeholder_with_root(class, root)?;
        let mut design = Design::new(&placeholder, &shape, &taus)?;
        design.mixed = true;
        let n_keys = r.usize()?;
        if n_keys != design.places.len() {
            return Err(TreeError::MixedClass);
        }
        let mut keys = Vec::with_capacity(n_keys);
        for place in &design.places {
            let statement_len = r.usize()?;
            let heights = r.heights()?;
            if statement_len != design.statement.len() || heights != taus[place.tier] {
                return Err(TreeError::MixedClass);
            }
            let n_columns = r.usize()?;
            let mut columns = Vec::with_capacity(n_columns);
            for _ in 0..n_columns {
                let len = r.usize()?;
                let words = r.0.get(..8 * len).ok_or(TreeError::MixedClass)?;
                r.0 = &r.0[8 * len..];
                let column: Vec<F64> = (words.chunks_exact(8))
                    .map(|w| F64(u64::from_le_bytes(w.try_into().expect("eight bytes"))))
                    .collect();
                columns.push(std::sync::Arc::new(column));
            }
            let circuit = Circuit::verifier_stub(statement_len, heights);
            keys.push(
                CircuitKey::from_parts(circuit, FixedColumns::from_columns(columns))
                    .map_err(|_| TreeError::TooLarge)?,
            );
        }
        if !r.0.is_empty() {
            return Err(TreeError::MixedClass);
        }
        let fixed = |tier: usize| {
            design.tiers.get(tier).map_or_else(
                || vec![F64::ZERO],
                |t| {
                    let columns: Vec<&FixedColumns> = keys[t.places.clone()].iter().map(CircuitKey::fixed).collect();
                    t.fixed.polynomial(&columns)
                },
            )
        };
        let rv = placeholder.rv();
        let mut image: Vec<F64> = rv.image().iter().map(|&w| F64(w)).collect();
        image.resize(1 << design.vars.0[DensePoly::Image as usize], F64::ZERO);
        let tables = DenseTables([Lookup::Bytecode.table(rv), image, fixed(SMALL), fixed(LARGE)]);
        Ok(Self {
            shape,
            design,
            keys,
            tables,
            verifier_only: true,
        })
    }
}
