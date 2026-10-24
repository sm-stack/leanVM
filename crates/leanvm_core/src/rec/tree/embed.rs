//! Authenticated mixed-class keys: bounds, shape, verifier columns and seal roots in one canonical encoding.
//! A consumer pins the digest from a trusted setup; a self-reported digest does not authenticate a class.

use super::*;
use crate::rec::fixed::FixedColumn;
use pcs::merkle::Hash;
use primitives::hash::Hasher;
use std::sync::{Arc, OnceLock};

/// The encoding's tag and version.
const MAGIC: u64 = u64::from_le_bytes(*b"LVMXCK01");

const DOMAIN: &[u8] = b"leanvm/mixed-class-key/v1";

fn digest(bytes: &[u8]) -> Hash {
    let mut h = Hasher::new();
    h.update(DOMAIN);
    h.update(bytes);
    h.finalize()
}

fn descriptor(class: ProgramClass, shape: TreeShape) -> Result<Vec<u8>, TreeError> {
    let claims = shape.claims.ok_or(TreeError::MixedClass)?;
    if shape.leaf.is_zero_knowledge() {
        return Err(TreeError::MixedClass);
    }
    let mut out = Vec::new();
    for word in [class.log_bytecode, class.log_ram, class.log_advice, class.image_words]
        .into_iter()
        .chain(shape.leaf.heights().into_values())
        .chain([
            usize::from(shape.leaf.rate().log_inv_rate()),
            shape.arity_0,
            shape.arity,
            usize::from(shape.rate.log_inv_rate()),
            claims.capacity.claims,
            claims.capacity.groups,
            usize::from(claims.small.is_some()),
        ])
    {
        put(&mut out, word as u64);
    }
    if let Some(tier) = claims.small {
        for word in [tier.arity, tier.capacity.claims, tier.capacity.groups] {
            put(&mut out, word as u64);
        }
    }
    put(&mut out, SEAL_LOG_INV_RATE as u64);
    Ok(out)
}

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

impl Tree<'_> {
    /// The complete mixed class key: class, shape, verifier columns and seal roots.
    /// Generate `roots` with this tree's [`Tree::seal_prover`], then authenticate the whole encoding.
    ///
    /// # Errors
    ///
    /// A tree that is not mixed, or a root count that differs from its tier count.
    pub fn mixed_verifier_bytes(&self, roots: &SealRoots) -> Result<Vec<u8>, TreeError> {
        if !self.design.mixed {
            return Err(TreeError::MixedClass);
        }
        if roots.0.len() != self.design.tiers.len() {
            return Err(TreeError::MixedClass);
        }
        let key = self.design.leaf.program().verifying_key();
        let sizes = key.sizes();
        let class = ProgramClass {
            log_bytecode: sizes.log_bytecode,
            log_ram: sizes.log_ram,
            log_advice: sizes.log_advice,
            image_words: key.image().len(),
        };
        let mut out = Vec::new();
        put(&mut out, MAGIC);
        out.extend_from_slice(&descriptor(class, self.shape)?);
        put(&mut out, roots.0.len() as u64);
        for root in &roots.0 {
            out.extend_from_slice(root);
        }
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

    pub(super) fn class_key_digest_for(&self, roots: &SealRoots) -> Result<Hash, TreeError> {
        if let Some((known_roots, known_digest)) = self.class_key.get() {
            if known_roots == roots {
                return Ok(*known_digest);
            }
            if self.verifier_only {
                return Err(TreeError::ClassKeyDigest);
            }
        }
        let hash = digest(&self.mixed_verifier_bytes(roots)?);
        let _ = self.class_key.set((roots.clone(), hash));
        Ok(hash)
    }

    /// The roots authenticated by a loaded class key, if this tree was loaded from bytes.
    pub fn seal_roots(&self) -> Option<&SealRoots> {
        self.class_key
            .get()
            .filter(|_| self.verifier_only)
            .map(|(roots, _)| roots)
    }
}

impl Tree<'static> {
    /// Hash the complete class-key encoding. Pin this digest from a trusted class setup.
    pub fn mixed_class_key_digest(bytes: &[u8]) -> Hash {
        digest(bytes)
    }

    /// A verifier-only mixed tree of this class and shape, from [`Tree::mixed_verifier_bytes`].
    ///
    /// # Errors
    ///
    /// A digest differing from the trusted pin, a mismatched class or shape, or malformed data.
    /// All proving methods on the returned tree refuse with [`TreeError::VerifierOnly`].
    pub fn mixed_from_bytes(
        class: ProgramClass,
        shape: TreeShape,
        bytes: &[u8],
        expected_digest: &Hash,
    ) -> Result<Self, TreeError> {
        let _span = info_span!("load mixed class key").entered();
        if &digest(bytes) != expected_digest {
            return Err(TreeError::ClassKeyDigest);
        }
        if shape.claims.is_none() || shape.leaf.is_zero_knowledge() {
            return Err(TreeError::MixedClass);
        }
        shape.check()?;
        let mut r = Words(bytes);
        if r.next()? != MAGIC {
            return Err(TreeError::MixedClass);
        }
        let expected = descriptor(class, shape)?;
        if !r.0.starts_with(&expected) {
            return Err(TreeError::MixedClass);
        }
        r.0 = &r.0[expected.len()..];
        let count = r.usize()?;
        if count != shape.claims.map_or(1, |c| c.tiers()) {
            return Err(TreeError::MixedClass);
        }
        let mut roots = Vec::with_capacity(count);
        for _ in 0..count {
            let (root, rest) = r.0.split_first_chunk::<32>().ok_or(TreeError::MixedClass)?;
            roots.push(*root);
            r.0 = rest;
        }
        let roots = SealRoots(roots);
        let (root, rest) = r.0.split_first_chunk::<32>().ok_or(TreeError::MixedClass)?;
        r.0 = rest;
        let root = *root;
        let tiers = r.usize()?;
        if tiers != shape.claims.map_or(1, |c| c.tiers()) {
            return Err(TreeError::MixedClass);
        }
        let taus = (0..tiers).map(|_| r.heights()).collect::<Result<Vec<_>, _>>()?;
        for heights in &taus {
            if heights.iter().any(|(t, &h)| h < t.height_log(0)) {
                return Err(TreeError::MixedClass);
            }
            crate::rec::RecLayout::from_taus(*heights).map_err(|_| TreeError::MixedClass)?;
        }
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
            if n_columns != FixedColumn::COUNT {
                return Err(TreeError::MixedClass);
            }
            let mut columns = Vec::with_capacity(n_columns);
            for index in 0..n_columns {
                let len = r.usize()?;
                if len != 1usize << heights[FixedColumn::at(index).table()] {
                    return Err(TreeError::MixedClass);
                }
                let byte_len = len.checked_mul(8).ok_or(TreeError::MixedClass)?;
                let words = r.0.get(..byte_len).ok_or(TreeError::MixedClass)?;
                r.0 = &r.0[byte_len..];
                let column: Vec<F64> = (words.chunks_exact(8))
                    .map(|w| F64(u64::from_le_bytes(w.try_into().expect("eight bytes"))))
                    .collect();
                columns.push(Arc::new(column));
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
            class_key: OnceLock::from((roots, *expected_digest)),
        })
    }
}
