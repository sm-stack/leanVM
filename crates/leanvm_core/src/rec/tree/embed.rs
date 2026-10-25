//! Authenticated mixed-class keys: bounds, shape, verifier columns and seal roots in one canonical encoding.
//! A consumer pins the digest from a trusted setup; a self-reported digest does not authenticate a class.

use super::*;
use crate::rec::fixed::FixedColumn;
use pcs::merkle::Hash;
use primitives::hash::Hasher;
use std::sync::{Arc, OnceLock};

/// The encoding's tag and version.
const MAGIC: u64 = u64::from_le_bytes(*b"LVMXCK02");

const DOMAIN: &[u8] = b"leanvm/mixed-class-key/v2";

fn digest(bytes: &[u8]) -> Hash {
    let mut h = Hasher::new();
    h.update(DOMAIN);
    h.update(bytes);
    h.finalize()
}

fn descriptor(classes: &[LeafClass], shape: TreeShape) -> Result<Vec<u8>, TreeError> {
    let claims = shape.claims.ok_or(TreeError::MixedClass)?;
    if classes.is_empty()
        || classes[0].shape != shape.leaf
        || classes
            .iter()
            .any(|c| c.shape.is_zero_knowledge() || c.program.max_members == 0)
    {
        return Err(TreeError::MixedClass);
    }
    let mut out = Vec::new();
    put(&mut out, classes.len() as u64);
    for leaf in classes {
        let c = leaf.program;
        for word in [c.log_bytecode, c.log_ram, c.log_advice, c.image_words, c.max_members]
            .into_iter()
            .chain(leaf.shape.heights().into_values())
            .chain([usize::from(leaf.shape.rate().log_inv_rate())])
        {
            put(&mut out, word as u64);
        }
    }
    for word in [
        shape.arity_0,
        shape.arity,
        usize::from(shape.rate.log_inv_rate()),
        claims.capacity.claims,
        claims.capacity.groups,
        usize::from(claims.small.is_some()),
    ] {
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
    /// A tree that is not mixed, a root count that differs from its tier count, or roots not belonging to this tree.
    pub fn mixed_verifier_bytes(&self, roots: &SealRoots) -> Result<Vec<u8>, TreeError> {
        if !self.design.mixed {
            return Err(TreeError::MixedClass);
        }
        if roots.0.len() != self.design.tiers.len() {
            return Err(TreeError::MixedClass);
        }
        self.check_seal_roots(roots)?;
        let leaves: Vec<_> = std::iter::once((&self.design.leaf, self.design.max_members))
            .chain(self.design.extra_leaves.iter().map(|(leaf, max)| (leaf, *max)))
            .collect();
        let classes: Vec<_> = leaves
            .iter()
            .map(|(leaf, max)| {
                let key = leaf.program().verifying_key();
                let sizes = key.sizes();
                LeafClass {
                    program: ProgramClass {
                        log_bytecode: sizes.log_bytecode,
                        log_ram: sizes.log_ram,
                        log_advice: sizes.log_advice,
                        image_words: key.image().len(),
                        max_members: *max,
                    },
                    shape: leaf.shape(),
                }
            })
            .collect();
        let mut out = Vec::new();
        put(&mut out, MAGIC);
        out.extend_from_slice(&descriptor(&classes, self.shape)?);
        put(&mut out, roots.0.len() as u64);
        for root in &roots.0 {
            out.extend_from_slice(root);
        }
        for (leaf, _) in leaves {
            out.extend_from_slice(leaf.program().verifying_key().root());
        }
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
            return Err(TreeError::SealRoots);
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

    /// Authenticate and load a verifier-only mixed tree from [`Tree::mixed_verifier_bytes`].
    ///
    /// This is the recommended loader for class-key bytes.
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
        Self::mixed_classes_from_bytes(
            &[LeafClass {
                program: class,
                shape: shape.leaf,
            }],
            shape,
            bytes,
            expected_digest,
        )
    }

    /// Authenticate a class key covering every expected leaf class, in this order.
    pub fn mixed_classes_from_bytes(
        classes: &[LeafClass],
        shape: TreeShape,
        bytes: &[u8],
        expected_digest: &Hash,
    ) -> Result<Self, TreeError> {
        let _span = info_span!("load mixed class key").entered();
        if &digest(bytes) != expected_digest {
            return Err(TreeError::ClassKeyDigest);
        }
        Self::mixed_classes_from_trusted_bytes(classes, shape, bytes, expected_digest)
    }

    /// Load a verifier-only mixed tree from bytes already authenticated by the caller, without hashing them.
    ///
    /// Prefer [`Tree::mixed_from_bytes`], which checks the digest. This method performs the same structural
    /// validation but takes `digest` as given for the seal session, in both debug and release builds.
    ///
    /// # Security
    ///
    /// Use only when an outer mechanism guarantees that `bytes` are exactly the class key whose BLAKE2s
    /// class-key digest is `digest`. For example, bind both the bytes and this digest in a trusted binary or
    /// prestate, or pin a content-addressed oracle key together with the corresponding class-key digest.
    /// An oracle's keccak256 key authenticates the bytes, but does not by itself authenticate their mapping
    /// to the supplied BLAKE2s digest. The caller must establish that association through trusted setup.
    ///
    /// Soundness rests entirely on the bytes being genuine. The supplied digest is assumed correct and
    /// is not checked against the bytes, including in release builds. It only binds the seal session;
    /// rejection of a wrong digest is a misconfiguration check, not the source of soundness.
    /// With untrusted bytes this accepts forged verifier data, even when `digest` is a genuine pinned digest.
    /// Structural validation cannot establish circuit authenticity. A wrong digest may load successfully;
    /// it changes the seal session and is not checked by direct verification. Existing seals with PCS
    /// openings then fail, but a first-level root's empty v2 seal cannot detect a wrong digest.
    ///
    /// # Errors
    ///
    /// A mismatched class or shape, or malformed data. All proving methods on the returned tree refuse
    /// with [`TreeError::VerifierOnly`].
    pub fn mixed_from_trusted_bytes(
        class: ProgramClass,
        shape: TreeShape,
        bytes: &[u8],
        digest: &Hash,
    ) -> Result<Self, TreeError> {
        Self::mixed_classes_from_trusted_bytes(
            &[LeafClass {
                program: class,
                shape: shape.leaf,
            }],
            shape,
            bytes,
            digest,
        )
    }

    /// Load an externally authenticated class key for all expected leaf classes.
    ///
    /// # Security
    /// Exactly the same trust obligation as [`Tree::mixed_from_trusted_bytes`]: the bytes must be genuine,
    /// and the supplied digest is assumed correct without being hashed. Empty first-level seals do not detect
    /// a wrong digest. Prefer [`Tree::mixed_classes_from_bytes`] for untrusted input.
    pub fn mixed_classes_from_trusted_bytes(
        classes: &[LeafClass],
        shape: TreeShape,
        bytes: &[u8],
        digest: &Hash,
    ) -> Result<Self, TreeError> {
        let _span = info_span!("load trusted mixed class key").entered();
        shape.check()?;
        let mut r = Words(bytes);
        if r.next()? != MAGIC {
            return Err(TreeError::MixedClass);
        }
        let expected = descriptor(classes, shape)?;
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
        let placeholders = classes
            .iter()
            .map(|class| {
                let (root, rest) = r.0.split_first_chunk::<32>().ok_or(TreeError::MixedClass)?;
                r.0 = rest;
                Self::mixed_placeholder_with_root(class.program, *root)
            })
            .collect::<Result<Vec<_>, TreeError>>()?;
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
        let placeholder = &placeholders[0];
        let extra: Vec<_> = placeholders[1..]
            .iter()
            .zip(&classes[1..])
            .map(|(p, c)| (p.clone(), c.shape, c.program.max_members))
            .collect();
        let mut design = Design::new(placeholder, &shape, &taus, &extra)?;
        design.mixed = true;
        design.max_members = classes[0].program.max_members;
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
                let column: Vec<F64> = words
                    .as_chunks::<8>()
                    .0
                    .iter()
                    .map(|&w| F64(u64::from_le_bytes(w)))
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
            class_key: OnceLock::from((roots, *digest)),
            fixed_roots: OnceLock::new(),
        })
    }
}
