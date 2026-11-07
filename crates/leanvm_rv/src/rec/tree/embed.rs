//! Authenticated mixed-class keys: bounds, shape, circuit dimensions and seal roots in one canonical encoding. A consumer pins the digest from a trusted setup; a self-reported digest does not authenticate a class.

use super::*;
use pcs::merkle::Hash;
use primitives::hash::Hasher;
use std::sync::OnceLock;

/// The encoding's tag and version.
const MAGIC: u64 = u64::from_le_bytes(*b"LVMXCK04");

const DOMAIN: &[u8] = b"leanvm/mixed-class-key/v4";
fn digest(bytes: &[u8]) -> Hash {
    let mut h = Hasher::new();
    h.update(DOMAIN);
    h.update(bytes);
    h.finalize()
}

fn descriptor(classes: &[LeafClass], shape: TreeShape, split_zk: bool) -> Result<Vec<u8>, TreeError> {
    let claims = shape.claims.ok_or(TreeError::MixedClass)?;
    if classes.is_empty() || classes[0].shape != shape.leaf || classes.iter().any(|c| c.program.max_members == 0) {
        return Err(TreeError::MixedClass);
    }
    let mut out = Vec::new();
    put(&mut out, u64::from(split_zk));
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
        put(&mut out, u64::from(leaf.shape.is_zero_knowledge()));
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
    /// The complete mixed class key: class, shape, circuit dimensions and seal roots. Generate `roots` with this tree's [`Tree::seal_prover`], then authenticate the whole encoding.
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
        out.extend_from_slice(&descriptor(&classes, self.shape, self.design.split_zk)?);
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
    /// # Errors
    ///
    /// A digest differing from the trusted pin, a mismatched class or shape, or malformed data. All proving methods on the returned tree refuse with [`TreeError::VerifierOnly`].
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
        Self::mixed_classes_from_bytes_with(classes, shape, ZkPlacement::Isolated, bytes, expected_digest)
    }

    /// Authenticate a key against the caller's ordered classes, shape and placement. The placement is never inferred from untrusted bytes.
    pub fn mixed_classes_from_bytes_with(
        classes: &[LeafClass],
        shape: TreeShape,
        placement: ZkPlacement,
        bytes: &[u8],
        expected_digest: &Hash,
    ) -> Result<Self, TreeError> {
        let _span = info_span!("load mixed class key").entered();
        if &digest(bytes) != expected_digest {
            return Err(TreeError::ClassKeyDigest);
        }
        Self::mixed_classes_from_trusted_bytes_with(classes, shape, placement, bytes, expected_digest)
    }

    /// Load a verifier-only mixed tree from bytes already authenticated by the caller, without hashing them.
    ///
    /// Prefer [`Tree::mixed_from_bytes`] for untrusted input. This loader checks structure but does not hash the bytes.
    ///
    /// # Security
    ///
    /// The caller must authenticate the exact bytes and their association with `digest`, for example by embedding both in a trusted binary or pinning a content-addressed oracle key and its corresponding class-key digest. An oracle's keccak256 key alone does not establish that BLAKE2s association.
    ///
    /// Soundness depends on genuine key bytes: untrusted bytes can supply forged verifier data. The digest is assumed correct and is not checked in debug or release builds. It binds the seal session; a wrong digest can load successfully but invalidates existing seals, including First-root seals.
    ///
    /// # Errors
    ///
    /// A mismatched class or shape, or malformed data. All proving methods on the returned tree refuse with [`TreeError::VerifierOnly`].
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
    /// Same requirements as [`Tree::mixed_from_trusted_bytes`].
    pub fn mixed_classes_from_trusted_bytes(
        classes: &[LeafClass],
        shape: TreeShape,
        bytes: &[u8],
        digest: &Hash,
    ) -> Result<Self, TreeError> {
        Self::mixed_classes_from_trusted_bytes_with(classes, shape, ZkPlacement::Isolated, bytes, digest)
    }

    /// Load externally authenticated bytes with caller-pinned placement.
    ///
    /// # Security
    /// Same requirements as [`Tree::mixed_from_trusted_bytes`].
    pub fn mixed_classes_from_trusted_bytes_with(
        classes: &[LeafClass],
        shape: TreeShape,
        placement: ZkPlacement,
        bytes: &[u8],
        digest: &Hash,
    ) -> Result<Self, TreeError> {
        let _span = info_span!("load trusted mixed class key").entered();
        shape.check()?;
        let mut r = Words(bytes);
        let zk_count = classes
            .iter()
            .filter(|c| placement.isolated() && c.shape.is_zero_knowledge())
            .count();
        if r.next()? != MAGIC {
            return Err(TreeError::MixedClass);
        }
        let expected = descriptor(classes, shape, placement.isolated())?;
        if !r.0.starts_with(&expected) {
            return Err(TreeError::MixedClass);
        }
        r.0 = &r.0[expected.len()..];
        let count = r.usize()?;
        if count != shape.claims.map_or(1, |c| c.tiers()) + zk_count {
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
        if tiers != shape.claims.map_or(1, |c| c.tiers()) + zk_count {
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
        let mut design = Design::new_with_zk(placeholder, &shape, &taus, &extra, placement.isolated())?;
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
            let circuit = Circuit::verifier_stub(statement_len, heights);
            keys.push(CircuitKey::from_parts(circuit, FixedColumns::absent()).map_err(|_| TreeError::TooLarge)?);
        }
        if !r.0.is_empty() {
            return Err(TreeError::MixedClass);
        }
        let tables = DenseTables(Vec::new());
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
