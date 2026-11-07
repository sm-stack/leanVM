//! Aggregation: prove a leaf program once, then a tree over copies of its proof, and report each kind of node and the whole tree; or, with `--signers`, a signer-set tree over distinct leaves, each publishing its signer set, proven bottom-up and verified by its root's set alone.

use crate::refuse;
use crate::workload::Workload;
use bench::{Plan, Timing};
use bench::{pretty_f64, pretty_integer};
use clap::ValueEnum;
use core::ops::Range;
use leanvm::aggregate::{
    Aggregate, Capacity, CircuitStats, ClaimLeaf, ClaimSet, ClaimShape, Kind, Leaf, LeafShape, Tree, TreeProof,
    TreeShape,
};
use leanvm::{ProvenRun, Prover};
use std::collections::BTreeMap;
use std::time::Instant;

/// The leaf program.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum LeafProgram {
    /// Fibonacci modulo 2^64, `n` steps.
    Fibonacci,
    /// `n` leanXMSS signatures.
    Leanxmss,
    /// `n` leanSPHINCS signatures.
    Leansphincs,
}

/// The leaf index every leanXMSS signature of a signer-set tree's leaves is at.
const LEAF_INDEX: u32 = 0;

impl LeafProgram {
    /// The leaf's run at size `n`.
    pub fn workload(self, n: usize) -> Workload {
        match self {
            Self::Fibonacci => Workload::fibonacci(n),
            Self::Leanxmss => Workload::leanxmss(n),
            Self::Leansphincs => Workload::leansphincs(n),
        }
    }

    /// A signer-set leaf's run: group `j`'s signers sign message `j`, the run publishing their set.
    ///
    /// Fibonacci publishes no set, which is the user's mistake, refused plainly.
    fn signer_leaf(self, groups: &[Range<usize>]) -> Workload {
        let message = |j: usize| [j as u64, 0, 0, 0];
        match self {
            Self::Fibonacci => refuse(format_args!(
                "fibonacci publishes no signer set: --signers takes --program leanxmss or leansphincs"
            )),
            Self::Leanxmss => Workload::leanxmss_groups(
                &(groups.iter().enumerate())
                    .map(|(j, signers)| leanxmss_host::Group {
                        leaf_index: LEAF_INDEX,
                        message: message(j),
                        signers: signers.clone(),
                    })
                    .collect::<Vec<_>>(),
            ),
            Self::Leansphincs => Workload::leansphincs_groups(
                &(groups.iter().enumerate())
                    .map(|(j, signers)| leansphincs_host::Group {
                        message: message(j),
                        signers: signers.clone(),
                    })
                    .collect::<Vec<_>>(),
            ),
        }
    }
}

/// What the root of a signer-set tree declares.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Declare {
    /// The union of its children's sets.
    All,
    /// The first half of the union's claims, in the canonical order.
    Half,
}

/// A signer-set tree's capacity, its leaves' groups and overlap, and what its root declares.
#[derive(Clone, Copy, Debug)]
pub struct Signers {
    /// What a node's children's sets together, and its own set, stay within.
    pub capacity: Capacity,
    /// The groups each leaf's signatures are split across, group `j` signing message `j`.
    pub groups: usize,
    /// The percentage of each of a leaf's groups' signers that are the previous leaf's.
    pub overlap: usize,
    /// What the root declares.
    pub declare: Declare,
}

fn ms(t: &Timing) -> String {
    format!("{} ms{}", pretty_f64(t.mean() * 1000.0), t.spread())
}

fn secs(t: &Timing) -> String {
    format!("{} s{}", pretty_f64(t.mean()), t.spread())
}

fn gib(bytes: u64) -> String {
    format!("{} GiB", pretty_f64(bytes as f64 / (1u64 << 30) as f64))
}

/// A circuit's name, its rows per table and its committed words.
fn print_circuit(name: &str, stats: &CircuitStats) {
    let rows: Vec<String> = (stats.tables.iter())
        .map(|t| format!("{} {} (2^{})", t.name, pretty_integer(&t.rows), t.height_log))
        .collect();
    println!("{name}");
    println!("  rows                        : {}", rows.join("  "));
    println!(
        "  committed words             : {} (2^{:.3})",
        pretty_integer(&stats.committed),
        (stats.committed as f64).log2()
    );
}

/// A proof's size.
fn print_proof_size(bytes: usize) {
    println!("  proof size                  : {:.1} KiB", bytes as f64 / 1024.0);
}

/// One kind of node: its circuit, its proof, and its times.
fn report(name: &str, tree: &Tree<'_>, kind: Kind, proof: &TreeProof, prove: &Timing, verify: &Timing) {
    print_circuit(name, &tree.stats(kind));
    print_proof_size(proof.to_bytes().len());
    println!("  proving                     : {}", secs(prove));
    println!("  verifying as a root         : {}", ms(verify));
}

/// The leaf's committed words and proof size, and its proving time if it is timed.
fn print_leaf(proven: &ProvenRun, prove: Option<&Timing>) {
    println!(
        "  committed words             : {} (2^{:.3})",
        pretty_integer(&proven.stats.committed),
        (proven.stats.committed as f64).log2()
    );
    print_proof_size(proven.proof.to_bytes().len());
    if let Some(prove) = prove {
        println!("  proving                     : {}", secs(prove));
    }
}

/// Prove the leaf at `leaf_prover`'s rate, then the tree of `leaves` over copies of its proof, every tree proof at `prover`'s rate, and print the report.
///
/// The tree's first level verifies `arity_0` leaves, each node `arity` children.
pub fn run(
    leaf: &Workload,
    leaves: usize,
    arity_0: usize,
    arity: usize,
    leaf_prover: &Prover,
    prover: &Prover,
    plan: Plan,
) {
    let rate = prover.rate();
    let title = &leaf.title;

    // The leaf's run, measured, gives the shape its proofs announce: the tree is checked before anything is proven.
    let stats = leaf.measure();
    let shape = TreeShape {
        leaf: if leaf_prover.is_zero_knowledge() {
            LeafShape::measured(&stats, leaf_prover.rate()).zero_knowledge()
        } else {
            LeafShape::measured(&stats, leaf_prover.rate())
        },
        arity_0,
        arity,
        rate,
        claims: None,
    };
    shape.root_kind(leaves).unwrap_or_else(|e| refuse(format_args!("{e}")));

    let (proved, leaf_time) = plan.warm_then_measure(|| leaf.prove(leaf_prover));
    let (proof, output) = (&proved.proof, proved.output);
    let quiet = plan.without_cooldown();

    let (tree, setup) = Plan::default().measure_quiet(|| {
        let _span = tracing::info_span!("Tree setup").entered();
        Tree::new(&leaf.program, shape).unwrap_or_else(|e| refuse(format_args!("{e}")))
    });
    let leaves_proofs = vec![Leaf::new(proof, output); leaves];

    println!(
        "Aggregation tree over {leaves} x {title}, first level {arity_0}, arity {arity}, leaves at log-inv-rate {}, tree proofs at {}",
        leaf_prover.rate().log_inv_rate(),
        rate.log_inv_rate()
    );
    println!("leaf");
    print_leaf(&proved, Some(&leaf_time));
    println!("tree setup (both circuits, the fixed polynomials): {}", secs(&setup));

    let firsts = vec![Leaf::new(proof, output); arity_0];
    let (first, first_time) = plan.warm_then_measure(|| tree.prove_first(&firsts).expect("honest leaves"));
    let outputs = vec![output; arity_0];
    let (_, first_verify) = quiet.measure_quiet(|| tree.verify(&first, &outputs).expect("a first-level root"));
    report(
        &format!("first-level node, {arity_0} leaves"),
        &tree,
        Kind::First,
        &first,
        &first_time,
        &first_verify,
    );

    if leaves > arity_0 {
        let children = vec![first; arity];
        let (node, node_time) = plan.warm_then_measure(|| tree.prove_node(&children).expect("honest children"));
        let outputs = vec![output; arity_0 * arity];
        let (_, node_verify) = quiet.measure_quiet(|| tree.verify(&node, &outputs).expect("a root"));
        report(
            &format!("node, {arity} children"),
            &tree,
            Kind::Node,
            &node,
            &node_time,
            &node_verify,
        );
    }

    let (root, whole) = Plan::default().measure_quiet(|| {
        let _span = tracing::info_span!("Prove tree", leaves).entered();
        tree.prove(&leaves_proofs)
            .unwrap_or_else(|e| refuse(format_args!("{e}")))
    });
    let outputs = vec![output; leaves];
    let (_, root_verify) = quiet.measure_quiet(|| tree.verify(&root, &outputs).expect("the root verifies"));
    println!("whole tree");
    println!(
        "  proving every node          : {}, after the leaf proofs",
        secs(&whole)
    );
    println!("  verifying the root          : {}", ms(&root_verify));
    println!("  peak memory                 : {}", gib(bench::peak_rss_bytes()));
}

/// Leaf `i`'s groups of signers: `n` split across `groups`, group `j` sliding from leaf to leaf by its size less its
/// overlap, so `overlap` percent of its signers (rounded down) are the previous leaf's.
fn leaf_groups(i: usize, n: usize, groups: usize, overlap: usize) -> Vec<Range<usize>> {
    (0..groups)
        .map(|j| {
            let size = n / groups + usize::from(j < n % groups);
            let start = i * (size - size * overlap / 100);
            start..start + size
        })
        .collect()
}

/// One of a signer-set tree's circuits: the first level's, or the node circuit of one arity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Circuit {
    First,
    Node(usize),
}

/// The proofs one circuit made: their proving times and the size of one.
#[derive(Default)]
struct Proofs {
    time: Timing,
    bytes: usize,
}

/// One node's proof, its proving time and size recorded under its circuit.
fn timed(proofs: &mut BTreeMap<Circuit, Proofs>, circuit: Circuit, prove: impl FnOnce() -> Aggregate) -> Aggregate {
    let start = Instant::now();
    let made = prove();
    let entry = proofs.entry(circuit).or_default();
    entry.time.push(start.elapsed().as_secs_f64());
    entry.bytes = made.proof.to_bytes().len();
    made
}

/// Prove the signer-set tree over `leaves` bottom-up, each node taking `arity` proofs (the last of a level fewer), the
/// root declaring `declare` or its union, every other node its union; every node's proving time is recorded under its
/// circuit.
fn prove_signer_tree(
    tree: &Tree<'_>,
    leaves: &[ClaimLeaf<'_>],
    arity_0: usize,
    arity: usize,
    declare: Option<&ClaimSet>,
    proofs: &mut BTreeMap<Circuit, Proofs>,
) -> Aggregate {
    let declares = |root: bool| declare.filter(|_| root);
    let first = declares(leaves.len() == arity_0);
    let mut level: Vec<Aggregate> = (leaves.chunks(arity_0))
        .map(|chunk| {
            timed(proofs, Circuit::First, || {
                (tree.aggregate_leaves(chunk, first))
                    .unwrap_or_else(|e| refuse(format_args!("a first-level node: {e}")))
            })
        })
        .collect();
    while level.len() > 1 {
        let node = declares(level.len() <= arity);
        level = (level.chunks(arity))
            .map(|chunk| {
                let children: Vec<&Aggregate> = chunk.iter().collect();
                // A node of one child is the node of two, its other place absent.
                timed(proofs, Circuit::Node(chunk.len().max(2)), || {
                    (tree.aggregate(&children, node)).unwrap_or_else(|e| refuse(format_args!("a node: {e}")))
                })
            })
            .collect();
    }
    level.pop().expect("one root")
}

/// Prove `leaves` distinct runs of `program`, each `n` signatures, at `leaf_prover`'s rate, untimed; then the
/// signer-set tree over them bottom-up at `prover`'s rate, `plan.repeat()` times, and verify its root by its set alone;
/// and print the report.
///
/// The first level verifies `arity_0` leaves, each node up to `arity` proofs, the last of a level fewer.
#[expect(clippy::too_many_arguments, reason = "the CLI's options, one each")]
pub fn run_signers(
    program: LeafProgram,
    n: usize,
    leaves: usize,
    arity_0: usize,
    arity: usize,
    signers: Signers,
    leaf_prover: &Prover,
    prover: &Prover,
    plan: Plan,
) {
    let Signers {
        capacity,
        groups,
        overlap,
        declare,
    } = signers;
    if groups == 0 || groups > n {
        refuse(format_args!(
            "--groups {groups}: each of a leaf's groups takes at least one of its {n} signatures"
        ));
    }
    if arity_0 == 0 || leaves == 0 || !leaves.is_multiple_of(arity_0) {
        refuse(format_args!(
            "{leaves} leaves fill no first level of {arity_0}: --leaves is a positive multiple of --arity0"
        ));
    }
    let runs: Vec<Workload> = (0..leaves)
        .map(|i| program.signer_leaf(&leaf_groups(i, n, groups, overlap)))
        .collect();
    let sets: Vec<&ClaimSet> = (runs.iter())
        .map(|run| run.claims.as_ref().expect("a signature guest publishes its claims"))
        .collect();
    let union = ClaimSet::from_claims(sets.iter().flat_map(|set| set.claims()));
    let declared = match declare {
        Declare::All => None,
        Declare::Half => Some(ClaimSet::from_claims(union.claims().take(union.n_claims() / 2))),
    };

    // The first leaf's run, measured, gives the shape every leaf's proof announces: the tree's key needs no proof.
    let measured = LeafShape::measured(&runs[0].measure(), leaf_prover.rate());
    let shape = TreeShape {
        leaf: if leaf_prover.is_zero_knowledge() {
            measured.zero_knowledge()
        } else {
            measured
        },
        arity_0,
        arity,
        rate: prover.rate(),
        claims: Some(ClaimShape::new(capacity)),
    };
    let (tree, setup) = Plan::default().measure_quiet(|| {
        let _span = tracing::info_span!("Tree setup").entered();
        Tree::new(&runs[0].program, shape).unwrap_or_else(|e| refuse(format_args!("{e}")))
    });

    let proven: Vec<ProvenRun> = (runs.iter().enumerate())
        .map(|(i, run)| {
            let _quiet = bench::suppress_tracing();
            let proven = run.prove(leaf_prover);
            if LeafShape::of(&proven.proof).ok() != Some(shape.leaf) {
                refuse(format_args!(
                    "leaf {i}'s proof has other table heights than leaf 0's, which the tree's circuits take: try another --n"
                ));
            }
            proven
        })
        .collect();
    let leaf_proofs: Vec<ClaimLeaf<'_>> = (proven.iter().zip(&sets))
        .map(|(proven, set)| ClaimLeaf::new(Leaf::from(proven), set))
        .collect();

    let mut proofs = BTreeMap::new();
    let mut heap_peak = 0;
    let (root, whole) = plan.measure_quiet(|| {
        let _span = tracing::info_span!("Prove signer-set tree", leaves).entered();
        let (root, heap) = bench::measure_heap(|| {
            prove_signer_tree(&tree, &leaf_proofs, arity_0, arity, declared.as_ref(), &mut proofs)
        });
        heap_peak = heap_peak.max(heap.peak);
        root
    });
    assert_eq!(
        &root.claims,
        declared.as_ref().unwrap_or(&union),
        "the root declares what it is asked to"
    );
    let (_, root_verify) = (plan.without_cooldown())
        .measure_quiet(|| (tree.verify_claims(&root.proof, &root.claims)).expect("the root verifies by its set"));

    let sum: usize = sets.iter().map(|set| set.n_claims()).sum();
    println!(
        "Signer-set tree over {leaves} x {}, first level {arity_0}, nodes of 2 to {arity} proofs, sets of fewer than {} claims in at most {} groups, leaves at log-inv-rate {}, tree proofs at {}",
        runs[0].title,
        pretty_integer(&capacity.claims),
        pretty_integer(&capacity.groups),
        leaf_prover.rate().log_inv_rate(),
        prover.rate().log_inv_rate()
    );
    println!(
        "leaves                        : {leaves} distinct runs of {n} claims in {groups} groups, {overlap}% of each group's signers the previous leaf's"
    );
    println!(
        "union                         : {} claims in {} groups, of the leaves' {} claims",
        pretty_integer(&union.n_claims()),
        pretty_integer(&union.groups.len()),
        pretty_integer(&sum)
    );
    println!(
        "root declares                 : {} claims",
        pretty_integer(&root.claims.n_claims())
    );
    println!("leaf (proven untimed)");
    print_leaf(&proven[0], None);
    println!("tree setup (every circuit, the fixed polynomials): {}", secs(&setup));
    for (circuit, Proofs { time, bytes }) in &proofs {
        let (name, stats) = match *circuit {
            Circuit::First => (format!("first-level node, {arity_0} leaves"), tree.stats(Kind::First)),
            Circuit::Node(children) => (
                format!("node, {children} children"),
                tree.node_stats(children)
                    .expect("a node circuit of every arity up to the largest"),
            ),
        };
        print_circuit(&name, &stats);
        print_proof_size(*bytes);
        let n = time.samples().len();
        println!(
            "  proving                     : {}, {n} proof{}",
            secs(time),
            if n == 1 { "" } else { "s" }
        );
    }
    println!("whole tree");
    println!(
        "  proving every node          : {}, after the leaf proofs",
        secs(&whole)
    );
    println!("  verifying the root          : {}", ms(&root_verify));
    println!("  heap peak                   : {}", gib(heap_peak));
    println!("  peak memory                 : {}", gib(bench::peak_rss_bytes()));
}

#[cfg(test)]
mod tests {
    use super::{Declare, LeafProgram, Signers, leaf_groups, run_signers};
    use bench::Plan;
    use leanvm::aggregate::Capacity;
    use leanvm::{Prover, Rate};

    #[test]
    fn consecutive_leaves_share_their_overlap() {
        // Each group slides by its size less its overlap, so consecutive leaves share the overlap and no more.
        let (n, groups, overlap) = (10, 3, 50);
        for i in 1..4 {
            let (previous, this) = (
                leaf_groups(i - 1, n, groups, overlap),
                leaf_groups(i, n, groups, overlap),
            );
            assert_eq!(this.iter().map(ExactSizeIterator::len).sum::<usize>(), n);
            let shared: Vec<usize> = (previous.iter().zip(&this))
                .map(|(p, t)| t.clone().filter(|s| p.contains(s)).count())
                .collect();
            assert_eq!(shared, [2, 1, 1]);
        }
        assert_eq!(leaf_groups(3, n, groups, 0), [12..16, 9..12, 9..12]);
        assert_eq!(leaf_groups(3, n, groups, 100), leaf_groups(0, n, groups, 100));
    }

    #[test]
    fn a_signer_set_tree_proves_and_its_root_verifies() {
        // End to end over both schemes: a level of three nodes, so its last takes one child, its other place absent,
        // and a root declaring half its union, checked against the set it is asked for and verified by it.
        let signers = Signers {
            capacity: Capacity { claims: 64, groups: 8 },
            groups: 2,
            overlap: 50,
            declare: Declare::Half,
        };
        let (leaf_prover, prover) = (Prover::new(Rate::MIN), Prover::new(Rate::MIN));
        for program in [LeafProgram::Leanxmss, LeafProgram::Leansphincs] {
            run_signers(program, 4, 6, 2, 2, signers, &leaf_prover, &prover, Plan::default());
        }
    }
}
