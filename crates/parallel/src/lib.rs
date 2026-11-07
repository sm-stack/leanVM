//! A fixed-size thread pool for flat data-parallel kernels.
//!
//! - Workers claim ranges from one shared counter, which also balances cores of different speeds.
//! - Dispatches cannot nest: a dispatch from a pool task panics, and one from a thread a task spawned deadlocks.
//! - A task panic is resumed on the dispatcher after every worker stops.

use std::sync::atomic::{AtomicUsize, Ordering};

mod pool;
mod topology;

pub use pool::{AlreadyConfigured, for_each_chunk, init, init_with_threads};
pub use topology::{Topology, num_threads, topology};

/// Claims per worker that a recommended chunk size aims for.
const CHUNK_OVERSUBSCRIBE: usize = 32;

/// The smallest chunk a recommended chunk size hands out.
const CHUNK_FLOOR: usize = 64;

/// The chunk size for a flat fan-out over `n_items`.
///
/// - Many chunks per worker, so the claim counter rebalances cores of different speeds.
/// - Chunks coarse enough to amortize the dispatch.
#[must_use]
#[inline]
pub fn recommended_chunk_size(n_items: usize) -> usize {
    n_items
        .div_ceil(num_threads() * CHUNK_OVERSUBSCRIBE)
        .max(CHUNK_FLOOR)
        .min(n_items.max(1))
}

/// `f(i)` for every `i` in `0..n_tasks`, in parallel. `#[inline]` folds the
/// range-to-index adapter into the monomorphized [`for_each_chunk`].
#[inline]
pub fn for_each<F: Fn(usize) + Sync>(n_tasks: usize, f: F) {
    for_each_chunk(n_tasks, |start, end| {
        for i in start..end {
            f(i);
        }
    });
}

/// A base `*mut` that can cross into the task closures. Sound only because
/// callers partition the allocation by item index; every dereference site
/// restates that.
#[derive(Debug)]
pub struct SendPtr<T>(pub *mut T);

// By hand: the derives would demand `T: Clone` and `T: Copy`.
impl<T> Clone for SendPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for SendPtr<T> {}

// SAFETY: `SendPtr` grants no access by itself; every dereference is inside an
// `unsafe` block whose comment establishes that the range being touched belongs
// to exactly one task, and the elements it reaches may move to that task's thread.
unsafe impl<T: Send> Send for SendPtr<T> {}
// SAFETY: sharing the pointer value is as harmless as sending it, for the reason above.
unsafe impl<T: Send> Sync for SendPtr<T> {}

impl<T> SendPtr<T> {
    /// Offset the base by `n` elements.
    ///
    /// # Safety
    /// `n` stays inside the allocation, and any write targets a slot no
    /// concurrent task touches.
    #[inline]
    pub const unsafe fn add(&self, n: usize) -> *mut T {
        // SAFETY: the caller keeps `n` inside the allocation.
        unsafe { self.0.add(n) }
    }

    /// Rebuild the `len`-element slice at element offset `off`.
    ///
    /// # Safety
    /// `off`/`len` are in bounds and disjoint from every other concurrent task's
    /// slice, and the underlying buffer outlives `'a`.
    #[inline]
    pub const unsafe fn slice<'a>(&self, off: usize, len: usize) -> &'a mut [T] {
        // SAFETY: the caller guarantees `off..off + len` is in bounds, borrowed by no other task, and alive for `'a`.
        unsafe { std::slice::from_raw_parts_mut(self.0.add(off), len) }
    }
}

/// Parallel `data.chunks_mut(chunk).enumerate().for_each(f)`; the final chunk may
/// be shorter.
pub fn chunks_mut<T: Send, F>(data: &mut [T], chunk: usize, f: F)
where
    F: Fn(usize, &mut [T]) + Sync,
{
    for_each_chunks_mut([data], [chunk], |i, [sub]| f(i, sub));
}

/// Parallel `a.chunks_mut(chunk).zip(b.chunks_mut(chunk))`, for the kernels that
/// fold two tables in lockstep. `a` and `b` must have equal length.
pub fn chunks_mut2<A: Send, B: Send, F>(a: &mut [A], b: &mut [B], chunk: usize, f: F)
where
    F: Fn(usize, &mut [A], &mut [B]) + Sync,
{
    assert_eq!(a.len(), b.len(), "chunks_mut2: slices differ in length");
    let b_ptr = SendPtr(b.as_mut_ptr());
    chunks_mut(a, chunk, |i, sub| {
        let start = i * chunk;
        // SAFETY: `b` has the same length as `a`, so chunk `i` of `b` is the same
        // in-bounds range that chunk `i` of `a` just proved disjoint.
        let sub_b = unsafe { b_ptr.slice(start, sub.len()) };
        f(i, sub, sub_b);
    });
}

/// A slice cut into chunks that tasks borrow by index, one chunk each.
///
/// It composes to any number of buffers, which the zip-based helpers do not.
///
/// A kernel writing four tables at two widths builds one view per table and indexes them all by the same item.
#[derive(Debug)]
pub struct ChunkView<T> {
    /// The slice's first element.
    base: SendPtr<T>,
    /// The elements per chunk; the last chunk may hold fewer.
    width: usize,
    /// The slice's length.
    len: usize,
}

// By hand: the derives would demand `T: Clone` and `T: Copy`.
impl<T> Clone for ChunkView<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for ChunkView<T> {}

impl<T> ChunkView<T> {
    /// View `data` as `len.div_ceil(width)` chunks of `width` (the last shorter).
    #[must_use]
    pub fn new(data: &mut [T], width: usize) -> Self {
        assert!(width > 0, "chunk width must be non-zero");
        Self {
            base: SendPtr(data.as_mut_ptr()),
            width,
            len: data.len(),
        }
    }

    /// The number of chunks.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len.div_ceil(self.width)
    }

    /// Whether the view holds no chunk.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Chunk `i`.
    ///
    /// # Safety
    ///
    /// - `i` is below the number of chunks.
    /// - No other live borrow covers chunk `i`.
    /// - The underlying buffer outlives `'a`.
    ///
    /// Taking each chunk once inside a parallel loop over the chunks satisfies all three.
    #[inline]
    pub unsafe fn get<'a>(&self, i: usize) -> &'a mut [T] {
        let start = i * self.width;
        debug_assert!(start < self.len);
        // SAFETY: `i < len()` puts `start` below `len`, so `start..start + min(width, len - start)` lies in
        // the slice `new` took; the caller guarantees no other borrow of it and that it outlives `'a`.
        unsafe { self.base.slice(start, self.width.min(self.len - start)) }
    }
}

/// [`map_reduce_with_state`] over the chunks of `N` buffers: task `i` gets chunk `i` of each, so a kernel
/// writing several tables takes its slices of all of them.
///
/// Buffer `k` is cut into chunks of `widths[k]`, the last shorter. There are as many tasks as the
/// buffer with the most chunks has, and a buffer with fewer gives an empty slice to the tasks past its end.
pub fn map_reduce_chunks_mut<T, const N: usize, S, A, IS, IA, F, C>(
    bufs: [&mut [T]; N],
    widths: [usize; N],
    init_state: IS,
    init_acc: IA,
    fold: F,
    combine: C,
) -> A
where
    T: Send,
    S: Send,
    A: Send,
    IS: Fn() -> S + Sync,
    IA: Fn() -> A + Sync,
    F: Fn(&mut S, &mut A, usize, [&mut [T]; N]) + Sync,
    C: Fn(A, A) -> A,
{
    let views = chunk_views(bufs, widths);
    let n_tasks = views.iter().map(ChunkView::len).max().unwrap_or(0);
    map_reduce_with_state(
        n_tasks,
        init_state,
        init_acc,
        |state, acc, i| {
            // SAFETY: the dispatch runs each task `i` once, and `bufs` stays borrowed until it returns.
            fold(state, acc, i, unsafe { task_chunks(&views, i) });
        },
        combine,
    )
}

/// [`map_reduce_chunks_mut`] without the reduction: `f(i, chunks)` for every task `i`, in parallel.
fn for_each_chunks_mut<T: Send, const N: usize, F>(bufs: [&mut [T]; N], widths: [usize; N], f: F)
where
    F: Fn(usize, [&mut [T]; N]) + Sync,
{
    let views = chunk_views(bufs, widths);
    let n_tasks = views.iter().map(ChunkView::len).max().unwrap_or(0);
    // SAFETY: the dispatch runs each task `i` once, and `bufs` stays borrowed until it returns.
    for_each(n_tasks, |i| f(i, unsafe { task_chunks(&views, i) }));
}

fn chunk_views<T, const N: usize>(bufs: [&mut [T]; N], widths: [usize; N]) -> [ChunkView<T>; N] {
    let mut widths = widths.into_iter();
    bufs.map(|buf| ChunkView::new(buf, widths.next().expect("one width per buffer")))
}

/// Task `i`'s chunk of each view, or an empty slice for a view with fewer chunks.
///
/// # Safety
/// Each `i` is taken once per dispatch, inside a [`for_each`] body, and the buffers behind the views
/// stay borrowed until it returns.
unsafe fn task_chunks<'a, T, const N: usize>(views: &[ChunkView<T>; N], i: usize) -> [&'a mut [T]; N] {
    // SAFETY: by the caller's contract, chunk `i` of each buffer is taken once, so the slices are disjoint.
    views.each_ref().map(|view| {
        if i < view.len() {
            unsafe { view.get(i) }
        } else {
            &mut []
        }
    })
}

/// Parallel `dst.chunks_mut(chunk).zip(src.chunks(chunk))`, for a kernel that
/// writes one table while reading another of the same length.
pub fn chunks_mut_zip<T: Send, S: Sync, F>(dst: &mut [T], src: &[S], chunk: usize, f: F)
where
    F: Fn(usize, &mut [T], &[S]) + Sync,
{
    assert_eq!(dst.len(), src.len(), "chunks_mut_zip: slices differ in length");
    chunks_mut(dst, chunk, |i, sub| {
        let start = i * chunk;
        f(i, sub, &src[start..start + sub.len()]);
    });
}

/// Parallel `data.iter_mut().enumerate().for_each(f)`, chunked by
/// [`recommended_chunk_size`]. Hands the closure each element's **global** index.
#[inline]
pub fn for_each_mut<T: Send, F>(data: &mut [T], f: F)
where
    F: Fn(usize, &mut T) + Sync,
{
    let chunk = recommended_chunk_size(data.len());
    chunks_mut(data, chunk, |chunk_index, values| {
        for (offset, slot) in values.iter_mut().enumerate() {
            f(chunk_index * chunk + offset, slot);
        }
    });
}

/// Parallel `for (i, slot) in dst.iter_mut().enumerate() { *slot = build(i) }`.
/// The in-place counterpart of [`map_collect`], which allocates.
#[inline]
pub fn fill<T: Send, F: Fn(usize) -> T + Sync>(dst: &mut [T], build: F) {
    for_each_mut(dst, |i, slot| *slot = build(i));
}

/// Parallel `(0..n_tasks).map(f).collect::<Vec<_>>()`: runs `f(i)` across the
/// pool and writes each result straight into the output at its own index: one
/// allocation, no `Option` slots, no per-worker intermediate vectors.
pub fn map_collect<T: Send, F: Fn(usize) -> T + Sync>(n_tasks: usize, f: F) -> Vec<T> {
    let mut out: Vec<T> = Vec::with_capacity(n_tasks);
    let base = SendPtr(out.as_mut_ptr());
    for_each(n_tasks, |i| {
        // SAFETY: distinct `i` write disjoint in-bounds slots, each exactly once,
        // and the dispatch blocks until every write is finished. A panic in `f`
        // leaks the slots written so far, which is acceptable: a task panic is
        // re-raised on the dispatcher and fails the proof.
        unsafe { base.add(i).write(f(i)) };
    });
    // SAFETY: every slot in `0..n_tasks` was initialized exactly once above.
    unsafe { out.set_len(n_tasks) };
    out
}

/// The smallest `i` in `0..n_tasks` with `pred(i)`, or `None`. Deterministic
/// regardless of how the claims fall, because the answer is the global minimum
/// rather than whichever hit landed first.
///
/// Workers publish hits into a shared minimum and skip any claim that starts past
/// it, so the search stops early without giving up determinism.
pub fn find_first<P: Fn(usize) -> bool + Sync>(n_tasks: usize, pred: P) -> Option<usize> {
    let best = AtomicUsize::new(usize::MAX);
    for_each_chunk(n_tasks, |start, end| {
        if start >= best.load(Ordering::Relaxed) {
            return; // a smaller hit already exists
        }
        for i in start..end {
            if pred(i) {
                best.fetch_min(i, Ordering::Relaxed);
                return; // later hits in this claim are larger
            }
        }
    });
    let index = best.load(Ordering::Relaxed);
    (index != usize::MAX).then_some(index)
}

/// One slot per cache line: a worker writes through its accumulator on the
/// per-item path, so a dense array would false-share the boundary lines. 128
/// rather than 64 for the same reason the pool's counters are, and because that is the line
/// itself on Apple silicon.
#[repr(align(128))]
struct Slot<S>(Option<S>);

/// Give each worker its own persistent `Option<S>` while it drains `0..n_tasks`:
/// `run(slot, start, end)` fires once per claim with that worker's slot, so state
/// accumulates across its claims. Returns the slots (the rest `None`) for the
/// caller to combine.
fn drain_into_slots<S: Send>(n_tasks: usize, run: impl Fn(&mut Option<S>, usize, usize) + Sync) -> Vec<Slot<S>> {
    let mut slots: Vec<Slot<S>> = (0..num_threads()).map(|_| Slot(None)).collect();
    let view = ChunkView::new(&mut slots, 1);
    for_each_chunk(n_tasks, |start, end| {
        // SAFETY: the worker index is below the thread count and unique per live worker, so no other live borrow
        // covers its slot; the slots outlive the dispatch.
        let slot = unsafe { view.get(pool::worker_id()) };
        run(&mut slot[0].0, start, end);
    });
    slots
}

/// Parallel map-reduce over `0..n_tasks`, i.e. `(0..n).map(map).reduce(identity,
/// reduce)`. Each worker folds its claimed indices into one local partial; the
/// partials combine on the dispatcher. `reduce` must be associative with
/// `identity()` a neutral element.
pub fn map_reduce<T, ID, M, R>(n_tasks: usize, identity: ID, map: M, reduce: R) -> T
where
    T: Send,
    ID: Fn() -> T,
    M: Fn(usize) -> T + Sync,
    R: Fn(T, T) -> T + Sync,
{
    let slots = drain_into_slots(n_tasks, |slot, start, end| {
        // Fold the claim into the worker's partial, seeded by the first `map` so
        // `identity` stays off the per-item path; touch the slot once per claim.
        *slot = (start..end).fold(slot.take(), |acc, i| {
            Some(acc.map_or_else(|| map(i), |partial| reduce(partial, map(i))))
        });
    });
    // `identity()` seeds the combine as a left identity, which makes the empty
    // and single-worker cases fall out without a special path.
    slots.into_iter().filter_map(|s| s.0).fold(identity(), &reduce)
}

/// Parallel fold-then-reduce: each worker builds one accumulator with `init`,
/// folds every index it claims into it, and the accumulators `combine` on the
/// dispatcher. `combine` must be associative with `init()` a neutral element.
///
/// This is the shape for a reduction whose accumulator is itself a buffer (a
/// 64-slot bit-fold, say): the buffer is allocated once per worker rather than
/// once per item, and no two workers share a cache line.
pub fn fold_reduce<A, I, F, C>(n_tasks: usize, init: I, fold: F, combine: C) -> A
where
    A: Send,
    I: Fn() -> A + Sync,
    F: Fn(&mut A, usize) + Sync,
    C: Fn(A, A) -> A,
{
    map_reduce_with_state(n_tasks, || (), &init, |_, acc, i| fold(acc, i), combine)
}

/// Parallel reduce where each worker keeps reusable scratch beside its
/// accumulator, so the per-item body need not allocate. `(scratch, acc)` are
/// created once per worker and threaded through its claims; the accumulators
/// combine on the dispatcher. `combine` must be associative with `init_acc()` a
/// neutral element.
pub fn map_reduce_with_state<S, A, IS, IA, F, C>(n_tasks: usize, init_state: IS, init_acc: IA, fold: F, combine: C) -> A
where
    S: Send,
    A: Send,
    IS: Fn() -> S + Sync,
    IA: Fn() -> A + Sync,
    F: Fn(&mut S, &mut A, usize) + Sync,
    C: Fn(A, A) -> A,
{
    let slots = drain_into_slots(n_tasks, |slot, start, end| {
        let (state, acc) = slot.get_or_insert_with(|| (init_state(), init_acc()));
        for i in start..end {
            fold(state, acc, i);
        }
    });
    slots
        .into_iter()
        .filter_map(|s| s.0)
        .map(|(_, acc)| acc)
        .fold(init_acc(), &combine)
}
