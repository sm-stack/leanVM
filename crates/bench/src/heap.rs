//! Memory as a benchmark sees it: the allocator, the heap it counts, and the resident set.
//!
//! - The global allocator of the CLI and the proving benchmarks keeps every page it maps.
//! - The heap counted over a window is what the code needs.
//! - The resident set mixes that with what the allocator keeps.
//!
//! Why the allocator keeps its pages:
//!
//! ```text
//!     proof 1: pages faulted in, then freed  ->  kept mapped in the allocator's cache
//!     proof 2: pages served from the cache   ->  no fault
//! ```
//!
//! The cost is resident memory: the process holds its peak until it exits.
//!
//! On Linux every mapping also asks for transparent huge pages.
//!
//! So the first proof faults one 2 MiB page where it would fault 512 small ones, and the buffers take fewer TLB entries.

use std::alloc::{GlobalAlloc, Layout};
use std::cell::Cell;
use std::sync::atomic::{AtomicIsize, AtomicU64, AtomicUsize, Ordering::Relaxed};

pub use tikv_jemallocator::Jemalloc;

/// jemalloc's configuration, which it reads before its first allocation.
///
/// - Dirty pages never decay, so freed memory never returns to the kernel.
/// - Every extent asks for transparent huge pages, and so does jemalloc's own metadata once it grows large; the kernel's mode decides whether they get them.
/// - jemalloc reads a C string pointer here, which a reference to a byte array is.
#[cfg(all(target_os = "linux", not(target_arch = "arm")))]
#[unsafe(export_name = "_rjem_malloc_conf")]
static MALLOC_CONF: &[u8; 47] = b"dirty_decay_ms:-1,thp:always,metadata_thp:auto\0";

/// jemalloc's configuration where it has no huge page support, and would warn about the option.
#[cfg(not(all(target_os = "linux", not(target_arch = "arm"))))]
#[unsafe(export_name = "_rjem_malloc_conf")]
static MALLOC_CONF: &[u8; 18] = b"dirty_decay_ms:-1\0";

/// A global allocator that counts what the one it wraps hands out, installed as `Counting(Jemalloc)`.
///
/// - Each thread counts its allocations on a cache line of its own, so the count is exact.
/// - Each thread folds its bytes into one global live count only once they move by 64 KiB or more.
/// - The peak is taken when they fold, so a window's peak is within 64 KiB per thread of the true one.
pub struct Counting<A>(pub A);

/// Bytes a thread allocates or frees before it folds them into the global live count.
const BATCH: usize = 64 << 10;

/// Live bytes, short of the true count by each thread's unfolded bytes.
static LIVE: AtomicIsize = AtomicIsize::new(0);

/// The most live bytes reached since the innermost open window opened.
static PEAK: AtomicIsize = AtomicIsize::new(0);

/// Allocation counters, one per thread, each on a cache line of its own.
///
/// Threads past this many share them.
const SLOTS: usize = 128;

/// One allocation counter, alone on its cache line so threads never contend for it.
#[repr(align(128))]
struct Slot(AtomicU64);

/// The allocation counters.
static ALLOCATIONS: [Slot; SLOTS] = [const { Slot(AtomicU64::new(0)) }; SLOTS];

/// The counter the next thread to allocate takes.
static NEXT_SLOT: AtomicUsize = AtomicUsize::new(0);

/// A thread's allocation counter and the bytes it has not folded yet.
struct Local {
    /// The thread's counter, or `usize::MAX` before its first allocation.
    slot: Cell<usize>,
    /// The bytes allocated less those freed since the last fold.
    unfolded: Cell<isize>,
}

thread_local! {
    // Constant and without a destructor, so reading it never allocates, even as the thread exits.
    static LOCAL: Local = const {
        Local {
            slot: Cell::new(usize::MAX),
            unfolded: Cell::new(0),
        }
    };
}

/// Counts an allocation that moved the live bytes by `bytes`, or with `allocations` zero a free.
#[inline]
fn record(bytes: isize, allocations: u64) {
    LOCAL.with(|local| {
        if allocations != 0 {
            let mut slot = local.slot.get();
            if slot == usize::MAX {
                slot = NEXT_SLOT.fetch_add(1, Relaxed) % SLOTS;
                local.slot.set(slot);
            }
            ALLOCATIONS[slot].0.fetch_add(allocations, Relaxed);
        }
        let unfolded = local.unfolded.get() + bytes;
        if unfolded.unsigned_abs() < BATCH {
            local.unfolded.set(unfolded);
            return;
        }
        local.unfolded.set(0);
        let live = LIVE.fetch_add(unfolded, Relaxed) + unfolded;
        if live > PEAK.load(Relaxed) {
            PEAK.fetch_max(live, Relaxed);
        }
    });
}

/// Every allocation counted so far, by every thread.
fn allocations() -> u64 {
    ALLOCATIONS.iter().map(|slot| slot.0.load(Relaxed)).sum()
}

// SAFETY: every call is forwarded to `A` unchanged; counting only reads the sizes.
unsafe impl<A: GlobalAlloc> GlobalAlloc for Counting<A> {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract, passed on.
        let ptr = unsafe { self.0.alloc(layout) };
        if !ptr.is_null() {
            record(layout.size() as isize, 1);
        }
        ptr
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract, passed on.
        let ptr = unsafe { self.0.alloc_zeroed(layout) };
        if !ptr.is_null() {
            record(layout.size() as isize, 1);
        }
        ptr
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract, passed on.
        unsafe { self.0.dealloc(ptr, layout) };
        record(-(layout.size() as isize), 0);
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller's contract, passed on.
        let new = unsafe { self.0.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            record(new_size as isize - layout.size() as isize, 1);
        }
        new
    }
}

/// What a window of the program allocated, as the counting allocator saw it.
///
/// Zero where the counting allocator is not the global one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Heap {
    /// The most bytes live at once above those live when the window opened, within 64 KiB per thread.
    pub peak: u64,
    /// Allocations and reallocations, exact.
    pub allocations: u64,
}

/// An open window of the program, measuring the heap until it closes.
///
/// Windows nest as spans do: an inner window closes first, and its peak counts towards the outer one's.
#[must_use = "a window measures until it is closed"]
pub(crate) struct HeapWindow {
    /// The live bytes when the window opened.
    live: isize,
    /// The enclosing window's peak, restored when this one closes.
    outer_peak: isize,
    /// The allocations counted when the window opened.
    allocations: u64,
}

/// A closed window, in the raw counts a trace tree compares across spans.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ClosedWindow {
    /// The live bytes when the window opened.
    pub(crate) opened: isize,
    /// The most live bytes while it was open.
    pub(crate) peak: isize,
    /// The allocations made while it was open.
    pub(crate) allocations: u64,
}

impl HeapWindow {
    /// Opens a window at the current live count.
    pub(crate) fn open() -> Self {
        let live = LIVE.load(Relaxed);
        Self {
            live,
            outer_peak: PEAK.swap(live, Relaxed),
            allocations: allocations(),
        }
    }

    /// Closes the window, handing its peak on to the enclosing one.
    pub(crate) fn close(self) -> ClosedWindow {
        let peak = PEAK.fetch_max(self.outer_peak, Relaxed);
        ClosedWindow {
            opened: self.live,
            peak,
            allocations: allocations() - self.allocations,
        }
    }
}

impl ClosedWindow {
    /// The window's heap above `base` live bytes.
    pub(crate) fn heap_above(&self, base: isize) -> Heap {
        Heap {
            peak: (self.peak - base).max(0) as u64,
            allocations: self.allocations,
        }
    }

    /// The window's heap above the bytes live when it opened.
    pub(crate) fn heap(&self) -> Heap {
        self.heap_above(self.opened)
    }
}

/// Runs `f` and measures the heap it uses.
pub fn measure_heap<T>(f: impl FnOnce() -> T) -> (T, Heap) {
    let window = HeapWindow::open();
    let out = f();
    (out, window.close().heap())
}

/// The peak resident set size of this process, in bytes.
///
/// It mixes what the code needs with what the allocator keeps.
#[must_use]
pub fn peak_rss_bytes() -> u64 {
    // SAFETY: `rusage` is a plain C struct of integers, for which all-zero bytes are a valid value.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `getrusage` only writes into the `rusage` handed to it, a live, correctly sized local.
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &raw mut usage) };
    let max = usage.ru_maxrss as u64;
    // The kernel reports bytes on macOS and KiB on Linux.
    if cfg!(target_os = "macos") { max } else { max * 1024 }
}

/// Whether the counting allocator is the global one: it has counted an allocation.
pub(crate) fn counting() -> bool {
    allocations() != 0
}

#[cfg(test)]
mod tests {
    use super::{Counting, Heap, HeapWindow};
    use std::alloc::{GlobalAlloc, Layout, System};

    #[test]
    fn an_inner_window_peak_counts_towards_the_outer_one() {
        let counting = Counting(System);
        let mib = |n: usize| Layout::from_size_align(n << 20, 8).unwrap();
        // The test binary's global allocator does not count.
        // So these blocks, each large enough to fold, are the only counted allocations.
        //
        // SAFETY: each block is freed once, with the layout it was allocated with.
        unsafe {
            let outer = HeapWindow::open();
            let held = counting.alloc(mib(1));
            let inner = HeapWindow::open();
            let freed = counting.alloc(mib(2));
            counting.dealloc(freed, mib(2));
            let grown = counting.realloc(held, mib(1), 3 << 20);
            let inner = inner.close().heap();
            counting.dealloc(grown, mib(3));
            let after = HeapWindow::open();
            let small = counting.alloc(mib(1));
            counting.dealloc(small, mib(1));
            let after = after.close().heap();
            let outer = outer.close().heap();

            let heap = |mib: u64, allocations| Heap {
                peak: mib << 20,
                allocations,
            };
            assert_eq!(inner, heap(2, 2), "above the 1 MiB held when it opened");
            assert_eq!(
                after,
                heap(1, 1),
                "a window after the inner one starts from its own opening"
            );
            assert_eq!(
                outer,
                heap(3, 4),
                "the inner window's peak, and every allocation in or out of it"
            );
        }
    }
}
