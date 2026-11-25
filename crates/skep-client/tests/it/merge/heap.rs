//! The test binary's global allocator — the system's, counting on each
//! thread the heap bytes asked for and the most held at once — so a merge
//! cell measures one composition's heap on its own thread while the suite's
//! other tests, and an in-process daemon's threads, allocate on theirs, as
//! skep-discovery's integration suite measures its reads (`tests/it/heap.rs`
//! there). Declared here, it is the whole binary's allocator. A cost claim
//! then becomes a number a regression changes at once, where a wall-clock
//! bound would flake. It counts *bytes*, not allocations: what a call keeps
//! of a read is told by how many bytes stand, never by how many blocks hold
//! them.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    // `const`-initialized, and a `Cell` of a number needs no destructor, so
    // each slot is a plain thread-local with no lazy initializer and no
    // destructor to register: the allocator can touch it without reentering
    // itself.
    static REQUESTED: Cell<u64> = const { Cell::new(0) };
    static LIVE: Cell<i64> = const { Cell::new(0) };
    static PEAK: Cell<i64> = const { Cell::new(0) };
}

/// Counts a block of `asked` bytes requested, `held` the change in the bytes
/// this thread holds.
///
/// Wrapping, so the count can never panic inside the allocator, which must
/// not unwind. A block freed on another thread than its own lowers that
/// thread's count, which only a call's own thread is measured by.
fn count(asked: usize, held: i64) {
    REQUESTED.with(|n| n.set(n.get().wrapping_add(asked as u64)));
    LIVE.with(|live| {
        let now = live.get().wrapping_add(held);
        live.set(now);
        PEAK.with(|peak| peak.set(peak.get().max(now)));
    });
}

/// `System`, counting.
struct CountingSystem;

// SAFETY: every method forwards its own arguments to `System` unchanged; the
// one addition, thread-local wrapping adds and a max, neither allocates nor
// unwinds.
unsafe impl GlobalAlloc for CountingSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size(), layout.size() as i64);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count(layout.size(), layout.size() as i64);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // The old block stands until the new one holds its bytes.
        count(new_size, new_size as i64);
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        count(0, -(layout.size() as i64));
        moved
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        count(0, -(layout.size() as i64));
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static COUNTING_SYSTEM: CountingSystem = CountingSystem;

/// The heap one call used on its thread.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Heap {
    /// The bytes of every block it requested — fresh, zeroed or resized.
    pub(crate) requested: u64,
    /// The most bytes it held at once above what stood before it, what it
    /// returns among them.
    pub(crate) peak: u64,
}

/// Runs `f` and returns its value beside the heap it used on this thread.
pub(crate) fn measured<T>(f: impl FnOnce() -> T) -> (T, Heap) {
    let requested = REQUESTED.with(Cell::get);
    let live = LIVE.with(Cell::get);
    PEAK.with(|peak| peak.set(live));
    let value = f();
    let heap = Heap {
        requested: REQUESTED.with(Cell::get).wrapping_sub(requested),
        peak: u64::try_from(PEAK.with(Cell::get).wrapping_sub(live)).unwrap_or(0),
    };
    (value, heap)
}
