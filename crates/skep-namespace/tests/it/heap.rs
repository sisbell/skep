//! The test binary's global allocator — the system's, counting the heap bytes
//! each thread asks for — so a test measures one call's heap cost on its own
//! thread while the suite's other tests allocate on theirs. A cost claim then
//! becomes a number a regression changes at once, where a wall-clock bound
//! would flake and a slow test would pass. It counts BYTES, not allocations:
//! M1's `Nat` keeps a one-digit value inline, so copying a tumbler is one
//! allocation at any depth, and only that allocation's size tells a
//! fifty-thousand-component copy from a three-component one. "Heap"
//! throughout: this crate's other allocation, an address minted on a
//! frontier, is `allocation.rs`'s.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    // `const`-initialized, and a `Cell<u64>` needs no destructor, so the
    // counter is a plain thread-local with no lazy initializer and no
    // destructor to register: the allocator can touch it without reentering
    // itself.
    static HEAP_BYTES: Cell<u64> = const { Cell::new(0) };
}

/// Wrapping, so the count can never panic inside the allocator, which must
/// not unwind.
fn count(bytes: usize) {
    HEAP_BYTES.with(|n| n.set(n.get().wrapping_add(bytes as u64)));
}

/// `System`, counting.
struct CountingSystem;

// SAFETY: every method forwards its own arguments to `System` unchanged; the
// one addition, a thread-local wrapping add, neither allocates nor unwinds.
unsafe impl GlobalAlloc for CountingSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static COUNTING_SYSTEM: CountingSystem = CountingSystem;

/// Run `f` and return its value beside the heap bytes it asked for on this
/// thread — the size of every block it requested, fresh, zeroed or resized.
pub fn heap_bytes<T>(f: impl FnOnce() -> T) -> (T, u64) {
    let before = HEAP_BYTES.with(Cell::get);
    let value = f();
    (value, HEAP_BYTES.with(Cell::get).wrapping_sub(before))
}
