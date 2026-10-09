//! The test binary's global allocator — the system's, counting the heap bytes
//! each thread asks for — so a test measures one call's heap cost on its own
//! thread while the suite's other tests allocate on theirs. A cost claim then
//! becomes a number a regression changes at once, where a wall-clock bound
//! would flake and a slow test would pass. It counts BYTES, not allocations:
//! M1's `Nat` keeps a one-digit value inline, so copying a tumbler is one
//! allocation at any depth, and only that allocation's size tells a
//! fifty-thousand-component copy from a three-component one. The module's
//! one test holds the counter to exactly that. "Heap" throughout: this
//! crate's other allocation, an address minted on a frontier, is
//! `allocation.rs`'s.

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

/// The instrument's own claim, which every cost test in this binary stands
/// on: a copy shows, and a deep copy shows as MORE than a shallow one. The
/// cost tests assert that two calls ask the heap for EQUAL bytes — an
/// equality a counter that counted nothing would satisfy at every depth, as
/// would one that counted blocks rather than bytes, since a tumbler copy is
/// one block at any depth. Either would turn every cost test green for the
/// wrong reason; this is what goes red instead.
#[test]
fn the_counter_sees_a_copy_and_tells_its_depth() {
    let address = |len: usize| {
        let mut comps = vec![1u32, 0];
        comps.extend(std::iter::repeat_n(1u32, len - 2));
        crate::common::a(&comps)
    };
    let (shallow, deep) = (address(3), address(1_000));
    let (_, shallow_bytes) = heap_bytes(|| shallow.clone());
    let (_, deep_bytes) = heap_bytes(|| deep.clone());
    assert!(shallow_bytes > 0, "the counter saw no copy at all");
    assert!(
        deep_bytes > shallow_bytes,
        "the counter cannot tell a 1000-component copy ({deep_bytes} bytes) from a 3-component one ({shallow_bytes})"
    );
}
