//! What a decoded value holds on the heap, counted: the test binary's
//! global allocator is the system's, keeping for each thread the bytes it
//! holds — every block asked for, less every block given back. A claim that
//! a decoded tumbler holds what a built one holds is then two numbers set
//! side by side. It counts the sizes asked for, never the allocator's own
//! rounding, and each thread counts alone.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use serde::de::value::Error as Refused;
use serde::de::IntoDeserializer;
use serde::Deserialize;
use skep_address::{Address, Nat, Span, Tumbler};

use crate::common::*;

thread_local! {
    // `const`-initialized, and a `Cell<i64>` needs no destructor, so the
    // slot is a plain thread-local with no lazy initializer and no
    // destructor to register: the allocator can touch it without
    // reentering itself.
    static LIVE: Cell<i64> = const { Cell::new(0) };
}

/// Wrapping, so the count can never panic inside the allocator, which must
/// not unwind.
fn moved(by: i64) {
    LIVE.with(|live| live.set(live.get().wrapping_add(by)));
}

/// `System`, counting.
struct CountingSystem;

// SAFETY: every method forwards its own arguments to `System` unchanged; the
// one addition, a thread-local cell written, neither allocates nor unwinds.
unsafe impl GlobalAlloc for CountingSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let block = unsafe { System.alloc(layout) };
        if !block.is_null() {
            moved(layout.size() as i64);
        }
        block
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let block = unsafe { System.alloc_zeroed(layout) };
        if !block.is_null() {
            moved(layout.size() as i64);
        }
        block
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let block = unsafe { System.realloc(ptr, layout, new_size) };
        if !block.is_null() {
            moved(new_size as i64 - layout.size() as i64);
        }
        block
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
        moved(-(layout.size() as i64));
    }
}

#[global_allocator]
static COUNTING_SYSTEM: CountingSystem = CountingSystem;

/// Runs `f` and returns its value beside the bytes it left live on this
/// thread: what the value it answered holds on the heap.
fn held<T>(f: impl FnOnce() -> T) -> (T, i64) {
    let before = LIVE.with(Cell::get);
    let value = f();
    (value, LIVE.with(Cell::get) - before)
}

/// The base-2³² digits a number is written as, least significant first:
/// none for zero.
fn digits(n: &Nat) -> Vec<u32> {
    n.iter_u32_digits().collect()
}

/// `comps` decoded as a tumbler from a form that declares every length, as
/// a checkpoint's codec does: each component its digits, each sequence's
/// count known before its first element.
fn decoded(comps: &[Nat]) -> Tumbler {
    let written: Vec<Vec<u32>> = comps.iter().map(digits).collect();
    Tumbler::deserialize(IntoDeserializer::<Refused>::into_deserializer(written)).expect("a nonempty component sequence decodes")
}

#[test]
fn a_decoded_tumbler_holds_what_a_built_one_holds() {
    // An element address's eight components, five of them nonzero and each
    // one machine word: built, the tumbler holds one block, its components'
    // own room, a digit inside each. Decoded from a form that declares each
    // component's digit count, each nonzero component arrives holding a
    // one-digit block of its own; the door re-makes it, and the decoded
    // tumbler holds what the built one does.
    let comps: Vec<Nat> = [1u32, 0, 1, 0, 64, 0, 1, 7_000].map(Nat::from).to_vec();
    let (built, built_bytes) = held(|| tumbler(comps.clone()));
    let (read, read_bytes) = held(|| decoded(&comps));
    assert_eq!(read, built);
    assert_eq!(built_bytes, (comps.len() * std::mem::size_of::<Nat>()) as i64, "a built tumbler: its components' room and nothing beside");
    assert_eq!(read_bytes, built_bytes, "a decoded tumbler holds what a built one holds");
    // A component of a whole machine word, its two halves both written.
    let comps = vec![n(1), Nat::from(u64::MAX), n(3)];
    let (built, built_bytes) = held(|| tumbler(comps.clone()));
    let (read, read_bytes) = held(|| decoded(&comps));
    assert_eq!((read, read_bytes), (built, built_bytes), "a component of one full word");
    // A component past a machine word keeps its digits, as a built one
    // does: two words, and three.
    for wide in [beyond_u64(), Nat::from(u128::MAX) + n(9)] {
        let comps = vec![n(1), wide.clone(), n(0), n(5)];
        let (built, built_bytes) = held(|| tumbler(comps.clone()));
        let (read, read_bytes) = held(|| decoded(&comps));
        assert_eq!(read, built, "a wide component decodes equal");
        assert_eq!(read.get(2), Some(&wide));
        assert_eq!(read_bytes, built_bytes, "a wide component keeps its digits and no more");
        assert!(built_bytes > (comps.len() * std::mem::size_of::<Nat>()) as i64, "the premise: a wide component holds digits on the heap");
    }
    // An address and a span are their tumblers: decoded through the same
    // door, they hold what built ones hold. Each written form is made and
    // dropped inside the count, so the count is the decoded value's alone.
    let element = [1u32, 0, 2, 0, 67, 0, 1, 9].map(Nat::from).to_vec();
    let (built, built_bytes) = held(|| addr(&[1, 0, 2, 0, 67, 0, 1, 9]));
    let (read, read_bytes) = held(|| {
        let written: Vec<Vec<u32>> = element.iter().map(digits).collect();
        Address::deserialize(IntoDeserializer::<Refused>::into_deserializer(written)).expect("an address decodes")
    });
    assert_eq!((read, read_bytes), (built, built_bytes), "a decoded address");
    let (built, built_bytes) = held(|| sp(&[1, 0, 2, 0, 67, 0, 1, 9], &[1, 0, 2, 0, 67, 0, 1, 12]));
    let (read, read_bytes) = held(|| {
        // A span writes as its start and its width, a pair: read here as
        // a sequence of the two.
        let pair = vec![
            built.start().iter().map(digits).collect::<Vec<_>>(),
            built.width().iter().map(digits).collect::<Vec<_>>(),
        ];
        Span::deserialize(IntoDeserializer::<Refused>::into_deserializer(pair)).expect("a span decodes")
    });
    assert_eq!((read, read_bytes), (built, built_bytes), "a decoded span");
}
