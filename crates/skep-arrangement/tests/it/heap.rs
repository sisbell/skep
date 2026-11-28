//! What the slice keeps live, counted: the test binary's global allocator is
//! the system's, keeping for each thread the bytes it holds — every block
//! asked for, less every block given back — and the most it has held since
//! the count was last marked. A claim about what a version keeps then
//! becomes a number a regression moves at once, where a wall-clock bound
//! would flake. It counts the sizes asked for, never the allocator's own
//! rounding, and each thread counts alone, so a cell measures on its own
//! thread while the suite's other cells allocate on theirs.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use skep_address::Address;
use skep_arrangement::{Caller, Change, Edit, HasM5, Placed, Shot, Vstream};
use skep_kernel::Kernel;
use skep_namespace::PrincipalId;
use tempfile::tempdir;

use crate::common::*;

thread_local! {
    // `const`-initialized, and a `Cell<i64>` needs no destructor, so each
    // slot is a plain thread-local with no lazy initializer and no
    // destructor to register: the allocator can touch it without reentering
    // itself.
    static LIVE: Cell<i64> = const { Cell::new(0) };
    static MOST: Cell<i64> = const { Cell::new(0) };
}

/// Wrapping, so the count can never panic inside the allocator, which must
/// not unwind.
fn moved(by: i64) {
    LIVE.with(|live| {
        let now = live.get().wrapping_add(by);
        live.set(now);
        MOST.with(|most| most.set(most.get().max(now)));
    });
}

/// `System`, counting.
struct CountingSystem;

// SAFETY: every method forwards its own arguments to `System` unchanged; the
// one addition, two thread-local cells written, neither allocates nor
// unwinds.
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

/// The bytes this thread holds live.
fn live() -> i64 {
    LIVE.with(Cell::get)
}

/// Runs `f` and returns its value beside the bytes it left live on this
/// thread: what it asked for and did not give back.
fn kept<T>(f: impl FnOnce() -> T) -> (T, i64) {
    let before = live();
    let value = f();
    (value, live() - before)
}

/// Runs `f` and returns its value beside the most bytes this thread held
/// during it above what it held at the start.
fn most_above<T>(f: impl FnOnce() -> T) -> (T, i64) {
    let before = live();
    MOST.with(|most| most.set(before));
    let value = f();
    (value, MOST.with(Cell::get) - before)
}

/// How many runs the member under the cell holds.
const RUNS: u32 = 65_536;

/// The principal that owns the fork the cell edits, and the one that
/// versions it.
const EDITOR: PrincipalId = PrincipalId(2);
const KEEPER: PrincipalId = PrincipalId(3);

/// One edit of `changes` changes spread over `doc`'s `RUNS` positions, each
/// replacing one position with one fresh value.
fn spread(changes: u32) -> Edit {
    let changes = (0..u64::from(changes))
        .map(|j| {
            let at = ((2 * j + 1) * u64::from(RUNS) / (2 * u64::from(changes))) as u32 + 1;
            Change { at: vp(1, at), width: n(1), placed: Placed::Values(vec![val(b"y")]) }
        })
        .collect();
    Edit { changes, head: None, base: None, merge: None }
}

/// Edits `doc` by `edit` and keeps a version of what the edit left.
fn edit_and_keep(k: &Kernel<World>, doc: &Address, edit: Edit) {
    let vs = Vstream::new(k);
    vs.edit(Caller::Principal(EDITOR), doc, edit, now(k)).expect("the edit lands");
    vs.version(KEEPER, doc, Some(false)).expect("a version of the edited document");
}

/// The slice's checkpoint form, in bytes.
fn slice_bytes(k: &Kernel<World>) -> usize {
    bincode::serialize(k.snapshot().world().m5()).expect("the slice serializes").len()
}

/// A version keeps what its change made, never a list of its own.
///
/// A member of 65,536 runs is forked, and the fork edited twenty times, a
/// version kept after each edit: ten edits of one change, then ten of 256
/// changes spread over the list. Every version holds the list as its edit
/// left it, and the fork's next edit leaves that list standing. What each
/// round adds to the bytes held live is counted, and a round of one change
/// must add less than a thousandth of what the member's list holds, and
/// one of 256 changes less than a tenth: a round that kept a whole list of
/// its own adds as much as the member did. A round of one change adds
/// about 6.4 kB — the nodes on its change's path, the span its placed run
/// appends to R, and the version's own entries — against the member's
/// 16.6 MB.
///
/// Then the board is checkpointed, twice with a round between, closed, and
/// opened again: the opened board holds what the board held before its
/// first checkpoint, to within a twentieth — the lists sharing as they
/// shared, and no number decoded holding more than one built.
///
/// The figures are printed, the bounds alone asserted: the bytes a run of
/// the member's list holds, what each round adds, the slice's checkpoint
/// form after each ten rounds, the most a checkpoint's encode holds above
/// the live store — the first, which no earlier checkpoint sizes, and a
/// second, sized by the first — and what the board holds before its
/// checkpoints and after the open.
#[test]
fn a_version_keeps_what_its_change_made_and_not_a_list_of_its_own() {
    let dir = tempdir().expect("tempdir");
    let before_the_board = live();
    let k = Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("open");
    let vs = Vstream::new(&k);
    // The edition's own values, and a first member windowing every second
    // one: `RUNS` runs, no two I-adjacent, and no span of R beside them.
    let values = (0..2 * RUNS + 8).map(|_| val(b"x")).collect();
    vs.insert(P1, &pdoc(), vp(1, 1), values, declared(), now(&k)).expect("the edition's values");
    let birth = Shot {
        base: None,
        draft: None,
        also: vec![],
        keep_base: false,
        runs: (1..=RUNS).map(|i| shot_run(&pdoc(), &pca(2 * i), 1)).collect(),
        stretches: Vec::new(),
    };
    let ((member, _), member_bytes) =
        kept(|| vs.publish(P1, &pdoc(), &birth, &readable_by(PrincipalId(1))).expect("the birth shot"));
    assert_eq!(k.snapshot().world().m5().content_run_count(&member), RUNS as usize);
    // The request's own runs are the test's, not the board's.
    drop(birth);
    let ((fork, _), fork_bytes) = kept(|| vs.version(EDITOR, &member, Some(false)).expect("the fork"));
    eprintln!(
        "heap: the member's {RUNS} runs keep {member_bytes} B live, {:.1} B a run; its fork adds {fork_bytes} B",
        member_bytes as f64 / f64::from(RUNS)
    );
    // Every figure is taken before the bound is judged, so a run that
    // fails the bound still says them all.
    let (mut one_change_rounds, mut many_change_rounds) = (Vec::new(), Vec::new());
    for changes in [1u32, 256] {
        let mut added = Vec::new();
        for _ in 0..10 {
            let ((), round) = kept(|| edit_and_keep(&k, &fork, spread(changes)));
            added.push(round);
        }
        eprintln!("heap: ten rounds of {changes} change(s), a version kept after each, add {added:?} B");
        eprintln!("heap: the slice's checkpoint form is then {} B", slice_bytes(&k));
        if changes == 1 {
            one_change_rounds = added;
        } else {
            many_change_rounds = added;
        }
    }
    // What the board holds, every round folded and no checkpoint taken.
    let held_before = live() - before_the_board;
    // The checkpoint's encode, through the kernel's own write: the first,
    // which no earlier checkpoint sizes, and a second after one more round,
    // sized by the first.
    for which in ["first", "second"] {
        let (at, peak) = most_above(|| k.checkpoint().expect("checkpoint"));
        let header = k.checkpoint_header(at).expect("the checkpoint just written");
        eprintln!("heap: the {which} checkpoint's file is {} B; its encode held {peak} B above the live store", header.len);
        edit_and_keep(&k, &fork, spread(1));
    }
    // The board closed, and opened from its second checkpoint and the one
    // round after it.
    drop(k);
    let (reopened, held_after) = kept(|| Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("reopen"));
    eprintln!("heap: the board held {held_before} B before its first checkpoint and holds {held_after} B opened again, two rounds on");
    assert_eq!(reopened.snapshot().world().m5().content_run_count(&member), RUNS as usize);
    for (changes, rounds, bound) in [(1, &one_change_rounds, member_bytes / 1000), (256, &many_change_rounds, member_bytes / 10)] {
        for round in rounds {
            assert!(
                *round < bound,
                "a round of {changes} change(s) added {round} B, past {bound} B against the member's {member_bytes} B: \
                 the version kept a list of its own"
            );
        }
    }
    assert!(
        held_after < held_before + held_before / 20,
        "the opened board holds {held_after} B where the board before its checkpoints held {held_before} B"
    );
}
