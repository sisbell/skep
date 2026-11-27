use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};

use super::*;

/// Returns a test address from its dotted form, T4-validated.
///
/// # Panics
///
/// Panics where `s` spells no T4-valid address.
fn addr(s: &str) -> Address {
    let comps: Vec<Nat> = s.split('.').map(|c| Nat::from(c.parse::<u32>().unwrap())).collect();
    validate(Tumbler::new(comps).expect("a tumbler")).expect("a test address")
}

/// Checks the two maps and the base.
///
/// An entry is idempotent per address; two cells of one account over one
/// hash count once; a second account's cell over the same hash counts in
/// its own base; a halt mark counts in no base and is the first halt;
/// readiness flips once.
#[test]
fn entries_are_idempotent_per_cell_and_the_base_counts_distinct_hashes_once() {
    let index = CellIndex::new();
    assert!(!index.is_ready());
    let hash = [7u8; 32];
    let cell = Cell { hash, size: 10 };
    let hex = hex_string(&hash);
    let (a, b) = (PrincipalId(1), PrincipalId(2));
    assert!(index.enter(&addr("1.0.1.0.64.0.1.1"), Some(a), &cell));
    assert!(!index.enter(&addr("1.0.1.0.64.0.1.1"), Some(a), &cell), "idempotent per address");
    assert!(index.enter(&addr("1.0.1.0.65.0.1.1"), Some(a), &cell), "a second cell of a's");
    assert_eq!(index.base(a), 10, "one hash, counted once");
    assert!(index.enter(&addr("1.0.2.0.1.0.1.1"), Some(b), &Cell { hash, size: 10 }));
    assert_eq!(index.base(b), 10);
    assert_eq!(index.total_base(), 20);
    assert!(index.names(a, DESIGNATION, &hex));
    assert!(index.names(b, DESIGNATION, &hex));
    assert!(!index.names(PrincipalId(3), DESIGNATION, &hex));
    assert!(index.referenced(DESIGNATION, &hex));
    assert!(!index.referenced("sha256-tree", &hex), "the designation is part of the key");
    assert_eq!(index.counts(), (3, 1, 0));
    // A cell under no seat: named for the pruner, counted for nobody.
    let other = Cell { hash: [9u8; 32], size: 4 };
    assert!(index.enter(&addr("1.0.9.0.1.0.1.1"), None, &other));
    assert!(index.referenced(DESIGNATION, &hex_string(&other.hash)));
    assert_eq!(index.total_base(), 20);
    // The larger size wins per hash per account, whatever the order.
    assert!(index.enter(&addr("1.0.1.0.66.0.1.1"), Some(a), &Cell { hash, size: 12 }));
    assert_eq!(index.base(a), 12);
    assert!(index.enter(&addr("1.0.1.0.67.0.1.1"), Some(a), &Cell { hash, size: 11 }));
    assert_eq!(index.base(a), 12);
    assert_eq!(index.first_halt(), None);
    assert!(index.halt(&addr("1.0.1.0.68.0.1.1")));
    assert!(!index.halt(&addr("1.0.1.0.68.0.1.1")));
    let mark = index.first_halt().expect("a halt mark");
    assert_eq!(mark.fault, "unknown_cell_schema");
    assert_eq!(mark.kind, cell::KIND);
    assert_eq!(index.counts(), (6, 2, 1));
    assert_eq!(index.total_base(), 22, "a halt mark counts in no base");
    // The inventory's reads: every reference at the largest size named,
    // its cells in address order; every account's base; the halt marks.
    let refs = index.references();
    assert_eq!(refs.len(), 2);
    assert_eq!((refs[0].hex.as_str(), refs[0].size, refs[0].cells.len()), (hex.as_str(), 12, 5));
    assert_eq!((refs[1].size, refs[1].cells.len()), (4, 1), "a cell under no seat: named, sized");
    assert_eq!(index.accounts(), vec![(a, 12), (b, 10)]);
    assert_eq!(index.halts().len(), 1);
    index.complete(Rebuild { values: 0, cells: 0, halts: 0, walk: Duration::ZERO, parse: Duration::ZERO });
    assert!(index.is_ready());
    assert!(!index.is_failed(), "a walk that completed never fails");
    assert_eq!(index.rebuild_report().map(|r| r.values), Some(0));
}

/// Polls until `done`, bounded, naming what never came.
///
/// # Panics
///
/// Panics, naming `what`, where `done` has not come within 30 seconds.
fn wait_until(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

/// Checks that a walk that panics marks the index failed, on either arm.
///
/// **The catch** (`operations.md` §4 row 26; §1.1 row 41). The walk's
/// thread dies under the seam's fault — the index failed, never ready, no
/// report, the fault spent as it fired — and a second walk over the same
/// kernel, meeting no fault, completes an index that is ready and not
/// failed: the two states are the walk's own, each set by one door. Then
/// the arm where the OS refuses the walk's thread: the walk runs on this
/// one before `start_walk` returns, completing its index where it meets
/// no fault, and where it meets one it is caught here as on its own
/// thread — the index failed, and no unwind reaching the caller, whose
/// open goes on. Then the line's words, verbatim, for a panic caught at
/// a site its hook noted, with a literal payload.
#[test]
fn a_walk_that_panics_marks_the_index_failed_and_never_ready() {
    let engine = skep_engine::Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    })
    .expect("in-memory genesis cannot fail");
    let index = Arc::new(CellIndex::new());
    WALK_FAULT.arm();
    start_walk(engine.kernel(), Arc::clone(&index));
    wait_until("the catch to mark the index FAILED", || index.is_failed());
    assert!(!index.is_ready(), "a walk that failed never completes");
    assert_eq!(index.rebuild_report(), None, "no report: the walk never returned");
    assert!(!WALK_FAULT.armed.load(Ordering::Acquire), "taken once: disarmed as it fired");
    let fresh = Arc::new(CellIndex::new());
    start_walk(engine.kernel(), Arc::clone(&fresh));
    wait_until("the second walk to complete", || fresh.is_ready());
    assert!(!fresh.is_failed(), "the fault was spent on the first walk");
    assert!(index.is_failed() && !index.is_ready(), "the first index stays FAILED");
    // The refused arm: the walk runs on this thread, so its state stands
    // as `start_walk` returns, with no wait.
    REFUSE_THE_WALKS_THREAD.store(true, Ordering::Release);
    let inline = Arc::new(CellIndex::new());
    start_walk(engine.kernel(), Arc::clone(&inline));
    assert!(!REFUSE_THE_WALKS_THREAD.load(Ordering::Acquire), "taken once, as it fired");
    assert!(inline.is_ready() && !inline.is_failed(), "walked at the open, and completed");
    assert!(inline.rebuild_report().is_some(), "its report kept");
    // …and a walk that panics there is caught there: the index failed,
    // and `start_walk` returns rather than unwinding into its caller.
    REFUSE_THE_WALKS_THREAD.store(true, Ordering::Release);
    WALK_FAULT.arm();
    let caught = Arc::new(CellIndex::new());
    start_walk(engine.kernel(), Arc::clone(&caught));
    assert!(caught.is_failed() && !caught.is_ready(), "caught here: failed, never ready");
    assert_eq!(caught.rebuild_report(), None, "no report: the walk never returned");
    assert!(!WALK_FAULT.armed.load(Ordering::Acquire), "the fault spent at the open");
    assert!(!REFUSE_THE_WALKS_THREAD.load(Ordering::Acquire), "the refusal spent with it");
    // The hook's part, played by the body: this suite's process runs
    // std's own hook, which notes no site.
    let at = std::panic::Location::caller();
    let died = caught::catch(|| {
        caught::note_site(Some(at));
        panic!("the test seam's walk fault");
    });
    let died = died.expect_err("the body panics");
    assert_eq!(
        WalkFailedLine { caught: &died }.to_string(),
        format!(
            "cell index: the walk failed (a panic at {at}: the test seam's walk fault); the \
             upload family and the door's index arm refuse for the uptime; the act: a \
             restart, or the build's fix where it recurs"
        )
    );
    // The door by hand, as the gate's suite takes it: failed set, ready
    // not, nothing entered.
    let by_hand = CellIndex::new();
    by_hand.fail(&died);
    assert!(by_hand.is_failed() && !by_hand.is_ready());
}

/// Checks the walk's landing and its refused thread's line in their words.
///
/// The landing (`operations.md` §1.1 row 13) says the walk's two durations
/// in whole milliseconds, the stream's one spelling of a duration (§1),
/// truncated as every other duration on it is: 23,456,789 µs reads `23456
/// ms`, and 152 µs reads `0 ms`. The refused thread's line (row 15)
/// carries the OS's own words for the limit the spawn met, as the
/// pruner's and the checkpoint thread's lines do (rows 21, 22).
#[test]
fn the_walks_landing_says_milliseconds_and_its_refused_thread_the_oss_words() {
    let report = Rebuild {
        values: 1_000_000,
        cells: 3,
        halts: 1,
        walk: Duration::from_micros(23_456_789),
        parse: Duration::from_micros(152),
    };
    assert_eq!(
        RebuiltLine { report: &report }.to_string(),
        "cell index rebuilt at open: 1000000 values walked, 3 cells, 1 halt marks, 23456 ms \
         (0 ms past the prefix test)"
    );
    let error = io::Error::other("Resource temporarily unavailable");
    assert_eq!(
        ThreadRefusedLine { error: &error }.to_string(),
        "cell index: the OS refused the rebuild's thread (Resource temporarily unavailable); \
         the walk runs at open"
    );
}

/// The picture cell's canonical form over the empty input's hash, at `size`.
fn cell_of(size: u64) -> Vec<u8> {
    let hash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    format!(r#"{{"type":"{}","hash":"{hash}","size":{size}}}"#, cell::KIND).into_bytes()
}

/// Checks that the entry at a shot's commit reads the fresh identity by
/// stored piece, a stretch skipped whole.
///
/// A draft of the positions' budget of values — three long runs of typed
/// bytes around two cells, a value naming the kind under no schema this
/// build pins and an atom of plain bytes — is published in one shot, so the
/// member's fresh identity is seven stored pieces: three stretches and four
/// values. The entry reads SEVEN pieces, a step a stored piece, where a
/// point read a position reads the budget's 1,048,576 of them; it enters the
/// two cells at their fresh addresses, marks the halt at its own, and takes
/// the plain atom and every typed byte for nothing. A count shorter than the
/// shot's reads only the chain's last positions, and one longer than the
/// chain reads no further back than its first.
#[test]
fn a_shots_fresh_identity_is_entered_by_stored_piece_a_stretch_skipped_whole() {
    use skep_arrangement::{AsOf, Caller, Deposit, Run, Shot, ShotRun, VPos};
    use skep_content::Val;
    use skep_namespace::{system_account, SYSTEM_PRINCIPAL};

    let engine = skep_engine::Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    })
    .expect("in-memory genesis cannot fail");
    let system = Caller::Principal(SYSTEM_PRINCIPAL);
    let mint = |published: bool| {
        engine.namespace().create_new_document(SYSTEM_PRINCIPAL, &system_account(), Some(published)).expect("the system principal mints in its own account").0
    };
    let (draft, edition) = (mint(false), mint(true));
    // The positions' budget of values: typed bytes around four atoms.
    let positions = MAX_REINSERTED_VALUES;
    let (lead, middle) = (400_000usize, 300_000usize);
    let tail = positions - lead - middle - 4;
    let unknown = format!(r#"{{"type":"{}","hash":"00","size":5,"hash_alg":"sha256-tree"}}"#, cell::KIND).into_bytes();
    let typed = |count: usize| std::iter::repeat_n(Val::new(&b"x"[..]), count);
    let values: Vec<Val> = typed(lead)
        .chain([Val::new(cell_of(5))])
        .chain(typed(middle))
        .chain([Val::new(unknown), Val::new(&b"plain"[..]), Val::new(cell_of(7))])
        .chain(typed(tail))
        .collect();
    assert_eq!(values.len(), positions);
    let first = engine
        .vstream()
        .insert(system, &draft, VPos::content(Nat::from(1u32)), values, Deposit::Undeclared, AsOf::Typed(engine.kernel().current_seq()))
        .expect("the engine, below the door, writes any bytes")
        .0;
    let shot = Shot {
        base: None,
        draft: Some(draft.clone()),
        also: vec![],
        keep_base: false,
        runs: vec![ShotRun { origin: draft.clone(), run: Run::new(first, Nat::from(positions)).expect("the draft's run") }],
    };
    let readable = skep_engine::World::visible_to(system);
    let (member, _) = engine.vstream().publish(system, &edition, &shot, &readable).expect("the shot commits: seven units");
    let snap = engine.kernel().snapshot();
    let world = snap.world();
    let fresh = |position: usize| {
        elem_addr(ElemPos { doc: edition.clone(), subspace: content_subspace(), ordinal: Nat::from(position) }).expect("a content address of the edition")
    };
    let index = CellIndex::new();
    let read = index.enter_publish(world, &member, positions as u64);
    assert_eq!(read, 7, "a step a stored piece: three stretches and four values, never a lookup a position");
    assert_eq!(index.counts(), (2, 1, 1), "the two cells over one hash, and the halt mark");
    let cells: Vec<Tumbler> = index.references().into_iter().flat_map(|reference| reference.cells).collect();
    assert_eq!(cells, vec![fresh(lead + 1).tumbler().clone(), fresh(lead + middle + 4).tumbler().clone()], "each cell at its fresh address");
    assert_eq!(index.halts().into_iter().map(|mark| mark.at).collect::<Vec<_>>(), vec![fresh(lead + middle + 2)]);
    // Fewer than the shot minted: the chain's last positions alone — the
    // last cell and the typed bytes behind it.
    let last = CellIndex::new();
    assert_eq!(last.enter_publish(world, &member, tail as u64 + 1), 2);
    assert_eq!(last.counts(), (1, 1, 0));
    // More than the chain holds: no further back than its first position.
    let whole = CellIndex::new();
    assert_eq!(whole.enter_publish(world, &member, u64::MAX), 7);
    assert_eq!(whole.counts(), (2, 1, 1));
}
