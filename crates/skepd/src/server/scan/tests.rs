use skep_febe::Codec;

use super::*;
use skep_core::codec::JsonCodec;

fn parse(frame: &str) -> Op {
    JsonCodec.parse(frame.as_bytes()).unwrap_or_else(|e| panic!("{frame}: {:?}", e.detail)).op
}

/// A four-set frame of `op` over the four slots as given, each already
/// JSON: `"any"`, `"empty"`, or a span array.
fn ftt(op: &str, home: &str, from: &str, to: &str, ty: &str) -> String {
    format!(r#"{{"op":"{op}","q":{{"from":{from},"home":{home},"to":{to},"ty":{ty}}}}}"#)
}

const ANY: &str = r#""any""#;
const EMPTY: &str = r#""empty""#;
/// A type class: a unit span at a type address.
const TY: &str = r#"[{"start":"1.1.0.1.0.1.0.3.90","width":"0.0.0.0.0.0.0.0.1"}]"#;
/// A content span in document `1.0.1.0.1`, for a link slot.
const CONTENT: &str = r#"[{"start":"1.0.1.0.1.0.1.1","width":"0.0.0.0.0.0.0.5"}]"#;
/// A `home` span at a document.
const DOC: &str = r#"[{"start":"1.0.1.0.1","width":"0.0.0.0.1"}]"#;
/// A `home` span at a version member of that document.
const MEMBER: &str = r#"[{"start":"1.0.1.0.1.1","width":"0.0.0.0.0.1"}]"#;
/// A `home` span at an account.
const ACCOUNT: &str = r#"[{"start":"1.0.1","width":"0.0.1"}]"#;
/// A `home` span at the node.
const NODE: &str = r#"[{"start":"1","width":"1"}]"#;
const REGION: &str = r#"[{"start":"1.1","width":"0.1"}]"#;

/// Checks the class-scan test over the query's SHAPE, and the region
/// test over the frame's document, with the reads that take no permit
/// beside them.
///
/// Every row is parsed through the codec rather than built by hand, so
/// the test reads the frames a client sends. The three lists are
/// disjoint; the class list is held to the three FTT ops and the region
/// list to its six, restated, so an op moved between the arms fails its
/// row where a list names it and a new op's row added without restating
/// the count fails the last assertions.
#[test]
fn a_class_scan_is_a_shape_and_a_region_read_names_its_document() {
    /// The ops that have a class-scan shape, and the ops the per-document
    /// pool bounds, restated.
    const CLASS_OPS: usize = 3;
    const REGION_OPS: usize = 6;

    let class = [
        // `ty` alone: the class, at each of the three ops, `cur` and `n`
        // notwithstanding; `"empty"` is the same shape annihilated.
        ftt("find_links_ftt", ANY, ANY, ANY, TY),
        ftt("count_ftt", ANY, ANY, ANY, TY),
        format!(
            r#"{{"cur":null,"n":16,"op":"window_ftt","q":{{"from":"any","home":"any","to":"any","ty":{TY}}}}}"#
        ),
        ftt("find_links_ftt", ANY, ANY, ANY, EMPTY),
        // Nothing at all: the board.
        ftt("find_links_ftt", ANY, ANY, ANY, ANY),
        ftt("count_ftt", ANY, ANY, ANY, ANY),
        // A `home` at an account or the node: every home under it, the
        // other slots narrowing the survivors and never the walk.
        ftt("find_links_ftt", ACCOUNT, ANY, ANY, ANY),
        ftt("find_links_ftt", NODE, ANY, ANY, ANY),
        ftt("find_links_ftt", ACCOUNT, ANY, ANY, TY),
        ftt("count_ftt", NODE, CONTENT, ANY, ANY),
    ];
    let region = [
        format!(r#"{{"d":"1.0.1.0.1","op":"find_links_v","region":{REGION}}}"#),
        format!(r#"{{"d":"1.0.1.0.1","op":"count_v","region":{REGION}}}"#),
        format!(r#"{{"cur":null,"d":"1.0.1.0.1","n":16,"op":"window_v","region":{REGION}}}"#),
        // The count by home, `except` naming a home or none: keyed by `d`.
        format!(
            r#"{{"d":"1.0.1.0.1","except":["1.0.1.0.2"],"n":64,"op":"count_v_by_home","region":{REGION}}}"#
        ),
        format!(r#"{{"d":"1.0.1.0.1","n":64,"op":"count_v_by_home","region":{REGION}}}"#),
        format!(r#"{{"d":"1.0.1.0.1","op":"retrieve_endsets","region":{REGION}}}"#),
        r#"{"d":"1.0.1.0.1","op":"delete_orphans","p":{"subspace":"1","ordinal":"1"},"width":"1"}"#
            .to_string(),
    ];
    let unbounded = [
        // A `home` at a document or a member: one chain, whatever else
        // is constrained.
        ftt("find_links_ftt", DOC, ANY, ANY, ANY),
        ftt("find_links_ftt", MEMBER, ANY, ANY, ANY),
        ftt("find_links_ftt", DOC, ANY, ANY, TY),
        ftt("count_ftt", DOC, CONTENT, ANY, TY),
        // A link slot beside `ty`, or alone: the directory drives.
        ftt("find_links_ftt", ANY, CONTENT, ANY, TY),
        ftt("count_ftt", ANY, ANY, CONTENT, TY),
        ftt("find_links_ftt", ANY, CONTENT, ANY, ANY),
        ftt("find_links_ftt", ANY, CONTENT, CONTENT, ANY),
        // The zero in the home slot: unsatisfiable.
        ftt("find_links_ftt", EMPTY, ANY, ANY, TY),
        // The lineage pair and the edition claims: the index, not the
        // class.
        r#"{"op":"in_claims","y":"1.0.1.0.1.0.2.1","view":"default"}"#.to_string(),
        r#"{"op":"out_claims","x":"1.0.1.0.1.0.2.1","view":"default"}"#.to_string(),
        r#"{"op":"edition_claims","target":"1.0.1.0.1"}"#.to_string(),
        // M5's resolve and one `readlink`: no store walk.
        format!(r#"{{"d":"1.0.1.0.1","op":"image","region":{REGION}}}"#),
        r#"{"a":"1.0.1.0.1.0.2.1","d":"1.0.1.0.1","op":"project","slot":1}"#.to_string(),
        r#"{"a":"1.0.1.0.1.0.2.1","d":"1.0.1.0.1","op":"discoverable_from"}"#.to_string(),
        r#"{"op":"read_link","a":"1.0.1.0.1.0.2.1"}"#.to_string(),
        r#"{"op":"follow_link","a":"1.0.1.0.1.0.2.1","slot":1}"#.to_string(),
        // The M6 and M3 reads touch no link store at all.
        r#"{"op":"retrieve_v","specs":[{"doc":"1.0.1.0.1","span":{"start":"1.1","width":"0.1"}}]}"#
            .to_string(),
        r#"{"op":"show_deletions","d_a":"1.0.1.0.1","d_b":"1.0.1.0.2"}"#.to_string(),
        r#"{"op":"doc_metadata","doc":"1.0.1.0.1"}"#.to_string(),
        r#"{"op":"next_account_prefix","parent":"1"}"#.to_string(),
    ];
    let mut class_names = std::collections::BTreeSet::new();
    for frame in &class {
        let op = parse(frame);
        assert!(is_class_scan(&op), "a class-scan shape, so the class pool bounds it: {frame}");
        assert!(region_document(&op).is_none(), "and the per-document pool does not: {frame}");
        class_names.insert(skep_core::codec::op_name(op.kind()));
    }
    let mut region_names = std::collections::BTreeSet::new();
    for frame in &region {
        let op = parse(frame);
        assert!(!is_class_scan(&op), "a region read is no class scan: {frame}");
        let d = region_document(&op).unwrap_or_else(|| panic!("names its document: {frame}"));
        assert_eq!(d, &address("1.0.1.0.1"), "the key is the frame's `d`: {frame}");
        region_names.insert(skep_core::codec::op_name(op.kind()));
    }
    for frame in &unbounded {
        let op = parse(frame);
        assert!(!is_class_scan(&op), "takes no class permit: {frame}");
        assert!(region_document(&op).is_none(), "takes no region permit: {frame}");
    }
    assert_eq!(class_names.len(), CLASS_OPS, "the class shapes' ops: {class_names:?}");
    assert_eq!(region_names.len(), REGION_OPS, "the region reads' ops: {region_names:?}");
}

fn address(text: &str) -> Address {
    let comps = text.split('.').map(|c| skep_address::Nat::from(c.parse::<u64>().expect("a digit")));
    validate(Tumbler::new(comps).expect("nonempty")).expect("a valid address")
}

/// Checks the class pool's admission at both ends (wire v7.9).
///
/// A class-scan shape takes one of the [`MAX_CONCURRENT_CLASS_SCANS`]
/// permits and a read of no pool takes none, a drained pool refuses
/// rather than queueing, and a released permit reopens its slot. The
/// pool is per shape, so an unbounded read is admitted while it is
/// drained — which is what keeps the bound off the reads that walk no
/// whole class.
#[test]
fn the_class_pool_admission_takes_a_permit_only_for_a_class_scan_shape() {
    let bounded = parse(&ftt("count_ftt", ANY, ANY, ANY, ANY));
    let narrowed = parse(&ftt("count_ftt", DOC, ANY, ANY, TY));
    let unbounded = parse(r#"{"op":"doc_metadata","doc":"1.0.1.0.1"}"#);
    let scans = ClassScans::new();
    for op in [&unbounded, &narrowed] {
        assert!(
            scans.admit(op).expect("an unbounded read is admitted").is_none(),
            "…and spends no permit"
        );
    }
    let held: Vec<_> = (0..MAX_CONCURRENT_CLASS_SCANS)
        .map(|_| scans.admit(&bounded).expect("a permit").expect("a class scan takes one"))
        .collect();
    assert_eq!(
        scans.admit(&bounded).err(),
        Some(ScanBusy::Class),
        "a drained pool refuses, by the class pool; it never queues"
    );
    for op in [&unbounded, &narrowed] {
        assert!(
            scans.admit(op).expect("an unbounded read is admitted").is_none(),
            "a drained pool does not reach the reads it does not bound"
        );
    }
    drop(held);
    assert!(
        scans.admit(&bounded).expect("a released permit reopens its slot").is_some(),
        "and the reopened slot is a permit, not an admission with none"
    );
}

/// Checks the per-document pool (D3, D4): a document admits its width
/// and refuses the read past it while another document is admitted; the
/// ceiling refuses past [`MAX_CONCURRENT_REGION_READS`] across documents,
/// and a read of a document at its width is refused by the width ahead
/// of the ceiling; the two pools are disjoint; and the table holds an
/// entry per document holding a permit and nothing once they are
/// returned, whatever was refused. Each slot here is taken with no wait, as
/// the test hook takes one, so each refusal of it comes at once; the wire
/// read's refusal comes after its wait, which the tests below pin.
#[test]
fn the_per_document_pool_admits_a_width_per_document_inside_the_ceiling() {
    let scans = ClassScans::new();
    let read = |d: &str| parse(&format!(r#"{{"d":"{d}","op":"find_links_v","region":{REGION}}}"#));
    let (a, b, c, e) = (address("1.0.1.0.1"), address("1.0.1.0.2"), address("1.0.1.0.3"), address("1.0.1.0.4"));

    // A's width, then A refused while B is admitted.
    let a1 = scans.take_region(&a, Duration::ZERO).expect("A's first");
    let a2 = scans.take_region(&a, Duration::ZERO).expect("A's second");
    assert_eq!(
        scans.take_region(&a, Duration::ZERO).err(),
        Some(ScanBusy::Document),
        "A holds its width"
    );
    assert_eq!(
        scans.admit(&read("1.0.1.0.1")).err(),
        Some(ScanBusy::Document),
        "a wire read of A is refused, by its width, once its wait ends"
    );
    let b1 = scans.admit(&read("1.0.1.0.2")).expect("B is admitted").expect("with a permit");
    assert_eq!(scans.documents_held(), 2, "an entry per document holding a permit");

    // The ceiling: six across three documents, the seventh refused by the
    // ceiling — and a document at its width by its width, first.
    let b2 = scans.take_region(&b, Duration::ZERO).expect("B's second");
    let c1 = scans.take_region(&c, Duration::ZERO).expect("C's first");
    let c2 = scans.take_region(&c, Duration::ZERO).expect("C's second");
    assert_eq!(
        scans.take_region(&e, Duration::ZERO).err(),
        Some(ScanBusy::Ceiling),
        "the board holds its ceiling"
    );
    assert_eq!(
        scans.take_region(&a, Duration::ZERO).err(),
        Some(ScanBusy::Document),
        "the width is judged first"
    );
    assert_eq!(scans.documents_held(), 3, "a refused read leaves no entry");

    // Disjoint: every region permit held, the class pool is whole; and
    // every class permit held, a region read is admitted.
    let class: Vec<_> = (0..MAX_CONCURRENT_CLASS_SCANS)
        .map(|_| scans.try_hold().expect("a class permit with every region permit held"))
        .collect();
    drop(c2);
    let c3 = scans
        .take_region(&c, Duration::ZERO)
        .expect("C's returned slot, with every class permit held");
    drop(class);

    // Returned permits free the width, the ceiling and the table.
    drop(a1);
    let _ = scans.take_region(&a, Duration::ZERO).expect("A's returned slot");
    drop((a2, b1, b2, c1, c3));
    assert_eq!(scans.documents_held(), 0, "no permit held, no entry");
    assert_eq!(scans.ceiling.try_acquire().map(|_| ()), Some(()), "the ceiling is whole again");
}

/// A wait long past any test's patience: a read given it is answered by a
/// returned permit, or by a refusal that never waits, and never by its end.
const LONG: Duration = Duration::from_secs(30);

/// The patience of an answer that comes at once, or the moment a permit
/// returns: generous beside a thread's wake, and far short of [`LONG`].
const PROMPT: Duration = Duration::from_secs(10);

/// Takes a region permit of `d`, waiting `wait` at most, and answers the
/// outcome with how long it took, the permit returned at once.
fn timed_take(scans: &ClassScans, d: &Address, wait: Duration) -> (Result<(), ScanBusy>, Duration) {
    let began = Instant::now();
    let taken = scans.take_region(d, wait).map(|_| ());
    (taken, began.elapsed())
}

/// Spins until `n` reads wait at their document's width, or panics past
/// [`PROMPT`].
fn wait_until_waiting(scans: &ClassScans, n: usize) {
    let began = Instant::now();
    while scans.waiting() < n {
        assert!(began.elapsed() < PROMPT, "{n} reads never came to wait");
        std::thread::yield_now();
    }
}

/// Holds `d`'s width: its [`MAX_REGION_READS_PER_DOCUMENT`] permits, taken
/// as the test hook takes them, with no wait.
fn hold_width<'a>(scans: &'a ClassScans, d: &Address) -> Vec<RegionPermit<'a>> {
    (0..MAX_REGION_READS_PER_DOCUMENT)
        .map(|_| scans.take_region(d, Duration::ZERO).expect("a slot of the width"))
        .collect()
}

/// Checks that a read at its document's width waits and is admitted as one
/// of the document's permits returns (the home-index record's D3 (b)).
///
/// The width held, a read waits in a waiting slot; the moment one of the
/// document's permits is dropped, the read takes its slot — a permit, where
/// before the wait it met a refusal — long before its own wait could end.
#[test]
fn a_read_at_its_documents_width_waits_and_is_admitted_as_a_permit_returns() {
    let scans = ClassScans::new();
    let a = address("1.0.1.0.1");
    let mut width = hold_width(&scans, &a);
    std::thread::scope(|s| {
        let waiter = s.spawn(|| timed_take(&scans, &a, LONG));
        wait_until_waiting(&scans, 1);
        drop(width.pop());
        let (taken, took) = waiter.join().expect("the waiter");
        assert_eq!(
            taken,
            Ok(()),
            "FINDING (#658): a returned permit admits the read waiting for its page"
        );
        assert!(took < PROMPT, "…the moment it returns, never at the wait's end: {took:?}");
    });
    assert_eq!(scans.waiting(), 0, "its waiting slot returned");
}

/// Checks that a read still at its document's width when its wait ends is
/// refused, the wait spent and no more (D3 (b)).
///
/// The width is held for the whole wait, as a flooded page's permits are
/// held for its answers, so a wire read is refused [`ScanBusy::Document`]
/// after [`REGION_READ_WAIT`] — never before it, and never long after — and
/// its waiting slot is returned.
#[test]
fn a_read_still_at_its_documents_width_after_the_wait_is_refused() {
    let scans = ClassScans::new();
    let _width = hold_width(&scans, &address("1.0.1.0.1"));
    let read = parse(&format!(r#"{{"d":"1.0.1.0.1","op":"find_links_v","region":{REGION}}}"#));
    let began = Instant::now();
    assert_eq!(scans.admit(&read).err(), Some(ScanBusy::Document), "refused by the width");
    let waited = began.elapsed();
    assert!(
        waited >= REGION_READ_WAIT,
        "FINDING (#658): refused after the wait, not before: {waited:?}"
    );
    assert!(waited < PROMPT, "…and no later than its bound: {waited:?}");
    assert_eq!(scans.waiting(), 0, "its waiting slot returned");
}

/// Checks that the waiting slots are capped across the board (D3 (b)).
///
/// Two reads of A wait, filling [`MAX_REGION_READ_WAITERS`]; a third read of
/// A, and a read of C — another page, also at its width — are each refused
/// at once, a waiting slot being the board's and never the page's; and the
/// two waiters are admitted as A's permits return.
#[test]
fn the_waiting_slots_are_capped_across_the_board() {
    let scans = ClassScans::new();
    let (a, c) = (address("1.0.1.0.1"), address("1.0.1.0.3"));
    let a_width = hold_width(&scans, &a);
    let _c_width = hold_width(&scans, &c);
    std::thread::scope(|s| {
        let waiters: Vec<_> = (0..MAX_REGION_READ_WAITERS)
            .map(|_| s.spawn(|| timed_take(&scans, &a, LONG)))
            .collect();
        wait_until_waiting(&scans, MAX_REGION_READ_WAITERS);
        for d in [&a, &c] {
            let (taken, took) = timed_take(&scans, d, LONG);
            assert_eq!(
                taken,
                Err(ScanBusy::Document),
                "FINDING (#658): every waiting slot taken, a read of {d:?} is refused"
            );
            assert!(took < PROMPT, "…at once, never after a wait: {took:?}");
        }
        drop(a_width);
        for waiter in waiters {
            let (taken, took) = waiter.join().expect("a waiter");
            assert_eq!(taken, Ok(()), "a waiter is admitted as A's permits return");
            assert!(took < PROMPT, "…the moment they do: {took:?}");
        }
    });
    assert_eq!(scans.waiting(), 0, "every waiting slot returned");
}

/// Checks that the ceiling refuses at once and is never waited for (D3 (b)).
///
/// Three pages at their width fill [`MAX_CONCURRENT_REGION_READS`]; a read of
/// a fourth page, which has room, is refused [`ScanBusy::Ceiling`] at once,
/// taking no waiting slot.
#[test]
fn the_ceiling_refuses_at_once() {
    let scans = ClassScans::new();
    let held: Vec<_> = ["1.0.1.0.1", "1.0.1.0.2", "1.0.1.0.3"]
        .into_iter()
        .flat_map(|d| hold_width(&scans, &address(d)))
        .collect();
    assert_eq!(held.len(), MAX_CONCURRENT_REGION_READS, "the premise: the ceiling is held");
    let (taken, took) = timed_take(&scans, &address("1.0.1.0.4"), LONG);
    assert_eq!(taken, Err(ScanBusy::Ceiling), "a page with room, on a board at its ceiling");
    assert!(took < PROMPT, "FINDING (#658): the ceiling is never waited for: {took:?}");
    assert_eq!(scans.waiting(), 0, "and took no waiting slot");
}

/// Checks that a returned permit admits its own page's waiter and no other
/// page's (D3 (b)).
///
/// A read waits for A and another for B, each page at its width; one of B's
/// permits returns. B's waiter takes the slot at once; A's, woken by the
/// same notice, re-checks its own page, finds A still at its width, and
/// waits on until its own wait ends, refused.
#[test]
fn a_returned_permit_admits_its_own_pages_waiter_and_no_other() {
    let scans = ClassScans::new();
    let (a, b) = (address("1.0.1.0.1"), address("1.0.1.0.2"));
    let _a_width = hold_width(&scans, &a);
    let mut b_width = hold_width(&scans, &b);
    let a_wait = Duration::from_secs(3);
    std::thread::scope(|s| {
        let for_a = s.spawn(|| timed_take(&scans, &a, a_wait));
        wait_until_waiting(&scans, 1);
        let for_b = s.spawn(|| timed_take(&scans, &b, LONG));
        wait_until_waiting(&scans, 2);
        drop(b_width.pop());
        let (taken, took) = for_b.join().expect("B's waiter");
        assert_eq!(taken, Ok(()), "B's waiter takes B's returned slot");
        assert!(took < PROMPT, "FINDING (#658): …the moment it returns: {took:?}");
        let (taken, waited) = for_a.join().expect("A's waiter");
        assert_eq!(
            taken,
            Err(ScanBusy::Document),
            "FINDING (#658): A's waiter takes no slot of B's"
        );
        assert!(waited >= a_wait, "…and waits out its own wait, re-checking its page: {waited:?}");
    });
    assert_eq!(scans.waiting(), 0, "every waiting slot returned");
}

/// Checks that the pools' five figures are the ones wire.md names (§Link
/// discovery reads).
///
/// The three counts, the wait and the waiting slots are daemon constants the
/// wire names, each spelled there in one bold run; this holds each to its
/// constant, so a figure moved here and not there fails here.
#[test]
fn the_five_figures_are_the_wires() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/wire.md");
    let wire = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let wire = wire.split_whitespace().collect::<Vec<_>>().join(" ");
    for figure in [
        format!("**`MAX_CONCURRENT_CLASS_SCANS` = {MAX_CONCURRENT_CLASS_SCANS}**"),
        format!("**`MAX_REGION_READS_PER_DOCUMENT` = {MAX_REGION_READS_PER_DOCUMENT}**"),
        format!("**`MAX_CONCURRENT_REGION_READS` = {MAX_CONCURRENT_REGION_READS}**"),
        format!("**`REGION_READ_WAIT` = {} ms**", REGION_READ_WAIT.as_millis()),
        format!("**`MAX_REGION_READ_WAITERS` = {MAX_REGION_READ_WAITERS}**"),
    ] {
        assert!(wire.contains(&figure), "wire.md names {figure}");
    }
}
