//! Tests of the held-burst store: its file, its queue and its budgets.
//!
//! The file's cells (T1–T5): the header written once and read whole with
//! P38's faces, `v` first — a header of every other form halting with its
//! own, and a header the device did not take whole leaving no file; the
//! torn last line ignored, and cut before the next line is written; a
//! damaged middle line halting; the misplaced file moved aside and never
//! overwriting; the lock a second holder cannot take; compaction once every
//! line is done, the file recreated header first by the next line; a
//! reopened queue taking an ordinal past every one its file names; and
//! persist-first — the line on disk before the append returns, and a copy
//! the device cut short or whose sync it refused cut back off the file.
//! Every line form reads back as it was held, and the store is its owner's
//! alone.
//!
//! The queue's cells, the queue the memory and the file its copy: a line the
//! device refused stands in the queue under its ordinal; the wait (§3c.3) —
//! a refused line and every line after it copied in `k` order as one copy,
//! one sync, once the device takes them, at the next hold or by a retry with
//! no new line (skep #822), that one copy past the line bound where each of
//! its lines is within it, the one copy the device refuses copied a line at
//! a time up to the first refused again and the next retry resuming there,
//! a line behind one the writer refuses for good waiting until that one
//! leaves, a waiting line's re-mark and shift carried to its one first copy
//! and its drop writing no `done`, and a join entering nothing ahead of a
//! waiting line; a re-mark reads back as the one line it re-marks; a `done`
//! the device refused still settles its line and is owed, a reopen before
//! the retry reading the line as held again and none after it; the copies
//! owed a line on disk (skep #821) — a mark of `sent` the device refused
//! written by the retry past a spent re-mark budget, a re-mark giving way to
//! its line's `done`, the copies owed written first in `k` order, in one
//! copy with the line held behind them, and a change riding its line's owed
//! copy, an owed `done` keeping its line in the budgets until it lands, and a
//! queue owing a copy joining nothing; the join (skep #817) — a full queue
//! joined in one copy with one sync, a join the device refused entering
//! nothing, owing nothing and joining once the device takes copies, two
//! equal lines of one queue both joining, a join a crash cut before its sync
//! joining again over the lines the device kept and doubling none, and a join
//! whose cut-back was refused leaving its copy past the file's whole lines
//! until the retry cuts it; a line kept at a position is the base of the
//! lines behind it on its document, in the queue and at a reopen, a line
//! held after it keeping its own and a lower raise lifting only the lines it
//! stood with, and every line's base the eager raise's over thousands of
//! seeded acts, in memory and at each reopen (skep #816); a line
//! re-marked with its base raised — the person's `send` on a moved document —
//! reads back with the raised base, never lowered by a raise below it or a
//! later `done` kept below it; and a run of re-marks or `done`s (skep #861)
//! is one copy with one sync, leaving the queue and the file as a call a line
//! leaves them, a run that changes nothing writing nothing; and what the file
//! owes read and counted (skep #860) — the lines in memory alone and the
//! `done`s owed by how each line left, a re-mark's copy none of it, a parked
//! line no line off disk, a `done` the pending file never wrote counted while
//! that file stands, and the compaction taking the `done`s it owes with it.
//!
//! The budgets' cells: the queue's frames and anchors held to its byte
//! budget, four frames at the frame cap fitting it, each line's anchors
//! counted beside its frame at the hold, the open, the join and the settle,
//! and its lines to the line budget — a reopened queue past it read whole,
//! holding nothing more until it drains; a line at every member's bound
//! written and read back; an unchanged re-mark writing nothing, a board
//! flapping between two causes growing the file no further than its re-mark
//! budget, and a line's mark of `sent` copied past a spent budget, spending
//! none of it; the ordinals held to the page's; the writer refusing a line
//! its reader would halt on and copying none past the line bound; and the
//! reader halting on any line it cannot read whole — no UTF-8, a member
//! missing or of another type, anchors past their bound, an ordinal past the
//! page's, a line past the bound — while ignoring a torn last line cut
//! mid-character. And, timed (`#[ignore]`, the full gate's), a drained file
//! at both budgets reopened within its ceiling, in time in proportion to its
//! lines.

use std::cell::{Cell, RefCell};
use std::fs;
use std::path::Path;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;
use sha2::{Digest, Sha256};
use skep_client::Origin;
use tempfile::TempDir;

use super::*;

// ── THE COPY SEAMS (read by `write_synced` and `Disk::append`) ───────────────

/// The seam a suite installs to read the file after a sync.
type Seam = Box<dyn Fn(&Path)>;

thread_local! {
    static FAIL_SYNC: Cell<bool> = const { Cell::new(false) };
    static REFUSED_AS: Cell<std::io::ErrorKind> = const { Cell::new(std::io::ErrorKind::StorageFull) };
    static TORN_WRITE: Cell<Option<usize>> = const { Cell::new(None) };
    static REFUSE_CUT_BACK: Cell<bool> = const { Cell::new(false) };
    static AFTER_SYNC: RefCell<Option<Seam>> = const { RefCell::new(None) };
}

/// Refuses the cut-back of the next copy the device refuses, once.
///
/// It stands in for a device whose cut back to the whole lines fails after a
/// copy it refused — for this suite and the hold's — the copy's bytes left
/// standing past the whole lines, as a write that landed and a sync refused
/// leave them.
pub(crate) fn refuse_the_next_cut_back() {
    REFUSE_CUT_BACK.with(|r| r.set(true));
}

/// Returns `failed` as a device that refused its cut-back leaves it, where
/// [`refuse_the_next_cut_back`] armed one: `line` and its `\n` written back
/// at the file's end, past its whole lines, and the cut-back's refusal named.
pub(super) fn cut_back_refused(path: &Path, line: &[u8], mut failed: skep_util::file::AppendFailed) -> skep_util::file::AppendFailed {
    if REFUSE_CUT_BACK.with(Cell::take) {
        let mut file = fs::OpenOptions::new().append(true).open(path).expect("the file the copy was refused at");
        file.write_all(line).and_then(|()| file.write_all(b"\n")).expect("the copy's bytes left standing");
        failed.cut_back = Some(std::io::Error::new(std::io::ErrorKind::StorageFull, "the held store's cut-back was made to fail"));
    }
    failed
}

/// Whether the next `sync_data` is forced to fail (T5's `store_unwritable`,
/// which the `held` answer carries as `unwritable`).
pub(super) fn fail_sync() -> bool {
    FAIL_SYNC.with(Cell::get)
}

/// Returns the kind a forced sync failure is refused with: a full disk's,
/// unless [`refuse_copies_as`] set another.
pub(super) fn refused_as() -> std::io::ErrorKind {
    REFUSED_AS.with(Cell::get)
}

/// Refuses every copy's sync with `kind` until [`take_copies`] clears it.
///
/// It stands in for the device's refusal of each class the `held` answer
/// tells apart (`unwritable_class`) — a full disk's `StorageFull`, a
/// read-only volume's `ReadOnlyFilesystem` — for this suite and the hold's.
pub(crate) fn refuse_copies_as(kind: std::io::ErrorKind) {
    REFUSED_AS.with(|r| r.set(kind));
    FAIL_SYNC.with(|f| f.set(true));
}

/// Returns the bytes the next copy writes before its write is refused.
///
/// It stands in for a device that cuts a write short, as a full disk does,
/// and fires once: the copy after it is written whole.
pub(super) fn torn_write() -> Option<usize> {
    TORN_WRITE.with(Cell::take)
}

/// Refuses every copy's sync once the next `landed` copies have landed.
///
/// It stands in for a device that fills as the store writes to it — for this
/// suite and the hold's, whose probe copies on the calling thread — until
/// [`take_copies`] clears it.
pub(crate) fn refuse_copies_after(landed: usize) {
    if landed == 0 {
        FAIL_SYNC.with(|f| f.set(true));
        return;
    }
    // The refusal is armed once, at the last of the copies let land.
    let left = Cell::new(Some(landed));
    AFTER_SYNC.with(|s| {
        *s.borrow_mut() = Some(Box::new(move |_: &Path| match left.get() {
            Some(1) => {
                left.set(None);
                FAIL_SYNC.with(|f| f.set(true));
            }
            Some(n) => left.set(Some(n - 1)),
            None => {}
        }))
    });
}

/// Cuts the next copy's write short after `bytes`, once, as a full disk
/// does: for this suite and the hold's, whose one copy of several lines is
/// then written one by one.
pub(crate) fn cut_the_next_write_short(bytes: usize) {
    TORN_WRITE.with(|t| t.set(Some(bytes)));
}

/// Installs `seam` to run after each copy's sync, for this suite and the
/// hold's, until [`take_copies`] clears it: a suite reads the file there to
/// pin what is on disk before any answer is built.
pub(crate) fn on_sync(seam: impl Fn(&Path) + 'static) {
    AFTER_SYNC.with(|s| *s.borrow_mut() = Some(Box::new(seam)));
}

/// Counts the copies of lines that land from here, each one append's sync,
/// for this suite and the hold's, until [`take_copies`] clears the seam.
///
/// A file's header is its own copy, made by `file::write_once_by`, and no
/// append: it is counted none.
pub(crate) fn count_copies() -> Rc<Cell<usize>> {
    let landed = Rc::new(Cell::new(0));
    let count = Rc::clone(&landed);
    AFTER_SYNC.with(|s| *s.borrow_mut() = Some(Box::new(move |_: &Path| count.set(count.get() + 1))));
    landed
}

/// Makes the device take copies again: the refusal [`refuse_copies_after`]
/// or [`refuse_copies_as`] armed, cleared, its kind a full disk's again.
pub(crate) fn take_copies() {
    AFTER_SYNC.with(|s| *s.borrow_mut() = None);
    FAIL_SYNC.with(|f| f.set(false));
    REFUSED_AS.with(|r| r.set(std::io::ErrorKind::StorageFull));
}

/// The principal-1 file's path under `tmp`.
fn file_path(tmp: &TempDir) -> std::path::PathBuf {
    tmp.path().join("held").join(chain().to_string()).join("principal-1.held")
}

/// The seam run after a successful `sync_data`, before the append returns — a
/// suite reads the file here to pin the line ON DISK before any answer (T5).
pub(super) fn after_sync(path: &Path) {
    AFTER_SYNC.with(|s| {
        if let Some(cb) = &*s.borrow() {
            cb(path);
        }
    });
}

fn chain() -> Chain {
    Chain::parse(&"ab".repeat(32)).unwrap()
}

fn dir(tmp: &TempDir) -> HeldDir {
    let d = HeldDir::new(tmp.path(), chain());
    d.ensure().unwrap();
    d
}

fn live(opened: Opened) -> HeldQueue {
    match opened {
        Opened::Live { queue, .. } => queue,
        Opened::Halted { why, .. } => panic!("expected a live file, halted {why:?}"),
    }
}

/// The ordinals standing in a queue, in order.
fn ks(queue: &HeldQueue) -> Vec<u64> {
    queue.lines().iter().map(|l| l.k).collect()
}

// ── T1 ──────────────────────────────────────────────────────────────────────

/// Checks that the header is written once and the line forms are byte-equal.
///
/// A second open reads the header; `v` is read first — a `v: 2` header with
/// a valid body answers the newer face and reads no line; an unknown header
/// member refuses the file; a torn last line is ignored and the lines before
/// it read; a middle line that does not parse halts the file; the members'
/// order and spelling of a written line are byte-equal to §3c.2 — a line
/// without anchors, one carrying the page's anchors after its frame, an edge
/// spelled `null`, and one whose anchors name a span, its runs after the
/// edges.
#[test]
fn the_header_is_written_once_v_read_first_and_the_forms_are_byte_equal() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(7, "1.0.7").unwrap());
    assert!(!queue.on_disk(), "no file until the first append");
    let held = queue.hold_next("1.0.7.0.1", None, 5, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap();
    assert!(held.unwritten.is_none(), "{:?}", held.unwritten);
    assert_eq!(held.k, 1);
    assert!(queue.on_disk(), "the first hold writes the header and the line");
    let anchored = queue.hold_next("1.0.7.0.1", None, 5, json!({"op": "insert"}), Some(anchors(Some("1.0.7.0.1.0.1.4"), None)), Reason::of("behind", false)).unwrap();
    assert!(anchored.unwritten.is_none(), "{:?}", anchored.unwritten);
    let span = spanned(None, Some("1.0.7.0.1.0.1.9"), &[("1.0.7.0.1.0.1.1", 2), ("1.0.7.0.1.0.1.7", 1)]);
    let spanning = queue.hold_next("1.0.7.0.1", None, 5, json!({"op": "delete"}), Some(span.clone()), Reason::of("behind", false)).unwrap();
    assert!(spanning.unwritten.is_none(), "{:?}", spanning.unwritten);

    // The exact byte forms (§3c.2), the lines' `time` apart.
    let raw = fs::read_to_string(tmp.path().join("held").join(chain().to_string()).join("principal-7.held")).unwrap();
    let mut lines = raw.lines();
    assert_eq!(lines.next().unwrap(), format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{}\",\"principal\":7,\"account\":\"1.0.7\"}}", chain()));
    let held = lines.next().unwrap();
    assert!(held.starts_with("{\"held\":1,\"doc\":\"1.0.7.0.1\",\"base\":5,\"frame\":{\"op\":\"insert\"},\"cause\":\"unreachable\","), "{held}");
    assert!(held.contains(",\"sent\":false,\"time\":") && held.ends_with('}'), "{held}");
    let held = lines.next().unwrap();
    assert!(held.starts_with("{\"held\":2,\"doc\":\"1.0.7.0.1\",\"base\":5,\"frame\":{\"op\":\"insert\"},\"anchors\":{\"before\":\"1.0.7.0.1.0.1.4\",\"after\":null},\"cause\":\"behind\","), "{held}");
    let held = lines.next().unwrap();
    assert!(
        held.starts_with("{\"held\":3,\"doc\":\"1.0.7.0.1\",\"base\":5,\"frame\":{\"op\":\"delete\"},\"anchors\":{\"before\":null,\"after\":\"1.0.7.0.1.0.1.9\",\"span\":[{\"start\":\"1.0.7.0.1.0.1.1\",\"width\":\"2\"},{\"start\":\"1.0.7.0.1.0.1.7\",\"width\":\"1\"}]},\"cause\":\"behind\","),
        "{held}"
    );

    // A second open reads the header and the standing lines, the anchors
    // with theirs.
    let reopened = live(d.open_file(7, "1.0.7").unwrap());
    assert_eq!(reopened.lines().len(), 3);
    assert_eq!(reopened.lines()[0].doc, "1.0.7.0.1");
    let read: Vec<Option<Anchors>> = reopened.lines().iter().map(|l| l.anchors.clone()).collect();
    assert_eq!(read, [None, Some(anchors(Some("1.0.7.0.1.0.1.4"), None)), Some(span)]);

    // `v: 2` with a valid body → the NEWER face, no line read (v FIRST).
    let d2 = {
        let d = HeldDir::new(tmp.path(), Chain::parse(&"cd".repeat(32)).unwrap());
        d.ensure().unwrap();
        d
    };
    let p2 = tmp.path().join("held").join(Chain::parse(&"cd".repeat(32)).unwrap().to_string()).join("principal-1.held");
    fs::write(
        &p2,
        format!("{{\"type\":\"skep-held-bursts\",\"v\":2,\"board\":\"{}\",\"principal\":1,\"account\":\"1.0.1\",\"later\":true}}\n{{\"held\":1}}\n", Chain::parse(&"cd".repeat(32)).unwrap()),
    )
    .unwrap();
    match d2.open_file(1, "1.0.1").unwrap() {
        Opened::Halted { why, .. } => assert_eq!(why, HaltWhy::Newer, "v read before the unknown member"),
        Opened::Live { .. } => panic!("a newer v must halt"),
    }

    // An unknown member on a `v: 1` header refuses the file.
    fs::write(&p2, format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{}\",\"principal\":1,\"account\":\"1.0.1\",\"later\":true}}\n", Chain::parse(&"cd".repeat(32)).unwrap())).unwrap();
    assert!(matches!(d2.open_file(1, "1.0.1").unwrap(), Opened::Halted { why: HaltWhy::UnknownMember, .. }));

    // A torn last line is ignored; the lines before it read.
    let chain2 = Chain::parse(&"cd".repeat(32)).unwrap();
    fs::write(&p2, format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{chain2}\",\"principal\":1,\"account\":\"1.0.1\"}}\n{{\"held\":1,\"doc\":\"1.0.1.0.1\",\"base\":0,\"frame\":{{}},\"cause\":\"stopped\",\"sent\":false,\"time\":1}}\n{{\"held\":2,\"doc\"")).unwrap();
    let torn = live(d2.open_file(1, "1.0.1").unwrap());
    assert_eq!(torn.lines().len(), 1, "the torn last line is ignored");
    assert_eq!(torn.lines()[0].k, 1);

    // A damaged MIDDLE line halts the file.
    fs::write(&p2, format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{chain2}\",\"principal\":1,\"account\":\"1.0.1\"}}\n{{not json}}\n{{\"held\":2,\"doc\":\"x\",\"base\":0,\"frame\":{{}},\"cause\":\"stopped\",\"sent\":false,\"time\":1}}\n")).unwrap();
    assert!(matches!(d2.open_file(1, "1.0.1").unwrap(), Opened::Halted { why: HaltWhy::Damaged, .. }));
}

/// A HEADER OF ANOTHER FORM halts with its own face (§3c.2, P38): a `type`
/// not the store's, or none, no `v`, a `v` of 0 or of a string — each the
/// unknown-member face; a newer `v` the newer face whatever its `type`, `v`
/// read first; a whole header line that is no JSON object the damaged face
/// (the mutants that drop the `type` check, read a missing `v` as 1, take
/// any `v` but 1 as newer, or read `type` before `v`). A file with no whole
/// header line is no header of another form: it is a crash's tail, read as
/// fresh (the next test).
#[test]
fn a_header_of_another_form_halts_with_its_face() {
    let header = |members: &str| format!("{{{members}\"board\":\"{}\",\"principal\":1,\"account\":\"1.0.1\"}}\n", chain());
    let cells = [
        ("a type not the store's", header("\"type\":\"skep-other\",\"v\":1,"), HaltWhy::UnknownMember),
        ("no type", header("\"v\":1,"), HaltWhy::UnknownMember),
        ("no v", header("\"type\":\"skep-held-bursts\","), HaltWhy::UnknownMember),
        ("a v of 0", header("\"type\":\"skep-held-bursts\",\"v\":0,"), HaltWhy::UnknownMember),
        ("a v of a string", header("\"type\":\"skep-held-bursts\",\"v\":\"1\","), HaltWhy::UnknownMember),
        ("a newer v of another type", header("\"type\":\"skep-other\",\"v\":3,"), HaltWhy::Newer),
        ("no object", "[1]\n".to_string(), HaltWhy::Damaged),
    ];
    for (cell, header, why) in cells {
        let tmp = TempDir::new().unwrap();
        let d = dir(&tmp);
        fs::write(tmp.path().join("held").join(chain().to_string()).join("principal-1.held"), header).unwrap();
        match d.open_file(1, "1.0.1").unwrap() {
            Opened::Halted { why: halted, .. } => assert_eq!(halted, why, "{cell}"),
            Opened::Live { .. } => panic!("{cell}: read live"),
        }
    }
}

/// A FILE WITH NO WHOLE HEADER LINE is read as FRESH (§3c.3; the tail rule's
/// class A at the file's head): an empty file, and a header torn before its
/// newline, each open `Live` with no lines, the open answering what it found
/// for the shell to say once; the next hold cuts the file's bytes and heads
/// it, its line on disk, and a reopen reads that line and halts on nothing;
/// a torn LAST line is answered the same way, as the line it is (the mutant
/// that halts on a torn header blocks every burst of the principal at the
/// board until a person removes a file that holds no line; the one that
/// makes the file anew under `create_new` refuses every copy
/// `AlreadyExists`).
#[test]
fn a_file_with_no_whole_header_line_is_read_as_fresh_and_headed_by_the_next_line() {
    let header = format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{}\",\"principal\":1,\"account\":\"1.0.1\"}}\n", chain());
    let cells = [("an empty file", String::new()), ("a header torn before its newline", header.trim_end().to_string())];
    for (cell, body) in cells {
        let tmp = TempDir::new().unwrap();
        let d = dir(&tmp);
        fs::write(file_path(&tmp), &body).unwrap();
        let mut queue = live(d.open_file(1, "1.0.1").unwrap());
        assert!(queue.lines().is_empty(), "{cell}: opened fresh");
        assert_eq!(queue.torn(), Some(Torn::Header { bytes: body.len() as u64 }), "{cell}: the open answers what it found");
        let held = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap();
        assert!(held.unwritten.is_none(), "{cell}: {:?}", held.unwritten);
        assert_eq!(held.k, 1);
        let raw = fs::read_to_string(file_path(&tmp)).unwrap();
        assert!(raw.starts_with(&format!("{header}{{\"held\":1,")), "{cell}: the file cut and headed:\n{raw}");
        let reopened = live(d.open_file(1, "1.0.1").unwrap());
        assert_eq!(ks(&reopened), [1], "{cell}: the next hold's line read back");
        assert_eq!(reopened.torn(), None, "{cell}: the file reads whole now");
    }
    let tmp = TempDir::new().unwrap();
    let torn = b"{\"held\":1,\"doc\"";
    let queue = live(opened_over(&tmp, torn));
    assert_eq!(queue.torn(), Some(Torn::Line { bytes: torn.len() as u64 }), "a torn last line answered as the line it is");
}

// ── T2 ──────────────────────────────────────────────────────────────────────

/// A MISPLACED file — header `board` another chain, or `principal` not the
/// file's name — is moved aside under `aside_name`'s form by a rename that
/// never overwrites an existing aside (`.1`, then `.2`), the open naming the
/// aside for the shell's own window to say; this principal's file is started
/// fresh, the aside byte-equal to the original.
#[test]
fn a_misplaced_file_is_moved_aside_without_overwriting() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let other = Chain::parse(&"ef".repeat(32)).unwrap();
    let board_dir = tmp.path().join("held").join(chain().to_string());
    let p = board_dir.join("principal-3.held");

    let misplaced = format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{other}\",\"principal\":3,\"account\":\"1.0.3\"}}\n");
    fs::write(&p, &misplaced).unwrap();
    let aside1 = board_dir.join(aside_name("principal-3.held", &other, 1));
    let fresh = match d.open_file(3, "1.0.3").unwrap() {
        Opened::Live { queue, aside } => {
            assert_eq!(aside.as_deref(), Some(aside1.as_path()), "the open names the aside");
            queue
        }
        Opened::Halted { why, .. } => panic!("a misplaced file is set aside, never halted: {why:?}"),
    };
    assert!(fresh.lines().is_empty() && !fresh.on_disk(), "the file is started fresh");
    assert_eq!(fs::read_to_string(&aside1).unwrap(), misplaced, "the aside is byte-equal to the original");

    // A second misplaced file of the same board lands beside the first at `.2`.
    fs::write(&p, &misplaced).unwrap();
    let _ = live(d.open_file(3, "1.0.3").unwrap());
    let aside2 = board_dir.join(aside_name("principal-3.held", &other, 2));
    assert!(aside1.exists() && aside2.exists(), "neither aside is overwritten");

    // A principal that is not the file's name is misplaced too.
    let p9 = board_dir.join("principal-9.held");
    fs::write(&p9, format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{}\",\"principal\":3,\"account\":\"1.0.3\"}}\n", chain())).unwrap();
    let _ = live(d.open_file(9, "1.0.9").unwrap());
    assert!(board_dir.join(aside_name("principal-9.held", &chain(), 1)).exists(), "a principal off its name is set aside under the dir's own chain");
}

// ── T3 ──────────────────────────────────────────────────────────────────────

/// THE LOCK: a second holder's `try_lock` on `held/<chain>/lock` fails while
/// the first stands and succeeds after it is dropped.
#[test]
fn the_lock_admits_one_holder_at_a_time() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let first = d.try_lock().unwrap().expect("the first shell takes the lock");
    assert!(d.try_lock().unwrap().is_none(), "a second shell finds it held");
    drop(first);
    assert!(d.try_lock().unwrap().is_some(), "and takes it once the first is gone");
}

// ── T4 ──────────────────────────────────────────────────────────────────────

/// COMPACTION: once every `held` line has its `done` the file is gone; with one
/// line still held it stands; the two `done` forms are byte-equal to §3c.2 —
/// `kept` with its `at`, `dropped` with none; a `done` for an ordinal with no
/// `held` line is refused by the writer.
#[test]
fn the_file_compacts_once_every_line_is_done() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let k1 = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("stopped", false)).unwrap().k;
    let k2 = queue.hold_next("1.0.1.0.2", None, 0, json!({"op": "delete"}), None, Reason::of("behind", false)).unwrap().k;
    let k3 = queue.hold_next("1.0.1.0.3", None, 0, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap().k;
    assert!(matches!(queue.done(99, Done::Kept { at: None }), Err(DoneError::NoSuchLine)), "a done for no line is refused");
    queue.done(k1, Done::Kept { at: Some(42) }).unwrap();
    queue.done(k2, Done::Dropped).unwrap();
    assert!(queue.on_disk(), "one line still held keeps the file");
    assert_eq!(ks(&queue), [k3]);
    let raw = fs::read_to_string(tmp.path().join("held").join(chain().to_string()).join("principal-1.held")).unwrap();
    let done: Vec<&str> = raw.lines().filter(|l| l.starts_with("{\"done\"")).collect();
    assert!(done[0].starts_with("{\"done\":1,\"as\":\"kept\",\"at\":42,\"time\":"), "{raw}");
    assert!(done[1].starts_with("{\"done\":2,\"as\":\"dropped\",\"time\":"), "{raw}");
    queue.done(k3, Done::Dropped).unwrap();
    assert!(!queue.on_disk(), "the file is gone once every line is done");
    assert!(queue.lines().is_empty());
}

// ── T5 ──────────────────────────────────────────────────────────────────────

/// PERSIST-FIRST: a successful append's line is ON DISK before the append
/// returns — pinned by reading the file in the seam the answer is built
/// after; an append whose `sync_data` is made to fail answers §3c.3's
/// `store_unwritable` (the device's I/O error, which the `held` answer
/// carries as `unwritable`) BESIDE a line that stands in the queue under
/// its ordinal, its bytes cut back off the file, the next line taking the
/// ordinal after it — copied behind the refused line, which the retry copies
/// first — and a reopen reading all three (the mutant that keeps the refused
/// line out of the queue loses the burst its `held` answer promised; the one
/// that leaves its bytes on the file keeps pages a refused sync may never
/// write, behind every later line; the one that copies the next line ahead
/// of it leaves a file holding a burst without the one it was composed
/// after).
#[test]
fn an_appends_line_is_on_disk_before_its_answer() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());

    // The successful append: the seam, run after the sync, finds the line.
    let seen = Arc::new(Mutex::new(false));
    let probe = Arc::clone(&seen);
    AFTER_SYNC.with(|s| {
        *s.borrow_mut() = Some(Box::new(move |p: &Path| {
            let on_disk = fs::read_to_string(p).unwrap_or_default().contains("\"doc\":\"1.0.1.0.1\"");
            *probe.lock().unwrap() = on_disk;
        }))
    });
    let first = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("stopped", false)).unwrap();
    assert!(first.unwritten.is_none(), "{:?}", first.unwritten);
    assert!(*seen.lock().unwrap(), "the line is on disk when the append's seam runs, before the answer");
    AFTER_SYNC.with(|s| *s.borrow_mut() = None);

    // The forced sync failure: the device's refusal beside a line that stands.
    FAIL_SYNC.with(|f| f.set(true));
    let refused = queue.hold_next("1.0.1.0.2", None, 0, json!({"op": "insert"}), None, Reason::of("stopped", false)).unwrap();
    FAIL_SYNC.with(|f| f.set(false));
    assert_eq!(refused.unwritten.expect("the device refused the copy").kind(), std::io::ErrorKind::StorageFull, "store_unwritable, answered `unwritable`");
    assert_eq!(refused.k, 2);
    assert_eq!(ks(&queue), [1, 2], "the refused line stands in the queue");
    assert!(!fs::read_to_string(file_path(&tmp)).unwrap().contains("\"doc\":\"1.0.1.0.2\""), "its bytes cut back off the file");
    let next = queue.hold_next("1.0.1.0.3", None, 0, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap();
    assert!(next.unwritten.is_none());
    assert_eq!((next.k, ks(&queue)), (3, vec![1, 2, 3]), "the next line takes the ordinal after it");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [1, 2, 3], "a reopen reads every line, the refused one copied before the next");
}

/// A QUEUE WHOSE FILE IS NOT YET READ (§3c.3) enters, re-marks and settles
/// lines as a file's does, under the same ordinals, writes nothing — the
/// file may hold an earlier run's lines no write may land behind — and
/// answers the store's refusal for every line held, each waiting for its
/// first copy under it; a file standing at its path is neither read nor
/// removed, the queue emptying or not (the mutant that writes to an unread
/// file lands lines behind an earlier run's; the one that compacts it
/// removes a file it never read; the one that answers no refusal tells the
/// page a line a close loses is on disk).
#[test]
fn a_queue_whose_file_is_not_yet_read_keeps_its_lines_and_writes_nothing() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    // An earlier run's file stands at the path, unread.
    let mut earlier = live(d.open_file(1, "1.0.1").unwrap());
    earlier.hold_next("1.0.1.0.9", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap();
    let before = fs::read(file_path(&tmp)).unwrap();
    let mut queue = HeldQueue::unopened(&d, 1, "1.0.1");
    assert!(!queue.is_opened() && queue.waiting().is_none() && queue.path() == file_path(&tmp), "the file named, not read");
    queue.refuse(std::io::Error::new(std::io::ErrorKind::ReadOnlyFilesystem, "the held store could not be made or locked: Read-only file system"));
    let k1 = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", true)).unwrap();
    let k2 = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap();
    assert_eq!((k1.k, k2.k), (1, 2));
    let kinds = (k1.unwritten.map(|e| e.kind()), k2.unwritten.map(|e| e.kind()));
    assert_eq!(kinds, (Some(std::io::ErrorKind::ReadOnlyFilesystem), Some(std::io::ErrorKind::ReadOnlyFilesystem)), "the store's refusal rides every line held");
    assert_eq!(queue.waiting().map(|w| (w.first(), w.owed(), w.refusal().kind())), Some((1, Owed::Line, std::io::ErrorKind::ReadOnlyFilesystem)), "every line waits under it, the first named");
    queue.remark(1, Reason::refused("out_of_bounds", json!({"code": "out_of_bounds"}))).unwrap();
    assert_eq!(queue.lines()[0].reason, Reason::refused("out_of_bounds", json!({"code": "out_of_bounds"})));
    queue.done(1, Done::Dropped).unwrap();
    assert_eq!(ks(&queue), [2]);
    queue.done(2, Done::Dropped).unwrap();
    assert!(ks(&queue).is_empty() && queue.waiting().is_none(), "nothing waits once no line stands");
    assert_eq!(fs::read(file_path(&tmp)).unwrap(), before, "the file at its path is neither written nor removed");
}

/// A RE-MARK reads back as the line it re-marks: a line held, re-marked
/// `moved`, and the file opened again holds ONE line, of that ordinal and
/// the new cause (the mutant reader that takes every `held` line as a new
/// one lists the burst twice and re-projects the person's text twice).
#[test]
fn a_remarked_line_reads_back_once_with_its_new_cause() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let k = queue.hold_next("1.0.1.0.1", None, 4, json!({"op": "insert"}), None, Reason::of("unreachable", true)).unwrap().k;
    queue.hold_next("1.0.1.0.2", None, 4, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap();
    queue.remark(k, Reason::of("moved", false)).unwrap();
    queue.remark(k, Reason::of("moved", false)).unwrap();
    let reopened = live(d.open_file(1, "1.0.1").unwrap());
    assert_eq!(ks(&reopened), [k, k + 1], "one line per ordinal, in `k` order");
    assert_eq!((reopened.lines()[0].reason.cause.as_str(), reopened.lines()[0].reason.sent), ("moved", false));
    assert_eq!(reopened.lines()[0].base, 4, "the re-mark keeps the line's own members");
}

/// Checks that a `done` the device refused settles its line and is owed until
/// the retry writes it (§3c.3; skep #821).
///
/// For a line kept and for one dropped, the line leaves the queue, so the
/// resend that acked it never sends it again (the mutant that keeps the line
/// standing resends the acked burst at once); its `done` is owed, the queue's
/// wait naming it and the device's refusal, and its bytes are cut back off
/// the file, so a reopen before the retry reads the line as held again; the
/// retry writes it, and a reopen then reads the line no more (the mutant that
/// writes a refused `done` once and never again brings a dropped line back at
/// every relaunch, and the board meets a write the person threw away).
#[test]
fn a_done_the_device_refused_settles_its_line_and_is_owed_until_the_retry_writes_it() {
    for done in [Done::Kept { at: Some(9) }, Done::Dropped] {
        let tmp = TempDir::new().unwrap();
        let d = dir(&tmp);
        let mut queue = live(d.open_file(1, "1.0.1").unwrap());
        let k1 = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
        let k2 = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap().k;
        FAIL_SYNC.with(|f| f.set(true));
        let settled = queue.done(k1, done).unwrap();
        FAIL_SYNC.with(|f| f.set(false));
        assert!(settled.unremoved.is_none(), "{done:?}: {settled:?}");
        assert_eq!(ks(&queue), [k2], "{done:?}: the settled line has left the queue");
        let owed = queue.waiting().map(|w| (w.first(), w.owed(), w.refusal().kind()));
        assert_eq!(owed, Some((k1, Owed::Done, std::io::ErrorKind::StorageFull)), "{done:?}: its `done` is owed");
        assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [k1, k2], "{done:?}: a reopen before the retry reads the line as held again");
        queue.retry();
        assert!(queue.waiting().is_none(), "{done:?}: nothing is owed");
        assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [k2], "{done:?}: the retry wrote the `done`");
    }
}

/// A HELD FILE THE COMPACTION CANNOT REMOVE is kept and appended on — the
/// removal's answer read, never assumed: every line done and the unlink
/// refused, the directory sealed against it, the settle answers the failure
/// naming the path, the file stands, the next hold APPENDS to it (no
/// `AlreadyExists`) under an ordinal past the file's, and a reopen reads
/// that line; the directory writable again, the next compaction removes it
/// and the ordinals run on (the mutant that marks the file gone refuses
/// every later line `AlreadyExists` and keeps every burst after it in
/// memory alone, lost at a relaunch).
#[cfg(unix)]
#[test]
fn a_held_file_the_compaction_cannot_remove_is_kept_and_appended_on() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let board_dir = tmp.path().join("held").join(chain().to_string());
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let k = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
    fs::set_permissions(&board_dir, fs::Permissions::from_mode(0o500)).unwrap();
    let settled = queue.done(k, Done::Kept { at: Some(3) }).unwrap();
    assert!(queue.waiting().is_none(), "the `done` is on disk: {settled:?}");
    let (path, _) = settled.unremoved.expect("the removal's failure is answered");
    assert_eq!(path, file_path(&tmp));
    assert!(queue.on_disk() && queue.lines().is_empty(), "the file stands, every line done");
    let next = queue.hold_next("1.0.1.0.2", None, 0, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap();
    assert!(next.unwritten.is_none(), "the next hold appends to the standing file: {:?}", next.unwritten);
    assert_eq!(next.k, 2, "an ordinal past the file's");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [2], "a reopen reads the line");
    fs::set_permissions(&board_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let settled = queue.done(2, Done::Dropped).unwrap();
    assert!(settled.unremoved.is_none() && !queue.on_disk(), "writable again, the compaction removes the file");
    assert_eq!(queue.hold_next("1.0.1.0.3", None, 0, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap().k, 3, "the ordinals run on once the file is gone");
}

/// A TORN LAST LINE is cut before the next line is written (R14; P38): a
/// file whose last line a crash tore reopens with the lines before it, and
/// the first copy after — a hold, or a `done` — is written where the last
/// whole line ends, so the next open reads every line and halts on none
/// (the mutant that appends past the torn bytes glues them to the new line,
/// one line the reader halts on, the person's every held burst out of reach
/// with it; the one that cuts before a hold's line alone glues a `done`).
#[test]
fn a_torn_last_line_is_cut_before_the_next_line_is_written() {
    let whole = |k: u64| format!("{{\"held\":{k},\"doc\":\"1.0.1.0.1\",\"base\":0,\"frame\":{{\"op\":\"insert\"}},\"cause\":\"stopped\",\"sent\":false,\"time\":1}}\n");
    for done in [false, true] {
        let tmp = TempDir::new().unwrap();
        let body = format!("{}{}{{\"held\":3,\"doc\":\"1.0.1.0.1\",\"ba", whole(1), whole(2));
        let mut queue = live(opened_over(&tmp, body.as_bytes()));
        assert_eq!(ks(&queue), [1, 2], "done {done}: the torn line ignored");
        if done {
            queue.done(1, Done::Kept { at: Some(9) }).unwrap();
        } else {
            let held = queue.hold_next("1.0.1.0.3", None, 0, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap();
            assert!(held.unwritten.is_none(), "{:?}", held.unwritten);
        }
        let want: &[u64] = if done { &[2] } else { &[1, 2, 3] };
        assert_eq!(ks(&live(dir(&tmp).open_file(1, "1.0.1").unwrap())), want, "done {done}: every line read, none glued");
    }
}

/// A COPY CUT SHORT leaves the file as it was: a line whose write the
/// device cut part-way, as a full disk does, answers `unwritable` and
/// stands in the queue, its bytes cut back off the file, so the retry at the
/// next hold copies it where the last whole line ends, the next line after
/// it, and a reopen reads every line (the mutant that skips the cut-back
/// leaves on the file the bytes its `unwritable` answer says it does not
/// hold, glued to the retry's copy).
#[test]
fn a_copy_cut_short_leaves_the_file_as_it_was() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    assert!(queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().unwritten.is_none());
    let before = fs::read(file_path(&tmp)).unwrap();
    TORN_WRITE.with(|t| t.set(Some(20)));
    let cut = queue.hold_next("1.0.1.0.2", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap();
    assert_eq!(cut.unwritten.map(|e| e.kind()), Some(std::io::ErrorKind::StorageFull), "the device cut the copy short");
    assert_eq!(fs::read(file_path(&tmp)).unwrap(), before, "its bytes cut back off the file");
    assert_eq!(ks(&queue), [1, 2], "and the line stands in the queue");
    assert!(queue.hold_next("1.0.1.0.3", None, 0, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap().unwritten.is_none());
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [1, 2, 3], "a reopen reads every line, the cut one copied in its place");
}

/// A HEADER THE DEVICE DID NOT TAKE WHOLE leaves no file (`write_once`'s
/// idiom): a header write cut short, and a header sync refused, each answer
/// the line `unwritable`, the line standing in the queue and the file the
/// header began removed, so the retry at the next hold makes the file again
/// under `create_new`, header first, the waiting line and then the next one
/// in it, and a reopen reads both (the mutant that leaves the half-made file
/// refuses every later copy `AlreadyExists`, and closed with a line standing
/// leaves a file the next open halts on).
#[test]
fn a_header_the_device_did_not_take_whole_leaves_no_file() {
    for torn in [true, false] {
        let tmp = TempDir::new().unwrap();
        let d = dir(&tmp);
        let mut queue = live(d.open_file(1, "1.0.1").unwrap());
        if torn {
            TORN_WRITE.with(|t| t.set(Some(5)));
        } else {
            FAIL_SYNC.with(|f| f.set(true));
        }
        let first = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap();
        FAIL_SYNC.with(|f| f.set(false));
        assert_eq!(first.unwritten.map(|e| e.kind()), Some(std::io::ErrorKind::StorageFull), "torn {torn}: the device refused the header");
        assert!(!queue.on_disk(), "torn {torn}: the half-made file is removed");
        assert_eq!(ks(&queue), [1], "torn {torn}: the line stands in the queue");
        let next = queue.hold_next("1.0.1.0.2", None, 0, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap();
        assert!(next.unwritten.is_none(), "torn {torn}: {:?}", next.unwritten);
        assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [1, 2], "torn {torn}: a reopen reads both lines, in order");
    }
}

/// AFTER COMPACTION the next line recreates the file, header first (§3c.3):
/// the queue emptied and its file removed, the next hold writes T1's header
/// once more and its line under the next ordinal, 2 — the ordinals run on,
/// never wound back (skep #856) — on disk, so a reopen reads it (the mutant
/// that keeps the removed file marked created appends to a file that is
/// gone, and every burst held after the first resend is one a crash would
/// lose; the one that starts the ordinals again at the compaction hands the
/// page an ordinal it was told was kept).
#[test]
fn after_compaction_the_next_line_recreates_the_file_header_first() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let k = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("stopped", false)).unwrap().k;
    queue.done(k, Done::Dropped).unwrap();
    assert!(!queue.on_disk(), "the file compacted away");
    assert_eq!(queue.greatest_k(), 1, "the greatest ordinal named stands");
    let again = queue.hold_next("1.0.1.0.2", None, 0, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap();
    assert!(again.unwritten.is_none(), "{:?}", again.unwritten);
    assert_eq!(again.k, 2, "the ordinals run on");
    let raw = fs::read_to_string(tmp.path().join("held").join(chain().to_string()).join("principal-1.held")).unwrap();
    let mut lines = raw.lines();
    assert_eq!(lines.next().unwrap(), format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{}\",\"principal\":1,\"account\":\"1.0.1\"}}", chain()));
    assert!(lines.next().unwrap().starts_with("{\"held\":2,\"doc\":\"1.0.1.0.2\","), "{raw}");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [2], "a reopen reads the line");
}

/// A REOPENED QUEUE takes an ordinal past every one its file names (§3c.2:
/// `k`, the file's monotone ordinal): three lines held and the last two
/// `done`, the file reopened holds the first alone, and the next line held
/// takes ordinal 4 — never one a line or a `done` of the file already names
/// — so a second reopen reads both (the mutants that start the ordinals
/// over, or count from the standing lines, reuse an ordinal, and the next
/// open reads the new line as a RE-MARK of the old one: the person's first
/// burst gone).
#[test]
fn a_reopened_queue_takes_an_ordinal_past_every_one_its_file_names() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    for doc in ["1.0.1.0.1", "1.0.1.0.2", "1.0.1.0.3"] {
        queue.hold_next(doc, None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap();
    }
    queue.done(2, Done::Dropped).unwrap();
    queue.done(3, Done::Kept { at: Some(9) }).unwrap();
    let mut reopened = live(d.open_file(1, "1.0.1").unwrap());
    assert_eq!((ks(&reopened), reopened.greatest_k()), (vec![1], 3), "the greatest ordinal the file names, held or done");
    let next = reopened.hold_next("1.0.1.0.4", None, 0, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap();
    assert_eq!(next.k, 4, "past every ordinal the file names");
    let read: Vec<(u64, String)> = live(d.open_file(1, "1.0.1").unwrap()).lines().iter().map(|l| (l.k, l.doc.clone())).collect();
    assert_eq!(read, [(1, "1.0.1.0.1".to_string()), (4, "1.0.1.0.4".to_string())], "both lines read back");
}

/// Checks that a line kept at a position is the base of the lines behind it.
///
/// A line kept at a position raises to it the `base` of every line held
/// after it on its document — a line before it, a line on another document
/// and a base already past the position each keep their own — and a reopen
/// raises them again from the `done` line (the mutants that never raise,
/// raise every document's lines or the lines before it, lower a base past
/// the position, or forget the raise at a reopen).
#[test]
fn a_line_kept_at_a_position_is_the_base_of_the_lines_behind_it() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let held: Vec<u64> = [("1.0.1.0.1", 0), ("1.0.1.0.1", 0), ("1.0.1.0.1", 0), ("1.0.1.0.2", 0), ("1.0.1.0.1", 99)]
        .into_iter()
        .map(|(doc, base)| queue.hold_next(doc, None, base, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k)
        .collect();
    queue.done(held[1], Done::Kept { at: Some(42) }).unwrap();
    let bases = |queue: &HeldQueue| queue.lines().iter().map(|l| (l.k, l.base)).collect::<Vec<_>>();
    let raised = [(held[0], 0), (held[2], 42), (held[3], 0), (held[4], 99)];
    assert_eq!(bases(&queue), raised);
    assert_eq!(bases(&live(d.open_file(1, "1.0.1").unwrap())), raised, "a reopen raises them from the `done` line");
}

/// Returns each standing line's ordinal and base, in `k` order.
fn bases(queue: &HeldQueue) -> Vec<(u64, u64)> {
    queue.lines().iter().map(|l| (l.k, l.base)).collect()
}

/// Checks that a line held after a kept line keeps its own base (skep #816).
///
/// Two lines on one document held at 0, the first kept at 50, raise the
/// second to 50; a third held at 10 after it stays at 10, as it did not
/// stand when the first was kept; the second kept at 60 then raises it to
/// 60; and a reopen reads each base as the queue holds it, after the third
/// is held and at the end (the mutant whose floor raises every line of its
/// document, held before it or after, lifts the third to 50, and its read
/// for its own landing starts past that landing).
#[test]
fn a_line_held_after_a_kept_line_keeps_its_own_base() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let hold = |queue: &mut HeldQueue, base: u64| queue.hold_next("1.0.1.0.1", None, base, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
    let (a, b) = (hold(&mut queue, 0), hold(&mut queue, 0));
    queue.done(a, Done::Kept { at: Some(50) }).unwrap();
    assert_eq!(bases(&queue), [(b, 50)], "the kept line raises the line behind it");
    let c = hold(&mut queue, 10);
    assert_eq!(bases(&queue), [(b, 50), (c, 10)], "a line held after the raise keeps its own base");
    assert_eq!(bases(&live(d.open_file(1, "1.0.1").unwrap())), [(b, 50), (c, 10)], "and a reopen reads it so");
    queue.done(b, Done::Kept { at: Some(60) }).unwrap();
    assert_eq!(bases(&queue), [(c, 60)], "the next line kept raises it");
    assert_eq!(bases(&live(d.open_file(1, "1.0.1").unwrap())), [(c, 60)], "and a reopen reads it so");
}

/// Checks that a lower raise lifts only the lines it stood with (skep #816).
///
/// Three lines on one document held at 0, the first kept at 50, raise the
/// other two to 50; a fourth held at 0 after it stays at 0; the second kept
/// at 40 then raises the fourth to 40 and leaves the third at 50, a base
/// already past it; and a reopen reads each base as the queue holds it (the
/// mutant that drops the higher floor as the lower one is given lowers the
/// third to 40; the one that reads a line's floor off the last floor given
/// after it lowers it too; the one whose floors raise a line held after
/// them lifts the fourth to 50).
#[test]
fn a_kept_line_below_an_earlier_raise_raises_only_the_lines_it_stood_with() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let hold = |queue: &mut HeldQueue| queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
    let (a, b, c) = (hold(&mut queue), hold(&mut queue), hold(&mut queue));
    queue.done(a, Done::Kept { at: Some(50) }).unwrap();
    let e = hold(&mut queue);
    assert_eq!(bases(&queue), [(b, 50), (c, 50), (e, 0)], "the lines that stood raised, the one held after not");
    queue.done(b, Done::Kept { at: Some(40) }).unwrap();
    assert_eq!(bases(&queue), [(c, 50), (e, 40)], "the lower raise lifts the line held after the first, and lowers none");
    assert_eq!(bases(&live(d.open_file(1, "1.0.1").unwrap())), [(c, 50), (e, 40)], "a reopen reads the same bases");
}

/// Checks that a re-mark read after a kept line is taken whole (§3c.2).
///
/// It is a file of two lines on one document, the first kept at 50, and
/// the second's re-mark after the `done`, spelling a base of 7: the reader
/// takes a `held` line of a standing ordinal in the earlier line's place,
/// its base the one it spells, so the second reads 7 — a writer re-marks a
/// line with its base as raised, so a file a writer made never spells one
/// below a raise (the mutant reader that keeps a re-marked line under the
/// floors given before its re-mark reads it at 50, past the base its last
/// copy spells).
#[test]
fn a_remark_read_after_a_kept_line_is_taken_whole() {
    let tmp = TempDir::new().unwrap();
    let line = |k: u64, base: u64| format!("{{\"held\":{k},\"doc\":\"1.0.1.0.1\",\"base\":{base},\"frame\":{{\"op\":\"insert\"}},\"cause\":\"unreachable\",\"sent\":false,\"time\":1}}\n");
    let body = format!("{}{}{{\"done\":1,\"as\":\"kept\",\"at\":50,\"time\":1}}\n{}", line(1, 0), line(2, 0), line(2, 7));
    assert_eq!(bases(&live(opened_over(&tmp, body.as_bytes()))), [(2, 7)]);
}

/// The eager raise's model of a queue's lines (skep #816).
///
/// It raises the lines behind a kept line one by one: the model a queue's
/// lines are checked against.
#[derive(Default)]
struct Eager {
    /// The standing lines, in `k` order.
    lines: Vec<HeldLine>,
}

impl Eager {
    /// Holds or joins `line`, entered where its ordinal falls.
    fn enter(&mut self, line: HeldLine) {
        let at = self.lines.partition_point(|l| l.k < line.k);
        self.lines.insert(at, line);
    }

    /// Takes line `k` out, as a `done` of it does.
    ///
    /// A line kept at a position raises every line after it on its document
    /// to it.
    fn done(&mut self, k: u64, done: Done) {
        let Some(index) = self.lines.iter().position(|l| l.k == k) else { return };
        let line = self.lines.remove(index);
        if let Done::Kept { at: Some(at) } = done {
            for behind in self.lines[index..].iter_mut().filter(|l| l.doc == line.doc) {
                behind.base = behind.base.max(at);
            }
        }
    }

    /// Re-marks line `k`, its base raised to `raise` where that is past it.
    fn remark(&mut self, k: u64, reason: &Reason, raise: Option<u64>) {
        if let Some(line) = self.lines.iter_mut().find(|l| l.k == k) {
            line.reason = reason.clone();
            line.base = raise.map_or(line.base, |at| line.base.max(at));
        }
    }

    /// Rewrites line `k`'s frame.
    fn rewrite(&mut self, k: u64, frame: &Value) {
        if let Some(line) = self.lines.iter_mut().find(|l| l.k == k) {
            line.frame = frame.clone();
        }
    }
}

/// Returns each line's members but its `time`, which the clock sets.
///
/// They are the members the model holds alike: a re-mark sets the `time`.
fn modeled(lines: &[HeldLine]) -> Vec<(u64, String, u64, Value, Reason)> {
    lines.iter().map(|l| (l.k, l.doc.clone(), l.base, l.frame.clone(), l.reason.clone())).collect()
}

/// A seeded xorshift, so a model cell takes the same acts at every run.
struct Xorshift(u64);

impl Xorshift {
    /// Returns a number below `n`.
    ///
    /// # Panics
    ///
    /// Panics where `n` is 0.
    fn below(&mut self, n: u64) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x % n
    }
}

/// Runs `acts` seeded acts over `queue` and the eager model alike.
///
/// The acts are holds, each past every ordinal given and an ordinal passed
/// over now and then; `done`s kept at a rising or a falling position, on a
/// document's first line or any; drops; runs of `done`s; re-marks, alone
/// and as a document's run with a raise; shifts of a frame; and joins of
/// this run's lines under the ordinals the holds passed over, below lines
/// that stand — over three documents. After each act the queue's lines are
/// the model's, and every `reopen_every` acts so are `reopened`'s, where it
/// reads any.
fn modeled_acts(queue: &mut HeldQueue, store: &HeldDir, acts: usize, seed: u64, reopen_every: usize, reopened: impl Fn() -> Option<Vec<HeldLine>>) {
    let docs = ["1.0.1.0.1", "1.0.1.0.2", "1.0.1.0.3"];
    let reasons = [Reason::of("behind", false), Reason::of("moved", false), Reason::of("unreachable", true)];
    let (mut model, mut rng) = (Eager::default(), Xorshift(seed));
    let (mut next_k, mut passed_over) = (1u64, Vec::new());
    for act in 0..acts {
        let standing: Vec<(u64, String)> = model.lines.iter().map(|l| (l.k, l.doc.clone())).collect();
        let doc = docs[rng.below(3) as usize];
        // A standing line: a document's first now and then, else any.
        let first_on = |doc: &str| standing.iter().find(|(_, on)| on == doc).map(|(k, _)| *k);
        let any = |rng: &mut Xorshift| (!standing.is_empty()).then(|| standing[rng.below(standing.len() as u64) as usize].0);
        let line = if rng.below(2) == 0 { first_on(doc) } else { any(&mut rng) };
        match (rng.below(100), line) {
            (0..=34, _) | (_, None) => {
                if rng.below(4) == 0 {
                    passed_over.push(next_k);
                    next_k += 1;
                }
                let base = rng.below(100);
                let frame = json!({"op": "insert", "n": act});
                queue.hold(next_k, doc, None, base, frame.clone(), None, Reason::of("unreachable", false)).unwrap();
                model.enter(HeldLine { k: next_k, doc: doc.to_string(), id: None, dial_id: None, base, frame, anchors: None, reason: Reason::of("unreachable", false), time: 0 });
                next_k += 1;
            }
            (35..=59, Some(k)) => {
                let done = Done::Kept { at: Some(rng.below(200)) };
                queue.done(k, done).unwrap();
                model.done(k, done);
            }
            (60..=69, Some(k)) => {
                queue.done(k, Done::Dropped).unwrap();
                model.done(k, Done::Dropped);
            }
            (70..=74, Some(k)) => {
                let run = [k, any(&mut rng).unwrap_or(k), any(&mut rng).unwrap_or(k)];
                let done = if rng.below(2) == 0 { Done::Kept { at: Some(rng.below(200)) } } else { Done::Dropped };
                queue.done_all(&run, done);
                for k in run {
                    model.done(k, done);
                }
            }
            (75..=84, Some(_)) => {
                let reason = &reasons[rng.below(3) as usize];
                let raise = (rng.below(2) == 0).then(|| rng.below(200));
                let marks: Vec<u64> = standing.iter().filter(|(_, on)| on == doc).map(|(k, _)| *k).collect();
                assert!(queue.remark_all(marks.iter().map(|&k| (k, reason.clone())), raise).is_empty(), "act {act}: every re-mark copied");
                for k in marks {
                    model.remark(k, reason, raise);
                }
            }
            (85..=89, Some(k)) => {
                let reason = &reasons[rng.below(3) as usize];
                queue.remark(k, reason.clone()).unwrap();
                model.remark(k, reason, None);
            }
            (90..=94, Some(k)) => {
                let frame = json!({"op": "insert", "n": act, "shifted": true});
                queue.rewrite(k, frame.clone()).unwrap();
                model.rewrite(k, &frame);
            }
            (_, Some(_)) => {
                let mut from = HeldQueue::unopened(store, 1, "1.0.1");
                for k in passed_over.drain(..) {
                    let (doc, base) = (docs[rng.below(3) as usize], rng.below(100));
                    from.hold(k, doc, None, base, json!({"op": "insert", "joined": k}), None, Reason::of("behind", false)).unwrap();
                    model.enter(HeldLine {
                        k,
                        doc: doc.to_string(),
                        id: None,
                        dial_id: None,
                        base,
                        frame: json!({"op": "insert", "joined": k}),
                        anchors: None,
                        reason: Reason::of("behind", false),
                        time: 0,
                    });
                }
                queue.join(&from, Joining::ThisRun);
            }
        }
        assert_eq!(modeled(&queue.lines()), modeled(&model.lines), "act {act}: the queue's lines are the model's");
        if (act + 1) % reopen_every == 0 {
            if let Some(read) = reopened() {
                assert_eq!(modeled(&read), modeled(&model.lines), "act {act}: a reopen reads the model's lines");
            }
        }
    }
}

/// Checks that every line's base is the eager raise's, in memory (#816).
///
/// It is four thousand seeded acts ([`modeled_acts`]) over a queue whose
/// file is not yet read, so no copy is synced: after each, every line's
/// base, frame and reason are the model's, which raises the lines behind a
/// kept line one by one (the mutant that raises by a floor where a line
/// stands before the kept one on its document lifts that earlier line; the
/// one whose floor raises the lines held after it lifts them; the one that
/// keeps a floor below one given after it, or reads a line's floor off
/// another than the first given after it, lowers a base).
#[test]
fn every_lines_base_is_the_eager_raises_in_memory() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = HeldQueue::unopened(&d, 1, "1.0.1");
    modeled_acts(&mut queue, &d, 4000, 0x9e37_79b9_7f4a_7c15, usize::MAX, || None);
}

/// Checks that every line's base is the eager raise's at each reopen (#816).
///
/// It is four hundred seeded acts ([`modeled_acts`]) over a queue whose
/// file is read, every copy synced, the file reopened every twenty acts:
/// after each act the queue's lines are the model's, and at each reopen so
/// are the file's, the reader deriving each document's floors from the
/// `done`s, the re-marks and the joined lines in the file's order (the
/// mutant reader whose floors raise the lines a join wrote after the `done`
/// that gave them reads those lines past their own bases; the one whose
/// `done` of a line behind another of its document gives a floor lifts the
/// line before it).
#[test]
fn every_lines_base_is_the_eager_raises_at_each_reopen() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    modeled_acts(&mut queue, &d, 400, 0x2545_f491_4f6c_dd1d, 20, || Some(live(d.open_file(1, "1.0.1").unwrap()).lines()));
}

/// Checks that a raised re-mark reads back with its base, never lowered.
///
/// It is the person's `send` on a moved document (§3c.4; skep #757): three
/// lines on a document — the first `moved` with the board's verdict, the
/// second `moved`, both at 4, and the third `behind` at 99. The second,
/// re-marked `behind` and raised to 40, takes both, its copy on disk and
/// spending the re-mark budget as a re-mark does; the first, re-marked
/// `behind` and raised to 2, below its base, takes the reason and keeps its
/// base — a raise is never a lowering; the third, raised to 40 below its 99
/// under the reason it carries, writes nothing, and nor do a raise the
/// second carries already and a line not standing. A reopen reads one line
/// per ordinal with the raised base and the new reason, its re-mark budget
/// spent as the writer spent it; and a `done` of the first kept at 20,
/// below the raised base, leaves the second at 40, in the queue and at a
/// reopen (the mutant writer that keeps the base off its line relaunches
/// the base below the rows the person acknowledged; the one that sets the
/// base to the position lowers the line past it, and its read takes a row it
/// passed for its own landing again).
#[test]
fn a_raised_remark_reads_back_with_its_base_and_no_later_done_lowers_it() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let verdict = json!({"resp": "rejected", "op": "insert", "code": "arrangement_moved", "disposition": "permanent", "site": {"as_of": 2, "current": 40}});
    let moved = Reason { cause: "moved".into(), refusal: Some(verdict), sent: true };
    let k1 = queue.hold_next("1.0.1.0.1", None, 4, json!({"op": "insert"}), None, moved).unwrap().k;
    let k2 = queue.hold_next("1.0.1.0.1", None, 4, json!({"op": "delete"}), None, Reason::of("moved", false)).unwrap().k;
    let k3 = queue.hold_next("1.0.1.0.1", None, 99, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap().k;
    let spent = |queue: &HeldQueue| queue.disk.remark_bytes;
    let raise = |queue: &mut HeldQueue, k: u64, reason: Reason, at: u64| assert!(queue.remark_all([(k, reason)], Some(at)).is_empty(), "line {k}: no copy refused");
    let (written, budget) = (file_len(&tmp), spent(&queue));
    raise(&mut queue, k2, Reason::of("behind", false), 40);
    assert!(file_len(&tmp) > written && spent(&queue) > budget, "the raise is on disk, and spends the re-mark budget");
    raise(&mut queue, k1, Reason::of("behind", true), 2);
    let (written, budget) = (file_len(&tmp), spent(&queue));
    raise(&mut queue, k2, Reason::of("behind", false), 40);
    raise(&mut queue, k3, Reason::of("behind", false), 40);
    raise(&mut queue, 99, Reason::of("behind", false), 40);
    assert_eq!((file_len(&tmp), spent(&queue)), (written, budget), "a reason and base the line carries, a raise below a standing base, and a line not standing write nothing");
    let marks = |queue: &HeldQueue| queue.lines().iter().map(|l| (l.k, l.base, l.reason.clone())).collect::<Vec<_>>();
    let raised = vec![(k1, 4, Reason::of("behind", true)), (k2, 40, Reason::of("behind", false)), (k3, 99, Reason::of("behind", false))];
    assert_eq!(marks(&queue), raised, "raised, never lowered");
    let reopened = live(d.open_file(1, "1.0.1").unwrap());
    assert_eq!((marks(&reopened), spent(&reopened)), (raised.clone(), spent(&queue)), "a reopen reads the raised base, and counts its line as a re-mark");
    queue.done(k1, Done::Kept { at: Some(20) }).unwrap();
    let kept = raised[1..].to_vec();
    assert_eq!(marks(&queue), kept, "a `done` kept below the raised base leaves it");
    assert_eq!(marks(&live(d.open_file(1, "1.0.1").unwrap())), kept, "and so does a reopen");
}

/// Checks that every line form reads back as it was held (§3c.2).
///
/// It is the law over a line's members: a line with no `id`, a plain one,
/// and the page's own `id` holding a quote, a newline and a backslash — the
/// page's string this file keeps — each under a hold `sent: false`, one that
/// *may* have landed, and a refused run's with the board's verdict beside it,
/// over a frame of a multi-byte value, each without anchors, with both, with
/// an edge on either side, with a span of two runs, and with a piece naming
/// the words of a line of the quoting `id` (skep #969) — which binds where
/// such a line stands before it, and is dropped where none does — each
/// form's anchors counting the bytes of their spelling; reopened, the queue
/// is the queue that was held (the mutant reader that drops `refusal` reads
/// a refused run back as holding, and the resend then sends what awaits the
/// person's act; the one that drops the anchors, or their span, holds a
/// burst the shift cannot move; the one that escapes a piece's `burst` other
/// than the bridge does binds it to no line; the door that counts other
/// bytes than the anchors' spelling lets their budget drift from the file's
/// lines).
#[test]
fn every_line_form_reads_back_as_it_was_held() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent", "detail": "past \"the\" end"});
    let reasons = [Reason::of("unreachable", false), Reason::of("poisoned", true), Reason::refused("out_of_bounds", verdict)];
    let anchored = [
        None,
        Some(anchors(Some("1.0.1.0.1.0.1.2"), Some("1.0.1.0.2.0.1.9"))),
        Some(anchors(None, Some("1.0.1.0.1.0.1.1"))),
        Some(anchors(Some("1.0.1.0.1.0.1.5"), None)),
        Some(spanned(Some("1.0.1.0.1.0.1.1"), None, &[("1.0.1.0.1.0.1.2", 3), ("1.0.1.0.2.0.1.18446744073709551615", 1)])),
        Some(Anchors::of(&json!({"before": {"burst": "a \"quote\", a\nnewline, a \\ backslash", "offset": 1}, "after": "1.0.1.0.1.0.1.9"})).expect("the anchors' form")),
    ];
    for anchors in anchored.iter().flatten() {
        assert_eq!(anchors.bytes(), json_len(&anchors.json()), "the anchors' bytes are their spelling's: {}", anchors.json());
    }
    for id in [None, Some("plain"), Some("a \"quote\", a\nnewline, a \\ backslash")] {
        for reason in &reasons {
            for anchors in &anchored {
                let held = queue.hold_next("1.0.1.0.1", id, 7, json!({"op": "insert", "values": ["é\"x"]}), anchors.clone(), reason.clone()).unwrap();
                assert!(held.unwritten.is_none(), "{:?}", held.unwritten);
            }
        }
    }
    let pieces = queue.lines().iter().filter(|line| line.anchors.as_ref().is_some_and(Anchors::names_pieces)).count();
    assert_eq!(pieces, 3, "a piece binds under the quoting `id` alone, one line a reason");
    let reopened = live(d.open_file(1, "1.0.1").unwrap());
    assert_eq!(reopened.lines().len(), 54);
    assert_eq!(reopened.lines(), queue.lines(), "the reopened queue is the queue that was held");
}

/// Checks that a piece binds to the line whose words it names, is placed as
/// that line is kept, and a reopen binds and places it as the queue did
/// (skep #969).
///
/// Four lines on one document: A under an `id` holding a quote and a
/// backslash, B naming A's third unit by a piece, C a second burst under the
/// same `id`, and D naming C's first unit. B's copy spells its piece in the
/// form the bridge reads, each piece binds to the newest line standing before
/// it with that `id` — B to A, D to C — and a reopen binds them alike. A kept
/// at a position with the address its words were minted at places B's piece
/// there advanced by its offset, D's untouched, the `done` carrying the
/// address in its member order; C dropped drops D's anchors, the settle
/// naming D; and at each step a reopen reads the queue as it stands, its
/// bytes counted alike (the mutant that binds a piece to the oldest line of
/// its `id` places D in A's words; the one that writes no `addr` places
/// nothing at a reopen, which drops the pieces; the one that counts no
/// placed anchors lets the queue's budget drift from its file's lines).
#[test]
fn a_piece_binds_to_the_line_it_names_and_a_reopen_places_it_as_the_queue_did() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let id = "b-\"1\"\\";
    let frame = |n: u64| json!({"op": "insert", "values": ["XYZ"], "n": n});
    let named = |offset: u64| Anchors::of(&json!({"before": {"burst": id, "offset": offset}, "after": "1.0.1.0.1.0.1.9"})).expect("the anchors' form");
    let mut hold = |id: Option<&str>, n: u64, anchors: Option<Anchors>| queue.hold_next("1.0.1.0.1", id, 0, frame(n), anchors, Reason::of("behind", false)).unwrap().k;
    let (a, b, c, last) = (hold(Some(id), 1, None), hold(None, 2, Some(named(2))), hold(Some(id), 3, None), hold(None, 4, Some(named(0))));
    let text = fs::read_to_string(file_path(&tmp)).unwrap();
    assert!(text.contains(r#","anchors":{"before":{"burst":"b-\"1\"\\","offset":2},"after":"1.0.1.0.1.0.1.9"},"#), "the piece in the bridge's form: {text}");
    assert!(queue.is_named(a) && queue.is_named(c) && !queue.is_named(b) && !queue.is_named(last), "B names A, and D names C");
    let reopens_as_held = |queue: &HeldQueue, step: &str| {
        let reopened = live(d.open_file(1, "1.0.1").unwrap());
        assert_eq!((reopened.lines(), reopened.held_bytes), (queue.lines(), queue.held_bytes), "{step}: a reopen reads the queue as it stands");
        assert_eq!(ks(&reopened).iter().map(|&k| reopened.is_named(k)).collect::<Vec<_>>(), ks(queue).iter().map(|&k| queue.is_named(k)).collect::<Vec<_>>(), "{step}: and binds alike");
    };
    reopens_as_held(&queue, "held");
    let anchors_of = |queue: &HeldQueue, k: u64| queue.line(k).and_then(|line| line.anchors).map(|anchors| anchors.json());
    let settled = queue.keep(a, Some(42), Some("1.0.1.0.1.0.1.100")).unwrap();
    assert!(settled.unplaced.is_empty(), "{settled:?}");
    assert_eq!(anchors_of(&queue, b), Some(json!({"before": "1.0.1.0.1.0.1.102", "after": "1.0.1.0.1.0.1.9"})), "B placed at A's words");
    assert_eq!(anchors_of(&queue, last), Some(json!({"before": {"burst": id, "offset": 0}, "after": "1.0.1.0.1.0.1.9"})), "D names C still");
    let text = fs::read_to_string(file_path(&tmp)).unwrap();
    let done = text.lines().find(|line| line.starts_with(&format!("{{\"done\":{a},"))).unwrap_or_else(|| panic!("A's `done`: {text}"));
    assert!(done.starts_with(&format!("{{\"done\":{a},\"as\":\"kept\",\"at\":42,\"addr\":\"1.0.1.0.1.0.1.100\",\"time\":")), "{done}");
    reopens_as_held(&queue, "A kept");
    let settled = queue.done(c, Done::Dropped).unwrap();
    assert_eq!((settled.unplaced, anchors_of(&queue, last)), (vec![last], None), "C dropped, D's anchors dropped and named");
    reopens_as_held(&queue, "C dropped");
}

/// The anchors a line carries: `before` and `after`, each an I-address or
/// none, and no span — read through their one door.
fn anchors(before: Option<&str>, after: Option<&str>) -> Anchors {
    Anchors::of(&json!({"before": before, "after": after})).expect("the anchors' form")
}

/// The anchors a page sends for a span of units.
///
/// They are `before` and `after`, and the span's runs, each its `start` and
/// its width — read through their one door, as the bridge and the reader
/// read them.
fn spanned(before: Option<&str>, after: Option<&str>, runs: &[(&str, u64)]) -> Anchors {
    let span: Vec<Value> = runs.iter().map(|(start, width)| json!({"start": start, "width": width.to_string()})).collect();
    Anchors::of(&json!({"before": before, "after": after, "span": span})).expect("the anchors' form")
}

/// A REWRITTEN FRAME reads back under its ordinal (skep #442): a line held
/// with anchors, its frame rewritten — the shift's act — and the file opened
/// again holds ONE line of that ordinal carrying the new frame, its reason,
/// `sent`, `base`, `id` and anchors as they were, the queue's bytes
/// recounted by the new frame, the anchors' kept; a frame the line already
/// carries writes nothing; a line not standing is left alone; and the
/// rewrite spends the re-mark budget a whole frame at a time — past it the
/// copy is refused, the queue taking the frame all the same, and a reopen
/// reads the frame copied last (the mutant reader that takes a rewritten line
/// as a new one lists the burst twice; the writer that keeps the frame off
/// the disk relaunches the page's positions after a shifted answer is lost,
/// and the landed test reads the wrong site).
#[test]
fn a_rewritten_frame_reads_back_under_its_ordinal_and_spends_the_remark_budget() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let typed = json!({"op": "insert", "doc": "1.0.1.0.1", "at": {"subspace": "1", "ordinal": "2"}, "values": ["x"], "as_of": 4});
    let shifted = json!({"op": "insert", "doc": "1.0.1.0.1", "at": {"subspace": "1", "ordinal": "7"}, "values": ["x"], "as_of": 9});
    let held = anchors(Some("1.0.1.0.1.0.1.1"), Some("1.0.1.0.1.0.1.2"));
    let k = queue.hold_next("1.0.1.0.1", Some("id-1"), 4, typed.clone(), Some(held.clone()), Reason::of("unreachable", true)).unwrap().k;
    queue.hold_next("1.0.1.0.1", None, 4, json!({"op": "delete"}), None, Reason::of("behind", false)).unwrap();
    let written = file_len(&tmp);
    queue.rewrite(k, shifted.clone()).unwrap();
    assert!(file_len(&tmp) > written, "the rewritten line is on disk");
    let written = file_len(&tmp);
    queue.rewrite(k, shifted.clone()).unwrap();
    queue.rewrite(99, json!({"op": "delete"})).unwrap();
    assert_eq!(file_len(&tmp), written, "the frame the line carries, and a line not standing, write nothing");
    assert_eq!(queue.held_bytes, json_len(&shifted) + held.bytes() + json_len(&json!({"op": "delete"})), "the frame bytes are recounted, the anchors' kept");
    let reopened = live(d.open_file(1, "1.0.1").unwrap());
    assert_eq!(ks(&reopened), [k, k + 1], "one line per ordinal");
    let line = &reopened.lines()[0];
    assert_eq!((&line.frame, line.id.as_deref(), line.base, &line.reason, &line.anchors), (&shifted, Some("id-1"), 4, &Reason::of("unreachable", true), &Some(held)), "the frame rewritten, the rest as held");
    assert_eq!(reopened.lines(), queue.lines(), "the reopened queue is the queue that was rewritten");

    // The budget: a large frame rewritten until the file's re-marks pass it.
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let k = queue.hold_next("1.0.1.0.1", None, 0, sized_frame(MAX_HELD_REMARK_BYTES / 4), None, Reason::of("unreachable", false)).unwrap().k;
    let frames: Vec<Value> = (1..=8).map(|n| json!({"op": "insert", "values": ["x".repeat(MAX_HELD_REMARK_BYTES / 4 - 40 + n)]})).collect();
    let copied = frames.iter().filter(|frame| queue.rewrite(k, (*frame).clone()).is_ok()).count();
    assert!((1..8).contains(&copied), "some rewrites are copied and the rest refused: {copied} of 8");
    assert_eq!(queue.lines()[0].frame, frames[7], "the queue takes the last frame given");
    let reopened = live(d.open_file(1, "1.0.1").unwrap());
    assert!(frames.contains(&reopened.lines()[0].frame), "a reopen reads a frame the file copied: {}", reopened.lines()[0].frame);
}

/// THE STORE IS ITS OWNER's ALONE (§3c.1): `held/` and `held/<chain>/` made
/// `0700`, a principal's file and the lock `0600` — modes set at creation,
/// which no umask that leaves the owner's own bits can widen (the mutant
/// that drops one leaves the person's draft text readable by every user of
/// the machine under the usual umask).
#[cfg(unix)]
#[test]
fn the_store_is_its_owners_alone() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let _lock = d.try_lock().unwrap().expect("the lock is free");
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    assert!(queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("stopped", false)).unwrap().unwritten.is_none());
    let held = tmp.path().join("held");
    let board = held.join(chain().to_string());
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let modes = [mode(&held), mode(&board), mode(&board.join("principal-1.held")), mode(&board.join("lock"))];
    assert_eq!(modes, [0o700, 0o700, 0o600, 0o600], "held/, held/<chain>/, the file, the lock");
}

/// A frame whose JSON spelling is exactly `bytes` long.
fn sized_frame(bytes: usize) -> Value {
    let overhead = json_len(&json!({"op": "insert", "values": [""]}));
    json!({"op": "insert", "values": ["x".repeat(bytes - overhead)]})
}

/// The principal-1 file's length on disk, 0 where there is none.
fn file_len(tmp: &TempDir) -> u64 {
    fs::metadata(file_path(tmp)).map_or(0, |m| m.len())
}

/// The anchors of their form whose spelling is exactly `bytes` long, read
/// through their one door.
fn anchors_of_len(bytes: usize) -> Anchors {
    Anchors::of(&anchors_spelled(bytes)).expect("the anchors' form")
}

/// THE QUEUE's BUDGET: the standing frames and anchors held to
/// [`MAX_HELD_BYTES`] — three frames at the board's frame cap and a fourth a
/// hundred bytes under it carrying anchors at their bound, four frames and
/// one line's anchors at their bounds less a hundred bytes — and a frame that
/// would pass the budget refused `Full`, naming the bytes held, the frame's
/// and the anchors', and NOTHING of it written; one at the budget exactly
/// held; and room made by a `done` (the mutant that never counts, or never
/// uncounts, holds a page's frames without bound, or refuses for good; the
/// one whose budget is one frame refuses the person's second burst at the
/// cap, and keeps it nowhere).
#[test]
fn the_queue_holds_its_frames_and_anchors_within_its_budget_and_writes_nothing_past_it() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let first = queue.hold_next("1.0.1.0.1", None, 0, sized_frame(MAX_FRAME_BYTES), None, Reason::of("stopped", false)).unwrap().k;
    for _ in 0..2 {
        let beside = queue.hold_next("1.0.1.0.1", None, 0, sized_frame(MAX_FRAME_BYTES), None, Reason::of("behind", false));
        assert!(beside.is_ok_and(|held| held.unwritten.is_none()), "a frame at the cap held and copied beside the first");
    }
    queue.hold_next("1.0.1.0.1", None, 0, sized_frame(MAX_FRAME_BYTES - 100), Some(anchors_of_len(MAX_ANCHOR_BYTES)), Reason::of("behind", false)).unwrap();
    let written = file_len(&tmp);
    let refused = queue.hold_next("1.0.1.0.1", None, 0, sized_frame(200), None, Reason::of("behind", false));
    assert_eq!(refused.unwrap_err(), Unheld::Full { held_bytes: MAX_HELD_BYTES - 100, frame_bytes: 200, anchor_bytes: 0, held_lines: 4 });
    assert_eq!((file_len(&tmp), ks(&queue)), (written, vec![first, first + 1, first + 2, first + 3]), "nothing of the refused line is kept");
    assert!(queue.hold_next("1.0.1.0.1", None, 0, sized_frame(100), None, Reason::of("behind", false)).is_ok(), "a frame at the budget exactly");
    queue.done(first, Done::Kept { at: Some(3) }).unwrap();
    assert!(queue.hold_next("1.0.1.0.1", None, 0, sized_frame(200), None, Reason::of("behind", false)).is_ok(), "a done makes room");
}

/// Checks that the queue counts each line's anchors beside its frame.
///
/// Small frames on as many documents, each carrying anchors of three
/// quarters of [`MAX_ANCHOR_BYTES`], are held as many as [`MAX_HELD_BYTES`]
/// holds, and the next — its frame a few bytes, its anchors carrying the
/// queue past the budget — is refused `Full`, naming its anchors' bytes, and
/// nothing of it written. The file reopened refuses it alike, and so does a
/// queue in memory alone that has joined the reopened one; a `done` of the
/// first gives its anchors' bytes back, and the next is held (the mutants
/// that count frames alone at the hold, the open, the join or the settle
/// hold a page's anchors without bound — every one copied to disk and read
/// back at each launch — or refuse for good).
#[test]
fn the_queue_counts_each_lines_anchors_beside_its_frame() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let (frame, each) = (json!({"op": "insert"}), anchors_of_len(MAX_ANCHOR_BYTES * 3 / 4));
    let fits = MAX_HELD_BYTES / (json_len(&frame) + each.bytes());
    assert!(fits >= 2, "the budget holds {fits} such lines, the frames a few bytes of them");
    let hold = |queue: &mut HeldQueue, n: usize| queue.hold_next(&format!("1.0.1.0.{}", n + 1), None, 0, frame.clone(), Some(each.clone()), Reason::of("behind", false));
    let full = |held: Result<Entered, Unheld>| matches!(held, Err(Unheld::Full { anchor_bytes, held_lines, .. }) if anchor_bytes == MAX_ANCHOR_BYTES * 3 / 4 && held_lines == fits);
    let first = hold(&mut queue, 0).unwrap().k;
    for n in 1..fits {
        hold(&mut queue, n).unwrap();
    }
    let written = file_len(&tmp);
    assert!(full(hold(&mut queue, fits)), "the next line's anchors pass the budget at the hold");
    assert_eq!(file_len(&tmp), written, "nothing of the refused line is written");
    let mut reopened = live(d.open_file(1, "1.0.1").unwrap());
    assert!(full(hold(&mut reopened, fits)), "the open counts its lines' anchors");
    let other = TempDir::new().unwrap();
    let mut joined = live(dir(&other).open_file(1, "1.0.1").unwrap());
    joined.join(&reopened, Joining::ThisRun);
    assert!(full(hold(&mut joined, fits)), "the join counts them too");
    queue.done(first, Done::Dropped).unwrap();
    assert!(hold(&mut queue, fits).is_ok(), "a done gives its anchors' bytes back");
}

/// Checks that a line at every member's bound is written and read back.
///
/// Its frame is the board's frame cap exactly, an `id` filling it — the
/// line spelling that `id` a second time as its own — and its anchors are at
/// [`MAX_ANCHOR_BYTES`]: held into an empty queue it fits the queue's budget
/// and the line bound alike, its copy written whole, and a reopen reads it
/// back as it was held (the mutant whose line bound leaves the anchors out
/// keeps the line in memory alone, `unwritten`, and a relaunch loses it).
#[test]
fn a_line_at_every_members_bound_is_written_and_read_back() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let id = "x".repeat(MAX_FRAME_BYTES - json_len(&json!({"op": "insert", "id": ""})));
    let frame = json!({"op": "insert", "id": id});
    assert_eq!(json_len(&frame), MAX_FRAME_BYTES, "the frame at the board's frame cap");
    let held = queue.hold_next("1.0.1.0.1", Some(id.as_str()), 0, frame, Some(anchors_of_len(MAX_ANCHOR_BYTES)), Reason::of("unreachable", false)).unwrap();
    assert!(held.unwritten.is_none(), "the line is copied whole: {:?}", held.unwritten);
    let reopened = live(d.open_file(1, "1.0.1").unwrap());
    assert!(reopened.lines() == queue.lines(), "the line read back as it was held");
}

/// THE QUEUE's LINE BUDGET: [`MAX_HELD_LINES`] lines of empty bursts held —
/// their bytes far under the byte budget, into a queue whose file is not
/// yet read, so no copy is synced — and the next refused `Full`, naming the
/// lines it holds, the queue standing at the budget; a `done` makes room for
/// one more (the mutant that counts bytes alone holds such bursts by the
/// hundred thousand, and the resend walks them past one another for days).
#[test]
fn the_queue_holds_no_line_past_its_line_budget() {
    let tmp = TempDir::new().unwrap();
    let mut queue = HeldQueue::unopened(&dir(&tmp), 1, "1.0.1");
    for _ in 0..MAX_HELD_LINES {
        assert!(queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "delete"}), None, Reason::of("behind", false)).is_ok());
    }
    let refused = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "delete"}), None, Reason::of("behind", false));
    assert!(matches!(refused, Err(Unheld::Full { held_lines: MAX_HELD_LINES, .. })), "{refused:?}");
    assert_eq!(queue.lines().len(), MAX_HELD_LINES, "the queue stands at the budget");
    queue.done(1, Done::Dropped).unwrap();
    assert!(queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "delete"}), None, Reason::of("behind", false)).is_ok(), "a done makes room");
}

/// A REOPENED QUEUE PAST ITS LINE BUDGET is read whole and holds nothing
/// more until it drains below it: a file of one line more than
/// [`MAX_HELD_LINES`] — as a `done` the device refused, or a file another
/// writer made, leaves one — reopens with every line, refuses the next hold
/// `Full`, and takes one again once two lines are done (the budget bounds
/// what a hold ADDS, never what a reader reads; the mutant whose reader
/// stops at the budget loses the person's text past it).
#[test]
fn a_reopened_queue_past_its_line_budget_reads_whole_and_holds_nothing_more() {
    let tmp = TempDir::new().unwrap();
    let body: String = (1..=MAX_HELD_LINES + 1)
        .map(|k| format!("{{\"held\":{k},\"doc\":\"1.0.1.0.1\",\"base\":0,\"frame\":{{\"op\":\"delete\"}},\"cause\":\"behind\",\"sent\":false,\"time\":1}}\n"))
        .collect();
    let mut queue = live(opened_over(&tmp, body.as_bytes()));
    assert_eq!(queue.lines().len(), MAX_HELD_LINES + 1, "the queue is read whole");
    let refused = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "delete"}), None, Reason::of("behind", false));
    assert!(matches!(refused, Err(Unheld::Full { held_lines, .. }) if held_lines == MAX_HELD_LINES + 1), "{refused:?}");
    queue.done(1, Done::Dropped).unwrap();
    queue.done(2, Done::Dropped).unwrap();
    assert!(queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "delete"}), None, Reason::of("behind", false)).is_ok(), "below the budget a hold is taken again");
}

/// The ordinals are held to the page's ([`MAX_ORDINAL`]): the last one
/// held, and the queue holding no line past it — the one after it refused,
/// whether handed in or the next past the queue's greatest.
#[test]
fn the_queue_holds_no_ordinal_past_the_pages() {
    let tmp = TempDir::new().unwrap();
    let mut queue = HeldQueue::unopened(&dir(&tmp), 1, "1.0.1");
    assert_eq!(queue.hold(MAX_ORDINAL, "1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("stopped", false)).unwrap().k, MAX_ORDINAL);
    assert!(matches!(queue.hold(MAX_ORDINAL + 1, "1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("stopped", false)), Err(Unheld::Full { .. })));
    assert!(matches!(queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("stopped", false)), Err(Unheld::Full { .. })));
    assert_eq!((ks(&queue), queue.greatest_k()), (vec![MAX_ORDINAL], MAX_ORDINAL));
}

/// THE WRITER holds no line its reader would halt on: a `doc` that is no
/// document address in its one spelling, and a frame that is no object,
/// refused `Unreadable` and written nowhere.
#[test]
fn the_writer_holds_no_line_its_reader_refuses() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    for (doc, frame) in [("d1", json!({"op": "insert"})), ("01.0.1.0.1", json!({"op": "insert"})), ("1.0.1", json!({"op": "insert"})), ("1.0.1.0.1", json!(["insert"]))] {
        assert_eq!(queue.hold_next(doc, None, 0, frame, None, Reason::of("stopped", false)).unwrap_err(), Unheld::Unreadable, "{doc}");
    }
    assert!(queue.lines().is_empty() && !queue.on_disk());
}

/// A RE-MARK THAT CHANGES NOTHING WRITES NOTHING: a board answering the
/// same hold at every probe grows no file (the mutant that appends every
/// re-mark copies the frame once a probe cadence for as long as the board
/// says so); a new reason is written as before.
#[test]
fn an_unchanged_remark_writes_nothing() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let k = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", true)).unwrap().k;
    let written = file_len(&tmp);
    for _ in 0..3 {
        queue.remark(k, Reason::of("unreachable", true)).unwrap();
    }
    assert_eq!(file_len(&tmp), written, "the same reason again writes nothing");
    queue.remark(k, Reason::of("durability", false)).unwrap();
    assert!(file_len(&tmp) > written, "a new reason is written");
}

/// THE RE-MARK BUDGET: a board flapping between two hold-class causes — the
/// line, one that may have landed, re-marked at every probe, its `sent` kept
/// as the hold keeps it, each re-mark a whole line of a large frame — grows
/// the file by at most [`MAX_HELD_REMARK_BYTES`]: the re-marks past it
/// refused their copy, the queue taking each reason all the same; a reopen
/// reads one line under a reason the file copied and keeps the budget spent,
/// refusing the next copy; and a compaction gives the file that replaces it a
/// budget of its own (the mutant that copies every re-mark fills the disk at
/// a frame per probe for as long as the board flaps; the one that counts
/// afresh at each open fills it a budget per relaunch).
#[test]
fn a_board_flapping_between_two_causes_grows_no_file_past_its_remark_budget() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let k = queue.hold_next("1.0.1.0.1", None, 0, sized_frame(MAX_HELD_REMARK_BYTES / 4), None, Reason::of("unreachable", true)).unwrap().k;
    let written = file_len(&tmp);
    let flaps = [Reason::of("poisoned", true), Reason::of("durability", true)];
    let copied = (0..8).filter(|i| queue.remark(k, flaps[i % 2].clone()).is_ok()).count();
    assert!((1..8).contains(&copied), "some re-marks are copied and the rest refused: {copied} of 8");
    let grown = (file_len(&tmp) - written) as usize;
    assert!(grown <= MAX_HELD_REMARK_BYTES + copied, "the file grew {grown} bytes past its budget of {MAX_HELD_REMARK_BYTES}");
    assert_eq!(queue.lines()[0].reason, flaps[1], "the queue takes the last reason given");
    let mut reopened = live(d.open_file(1, "1.0.1").unwrap());
    assert_eq!(reopened.lines().len(), 1);
    let reason = reopened.lines()[0].reason.clone();
    assert!(flaps.contains(&reason), "a reason the file copied: {reason:?}");
    let other = flaps.iter().find(|f| **f != reason).unwrap().clone();
    assert!(reopened.remark(k, other).is_err(), "the reopen keeps the budget spent");
    drop(reopened);
    queue.done(k, Done::Dropped).unwrap();
    assert!(!queue.on_disk(), "the file compacted away");
    let k = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
    let written = file_len(&tmp);
    queue.remark(k, Reason::of("durability", false)).unwrap();
    assert!(file_len(&tmp) > written, "the file that replaces it copies its re-marks afresh");
}

/// Checks that a line's mark of `sent` spends none of the re-mark budget.
///
/// It is the mark a resend makes before its dial (§3c.2). With the budget
/// spent to forty bytes short — a large line re-marked between two refusals
/// spelled at one length, its `sent` kept, four times, and a fifth copy
/// refused — a small line's mark of `sent` is copied all the same and spends
/// nothing; a reopen reads it marked, the budget spent as the writer spent
/// it; and a re-mark of that line keeping its `sent`, or lowering it, is
/// refused past the budget as every other re-mark is (the mutant that counts
/// the mark refuses it once the budget is spent, and a relaunch reads a line
/// whose dial may have landed as one never sent, which the resend sends again
/// without the read for its landing; the ones that spare a re-mark keeping
/// `sent` true, or lowering it, grow the file past its budget under a board
/// flapping between two causes).
#[test]
fn a_lines_mark_of_sent_spends_none_of_the_remark_budget() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let spent = |queue: &HeldQueue| queue.disk.remark_bytes;
    let refused = |n: u64| Reason { sent: true, ..Reason::refused("out_of_bounds", json!({"n": n})) };
    // The large line spells a quarter of the budget less ten bytes: its frame
    // sized by the rest of its spelling, its two reasons spelled at one length.
    let spelled = HeldLine { k: 1, doc: "1.0.1.0.1".into(), id: None, dial_id: None, base: 0, frame: json!({}), anchors: None, reason: refused(1), time: now_ms() };
    let rest = held_line_bytes(&spelled, spelled.base).len() - 1 - json_len(&spelled.frame);
    let large = queue.hold_next("1.0.1.0.1", None, 0, sized_frame(MAX_HELD_REMARK_BYTES / 4 - 10 - rest), None, refused(1)).unwrap().k;
    let small = queue.hold_next("1.0.1.0.2", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
    for n in [2, 1, 2, 1] {
        queue.remark(large, refused(n)).unwrap();
    }
    assert_eq!(spent(&queue), MAX_HELD_REMARK_BYTES - 40, "the budget spent to forty bytes short");
    assert!(queue.remark(large, refused(2)).is_err(), "a fifth copy is refused");
    let written = file_len(&tmp);
    queue.remark(small, Reason::of("unreachable", true)).expect("the mark is copied past the spent budget");
    assert!(file_len(&tmp) > written && spent(&queue) == MAX_HELD_REMARK_BYTES - 40, "the mark is on disk, and spends nothing");
    let reopened = live(d.open_file(1, "1.0.1").unwrap());
    let marked = reopened.lines().iter().find(|l| l.k == small).map(|l| l.reason.clone());
    assert_eq!((marked, spent(&reopened)), (Some(Reason::of("unreachable", true)), spent(&queue)), "a reopen reads the mark, the budget spent as the writer spent it");
    assert!(queue.remark(small, Reason::of("durability", true)).is_err(), "a re-mark keeping `sent` spends the budget");
    assert!(queue.remark(small, Reason::of("unreachable", false)).is_err(), "and so does one lowering it");
}

/// Checks that a resend's readying names one dial id that every copy carries.
///
/// It is named in one copy (skep #971). A line held unsent and readied for its
/// resend names a fresh dial id and
/// is marked `sent` in one copy, the `dial` member spelled after the page's
/// `id`; readied again it names the same id and writes nothing. A re-mark, a
/// shift and a reopen carry it, and a line held after it names none; a
/// renumbering moves the line under a fresh ordinal with its id, and a join
/// enters a line readied while it waited in memory with the id it carries
/// (the mutant that names a fresh id at each readying dials each resend of a
/// line under another `id`, so a true reissue meets no memo entry of its
/// own; the one whose copy drops the member relaunches the line under an
/// `id` no earlier resend dialed).
#[test]
fn a_resends_readying_names_one_dial_id_in_one_copy_and_every_copy_after_carries_it() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let k = queue.hold_next("1.0.1.0.1", Some("b-1"), 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
    let copies = count_copies();
    let (dial_id, refused) = queue.ready_to_resend(k).expect("the line stands");
    let written = file_len(&tmp);
    let again = queue.ready_to_resend(k).expect("the line stands");
    take_copies();
    assert!(refused.is_none() && again.1.is_none(), "{refused:?} {:?}", again.1);
    assert_eq!((&again.0, copies.get(), file_len(&tmp)), (&dial_id, 1, written), "one copy names the id and marks the line; readied again, the same id and nothing written");
    let text = fs::read_to_string(file_path(&tmp)).unwrap();
    let last = text.lines().last().unwrap();
    let lead = format!("{{\"held\":{k},\"doc\":\"1.0.1.0.1\",\"id\":\"b-1\",\"dial\":\"{}\",\"base\":0,", dial_id.as_str());
    assert!(last.starts_with(&lead) && last.contains(",\"sent\":true,"), "{last}");
    queue.remark(k, Reason::of("durability", true)).unwrap();
    queue.rewrite(k, json!({"op": "insert", "as_of": 9})).unwrap();
    let behind = queue.hold_next("1.0.1.0.1", Some("b-1"), 0, json!({"op": "delete"}), None, Reason::of("behind", false)).unwrap().k;
    let reopened = live(d.open_file(1, "1.0.1").unwrap());
    let dials: Vec<Option<DialId>> = reopened.lines().iter().map(|line| line.dial_id.clone()).collect();
    assert_eq!(dials, [Some(dial_id.clone()), None], "a re-mark and a shift carry it, a reopen reads it, and the line behind names none");
    assert_eq!(reopened.lines(), queue.lines(), "the reopened queue is the queue that was held");
    let mut renumbered = reopened;
    let mut next_k = 10;
    assert_eq!(renumbered.renumber(&mut next_k).unwrap(), [(k, 10), (behind, 11)]);
    let read: Vec<(u64, Option<DialId>)> = live(d.open_file(1, "1.0.1").unwrap()).lines().iter().map(|line| (line.k, line.dial_id.clone())).collect();
    assert_eq!(read, [(10, Some(dial_id)), (11, None)], "a renumbering moves the line with its id");
    let other = TempDir::new().unwrap();
    let mut from = HeldQueue::unopened(&dir(&other), 1, "1.0.1");
    let waiting = from.hold_next("1.0.1.0.2", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
    let (carried, _) = from.ready_to_resend(waiting).expect("the line stands in memory");
    let mut into = live(dir(&other).open_file(1, "1.0.1").unwrap());
    into.join(&from, Joining::ThisRun);
    let read: Vec<Option<DialId>> = live(dir(&other).open_file(1, "1.0.1").unwrap()).lines().iter().map(|line| line.dial_id.clone()).collect();
    assert_eq!(read, [Some(carried)], "a join enters the line with the id it carries");
}

/// Checks that naming a line's dial id spends none of the re-mark budget.
///
/// It is the copy a resend's readying writes (skep #971). With the budget
/// spent to forty bytes short, as
/// `a_lines_mark_of_sent_spends_none_of_the_remark_budget` spends it, a line
/// held `sent` — a lost answer's — readied for its resend names its dial id
/// in a copy written past the spent budget, and so does a line held unsent,
/// its mark beside it; neither spends anything, and a reopen reads both ids
/// and counts the budget as the writer did (the mutant reader that counts the
/// naming leaves a relaunch less of the budget than its writer left it; the
/// mutant writer that counts it refuses the copy, and a relaunch reads the
/// line naming no id).
#[test]
fn naming_a_dial_id_spends_none_of_the_remark_budget() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let spent = |queue: &HeldQueue| queue.disk.remark_bytes;
    let refused = |n: u64| Reason { sent: true, ..Reason::refused("out_of_bounds", json!({"n": n})) };
    let spelled = HeldLine { k: 1, doc: "1.0.1.0.1".into(), id: None, dial_id: None, base: 0, frame: json!({}), anchors: None, reason: refused(1), time: now_ms() };
    let rest = held_line_bytes(&spelled, spelled.base).len() - 1 - json_len(&spelled.frame);
    let large = queue.hold_next("1.0.1.0.1", None, 0, sized_frame(MAX_HELD_REMARK_BYTES / 4 - 10 - rest), None, refused(1)).unwrap().k;
    for n in [2, 1, 2, 1] {
        queue.remark(large, refused(n)).unwrap();
    }
    assert_eq!(spent(&queue), MAX_HELD_REMARK_BYTES - 40, "premise: the budget spent to forty bytes short");
    let lost = queue.hold_next("1.0.1.0.2", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", true)).unwrap().k;
    let unsent = queue.hold_next("1.0.1.0.3", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
    for k in [lost, unsent] {
        let written = file_len(&tmp);
        let (_, refused) = queue.ready_to_resend(k).expect("the line stands");
        assert!(refused.is_none() && file_len(&tmp) > written && spent(&queue) == MAX_HELD_REMARK_BYTES - 40, "line {k}: the copy is on disk past the spent budget, and spends nothing: {refused:?}");
    }
    let reopened = live(d.open_file(1, "1.0.1").unwrap());
    let named: Vec<bool> = reopened.lines().iter().filter(|l| l.k != large).map(|l| l.dial_id.is_some() && l.reason.sent).collect();
    assert_eq!((named, spent(&reopened)), (vec![true, true], spent(&queue)), "a reopen reads both ids, the budget spent as the writer spent it");
}

/// The header T1 writes for principal 1, then `body`, as the principal's
/// file — opened.
fn opened_over(tmp: &TempDir, body: &[u8]) -> Opened {
    let d = dir(tmp);
    let mut bytes = format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{}\",\"principal\":1,\"account\":\"1.0.1\"}}\n", chain()).into_bytes();
    bytes.extend_from_slice(body);
    fs::write(tmp.path().join("held").join(chain().to_string()).join("principal-1.held"), bytes).unwrap();
    d.open_file(1, "1.0.1").unwrap()
}

/// A whole `held` line of ordinal 1, `member` set to `value` (or removed,
/// where `value` is `None`).
fn line_with(member: &str, value: Option<Value>) -> Vec<u8> {
    let mut line = json!({"held": 1, "doc": "1.0.1.0.1", "base": 0, "frame": {"op": "insert"}, "cause": "stopped", "sent": false, "time": 1});
    match value {
        Some(v) => line[member] = v,
        None => {
            line.as_object_mut().unwrap().remove(member);
        }
    }
    format!("{line}\n").into_bytes()
}

/// Checks that the reader reads every line whole or halts the file (P38).
///
/// It halts as damaged on a line that is no UTF-8 or no JSON object, a
/// `held` line missing a member or holding one of another type — a `doc`
/// that is no document address, a frame that is no object, a `sent` that is
/// no boolean, anchors of no object, naming one anchor, a member beside the
/// three, an anchor that is no I-address, anchors one byte past their bound,
/// a piece of no string `burst` or past its bound, of no natural `offset` or
/// with a member beside its two (skep #969), or a span of no list, of no
/// run, or holding a run that is not one I-extent in its spelling, a `dial`
/// that is no dial id (skep #971) — an ordinal past the page's (the largest a
/// `u64` holds among them, read without a panic), and a `done` line of
/// another form, a `kept` one naming an `addr` that is no I-address and a
/// `dropped` one naming any among them; the same file with the line whole
/// reads live, its anchors of their form read, at their bound and a span
/// among them, a piece naming no line before it dropped, its dial id of its
/// form read, and a `kept` `done` naming an address (the mutants
/// that default a missing member, read text lossily, or take any ordinal,
/// rebuild the person's text out of a file no writer of this format wrote;
/// the one that reads anchors of another form as none shifts nothing a
/// relaunch should; the one that takes a span run of another spelling — a
/// width signed, of a leading zero, or past a `u64` — compares units the
/// page never named; the one that reads anchors past their bound holds a
/// stranger's bytes the bridge would have refused; the one that reads a
/// `dial` of another form dials a resend under an `id` no resend drew).
#[test]
fn a_line_the_reader_cannot_read_whole_halts_the_file() {
    let valid = line_with("sent", Some(json!(false)));
    let tmp = TempDir::new().unwrap();
    assert_eq!(live(opened_over(&tmp, &valid)).lines().len(), 1, "the line whole reads live");
    let tmp = TempDir::new().unwrap();
    let anchored = live(opened_over(&tmp, &line_with("anchors", Some(json!({"before": null, "after": "1.0.1.0.1.0.1.3"})))));
    assert_eq!(anchored.lines()[0].anchors, Some(anchors(None, Some("1.0.1.0.1.0.1.3"))), "anchors of their form read");
    let tmp = TempDir::new().unwrap();
    let span = json!({"before": "1.0.1.0.1.0.1.1", "after": null, "span": [{"start": "1.0.1.0.1.0.1.2", "width": "2"}]});
    let spanning = live(opened_over(&tmp, &line_with("anchors", Some(span))));
    assert_eq!(spanning.lines()[0].anchors, Some(spanned(Some("1.0.1.0.1.0.1.1"), None, &[("1.0.1.0.1.0.1.2", 2)])), "a span of its form read");
    let tmp = TempDir::new().unwrap();
    let bounded = live(opened_over(&tmp, &line_with("anchors", Some(anchors_spelled(MAX_ANCHOR_BYTES)))));
    assert_eq!(bounded.lines()[0].anchors.as_ref().map(Anchors::bytes), Some(MAX_ANCHOR_BYTES), "anchors at their bound read, their bytes counted");
    let tmp = TempDir::new().unwrap();
    let unbound = live(opened_over(&tmp, &line_with("anchors", Some(json!({"before": {"burst": "b-1", "offset": 2}, "after": null})))));
    assert_eq!((unbound.lines().len(), unbound.lines()[0].anchors.clone()), (1, None), "a piece naming no line before it: the line read, its anchors dropped");
    let tmp = TempDir::new().unwrap();
    let mut kept = b"{\"done\":9,\"as\":\"kept\",\"at\":4,\"addr\":\"1.0.1.0.1.0.1.4\",\"time\":1}\n".to_vec();
    kept.extend_from_slice(&valid);
    assert_eq!(live(opened_over(&tmp, &kept)).lines().len(), 1, "a kept `done` naming an address reads live");
    let tmp = TempDir::new().unwrap();
    let dial = format!("shell:{}", "0a".repeat(12));
    let dialed = live(opened_over(&tmp, &line_with("dial", Some(json!(dial)))));
    assert_eq!(dialed.lines()[0].dial_id.as_ref().map(DialId::as_str), Some(dial.as_str()), "a dial id of its form read");
    let with_span = |span: Value| line_with("anchors", Some(json!({"before": null, "after": null, "span": span})));
    let run = |start: &str, width: Value| json!({"start": start, "width": width});
    // The bytes no UTF-8 holds sit inside a string member, so a lossy read
    // would make a whole line of them.
    let mut not_utf8 = valid.clone();
    let cause = valid.windows(7).position(|w| w == b"stopped").expect("the line names its cause") + 7;
    not_utf8.splice(cause..cause, [0xff, 0xfe]);
    let damaged: Vec<(&str, Vec<u8>)> = vec![
        ("no UTF-8", not_utf8),
        ("a JSON array", b"[1, 2]\n".to_vec()),
        ("no doc", line_with("doc", None)),
        ("a doc of no document", line_with("doc", Some(json!("d1")))),
        ("a doc in another spelling", line_with("doc", Some(json!("01.0.1.0.1")))),
        ("a frame of no object", line_with("frame", Some(json!("insert")))),
        ("anchors past their bound", line_with("anchors", Some(anchors_spelled(MAX_ANCHOR_BYTES + 1)))),
        ("no frame", line_with("frame", None)),
        ("a sent of no boolean", line_with("sent", Some(json!("no")))),
        ("a dial of no dial id", line_with("dial", Some(json!("shell:0a")))),
        ("a dial of another prefix", line_with("dial", Some(json!(format!("b-{}", "0a".repeat(12)))))),
        ("a dial of no string", line_with("dial", Some(json!(7)))),
        ("a dial of null", line_with("dial", Some(Value::Null))),
        ("anchors of no object", line_with("anchors", Some(json!("1.0.1.0.1.0.1.3")))),
        ("anchors naming one anchor", line_with("anchors", Some(json!({"before": null})))),
        ("anchors with a member beside the three", line_with("anchors", Some(json!({"before": null, "after": null, "edge": 2})))),
        ("an anchor of no I-address", line_with("anchors", Some(json!({"before": "x.1", "after": null})))),
        ("an anchor with a leading zero", line_with("anchors", Some(json!({"before": null, "after": "1.0.1.0.1.0.1.03"})))),
        ("an anchor of one component", line_with("anchors", Some(json!({"before": "7", "after": null})))),
        ("a piece of no string burst", line_with("anchors", Some(json!({"before": {"burst": 7, "offset": 0}, "after": null})))),
        ("a piece past its burst's bound", line_with("anchors", Some(json!({"before": {"burst": "b".repeat(MAX_BURST_ID_BYTES + 1), "offset": 0}, "after": null})))),
        ("a piece of a negative offset", line_with("anchors", Some(json!({"before": null, "after": {"burst": "b-1", "offset": -1}})))),
        ("a piece with no offset", line_with("anchors", Some(json!({"before": null, "after": {"burst": "b-1"}})))),
        ("a piece with a member beside its two", line_with("anchors", Some(json!({"before": {"burst": "b-1", "offset": 0, "width": 1}, "after": null})))),
        ("a span of no list", with_span(json!(2))),
        ("a span of null", with_span(Value::Null)),
        ("a span of no run", with_span(json!([]))),
        ("a span run of no object", with_span(json!(["1.0.1.0.1.0.1.2"]))),
        ("a span run with no width", with_span(json!([{"start": "1.0.1.0.1.0.1.2"}]))),
        ("a span run with a member beside the two", with_span(json!([{"start": "1.0.1.0.1.0.1.2", "width": "1", "end": "1.0.1.0.1.0.1.2"}]))),
        ("a span run whose start is no I-address", with_span(json!([run("x.2", json!("1"))]))),
        ("a span run whose width is a number", with_span(json!([run("1.0.1.0.1.0.1.2", json!(1))]))),
        ("a span run of no width", with_span(json!([run("1.0.1.0.1.0.1.2", json!("0"))]))),
        ("a span run whose width has a leading zero", with_span(json!([run("1.0.1.0.1.0.1.2", json!("02"))]))),
        ("a span run whose width is signed", with_span(json!([run("1.0.1.0.1.0.1.2", json!("+2"))]))),
        ("a span run whose width passes a u64", with_span(json!([run("1.0.1.0.1.0.1.2", json!("18446744073709551616"))]))),
        ("a span run whose units pass a u64", with_span(json!([run("1.0.1.0.1.0.1.18446744073709551615", json!("2"))]))),
        ("no cause", line_with("cause", None)),
        ("no time", line_with("time", None)),
        ("an id of no string", line_with("id", Some(json!(7)))),
        ("an ordinal past the page's", line_with("held", Some(json!(MAX_ORDINAL + 1)))),
        ("the largest ordinal a u64 holds", line_with("held", Some(json!(u64::MAX)))),
        ("a done of another resolution", b"{\"done\":1,\"as\":\"lost\",\"time\":1}\n".to_vec()),
        ("a dropped done naming a position", b"{\"done\":1,\"as\":\"dropped\",\"at\":4,\"time\":1}\n".to_vec()),
        ("a done with no time", b"{\"done\":1,\"as\":\"kept\"}\n".to_vec()),
        ("a kept done naming no I-address", b"{\"done\":1,\"as\":\"kept\",\"addr\":\"x.1\",\"time\":1}\n".to_vec()),
        ("a kept done naming an address of no string", b"{\"done\":1,\"as\":\"kept\",\"addr\":7,\"time\":1}\n".to_vec()),
        ("a dropped done naming an address", b"{\"done\":1,\"as\":\"dropped\",\"addr\":\"1.0.1.0.1.0.1.4\",\"time\":1}\n".to_vec()),
        ("a done past the page's ordinals", format!("{{\"done\":{},\"as\":\"kept\",\"time\":1}}\n", MAX_ORDINAL + 1).into_bytes()),
    ];
    for (cell, line) in damaged {
        let tmp = TempDir::new().unwrap();
        let mut body = line;
        body.extend_from_slice(&valid);
        match opened_over(&tmp, &body) {
            Opened::Halted { why, .. } => assert_eq!(why, HaltWhy::Damaged, "{cell}"),
            Opened::Live { queue, .. } => panic!("{cell}: read live: {queue:?}"),
        }
    }
}

/// A TORN LAST LINE cut in the middle of a character is the burst a crash
/// caught, ignored like any torn line — never decoded, never a halt — and
/// the lines before it read.
#[test]
fn a_torn_last_line_cut_mid_character_is_ignored() {
    let tmp = TempDir::new().unwrap();
    let mut body = line_with("sent", Some(json!(true)));
    body.extend_from_slice("{\"held\":2,\"doc\":\"1.0.1.0.1\",\"frame\":{\"values\":[\"é".as_bytes());
    body.pop();
    let queue = live(opened_over(&tmp, &body));
    assert_eq!(ks(&queue), [1], "the torn line ignored, the line before it read");
}

/// THE LINE BOUND, at the reader and the writer: a line past
/// [`MAX_HELD_LINE_BYTES`] halts the file as damaged, read no further than
/// one byte past the bound; and a line the writer would make past it — a
/// board's verdict past any a daemon answers — is held in the queue,
/// answered `unwritten`, and never copied, so the file stays one its reader
/// reads.
#[test]
fn a_line_past_the_line_bound_halts_the_reader_and_is_never_written() {
    let tmp = TempDir::new().unwrap();
    let mut long = vec![b'x'; MAX_HELD_LINE_BYTES + 1];
    long.push(b'\n');
    assert!(matches!(opened_over(&tmp, &long), Opened::Halted { why: HaltWhy::Damaged, .. }));
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "detail": "x".repeat(MAX_HELD_LINE_BYTES)});
    let held = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::refused("out_of_bounds", verdict)).unwrap();
    assert_eq!(held.unwritten.map(|e| e.kind()), Some(std::io::ErrorKind::InvalidInput), "the line is answered unwritten");
    assert_eq!(ks(&queue), [held.k], "and stands in the queue");
    assert!(!queue.on_disk(), "and is copied nowhere");
}

// ── THE WAIT (§3c.3; skep #813, #822) ───────────────────────────────────────

/// Returns the copies the appends to `path` make from here, in their order.
///
/// Each is the ordinals of the `held` lines one append wrote, in the order
/// they stand: the seam it installs runs after each append's sync and reads
/// the file past the end of the append before it — a header written between
/// two appends read among them, and passed over, as it names no ordinal, and
/// a file made again since that append read from its start.
fn record_copies(path: &Path) -> Arc<Mutex<Vec<Vec<u64>>>> {
    let copied = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&copied);
    let seen = Cell::new(fs::metadata(path).map_or(0, |m| m.len() as usize));
    AFTER_SYNC.with(|s| {
        *s.borrow_mut() = Some(Box::new(move |p: &Path| {
            let bytes = fs::read(p).unwrap_or_default();
            let from = Some(seen.replace(bytes.len())).filter(|at| *at <= bytes.len()).unwrap_or(0);
            let added = String::from_utf8_lossy(&bytes[from..]).lines().filter_map(|line| serde_json::from_str::<Value>(line).ok()?["held"].as_u64()).collect();
            kept.lock().unwrap().push(added);
        }))
    });
    copied
}

/// Returns a verdict whose line is past the line bound.
///
/// It is past any a daemon answers: a line carrying it is past
/// [`MAX_HELD_LINE_BYTES`], which the writer never copies.
fn verdict_past_the_line_bound() -> Value {
    json!({"resp": "rejected", "code": "out_of_bounds", "detail": "x".repeat(MAX_HELD_LINE_BYTES)})
}

/// Checks that a refused line and the lines after it go as one copy, in order.
///
/// With every copy refused, two lines are held: each answers the device's
/// refusal, its kind and its words, and no file stands. The device takes
/// copies again, and the next hold copies the waiting lines and its own as
/// ONE copy — one write and one sync, the file's header its own before it —
/// the lines in `k` order, so the file never holds a line without the lines
/// held before it; a reopen reads all three (the mutant that copies a line
/// once, at its hold, writes the third alone; the one that copies the new
/// line before the waiting ones writes them out of order; the one that
/// copies each line apart pays a sync a line).
#[test]
fn a_refused_line_and_every_line_after_it_are_copied_as_one_copy_in_k_order_once_the_device_takes_them() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    FAIL_SYNC.with(|f| f.set(true));
    for doc in ["1.0.1.0.1", "1.0.1.0.2"] {
        let held = queue.hold_next(doc, None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap();
        let why = held.unwritten.map(|e| (e.kind(), e.to_string()));
        assert_eq!(why, Some((std::io::ErrorKind::StorageFull, "the held store's sync was made to fail".to_string())), "{doc}: the device's refusal");
    }
    FAIL_SYNC.with(|f| f.set(false));
    assert!(!queue.on_disk(), "no file stands");
    assert_eq!(queue.waiting().map(Waiting::first), Some(1), "both wait, from the first");
    let copied = record_copies(&file_path(&tmp));
    let third = queue.hold_next("1.0.1.0.3", None, 0, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap();
    AFTER_SYNC.with(|s| *s.borrow_mut() = None);
    assert!(third.unwritten.is_none(), "{:?}", third.unwritten);
    assert_eq!(*copied.lock().unwrap(), [vec![1, 2, 3]], "one copy of the waiting lines and the third, in `k` order");
    assert!(queue.waiting().is_none(), "none waits");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [1, 2, 3], "a reopen reads all three");
}

/// Checks that the one copy refused falls back to a copy a line.
///
/// A line on disk, then three held with every copy refused. The device then
/// cuts the retry's one copy of the three short, takes the first of them
/// alone and cuts the next short: the retry copies them one by one, in `k`
/// order, up to the first refused again — the first landing, the second's
/// bytes cut back, the third not tried — so a reopen reads the line on disk
/// and the first of the three with no tail behind them, and the lines wait
/// from the second. The next retry, with no new line held, resumes there,
/// copying the second and the third as one copy (the mutant with no fallback
/// saves none of the three on a device with room for one; the one whose
/// fallback copies on past a refusal writes the third without the second;
/// the one whose fallback starts past the first copy writes the second
/// without the first).
#[test]
fn the_one_copy_refused_falls_back_to_a_copy_a_line_up_to_the_first_refused_again() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    assert!(queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().unwritten.is_none());
    FAIL_SYNC.with(|f| f.set(true));
    for doc in ["1.0.1.0.2", "1.0.1.0.3", "1.0.1.0.4"] {
        assert!(queue.hold_next(doc, None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().unwritten.is_some(), "{doc}: refused");
    }
    FAIL_SYNC.with(|f| f.set(false));
    // The one copy is cut short, and the seam run after the first copy's sync
    // cuts the next copy short, once.
    TORN_WRITE.with(|t| t.set(Some(10)));
    let armed = Cell::new(false);
    AFTER_SYNC.with(|s| {
        *s.borrow_mut() = Some(Box::new(move |_: &Path| {
            if !armed.replace(true) {
                TORN_WRITE.with(|t| t.set(Some(10)));
            }
        }))
    });
    queue.retry();
    AFTER_SYNC.with(|s| *s.borrow_mut() = None);
    let waiting = queue.waiting().map(|w| (w.first(), w.owed(), w.refusal().kind()));
    assert_eq!(waiting, Some((3, Owed::Line, std::io::ErrorKind::StorageFull)), "the lines wait from the one cut short");
    let reopened = live(d.open_file(1, "1.0.1").unwrap());
    assert_eq!((ks(&reopened), reopened.torn()), (vec![1, 2], None), "line 2 copied alone, line 3's bytes cut back, line 4 not tried");
    let copied = record_copies(&file_path(&tmp));
    queue.retry();
    AFTER_SYNC.with(|s| *s.borrow_mut() = None);
    assert!(queue.waiting().is_none(), "none waits");
    assert_eq!(*copied.lock().unwrap(), [vec![3, 4]], "the next retry copies the rest as one copy, in order");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [1, 2, 3, 4], "a reopen reads every line");
}

/// Checks that the one copy may pass the line bound that each line keeps.
///
/// A line on disk, then four held at the board's frame cap with every copy
/// refused: the queue's byte budget holds them, and each is one line within
/// [`MAX_HELD_LINE_BYTES`], their sum past it. The device takes copies
/// again, and one retry copies the four as one copy, one sync, and a reopen
/// reads all five (the mutant that bounds the one copy as it bounds a line
/// refuses it, and copies the four a sync each).
#[test]
fn the_one_copy_passes_the_line_bound_where_each_of_its_lines_is_within_it() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    assert!(queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().unwritten.is_none());
    FAIL_SYNC.with(|f| f.set(true));
    for _ in 0..4 {
        assert!(queue.hold_next("1.0.1.0.1", None, 0, sized_frame(MAX_FRAME_BYTES), None, Reason::of("behind", false)).unwrap().unwritten.is_some(), "refused");
    }
    FAIL_SYNC.with(|f| f.set(false));
    let written = file_len(&tmp);
    let copied = record_copies(&file_path(&tmp));
    queue.retry();
    AFTER_SYNC.with(|s| *s.borrow_mut() = None);
    assert!(queue.waiting().is_none(), "none waits");
    assert!((file_len(&tmp) - written) as usize > MAX_HELD_LINE_BYTES, "premise: the copy is past the line bound");
    assert_eq!(*copied.lock().unwrap(), [vec![2, 3, 4, 5]], "one copy of the four");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [1, 2, 3, 4, 5], "a reopen reads all five");
}

/// Checks that a line waits behind a refused one until that one leaves.
///
/// A line the writer refuses for good — a board's verdict past the line
/// bound — waits, and the small line held after it answers the same refusal
/// and is not copied, though the device would take it. The person's drop of
/// the first writes no `done`, nothing of it standing on disk, and the
/// retry then copies the small line, which a reopen reads alone (the mutant
/// that copies a line past a waiting one leaves a file holding the second
/// burst without the first; the one that writes a `done` for a waiting line
/// names an ordinal the file never held).
#[test]
fn a_line_behind_a_refused_one_waits_until_it_leaves() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let first = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::refused("out_of_bounds", verdict_past_the_line_bound())).unwrap();
    let refused = first.unwritten.map(|e| (e.kind(), e.to_string())).expect("the writer refuses the line past its bound");
    let behind = queue.hold_next("1.0.1.0.2", None, 0, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap();
    assert_eq!(behind.unwritten.map(|e| (e.kind(), e.to_string())), Some(refused), "the line behind answers the same refusal");
    assert!(!queue.on_disk(), "and is not copied ahead of the first");
    let settled = queue.done(first.k, Done::Dropped).unwrap();
    assert!(settled.unremoved.is_none(), "{settled:?}");
    assert!(queue.waiting().is_none(), "none waits once the first has left, and no `done` is owed for it");
    let text = fs::read_to_string(file_path(&tmp)).unwrap();
    assert!(!text.contains("\"done\""), "no `done` for a line never copied: {text}");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [behind.k], "a reopen reads the line behind alone");
}

/// Checks that a waiting line's change is copied once, by the retry.
///
/// A line on disk, then two lines held while every copy is refused: the
/// second's mark of `sent` and its shift answer no refusal — the queue takes
/// both, and the line carries them to its first copy — and the third's drop
/// answers no `done` refused, nothing of it standing on disk. The device
/// takes copies again, and the retry copies the second ONCE, carrying the
/// mark and the shifted frame and spending none of the re-mark budget; the
/// file names no third line and no `done` of it, and a reopen reads the
/// queue as it stands (the mutant that copies a waiting line's re-mark on
/// its own writes the line ahead of its first copy's turn; the one that
/// spends the budget on a first copy refuses re-marks the file never held).
#[test]
fn a_waiting_lines_change_is_copied_once_by_the_retry() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap();
    FAIL_SYNC.with(|f| f.set(true));
    let second = queue.hold_next("1.0.1.0.2", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
    let third = queue.hold_next("1.0.1.0.3", None, 0, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap().k;
    let shifted = json!({"op": "insert", "as_of": 9});
    let marked = queue.remark(second, Reason::of("unreachable", true));
    let moved = queue.rewrite(second, shifted.clone());
    let settled = queue.done(third, Done::Dropped).unwrap();
    FAIL_SYNC.with(|f| f.set(false));
    assert!(marked.is_ok() && moved.is_ok(), "the mark and the shift wait with their line: {marked:?} {moved:?}");
    assert!(settled.unremoved.is_none(), "{settled:?}");
    let waiting = queue.waiting().map(|w| (w.first(), w.owed()));
    assert_eq!(waiting, Some((second, Owed::Line)), "the second waits still for its first copy, and no `done` is owed for a line never copied");
    queue.retry();
    assert!(queue.waiting().is_none(), "none waits");
    let text = fs::read_to_string(file_path(&tmp)).unwrap();
    let copies: Vec<Value> = text.lines().filter_map(|line| serde_json::from_str::<Value>(line).ok()).filter(|line| line["held"] == second).collect();
    assert_eq!(copies.len(), 1, "one copy of the second: {text}");
    assert_eq!((&copies[0]["sent"], &copies[0]["frame"]), (&json!(true), &shifted), "carrying the mark and the shift: {text}");
    assert!(!text.contains(&format!("\"held\":{third},")) && !text.contains(&format!("\"done\":{third},")), "nothing of the third: {text}");
    assert_eq!(queue.disk.remark_bytes, 0, "no re-mark budget spent");
    assert_eq!(live(d.open_file(1, "1.0.1").unwrap()).lines(), queue.lines(), "a reopen reads the queue as it stands");
}

/// Checks that a queue whose lines wait copies nothing joined ahead of them.
///
/// The board's queue holds a line the writer refuses for good, waiting; a
/// join of this run's line — held while the file could not be read — enters
/// it at once, owed, and copies nothing: the retry stops at the waiting
/// line, and the joined line waits behind it under its refusal. Once the
/// waiting line leaves, the retry writes the joined line (the mutant that
/// copies a joined line past a waiting one copies it to a file that lacks
/// the one held before it; the one that holds the join back keeps a line the
/// page was answered off the queue).
#[test]
fn a_queue_whose_lines_wait_copies_nothing_joined_ahead_of_them() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut chain = live(d.open_file(1, "1.0.1").unwrap());
    let waiting = chain.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::refused("out_of_bounds", verdict_past_the_line_bound())).unwrap().k;
    let mut ours = HeldQueue::unopened(&d, 1, "1.0.1");
    ours.hold(2, "1.0.1.0.2", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap();
    let joined = chain.join(&ours, Joining::ThisRun);
    assert_eq!((joined.entered, ks(&chain)), (vec![(2, 2)], vec![waiting, 2]), "the line enters at once, under its own ordinal");
    assert_eq!(chain.waiting().map(|w| (w.first(), w.error.kind())), Some((waiting, std::io::ErrorKind::InvalidInput)), "the retry stops at the waiting line, the joined line behind it");
    assert!(!chain.on_disk(), "nothing copied");
    chain.done(waiting, Done::Dropped).unwrap();
    assert!(chain.waiting().is_none(), "the joined line is written once the waiting one has left");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [2], "and is on disk");
}

// ── THE COPIES OWED (§3c.3; skep #821) ──────────────────────────────────────

/// Checks that a mark of `sent` the device refused is written by the retry,
/// past a spent re-mark budget.
///
/// It is the mark a resend makes before its dial (§3c.2), refused: the budget
/// spent to forty bytes short as
/// `a_lines_mark_of_sent_spends_none_of_the_remark_budget` spends it, the
/// small line's mark of `sent` is refused by the device and answers no error
/// — it is owed, the queue's wait naming it, the file holding the line
/// unmarked — and the retry writes it, spending nothing; a reopen reads the
/// line `sent` (the mutant that writes a refused mark once and never again
/// relaunches a line whose dial may have landed as one never sent, which the
/// resend sends without the read for its landing; the one that spends the
/// budget at the retry refuses the mark there).
#[test]
fn a_sent_mark_the_device_refused_is_written_by_the_retry_past_a_spent_budget() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let spent = |queue: &HeldQueue| queue.disk.remark_bytes;
    let refused = |n: u64| Reason { sent: true, ..Reason::refused("out_of_bounds", json!({"n": n})) };
    let spelled = HeldLine { k: 1, doc: "1.0.1.0.1".into(), id: None, dial_id: None, base: 0, frame: json!({}), anchors: None, reason: refused(1), time: now_ms() };
    let rest = held_line_bytes(&spelled, spelled.base).len() - 1 - json_len(&spelled.frame);
    let large = queue.hold_next("1.0.1.0.1", None, 0, sized_frame(MAX_HELD_REMARK_BYTES / 4 - 10 - rest), None, refused(1)).unwrap().k;
    let small = queue.hold_next("1.0.1.0.2", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
    for n in [2, 1, 2, 1] {
        queue.remark(large, refused(n)).unwrap();
    }
    assert_eq!(spent(&queue), MAX_HELD_REMARK_BYTES - 40, "premise: the budget spent to forty bytes short");
    FAIL_SYNC.with(|f| f.set(true));
    let marked = queue.remark(small, Reason::of("unreachable", true));
    FAIL_SYNC.with(|f| f.set(false));
    assert!(marked.is_ok(), "the device's refusal is owed, never answered: {marked:?}");
    assert_eq!(queue.waiting().map(|w| (w.first(), w.owed())), Some((small, Owed::Mark)), "the mark is owed");
    let unmarked = live(d.open_file(1, "1.0.1").unwrap()).lines().iter().find(|l| l.k == small).map(|l| l.reason.sent);
    assert_eq!(unmarked, Some(false), "premise: the file holds the line unmarked");
    queue.retry();
    assert!(queue.waiting().is_none() && spent(&queue) == MAX_HELD_REMARK_BYTES - 40, "the retry writes the mark, spending nothing");
    let marked = live(d.open_file(1, "1.0.1").unwrap()).lines().iter().find(|l| l.k == small).map(|l| l.reason.clone());
    assert_eq!(marked, Some(Reason::of("unreachable", true)), "a reopen reads the line `sent`");
}

/// Checks that an owed re-mark gives way to its line's `done`.
///
/// A line's re-mark and then its `done` are refused by the device: the `done`
/// takes the re-mark's place as the one copy the line owes, so the retry
/// writes the `done` alone — the file holding the line's first copy and no
/// `held` line of its ordinal after it, which the reader would take for a new
/// line — and a reopen reads the line no more, the line behind it standing
/// (the mutant that keeps each change owed writes the re-mark after the
/// `done` and brings the dropped line back; the one that keeps the re-mark in
/// the `done`'s place loses the `done`).
#[test]
fn an_owed_remark_gives_way_to_its_lines_done() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let k = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
    let behind = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "delete"}), None, Reason::of("behind", false)).unwrap().k;
    FAIL_SYNC.with(|f| f.set(true));
    queue.remark(k, Reason::of("unreachable", true)).unwrap();
    queue.done(k, Done::Dropped).unwrap();
    FAIL_SYNC.with(|f| f.set(false));
    assert_eq!(queue.waiting().map(|w| (w.first(), w.owed())), Some((k, Owed::Done)), "the `done` is the one copy the line owes");
    queue.retry();
    let text = fs::read_to_string(file_path(&tmp)).unwrap();
    let held_k = format!("{{\"held\":{k},");
    let done_at = text.lines().position(|line| line.starts_with(&format!("{{\"done\":{k},"))).unwrap_or_else(|| panic!("the `done` is written: {text}"));
    assert!(text.lines().skip(done_at + 1).all(|line| !line.starts_with(&held_k)), "no re-mark after the `done`: {text}");
    assert_eq!(text.lines().filter(|line| line.starts_with(&held_k)).count(), 1, "the line's first copy alone, the re-mark given way: {text}");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [behind], "a reopen reads the dropped line no more");
}

/// Checks that the copies owed go first, in `k` order, and that a change
/// rides its line's owed copy.
///
/// Two lines on disk; with every copy refused, the second is re-marked, then
/// the first, then the second again — each answered no error, its copy owed,
/// the last riding the second's copy owed and spending nothing of the
/// re-mark budget — and a third line held while the device still refuses
/// waits behind the copy the retry stopped at, the first's re-mark,
/// answering its refusal, and is not copied. The next retry writes the
/// first's re-mark, the second's and the third line as one copy, in `k`
/// order, one copy of the second carrying its last reason, and a reopen
/// reads the queue as it stands (the mutant that copies a new line past the
/// copies owed writes the third ahead of them; the one that owes each change
/// of a line apart writes the second's twice, and spends the budget on each).
#[test]
fn owed_copies_go_first_in_k_order_and_a_change_rides_its_owed_copy() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let spent = |queue: &HeldQueue| queue.disk.remark_bytes;
    let k1 = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
    let k2 = queue.hold_next("1.0.1.0.2", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
    FAIL_SYNC.with(|f| f.set(true));
    let mut spends = Vec::new();
    for (k, reason) in [(k2, Reason::of("poisoned", false)), (k1, Reason::of("durability", false)), (k2, Reason::of("halted", false))] {
        let before = spent(&queue);
        let remarked = queue.remark(k, reason);
        assert!(remarked.is_ok(), "line {k}: the device's refusal is owed: {remarked:?}");
        spends.push(spent(&queue) > before);
    }
    assert_eq!(spends, [true, true, false], "each copy owed afresh spends the budget as it is tried, and a change riding one spends nothing");
    assert_eq!(queue.waiting().map(|w| (w.first(), w.owed())), Some((k1, Owed::Mark)), "the first copy owed, in `k` order");
    let third = queue.hold_next("1.0.1.0.3", None, 0, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap();
    FAIL_SYNC.with(|f| f.set(false));
    assert_eq!(third.unwritten.map(|e| e.kind()), Some(std::io::ErrorKind::StorageFull), "the third waits behind the copy the retry stopped at");
    assert_eq!(queue.waiting().map(|w| (w.first(), w.owed())), Some((k1, Owed::Mark)), "the retry stopped at the first's re-mark");
    assert!(!fs::read_to_string(file_path(&tmp)).unwrap().contains("\"doc\":\"1.0.1.0.3\""), "the third is not copied ahead of the copies owed");
    let copied = record_copies(&file_path(&tmp));
    queue.retry();
    AFTER_SYNC.with(|s| *s.borrow_mut() = None);
    assert_eq!(*copied.lock().unwrap(), [vec![k1, k2, third.k]], "the copies owed first, then the line, in `k` order, as one copy");
    let text = fs::read_to_string(file_path(&tmp)).unwrap();
    let seconds: Vec<Value> = text.lines().skip(1).filter_map(|line| serde_json::from_str::<Value>(line).ok()).filter(|line| line["held"] == k2).collect();
    assert_eq!(seconds.len(), 2, "the second's first copy and one re-mark: {text}");
    assert_eq!(seconds[1]["cause"], "halted", "the re-mark carrying its last reason: {text}");
    assert_eq!(live(d.open_file(1, "1.0.1").unwrap()).lines(), queue.lines(), "a reopen reads the queue as it stands");
}

/// Checks that an owed `done` keeps its line in the queue's budgets until it
/// lands.
///
/// The queue at its byte budget less a hundred bytes, as
/// `the_queue_holds_its_frames_and_anchors_within_its_budget_and_writes_nothing_past_it`
/// fills it, the first line's `done` is refused by the device: the line has
/// left the queue and the file holds it standing, so a hold needing its room
/// is refused `Full`, its frame among the bytes and its line among the lines;
/// once the retry writes the `done`, the same hold is taken. The last line's
/// `done` refused goes with the file the compaction removes: nothing is owed
/// or counted, and the ordinals run on (the mutant that gives a line's
/// bytes back at its refused `done` lets the queue pass its budgets by every
/// line whose `done` the device refuses, the file a reopen reads holding
/// them all).
#[test]
fn an_owed_done_keeps_its_line_in_the_budget_until_it_lands() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let first = queue.hold_next("1.0.1.0.1", None, 0, sized_frame(MAX_FRAME_BYTES), None, Reason::of("stopped", false)).unwrap().k;
    for _ in 0..2 {
        queue.hold_next("1.0.1.0.1", None, 0, sized_frame(MAX_FRAME_BYTES), None, Reason::of("behind", false)).unwrap();
    }
    queue.hold_next("1.0.1.0.1", None, 0, sized_frame(MAX_FRAME_BYTES - 100), Some(anchors_of_len(MAX_ANCHOR_BYTES)), Reason::of("behind", false)).unwrap();
    FAIL_SYNC.with(|f| f.set(true));
    queue.done(first, Done::Kept { at: Some(3) }).unwrap();
    FAIL_SYNC.with(|f| f.set(false));
    assert_eq!(queue.lines().len(), 3, "the line has left the queue");
    // The hold's budgets are read before its retry, the `done` owed still.
    let refused = queue.hold_next("1.0.1.0.1", None, 0, sized_frame(200), None, Reason::of("behind", false));
    assert_eq!(refused.unwrap_err(), Unheld::Full { held_bytes: MAX_HELD_BYTES - 100, frame_bytes: 200, anchor_bytes: 0, held_lines: 4 }, "the owed `done`'s line counted in both budgets");
    queue.retry();
    assert!(queue.waiting().is_none(), "the `done` landed");
    assert!(queue.hold_next("1.0.1.0.1", None, 0, sized_frame(200), None, Reason::of("behind", false)).is_ok(), "its room given back");

    // The last line's `done` refused: the file goes, and nothing is owed.
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let k = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
    FAIL_SYNC.with(|f| f.set(true));
    let settled = queue.done(k, Done::Dropped).unwrap();
    FAIL_SYNC.with(|f| f.set(false));
    assert!(settled.unremoved.is_none() && !queue.on_disk(), "the file is removed: {settled:?}");
    assert!(queue.waiting().is_none() && queue.held_bytes == 0, "nothing is owed, and nothing counted");
    assert_eq!(queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap().k, 2, "the ordinals run on");
}

/// Checks that a queue whose file owes a copy joins nothing until it lands.
///
/// The board's queue holds a line whose re-mark the device refused, owed, and
/// the device then cuts the next copy short: a join of a queue kept in memory
/// is refused at that queue's first line, under the owed copy's refusal — the
/// retry stopping at it — nothing entered and nothing copied, though the
/// device would take the joined line. Once it does, the retry writes the
/// re-mark first and the joined line after it (the mutant that copies a
/// joined line past an owed copy writes it ahead of the re-mark owed before
/// it).
#[test]
fn a_queue_owing_a_copy_writes_it_before_a_line_joined_behind_it() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut chain = live(d.open_file(1, "1.0.1").unwrap());
    let k = chain.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
    FAIL_SYNC.with(|f| f.set(true));
    chain.remark(k, Reason::of("unreachable", true)).unwrap();
    let mut ours = HeldQueue::unopened(&d, 1, "1.0.1");
    ours.hold(2, "1.0.1.0.2", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap();
    let joined = chain.join(&ours, Joining::ThisRun);
    assert_eq!((joined.entered, ks(&chain)), (vec![(2, 2)], vec![k, 2]), "the line enters at once, owed");
    assert_eq!(chain.waiting().map(|w| (w.first(), w.owed())), Some((k, Owed::Mark)), "the re-mark owed before it is the copy the retry stopped at");
    assert!(!fs::read_to_string(file_path(&tmp)).unwrap().contains("\"doc\":\"1.0.1.0.2\""), "nothing copied while the re-mark waits");
    FAIL_SYNC.with(|f| f.set(false));
    chain.retry();
    assert!(chain.waiting().is_none(), "both written");
    let text = fs::read_to_string(file_path(&tmp)).unwrap();
    let order: Vec<(u64, bool)> = text.lines().skip(1).filter_map(|line| serde_json::from_str::<Value>(line).ok()).filter_map(|line| Some((line["held"].as_u64()?, line["sent"].as_bool()?))).collect();
    assert_eq!(order, [(k, false), (k, true), (2, false)], "the re-mark before the joined line: {text}");
    assert_eq!(live(d.open_file(1, "1.0.1").unwrap()).lines(), chain.lines(), "the file holds the queue as it stands, the re-mark among it");
}

/// Checks that a join the device refuses enters its lines owed, and the
/// retry writes them once the device takes copies.
///
/// The board's queue holds a line; two lines of this run's join it with
/// every copy refused: both enter at once, each owed its first copy and
/// waiting under the refusal, nothing copied — the file byte for byte as it
/// stood, so a reopen meanwhile reads the one line — and a second join of
/// the same lines enters nothing, each standing already. Once the device
/// takes copies, the retry writes both, and a reopen reads three lines,
/// each once (the mutant that holds the lines back until their copy lands
/// keeps lines the page was answered off the queue; the one that leaves a
/// refused copy's bytes in the file, or enters a standing line again, reads
/// a line twice).
#[test]
fn a_join_the_device_refuses_enters_its_lines_owed_and_the_retry_writes_them_once_it_takes_copies() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut chain = live(d.open_file(1, "1.0.1").unwrap());
    chain.hold_next("1.0.1.0.9", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap();
    let mut ours = HeldQueue::unopened(&d, 1, "1.0.1");
    ours.hold(2, "1.0.1.0.1", None, 0, json!({"op": "insert", "v": 1}), None, Reason::of("unreachable", false)).unwrap();
    ours.hold(3, "1.0.1.0.1", None, 0, json!({"op": "insert", "v": 2}), None, Reason::of("behind", false)).unwrap();
    let before = fs::read(file_path(&tmp)).unwrap();
    FAIL_SYNC.with(|f| f.set(true));
    let joined = chain.join(&ours, Joining::ThisRun);
    let again = chain.join(&ours, Joining::ThisRun);
    FAIL_SYNC.with(|f| f.set(false));
    assert_eq!((joined.entered, ks(&chain)), (vec![(2, 2), (3, 3)], vec![1, 2, 3]), "both enter at once");
    assert_eq!((again.entered.len(), again.repeated), (0, 2), "a join of lines standing already enters nothing");
    assert_eq!(chain.waiting().map(|w| (w.first(), w.owed(), w.error.kind())), Some((2, Owed::Line, std::io::ErrorKind::StorageFull)), "both wait under the refusal, the first named");
    assert_eq!(fs::read(file_path(&tmp)).unwrap(), before, "the file byte for byte as it stood");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [1], "a reopen meanwhile reads the one line");
    chain.retry();
    assert!(chain.waiting().is_none(), "both written once the device takes copies");
    let read: Vec<(String, u64)> = live(d.open_file(1, "1.0.1").unwrap()).lines().iter().map(|l| (l.doc.clone(), l.frame["v"].as_u64().unwrap_or(0))).collect();
    let want = [("1.0.1.0.9".to_string(), 0), ("1.0.1.0.1".to_string(), 1), ("1.0.1.0.1".to_string(), 2)];
    assert_eq!(read, want, "three lines, each once");
}

/// Checks that a join is one copy with one sync, however many lines enter.
///
/// A queue holding `MAX_HELD_LINES` lines, each its own, held while its file
/// could not be read, joins a fresh board's file: the file's header is its
/// own copy, and every line enters in ONE copy beside it, synced once, its
/// lines in `k` order; a reopen reads them all (the mutant that copies the
/// joined lines one by one syncs `MAX_HELD_LINES` times, the board's lock
/// held across every one).
#[test]
fn a_join_of_a_full_queue_is_one_copy_with_one_sync() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut ours = HeldQueue::unopened(&d, 1, "1.0.1");
    for n in 0..MAX_HELD_LINES {
        ours.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert", "v": n}), None, Reason::of("unreachable", false)).unwrap();
    }
    let mut chain = live(d.open_file(1, "1.0.1").unwrap());
    let copied = record_copies(&file_path(&tmp));
    let joined = chain.join(&ours, Joining::ThisRun);
    AFTER_SYNC.with(|s| *s.borrow_mut() = None);
    assert_eq!((joined.entered.len(), joined.repeated), (MAX_HELD_LINES, 0), "every line enters, its ordinal kept");
    let all: Vec<u64> = (1..=MAX_HELD_LINES as u64).collect();
    assert_eq!(copied.lock().unwrap().as_slice(), std::slice::from_ref(&all), "one copy of every line, in `k` order");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), all, "a reopen reads them all");
}

/// Checks that within one run a join meeting a line it already holds enters
/// it once, and keeps two equal lines of different ordinals (skep #856).
///
/// This run's ordinals name one line each: the board's file holds line 1,
/// and a queue of this run's holds the same line under 1 — a join's copy
/// that landed before the join was cut short — beside 2 and 3, the two
/// equal to it by document, `id` and frame, as an agent sending the same
/// call twice makes them. Into a fresh file every line enters; into the
/// file holding 1, the join passes 1 over as the line it already holds and
/// enters 2 and 3, equal or not, and a reopen reads three lines, each once
/// (the mutant that tests repeats by what a line carries within a run drops
/// the second equal burst, the person's text landing once where it was typed
/// twice; the one that enters a line of a standing ordinal writes a re-mark
/// of a line the queue then holds twice).
#[test]
fn within_one_run_a_join_enters_a_line_it_holds_once_and_keeps_equal_lines_of_other_ordinals() {
    let equal = json!({"op": "delete", "doc": "1.0.1.0.1", "as_of": 4});
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut ours = HeldQueue::unopened(&d, 1, "1.0.1");
    for k in [1, 2, 3] {
        ours.hold(k, "1.0.1.0.1", None, 0, equal.clone(), None, Reason::of("unreachable", false)).unwrap();
    }
    let mut chain = live(d.open_file(1, "1.0.1").unwrap());
    let joined = chain.join(&ours, Joining::ThisRun);
    assert_eq!((joined.entered.len(), joined.repeated), (3, 0), "into a fresh file every line enters");
    assert_eq!(live(d.open_file(1, "1.0.1").unwrap()).lines().iter().filter(|l| l.frame == equal).count(), 3, "a reopen reads the three equal lines");
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut chain = live(d.open_file(1, "1.0.1").unwrap());
    chain.hold(1, "1.0.1.0.1", None, 0, equal.clone(), None, Reason::of("unreachable", false)).unwrap();
    let joined = chain.join(&ours, Joining::ThisRun);
    assert_eq!((joined.entered, joined.repeated), (vec![(2, 2), (3, 3)], 1), "the line held already passed over, the equal lines of other ordinals entered");
    let read = live(d.open_file(1, "1.0.1").unwrap());
    assert_eq!((ks(&read), read.lines().iter().filter(|l| l.frame == equal).count()), (vec![1, 2, 3], 3), "a reopen reads three lines, each once");
}

/// Checks that a copy's bytes left standing after a refused cut-back are
/// cut by the retry before it writes.
///
/// The board's queue holds a line, and one line of this run's joins it with
/// its copy's sync refused and the cut-back refused too: the line enters,
/// owed, and the queue keeps that its file holds the copy's bytes, which a
/// fresh read takes for a held line (a copy of several lines is copied one
/// by one once refused, each try's own cut taking what the one before left,
/// so the bytes outlive a retry only where one copy was made). The device
/// taking copies again, the retry cuts them first and then writes the copy
/// owed, so the file holds each line once and a fresh read reads two lines
/// (the mutant that forgets the refused cut-back writes the copy after its
/// own bytes, and a fresh read takes the first for a line and the second for
/// its re-mark, or holds the line twice).
#[test]
fn a_copys_bytes_left_by_a_refused_cut_back_are_cut_by_the_retry_before_it_writes() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut chain = live(d.open_file(1, "1.0.1").unwrap());
    chain.hold_next("1.0.1.0.9", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap();
    let mut ours = HeldQueue::unopened(&d, 1, "1.0.1");
    ours.hold(2, "1.0.1.0.1", None, 0, json!({"op": "insert", "v": 1}), None, Reason::of("unreachable", false)).unwrap();
    FAIL_SYNC.with(|f| f.set(true));
    refuse_the_next_cut_back();
    let joined = chain.join(&ours, Joining::ThisRun);
    FAIL_SYNC.with(|f| f.set(false));
    assert_eq!((joined.entered.len(), ks(&chain)), (1, vec![1, 2]), "entered, owed");
    assert!(chain.disk.tail_left && chain.waiting().is_some(), "the copy's bytes left, the copy owed");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [1, 2], "premise: a fresh read takes the copy's bytes for a held line");
    chain.retry();
    assert!(!chain.disk.tail_left && chain.waiting().is_none(), "the retry cut them, then wrote the copy");
    let text = fs::read_to_string(file_path(&tmp)).unwrap();
    assert_eq!(text.lines().skip(1).count(), 2, "each line once in the file, the refused copy's bytes gone: {text}");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [1, 2], "a fresh read reads the two lines");
}

// ── WHAT THE FILE OWES, READ (§3c.3; skep #860) ─────────────────────────────

/// Checks that what the file owes is counted, and lands with the retry.
///
/// A line waiting for its first copy counts in `lines`, and its document
/// waits; a `done` the device refused counts by how the line left, the line
/// off the queue; a re-mark's copy counts nothing. The device taking copies
/// again, the retry writes them and nothing is counted (the mutant that
/// counts a `done` as a line says a settled line goes with the process; the
/// one that counts a re-mark says a line's standing is at risk where only
/// its reason is).
#[test]
fn what_the_file_owes_is_counted_until_the_retry_writes_it() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let hold = |queue: &mut HeldQueue, doc: &str| queue.hold_next(doc, None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
    let (k1, k2, k3) = (hold(&mut queue, "1.0.1.0.1"), hold(&mut queue, "1.0.1.0.2"), hold(&mut queue, "1.0.1.0.3"));
    assert_eq!(queue.copies_owed(), CopiesOwed::default(), "every line on disk");
    FAIL_SYNC.with(|f| f.set(true));
    queue.done(k1, Done::Kept { at: Some(9) }).unwrap();
    queue.done(k2, Done::Dropped).unwrap();
    queue.remark(k3, Reason::of("poisoned", false)).unwrap();
    assert_eq!(queue.copies_owed(), CopiesOwed { lines: 0, kept: 1, dropped: 1 }, "each `done` by how the line left, the re-mark nothing");
    assert!(!queue.waits_on("1.0.1.0.3"), "a line whose re-mark is owed has its first copy");
    let k4 = hold(&mut queue, "1.0.1.0.4");
    assert_eq!(queue.copies_owed(), CopiesOwed { lines: 1, kept: 1, dropped: 1 }, "a line waiting for its first copy");
    assert!(queue.off_disk(k4) && !queue.off_disk(k3), "the line waiting has no copy, the line re-marked has one");
    assert!(queue.waits_on("1.0.1.0.4") && !queue.waits_on("1.0.1.0.3") && !queue.waits_on("1.0.1.0.9"), "a document's own lines answer for it");
    FAIL_SYNC.with(|f| f.set(false));
    queue.retry();
    assert_eq!(queue.copies_owed(), CopiesOwed::default(), "the retry wrote them");
    assert!(!queue.off_disk(k4) && !queue.waits_on("1.0.1.0.4"), "and the line has its copy");
}

/// Checks that the compaction takes the `done`s it owes with the file.
///
/// The last line's `done` refused, the queue empties and the file goes:
/// nothing is left to come back, and nothing is counted (the mutant that
/// keeps the count past the compaction says a line returns that no file
/// holds).
#[test]
fn the_compaction_takes_the_dones_it_owes_with_the_file() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let k = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
    FAIL_SYNC.with(|f| f.set(true));
    let settled = queue.done(k, Done::Dropped).unwrap();
    FAIL_SYNC.with(|f| f.set(false));
    assert!(settled.unremoved.is_none() && !queue.on_disk(), "the file went: {settled:?}");
    assert_eq!(queue.copies_owed(), CopiesOwed::default(), "and its `done` with it");
}

/// Checks that a `done` stays counted where the file cannot be removed.
///
/// The queue emptied, its file sealed against the unlink and its `done`
/// refused, the file stands: a relaunch reads the line as held, and the
/// count says so (the mutant that clears the owed copies at a refused
/// removal says nothing of a line the next start lists).
#[cfg(unix)]
#[test]
fn a_done_stays_counted_where_the_file_cannot_be_removed() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let board_dir = tmp.path().join("held").join(chain().to_string());
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let k = queue.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().k;
    fs::set_permissions(&board_dir, fs::Permissions::from_mode(0o500)).unwrap();
    FAIL_SYNC.with(|f| f.set(true));
    let settled = queue.done(k, Done::Kept { at: Some(3) }).unwrap();
    FAIL_SYNC.with(|f| f.set(false));
    fs::set_permissions(&board_dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(settled.unremoved.is_some() && queue.on_disk(), "the file stands: {settled:?}");
    assert_eq!(queue.copies_owed(), CopiesOwed { lines: 0, kept: 1, dropped: 0 }, "and the `done` is still owed");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [k], "a relaunch reads the line as held");
}

/// Checks that a parked line is no line off disk, and what its file never
/// wrote is counted while it stands.
///
/// The change's copies refused (skep #859): two lines the pending file holds
/// are parked on it, their copies owed to the board's file, and neither is
/// off disk, since a close keeps both; the `done` the pending queue owed
/// when the change replaced it, and a parked line that leaves, are `done`s
/// the pending file will never hold, counted until it goes (the mutant that
/// counts a parked line as in memory says a close loses words the pending
/// file keeps; the one that drops the replaced queue's `done`s says nothing
/// of a line that returns from the pending file).
#[test]
fn a_parked_line_has_its_copy_and_what_its_file_never_wrote_is_counted() {
    let tmp = TempDir::new().unwrap();
    let (pending, chain_dir) = (pending_dir(&tmp), dir(&tmp));
    let mut from = live(pending.open_file(1, "1.0.1").unwrap());
    let hold = |queue: &mut HeldQueue, doc: &str| queue.hold_next(doc, None, 0, json!({"op": "insert"}), None, Reason::of("head_unreadable", false)).unwrap().k;
    let (k1, k2, k3) = (hold(&mut from, "1.0.1.0.1"), hold(&mut from, "1.0.1.0.2"), hold(&mut from, "1.0.1.0.3"));
    FAIL_SYNC.with(|f| f.set(true));
    from.done(k1, Done::Kept { at: Some(9) }).unwrap();
    let mut chain = live(chain_dir.open_file(1, "1.0.1").unwrap());
    let joined = chain.join(&from, Joining::ThisRun);
    assert_eq!(joined.entered, [(k2, k2), (k3, k3)], "premise: both lines enter, owed");
    chain.supersede(from.path().to_path_buf(), from.standing_on_disk(), from.dones_owed());
    assert!(chain.parked(k2) && !chain.off_disk(k2) && !chain.off_disk(k3), "parked lines have their copy on the pending file");
    assert!(!chain.waits_on("1.0.1.0.2"), "and their documents wait for nothing a close loses");
    assert_eq!(chain.copies_owed(), CopiesOwed { lines: 0, kept: 1, dropped: 0 }, "the replaced queue's `done` is counted");
    let waits = chain.hold_next("1.0.1.0.4", None, 0, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap();
    assert!(waits.unwritten.is_some() && chain.off_disk(waits.k) && chain.waits_on("1.0.1.0.4"), "a line held since has no copy");
    assert_eq!(chain.copies_owed(), CopiesOwed { lines: 1, kept: 1, dropped: 0 }, "and is counted");
    chain.done(k2, Done::Dropped).unwrap();
    assert_eq!(chain.copies_owed(), CopiesOwed { lines: 1, kept: 1, dropped: 1 }, "a parked line that leaves is a `done` the pending file never wrote");
    FAIL_SYNC.with(|f| f.set(false));
    chain.retry();
    assert!(chain.superseded().is_none(), "premise: the pending file is removed once nothing is owed");
    assert_eq!(chain.copies_owed(), CopiesOwed::default(), "nothing is counted once it goes");
}

/// Checks that a document's waiting is read among lines of other ordinals.
///
/// The queue's lines interleave across documents, an earlier run's on disk
/// under ordinals past this run's: a document with a line waiting answers
/// true, one with only a line on disk false, whichever ordinal comes first
/// (the mutant that stops at the first ordinal the two walks disagree on
/// answers false for a document whose waiting line lies beyond it).
#[test]
fn a_documents_waiting_is_read_among_lines_of_other_ordinals() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut chain = live(d.open_file(1, "1.0.1").unwrap());
    let on_disk = |doc: &str, k: u64, chain: &mut HeldQueue| assert!(chain.hold(k, doc, None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().unwritten.is_none());
    on_disk("1.0.1.0.1", 8, &mut chain);
    on_disk("1.0.1.0.2", 9, &mut chain);
    let mut ours = HeldQueue::unopened(&d, 1, "1.0.1");
    for (k, doc) in [(2, "1.0.1.0.1"), (3, "1.0.1.0.3"), (5, "1.0.1.0.1")] {
        ours.hold(k, doc, None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap();
    }
    FAIL_SYNC.with(|f| f.set(true));
    chain.join(&ours, Joining::ThisRun);
    FAIL_SYNC.with(|f| f.set(false));
    assert!(chain.waits_on("1.0.1.0.1"), "ordinals 2 and 5 wait below the 8 on disk");
    assert!(chain.waits_on("1.0.1.0.3"), "ordinal 3 waits");
    assert!(!chain.waits_on("1.0.1.0.2"), "its one line is on disk, past every line waiting");
    assert_eq!(chain.copies_owed(), CopiesOwed { lines: 3, kept: 0, dropped: 0 });
}

// ── THE RUNS (§3c.3; skep #861) ─────────────────────────────────────────────

/// Returns the copies of lines `act` lands, each one append's sync.
fn copies_of(act: impl FnOnce()) -> usize {
    let landed = count_copies();
    act();
    take_copies();
    landed.get()
}

/// Checks that a run of re-marks or `done`s is one copy, and leaves the file
/// as a call a line leaves it.
///
/// Two queues over two stores hold the same five lines — three on one
/// document, the fourth on another, and a fifth on the first held with its
/// copy refused, so it waits for its first copy — and take the same acts,
/// one a line at a time and the other as runs (skep #861): a re-mark of three
/// lines raised to 45, the waiting one among them, its change carried in its
/// first copy; a re-mark of two more; a `done` of the first two kept at 60,
/// raising the bases behind them on their document; a run naming no standing
/// line, and one changing nothing; and a `done` of the rest. Each run is one
/// copy with one sync — none for the two that settle and change nothing, and
/// the last written before the compaction removes the file — and after each
/// act both queues, and both files reopened, hold the lines expected, by
/// ordinal, document, base and reason (the mutant that runs the retry a line
/// at a time inside a run pays a sync a line; the one that drops the run's
/// raise holds its lines below the rows the person acknowledged; the one
/// that raises no base behind a run's kept line reads the rows below it
/// again until a relaunch; the one that ends a run of `done`s without its
/// retry relaunches the lines it settled).
#[test]
fn a_run_of_remarks_or_dones_is_one_copy_and_leaves_the_file_as_a_call_a_line_does() {
    let (d1, d2) = ("1.0.1.0.1", "1.0.1.0.2");
    let held = |tmp: &TempDir| -> HeldQueue {
        let mut queue = live(dir(tmp).open_file(1, "1.0.1").unwrap());
        for doc in [d1, d1, d1, d2] {
            assert!(queue.hold_next(doc, None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap().unwritten.is_none());
        }
        FAIL_SYNC.with(|f| f.set(true));
        let waits = queue.hold_next(d1, None, 0, json!({"op": "delete"}), None, Reason::of("behind", false)).unwrap();
        FAIL_SYNC.with(|f| f.set(false));
        assert!(waits.unwritten.is_some(), "premise: the fifth waits for its first copy");
        queue
    };
    let (by_line, by_run) = (TempDir::new().unwrap(), TempDir::new().unwrap());
    let (mut one, mut run) = (held(&by_line), held(&by_run));
    let standing = |lines: &[HeldLine]| -> Vec<(u64, String, u64, Reason)> { lines.iter().map(|l| (l.k, l.doc.clone(), l.base, l.reason.clone())).collect() };
    let expect = |act: &str, queues: [&HeldQueue; 2], lines: &[(u64, &str, u64, &Reason)]| {
        let lines: Vec<(u64, String, u64, Reason)> = lines.iter().map(|&(k, doc, base, reason)| (k, doc.to_string(), base, reason.clone())).collect();
        let files = [&by_line, &by_run].map(|tmp| standing(&live(dir(tmp).open_file(1, "1.0.1").unwrap()).lines()));
        assert_eq!(
            (queues.map(|queue| standing(&queue.lines())), files),
            ([lines.clone(), lines.clone()], [lines.clone(), lines]),
            "{act}: each queue, and each file reopened, holds the lines expected"
        );
    };
    let (unreachable, behind, moved) = (Reason::of("unreachable", false), Reason::of("behind", false), Reason::of("moved", false));
    // A re-mark of three lines raised to 45, the waiting one among them.
    for k in [2, 3, 5] {
        assert!(one.remark_all([(k, behind.clone())], Some(45)).is_empty());
    }
    assert_eq!(copies_of(|| assert!(run.remark_all([2, 3, 5].map(|k| (k, behind.clone())), Some(45)).is_empty())), 1, "the raised re-marks, one copy");
    expect("raised", [&one, &run], &[(1, d1, 0, &unreachable), (2, d1, 45, &behind), (3, d1, 45, &behind), (4, d2, 0, &unreachable), (5, d1, 45, &behind)]);
    // A re-mark of two more, one on each document.
    for k in [1, 4] {
        one.remark(k, moved.clone()).unwrap();
    }
    assert_eq!(copies_of(|| assert!(run.remark_all([1, 4].map(|k| (k, moved.clone())), None).is_empty())), 1, "the re-marks, one copy");
    expect("re-marked", [&one, &run], &[(1, d1, 0, &moved), (2, d1, 45, &behind), (3, d1, 45, &behind), (4, d2, 0, &moved), (5, d1, 45, &behind)]);
    // A `done` of the first two kept at 60, raising the bases behind them.
    for k in [1, 2] {
        one.done(k, Done::Kept { at: Some(60) }).unwrap();
    }
    assert_eq!(copies_of(|| assert!(run.done_all(&[1, 2], Done::Kept { at: Some(60) }).unremoved.is_none())), 1, "the `done`s, one copy");
    expect("kept", [&one, &run], &[(3, d1, 60, &behind), (4, d2, 0, &moved), (5, d1, 60, &behind)]);
    // A run naming no standing line, and one changing nothing.
    assert_eq!(copies_of(|| assert!(run.done_all(&[99], Done::Dropped).unremoved.is_none())), 0, "a run settling no line writes nothing");
    assert_eq!(copies_of(|| assert!(run.remark_all([(3, behind.clone())], Some(45)).is_empty())), 0, "a run changing nothing writes nothing");
    expect("unchanged", [&one, &run], &[(3, d1, 60, &behind), (4, d2, 0, &moved), (5, d1, 60, &behind)]);
    // A `done` of the rest: written, then the file removed.
    for k in [3, 4, 5] {
        one.done(k, Done::Dropped).unwrap();
    }
    assert_eq!(copies_of(|| assert!(run.done_all(&[3, 4, 5], Done::Dropped).unremoved.is_none())), 1, "the last `done`s, one copy before the compaction");
    assert!(!one.on_disk() && !run.on_disk() && run.lines().is_empty(), "both files compacted away");
}

// ── THE PENDING DIRECTORY (§3c.1; skep #725) ────────────────────────────────

/// The origin a pending directory is named by in these cells.
fn origin() -> Origin {
    Origin::parse("http://127.0.0.1:4242").unwrap()
}

/// The pending directory for [`origin`] under `tmp`, made.
fn pending_dir(tmp: &TempDir) -> HeldDir {
    let d = HeldDir::pending(tmp.path(), &origin());
    d.ensure().unwrap();
    d
}

/// The hash a pending directory is named by: the lowercase hex SHA-256 of the
/// origin as `Board::dialed` spells it.
fn hash_of(origin: &str) -> Chain {
    Chain::from_bytes(Sha256::digest(origin.as_bytes()).into())
}

/// The principal-1 pending file's path under `tmp`.
fn pending_path(tmp: &TempDir) -> std::path::PathBuf {
    tmp.path().join("held").join("pending").join(hash_of(origin().as_str()).to_string()).join("principal-1.held")
}

/// Checks that a pending file carries the origin and `v` 2 and reads back.
///
/// Its directory is `held/pending/<hash>/`, the hash the SHA-256 of the
/// origin dialed, 64 lowercase hex as a chain's name is; its header is the
/// chain file's in every member save `v` 2 and `board` the origin, byte-exact;
/// its lines read back as they were held, the header's account the queue's
/// own; another origin's pending file in the directory is set aside under
/// the hash of the origin it names and never read; a pending file misplaced
/// into a chain directory halts `Newer`, the chain reader untouched; and a
/// chain file (`v` 1) in a pending directory is a header off that
/// directory's spelling (the mutants that read a pending file as a chain
/// file's, or take `v` 2 in a chain directory, write under a name the board
/// never gave).
#[test]
fn a_pending_file_carries_the_origin_and_v_2_and_reads_back_with_its_lines() {
    let tmp = TempDir::new().unwrap();
    let d = pending_dir(&tmp);
    let hash = hash_of(origin().as_str()).to_string();
    assert!(hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')), "{hash}");
    let path = pending_path(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    assert!(queue.is_pending() && !queue.on_disk());
    let held = queue.hold_next("1.0.1.0.1", None, 5, json!({"op": "insert"}), None, Reason::of("head_unreadable", false)).unwrap();
    assert!(held.unwritten.is_none(), "{:?}", held.unwritten);
    let raw = fs::read_to_string(&path).unwrap();
    assert_eq!(raw.lines().next().unwrap(), r#"{"type":"skep-held-bursts","v":2,"board":"http://127.0.0.1:4242","principal":1,"account":"1.0.1"}"#);
    assert!(raw.lines().nth(1).unwrap().starts_with("{\"held\":1,\"doc\":\"1.0.1.0.1\",\"base\":5,\"frame\":{\"op\":\"insert\"},\"cause\":\"head_unreadable\","), "the chain file's line form: {raw}");
    let reopened = live(d.open_file(1, "").unwrap());
    assert_eq!(ks(&reopened), [1], "the line reads back");
    assert_eq!((reopened.account(), reopened.board().as_deref(), reopened.is_pending()), (Some("1.0.1"), Some("http://127.0.0.1:4242"), true), "the header's account and board are the file's own");

    // Another origin's pending file: set aside under the hash of the origin
    // it names, never read, this principal's file started fresh.
    let other = "http://127.0.0.1:1";
    fs::write(&path, format!("{{\"type\":\"skep-held-bursts\",\"v\":2,\"board\":\"{other}\",\"principal\":1,\"account\":\"1.0.1\"}}\n{{\"held\":1,\"doc\":\"1.0.1.0.1\",\"base\":0,\"frame\":{{}},\"cause\":\"stopped\",\"sent\":false,\"time\":1}}\n")).unwrap();
    let Opened::Live { queue, aside } = d.open_file(1, "1.0.1").unwrap() else { panic!("set aside, never halted") };
    let aside1 = path.parent().unwrap().join(aside_name("principal-1.held", &hash_of(other), 1));
    assert_eq!(aside.as_deref(), Some(aside1.as_path()), "the aside under the other origin's hash");
    assert!(aside1.is_file() && queue.lines().is_empty() && !path.exists(), "the file set aside, this principal's started fresh");

    // A pending file misplaced into a chain directory: `Newer`, as the chain
    // reader has it for every `v` above 1.
    let chain_dir = dir(&tmp);
    fs::write(file_path(&tmp), format!("{{\"type\":\"skep-held-bursts\",\"v\":2,\"board\":\"{}\",\"principal\":1,\"account\":\"1.0.1\"}}\n", origin().as_str())).unwrap();
    assert!(matches!(chain_dir.open_file(1, "1.0.1").unwrap(), Opened::Halted { why: HaltWhy::Newer, .. }), "a pending file in a chain directory halts Newer");
    // A chain file in a pending directory: a header off the directory's
    // spelling.
    fs::write(&path, format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{}\",\"principal\":1,\"account\":\"1.0.1\"}}\n", chain())).unwrap();
    assert!(matches!(d.open_file(1, "1.0.1").unwrap(), Opened::Halted { why: HaltWhy::UnknownMember, .. }), "a chain file in a pending directory is a header off its spelling");
}

/// Checks that this run's lines keep their ordinals into a fresh file and
/// into one that holds lines: the join an ordered insert (skep #856).
///
/// Five lines held on the pending file with three of them done leave 3 and
/// 5 standing. Into a board's file that holds no line, each keeps its
/// ordinal, the lines' members as they were held and a reopen reading them
/// so, the queue's greatest ordinal past them; into a file that holds lines
/// under 1 and 9, each keeps its ordinal too, inserted where it falls — the
/// queue [1, 3, 5, 9] though the file holds 3 and 5 after 9 — and a reopen
/// reads the same queue (the mutant that renumbers a line into a file that
/// holds lines hands the page an ordinal it does not hold; the one that
/// appends in place of inserting walks 9 before 3).
#[test]
fn this_runs_lines_keep_their_ordinals_into_a_fresh_file_and_into_one_that_holds_lines() {
    let tmp = TempDir::new().unwrap();
    let pending = pending_dir(&tmp);
    let chain_dir = dir(&tmp);
    let mut from = live(pending.open_file(1, "1.0.1").unwrap());
    for n in 1..=5u64 {
        let doc = format!("1.0.1.0.{n}");
        from.hold_next(&doc, Some("id"), 7, json!({"op": "insert", "doc": doc}), None, Reason::of("head_unreadable", false)).unwrap();
    }
    for k in [1, 2, 4] {
        from.done(k, Done::Dropped).unwrap();
    }
    assert_eq!(ks(&from), [3, 5]);
    // Into a fresh file: the ordinals kept, the greatest past them.
    let mut into = live(chain_dir.open_file(1, "1.0.1").unwrap());
    let joined = into.join(&from, Joining::ThisRun);
    assert_eq!((joined.entered, joined.repeated), (vec![(3, 3), (5, 5)], 0));
    assert_eq!((ks(&into), into.greatest_k()), (vec![3, 5], 5));
    assert_eq!(into.hold_next("1.0.1.0.6", None, 0, json!({"op": "insert"}), None, Reason::of("behind", false)).unwrap().k, 6, "the next ordinal past them");
    let reopened = live(chain_dir.open_file(1, "1.0.1").unwrap()).lines();
    let read: Vec<(u64, &str, u64, &str, Option<&str>)> = reopened.iter().map(|l| (l.k, l.doc.as_str(), l.base, l.reason.cause.as_str(), l.id.as_deref())).collect();
    assert_eq!(read, [(3, "1.0.1.0.3", 7, "head_unreadable", Some("id")), (5, "1.0.1.0.5", 7, "head_unreadable", Some("id")), (6, "1.0.1.0.6", 0, "behind", None)], "the lines as they were held, on disk");
    into.supersede(from.path().to_path_buf(), from.standing_on_disk(), Vec::new());
    assert!(!pending_path(&tmp).exists() && into.superseded().is_none(), "the pending file removed once nothing is owed");

    // Into a file that holds lines under 1 and 9: inserted where they fall.
    let tmp = TempDir::new().unwrap();
    let (pending, chain_dir) = (pending_dir(&tmp), dir(&tmp));
    let mut from = live(pending.open_file(1, "1.0.1").unwrap());
    from.hold(3, "1.0.1.0.1", None, 0, json!({"op": "insert", "v": 3}), None, Reason::of("head_unreadable", false)).unwrap();
    from.hold(5, "1.0.1.0.1", None, 0, json!({"op": "insert", "v": 5}), None, Reason::of("behind", false)).unwrap();
    let mut into = live(chain_dir.open_file(1, "1.0.1").unwrap());
    into.hold(1, "1.0.1.0.9", None, 0, json!({"op": "insert", "v": 1}), None, Reason::of("unreachable", false)).unwrap();
    into.hold(9, "1.0.1.0.9", None, 0, json!({"op": "insert", "v": 9}), None, Reason::of("behind", false)).unwrap();
    let joined = into.join(&from, Joining::ThisRun);
    assert_eq!((joined.entered, joined.repeated), (vec![(3, 3), (5, 5)], 0), "kept, whatever the file holds");
    assert_eq!(ks(&into), [1, 3, 5, 9], "inserted where they fall");
    let on_disk: Vec<u64> = fs::read_to_string(file_path(&tmp))
        .unwrap()
        .lines()
        .skip(1)
        .filter_map(|line| {
            let line: Value = serde_json::from_str(line).ok()?;
            line["held"].as_u64()
        })
        .collect();
    assert_eq!(on_disk, [1, 9, 3, 5], "the file holds the copy after every line written before it");
    let read: Vec<(u64, u64)> = live(chain_dir.open_file(1, "1.0.1").unwrap()).lines().iter().map(|l| (l.k, l.frame["v"].as_u64().unwrap_or(0))).collect();
    assert_eq!(read, [(1, 1), (3, 3), (5, 5), (9, 9)], "a reopen reads the same queue, in `k` order");
}

/// Checks that an earlier run's lines take fresh ordinals from the counter
/// in their file's order, whatever the file they join holds (skep #856).
///
/// An earlier run's pending file holds 3 and 5 standing: into a fresh
/// board's file under a counter at 1, they enter as 1 and 2, the counter
/// moved to 3, and a reopen reads them so under their fresh ordinals; into
/// a file that holds a line under 1, under a counter at 2, they enter as 2
/// and 3 behind it; and into a file that holds no line but names every
/// ordinal done — every line done, the removal refused by a sealed
/// directory, so the file stands — they enter under the counter past them,
/// 4 and 5, as the hold's counter runs on (the mutant that keeps an earlier
/// run's ordinal writes a line under one this run may hold; the one that
/// counts from the standing lines re-marks a line the file names done).
#[cfg(unix)]
#[test]
fn an_earlier_runs_lines_take_fresh_ordinals_from_the_counter_in_their_files_order() {
    use std::os::unix::fs::PermissionsExt;
    let earlier = |tmp: &TempDir| {
        let pending = pending_dir(tmp);
        let mut from = live(pending.open_file(1, "1.0.1").unwrap());
        for n in 1..=5u64 {
            from.hold_next(&format!("1.0.1.0.{n}"), Some("id"), 7, json!({"op": "insert", "v": n}), None, Reason::of("head_unreadable", false)).unwrap();
        }
        for k in [1, 2, 4] {
            from.done(k, Done::Dropped).unwrap();
        }
        assert_eq!(ks(&from), [3, 5]);
        from
    };
    // Into a fresh file, under a counter at 1.
    let tmp = TempDir::new().unwrap();
    let from = earlier(&tmp);
    let chain_dir = dir(&tmp);
    let mut into = live(chain_dir.open_file(1, "1.0.1").unwrap());
    let mut next_k = 1;
    let joined = into.join(&from, Joining::EarlierRun { next_k: &mut next_k });
    assert_eq!((joined.entered, joined.repeated, next_k), (vec![(3, 1), (5, 2)], 0, 3), "fresh ordinals in the file's order, the counter past them");
    let read: Vec<(u64, u64, u64)> = live(chain_dir.open_file(1, "1.0.1").unwrap()).lines().iter().map(|l| (l.k, l.frame["v"].as_u64().unwrap_or(0), l.base)).collect();
    assert_eq!(read, [(1, 3, 7), (2, 5, 7)], "the lines as they were held, under their fresh ordinals, on disk");

    // Into a file that holds a line, under a counter at 2.
    let tmp = TempDir::new().unwrap();
    let from = earlier(&tmp);
    let chain_dir = dir(&tmp);
    let mut into = live(chain_dir.open_file(1, "1.0.1").unwrap());
    into.hold(1, "1.0.1.0.9", None, 0, json!({"op": "insert", "v": 9}), None, Reason::of("unreachable", false)).unwrap();
    let mut next_k = 2;
    let joined = into.join(&from, Joining::EarlierRun { next_k: &mut next_k });
    assert_eq!((joined.entered, next_k), (vec![(3, 2), (5, 3)], 4));
    let read: Vec<(u64, u64)> = live(chain_dir.open_file(1, "1.0.1").unwrap()).lines().iter().map(|l| (l.k, l.frame["v"].as_u64().unwrap_or(0))).collect();
    assert_eq!(read, [(1, 9), (2, 3), (3, 5)], "behind the standing line, on disk");

    // Into a file that holds no line but names every ordinal done, the
    // removal refused by a sealed directory: under the counter, past them.
    let tmp = TempDir::new().unwrap();
    let from = earlier(&tmp);
    let chain_dir = dir(&tmp);
    let board_dir = tmp.path().join("held").join(chain().to_string());
    let mut into = live(chain_dir.open_file(1, "1.0.1").unwrap());
    for _ in 0..3 {
        into.hold_next("1.0.1.0.2", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap();
    }
    into.done(1, Done::Dropped).unwrap();
    into.done(2, Done::Dropped).unwrap();
    fs::set_permissions(&board_dir, fs::Permissions::from_mode(0o500)).unwrap();
    let settled = into.done(3, Done::Dropped).unwrap();
    fs::set_permissions(&board_dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(settled.unremoved.is_some() && into.lines().is_empty(), "the file stands, every line done");
    let mut next_k = into.greatest_k() + 1;
    let joined = into.join(&from, Joining::EarlierRun { next_k: &mut next_k });
    assert_eq!((joined.entered, next_k), (vec![(3, 4), (5, 5)], 6), "past every ordinal the file names");
    assert_eq!(ks(&live(chain_dir.open_file(1, "1.0.1").unwrap())), [4, 5]);
}

/// Checks that a file holding lower ordinals after higher ones reopens to
/// the same queue, the re-mark budget and the raise keyed by ordinal (skep
/// #856; the record's §8 item 11).
///
/// The board's file holds lines 5 and 6 on one document and 7 on another;
/// this run's memory lines 1 and 2, on the first document, join it — the
/// ordered insert, their copy after every line the file held — then 1 and 5
/// are re-marked, 1 is kept at a position and 5 at a later one, each `done`
/// written after the higher ordinals' lines. In the queue, 1's `done`
/// raised 2, 5 and 6 — the lines of HIGHER ordinals on its document, 5 and
/// 6 among them though written before it — and 7 not, another document's;
/// 5's then raised 6 alone. A reopen reads the same lines, each with its
/// base and its last reason, and counts the two re-marks against the budget
/// as the writer did, neither first copy as a re-mark (the mutant reader
/// that keys a re-mark or a raise by file position raises the lines written
/// after the `done` in place of the ordinals after it, or counts a joined
/// line's first copy as a re-mark).
#[test]
fn a_file_holding_lower_ordinals_after_higher_ones_reopens_to_the_same_queue() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    for (k, doc) in [(5, "1.0.1.0.1"), (6, "1.0.1.0.1"), (7, "1.0.1.0.2")] {
        queue.hold(k, doc, None, 0, json!({"op": "insert", "k": k}), None, Reason::of("unreachable", false)).unwrap();
    }
    let mut ours = HeldQueue::unopened(&d, 1, "1.0.1");
    for k in [1, 2] {
        ours.hold(k, "1.0.1.0.1", None, 0, json!({"op": "insert", "k": k}), None, Reason::of("unreachable", false)).unwrap();
    }
    assert_eq!(queue.join(&ours, Joining::ThisRun).entered, [(1, 1), (2, 2)]);
    assert_eq!(ks(&queue), [1, 2, 5, 6, 7], "the ordered insert");
    let spent = |queue: &HeldQueue| queue.disk.remark_bytes;
    queue.remark(1, Reason::of("poisoned", false)).unwrap();
    queue.remark(5, Reason::of("durability", false)).unwrap();
    assert!(spent(&queue) > 0, "the two re-marks spend the budget");
    queue.done(1, Done::Kept { at: Some(50) }).unwrap();
    let bases = |queue: &HeldQueue| queue.lines().iter().map(|l| (l.k, l.base)).collect::<Vec<_>>();
    assert_eq!(bases(&queue), [(2, 50), (5, 50), (6, 50), (7, 0)], "1's `done` raises the higher ordinals on its document, 5 and 6 among them");
    queue.done(5, Done::Kept { at: Some(70) }).unwrap();
    assert_eq!(bases(&queue), [(2, 50), (6, 70), (7, 0)], "5's `done` raises 6 alone");
    let reopened = live(d.open_file(1, "1.0.1").unwrap());
    assert_eq!(reopened.lines(), queue.lines(), "a reopen reads the same queue");
    assert_eq!((spent(&reopened), reopened.greatest_k()), (spent(&queue), 7), "and counts the re-marks as the writer did");
}

/// Checks that a join cut before the pending file's removal joins again
/// without doubling a line.
///
/// Two pending lines of an earlier run join a fresh board's file under fresh
/// ordinals; the crash comes before the pending file is removed, so both
/// files stand. The next launch reads both and joins again: each line a
/// standing line already carries — by `doc`, `id` and frame, never by
/// ordinal, since that run's ordinals were its own — is not entered again,
/// the file grows by no line, the counter stands, and the pending file is
/// then removed. A crash after one of two writes leaves one line to enter,
/// under the next fresh ordinal the counter gives it (the mutant that enters
/// every pending line again resends the person's text twice; the one that
/// matches an earlier run's line by ordinal doubles a line whose ordinal
/// moved; the one that moves the counter for a line passed over skips
/// ordinals).
#[test]
fn a_join_cut_before_the_pending_files_removal_joins_again_without_doubling_a_line() {
    let tmp = TempDir::new().unwrap();
    let (pending, chain_dir) = (pending_dir(&tmp), dir(&tmp));
    let mut from = live(pending.open_file(1, "1.0.1").unwrap());
    from.hold_next("1.0.1.0.1", Some("a"), 0, json!({"op": "insert", "v": 1}), None, Reason::of("head_unreadable", false)).unwrap();
    from.hold_next("1.0.1.0.1", Some("b"), 0, json!({"op": "insert", "v": 2}), None, Reason::of("behind", false)).unwrap();
    let mut chain = live(chain_dir.open_file(1, "1.0.1").unwrap());
    let mut next_k = 4;
    assert_eq!((chain.join(&from, Joining::EarlierRun { next_k: &mut next_k }).entered, next_k), (vec![(1, 4), (2, 5)], 6));
    // The crash: the pending file is not removed. The next launch reads both.
    let bytes = file_len(&tmp);
    let mut chain = live(chain_dir.open_file(1, "1.0.1").unwrap());
    let from = live(pending.open_file(1, "1.0.1").unwrap());
    let again = chain.join(&from, Joining::EarlierRun { next_k: &mut next_k });
    assert_eq!((again.entered.len(), again.repeated, next_k), (0, 2, 6), "nothing entered again, the counter standing");
    assert_eq!((ks(&chain), file_len(&tmp)), (vec![4, 5], bytes), "the queue and the file as they were");
    chain.supersede(from.path().to_path_buf(), from.standing_on_disk(), Vec::new());
    assert!(!pending_path(&tmp).exists(), "the pending file removed, nothing owed");

    // A crash after one of two writes: the second alone enters, under the
    // next fresh ordinal.
    let tmp = TempDir::new().unwrap();
    let (pending, chain_dir) = (pending_dir(&tmp), dir(&tmp));
    let mut from = live(pending.open_file(1, "1.0.1").unwrap());
    from.hold_next("1.0.1.0.1", Some("a"), 0, json!({"op": "insert", "v": 1}), None, Reason::of("head_unreadable", false)).unwrap();
    from.hold_next("1.0.1.0.2", Some("b"), 0, json!({"op": "insert", "v": 2}), None, Reason::of("behind", false)).unwrap();
    let mut chain = live(chain_dir.open_file(1, "1.0.1").unwrap());
    chain.hold(4, "1.0.1.0.1", Some("a"), 0, json!({"op": "insert", "v": 1}), None, Reason::of("head_unreadable", false)).unwrap();
    let mut next_k = 5;
    let joined = chain.join(&from, Joining::EarlierRun { next_k: &mut next_k });
    assert_eq!((joined.entered, joined.repeated, next_k), (vec![(2, 5)], 1, 6), "the line already there is passed over, the other entered under the next fresh ordinal");
    assert_eq!(ks(&live(chain_dir.open_file(1, "1.0.1").unwrap())), [4, 5]);
}

/// Checks that a join the device refuses enters its lines owed and keeps the
/// pending file until they land.
///
/// The device refuses the one copy into the board's file in three states:
/// no file, so its header is refused and none is made; a file holding no
/// line, its header alone; and a file holding a line, byte for byte as it
/// stood. Each time both lines enter under fresh ordinals, the counter past
/// them, each owed its copy and waiting under the refusal at the first; the
/// board's file holds what it held, so a reopen of it reads what stood
/// before, and the pending file — superseded, as the hold names it — stands
/// with both lines, since a copy is owed. Once the device takes copies, the
/// retry writes both and removes the pending file (the mutant that removes
/// the pending file before the copy lands loses the lines whose copy was
/// refused; the one that holds the lines back keeps them off the queue the
/// page reads).
#[test]
fn a_join_the_device_refuses_enters_its_lines_owed_and_keeps_the_pending_file_until_they_land() {
    let header = header_bytes(&Named::Chain(chain()), 1, "1.0.1");
    for (state, holding) in [("no file", false), ("a file holding no line", false), ("a file holding a line", true)] {
        let tmp = TempDir::new().unwrap();
        let (pending, chain_dir) = (pending_dir(&tmp), dir(&tmp));
        let mut from = live(pending.open_file(1, "1.0.1").unwrap());
        from.hold_next("1.0.1.0.1", None, 0, json!({"op": "insert", "v": 1}), None, Reason::of("head_unreadable", false)).unwrap();
        from.hold_next("1.0.1.0.2", None, 0, json!({"op": "insert", "v": 2}), None, Reason::of("behind", false)).unwrap();
        if state == "a file holding no line" {
            fs::write(file_path(&tmp), &header).unwrap();
        }
        let mut chain = live(chain_dir.open_file(1, "1.0.1").unwrap());
        if holding {
            chain.hold_next("1.0.1.0.9", None, 0, json!({"op": "insert"}), None, Reason::of("unreachable", false)).unwrap();
        }
        let before = fs::read(file_path(&tmp)).ok();
        let mut next_k = 7;
        FAIL_SYNC.with(|f| f.set(true));
        let joined = chain.join(&from, Joining::EarlierRun { next_k: &mut next_k });
        chain.supersede(from.path().to_path_buf(), joined.entered.iter().map(|&(_, k)| k).collect(), Vec::new());
        FAIL_SYNC.with(|f| f.set(false));
        assert_eq!((joined.entered, next_k), (vec![(1, 7), (2, 8)], 9), "{state}: both enter under fresh ordinals, the counter past them");
        assert_eq!(chain.waiting().map(|w| (w.first(), w.owed(), w.error.kind())), Some((7, Owed::Line, std::io::ErrorKind::StorageFull)), "{state}: both wait under the refusal");
        assert!(chain.parked(7) && chain.parked(8) && !chain.parked(1), "{state}: the lines on the pending file are parked while their copies are owed, the file's own not");
        assert_eq!(ks(&chain), if holding { vec![1, 7, 8] } else { vec![7, 8] }, "{state}: both standing in the queue");
        assert_eq!(fs::read(file_path(&tmp)).ok(), before, "{state}: the board's file as it stood");
        assert_eq!(ks(&live(pending.open_file(1, "1.0.1").unwrap())), [1, 2], "{state}: the pending file stands with both lines while a copy is owed");
        assert_eq!(live(chain_dir.open_file(1, "1.0.1").unwrap()).lines().len(), usize::from(holding), "{state}: the board's file reads what stood");
        chain.retry();
        assert!(chain.waiting().is_none() && chain.superseded().is_none(), "{state}: both written, the pending file removed");
        assert!(!chain.parked(7) && !chain.parked(8), "{state}: nothing parked once the copies landed");
        assert!(!pending_path(&tmp).exists(), "{state}: the pending file is gone");
        assert_eq!(ks(&live(chain_dir.open_file(1, "1.0.1").unwrap())), if holding { vec![1, 7, 8] } else { vec![7, 8] }, "{state}: a reopen reads every line");
    }
}

/// Checks that a join cut before its sync joins again at the next launch
/// and doubles no line.
///
/// A pending file holds four lines, the middle two equal — the same
/// document, no `id`, one frame. The crash comes as their join's one copy is
/// written: the board's file holds its header, the copy's first two lines
/// whole and the third torn, and the pending file stands. The next launch
/// reads both and joins again: the two lines the board's file holds are
/// passed over, each answering for one pending line, and the other two
/// enter, the torn tail cut first; a reopen reads the four lines in `k`
/// order, the equal two among them, and halts on nothing (the mutant that
/// counts a line entering against the lines after it drops the second equal
/// line; the one that enters every pending line again doubles the first
/// two).
#[test]
fn a_join_cut_before_its_sync_joins_again_and_doubles_no_line() {
    let tmp = TempDir::new().unwrap();
    let (pending, chain_dir) = (pending_dir(&tmp), dir(&tmp));
    let mut from = live(pending.open_file(1, "1.0.1").unwrap());
    let equal = json!({"op": "delete", "doc": "1.0.1.0.1", "as_of": 4});
    for frame in [json!({"op": "insert", "v": 1}), equal.clone(), equal.clone(), json!({"op": "insert", "v": 4})] {
        from.hold_next("1.0.1.0.1", None, 0, frame, None, Reason::of("head_unreadable", false)).unwrap();
    }
    // The crash: the copy's first two lines whole, its third torn.
    let lines = from.lines();
    let third = held_line_bytes(&lines[2], lines[2].base);
    let mut crashed = header_bytes(&Named::Chain(chain()), 1, "1.0.1");
    crashed.extend(held_line_bytes(&lines[0], lines[0].base));
    crashed.extend(held_line_bytes(&lines[1], lines[1].base));
    crashed.extend_from_slice(&third[..third.len() / 2]);
    fs::write(file_path(&tmp), &crashed).unwrap();
    let mut chain = live(chain_dir.open_file(1, "1.0.1").unwrap());
    let from = live(pending.open_file(1, "1.0.1").unwrap());
    assert_eq!((ks(&chain), chain.torn().is_some()), (vec![1, 2], true), "premise: the board's file holds two lines and a torn third");
    let mut next_k = chain.greatest_k() + 1;
    let joined = chain.join(&from, Joining::EarlierRun { next_k: &mut next_k });
    assert_eq!((joined.entered, joined.repeated), (vec![(3, 3), (4, 4)], 2), "the two lines on disk passed over, the other two entering");
    let reopened = live(chain_dir.open_file(1, "1.0.1").unwrap());
    let read: Vec<(u64, Value)> = reopened.lines().iter().map(|l| (l.k, l.frame.clone())).collect();
    let want: Vec<(u64, Value)> = from.lines().iter().map(|l| (l.k, l.frame.clone())).collect();
    assert_eq!((read, reopened.torn()), (want, None), "the four lines once each, in `k` order, the torn tail cut");
}

// ── THE BUDGETS, TIMED (§3c.3) ──────────────────────────────────────────────

/// The most a timed cost may grow from a quarter of the lines to all of them.
///
/// It is the growth bound of skep #816: twice the four a cost in proportion to
/// the lines grows by, and half the sixteen a cost growing as their square
/// does: the timing cells hold the reopen, the walk and the drop to it
/// ([`assert_linear`]), so a cost grown by another power of the lines fails
/// them whatever the machine's speed.
pub(crate) const LINEAR_GROWTH: u32 = 8;

/// Returns the build's profile, as a timing cell's figure names it.
pub(crate) fn profile() -> &'static str {
    if cfg!(debug_assertions) {
        "unoptimized"
    } else {
        "optimized"
    }
}

/// Asserts that `what` takes time in proportion to its lines (skep #816).
///
/// `run` times its act over the lines it is given, each line's frame the
/// least the act lets it be, so the time is each line's work and not its
/// bytes, which the byte budget bounds apart. The least of three runs at a
/// quarter of [`MAX_HELD_LINES`], and of three at all of it — the runs
/// alternating, so a stretch of load beside the gate's run meets both counts
/// alike — are printed with the build's profile, and the second is held
/// within [`LINEAR_GROWTH`] times the first.
pub(crate) fn assert_linear(what: &str, mut run: impl FnMut(usize) -> Duration) {
    let (mut quarter, mut budget) = (Duration::MAX, Duration::MAX);
    for _ in 0..3 {
        quarter = quarter.min(run(MAX_HELD_LINES / 4));
        budget = budget.min(run(MAX_HELD_LINES));
    }
    eprintln!("{what}, each line's frame its least: {budget:?} at {MAX_HELD_LINES} lines, {quarter:?} at a quarter of them ({})", profile());
    assert!(budget < quarter * LINEAR_GROWTH, "{what}: {budget:?} at {MAX_HELD_LINES} lines, past {LINEAR_GROWTH} times the {quarter:?} at a quarter of them");
}

/// Asserts that `what` took `took` at both budgets, within the ceiling.
///
/// The ceiling is [`TIMED_CEILING`]. The figure is printed first, with the
/// build's profile: the one [`MAX_HELD_LINES`] states.
pub(crate) fn assert_within_the_ceiling(what: &str, took: Duration) {
    eprintln!("{what}, at both budgets: {took:?} ({})", profile());
    assert!(took < TIMED_CEILING, "{what}: {took:?} at both budgets, past {TIMED_CEILING:?}");
}

/// Returns a drained file of `n` lines, as a drain of a full queue writes it.
///
/// Each line, on one document, carries `frame`. Every line is held, then line
/// by line marked `sent`, its base the one the line kept before it raised it
/// to, and kept at a position by a `done` — line `k` at `100 + k` — the last
/// refused instead, so the file stands, each `done` raising every line standing
/// after it.
fn drained_file(n: u64, frame: &Value) -> Vec<u8> {
    let edges = anchors(Some("1.0.1.0.1.0.1.4"), Some("1.0.1.0.1.0.1.5"));
    let line = |k: u64, base: u64, reason: Reason| {
        let line = HeldLine { k, doc: "1.0.1.0.1".into(), id: None, dial_id: None, base, frame: frame.clone(), anchors: Some(edges.clone()), reason, time: now_ms() };
        held_line_bytes(&line, base)
    };
    // The position line `k` is kept at, and the base it raises the lines after
    // it to.
    let kept_at = |k: u64| 100 + k;
    let mut body = header_bytes(&Named::Chain(chain()), 1, "1.0.1");
    for k in 1..=n {
        body.extend(line(k, 0, Reason::of("unreachable", false)));
    }
    for k in 1..n {
        let base = if k == 1 { 0 } else { kept_at(k - 1) };
        body.extend(line(k, base, Reason::of("unreachable", true)));
        body.extend(done_line_bytes(k, Done::Kept { at: Some(kept_at(k)) }, None));
    }
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent"});
    body.extend(line(n, kept_at(n - 1), Reason::of("unreachable", true)));
    body.extend(line(n, kept_at(n - 1), Reason { sent: true, ..Reason::refused("out_of_bounds", verdict) }));
    body
}

/// Returns a store holding a drained file of `n` lines carrying `frame`.
///
/// The file is [`drained_file`]'s.
fn drained_store(n: u64, frame: &Value) -> TempDir {
    let tmp = TempDir::new().unwrap();
    dir(&tmp);
    fs::write(file_path(&tmp), drained_file(n, frame)).unwrap();
    tmp
}

/// Returns the time a reopen of `store`'s drained file of `n` lines takes.
///
/// The one line standing is read, raised by the last line kept before it.
fn reopened_in(store: &TempDir, n: u64) -> Duration {
    let d = dir(store);
    let started = Instant::now();
    let reopened = live(d.open_file(1, "1.0.1").unwrap());
    let took = started.elapsed();
    let standing: Vec<(u64, u64, String)> = reopened.lines().iter().map(|l| (l.k, l.base, l.reason.cause.clone())).collect();
    assert_eq!(standing, [(n, 100 + n - 1, "out_of_bounds".to_string())], "the one line standing, raised by the last line kept before it");
    took
}

/// Checks that a drained file at both budgets reopens within the ceiling.
///
/// It reopens in time in proportion to its lines (skep #816). It is a
/// launch's read of a drained file ([`drained_file`]): at a quarter
/// of [`MAX_HELD_LINES`] and at all of it, each line's frame the least an
/// insert spells, held to [`LINEAR_GROWTH`] ([`assert_linear`]); and the
/// worst file the budgets admit, at the line budget each line's frame and
/// anchors their share of [`MAX_HELD_BYTES`], read within [`TIMED_CEILING`]
/// ([`assert_within_the_ceiling`]) (the mutant reader whose `done` raises the
/// lines standing after it one by one grows as the square of the lines).
#[test]
#[ignore = "timing test - gate-full only"]
fn a_drained_file_at_both_budgets_reopens_within_the_ceiling() {
    let least = json!({"op": "insert"});
    let stores: Vec<(usize, TempDir)> = [MAX_HELD_LINES / 4, MAX_HELD_LINES].into_iter().map(|n| (n, drained_store(n as u64, &least))).collect();
    assert_linear("a drained held file's reopen", |n| reopened_in(&stores.iter().find(|(lines, _)| *lines == n).expect("a store of each count").1, n as u64));
    let edges = anchors(Some("1.0.1.0.1.0.1.4"), Some("1.0.1.0.1.0.1.5"));
    let n = MAX_HELD_LINES as u64;
    let full = drained_store(n, &sized_frame(MAX_HELD_BYTES / MAX_HELD_LINES - edges.bytes()));
    assert_within_the_ceiling("a drained held file's reopen", reopened_in(&full, n));
}

/// Checks that a file whose lines each name the one before reopens in time
/// in proportion to its lines (skep #816, #969).
///
/// Line `k` carries the `id` `b-k` and a piece naming the first unit of line
/// `k - 1`'s words, and every line but the last is kept at an address, each
/// `done` placing the next line's piece: the reopen binds each piece as its
/// line is read and places it at the `done`, at a quarter of
/// [`MAX_HELD_LINES`] and at all of it, each line's frame its least, held to
/// [`LINEAR_GROWTH`] (the mutant reader that finds a piece's line by walking
/// the lines standing grows as the square of the lines).
#[test]
#[ignore = "timing test - gate-full only"]
fn a_file_whose_lines_each_name_the_one_before_reopens_in_time_in_proportion_to_its_lines() {
    let stores: Vec<(usize, TempDir)> = [MAX_HELD_LINES / 4, MAX_HELD_LINES]
        .into_iter()
        .map(|n| {
            let tmp = TempDir::new().unwrap();
            dir(&tmp);
            let mut body = header_bytes(&Named::Chain(chain()), 1, "1.0.1");
            for k in 1..=n as u64 {
                let anchors = (k > 1).then(|| Anchors::of(&json!({"before": {"burst": format!("b-{}", k - 1), "offset": 0}, "after": null})).expect("the anchors' form"));
                let line = HeldLine {
                    k,
                    doc: "1.0.1.0.1".into(),
                    id: Some(format!("b-{k}")),
                    dial_id: None,
                    base: 0,
                    frame: json!({"op": "insert"}),
                    anchors,
                    reason: Reason::of("unreachable", false),
                    time: 1,
                };
                body.extend(held_line_bytes(&line, 0));
            }
            for k in 1..n as u64 {
                body.extend(done_line_bytes(k, Done::Kept { at: Some(100 + k) }, Some(&format!("1.0.1.0.1.0.1.{}", 1000 + k))));
            }
            fs::write(file_path(&tmp), body).unwrap();
            (n, tmp)
        })
        .collect();
    assert_linear("a held file whose lines each name the one before, reopened", |n| {
        let store = &stores.iter().find(|(lines, _)| *lines == n).expect("a store of each count").1;
        let started = Instant::now();
        let reopened = live(dir(store).open_file(1, "1.0.1").unwrap());
        let took = started.elapsed();
        let last = reopened.lines().pop().expect("the last line stands");
        assert_eq!(
            (reopened.lines().len(), last.anchors.map(|anchors| anchors.json())),
            (1, Some(json!({"before": format!("1.0.1.0.1.0.1.{}", 1000 + n - 1), "after": null}))),
            "the last line's piece placed"
        );
        took
    });
}
