//! THE STORE's FENCE (T1–T5): the header written once and read whole with
//! P38's faces (`v` first), the torn last line ignored and a damaged middle
//! line halting, the misplaced file moved aside and never overwriting, the
//! lock a second holder cannot take, compaction once every line is done and
//! the file recreated, header first, by the next line, and persist-first —
//! the line on disk before the append returns. Every line form reads back as
//! it was held, and the store is its owner's alone. And the queue as the
//! memory with the file its copy: a line the device refused stands in the
//! queue under its ordinal, a re-mark reads back as the one line it
//! re-marks, and a `done` the device refused still settles its line.

use std::cell::{Cell, RefCell};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::json;
use tempfile::TempDir;

use super::*;

// ── THE SYNC SEAMS (read by `Disk::append` under `#[cfg(test)]`) ─────────────

/// The seam a suite installs to read the file after a sync.
type Seam = Box<dyn Fn(&Path)>;

thread_local! {
    static FAIL_SYNC: Cell<bool> = const { Cell::new(false) };
    static AFTER_SYNC: RefCell<Option<Seam>> = const { RefCell::new(None) };
}

/// Whether the next `sync_data` is forced to fail (T5's `store_unwritable`).
pub(super) fn fail_sync() -> bool {
    FAIL_SYNC.with(Cell::get)
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

/// THE HEADER written once; a second open reads it; `v` is read FIRST — a
/// `v: 2` header with a valid body answers the NEWER face and reads no line; an
/// unknown header member refuses the file; a torn last line is ignored and the
/// lines before it read; a middle line that does not parse HALTS the file; the
/// members' order and spelling of a written line are byte-equal to §3c.2.
#[test]
fn the_header_is_written_once_v_read_first_and_the_forms_are_byte_equal() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(7, "1.0.7").unwrap());
    assert!(!queue.on_disk(), "no file until the first append");
    let held = queue.hold("1.0.7.0.1", None, 5, json!({"op": "insert"}), Reason::of("unreachable", false));
    assert!(held.unwritten.is_none(), "{:?}", held.unwritten);
    assert_eq!(held.k, 1);
    assert!(queue.on_disk(), "the first hold writes the header and the line");

    // The exact byte forms (§3c.2), the one line's `time` apart.
    let raw = fs::read_to_string(tmp.path().join("held").join(chain().to_string()).join("principal-7.held")).unwrap();
    let mut lines = raw.lines();
    assert_eq!(lines.next().unwrap(), format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{}\",\"principal\":7,\"account\":\"1.0.7\"}}", chain()));
    let held = lines.next().unwrap();
    assert!(held.starts_with("{\"held\":1,\"doc\":\"1.0.7.0.1\",\"base\":5,\"frame\":{\"op\":\"insert\"},\"cause\":\"unreachable\","), "{held}");
    assert!(held.contains(",\"sent\":false,\"time\":") && held.ends_with('}'), "{held}");

    // A second open reads the header and the standing line.
    let reopened = live(d.open_file(7, "1.0.7").unwrap());
    assert_eq!(reopened.lines().len(), 1);
    assert_eq!(reopened.lines()[0].doc, "1.0.7.0.1");

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
fn the_lock_is_held_for_the_shells_life() {
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
    let k1 = queue.hold("d1", None, 0, json!({"op": "insert"}), Reason::of("stopped", false)).k;
    let k2 = queue.hold("d2", None, 0, json!({"op": "delete"}), Reason::of("behind", false)).k;
    let k3 = queue.hold("d3", None, 0, json!({"op": "insert"}), Reason::of("behind", false)).k;
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
/// after; an append whose `sync_data` is made to fail answers
/// `store_unwritable` (the device's I/O error) BESIDE a line that stands in
/// the queue under its ordinal, the next line taking the ordinal after it
/// (the mutant that keeps the refused line out of the queue loses the burst
/// its `held` answer promised).
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
            let on_disk = fs::read_to_string(p).unwrap_or_default().contains("\"doc\":\"d1\"");
            *probe.lock().unwrap() = on_disk;
        }))
    });
    let first = queue.hold("d1", None, 0, json!({"op": "insert"}), Reason::of("stopped", false));
    assert!(first.unwritten.is_none(), "{:?}", first.unwritten);
    assert!(*seen.lock().unwrap(), "the line is on disk when the append's seam runs, before the answer");
    AFTER_SYNC.with(|s| *s.borrow_mut() = None);

    // The forced sync failure: the device's refusal beside a line that stands.
    FAIL_SYNC.with(|f| f.set(true));
    let refused = queue.hold("d2", None, 0, json!({"op": "insert"}), Reason::of("stopped", false));
    FAIL_SYNC.with(|f| f.set(false));
    assert_eq!(refused.unwritten.expect("the device refused the copy").kind(), std::io::ErrorKind::StorageFull, "store_unwritable");
    assert_eq!(refused.k, 2);
    assert_eq!(ks(&queue), [1, 2], "the refused line stands in the queue");
    let next = queue.hold("d3", None, 0, json!({"op": "insert"}), Reason::of("behind", false));
    assert!(next.unwritten.is_none());
    assert_eq!((next.k, ks(&queue)), (3, vec![1, 2, 3]), "the next line takes the ordinal after it");
}

/// A QUEUE IN MEMORY ALONE (§3c.3) enters, re-marks and settles lines as a
/// file's does, under the same ordinals, and writes nothing.
#[test]
fn a_queue_in_memory_alone_keeps_its_lines_and_writes_nothing() {
    let mut queue = HeldQueue::in_memory();
    let k1 = queue.hold("d1", None, 0, json!({"op": "insert"}), Reason::of("unreachable", true));
    let k2 = queue.hold("d1", None, 0, json!({"op": "insert"}), Reason::of("behind", false));
    assert!(k1.unwritten.is_none() && k2.unwritten.is_none());
    assert_eq!((k1.k, k2.k), (1, 2));
    queue.remark(1, Reason::refused("out_of_bounds", json!({"code": "out_of_bounds"}))).unwrap();
    assert_eq!(queue.lines()[0].reason, Reason::refused("out_of_bounds", json!({"code": "out_of_bounds"})));
    queue.done(1, Done::Dropped).unwrap();
    assert_eq!(ks(&queue), [2]);
    assert!(!queue.on_disk());
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
    let k = queue.hold("d1", None, 4, json!({"op": "insert"}), Reason::of("unreachable", true)).k;
    queue.hold("d2", None, 4, json!({"op": "insert"}), Reason::of("behind", false));
    queue.remark(k, Reason::of("moved", false)).unwrap();
    queue.remark(k, Reason::of("moved", false)).unwrap();
    let reopened = live(d.open_file(1, "1.0.1").unwrap());
    assert_eq!(ks(&reopened), [k, k + 1], "one line per ordinal, in `k` order");
    assert_eq!((reopened.lines()[0].reason.cause.as_str(), reopened.lines()[0].reason.sent), ("moved", false));
    assert_eq!(reopened.lines()[0].base, 4, "the re-mark keeps the line's own members");
}

/// A `done` THE DEVICE REFUSED still settles its line: the line leaves the
/// queue, so the resend that acked it never sends it again (the mutant that
/// keeps the line standing resends the acked burst at once), and the
/// refusal is answered for the shell's own window to say.
#[test]
fn a_done_the_device_refused_still_settles_its_line() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let k1 = queue.hold("d1", None, 0, json!({"op": "insert"}), Reason::of("unreachable", false)).k;
    let k2 = queue.hold("d1", None, 0, json!({"op": "insert"}), Reason::of("behind", false)).k;
    FAIL_SYNC.with(|f| f.set(true));
    let settled = queue.done(k1, Done::Kept { at: Some(9) });
    FAIL_SYNC.with(|f| f.set(false));
    assert!(matches!(settled, Err(DoneError::Unwritten(_))), "{settled:?}");
    assert_eq!(ks(&queue), [k2], "the settled line has left the queue");
}

/// AFTER COMPACTION the next line recreates the file, header first (§3c.3):
/// the queue emptied and its file removed, the next hold writes T1's header
/// once more and its line under ordinal 1 — on disk, so a reopen reads it
/// (the mutant that keeps the removed file marked created appends to a file
/// that is gone, and every burst held after the first resend is one a crash
/// would lose).
#[test]
fn after_compaction_the_next_line_recreates_the_file_header_first() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let k = queue.hold("d1", None, 0, json!({"op": "insert"}), Reason::of("stopped", false)).k;
    queue.done(k, Done::Dropped).unwrap();
    assert!(!queue.on_disk(), "the file compacted away");
    let again = queue.hold("d2", None, 0, json!({"op": "insert"}), Reason::of("behind", false));
    assert!(again.unwritten.is_none(), "{:?}", again.unwritten);
    assert_eq!(again.k, 1, "the ordinals start again");
    let raw = fs::read_to_string(tmp.path().join("held").join(chain().to_string()).join("principal-1.held")).unwrap();
    let mut lines = raw.lines();
    assert_eq!(lines.next().unwrap(), format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{}\",\"principal\":1,\"account\":\"1.0.1\"}}", chain()));
    assert!(lines.next().unwrap().starts_with("{\"held\":1,\"doc\":\"d2\","), "{raw}");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [1], "a reopen reads the line");
}

/// EVERY LINE FORM READS BACK AS IT WAS HELD (§3c.2), the law over its
/// members: a line with no `id`, a plain one, and the page's own `id`
/// holding a quote, a newline and a backslash — the page's string this file
/// keeps — each under a hold `sent: false`, one that MAY have landed, and a
/// REFUSED run's with the board's verdict beside it, over a frame of a
/// multi-byte value; reopened, the queue is the queue that was held (the
/// mutant reader that drops `refusal` reads a refused run back as holding,
/// and the resend then sends what awaits the person's act).
#[test]
fn every_line_form_reads_back_as_it_was_held() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent", "detail": "past \"the\" end"});
    let reasons = [Reason::of("unreachable", false), Reason::of("poisoned", true), Reason::refused("out_of_bounds", verdict)];
    for id in [None, Some("plain"), Some("a \"quote\", a\nnewline, a \\ backslash")] {
        for reason in &reasons {
            let held = queue.hold("1.0.1.0.1", id, 7, json!({"op": "insert", "values": ["é\"x"]}), reason.clone());
            assert!(held.unwritten.is_none(), "{:?}", held.unwritten);
        }
    }
    let reopened = live(d.open_file(1, "1.0.1").unwrap());
    assert_eq!(reopened.lines().len(), 9);
    assert_eq!(reopened.lines(), queue.lines(), "the reopened queue is the queue that was held");
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
    assert!(queue.hold("d1", None, 0, json!({"op": "insert"}), Reason::of("stopped", false)).unwritten.is_none());
    let held = tmp.path().join("held");
    let board = held.join(chain().to_string());
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let modes = [mode(&held), mode(&board), mode(&board.join("principal-1.held")), mode(&board.join("lock"))];
    assert_eq!(modes, [0o700, 0o700, 0o600, 0o600], "held/, held/<chain>/, the file, the lock");
}
