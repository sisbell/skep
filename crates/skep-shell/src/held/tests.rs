//! THE STORE's FENCE (T1–T5): the header written once and read whole with
//! P38's faces (`v` first), the torn last line ignored and a damaged middle
//! line halting, the misplaced file moved aside and never overwriting, the
//! lock a second holder cannot take, compaction once every line is done, and
//! persist-first — the line on disk before the append returns. And the queue
//! as the memory with the file its copy: a line the device refused stands in
//! the queue under its ordinal, a re-mark reads back as the one line it
//! re-marks, and a `done` the device refused still settles its line.

use std::cell::{Cell, RefCell};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::json;
use tempfile::TempDir;

use super::*;

// ── THE SYNC SEAMS (read by `HeldFile::append` under `#[cfg(test)]`) ─────────

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

fn live(opened: Opened) -> HeldFile {
    match opened {
        Opened::Live { file, .. } => file,
        Opened::Halted { why, .. } => panic!("expected a live file, halted {why:?}"),
    }
}

/// The ordinals standing in a queue, in order.
fn ks(file: &HeldFile) -> Vec<u64> {
    file.lines().iter().map(|l| l.k).collect()
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
    let mut file = live(d.open_file(7, "1.0.7").unwrap());
    assert!(!file.on_disk(), "no file until the first append");
    let held = file.hold("1.0.7.0.1", None, 5, json!({"op": "insert"}), Reason::of("unreachable", false));
    assert!(held.unwritten.is_none(), "{:?}", held.unwritten);
    assert_eq!(held.k, 1);
    assert!(file.on_disk(), "the first hold writes the header and the line");

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
        Opened::Live { file, aside } => {
            assert_eq!(aside.as_deref(), Some(aside1.as_path()), "the open names the aside");
            file
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
/// line still held it stands; a `done` for an ordinal with no `held` line is
/// refused by the writer.
#[test]
fn the_file_compacts_once_every_line_is_done() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut file = live(d.open_file(1, "1.0.1").unwrap());
    let k1 = file.hold("d1", None, 0, json!({"op": "insert"}), Reason::of("stopped", false)).k;
    let k2 = file.hold("d2", None, 0, json!({"op": "delete"}), Reason::of("behind", false)).k;
    assert!(matches!(file.done(99, true, None), Err(DoneError::NoSuchLine)), "a done for no line is refused");
    file.done(k1, true, Some(42)).unwrap();
    assert!(file.on_disk(), "one line still held keeps the file");
    assert_eq!(file.lines().len(), 1);
    file.done(k2, false, None).unwrap();
    assert!(!file.on_disk(), "the file is gone once every line is done");
    assert!(file.lines().is_empty());
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
    let mut file = live(d.open_file(1, "1.0.1").unwrap());

    // The successful append: the seam, run after the sync, finds the line.
    let seen = Arc::new(Mutex::new(false));
    let probe = Arc::clone(&seen);
    AFTER_SYNC.with(|s| {
        *s.borrow_mut() = Some(Box::new(move |p: &Path| {
            let on_disk = fs::read_to_string(p).unwrap_or_default().contains("\"doc\":\"d1\"");
            *probe.lock().unwrap() = on_disk;
        }))
    });
    let first = file.hold("d1", None, 0, json!({"op": "insert"}), Reason::of("stopped", false));
    assert!(first.unwritten.is_none(), "{:?}", first.unwritten);
    assert!(*seen.lock().unwrap(), "the line is on disk when the append's seam runs, before the answer");
    AFTER_SYNC.with(|s| *s.borrow_mut() = None);

    // The forced sync failure: the device's refusal beside a line that stands.
    FAIL_SYNC.with(|f| f.set(true));
    let refused = file.hold("d2", None, 0, json!({"op": "insert"}), Reason::of("stopped", false));
    FAIL_SYNC.with(|f| f.set(false));
    assert_eq!(refused.unwritten.expect("the device refused the copy").kind(), std::io::ErrorKind::StorageFull, "store_unwritable");
    assert_eq!(refused.k, 2);
    assert_eq!(ks(&file), [1, 2], "the refused line stands in the queue");
    let next = file.hold("d3", None, 0, json!({"op": "insert"}), Reason::of("behind", false));
    assert!(next.unwritten.is_none());
    assert_eq!((next.k, ks(&file)), (3, vec![1, 2, 3]), "the next line takes the ordinal after it");
}

/// A QUEUE IN MEMORY ALONE (§3c.3) enters, re-marks and settles lines as a
/// file's does, under the same ordinals, and writes nothing.
#[test]
fn a_queue_in_memory_alone_keeps_its_lines_and_writes_nothing() {
    let mut file = HeldFile::in_memory();
    let k1 = file.hold("d1", None, 0, json!({"op": "insert"}), Reason::of("unreachable", true));
    let k2 = file.hold("d1", None, 0, json!({"op": "insert"}), Reason::of("behind", false));
    assert!(k1.unwritten.is_none() && k2.unwritten.is_none());
    assert_eq!((k1.k, k2.k), (1, 2));
    file.remark(1, Reason::refused("out_of_bounds", json!({"code": "out_of_bounds"}))).unwrap();
    assert_eq!(file.lines()[0].reason, Reason::refused("out_of_bounds", json!({"code": "out_of_bounds"})));
    file.done(1, false, None).unwrap();
    assert_eq!(ks(&file), [2]);
    assert!(!file.on_disk());
}

/// A RE-MARK reads back as the line it re-marks: a line held, re-marked
/// `moved`, and the file opened again holds ONE line, of that ordinal and
/// the new cause (the mutant reader that takes every `held` line as a new
/// one lists the burst twice and re-projects the person's text twice).
#[test]
fn a_remarked_line_reads_back_once_with_its_new_cause() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut file = live(d.open_file(1, "1.0.1").unwrap());
    let k = file.hold("d1", None, 4, json!({"op": "insert"}), Reason::of("unreachable", true)).k;
    file.hold("d2", None, 4, json!({"op": "insert"}), Reason::of("behind", false));
    file.remark(k, Reason::of("moved", false)).unwrap();
    file.remark(k, Reason::of("moved", false)).unwrap();
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
    let mut file = live(d.open_file(1, "1.0.1").unwrap());
    let k1 = file.hold("d1", None, 0, json!({"op": "insert"}), Reason::of("unreachable", false)).k;
    let k2 = file.hold("d1", None, 0, json!({"op": "insert"}), Reason::of("behind", false)).k;
    FAIL_SYNC.with(|f| f.set(true));
    let settled = file.done(k1, true, Some(9));
    FAIL_SYNC.with(|f| f.set(false));
    assert!(matches!(settled, Err(DoneError::Unwritten(_))), "{settled:?}");
    assert_eq!(ks(&file), [k2], "the settled line has left the queue");
}
