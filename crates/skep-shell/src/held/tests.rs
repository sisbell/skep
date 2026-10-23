//! THE STORE's FENCE (T1–T5): the header written once and read whole with
//! P38's faces (`v` first) — a header of every other form halting with its
//! own, and a header the device did not take whole leaving no file — the
//! torn last line ignored, and cut before the next line is written, and a
//! damaged middle line halting, the misplaced file moved aside and never
//! overwriting, the lock a second holder cannot take, compaction once every
//! line is done and the file recreated, header first, by the next line, a
//! reopened queue taking an ordinal past every one its file names, and
//! persist-first — the line on disk before the append returns, and a copy
//! the device cut short or whose sync it refused cut back off the file.
//! Every line form reads back as it was held, and the store is its owner's
//! alone. And the queue as the memory with the file its copy: a line the
//! device refused stands in the queue under its ordinal, a re-mark reads
//! back as the one line it re-marks, and a `done` the device refused still
//! settles its line, a reopen reading the line as held again. THE
//! STORE's BUDGETS: the queue's frames held to the board's frame cap and its
//! lines to the line budget — a reopened queue past it read whole, holding
//! nothing more until it drains — an unchanged re-mark writing nothing and
//! a board flapping between two causes growing the file no further than its
//! re-mark budget, the ordinals held to the page's, the writer refusing a
//! line its reader would halt on and copying none past the line bound, and
//! the reader halting on any line it cannot read whole — no UTF-8, a member
//! missing or of another type, an ordinal past the page's, a line past the
//! bound — while ignoring a torn last line cut mid-character.

use std::cell::{Cell, RefCell};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::json;
use tempfile::TempDir;

use super::*;

// ── THE COPY SEAMS (read by `write_synced` and `Disk::append`) ───────────────

/// The seam a suite installs to read the file after a sync.
type Seam = Box<dyn Fn(&Path)>;

thread_local! {
    static FAIL_SYNC: Cell<bool> = const { Cell::new(false) };
    static TORN_WRITE: Cell<Option<usize>> = const { Cell::new(None) };
    static AFTER_SYNC: RefCell<Option<Seam>> = const { RefCell::new(None) };
}

/// Whether the next `sync_data` is forced to fail (T5's `store_unwritable`,
/// which the `held` answer carries as `unwritable`).
pub(super) fn fail_sync() -> bool {
    FAIL_SYNC.with(Cell::get)
}

/// Returns the bytes the next copy writes before its write is refused.
///
/// It stands in for a device that cuts a write short, as a full disk does,
/// and fires once: the copy after it is written whole.
pub(super) fn torn_write() -> Option<usize> {
    TORN_WRITE.with(Cell::take)
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
    let held = queue.hold("1.0.7.0.1", None, 5, json!({"op": "insert"}), Reason::of("unreachable", false)).unwrap();
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
        let held = queue.hold("1.0.1.0.1", None, 0, json!({"op": "insert"}), Reason::of("unreachable", false)).unwrap();
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
    let k1 = queue.hold("1.0.1.0.1", None, 0, json!({"op": "insert"}), Reason::of("stopped", false)).unwrap().k;
    let k2 = queue.hold("1.0.1.0.2", None, 0, json!({"op": "delete"}), Reason::of("behind", false)).unwrap().k;
    let k3 = queue.hold("1.0.1.0.3", None, 0, json!({"op": "insert"}), Reason::of("behind", false)).unwrap().k;
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
/// ordinal after it and a reopen reading the lines the disk took (the
/// mutant that keeps the refused line out of the queue loses the burst its
/// `held` answer promised; the one that leaves its bytes on the file keeps
/// pages a refused sync may never write, behind every later line).
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
    let first = queue.hold("1.0.1.0.1", None, 0, json!({"op": "insert"}), Reason::of("stopped", false)).unwrap();
    assert!(first.unwritten.is_none(), "{:?}", first.unwritten);
    assert!(*seen.lock().unwrap(), "the line is on disk when the append's seam runs, before the answer");
    AFTER_SYNC.with(|s| *s.borrow_mut() = None);

    // The forced sync failure: the device's refusal beside a line that stands.
    FAIL_SYNC.with(|f| f.set(true));
    let refused = queue.hold("1.0.1.0.2", None, 0, json!({"op": "insert"}), Reason::of("stopped", false)).unwrap();
    FAIL_SYNC.with(|f| f.set(false));
    assert_eq!(refused.unwritten.expect("the device refused the copy").kind(), std::io::ErrorKind::StorageFull, "store_unwritable, answered `unwritable`");
    assert_eq!(refused.k, 2);
    assert_eq!(ks(&queue), [1, 2], "the refused line stands in the queue");
    assert!(!fs::read_to_string(file_path(&tmp)).unwrap().contains("\"doc\":\"1.0.1.0.2\""), "its bytes cut back off the file");
    let next = queue.hold("1.0.1.0.3", None, 0, json!({"op": "insert"}), Reason::of("behind", false)).unwrap();
    assert!(next.unwritten.is_none());
    assert_eq!((next.k, ks(&queue)), (3, vec![1, 2, 3]), "the next line takes the ordinal after it");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [1, 3], "a reopen reads the lines the disk took");
}

/// A QUEUE IN MEMORY ALONE (§3c.3) enters, re-marks and settles lines as a
/// file's does, under the same ordinals, and writes nothing.
#[test]
fn a_queue_in_memory_alone_keeps_its_lines_and_writes_nothing() {
    let mut queue = HeldQueue::in_memory();
    let k1 = queue.hold("1.0.1.0.1", None, 0, json!({"op": "insert"}), Reason::of("unreachable", true)).unwrap();
    let k2 = queue.hold("1.0.1.0.1", None, 0, json!({"op": "insert"}), Reason::of("behind", false)).unwrap();
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
    let k = queue.hold("1.0.1.0.1", None, 4, json!({"op": "insert"}), Reason::of("unreachable", true)).unwrap().k;
    queue.hold("1.0.1.0.2", None, 4, json!({"op": "insert"}), Reason::of("behind", false)).unwrap();
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
/// refusal is answered for the shell's own window to say; its bytes are cut
/// back off the file, so a reopen reads the line as held again and the
/// resend's read decides it (§3c.5), as `Settled::unwritten` says.
#[test]
fn a_done_the_device_refused_still_settles_its_line() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let k1 = queue.hold("1.0.1.0.1", None, 0, json!({"op": "insert"}), Reason::of("unreachable", false)).unwrap().k;
    let k2 = queue.hold("1.0.1.0.1", None, 0, json!({"op": "insert"}), Reason::of("behind", false)).unwrap().k;
    FAIL_SYNC.with(|f| f.set(true));
    let settled = queue.done(k1, Done::Kept { at: Some(9) }).unwrap();
    FAIL_SYNC.with(|f| f.set(false));
    assert!(settled.unwritten.is_some() && settled.unremoved.is_none(), "{settled:?}");
    assert_eq!(ks(&queue), [k2], "the settled line has left the queue");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [k1, k2], "a reopen reads the line as held again");
}

/// A HELD FILE THE COMPACTION CANNOT REMOVE is kept and appended on — the
/// removal's answer read, never assumed: every line done and the unlink
/// refused, the directory sealed against it, the settle answers the failure
/// naming the path, the file stands, the next hold APPENDS to it (no
/// `AlreadyExists`) under an ordinal past the file's, and a reopen reads
/// that line; the directory writable again, the next compaction removes it
/// and the ordinals start over (the mutant that marks the file gone refuses
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
    let k = queue.hold("1.0.1.0.1", None, 0, json!({"op": "insert"}), Reason::of("unreachable", false)).unwrap().k;
    fs::set_permissions(&board_dir, fs::Permissions::from_mode(0o500)).unwrap();
    let settled = queue.done(k, Done::Kept { at: Some(3) }).unwrap();
    assert!(settled.unwritten.is_none(), "{settled:?}");
    let (path, _) = settled.unremoved.expect("the removal's failure is answered");
    assert_eq!(path, file_path(&tmp));
    assert!(queue.on_disk() && queue.lines().is_empty(), "the file stands, every line done");
    let next = queue.hold("1.0.1.0.2", None, 0, json!({"op": "insert"}), Reason::of("behind", false)).unwrap();
    assert!(next.unwritten.is_none(), "the next hold appends to the standing file: {:?}", next.unwritten);
    assert_eq!(next.k, 2, "an ordinal past the file's");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [2], "a reopen reads the line");
    fs::set_permissions(&board_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let settled = queue.done(2, Done::Dropped).unwrap();
    assert!(settled.unremoved.is_none() && !queue.on_disk(), "writable again, the compaction removes the file");
    assert_eq!(queue.hold("1.0.1.0.3", None, 0, json!({"op": "insert"}), Reason::of("behind", false)).unwrap().k, 1, "the ordinals start over once the file is gone");
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
            let held = queue.hold("1.0.1.0.3", None, 0, json!({"op": "insert"}), Reason::of("behind", false)).unwrap();
            assert!(held.unwritten.is_none(), "{:?}", held.unwritten);
        }
        let want: &[u64] = if done { &[2] } else { &[1, 2, 3] };
        assert_eq!(ks(&live(dir(&tmp).open_file(1, "1.0.1").unwrap())), want, "done {done}: every line read, none glued");
    }
}

/// A COPY CUT SHORT leaves the file as it was: a line whose write the
/// device cut part-way, as a full disk does, answers `unwritable` and
/// stands in the queue, its bytes cut back off the file, so the next line
/// is written where the last whole one ends and a reopen reads every line
/// the disk took (the mutant that skips the cut-back leaves on the file the
/// bytes its `unwritable` answer says it does not hold).
#[test]
fn a_copy_cut_short_leaves_the_file_as_it_was() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    assert!(queue.hold("1.0.1.0.1", None, 0, json!({"op": "insert"}), Reason::of("unreachable", false)).unwrap().unwritten.is_none());
    let before = fs::read(file_path(&tmp)).unwrap();
    TORN_WRITE.with(|t| t.set(Some(20)));
    let cut = queue.hold("1.0.1.0.2", None, 0, json!({"op": "insert"}), Reason::of("unreachable", false)).unwrap();
    assert_eq!(cut.unwritten.map(|e| e.kind()), Some(std::io::ErrorKind::StorageFull), "the device cut the copy short");
    assert_eq!(fs::read(file_path(&tmp)).unwrap(), before, "its bytes cut back off the file");
    assert_eq!(ks(&queue), [1, 2], "and the line stands in the queue");
    assert!(queue.hold("1.0.1.0.3", None, 0, json!({"op": "insert"}), Reason::of("behind", false)).unwrap().unwritten.is_none());
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [1, 3], "a reopen reads every line the disk took");
}

/// A HEADER THE DEVICE DID NOT TAKE WHOLE leaves no file (`write_once`'s
/// idiom): a header write cut short, and a header sync refused, each answer
/// the line `unwritable`, the line standing in the queue and the file the
/// header began removed, so the next line makes the file again under
/// `create_new`, header first, and a reopen reads it (the mutant that leaves
/// the half-made file refuses every later copy `AlreadyExists`, and closed
/// with a line standing leaves a file the next open halts on).
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
        let first = queue.hold("1.0.1.0.1", None, 0, json!({"op": "insert"}), Reason::of("unreachable", false)).unwrap();
        FAIL_SYNC.with(|f| f.set(false));
        assert_eq!(first.unwritten.map(|e| e.kind()), Some(std::io::ErrorKind::StorageFull), "torn {torn}: the device refused the header");
        assert!(!queue.on_disk(), "torn {torn}: the half-made file is removed");
        assert_eq!(ks(&queue), [1], "torn {torn}: the line stands in the queue");
        let next = queue.hold("1.0.1.0.2", None, 0, json!({"op": "insert"}), Reason::of("behind", false)).unwrap();
        assert!(next.unwritten.is_none(), "torn {torn}: {:?}", next.unwritten);
        assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [2], "torn {torn}: a reopen reads the line the file took");
    }
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
    let k = queue.hold("1.0.1.0.1", None, 0, json!({"op": "insert"}), Reason::of("stopped", false)).unwrap().k;
    queue.done(k, Done::Dropped).unwrap();
    assert!(!queue.on_disk(), "the file compacted away");
    let again = queue.hold("1.0.1.0.2", None, 0, json!({"op": "insert"}), Reason::of("behind", false)).unwrap();
    assert!(again.unwritten.is_none(), "{:?}", again.unwritten);
    assert_eq!(again.k, 1, "the ordinals start again");
    let raw = fs::read_to_string(tmp.path().join("held").join(chain().to_string()).join("principal-1.held")).unwrap();
    let mut lines = raw.lines();
    assert_eq!(lines.next().unwrap(), format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{}\",\"principal\":1,\"account\":\"1.0.1\"}}", chain()));
    assert!(lines.next().unwrap().starts_with("{\"held\":1,\"doc\":\"1.0.1.0.2\","), "{raw}");
    assert_eq!(ks(&live(d.open_file(1, "1.0.1").unwrap())), [1], "a reopen reads the line");
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
        queue.hold(doc, None, 0, json!({"op": "insert"}), Reason::of("unreachable", false)).unwrap();
    }
    queue.done(2, Done::Dropped).unwrap();
    queue.done(3, Done::Kept { at: Some(9) }).unwrap();
    let mut reopened = live(d.open_file(1, "1.0.1").unwrap());
    assert_eq!(ks(&reopened), [1]);
    let next = reopened.hold("1.0.1.0.4", None, 0, json!({"op": "insert"}), Reason::of("behind", false)).unwrap();
    assert_eq!(next.k, 4, "past every ordinal the file names");
    let read: Vec<(u64, String)> = live(d.open_file(1, "1.0.1").unwrap()).lines().iter().map(|l| (l.k, l.doc.clone())).collect();
    assert_eq!(read, [(1, "1.0.1.0.1".to_string()), (4, "1.0.1.0.4".to_string())], "both lines read back");
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
            let held = queue.hold("1.0.1.0.1", id, 7, json!({"op": "insert", "values": ["é\"x"]}), reason.clone()).unwrap();
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
    assert!(queue.hold("1.0.1.0.1", None, 0, json!({"op": "insert"}), Reason::of("stopped", false)).unwrap().unwritten.is_none());
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

/// THE QUEUE's BUDGET: the standing frames held to [`MAX_HELD_FRAME_BYTES`]
/// — a frame that would pass it refused `Full`, naming the bytes held and
/// the frame's, and NOTHING of it written; one at the budget exactly held;
/// and room made by a `done` (the mutant that never counts, or never
/// uncounts, holds a page's frames without bound, or refuses for good).
#[test]
fn the_queue_holds_its_frames_within_its_budget_and_writes_nothing_past_it() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let first = queue.hold("1.0.1.0.1", None, 0, sized_frame(MAX_HELD_FRAME_BYTES - 100), Reason::of("stopped", false)).unwrap().k;
    let written = file_len(&tmp);
    let refused = queue.hold("1.0.1.0.1", None, 0, sized_frame(200), Reason::of("behind", false));
    assert_eq!(refused.unwrap_err(), Unheld::Full { held_bytes: MAX_HELD_FRAME_BYTES - 100, frame_bytes: 200, held_lines: 1 });
    assert_eq!((file_len(&tmp), ks(&queue)), (written, vec![first]), "nothing of the refused line is kept");
    assert!(queue.hold("1.0.1.0.1", None, 0, sized_frame(100), Reason::of("behind", false)).is_ok(), "a frame at the budget exactly");
    queue.done(first, Done::Kept { at: Some(3) }).unwrap();
    assert!(queue.hold("1.0.1.0.1", None, 0, sized_frame(200), Reason::of("behind", false)).is_ok(), "a done makes room");
}

/// THE QUEUE's LINE BUDGET: [`MAX_HELD_LINES`] lines of empty bursts held —
/// their bytes far under the frames' budget — and the next refused `Full`,
/// naming the lines it holds, the queue standing at the budget; a `done`
/// makes room for one more (the mutant that counts bytes alone holds a
/// quarter of a million such bursts, and the resend walks them past one
/// another for days).
#[test]
fn the_queue_holds_no_line_past_its_line_budget() {
    let mut queue = HeldQueue::in_memory();
    for _ in 0..MAX_HELD_LINES {
        assert!(queue.hold("1.0.1.0.1", None, 0, json!({"op": "delete"}), Reason::of("behind", false)).is_ok());
    }
    let refused = queue.hold("1.0.1.0.1", None, 0, json!({"op": "delete"}), Reason::of("behind", false));
    assert!(matches!(refused, Err(Unheld::Full { held_lines: MAX_HELD_LINES, .. })), "{refused:?}");
    assert_eq!(queue.lines().len(), MAX_HELD_LINES, "the queue stands at the budget");
    queue.done(1, Done::Dropped).unwrap();
    assert!(queue.hold("1.0.1.0.1", None, 0, json!({"op": "delete"}), Reason::of("behind", false)).is_ok(), "a done makes room");
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
    let refused = queue.hold("1.0.1.0.1", None, 0, json!({"op": "delete"}), Reason::of("behind", false));
    assert!(matches!(refused, Err(Unheld::Full { held_lines, .. }) if held_lines == MAX_HELD_LINES + 1), "{refused:?}");
    queue.done(1, Done::Dropped).unwrap();
    queue.done(2, Done::Dropped).unwrap();
    assert!(queue.hold("1.0.1.0.1", None, 0, json!({"op": "delete"}), Reason::of("behind", false)).is_ok(), "below the budget a hold is taken again");
}

/// The ordinals are held to the page's ([`MAX_ORDINAL`]): the last one
/// held, and the queue holding no line past it.
#[test]
fn the_queue_holds_no_ordinal_past_the_pages() {
    let mut queue = HeldQueue::in_memory();
    queue.next_k = MAX_ORDINAL;
    assert_eq!(queue.hold("1.0.1.0.1", None, 0, json!({"op": "insert"}), Reason::of("stopped", false)).unwrap().k, MAX_ORDINAL);
    assert!(matches!(queue.hold("1.0.1.0.1", None, 0, json!({"op": "insert"}), Reason::of("stopped", false)), Err(Unheld::Full { .. })));
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
        assert_eq!(queue.hold(doc, None, 0, frame, Reason::of("stopped", false)).unwrap_err(), Unheld::Unreadable, "{doc}");
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
    let k = queue.hold("1.0.1.0.1", None, 0, json!({"op": "insert"}), Reason::of("unreachable", true)).unwrap().k;
    let written = file_len(&tmp);
    for _ in 0..3 {
        queue.remark(k, Reason::of("unreachable", true)).unwrap();
    }
    assert_eq!(file_len(&tmp), written, "the same reason again writes nothing");
    queue.remark(k, Reason::of("durability", false)).unwrap();
    assert!(file_len(&tmp) > written, "a new reason is written");
}

/// THE RE-MARK BUDGET: a board flapping between two hold-class causes — the
/// line re-marked at every probe, each re-mark a whole line of a large frame
/// — grows the file by at most [`MAX_HELD_REMARK_BYTES`]: the re-marks past
/// it refused their copy, the queue taking each reason all the same; a
/// reopen reads one line under a reason the file copied and keeps the
/// budget spent, refusing the next copy; and a compaction gives the file
/// that replaces it a budget of its own (the mutant that copies every
/// re-mark fills the disk at a frame per probe for as long as the board
/// flaps; the one that counts afresh at each open fills it a budget per
/// relaunch).
#[test]
fn a_board_flapping_between_two_causes_grows_no_file_past_its_remark_budget() {
    let tmp = TempDir::new().unwrap();
    let d = dir(&tmp);
    let mut queue = live(d.open_file(1, "1.0.1").unwrap());
    let k = queue.hold("1.0.1.0.1", None, 0, sized_frame(MAX_HELD_REMARK_BYTES / 4), Reason::of("unreachable", false)).unwrap().k;
    let written = file_len(&tmp);
    let flaps = [Reason::of("poisoned", true), Reason::of("durability", false)];
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
    let k = queue.hold("1.0.1.0.1", None, 0, json!({"op": "insert"}), Reason::of("unreachable", false)).unwrap().k;
    let written = file_len(&tmp);
    queue.remark(k, Reason::of("durability", false)).unwrap();
    assert!(file_len(&tmp) > written, "the file that replaces it copies its re-marks afresh");
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

/// THE READER reads every line WHOLE or halts the file as damaged (P38): a
/// line that is no UTF-8 or no JSON object, a `held` line missing a member
/// or holding one of another type — a `doc` that is no document address, a
/// frame that is no object, a `sent` that is no boolean — an ordinal past
/// the page's (the largest a `u64` holds among them, whose successor no
/// longer panics), and a `done` line of another form; the same file with
/// the line whole reads live (the mutants that default a missing member,
/// read text lossily, or take any ordinal, rebuild the person's text out
/// of a file no writer of this format wrote).
#[test]
fn a_line_the_reader_cannot_read_whole_halts_the_file() {
    let valid = line_with("sent", Some(json!(false)));
    let tmp = TempDir::new().unwrap();
    assert_eq!(live(opened_over(&tmp, &valid)).lines().len(), 1, "the line whole reads live");
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
        ("no frame", line_with("frame", None)),
        ("a sent of no boolean", line_with("sent", Some(json!("no")))),
        ("no cause", line_with("cause", None)),
        ("no time", line_with("time", None)),
        ("an id of no string", line_with("id", Some(json!(7)))),
        ("an ordinal past the page's", line_with("held", Some(json!(MAX_ORDINAL + 1)))),
        ("the largest ordinal a u64 holds", line_with("held", Some(json!(u64::MAX)))),
        ("a done of another resolution", b"{\"done\":1,\"as\":\"lost\",\"time\":1}\n".to_vec()),
        ("a dropped done naming a position", b"{\"done\":1,\"as\":\"dropped\",\"at\":4,\"time\":1}\n".to_vec()),
        ("a done with no time", b"{\"done\":1,\"as\":\"kept\"}\n".to_vec()),
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
    let held = queue.hold("1.0.1.0.1", None, 0, json!({"op": "insert"}), Reason::refused("out_of_bounds", verdict)).unwrap();
    assert_eq!(held.unwritten.map(|e| e.kind()), Some(std::io::ErrorKind::InvalidInput), "the line is answered unwritten");
    assert_eq!(ks(&queue), [held.k], "and stands in the queue");
    assert!(!queue.on_disk(), "and is copied nowhere");
}
