use super::*;
use serde_json::json;

/// The log reads back what it appended, in order, and a torn tail is
/// cut off the file at open, the lines before it standing.
#[test]
fn a_log_reads_back_its_lines_and_cuts_a_torn_tail() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x.log");
    let (mut log, values, _) = Log::open(path.clone()).unwrap();
    assert!(values.is_empty(), "an absent log holds no line");
    log.append_synced(&json!({"n": 1})).unwrap();
    log.append_unsynced(&json!({"n": 2})).unwrap();
    drop(log);
    let whole = fs::read_to_string(&path).unwrap();
    assert_eq!(whole, "{\"n\":1}\n{\"n\":2}\n");
    fs::write(&path, format!("{whole}{{\"n\":3")).unwrap();
    let (_, values, _) = Log::open(path.clone()).unwrap();
    assert_eq!(values, vec![json!({"n": 1}), json!({"n": 2})]);
    assert_eq!(fs::read_to_string(&path).unwrap(), whole, "the torn tail is cut");
}

/// TRUST ENDS AT THE FIRST TORN LINE, WHATEVER TORE IT, AND IS NEVER READ
/// PAST: for each way a line between two whole ones can be torn — no JSON,
/// JSON that is no object, an empty line, two objects run together — open
/// answers the lines before it alone and cuts the file there, the whole
/// line after it with it.
#[test]
fn trust_ends_at_the_first_torn_line_whatever_tore_it() {
    for torn in ["{\"n\":2\n", "[2]\n", "2\n", "\"two\"\n", "null\n", "\n", "{\"n\":2}{\"n\":3}\n"] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("x.log");
        fs::write(&path, format!("{{\"n\":1}}\n{torn}{{\"n\":4}}\n")).unwrap();
        let (_, values, _) = Log::open(path.clone()).unwrap();
        assert_eq!(values, vec![json!({"n": 1})], "{torn:?}: the lines before it alone");
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"n\":1}\n", "{torn:?}: cut there, the line after it too");
    }
}

/// A WHOLE OBJECT WITHOUT ITS NEWLINE IS A TORN TAIL, NOT A LINE (`Log::open`:
/// trust ends "at the first line that is no JSON object or that lacks its
/// newline"): a crash that kept every byte of the last line but its newline
/// leaves a tail that parses — read as a line, the next append would land on
/// it, the two run together, and the next open would cut them both, the
/// appended line answered as durable among them. Open cuts it instead, and
/// the next append lands on a whole line and reads back.
#[test]
fn a_whole_object_without_its_newline_is_a_torn_tail() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x.log");
    fs::write(&path, "{\"n\":1}\n{\"n\":2}").unwrap();
    let (mut log, values, _) = Log::open(path.clone()).unwrap();
    assert_eq!(values, vec![json!({"n": 1})], "the unterminated object is no line");
    assert_eq!(fs::read_to_string(&path).unwrap(), "{\"n\":1}\n", "and is cut off the file");
    log.append_synced(&json!({"n": 3})).unwrap();
    drop(log);
    assert_eq!(Log::open(path).unwrap().1, vec![json!({"n": 1}), json!({"n": 3})], "the next append stands");
}

/// EACH READING ANSWERS WHAT IT FOUND (`LogRead`, `TailCut`): an absent log
/// found absent — the inspection making nothing, the open making it empty;
/// a whole one trusted to its end, no cut; a half-written tail — a crash's,
/// its newline never written — cut with no whole line past it; and a
/// damaged line mid-file cut with the two whole lines after it, which no
/// crash takes — the inspection's reading answering exactly what the open
/// then finds and cuts.
#[test]
fn each_reading_answers_where_trust_ended_and_the_whole_lines_the_cut_took() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x.log");
    let name = label(&path, 2);
    let (_, found) = Log::read_as_found(&path).unwrap();
    assert_eq!((found.absent, found.lines, found.cut), (true, 0, None), "absent");
    assert!(!path.exists(), "and the inspection makes nothing");
    let (_, _, found) = Log::open(path.clone()).unwrap();
    assert_eq!(
        (found.name.as_str(), found.absent, found.lines, found.cut),
        (name.as_str(), true, 0, None),
        "absent: the open makes it empty, the log named by its place"
    );
    for (bytes, lines, cut) in [
        ("{\"n\":1}\n{\"n\":2}\n", 2, None),
        ("{\"n\":1}\n{\"n\"", 1, Some((8, 12, 0))),
        ("{\"n\":1}\ngarbage\n{\"n\":3}\n{\"n\":4}\n", 1, Some((8, 32, 2))),
    ] {
        fs::write(&path, bytes).unwrap();
        let (_, as_found) = Log::read_as_found(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), bytes, "{bytes:?}: the inspection cuts nothing");
        let (_, _, opened) = Log::open(path.clone()).unwrap();
        assert_eq!(as_found, opened, "{bytes:?}: the inspection answers what the open finds");
        assert_eq!((opened.absent, opened.lines, opened.unread), (false, lines, 0), "{bytes:?}");
        assert_eq!(opened.cut.map(|c| (c.at, c.len, c.lines_after)), cut, "{bytes:?}");
        let kept = cut.map_or(bytes.len() as u64, |(at, _, _)| at);
        assert_eq!(fs::metadata(&path).unwrap().len(), kept, "{bytes:?}: the open cut there");
    }
}

/// AN APPEND THAT FAILS is cut back off the file: a write cut short —
/// part of the line on disk, then an error, as a full disk gives —
/// leaves the file at its whole lines, the next append lands on a whole
/// line, and the reopen reads every whole line, the one after the
/// failure included. The failure is answered named — the log by its place,
/// the act, the cause.
#[test]
fn a_failed_append_is_cut_back_off_the_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x.log");
    let (mut log, _, _) = Log::open(path.clone()).unwrap();
    log.append_synced(&json!({"n": 1})).unwrap();
    let cut_short = log.append_by(&json!({"n": 2}), |file, line| {
        file.write_all(&line[..4])?;
        Err(io::Error::other("no space left on the device"))
    });
    let failed = cut_short.expect_err("the write cut short");
    assert_eq!(failed.to_string(), format!("{}: append: no space left on the device", label(&path, 2)));
    assert_eq!(fs::read_to_string(&path).unwrap(), "{\"n\":1}\n", "the torn line is cut back off the file");
    log.append_synced(&json!({"n": 3})).unwrap();
    drop(log);
    let (_, values, _) = Log::open(path.clone()).unwrap();
    assert_eq!(values, vec![json!({"n": 1}), json!({"n": 3})], "the line after the failure stands");
}

/// A FAILED APPEND LEAVES THE FILE AS IT FOUND IT, WHATEVER OPENED OR
/// REWROTE IT: the length it is cut back to is the file's whole lines —
/// read at open, over a torn tail cut there too, and reset by a
/// compaction that rewrote the file shorter — so a write cut short by a
/// full disk never cuts a whole line away, nor leaves behind bytes the
/// next open would cut a later whole line with.
#[test]
fn a_failed_append_leaves_the_file_as_it_found_it_whatever_opened_or_rewrote_it() {
    for state in ["fresh", "reopened", "reopened over a torn tail", "compacted shorter"] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("x.log");
        match state {
            "reopened" => fs::write(&path, "{\"n\":1}\n{\"n\":2}\n").unwrap(),
            "reopened over a torn tail" => fs::write(&path, "{\"n\":1}\n{\"n\":2}\n{\"n\"").unwrap(),
            _ => {}
        }
        let (mut log, _, _) = Log::open(path.clone()).unwrap();
        match state {
            "fresh" => log.append_synced(&json!({"n": 1})).unwrap(),
            "compacted shorter" => {
                for n in 1..=3 {
                    log.append_synced(&json!({"n": n})).unwrap();
                }
                log.compact(vec![json!({"n": 3})].into_iter()).unwrap();
            }
            _ => {}
        }
        let before = fs::read(&path).unwrap();
        let failed = log.append_by(&json!({"n": 9}), |file, line| {
            file.write_all(&line[..4])?;
            Err(io::Error::other("no space left on the device"))
        });
        assert!(failed.is_err(), "{state}");
        assert_eq!(fs::read(&path).unwrap(), before, "{state}: cut back to exactly the whole lines it held");
        log.append_synced(&json!({"n": 10})).unwrap();
        drop(log);
        let want: Vec<Value> = match state {
            "fresh" => vec![json!({"n": 1}), json!({"n": 10})],
            "compacted shorter" => vec![json!({"n": 3}), json!({"n": 10})],
            _ => vec![json!({"n": 1}), json!({"n": 2}), json!({"n": 10})],
        };
        assert_eq!(Log::open(path).unwrap().1, want, "{state}: the line after the failure stands at the next open");
    }
}

/// A FULL VOLUME's FAILURE READS IN THE STREAM's WORDS (`blobs::Cause`;
/// `operations.md` §1): an append the OS refuses for room answers `{log}:
/// append: the volume is full ({the OS's text})`, its kind kept, the line
/// cut back off the file; and where the cut-back fails too, the stop's cause
/// keeps those words for the append's half, and the append that stopped the
/// log says them.
#[cfg(unix)]
#[test]
fn a_full_volumes_append_and_stop_read_the_volume_is_full() {
    let enospc = || io::Error::from_raw_os_error(28);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x.log");
    let (mut log, _, _) = Log::open(path.clone()).unwrap();
    log.append_synced(&json!({"n": 1})).unwrap();
    let full = log
        .append_by(&json!({"n": 2}), |file, line| {
            file.write_all(&line[..4])?;
            Err(enospc())
        })
        .expect_err("the volume full");
    assert_eq!(full.kind(), io::ErrorKind::StorageFull, "the kind kept");
    assert_eq!(full.to_string(), format!("{}: append: the volume is full ({})", label(&path, 2), enospc()));
    assert_eq!(fs::read_to_string(&path).unwrap(), "{\"n\":1}\n", "cut back off the file");
    // The cut back refused too: a read-only file, as in the stop's own test.
    log.file = File::open(&path).unwrap();
    let mut other = open_append(&path).unwrap();
    let stopping = log
        .append_by(&json!({"n": 3}), |_, line| {
            other.write_all(&line[..4])?;
            Err(enospc())
        })
        .expect_err("the volume full, the cut back refused");
    let cause = log.stopped().expect("the log stopped").to_string();
    assert!(
        cause.starts_with(&format!("its append failed (the volume is full ({})) and the cut back", enospc())),
        "{cause}"
    );
    assert!(stopping.to_string().contains(&cause), "the append that stops the log says its cause: {stopping}");
}

/// AN APPEND WHOSE CUT-BACK FAILS TOO stops the log: every later append
/// is refused, so the torn line stays the file's tail, the one place
/// open's tail check cuts without taking a whole line with it. The stop
/// keeps its cause — the append's failure and the cut's, each the OS's —
/// which the append that stopped the log says at once and every refusal
/// after it names, the refusal its cause alone; the stop counts each
/// refused append, the operator's figure (`Log::stop`). A compaction writes
/// the file whole from its whole lines, the torn tail not among them, and
/// lifts the stop.
#[test]
fn a_failed_cut_back_stops_the_log_until_a_compaction() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x.log");
    let (mut log, _, _) = Log::open(path.clone()).unwrap();
    log.append_synced(&json!({"n": 1})).unwrap();
    // A read-only file, as a failing disk leaves the log's: the rest of
    // the write fails at the OS, and so does the cut. The torn bytes land
    // through a second open file, as a write cut short leaves them.
    log.file = File::open(&path).unwrap();
    let mut other = open_append(&path).unwrap();
    let failed = log.append_by(&json!({"n": 2}), |file, line| {
        other.write_all(&line[..4])?;
        file.write_all(&line[4..])
    });
    let failed = failed.expect_err("the write and its cut back both refused");
    assert!(
        failed.to_string().ends_with("so it takes no append until a compaction completes"),
        "the append that stops the log says so: {failed}"
    );
    let cause = log.stopped().expect("the log stopped").to_string();
    assert!(
        cause.starts_with("its append failed (")
            && cause.contains(") and the cut back to its last whole line failed too ("),
        "the stop keeps both causes: {cause}"
    );
    assert_eq!(log.stop().map(|s| s.refused), Some(0), "no append refused yet");
    log.file = open_append(&path).unwrap();
    let refused = log.append_synced(&json!({"n": 3})).expect_err("a stopped log takes no append");
    assert_eq!(
        refused.to_string(),
        format!("{} takes no append until a compaction completes: {cause}", label(&path, 2)),
        "its refusal names the log and the stop's cause, and no figure of the operator's"
    );
    let stop = log.stop().expect("still stopped");
    assert_eq!((stop.cause.as_str(), stop.refused), (cause.as_str(), 1), "the refused append counted");
    assert_eq!(fs::read_to_string(&path).unwrap(), "{\"n\":1}\n{\"n\"", "the torn line stays the tail");
    let from = log.compact(vec![json!({"n": 1})].into_iter()).unwrap().expect("a stopped log is rewritten");
    assert_eq!((from.lines, from.bytes), (1, 8), "rewritten from its whole lines, the torn tail not among them");
    assert_eq!(log.stopped(), None, "a completed compaction lifts the stop");
    log.append_synced(&json!({"n": 4})).unwrap();
    drop(log);
    let (_, values, _) = Log::open(path.clone()).unwrap();
    assert_eq!(values, vec![json!({"n": 1}), json!({"n": 4})], "compacted whole, the stop lifted");
}

/// A COMPACTION THAT FAILS PAST ITS RENAME stops the log: the rewrite
/// stands at the log's name while the log's open file is the one it
/// replaced, so an append would answer durable over a line no open reads —
/// refused instead, until a compaction completes and the file is the
/// rewrite's. The log's size is the rewrite's, the file at its name; a
/// second such failure gives the stop its new cause and keeps its count of
/// refused appends, the log having refused every one since the first.
/// Injected by the directory itself: written and searched but not read, the
/// twin is created and renamed over the log, and the directory's own open
/// for its fsync fails.
#[cfg(unix)]
#[test]
fn a_compaction_that_fails_past_its_rename_stops_the_log() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x.log");
    let (mut log, _, _) = Log::open(path.clone()).unwrap();
    log.append_synced(&json!({"n": 1})).unwrap();
    log.append_synced(&json!({"n": 2})).unwrap();
    let mode = fs::metadata(dir.path()).unwrap().permissions();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o300)).unwrap();
    let compacted = log.compact(vec![json!({"n": 2})].into_iter());
    let appended = log.append_synced(&json!({"n": 3}));
    let again = log.compact(vec![json!({"n": 2})].into_iter());
    fs::set_permissions(dir.path(), mode).unwrap();
    if compacted.is_ok() {
        return; // a privileged process reads any directory: nothing to inject
    }
    let cause = log.stopped().expect("stopped past its rename").to_string();
    assert!(
        cause.starts_with(&format!("its rewrite failed past its rename ({}: fsync: ", dir_label(dir.path(), 1))),
        "the stop's cause names the act that failed past the rename: {cause}"
    );
    assert!(appended.is_err(), "a log whose compaction failed past its rename takes no append");
    assert!(again.is_err(), "and its next compaction, the directory still unreadable, fails past its rename too");
    assert_eq!(log.stop().map(|s| s.refused), Some(1), "the second stop keeps the first's count");
    assert_eq!(fs::read_to_string(&path).unwrap(), "{\"n\":2}\n", "the rewrite stands at the name");
    let size = log.size();
    assert_eq!((size.lines, size.bytes), (1, 8), "the log's size is the rewrite's, the file at its name");
    let from = log.compact(vec![json!({"n": 2})].into_iter()).unwrap().expect("a stopped log is rewritten");
    assert_eq!((from.lines, from.bytes), (1, 8), "rewritten from the file at its name");
    log.append_synced(&json!({"n": 4})).unwrap();
    drop(log);
    let (_, values, _) = Log::open(path).unwrap();
    assert_eq!(values, vec![json!({"n": 2}), json!({"n": 4})], "a completed compaction lifts the stop");
}

/// A COMPACTION THAT FAILS BEFORE ITS RENAME LEAVES THE LOG AS IT WAS
/// (`Log::compact`: "One that fails before its rename leaves the log as it
/// was"): the twin cannot be written — a directory stands at its name, as a
/// full disk leaves no room for one — so the file, its count and its appends
/// are the ones the log had, and it is not stopped: the next append lands
/// and reads back, and a later compaction, the obstacle gone, rewrites the
/// file whole.
#[test]
fn a_compaction_that_fails_before_its_rename_leaves_the_log_as_it_was() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x.log");
    let (mut log, _, _) = Log::open(path.clone()).unwrap();
    log.append_synced(&json!({"n": 1})).unwrap();
    log.append_synced(&json!({"n": 2})).unwrap();
    fs::create_dir(path.with_extension("compact")).unwrap();
    assert!(log.compact(vec![json!({"n": 2})].into_iter()).is_err(), "no twin can be written");
    assert_eq!(fs::read_to_string(&path).unwrap(), "{\"n\":1}\n{\"n\":2}\n", "the log as it was");
    log.append_synced(&json!({"n": 3})).expect("a log whose compaction failed before its rename takes an append");
    fs::remove_dir(path.with_extension("compact")).unwrap();
    log.compact(vec![json!({"n": 2}), json!({"n": 3})].into_iter()).unwrap();
    drop(log);
    assert_eq!(Log::open(path).unwrap().1, vec![json!({"n": 2}), json!({"n": 3})], "rewritten whole");
}

/// THE COMPACTION reads the log's own count of its lines: a log holding
/// exactly as many lines as its current records is left as it is (on
/// unix, the same inode), the compaction answering none; one holding more
/// is rewritten to exactly the current records, the compaction answering
/// the size it rewrote the log from and the log's size the rewrite's, and
/// the appends after it land in the rewritten file and count from there.
#[test]
fn the_line_count_decides_the_compaction() {
    #[cfg(unix)]
    let inode = |p: &Path| std::os::unix::fs::MetadataExt::ino(&fs::metadata(p).unwrap());
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x.log");
    let (mut log, _, _) = Log::open(path.clone()).unwrap();
    log.append_synced(&json!({"k": "a", "v": 1})).unwrap();
    log.append_synced(&json!({"k": "b", "v": 1})).unwrap();
    // Two lines, two current records: nothing to drop, no rewrite.
    #[cfg(unix)]
    let before = inode(&path);
    let left = log.compact(vec![json!({"k": "a", "v": 1}), json!({"k": "b", "v": 1})].into_iter()).unwrap();
    assert_eq!(left, None, "left as it is");
    #[cfg(unix)]
    assert_eq!(inode(&path), before, "a log holding only its current records is not rewritten");
    // A third line replacing `a`'s: three lines, two records — rewritten.
    log.append_synced(&json!({"k": "a", "v": 2})).unwrap();
    let from = log.compact(vec![json!({"k": "a", "v": 2}), json!({"k": "b", "v": 1})].into_iter()).unwrap();
    assert_eq!(from.map(|s| (s.name, s.lines, s.bytes)), Some((label(&path, 2), 3, 48)), "rewritten from three lines");
    assert_eq!(fs::read_to_string(&path).unwrap(), "{\"k\":\"a\",\"v\":2}\n{\"k\":\"b\",\"v\":1}\n");
    let size = log.size();
    assert_eq!((size.lines, size.bytes), (2, 32), "the log's size is the rewrite's");
    assert!(!path.with_extension("compact").exists(), "the twin is renamed over the log");
    // The next append lands in the rewritten file, and the count runs
    // on from the rewrite's two lines: three lines, three records, no
    // rewrite.
    log.append_synced(&json!({"k": "c", "v": 1})).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 3, "the append landed in the rewritten file");
    #[cfg(unix)]
    let rewritten = inode(&path);
    log.compact(
        vec![json!({"k": "a", "v": 2}), json!({"k": "b", "v": 1}), json!({"k": "c", "v": 1})].into_iter(),
    )
    .unwrap();
    #[cfg(unix)]
    assert_eq!(inode(&path), rewritten, "the count is the rewritten file's");
}
