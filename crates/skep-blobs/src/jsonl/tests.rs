use super::*;
use serde_json::json;

/// The log reads back what it appended, in order, and a torn tail is
/// cut off the file at open, the lines before it standing.
#[test]
fn a_log_reads_back_its_lines_and_cuts_a_torn_tail() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x.log");
    let (mut log, values) = Log::open(path.clone()).unwrap();
    assert!(values.is_empty(), "an absent log holds no line");
    log.append_synced(&json!({"n": 1})).unwrap();
    log.append_unsynced(&json!({"n": 2})).unwrap();
    drop(log);
    let whole = fs::read_to_string(&path).unwrap();
    assert_eq!(whole, "{\"n\":1}\n{\"n\":2}\n");
    fs::write(&path, format!("{whole}{{\"n\":3")).unwrap();
    let (_, values) = Log::open(path.clone()).unwrap();
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
        let (_, values) = Log::open(path.clone()).unwrap();
        assert_eq!(values, vec![json!({"n": 1})], "{torn:?}: the lines before it alone");
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"n\":1}\n", "{torn:?}: cut there, the line after it too");
    }
}

/// AN APPEND THAT FAILS is cut back off the file: a write cut short —
/// part of the line on disk, then an error, as a full disk gives —
/// leaves the file at its whole lines, the next append lands on a whole
/// line, and the reopen reads every whole line, the one after the
/// failure included.
#[test]
fn a_failed_append_is_cut_back_off_the_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x.log");
    let (mut log, _) = Log::open(path.clone()).unwrap();
    log.append_synced(&json!({"n": 1})).unwrap();
    let cut_short = log.append_by(&json!({"n": 2}), |file, line| {
        file.write_all(&line[..4])?;
        Err(io::Error::other("no space left on the device"))
    });
    assert!(cut_short.is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), "{\"n\":1}\n", "the torn line is cut back off the file");
    log.append_synced(&json!({"n": 3})).unwrap();
    drop(log);
    let (_, values) = Log::open(path.clone()).unwrap();
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
        let (mut log, _) = Log::open(path.clone()).unwrap();
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

/// AN APPEND WHOSE CUT-BACK FAILS TOO stops the log: every later append
/// is refused, so the torn line stays the file's tail, the one place
/// open's tail check cuts without taking a whole line with it. A
/// compaction writes the file whole and lifts the stop.
#[test]
fn a_failed_cut_back_stops_the_log_until_a_compaction() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x.log");
    let (mut log, _) = Log::open(path.clone()).unwrap();
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
    assert!(failed.is_err());
    log.file = open_append(&path).unwrap();
    assert!(log.append_synced(&json!({"n": 3})).is_err(), "a stopped log takes no append");
    assert_eq!(fs::read_to_string(&path).unwrap(), "{\"n\":1}\n{\"n\"", "the torn line stays the tail");
    log.compact(vec![json!({"n": 1})].into_iter()).unwrap();
    log.append_synced(&json!({"n": 4})).unwrap();
    drop(log);
    let (_, values) = Log::open(path.clone()).unwrap();
    assert_eq!(values, vec![json!({"n": 1}), json!({"n": 4})], "compacted whole, the stop lifted");
}

/// A COMPACTION THAT FAILS PAST ITS RENAME stops the log: the rewrite
/// stands at the log's name while the log's open file is the one it
/// replaced, so an append would answer durable over a line no open reads —
/// refused instead, until a compaction completes and the file is the
/// rewrite's. Injected by the directory itself: written and searched but not
/// read, the twin is created and renamed over the log, and the directory's
/// own open for its fsync fails.
#[cfg(unix)]
#[test]
fn a_compaction_that_fails_past_its_rename_stops_the_log() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x.log");
    let (mut log, _) = Log::open(path.clone()).unwrap();
    log.append_synced(&json!({"n": 1})).unwrap();
    log.append_synced(&json!({"n": 2})).unwrap();
    let mode = fs::metadata(dir.path()).unwrap().permissions();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o300)).unwrap();
    let compacted = log.compact(vec![json!({"n": 2})].into_iter());
    let appended = log.append_synced(&json!({"n": 3}));
    fs::set_permissions(dir.path(), mode).unwrap();
    if compacted.is_ok() {
        return; // a privileged process reads any directory: nothing to inject
    }
    assert!(appended.is_err(), "a log whose compaction failed past its rename takes no append");
    assert_eq!(fs::read_to_string(&path).unwrap(), "{\"n\":2}\n", "the rewrite stands at the name");
    log.compact(vec![json!({"n": 2})].into_iter()).unwrap();
    log.append_synced(&json!({"n": 4})).unwrap();
    drop(log);
    let (_, values) = Log::open(path).unwrap();
    assert_eq!(values, vec![json!({"n": 2}), json!({"n": 4})], "a completed compaction lifts the stop");
}

/// THE COMPACTION reads the log's own count of its lines: a log holding
/// exactly as many lines as its current records is left as it is (on
/// unix, the same inode); one holding more is rewritten to exactly the
/// current records, and the appends after it land in the rewritten file
/// and count from there.
#[test]
fn the_line_count_decides_the_compaction() {
    #[cfg(unix)]
    let inode = |p: &Path| std::os::unix::fs::MetadataExt::ino(&fs::metadata(p).unwrap());
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x.log");
    let (mut log, _) = Log::open(path.clone()).unwrap();
    log.append_synced(&json!({"k": "a", "v": 1})).unwrap();
    log.append_synced(&json!({"k": "b", "v": 1})).unwrap();
    // Two lines, two current records: nothing to drop, no rewrite.
    #[cfg(unix)]
    let before = inode(&path);
    log.compact(vec![json!({"k": "a", "v": 1}), json!({"k": "b", "v": 1})].into_iter()).unwrap();
    #[cfg(unix)]
    assert_eq!(inode(&path), before, "a log holding only its current records is not rewritten");
    // A third line replacing `a`'s: three lines, two records — rewritten.
    log.append_synced(&json!({"k": "a", "v": 2})).unwrap();
    log.compact(vec![json!({"k": "a", "v": 2}), json!({"k": "b", "v": 1})].into_iter()).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), "{\"k\":\"a\",\"v\":2}\n{\"k\":\"b\",\"v\":1}\n");
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
