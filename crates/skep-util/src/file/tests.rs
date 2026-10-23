//! THE TAIL RULE's FENCE: a read over a file ending without `\n` answers
//! the lines and the tail; the streaming read answers each line then what
//! ends it, a line past the bound named by its byte; every torn tail is
//! cut or closed at the next append and reported in `Appended`; a failed
//! append is cut back to the whole lines, and a failed cut-back answered
//! beside the write; `write_once` makes a new file and removes what a
//! failed write made, the removal's failure named beside it; `publish` at
//! each step of a simulated kill leaves the final name whole or absent,
//! and a kill's temp is listed and swept; a temp a live writer holds is
//! skipped by the listing and the sweep; `remove`'s three answers.

use std::fs;
use std::io;
use std::path::Path;

use tempfile::TempDir;

use super::*;

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// The lines of `path`, each as text, read through `read_lines`.
fn lines_of(path: &Path) -> Vec<String> {
    read_lines(path).unwrap().expect("the file stands").lines.iter().map(|l| String::from_utf8(l.clone()).unwrap()).collect()
}

/// `read_lines` over a file ending without `\n` answers the whole lines and
/// the tail — where it starts and where the file ends — and writes nothing;
/// one ending in `\n` answers no tail; an empty file no lines and no tail;
/// no file at all `None`.
#[test]
fn a_read_over_a_file_ending_without_a_newline_answers_the_lines_and_the_tail() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("lines");
    fs::write(&path, b"one\ntwo\nthr").unwrap();
    let found = read_lines(&path).unwrap().unwrap();
    assert_eq!(found.lines, [b"one".to_vec(), b"two".to_vec()]);
    assert_eq!((found.whole, found.tail), (8, Some(Tail { at: 8, len: 11 })));
    assert_eq!(found.tail.unwrap().bytes(), 3);
    assert_eq!(fs::read(&path).unwrap(), b"one\ntwo\nthr", "the read writes nothing: the tail stands");
    fs::write(&path, b"one\ntwo\n").unwrap();
    let found = read_lines(&path).unwrap().unwrap();
    assert_eq!((found.lines.len(), found.whole, found.tail), (2, 8, None));
    fs::write(&path, b"").unwrap();
    let found = read_lines(&path).unwrap().unwrap();
    assert_eq!((found.lines.len(), found.whole, found.tail), (0, 0, None));
    fs::write(&path, b"torn").unwrap();
    let found = read_lines(&path).unwrap().unwrap();
    assert_eq!((found.lines.len(), found.whole, found.tail), (0, 0, Some(Tail { at: 0, len: 4 })), "a file of one torn line");
    assert!(read_lines(&tmp.path().join("absent")).unwrap().is_none());
}

/// THE STREAMING READ answers each whole line in turn, counting their bytes,
/// then the tail — or the end where the file ends in `\n` — and `End` at
/// every later call; a line past the bound ends the read as `Long` naming
/// the byte it starts at, read no further than one byte past the bound,
/// while a line at the bound exactly is a line.
#[test]
fn the_line_reader_answers_each_line_then_what_ends_the_read() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("lines");
    fs::write(&path, b"one\ntwo\nthr").unwrap();
    let mut reader = LineReader::open(&path, 8).unwrap().unwrap();
    assert_eq!(reader.next_line().unwrap(), Next::Line(b"one"));
    assert_eq!(reader.whole(), 4);
    assert_eq!(reader.next_line().unwrap(), Next::Line(b"two"));
    assert_eq!(reader.next_line().unwrap(), Next::Tail(Tail { at: 8, len: 11 }));
    assert_eq!(reader.next_line().unwrap(), Next::End, "the read has ended");
    assert_eq!(reader.whole(), 8);
    fs::write(&path, b"one\n").unwrap();
    let mut reader = LineReader::open(&path, 8).unwrap().unwrap();
    assert_eq!(reader.next_line().unwrap(), Next::Line(b"one"));
    assert_eq!(reader.next_line().unwrap(), Next::End);
    assert!(LineReader::open(&tmp.path().join("absent"), 8).unwrap().is_none());
}

/// A LINE PAST THE BOUND ends the read as `Long`, naming the byte it starts
/// at, whether it ends in `\n` or is the file's tail; a line of the bound's
/// length exactly is a whole line.
#[test]
fn a_line_past_the_bound_ends_the_read_naming_its_byte() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("lines");
    fs::write(&path, b"one\n12345678\n123456789\nafter\n").unwrap();
    let mut reader = LineReader::open(&path, 8).unwrap().unwrap();
    assert_eq!(reader.next_line().unwrap(), Next::Line(b"one"));
    assert_eq!(reader.next_line().unwrap(), Next::Line(b"12345678"), "a line at the bound exactly");
    assert_eq!(reader.next_line().unwrap(), Next::Long { at: 13 }, "the ninth byte of a line passes the bound");
    assert_eq!(reader.next_line().unwrap(), Next::End, "the read ended at the long line");
    assert_eq!(reader.whole(), 13, "the whole lines before it");
    fs::write(&path, b"one\n123456789").unwrap();
    let mut reader = LineReader::open(&path, 8).unwrap().unwrap();
    assert_eq!(reader.next_line().unwrap(), Next::Line(b"one"));
    assert_eq!(reader.next_line().unwrap(), Next::Long { at: 4 }, "a tail past the bound is long, never a crash's");
}

/// EVERY TORN TAIL IS CUT at the next append and reported: over each prefix
/// of a line left as the file's tail — and none — the next append lands
/// where the last whole line ends, the tail reported in `Appended` with its
/// bytes, the lines before it unchanged, and a read after it finds every
/// line whole; the file is created at the mode where absent.
#[test]
fn every_torn_tail_is_cut_at_the_next_append_and_reported() {
    let line = b"{\"held\":3,\"doc\":\"1.0.1.0.1\"}";
    for cut in 0..=line.len() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("held");
        let mut before = b"first\nsecond\n".to_vec();
        before.extend_from_slice(&line[..cut]);
        fs::write(&path, &before).unwrap();
        let mut appender = Appender::open(&path, 0o600).unwrap();
        assert_eq!(appender.whole(), 13, "cut {cut}: the scan finds the last whole line's end");
        let appended = appender.append(b"third", OnTail::Cut, Fsync::Data).unwrap();
        let want = (cut > 0).then_some(Tail { at: 13, len: 13 + cut as u64 });
        assert_eq!(appended, Appended { tail: want, closed: false }, "cut {cut}");
        assert_eq!(fs::read(&path).unwrap(), b"first\nsecond\nthird\n", "cut {cut}: the tail cut, the line where the last whole line ends");
        assert_eq!(appender.whole(), 19);
        assert_eq!(lines_of(&path), ["first", "second", "third"]);
    }
    // Created at the mode where absent, the first line at byte 0.
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("new");
    let mut appender = Appender::open(&path, 0o600).unwrap();
    assert_eq!(appender.append(b"first", OnTail::Cut, Fsync::All).unwrap(), Appended { tail: None, closed: false });
    assert_eq!(fs::read(&path).unwrap(), b"first\n");
    #[cfg(unix)]
    assert_eq!(mode(&path), 0o600);
}

/// EVERY TORN TAIL IS CLOSED by the mark at the next append and reported:
/// over each prefix of a line left as the file's tail, the next append
/// writes the mark, a `\n`, the line and its `\n` in one write after the
/// torn bytes — the bytes the file held standing unchanged ahead of them —
/// so the torn bytes become a whole line the caller's reader skips, and a
/// tail of nothing takes no mark.
#[test]
fn every_torn_tail_is_closed_by_the_mark_at_the_next_append_and_reported() {
    let mark = b" # not read: this line ended without a newline";
    let line = b"http://127.0.0.1:8642 9 1.0.3 abab";
    for cut in 0..=line.len() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("bindings");
        let mut before = b"first\n".to_vec();
        before.extend_from_slice(&line[..cut]);
        fs::write(&path, &before).unwrap();
        let mut appender = Appender::open(&path, 0o600).unwrap();
        let appended = appender.append(b"second", OnTail::Close(mark), Fsync::All).unwrap();
        let after = fs::read(&path).unwrap();
        assert!(after.starts_with(&before), "cut {cut}: the bytes before the append changed");
        if cut == 0 {
            assert_eq!(appended, Appended { tail: None, closed: false }, "cut {cut}");
            assert_eq!(&after[before.len()..], b"second\n");
        } else {
            assert_eq!(appended, Appended { tail: Some(Tail { at: 6, len: 6 + cut as u64 }), closed: true }, "cut {cut}");
            let mut want = mark.to_vec();
            want.extend_from_slice(b"\nsecond\n");
            assert_eq!(&after[before.len()..], &want[..], "cut {cut}: the mark, its newline, the line, its newline");
            let lines = lines_of(&path);
            assert_eq!(lines.len(), 3);
            assert!(lines[1].ends_with(std::str::from_utf8(mark).unwrap()), "cut {cut}: the torn bytes closed into one line");
        }
        assert_eq!(appender.whole(), after.len() as u64, "cut {cut}: every byte is a whole line's now");
    }
}

/// AN APPEND AT A TRUSTED COUNT lands where the caller's count says the
/// whole lines end, cutting what stands past it — the count the caller's
/// own read made — and opens no file where none stands.
#[test]
fn an_append_at_a_trusted_count_cuts_what_stands_past_it() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("held");
    fs::write(&path, b"header\nline\ntorn").unwrap();
    let mut reader = LineReader::open(&path, 64).unwrap().unwrap();
    while !matches!(reader.next_line().unwrap(), Next::Tail(_) | Next::End) {}
    let mut appender = Appender::open_at(&path, reader.whole()).unwrap();
    let appended = appender.append(b"next", OnTail::Cut, Fsync::Data).unwrap();
    assert_eq!(appended.tail, Some(Tail { at: 12, len: 16 }));
    assert_eq!(fs::read(&path).unwrap(), b"header\nline\nnext\n");
    assert_eq!(Appender::open_at(&tmp.path().join("absent"), 0).unwrap_err().kind(), io::ErrorKind::NotFound, "nothing is created at a trusted count");
}

/// A FAILED APPEND IS CUT BACK to the whole lines: a write cut short part-way
/// — the first bytes written and the rest refused, as a full disk does —
/// leaves the file as it was, the count unmoved, and the next append lands where
/// the last whole line ends; under `Close` the cut-back keeps the torn bytes
/// the mark was to close (the mutant that skips the cut-back leaves on the
/// file the bytes the refusal says it does not hold, and the next line
/// glues to them).
#[test]
fn a_failed_append_is_cut_back_to_the_whole_lines() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("held");
    fs::write(&path, b"first\n").unwrap();
    let mut appender = Appender::open(&path, 0o600).unwrap();
    let refused = appender.append_by(b"second line", OnTail::Cut, |file, bytes| {
        file.write_all(&bytes[..4])?;
        Err(io::Error::new(io::ErrorKind::StorageFull, "the volume is full"))
    });
    assert_eq!(refused.unwrap_err().kind(), io::ErrorKind::StorageFull);
    assert_eq!(fs::read(&path).unwrap(), b"first\n", "the bytes the write made are cut back off");
    assert_eq!(appender.whole(), 6, "the count did not move");
    appender.append(b"second", OnTail::Cut, Fsync::None).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"first\nsecond\n");
    // Under `Close`, the torn bytes stand after the cut-back.
    fs::write(&path, b"first\ntorn").unwrap();
    let mut appender = Appender::open(&path, 0o600).unwrap();
    let refused = appender.append_by(b"second", OnTail::Close(b"#"), |file, bytes| {
        file.write_all(&bytes[..1])?;
        Err(io::Error::new(io::ErrorKind::StorageFull, "the volume is full"))
    });
    assert!(refused.is_err());
    assert_eq!(fs::read(&path).unwrap(), b"first\ntorn", "the torn bytes are never cut under Close");
    assert!(appender.append(b"second", OnTail::Close(b"#"), Fsync::None).unwrap().closed);
    assert_eq!(fs::read(&path).unwrap(), b"first\ntorn#\nsecond\n");
}

/// A FAILED CUT-BACK IS ANSWERED BESIDE THE WRITE: where the write fails and
/// the cut back to the whole lines fails too — here the write's seam hands
/// the appender a file it cannot truncate — the one error answered carries
/// the write's kind and names both failures (the mutant that answers the
/// write's alone leaves the tail unsaid until the next open).
#[test]
fn a_failed_cut_back_is_answered_beside_the_write() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("held");
    fs::write(&path, b"first\n").unwrap();
    let read_only = tmp.path().join("other");
    fs::write(&read_only, b"").unwrap();
    let mut appender = Appender::open(&path, 0o600).unwrap();
    let refused = appender
        .append_by(b"second", OnTail::Cut, |file, _| {
            *file = File::open(&read_only)?;
            Err(io::Error::new(io::ErrorKind::StorageFull, "the volume is full"))
        })
        .unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::StorageFull, "the write's kind");
    let text = refused.to_string();
    assert!(text.contains("the volume is full") && text.contains("the cut back to the last whole line failed too"), "{text}");
}

/// `write_once` MAKES A NEW FILE at the mode, synced, and refuses a standing
/// one `AlreadyExists`, leaving it as it stands; a write that fails has the
/// file it made removed, and where that removal fails too the one error
/// names both and the file stands with what was written.
#[test]
fn write_once_makes_a_new_file_and_removes_what_a_failed_write_made() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("key");
    write_once(&path, b"{\"v\":1}\n", 0o600).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"{\"v\":1}\n");
    #[cfg(unix)]
    assert_eq!(mode(&path), 0o600);
    assert_eq!(write_once(&path, b"x", 0o600).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&path).unwrap(), b"{\"v\":1}\n", "the standing file is left as it stands");
    let refused = tmp.path().join("refused");
    let err = write_once_by(&refused, b"bytes", 0o600, |file, bytes| {
        file.write_all(&bytes[..2])?;
        Err(io::Error::new(io::ErrorKind::StorageFull, "the volume is full"))
    })
    .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::StorageFull);
    assert!(!refused.exists(), "the file a failed write made is removed");
    #[cfg(unix)]
    {
        let dir = tmp.path().join("sealed");
        fs::create_dir(&dir).unwrap();
        let inside = dir.join("refused");
        let err = write_once_by(&inside, b"bytes", 0o600, |file, bytes| {
            file.write_all(&bytes[..2])?;
            set_mode(&dir, 0o500);
            Err(io::Error::new(io::ErrorKind::StorageFull, "the volume is full"))
        })
        .unwrap_err();
        set_mode(&dir, 0o700);
        let text = err.to_string();
        assert!(text.contains("the volume is full") && text.contains("could not be removed after it"), "{text}");
        assert_eq!(fs::read(&inside).unwrap(), b"by", "the file stands with what was written");
    }
}

/// `publish` AT EACH STEP OF A SIMULATED KILL leaves the final name whole or
/// absent: the states a kill leaves — the temp alone, the temp written
/// whole, the name made — each staged by hand, hold no part of a file at
/// the name; a kill's temp is listed as stale and swept, named, after which
/// the publish lands; and a publish that completes leaves no temp, the file
/// at the mode holding every byte.
#[test]
fn publish_at_each_step_of_a_kill_leaves_the_name_whole_or_absent() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("ab.key");
    let temp = temp_of(&path);
    assert_eq!(temp, tmp.path().join("ab.key.tmp"));
    // The temp alone, and the temp written whole: the name is absent, the
    // temp stale, swept and named.
    for staged in [&b""[..], &b"{\"v\":1}\n"[..]] {
        fs::write(&temp, staged).unwrap();
        assert!(!path.exists(), "nothing stands at the name");
        assert_eq!(stale(tmp.path(), ".key.tmp").unwrap(), std::slice::from_ref(&temp));
        let sweep = sweep_stale(tmp.path(), ".key.tmp").unwrap();
        assert_eq!(sweep.removed, std::slice::from_ref(&temp));
        assert!(sweep.failed.is_empty() && !temp.exists());
        publish(&path, b"{\"v\":1}\n", 0o600, OnStale::Refuse).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"{\"v\":1}\n");
        assert!(!temp.exists(), "a completed publish leaves no temp");
        #[cfg(unix)]
        assert_eq!(mode(&path), 0o600);
        fs::remove_file(&path).unwrap();
    }
    // The name made, the directory unsynced: the file is whole at its name
    // and nothing is stale.
    publish(&path, b"{\"v\":1}\n", 0o600, OnStale::Refuse).unwrap();
    assert!(stale(tmp.path(), ".key.tmp").unwrap().is_empty());
    assert_eq!(fs::read(&path).unwrap(), b"{\"v\":1}\n");
    // A directory that does not stand holds no temp.
    assert!(stale(&tmp.path().join("absent"), ".tmp").unwrap().is_empty());
    assert!(sweep_stale(&tmp.path().join("absent"), ".tmp").unwrap().removed.is_empty());
    // A publish the directory refuses leaves nothing.
    #[cfg(unix)]
    {
        let dir = tmp.path().join("sealed");
        fs::create_dir(&dir).unwrap();
        set_mode(&dir, 0o500);
        let refused = publish(&dir.join("x.key"), b"x", 0o600, OnStale::Refuse);
        set_mode(&dir, 0o700);
        assert!(refused.is_err());
        assert!(fs::read_dir(&dir).unwrap().next().is_none(), "nothing left in the directory");
    }
}

/// A TEMP A LIVE WRITER HOLDS — its advisory lock taken, as `publish` takes
/// it for the write's life — is skipped by the listing and the sweep and
/// refuses a publish at its name under either stale policy; released, it is
/// a dead run's: listed, refused under `Refuse`, replaced under `Replace`,
/// and swept (the mutant sweep that ignores the lock unlinks a live run's
/// temp from under it, and that run's rename fails).
#[test]
fn a_temp_a_live_writer_holds_is_skipped_by_the_listing_and_the_sweep() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("ab.key");
    let temp = temp_of(&path);
    fs::write(&temp, b"{\"v\":").unwrap();
    let held = OpenOptions::new().read(true).write(true).open(&temp).unwrap();
    held.try_lock().unwrap();
    assert!(stale(tmp.path(), ".key.tmp").unwrap().is_empty(), "a held temp is no stale temp");
    let sweep = sweep_stale(tmp.path(), ".key.tmp").unwrap();
    assert!(sweep.removed.is_empty() && sweep.failed.is_empty() && temp.exists(), "a held temp is not swept");
    for stale_policy in [OnStale::Refuse, OnStale::Replace] {
        let refused = publish(&path, b"{\"v\":1}\n", 0o600, stale_policy).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::AlreadyExists, "{stale_policy:?}");
        assert!(!path.exists() && fs::read(&temp).unwrap() == b"{\"v\":", "{stale_policy:?}: the live writer's temp stands untouched");
    }
    drop(held);
    assert_eq!(stale(tmp.path(), ".key.tmp").unwrap(), std::slice::from_ref(&temp), "released, it is a dead run's");
    assert_eq!(publish(&path, b"{\"v\":1}\n", 0o600, OnStale::Refuse).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    publish(&path, b"{\"v\":1}\n", 0o600, OnStale::Replace).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"{\"v\":1}\n");
    assert!(!temp.exists());
    // Another dead run's temp beside it: swept and named, the key untouched.
    let other = tmp.path().join("cd.key.tmp");
    fs::write(&other, b"").unwrap();
    fs::write(tmp.path().join("not-a-temp"), b"").unwrap();
    let sweep = sweep_stale(tmp.path(), ".key.tmp").unwrap();
    assert_eq!(sweep.removed, std::slice::from_ref(&other));
    assert!(!other.exists() && path.exists() && tmp.path().join("not-a-temp").exists());
}

/// `remove` ANSWERS THE THREE WAYS: a file that stood is `Gone`, none `Absent`,
/// and an unlink the directory refuses is the error, the file standing —
/// never one of the two (the mutant that drops the failure tells its
/// caller a file is destroyed that is not).
#[test]
fn remove_answers_gone_absent_or_the_failure() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("paper");
    fs::write(&path, b"seed").unwrap();
    assert_eq!(remove(&path).unwrap(), Removed::Gone);
    assert!(!path.exists());
    assert_eq!(remove(&path).unwrap(), Removed::Absent);
    #[cfg(unix)]
    {
        fs::write(&path, b"seed").unwrap();
        set_mode(tmp.path(), 0o500);
        let refused = remove(&path);
        set_mode(tmp.path(), 0o700);
        assert!(refused.is_err(), "{refused:?}");
        assert_eq!(fs::read(&path).unwrap(), b"seed", "the file stands");
    }
}
