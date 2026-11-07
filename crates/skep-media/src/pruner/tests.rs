use std::path::Path;
use std::time::Instant;

use super::*;
use crate::index::Rebuild;

/// Returns a gate over `dir` whose index is ready, built by hand.
///
/// It goes through the walk's door, with nothing walked.
///
/// # Panics
///
/// Panics where the store does not open.
fn ready_gate(dir: &Path) -> MediaGate {
    let gate = MediaGate::open(dir).expect("the store opens");
    gate.index().complete(Rebuild {
        values: 0,
        cells: 0,
        halts: 0,
        walk: Duration::ZERO,
        parse: Duration::ZERO,
    });
    gate
}

/// Checks that the cadence wakes due or stopped.
///
/// It wakes at the interval, and at once at the stop — before and after
/// it is asked.
#[test]
fn the_cadence_wakes_due_or_stopped() {
    let cadence = Cadence::new();
    let started = Instant::now();
    assert_eq!(cadence.wait(Duration::from_millis(20)), Wake::Due);
    assert!(started.elapsed() >= Duration::from_millis(20));
    let waiter = std::thread::scope(|s| {
        let h = s.spawn(|| cadence.wait(Duration::from_secs(3600)));
        std::thread::sleep(Duration::from_millis(20));
        cadence.stop();
        h.join().expect("waiter")
    });
    assert_eq!(waiter, Wake::Stop);
    assert_eq!(cadence.wait(Duration::from_secs(3600)), Wake::Stop, "stopped stays stopped");
}

/// Checks the pass's (a) and the hold (clause (5)).
///
/// An expired upload a stream still holds is left to that stream's end —
/// its partial and its record untouched by the pass — and, the hold
/// released, the next pass retires it. The pruner counts the passes it
/// ran, and a pass over an index not yet ready does not start: it answers
/// nothing and counts none.
#[test]
fn an_expired_upload_a_stream_holds_is_left_to_that_streams_end() {
    use skep_blobs::HashFunction;
    use skep_namespace::PrincipalId;

    let pruner = Pruner::new();
    let unready_dir = tempfile::tempdir().expect("tempdir");
    let unready = MediaGate::open(unready_dir.path()).expect("the store opens");
    assert_eq!(pruner.pass(&unready, || ()), None, "the index not ready: no pass starts");
    assert_eq!(pruner.passes_completed(), 0, "…and none is counted");

    let dir = tempfile::tempdir().expect("tempdir");
    let gate = ready_gate(dir.path());
    let now = gate.now_ms();
    let key = MediaGate::key(PrincipalId(1));
    let interval = Duration::from_millis(1_000);
    let record = gate
        .store()
        .create_upload(&key, HashFunction::Blake3, 10, interval, now)
        .expect("an upload");
    gate.advance_clock_ms(2_000);
    let hold = gate.claim(record.id).expect("a fresh upload is claimable");
    let pass_now = || pruner.pass(&gate, || ()).expect("the index is ready");
    assert_eq!(pass_now().expired_partials, 0, "held: left to its stream");
    assert!(gate.store().expired_uploads(gate.now_ms()).iter().any(|r| r.id == record.id));
    drop(hold);
    assert_eq!(pass_now().expired_partials, 1, "released: the next pass retires it");
    assert!(gate.store().expired_uploads(gate.now_ms()).is_empty(), "…its record with it");
    assert_eq!(pruner.passes_completed(), 2, "the two passes that ran");
}

/// Checks that a failure at step (a) never skips step (c).
///
/// The pass's exit (`operations.md` §4 row 5; §1.1 row 35): an expired
/// upload whose partial the OS will not remove — a directory holding a
/// file stands at its name, which no unlink takes — fails (a), the step
/// named, the store's words for the act in its cause and the one failure
/// counted. The pass goes on and unlinks the lapsed deposit no cell names,
/// its bytes freed and nothing halted, and its line names the failure ahead
/// of what it did. The record stands expired, so the next pass fails at (a)
/// again, with nothing left to unlink.
#[test]
fn a_failed_expiry_never_skips_the_unreferenced_files() {
    use skep_namespace::PrincipalId;

    use crate::cell::DESIGNATION;

    let dir = tempfile::tempdir().expect("tempdir");
    let gate = ready_gate(dir.path());
    gate.install_limits(None, None, Some(1_000), None, None).expect("a record installs");
    let p = PrincipalId(1);
    let now = gate.now_ms();
    let stuck = gate.create_upload(p, 10, now).expect("an upload");
    let partial = dir.path().join("blobs").join(DESIGNATION).join(format!(".upload-{}", stuck.id));
    std::fs::remove_file(&partial).expect("the empty partial");
    std::fs::create_dir(&partial).expect("a directory at its name");
    std::fs::write(partial.join("held"), b"x").expect("a file inside it");
    let bytes = b"a picture no cell names";
    let record = gate.create_upload(p, bytes.len() as u64, now).expect("a creation");
    let mut stream = gate.store().resume(&MediaGate::key(p), &record.id, 0, now).expect("a resume");
    stream.append(bytes, now).expect("the bytes");
    let hex = gate.finish_upload(stream, now).expect("a finish").hex;
    let blob = gate.store().blob_path(DESIGNATION, &hex).expect("a path");
    gate.advance_clock_ms(2_000);
    let pruner = Pruner::new();
    let pass = pruner.pass(&gate, || ()).expect("the index is ready");
    let [failure] = pass.failed.as_slice() else { panic!("one failure, (a)'s: {pass:?}") };
    assert_eq!((failure.step, failure.count), (PassStep::ExpiredPartials, 1), "{pass:?}");
    assert!(failure.cause.contains(": remove: "), "the store's words for the act: {failure}");
    assert!(failure.to_string().ends_with(" — the first of 1 failures"), "counted: {failure}");
    assert_eq!((pass.expired_partials, pass.unlinked, pass.kept), (0, 1, 0), "{pass:?}");
    assert_eq!(pass.freed, bytes.len() as u64, "the deposit's bytes: {pass:?}");
    assert_eq!(pass.halted, None, "{pass:?}");
    assert!(!blob.exists(), "unlinked in the pass whose (a) failed");
    let line = pass.to_string();
    assert!(
        line.starts_with(&format!(
            "pruner: the pass failed: {failure}; 0 expired partials removed, 1 files \
             unlinked, 0 kept, 0 asides removed, {} bytes freed; blobs/uploads.log ",
            bytes.len()
        )),
        "the failure named ahead of what the pass did: {line}"
    );
    let again = pruner.pass(&gate, || ()).expect("the index is ready");
    assert_eq!(again.failed, pass.failed, "the record stands expired: (a) fails again");
    assert_eq!((again.unlinked, again.kept, again.freed), (0, 0, 0), "{again:?}");
}

/// Checks that a failed expiry never strands the expired uploads after it.
///
/// Four expired uploads hold bytes, and a directory holding a file stands at
/// the partial's name of the one first in identifier order, the order the
/// pass walks them. The pass fails at (a) once and goes on: the other three
/// are removed, their bytes freed, and the stuck record stands, expired. The
/// next pass fails on it alone and removes nothing; with the directory gone,
/// a pass removes it with no failure.
#[test]
fn a_failed_expiry_never_strands_the_uploads_after_it() {
    use skep_namespace::PrincipalId;

    use crate::cell::DESIGNATION;

    let dir = tempfile::tempdir().expect("tempdir");
    let gate = ready_gate(dir.path());
    gate.install_limits(None, None, Some(1_000), None, None).expect("a record installs");
    let p = PrincipalId(1);
    let key = MediaGate::key(p);
    let now = gate.now_ms();
    let mut uploads: Vec<_> = (0..4u8)
        .map(|n| {
            let bytes = vec![b'a' + n; 10 + usize::from(n)];
            let record = gate.create_upload(p, 100, now).expect("an upload");
            let mut stream = gate.store().resume(&key, &record.id, 0, now).expect("a resume");
            stream.append(&bytes, now).expect("the bytes");
            (stream.settle(now).expect("a settle").id, bytes.len() as u64)
        })
        .collect();
    uploads.sort();
    let stuck = uploads[0].0;
    let partial = dir.path().join("blobs").join(DESIGNATION).join(format!(".upload-{stuck}"));
    std::fs::remove_file(&partial).expect("the partial");
    std::fs::create_dir(&partial).expect("a directory at its name");
    std::fs::write(partial.join("held"), b"x").expect("a file inside it");
    gate.advance_clock_ms(2_000);
    let expired = || -> Vec<_> {
        gate.store().expired_uploads(gate.now_ms()).into_iter().map(|r| r.id).collect()
    };
    let pruner = Pruner::new();
    let pass = pruner.pass(&gate, || ()).expect("the index is ready");
    let [failure] = pass.failed.as_slice() else { panic!("one failure, (a)'s: {pass:?}") };
    assert_eq!((failure.step, failure.count), (PassStep::ExpiredPartials, 1), "{pass:?}");
    assert!(failure.cause.starts_with("a partial in blobs/blake3/: remove: "), "{failure}");
    assert_eq!(pass.expired_partials, 3, "the walk went on past the stuck one: {pass:?}");
    let others: u64 = uploads[1..].iter().map(|(_, len)| len).sum();
    assert_eq!(pass.freed, others, "the three others' bytes: {pass:?}");
    assert_eq!(expired(), vec![stuck], "the stuck record stands, expired");
    let again = pruner.pass(&gate, || ()).expect("the index is ready");
    assert_eq!(again.failed, pass.failed, "the next pass fails on it alone");
    assert_eq!((again.expired_partials, again.freed), (0, 0), "{again:?}");
    std::fs::remove_dir_all(&partial).expect("the cause cleared");
    let cleared = pruner.pass(&gate, || ()).expect("the index is ready");
    assert!(cleared.failed.is_empty(), "{cleared:?}");
    assert_eq!(cleared.expired_partials, 1, "{cleared:?}");
    assert!(expired().is_empty(), "the record retired");
}

/// Checks that a file step (c) cannot take never strands the files after it.
///
/// Two lapsed deposits no cell names stand, and a directory holding a file
/// stands at `.retired-{lower hex}-0`, the aside name a fresh store's first
/// rename aside takes, so the lower file's rename aside fails: no file is
/// renamed onto a directory. The pass goes on to the higher file and unlinks
/// it, its bytes freed, the lower one left at its hex name; then the step's
/// aside loop meets the directory and fails on it too, and step (c)'s one
/// failure counts the two. With the directory gone, the next pass unlinks
/// the lower file with no failure.
#[test]
fn a_file_step_c_cannot_take_never_strands_the_files_after_it() {
    use skep_namespace::PrincipalId;

    use crate::cell::DESIGNATION;

    let dir = tempfile::tempdir().expect("tempdir");
    let gate = ready_gate(dir.path());
    gate.install_limits(None, None, Some(1_000), None, None).expect("a record installs");
    let p = PrincipalId(1);
    let now = gate.now_ms();
    let pictures: [&[u8]; 2] = [b"a picture no cell names", b"another, as unplaced"];
    let mut deposits: Vec<(String, u64)> = pictures
        .iter()
        .map(|bytes| {
            let record = gate.create_upload(p, bytes.len() as u64, now).expect("a creation");
            let mut stream =
                gate.store().resume(&MediaGate::key(p), &record.id, 0, now).expect("a resume");
            stream.append(bytes, now).expect("the bytes");
            (gate.finish_upload(stream, now).expect("a finish").hex, bytes.len() as u64)
        })
        .collect();
    deposits.sort();
    let [(lower, lower_len), (higher, higher_len)] = deposits.as_slice() else {
        panic!("two deposits: {deposits:?}")
    };
    let blob = |hex: &str| gate.store().blob_path(DESIGNATION, hex).expect("a path");
    let squatter = dir.path().join("blobs").join(DESIGNATION).join(format!(".retired-{lower}-0"));
    std::fs::create_dir(&squatter).expect("a directory at the first aside's name");
    std::fs::write(squatter.join("held"), b"x").expect("a file inside it");
    gate.advance_clock_ms(2_000);
    let pruner = Pruner::new();
    let pass = pruner.pass(&gate, || ()).expect("the index is ready");
    let [failure] = pass.failed.as_slice() else { panic!("one failure, (c)'s: {pass:?}") };
    assert_eq!(
        (failure.step, failure.count),
        (PassStep::UnreferencedFiles, 2),
        "the rename aside, then that aside's removal: {pass:?}"
    );
    assert!(failure.cause.contains(": rename aside: "), "the first, the rename's: {failure}");
    assert_eq!((pass.unlinked, pass.kept, pass.asides), (1, 0, 0), "{pass:?}");
    assert_eq!(pass.freed, *higher_len, "the higher file's bytes: {pass:?}");
    assert!(blob(lower).is_file(), "the lower file left at its hex name");
    assert!(!blob(higher).exists(), "the higher one unlinked past the failure");
    std::fs::remove_dir_all(&squatter).expect("the cause cleared");
    let cleared = pruner.pass(&gate, || ()).expect("the index is ready");
    assert!(cleared.failed.is_empty(), "{cleared:?}");
    assert_eq!((cleared.unlinked, cleared.freed), (1, *lower_len), "{cleared:?}");
    assert!(!blob(lower).exists(), "unlinked once the cause is cleared");
}

/// Returns the entries at aside names in `dir`.
fn asides_in(dir: &Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .expect("the designation directory")
        .map(|entry| entry.expect("an entry").path())
        .filter(|path| {
            path.file_name().is_some_and(|n| n.to_string_lossy().starts_with(".retired-"))
        })
        .collect()
}

/// The arm's guard, as this suite hands the pass one.
///
/// Armed, its drop — the arm released after a rename aside, the unlink yet
/// to come — stands a directory holding a file in place of each aside that
/// is a file, then disarms, so the unlink after fails once.
struct Sabotage<'a> {
    armed: &'a std::cell::Cell<bool>,
    dir: &'a Path,
}

impl Drop for Sabotage<'_> {
    fn drop(&mut self) {
        if !self.armed.replace(false) {
            return;
        }
        for aside in asides_in(self.dir).into_iter().filter(|path| path.is_file()) {
            std::fs::remove_file(&aside).expect("the aside");
            std::fs::create_dir(&aside).expect("a directory at its name");
            std::fs::write(aside.join("held"), b"x").expect("a file inside it");
        }
    }
}

/// Checks that a file whose aside will not unlink counts only once it goes.
///
/// The arm's guard is the suite's ([`Sabotage`]): as it drops after the
/// lapsed deposit's rename aside, it stands a directory at the aside's name,
/// so the unlink after fails; each acquisition puts a file back at a
/// directory standing at an aside's name. The file is counted in no `files
/// unlinked`, step (c)'s one failure is the unlink's, and the step's aside
/// loop takes the aside in the same pass, counted among the asides removed
/// with the bytes it freed.
#[test]
fn a_file_whose_aside_will_not_unlink_is_left_to_the_aside_loop() {
    use skep_namespace::PrincipalId;

    use crate::cell::DESIGNATION;

    let dir = tempfile::tempdir().expect("tempdir");
    let gate = ready_gate(dir.path());
    gate.install_limits(None, None, Some(1_000), None, None).expect("a record installs");
    let p = PrincipalId(1);
    let now = gate.now_ms();
    let bytes = b"a picture no cell names";
    let record = gate.create_upload(p, bytes.len() as u64, now).expect("a creation");
    let mut stream = gate.store().resume(&MediaGate::key(p), &record.id, 0, now).expect("a resume");
    stream.append(bytes, now).expect("the bytes");
    let hex = gate.finish_upload(stream, now).expect("a finish").hex;
    gate.advance_clock_ms(2_000);
    let designation_dir = dir.path().join("blobs").join(DESIGNATION);
    let armed = std::cell::Cell::new(true);
    let healed = b"healed";
    let exclusive = || {
        for aside in asides_in(&designation_dir).into_iter().filter(|path| path.is_dir()) {
            std::fs::remove_dir_all(&aside).expect("the directory");
            std::fs::write(&aside, healed).expect("a file at the aside's name");
        }
        Sabotage { armed: &armed, dir: &designation_dir }
    };
    let pass = Pruner::new().pass(&gate, exclusive).expect("the index is ready");
    assert!(!armed.get(), "the guard stood the directory after the rename aside");
    let [failure] = pass.failed.as_slice() else { panic!("one failure, (c)'s: {pass:?}") };
    assert_eq!((failure.step, failure.count), (PassStep::UnreferencedFiles, 1), "{pass:?}");
    assert!(failure.cause.contains(": remove: "), "the unlink after the rename: {failure}");
    assert_eq!((pass.unlinked, pass.asides), (0, 1), "counted where it went: {pass:?}");
    assert_eq!(pass.freed, healed.len() as u64, "the aside's bytes, freed by the aside loop");
    assert!(!designation_dir.join(&hex).exists(), "the file renamed aside");
    assert!(asides_in(&designation_dir).is_empty(), "and its aside taken in the same pass");
}
