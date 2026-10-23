//! WHAT OPEN MAKES OF THE RECORDS AND THE PARTIALS (M-I5 (c); `media.md` the
//! resumable upload's clauses (1), (4); §The media stores): the
//! reconciliation both ways at open, an orphan removed under this build's
//! designations alone, an offset set back keeping its expiry, and the sweep
//! of the asides beside it; a partial that cannot be read failing the open
//! and retiring nothing; a record line read as no record
//! where it lacks any member, its interval among them, where its offset
//! passes its length, and where its designation climbs out of the root,
//! nothing beside the root touched; an upload log naming a function this
//! build does not compute — another build's — refusing the open whole,
//! nothing changed, and its read-alone door walking first, never left
//! waiting; the compaction, down to nothing where
//! nothing stands, over the twin a kill mid-compaction left beside each
//! log — a twin never read in place of its log; and before any of it, a
//! link at a name open acts on — symbolic, or a second hard link to a file
//! the store writes in place — or a special file there failing the open,
//! nothing it names touched and no open left waiting, every such entry
//! counted in one refusal of bounded length — eight clauses named, the rest
//! counted by kind — with the act for its kind; then what frees room before
//! what takes it, the asides and an expired partial gone before the lease
//! log's twin and the probe are asked for; the volume's hard-link probe,
//! which leaves nothing, a probe a kill cut short cleared by the next open;
//! and the root's own entry made durable at every open, the board's own
//! directory fsynced after the root. THE OPEN's ACCOUNT
//! (`Store::opened`): each repair counted and the bytes they freed, a store
//! or a log found absent answered made, a log's cut told from a crash's by
//! the whole lines it took; an open refused at a log naming the log and its
//! act, the kind kept; and the inspection refusing what the open refuses,
//! never hanging.

use std::fs::{self, OpenOptions};
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use skep_blobs::{BlobError, HashFunction, LeaseState, Step, Store, UploadId};

use crate::{every_deposit_unplaced, hex_of, open, put_whole, standing, HORIZON, HORIZON_MS, INTERVAL, INTERVAL_MS};

/// THE INSPECTION READS THE STORES AS THEY STAND (M-I5 (e); `Store::inspect`:
/// "reconciles nothing, compacts nothing, sweeps nothing, fsyncs nothing,
/// creates nothing"): over a root holding a standing upload, a retired
/// one's lines, two leases — one lapsed — a torn tail on each log, an
/// orphan partial and an aside, the inspection answers every record and
/// every lease the logs fold to, what each log's reading found — its torn
/// tail the cut an open would make, a half-written tail taking no whole
/// line — the listings by class — and leaves every byte and every file as found,
/// where the open cuts the tails, drops the retired lines, removes the
/// orphan and the aside and rewrites both logs; a root that is no
/// directory is `NotFound`, and nothing is created for it.
#[test]
fn the_inspection_reads_the_stores_as_they_stand_and_writes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let (kept, lapsed_hex, live_hex) = {
        let store = open(&root, 0);
        let kept = standing(&store, "k", 10, b"hello", 0);
        let ended = store.create_upload("k", HashFunction::Blake3, 10, INTERVAL, 0).unwrap();
        store.end_upload("k", &ended.id, 0).unwrap();
        let lapsed = put_whole(&store, "k", b"lapsed later", 0);
        let live = put_whole(&store, "j", b"live", INTERVAL_MS + 10);
        (kept, lapsed.hex, live.hex)
    };
    // Planted after the store closed: a torn tail on each log, an orphan
    // partial, an aside.
    for log in ["uploads.log", "leases.log"] {
        let mut text = fs::read_to_string(root.join(log)).unwrap();
        text.push_str("{\"torn");
        fs::write(root.join(log), text).unwrap();
    }
    fs::write(root.join("blake3").join(".upload-00000000000000000000000000000000"), b"orphan").unwrap();
    fs::write(root.join("blake3").join(format!(".retired-{live_hex}-7")), b"aside").unwrap();
    let snapshot = |root: &Path| -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        for entry in fs::read_dir(root).unwrap().chain(fs::read_dir(root.join("blake3")).unwrap()) {
            let path = entry.unwrap().path();
            if path.is_file() {
                out.push((path.display().to_string(), fs::read(&path).unwrap()));
            }
        }
        out.sort();
        out
    };
    let before = snapshot(&root);
    let now = INTERVAL_MS + 10;
    let inspection = Store::inspect(&root).expect("the inspection");
    assert_eq!(snapshot(&root), before, "every file as found");
    assert_eq!(inspection.root(), root.as_path());
    let uploads = inspection.uploads();
    assert_eq!(uploads.len(), 1, "the standing record, the retired one folded away: {uploads:?}");
    assert_eq!((uploads[0].id, uploads[0].offset), (kept.id, 5));
    let mut leases: Vec<(String, String)> = inspection.leases().iter().map(|l| (l.principal.clone(), l.hex.clone())).collect();
    leases.sort();
    assert_eq!(leases, vec![("j".into(), live_hex.clone()), ("k".into(), lapsed_hex.clone())], "every lease, lapsed ones too");
    let lapsed = inspection.leases().iter().find(|l| l.hex == lapsed_hex).unwrap();
    assert!(now >= lapsed.expires, "lapsed by the reader's own judgment of the expiry");
    // What each log's reading found: the standing record's creation and byte
    // received, the ended one's creation and retirement, each whole PUT's
    // creation and retirement — eight lines — and two leases; each log's torn
    // tail (no newline: no line) the cut an open would make, six bytes and
    // no whole line past it: a half-written tail, losing nothing.
    let (uploads_log, leases_log) = inspection.logs();
    for (log, name, lines) in [(uploads_log, "blobs/uploads.log", 8), (leases_log, "blobs/leases.log", 2)] {
        assert_eq!((log.name.as_str(), log.absent, log.lines, log.unread), (name, false, lines, 0), "{name}");
        let cut = log.cut.expect("the torn tail is where trust ends");
        assert_eq!((cut.bytes(), cut.lines_after), (6, 0), "{name}: a half-written tail alone");
    }
    assert_eq!(inspection.designation_dirs().unwrap(), vec!["blake3"]);
    let mut blobs = inspection.blobs_of("blake3").unwrap();
    blobs.sort();
    let mut want = vec![lapsed_hex.clone(), live_hex.clone()];
    want.sort();
    assert_eq!(blobs, want);
    assert_eq!(inspection.asides_of("blake3").unwrap(), vec![format!(".retired-{live_hex}-7")]);
    let mut partials = inspection.partials_of("blake3").unwrap();
    partials.sort();
    let mut want = vec![kept.id, UploadId::parse("00000000000000000000000000000000").unwrap()];
    want.sort();
    assert_eq!(partials, want, "the standing one's and the orphan");
    assert_eq!(inspection.blob_size("blake3", &live_hex).unwrap(), Some(4));
    assert_eq!(inspection.blob_size("blake3", &hex_of(b"absent")).unwrap(), None);
    assert_eq!(inspection.blob_path("blake3", &live_hex), Some(root.join("blake3").join(&live_hex)));
    assert_eq!(snapshot(&root), before, "still as found");
    let absent = dir.path().join("absent");
    assert_eq!(Store::inspect(&absent).expect_err("no directory").kind(), std::io::ErrorKind::NotFound);
    assert!(!absent.exists(), "nothing created");
    // The open, for contrast: the tails cut, the retired lines dropped, the
    // orphan and the aside removed.
    let store = open(&root, now);
    assert_ne!(snapshot(&root), before, "the open writes");
    assert!(store.asides_of("blake3").unwrap().is_empty());
    assert!(!root.join("blake3").join(".upload-00000000000000000000000000000000").exists());
}

/// THE COPY ORDER (M-I5 (e); `media.md` §Recovery, the deployment list's
/// items (3) and (4): "within `blobs/` the designation directories, then
/// the upload records, then the lease log"; s6-op-c): a live copy taken in
/// that order while a finish lands BEFORE its first take, BETWEEN its
/// first and second, BETWEEN its second and third, and AFTER its third —
/// the finish held at its first step and released at each point — opens,
/// reconciled, to the deposit AS ITSELF (the file whole under its live
/// lease), as LAPSED (a live lease over a file the copy's directories do
/// not hold, the partial an orphan), or as a STANDING UPLOAD (its record
/// over its partial at the offset) — and NEVER as a file with no lease and
/// no record, the one state an order that copied the lease log first could
/// leave: a file the pruner would take from under an acked deposit.
#[test]
fn a_live_copy_taken_in_the_order_restores_a_deposit_as_itself_as_lapsed_or_as_a_standing_upload() {
    let bytes = b"the deposit a live copy catches mid-finish".to_vec();
    let hex = hex_of(&bytes);
    for landing in 0..=3usize {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("blobs");
        let copy = dir.path().join("copy");
        fs::create_dir_all(&copy).unwrap();
        let store = open(&root, 0);
        let rec = standing(&store, "k", bytes.len() as u64, &bytes, 1);
        assert_eq!(rec.offset, bytes.len() as u64);
        let at_hold = Arc::new(Barrier::new(2));
        let go = Arc::new(Barrier::new(2));
        {
            let (at_hold, go) = (Arc::clone(&at_hold), Arc::clone(&go));
            store.hold_at(Step::PartialSync, move || {
                at_hold.wait();
                go.wait();
            });
        }
        // The three takes, in the order the record states.
        let take = |what: usize| match what {
            0 => {
                let from = root.join("blake3");
                let to = copy.join("blake3");
                fs::create_dir_all(&to).unwrap();
                for entry in fs::read_dir(&from).unwrap() {
                    let entry = entry.unwrap();
                    fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
                }
            }
            1 => {
                let _ = fs::copy(root.join("uploads.log"), copy.join("uploads.log"));
            }
            _ => {
                let _ = fs::copy(root.join("leases.log"), copy.join("leases.log"));
            }
        };
        thread::scope(|s| {
            let mut finish = Some(s.spawn(|| store.resume("k", &rec.id, bytes.len() as u64, 2).unwrap().finish(INTERVAL, 2)));
            at_hold.wait();
            for what in 0..3 {
                if landing == what {
                    go.wait();
                    finish.take().unwrap().join().expect("the finish thread").expect("the finish");
                }
                take(what);
            }
            if let Some(h) = finish.take() {
                go.wait();
                h.join().expect("the finish thread").expect("the finish");
            }
        });
        drop(store);
        let restored = open(&copy, 3);
        let file = restored.blob_size("blake3", &hex).unwrap();
        let lease = restored.lease_state("k", "blake3", &hex, 3);
        let record = restored.upload("k", &rec.id, 3);
        let ctx = format!("the finish landing {}", ["before every take", "between the directories and the records", "between the records and the leases", "after every take"][landing]);
        assert!(
            !(file.is_some() && lease == LeaseState::None && record.is_none()),
            "FINDING ({ctx}): a file with no lease and no record — the pruner's to take from under an acked deposit"
        );
        match landing {
            0 => {
                assert_eq!(file, Some(bytes.len() as u64), "{ctx}: itself, whole");
                assert!(matches!(lease, LeaseState::Live { .. }), "{ctx}: under its live lease");
                assert!(record.is_none(), "{ctx}: its record retired");
            }
            1 => {
                assert_eq!(file, None, "{ctx}: the directories copied before the rename");
                assert!(matches!(lease, LeaseState::Live { .. }), "{ctx}: a live lease over no file — LAPSED to the daemon's reading");
                assert!(record.is_none(), "{ctx}: the records copied after the retirement");
            }
            2 => {
                assert_eq!(file, None, "{ctx}");
                assert!(matches!(lease, LeaseState::Live { .. }), "{ctx}: the lease log copied after the lease");
                assert_eq!(record.map(|r| r.offset), Some(bytes.len() as u64), "{ctx}: a standing upload at its offset");
            }
            _ => {
                assert_eq!(file, None, "{ctx}");
                assert_eq!(lease, LeaseState::None, "{ctx}: no lease yet");
                assert_eq!(record.map(|r| r.offset), Some(bytes.len() as u64), "{ctx}: a standing upload, resumable");
            }
        }
        // Whatever the copy holds, no partial stands that no record names,
        // and a standing upload's partial is its offset long.
        let partial = copy.join("blake3").join(format!(".upload-{}", rec.id.to_hex()));
        match restored.upload("k", &rec.id, 3) {
            Some(r) => assert_eq!(fs::metadata(&partial).unwrap().len(), r.offset, "{ctx}"),
            None => assert!(!partial.exists(), "{ctx}: an orphan partial is removed at open"),
        }
    }
}

/// (1) A RECORD LINE LACKING ANY MEMBER IT CARRIES IS NO RECORD
/// (`parse_line`: "the store holds no value of its own to put in a missing
/// member's place"): for each member in turn — the interval among them — a
/// creation's line lacking it reads as a lost record does: no upload, its
/// partial an orphan open removes whatever principal the line would answer
/// to, the resume starting afresh; while the whole line stands, and the
/// compaction keeps it alone. The lines are a creation's, at offset 0, so a
/// missing length a default filled with 0 would make a record that stands:
/// past offset 0, the offset check would refuse the line itself and hide the
/// default.
#[test]
fn a_record_line_lacking_any_member_reads_as_no_upload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let members = ["designation", "expires", "interval", "key", "length", "offset"];
    let id_of = |n: usize| UploadId::parse(&hex_of(&[n as u8])[..32]).expect("32 lowercase hex");
    let partial = |id: &UploadId| root.join("blake3").join(format!(".upload-{}", id.to_hex()));
    let line = |id: &UploadId, lacking: Option<&str>| {
        let mut v = serde_json::json!({
            "designation": "blake3", "expires": 9_999, "id": id.to_hex(),
            "interval": 1_000, "key": "k", "length": 10, "offset": 0,
        });
        if let Some(member) = lacking {
            v.as_object_mut().expect("a record line is an object").remove(member);
        }
        format!("{v}\n")
    };
    fs::create_dir_all(root.join("blake3")).unwrap();
    let whole = id_of(members.len());
    let mut log = String::new();
    for (n, &member) in members.iter().enumerate() {
        fs::write(partial(&id_of(n)), b"").unwrap();
        log += &line(&id_of(n), Some(member));
    }
    fs::write(partial(&whole), b"").unwrap();
    log += &line(&whole, None);
    fs::write(root.join("uploads.log"), log).unwrap();
    let store = open(&root, 1);
    assert_eq!(store.opened().uploads_log.unread, members.len(), "each line read as no record, and counted");
    for (n, &member) in members.iter().enumerate() {
        assert_eq!(store.upload("k", &id_of(n), 1), None, "lacking {member}: no record");
        assert!(!partial(&id_of(n)).exists(), "lacking {member}: its partial an orphan open removes");
        assert!(matches!(store.resume("k", &id_of(n), 0, 1), Err(BlobError::NoUpload)), "lacking {member}: no resume");
    }
    let r = store.upload("k", &whole, 1).expect("the whole line stands");
    assert_eq!((r.offset, r.length, r.interval), (0, 10, Duration::from_millis(1_000)));
    assert!(partial(&whole).is_file(), "its partial kept");
    assert_eq!(fs::read_to_string(root.join("uploads.log")).unwrap().lines().count(), 1, "compacted to the whole line");
}

/// (4) A RECORD LINE WHOSE DESIGNATION CLIMBS OUT OF THE ROOT IS NO RECORD
/// (`Store`: "THE STORE CHECKS EVERY NAME IT IS HANDED", a log's names at
/// open as a caller's): a log restored from elsewhere is read through the
/// name check a creation's designation meets, so a line whose designation
/// would carry its partial's path out of the root — above it through `..`,
/// anywhere as an absolute path — reads as a lost record does. Open's
/// reconciliation, which cuts a standing upload's partial back to its
/// record's offset and removes an expired one's, then touches no file
/// beside the root; the same line naming a designation a creation admits
/// stands, and the compaction keeps it alone.
#[test]
fn a_record_line_whose_designation_climbs_out_of_the_root_is_no_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let elsewhere = dir.path().join("elsewhere");
    fs::create_dir_all(root.join("blake3")).unwrap();
    fs::create_dir_all(&elsewhere).unwrap();
    let absolute = elsewhere.to_str().expect("a UTF-8 tempdir").to_string();
    // Each escape, the directory its partial's name lands in, and its
    // expiry: standing at the open below, so cut back, or past, so removed.
    let escapes = [
        ("..".to_string(), dir.path().to_path_buf(), 9_999),
        ("..".to_string(), dir.path().to_path_buf(), 5),
        ("../elsewhere".to_string(), elsewhere.clone(), 9_999),
        (absolute.clone(), elsewhere.clone(), 9_999),
        (absolute, elsewhere.clone(), 5),
    ];
    let id_of = |n: usize| UploadId::parse(&hex_of(&[n as u8])[..32]).expect("32 lowercase hex");
    let line = |id: &UploadId, designation: &str, expires: u64| {
        let v = serde_json::json!({
            "designation": designation, "expires": expires, "id": id.to_hex(),
            "interval": 1_000, "key": "k", "length": 100, "offset": 3,
        });
        format!("{v}\n")
    };
    let mut log = String::new();
    for (n, (designation, at, expires)) in escapes.iter().enumerate() {
        fs::write(at.join(format!(".upload-{}", id_of(n).to_hex())), b"beside the root").unwrap();
        log += &line(&id_of(n), designation, *expires);
    }
    let kept = id_of(escapes.len());
    fs::write(root.join("blake3").join(format!(".upload-{}", kept.to_hex())), b"abc").unwrap();
    log += &line(&kept, "blake3", 9_999);
    fs::write(root.join("uploads.log"), log).unwrap();
    let store = open(&root, 10);
    for (n, (designation, at, _)) in escapes.iter().enumerate() {
        assert_eq!(
            fs::read(at.join(format!(".upload-{}", id_of(n).to_hex()))).ok().as_deref(),
            Some(b"beside the root".as_slice()),
            "{designation:?}: the file beside the root neither cut back nor removed"
        );
        assert_eq!(store.upload("k", &id_of(n), 10), None, "{designation:?}: no record");
    }
    let stand: Vec<UploadId> = store.uploads_of("k", 10).into_iter().map(|r| r.id).collect();
    assert_eq!(stand, vec![kept], "the line naming a designation a creation admits stands alone");
    assert_eq!(fs::read_to_string(root.join("uploads.log")).unwrap().lines().count(), 1, "compacted to it");
}

/// AN UPLOAD LOG NAMING A FUNCTION THIS BUILD DOES NOT COMPUTE REFUSES THE
/// OPEN, NOTHING CHANGED (`Store::open`; `media.md` §The design, item 4, "a
/// bare key would not say which function made it"; the register M-I3 (f)):
/// a log restored from another build holds two upload records under
/// `sha256-tree` — one standing, one expired — beside one of this build's,
/// each over a partial longer than its offset. The open refuses the log
/// whole before any act: the log and every partial as found, byte for byte,
/// where its reconciliation would cut the standing ones back and remove the
/// expired one's partial in the other build's directory, and no log begun;
/// the refusal names the log, the function and the build to start, never an
/// identifier, a principal or a path, and `RUNBOOK.md` quotes it whole; the
/// read-alone door answers it alike, and over a root that does not stand
/// answers `Ok` and makes nothing. An expired record of that build's alone
/// refuses the open too, its partial's removal an act in that build's
/// directory; with both retired — no upload of that build's left — the open
/// serves, its own upload reconciled and the other build's directory left
/// as found.
#[test]
fn an_upload_log_naming_a_function_this_build_does_not_compute_refuses_the_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let id_of = |n: usize| UploadId::parse(&hex_of(&[n as u8])[..32]).expect("32 lowercase hex");
    let (standing_there, expired_there, ours) = (id_of(0), id_of(1), id_of(2));
    let partial = |designation: &str, id: &UploadId| root.join(designation).join(format!(".upload-{}", id.to_hex()));
    let record = |id: &UploadId, designation: &str, expires: u64| {
        let v = serde_json::json!({
            "designation": designation, "expires": expires, "id": id.to_hex(),
            "interval": 1_000, "key": "p-4242", "length": 100, "offset": 3,
        });
        format!("{v}\n")
    };
    let retirement = |id: &UploadId| format!("{}\n", serde_json::json!({"id": id.to_hex(), "retired": true}));
    for designation in ["sha256-tree", "blake3"] {
        fs::create_dir_all(root.join(designation)).unwrap();
    }
    fs::write(partial("sha256-tree", &standing_there), b"another build's bytes").unwrap();
    fs::write(partial("sha256-tree", &expired_there), b"another build's, expired").unwrap();
    fs::write(partial("blake3", &ours), b"abcdef").unwrap();
    let log = root.join("uploads.log");
    let lines = [
        record(&standing_there, "sha256-tree", 9_999),
        record(&expired_there, "sha256-tree", 5),
        record(&ours, "blake3", 9_999),
    ];
    fs::write(&log, lines.concat()).unwrap();
    let append = |line: String| fs::write(&log, fs::read_to_string(&log).unwrap() + &line).unwrap();
    // Every file under the root and in its two designation directories, by
    // path, with its bytes: what "nothing changed" compares.
    let as_found = || -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        for at in [root.clone(), root.join("sha256-tree"), root.join("blake3")] {
            for entry in fs::read_dir(&at).unwrap() {
                let path = entry.unwrap().path();
                if path.is_file() {
                    out.push((path.display().to_string(), fs::read(&path).unwrap()));
                }
            }
        }
        out.sort();
        out
    };
    let before = as_found();
    let refused = Store::open(&root, HORIZON, 10).map(drop).expect_err("another build's uploads refuse the open");
    assert_eq!(refused.kind(), std::io::ErrorKind::InvalidData, "{refused}");
    let text = refused.to_string();
    assert_eq!(
        text,
        "blobs/uploads.log: read: 2 upload records name sha256-tree, a hash function this build does not compute \
         (it computes blake3), so a finish here would name a file and its lease under sha256-tree by a hash that \
         function did not make; nothing was changed: start the board with the build that wrote this log, one \
         that computes sha256-tree"
    );
    assert_eq!(as_found(), before, "the log and every partial as found: nothing reconciled, cut or removed");
    assert!(!root.join("leases.log").exists(), "and no log begun");
    for id in [&standing_there, &expired_there, &ours] {
        assert!(!text.contains(&id.to_hex()), "never an identifier: {text}");
    }
    assert!(!text.contains("4242"), "never a principal: {text}");
    assert!(!text.contains(&dir.path().display().to_string()), "never an absolute path: {text}");
    let door = Store::refuse_uploads_of_another_function(&root).expect_err("the door refuses it as the open does");
    assert_eq!((door.kind(), door.to_string()), (refused.kind(), text.clone()), "one judgment, two callers");
    assert_eq!(as_found(), before, "the door reads alone");
    let absent = dir.path().join("absent");
    assert!(Store::refuse_uploads_of_another_function(&absent).is_ok(), "a root that does not stand holds nothing");
    assert!(!absent.exists(), "and is not made");
    let runbook = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../RUNBOOK.md")).unwrap();
    let quoted = text.replace("sha256-tree", "{designation}").replace("2 upload records", "{n} upload records");
    assert!(runbook.contains(&format!("skepd: blob store: {quoted}\n")), "RUNBOOK.md quotes it whole: {quoted}");
    // That build's standing record retired: its expired one alone still
    // refuses the open.
    append(retirement(&standing_there));
    let before = as_found();
    let refused = Store::open(&root, HORIZON, 10).map(drop).expect_err("an expired record of that build's refuses");
    assert!(
        refused.to_string().starts_with("blobs/uploads.log: read: 1 upload record names sha256-tree, a hash function"),
        "{refused}"
    );
    assert_eq!(as_found(), before, "its partial not removed: nothing changed");
    // Both retired: no upload of that build's stands in the log.
    append(retirement(&expired_there));
    let store = open(&root, 10);
    let opened = store.opened();
    assert_eq!((opened.partials_cut_back, opened.orphan_partials, opened.expired_uploads), (1, 0, 0), "{opened:?}");
    assert_eq!(store.upload("p-4242", &ours, 10).map(|r| r.offset), Some(3), "this build's upload stands");
    assert_eq!(fs::read(partial("blake3", &ours)).unwrap(), b"abc", "reconciled, its partial cut back to its offset");
    assert_eq!(fs::read(partial("sha256-tree", &standing_there)).unwrap(), b"another build's bytes", "left as found");
    assert_eq!(fs::read(partial("sha256-tree", &expired_there)).unwrap(), b"another build's, expired");
    assert_eq!(fs::read_to_string(&log).unwrap().lines().count(), 1, "compacted to this build's one record");
}

/// (1) A RECORD LINE WHOSE OFFSET PASSES ITS LENGTH IS NO RECORD
/// (`UploadRecord`: "ITS OFFSET NEVER PASSES ITS LENGTH", the log's line the
/// one gate of that invariant a line from disk meets): no act writes one,
/// and standing, its upload would refuse every resume and never reach a
/// finish, counted past its length in its principal's pending bytes. It
/// reads as a lost record does — its partial an orphan open removes — while
/// the same line with its offset AT its length stands.
#[test]
fn a_record_line_whose_offset_passes_its_length_is_no_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let past = UploadId::parse("0123456789abcdef0123456789abcdef").unwrap();
    let at = UploadId::parse("fedcba9876543210fedcba9876543210").unwrap();
    let partial = |id: &UploadId| root.join("blake3").join(format!(".upload-{}", id.to_hex()));
    fs::create_dir_all(root.join("blake3")).unwrap();
    fs::write(partial(&past), [b'x'; 11]).unwrap();
    fs::write(partial(&at), [b'x'; 10]).unwrap();
    let line = |id: &UploadId, offset: u64| {
        let v = serde_json::json!({
            "designation": "blake3", "expires": 9_999, "id": id.to_hex(),
            "interval": 1_000, "key": "k", "length": 10, "offset": offset,
        });
        format!("{v}\n")
    };
    fs::write(root.join("uploads.log"), line(&past, 11) + &line(&at, 10)).unwrap();
    let store = open(&root, 1);
    assert_eq!(store.upload("k", &past, 1), None, "an offset past its length: no record");
    assert!(!partial(&past).exists(), "its partial an orphan open removes");
    let r = store.upload("k", &at, 1).expect("an offset at its length stands");
    assert_eq!((r.offset, r.length), (10, 10));
    assert_eq!(store.pending_bytes("k", 1, every_deposit_unplaced), 10, "the standing one's bytes alone");
}

/// (4) AT OPEN THE TWO ARE RECONCILED BOTH WAYS, and their lengths: a
/// partial no record names is removed in the designation directory this
/// build pins, and LEFT in one it does not — another build's (clause (4):
/// "in every designation directory under `blobs/` that this build's schemas
/// pin"), as the pruner's pass leaves it; a record whose partial is gone is
/// retired; a partial longer than its record's offset is cut back; a record
/// whose offset passes its partial's length is set back to the length, its
/// expiry kept (a copy that took the partial before its record); an expired
/// upload is retired and its partial removed; and the records log is
/// compacted to the current records. Beside them, every aside a crash left
/// is removed — and a name that only begins as an aside's is none, and is
/// left. The open's account (`Store::opened`) counts each act, one apiece,
/// the foreign directory's orphan and the name no aside has among none, and
/// the bytes those acts freed, each file's length and the cut-back's tail.
#[test]
fn open_reconciles_the_partials_and_the_records_both_ways() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let (kept, longer, shorter, gone, expired) = {
        let store = open(&root, 0);
        let kept = standing(&store, "k", 100, b"kept", 10);
        let longer = standing(&store, "k", 100, b"longer", 10);
        let shorter = standing(&store, "k", 100, b"shorter-shorter", 10);
        let gone = standing(&store, "k", 100, b"gone", 10);
        // Settled EARLIER than the rest, so its expiry comes first.
        let expired = standing(&store, "k", 100, b"expired", 0);
        (kept, longer, shorter, gone, expired)
    };
    let partial = |id: &UploadId| root.join("blake3").join(format!(".upload-{}", id.to_hex()));
    // Mutilations with no store open.
    fs::write(partial(&longer.id), b"longer plus a tail").unwrap();
    OpenOptions::new().write(true).open(partial(&shorter.id)).unwrap().set_len(3).unwrap();
    fs::remove_file(partial(&gone.id)).unwrap();
    fs::write(root.join("blake3").join(".upload-ffffffffffffffffffffffffffffffff"), b"orphan").unwrap();
    fs::create_dir_all(root.join("sha256-tree")).unwrap();
    fs::write(root.join("sha256-tree").join(".upload-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"), b"orphan too").unwrap();
    // An aside a replace left — a crash between the answer and the deferred
    // unlink — named by nothing; and a file whose name only begins as an
    // aside's, which no replace made.
    fs::write(root.join("blake3").join(format!(".retired-{}-0", hex_of(b"old"))), b"old").unwrap();
    fs::write(root.join("blake3").join(".retired-x"), b"not an aside").unwrap();
    let lines_before = fs::read_to_string(root.join("uploads.log")).unwrap().lines().count();
    assert!(lines_before > 5, "each standing upload wrote more than one line");
    // Reopened past `expired`'s expiry alone.
    let now = expired.expires;
    let store = open(&root, now);
    let opened = store.opened();
    assert_eq!(
        (opened.expired_uploads, opened.records_without_partial, opened.partials_cut_back, opened.records_set_back),
        (1, 1, 1, 1),
        "the open's account, act by act: {opened:?}"
    );
    assert_eq!((opened.orphan_partials, opened.asides), (1, 1), "this build's orphan and the aside alone: {opened:?}");
    assert_eq!(
        opened.bytes_freed,
        12 + 7 + 6 + 3,
        "the bytes the repairs freed: the cut-back's tail, the expired partial, the orphan and the aside: {opened:?}"
    );
    assert_eq!((opened.uploads, opened.leases, opened.root_made), (3, 0, false), "{opened:?}");
    assert_eq!((opened.uploads_log.cut, opened.uploads_log.unread), (None, 0), "a whole log, every line read");
    let r = store.upload("k", &kept.id, now).expect("kept stands");
    assert_eq!(r.offset, 4);
    assert_eq!(fs::metadata(partial(&kept.id)).unwrap().len(), 4);
    let r = store.upload("k", &longer.id, now).expect("longer stands");
    assert_eq!(r.offset, 6);
    assert_eq!(fs::metadata(partial(&longer.id)).unwrap().len(), 6, "cut back to the record's offset");
    let r = store.upload("k", &shorter.id, now).expect("shorter stands");
    assert_eq!(r.offset, 3, "set back to the partial's length");
    assert_eq!(r.expires, shorter.expires, "its expiry kept: a set-back receives no byte");
    assert!(store.upload("k", &gone.id, now).is_none(), "a record with no partial is retired");
    assert!(store.upload("k", &expired.id, now).is_none(), "an expired upload is retired");
    assert!(!partial(&expired.id).exists(), "and its partial removed");
    assert!(!root.join("blake3").join(".upload-ffffffffffffffffffffffffffffffff").exists(), "an orphan is removed");
    assert_eq!(
        fs::read(root.join("sha256-tree").join(".upload-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")).unwrap(),
        b"orphan too",
        "left under a designation this build pins no function for: another build's (clause (4))"
    );
    assert!(store.asides_of("blake3").unwrap().is_empty(), "an aside is removed at open");
    assert!(root.join("blake3").join(".retired-x").is_file(), "a name no aside has is left");
    assert_eq!(store.remove_aside("blake3", ".retired-x").unwrap(), None, "and is no aside to remove");
    assert_eq!(
        store.designation_dirs().unwrap(),
        vec!["blake3".to_string(), "sha256-tree".to_string()],
        "every directory under the root, the foreign one included"
    );
    let lines_after = fs::read_to_string(root.join("uploads.log")).unwrap().lines().count();
    assert_eq!(lines_after, 3, "compacted to the three current records");
    assert_eq!(store.pending_bytes("k", now, every_deposit_unplaced), 4 + 6 + 3);
    // The expired upload's partial would be a resume into nothing; the
    // standing ones resume at their reconciled offsets and finish whole.
    for (rec, head, tail) in [(&kept, b"kept".as_slice(), b"".as_slice()), (&longer, b"longer", b""), (&shorter, b"sho", b"rter")] {
        let r = store.upload("k", &rec.id, now).unwrap();
        let mut stream = store.resume("k", &r.id, r.offset, now).unwrap();
        let fill = vec![b'x'; 100 - head.len() - tail.len()];
        stream.append(tail, now).unwrap();
        stream.append(&fill, now).unwrap();
        let fin = stream.finish(INTERVAL, now).unwrap();
        let mut whole = head.to_vec();
        whole.extend_from_slice(tail);
        whole.extend(fill);
        assert_eq!(fin.hex, hex_of(&whole));
    }
}

/// (4) A PARTIAL THAT CANNOT BE READ FAILS THE OPEN AND RETIRES NOTHING
/// (clause (4) retires "a record that names no temp file", and a record
/// naming one that cannot be read still names it): the reconciliation
/// answers the failure rather than reading it as an absence, writing no
/// retirement a later open would remove the partial as an orphan for — the
/// failure naming the partial by its directory and the act, never by its
/// file name, an upload's identifier; once the partial can be read again,
/// the upload stands where its record left it, its bytes whole.
#[cfg(unix)]
#[test]
fn a_partial_that_cannot_be_read_fails_the_open_and_retires_nothing() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let rec = standing(&open(&root, 0), "k", 100, b"abc", 1);
    let designation_dir = root.join("blake3");
    let mode = fs::metadata(&designation_dir).unwrap().permissions();
    // Read and written, never searched: no partial in it can be stat'ed.
    fs::set_permissions(&designation_dir, fs::Permissions::from_mode(0o600)).unwrap();
    let opened = Store::open(&root, HORIZON, 2).map(drop).map_err(|e| (e.kind(), e.to_string()));
    fs::set_permissions(&designation_dir, mode).unwrap();
    let Err((kind, message)) = opened else {
        return; // a privileged process searches any directory: nothing to inject
    };
    assert_eq!(kind, std::io::ErrorKind::PermissionDenied, "the open answers the failure: {message}");
    assert!(message.starts_with("a partial in blobs/blake3/: stat: "), "named by its directory and its act: {message}");
    assert!(!message.contains(&rec.id.to_hex()), "never by its identifier: {message}");
    let store = open(&root, 3);
    assert_eq!(store.upload("k", &rec.id, 3).map(|r| r.offset), Some(3), "the upload stands where its record left it");
    assert_eq!(fs::read(designation_dir.join(format!(".upload-{}", rec.id.to_hex()))).unwrap(), b"abc", "its partial whole");
}

/// NOTHING OPEN ACTS ON IS FOLLOWED OR SHARED
/// (`blobs::refuse_links_and_special_files`; `media.md` §Recovery, "A
/// COMPROMISE's REMEDIATION DISCARDS EVERY MEDIA STORE BUT THE FILES"): a
/// link planted at a name open acts on — a symbolic one at a compaction
/// twin, a log, a partial a record names, a file at a hex name or the
/// designation directory; a second hard link at a twin, a log or a partial
/// — fails the open, and the file it names is untouched, where an open
/// through it would overwrite that file (the twin's rewrite), cut it at its
/// first line that is no JSON object (a log's tail check) or at the
/// record's offset (a partial's cut-back), or hand its directory to the
/// pruner as the designation's; the link gone, the board opens as it stood.
/// And a file at a hex name sharing its inode with an aside — a crash
/// between a replace's link and its rename — is the store's own: the open
/// passes it.
#[cfg(unix)]
#[test]
fn a_link_at_a_name_open_acts_on_fails_the_open_and_touches_nothing() {
    use std::os::unix::fs::symlink;
    const UNTOUCHED: &[u8] = b"bytes the store must not touch";
    // A board of its own per row: a deposit's file and a standing upload,
    // the records log four lines over one record, so an open past the walk
    // rewrites that log through its twin.
    let board = || {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("blobs");
        let store = open(&root, 0);
        let hex = put_whole(&store, "k", b"a deposit", 1).hex;
        let rec = standing(&store, "k", 100, b"abc", 2);
        drop(store);
        (dir, root, rec, hex)
    };
    for (at, symbolic) in [
        ("uploads.compact", true),
        ("leases.log", true),
        ("a partial a record names", true),
        ("a hex name", true),
        ("the designation directory", true),
        ("uploads.compact", false),
        ("leases.log", false),
        ("a partial a record names", false),
    ] {
        let (dir, root, rec, hex) = board();
        let name = match at {
            "a partial a record names" => root.join("blake3").join(format!(".upload-{}", rec.id.to_hex())),
            "a hex name" => root.join("blake3").join(&hex),
            "the designation directory" => root.join("blake3"),
            root_file => root.join(root_file),
        };
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let victim = outside.join("victim");
        fs::write(&victim, UNTOUCHED).unwrap();
        let moved = dir.path().join("moved");
        let stood = name.exists();
        if stood {
            fs::rename(&name, &moved).unwrap();
        }
        let label = format!("a {} link at {at}", if symbolic { "symbolic" } else { "second hard" });
        if symbolic {
            symlink(if at == "the designation directory" { &outside } else { &victim }, &name).unwrap();
        } else {
            fs::hard_link(&victim, &name).unwrap();
        }
        let opened = Store::open(&root, HORIZON, 3).map(drop).map_err(|e| e.kind());
        assert_eq!(opened, Err(std::io::ErrorKind::InvalidData), "{label}: fails the open");
        assert_eq!(fs::read(&victim).unwrap(), UNTOUCHED, "{label}: and the file it names is untouched");
        fs::remove_file(&name).unwrap();
        if stood {
            fs::rename(&moved, &name).unwrap();
        }
        let store = open(&root, 3);
        assert_eq!(store.upload("k", &rec.id, 3).map(|r| r.offset), Some(3), "{label} gone: the upload as it stood");
        assert_eq!(store.blob_size("blake3", &hex).unwrap(), Some(9), "{label} gone: and the deposit's file");
    }
    let (_dir, root, _, hex) = board();
    let designation_dir = root.join("blake3");
    fs::hard_link(designation_dir.join(&hex), designation_dir.join(format!(".retired-{hex}-0"))).unwrap();
    let store = open(&root, 3);
    assert_eq!(store.blob_size("blake3", &hex).unwrap(), Some(9), "a hex name an aside shares is the store's own");
    assert!(store.asides_of("blake3").unwrap().is_empty(), "and the aside is swept at open");
}

/// ONE REFUSAL NAMES EVERY PLANTED ENTRY, AND THE ACT FOR EACH KIND
/// (`blobs::refuse_links_and_special_files`): a hard-link copy taken of a
/// live board gives every log and partial a second link at once, so the
/// open refuses once — not once per entry over as many starts — naming
/// each of a few: the log, the partial by its directory alone (its file
/// name an upload's identifier), and a symbolic link beside them; and it
/// says what makes each kind and the act that clears it. (Past eight
/// clauses the rest are counted by kind:
/// `a_refusal_over_a_tree_of_links_names_eight_clauses_and_counts_the_rest`.)
#[cfg(unix)]
#[test]
fn one_refusal_names_every_planted_entry_and_the_act_for_each_kind() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let rec = {
        let store = open(&root, 0);
        put_whole(&store, "k", b"a deposit", 1);
        standing(&store, "k", 100, b"abc", 2)
    };
    let copy = dir.path().join("copy");
    fs::create_dir(&copy).unwrap();
    fs::hard_link(root.join("uploads.log"), copy.join("uploads.log")).unwrap();
    fs::hard_link(root.join("blake3").join(format!(".upload-{}", rec.id.to_hex())), copy.join("partial")).unwrap();
    fs::remove_file(root.join("leases.log")).unwrap();
    symlink(copy.join("uploads.log"), root.join("leases.log")).unwrap();
    let refused = Store::open(&root, HORIZON, 3).map(drop).expect_err("the open is refused");
    assert_eq!(refused.kind(), std::io::ErrorKind::InvalidData, "{refused}");
    let message = refused.to_string();
    for named in [
        "blobs/ holds 3 entries the blob store never makes",
        "blobs/uploads.log has 2 links",
        "a partial in blobs/blake3/ has 2 links",
        "blobs/leases.log is a symbolic link",
        "a hard-link copy (cp -al, ln) makes one",
        "from the board directory's copy (Restore)",
    ] {
        assert!(message.contains(named), "{named:?} in the one refusal: {message}");
    }
    assert!(!message.contains(&rec.id.to_hex()), "a partial never named by its identifier: {message}");
    assert!(!message.contains(&dir.path().display().to_string()), "never an absolute path: {message}");
}

/// ONE REFUSAL STAYS ONE LINE A LOG COLLECTOR KEEPS WHOLE
/// (`blobs::refuse_links_and_special_files`, its `PLANTED_NAMED`): a tree
/// linked back from another disk — a symbolic link at every hex name —
/// beside a hard-link copy's partials refuses once, counting every entry,
/// naming eight clauses — the three partials one clause, their directory
/// alone — and counting the rest by kind, the act for each kind at its end,
/// the whole under 4 KiB, where a clause per entry over ten thousand passes
/// the 16 KiB a container's log driver splits a line at.
#[cfg(unix)]
#[test]
fn a_refusal_over_a_tree_of_links_names_eight_clauses_and_counts_the_rest() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    drop(open(&root, 0));
    let designation_dir = root.join("blake3");
    fs::create_dir(&designation_dir).unwrap();
    let elsewhere = dir.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    for i in 0u8..3 {
        let partial = designation_dir.join(format!(".upload-{}", &hex_of(&[i])[..32]));
        fs::write(&partial, b"bytes received").unwrap();
        fs::hard_link(&partial, elsewhere.join(format!("partial-{i}"))).unwrap();
    }
    for i in 0u32..200 {
        let hex = hex_of(&i.to_be_bytes());
        let moved = elsewhere.join(&hex);
        fs::write(&moved, b"a deposit moved to another disk").unwrap();
        symlink(&moved, designation_dir.join(&hex)).unwrap();
    }
    let refused = Store::open(&root, HORIZON, 1).map(drop).expect_err("the open is refused");
    assert_eq!(refused.kind(), std::io::ErrorKind::InvalidData, "{refused}");
    let message = refused.to_string();
    assert!(
        message.starts_with("blobs/ holds 203 entries the blob store never makes"),
        "every entry counted: {message}"
    );
    assert!(
        message.contains("written through them: 3 partials in blobs/blake3/ have 2 links; blobs/blake3/"),
        "the partials one clause, before the names: {message}"
    );
    assert_eq!(message.matches(" is a symbolic link").count(), 7, "eight clauses named in all: {message}");
    assert!(message.contains("; and 193 more symbolic links."), "the rest counted by kind: {message}");
    assert!(message.contains("(cp -al, ln)") && message.contains("(Restore)"), "the act for each kind: {message}");
    assert!(message.ends_with(" Then try again."), "its act ends it: {message}");
    assert!(message.len() < 4096, "{} bytes: {message}", message.len());
}

/// AN OPEN REFUSED AT A LOG NAMES IT, ITS ACT AND ITS CAUSE, THE KIND KEPT
/// (`blobs.rs`, EVERY FAILURE NAMES ITS FILE AND ITS ACT; `operations.md`
/// §1.1 row 2's form): a lease log the process may not read refuses the
/// open with `blobs/leases.log: read: Permission denied …` — the text the
/// daemon's `blob store: {e}` carries whole — and never names the file by
/// its absolute path.
#[cfg(unix)]
#[test]
fn an_open_refused_at_a_log_names_the_log_and_its_act_and_keeps_the_kind() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    drop(open(&root, 0));
    let log = root.join("leases.log");
    fs::set_permissions(&log, fs::Permissions::from_mode(0o000)).unwrap();
    // A privileged process reads a mode-000 file: nothing to inject.
    let privileged = fs::File::open(&log).is_ok();
    let refused = (!privileged).then(|| Store::open(&root, HORIZON, 1).map(drop));
    fs::set_permissions(&log, fs::Permissions::from_mode(0o600)).unwrap();
    let Some(refused) = refused else { return };
    let e = refused.expect_err("the open is refused at the log");
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "the kind kept: {e}");
    assert!(e.to_string().starts_with("blobs/leases.log: read: "), "the file and the act named: {e}");
    assert!(!e.to_string().contains(&dir.path().display().to_string()), "never an absolute path: {e}");
}

/// WHAT THE OPEN FOUND ABSENT IT ANSWERS MADE (`Store::opened`): a fresh
/// root is made, both its logs with it, and the account says so; a reopen
/// finds all three standing; and a lease log removed from beside a standing
/// root — a copy that stopped before it, a hand that removed it — is made
/// empty, every lease it held reading as none, and answered absent, which
/// nothing else would say.
#[test]
fn what_the_open_found_absent_it_answers_made() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let hex = {
        let store = open(&root, 0);
        let opened = store.opened();
        assert!(opened.root_made, "a fresh root is made: {opened:?}");
        assert!(opened.uploads_log.absent && opened.leases_log.absent, "and both its logs: {opened:?}");
        put_whole(&store, "k", b"a deposit", 1).hex
    };
    let store = open(&root, 2);
    let opened = store.opened();
    assert!(!opened.root_made && !opened.uploads_log.absent && !opened.leases_log.absent, "{opened:?}");
    assert_eq!(opened.leases, 1, "{opened:?}");
    drop(store);
    fs::remove_file(root.join("leases.log")).unwrap();
    let store = open(&root, 3);
    let opened = store.opened();
    assert_eq!((opened.root_made, opened.uploads_log.absent, opened.leases_log.absent), (false, false, true));
    assert_eq!(opened.leases_log.name, "blobs/leases.log", "the log named by its place");
    assert_eq!(opened.leases, 0, "every lease it held reads as none");
    assert_eq!(store.lease_state("k", "blake3", &hex, 3), LeaseState::None);
}

/// A DAMAGED LOG's CUT IS TOLD FROM A CRASH's, AND KEPT (`Store::opened`,
/// `TailCut`, `LogRead::kept`): three deposits' lease lines. A crash's tail
/// — bytes of a line with no newline — is cut taking no whole line, its
/// first line torn, nothing kept, and every lease stands. Then the last line
/// damaged in place, whole and ended by its newline — no whole line after it,
/// yet damage, told by its first line being whole: cut and KEPT beside the
/// log, byte for byte, as `blobs/leases.log.cut-{byte}`. Then the first line
/// damaged in place — a bad sector, a damaged copy — and the open's tail
/// check cuts at it, the two whole lines after it with it, every byte kept
/// first: their leases, which a PUT answered 200 over, read as none, and the
/// account names the cut, the two lines among it and the kept file.
#[test]
fn a_damaged_lease_log_is_cut_and_the_open_answers_the_whole_lines_it_took() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let hexes: Vec<String> = {
        let store = open(&root, 0);
        (0u8..3).map(|i| put_whole(&store, "k", &[i; 4], 1).hex).collect()
    };
    let log = root.join("leases.log");
    let whole = fs::read(&log).unwrap();
    let mut torn = whole.clone();
    torn.extend_from_slice(b"{\"designation\":\"bla");
    fs::write(&log, &torn).unwrap();
    let store = open(&root, 2);
    let read = &store.opened().leases_log;
    let cut = read.cut.expect("the torn tail cut");
    assert_eq!((read.lines, cut.at, cut.bytes(), cut.lines_after), (3, whole.len() as u64, 19, 0), "{read:?}");
    assert!(!cut.first_whole && !cut.damage(), "a crash's: its first line torn: {read:?}");
    assert_eq!(read.kept, None, "a crash's tail is cut and gone, nothing kept");
    assert_eq!(store.opened().leases, 3, "a crash's tail: every lease stands");
    drop(store);
    // The LAST line damaged, whole: no whole line after it, and damage all
    // the same — kept, then cut.
    let last_line_at =
        whole[..whole.len() - 1].iter().rposition(|&b| b == b'\n').map_or(0, |at| at + 1);
    let mut last_damaged = whole.clone();
    last_damaged[last_line_at] = b'x';
    fs::write(&log, &last_damaged).unwrap();
    let store = open(&root, 3);
    let read = &store.opened().leases_log;
    let cut = read.cut.expect("trust ends at the damaged last line");
    assert_eq!(
        (read.lines, cut.at, cut.len, cut.lines_after),
        (2, last_line_at as u64, whole.len() as u64, 0),
        "{read:?}"
    );
    assert!(cut.first_whole && cut.damage(), "a damaged last line is damage: {read:?}");
    let kept = format!("blobs/leases.log.cut-{last_line_at}");
    assert_eq!(read.kept.as_deref(), Some(kept.as_str()), "{read:?}");
    assert_eq!(
        fs::read(dir.path().join(&kept)).unwrap(),
        &last_damaged[last_line_at..],
        "kept byte for byte"
    );
    assert_eq!(store.opened().leases, 2, "the lease the cut took");
    drop(store);
    fs::remove_file(dir.path().join(&kept)).unwrap();
    // The FIRST line damaged: the two whole lines after it go with it, kept.
    let mut damaged = fs::read(&log).unwrap();
    damaged[0] = b'x';
    fs::write(&log, &damaged).unwrap();
    let store = open(&root, 4);
    let read = &store.opened().leases_log;
    let cut = read.cut.expect("trust ends at the damaged line");
    assert_eq!(
        (read.lines, cut.at, cut.len, cut.lines_after),
        (0, 0, damaged.len() as u64, 1),
        "{read:?}"
    );
    assert!(cut.damage(), "{read:?}");
    assert_eq!(read.kept.as_deref(), Some("blobs/leases.log.cut-0"), "{read:?}");
    assert_eq!(
        fs::read(root.join("leases.log.cut-0")).unwrap(),
        damaged,
        "every byte from the cut on"
    );
    assert_eq!(fs::metadata(&log).unwrap().len(), 0, "cut at the damaged line");
    assert_eq!(store.opened().leases, 0, "the leases the cut took");
    for hex in &hexes[..2] {
        assert_eq!(
            store.lease_state("k", "blake3", hex, 4),
            LeaseState::None,
            "{hex}: answered over, and gone"
        );
    }
}

/// THE INSPECTION REFUSES WHAT THE OPEN REFUSES, AND NEVER HANGS
/// (`Store::inspect`): a hard-link copy of a live board — its logs sharing
/// their inodes with the board's, no copy at all — is refused, naming each
/// log and the act; and a FIFO at the lease log's name, whose read would
/// wait for good, is refused inside a bounded wait, named.
#[cfg(unix)]
#[test]
fn the_inspection_refuses_what_the_open_refuses_and_never_hangs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    drop(open(&root, 0));
    let copy = dir.path().join("copy").join("blobs");
    fs::create_dir_all(&copy).unwrap();
    for log in ["uploads.log", "leases.log"] {
        fs::hard_link(root.join(log), copy.join(log)).unwrap();
    }
    let refused = Store::inspect(&copy).expect_err("a hard-link copy is no copy");
    assert_eq!(refused.kind(), std::io::ErrorKind::InvalidData, "{refused}");
    for named in ["blobs/uploads.log has 2 links", "blobs/leases.log has 2 links", "(cp -al, ln)"] {
        assert!(refused.to_string().contains(named), "{named:?}: {refused}");
    }
    fs::remove_file(root.join("leases.log")).unwrap();
    let made = std::process::Command::new("mkfifo").arg(root.join("leases.log")).status().expect("mkfifo runs");
    assert!(made.success(), "a FIFO made at the lease log's name");
    let (tx, rx) = std::sync::mpsc::channel();
    // On a thread of its own: an inspection that read the FIFO would wait for good.
    std::thread::spawn(move || {
        let _ = tx.send(Store::inspect(&root).map(drop).map_err(|e| (e.kind(), e.to_string())));
    });
    let inspected = rx.recv_timeout(Duration::from_secs(5)).expect("the inspection answers inside a bounded wait");
    let (kind, message) = inspected.expect_err("a FIFO refuses the inspection");
    assert_eq!(kind, std::io::ErrorKind::InvalidData, "{message}");
    assert!(message.contains("blobs/leases.log is a special file"), "named: {message}");
}

/// A SPECIAL FILE AT A NAME OPEN ACTS ON FAILS THE OPEN AND NEVER HANGS IT
/// (`blobs::refuse_links_and_special_files`): a FIFO planted at the lease
/// log's name — where open's read of the log would wait for good on a writer
/// that never comes — fails the open as `InvalidData`, naming it, inside a
/// bounded wait.
#[cfg(unix)]
#[test]
fn a_special_file_at_a_name_open_acts_on_fails_the_open_and_never_hangs_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    drop(open(&root, 0));
    let log = root.join("leases.log");
    fs::remove_file(&log).unwrap();
    let made = std::process::Command::new("mkfifo").arg(&log).status().expect("mkfifo runs");
    assert!(made.success(), "a FIFO made at the lease log's name");
    let (tx, rx) = std::sync::mpsc::channel();
    // On a thread of its own: an open that read the FIFO would wait for good.
    std::thread::spawn(move || {
        let _ = tx.send(Store::open(&root, HORIZON, 1).map(drop).map_err(|e| (e.kind(), e.to_string())));
    });
    let opened = rx.recv_timeout(Duration::from_secs(5)).expect("the open answers inside a bounded wait");
    let (kind, message) = opened.expect_err("a FIFO fails the open");
    assert_eq!(kind, std::io::ErrorKind::InvalidData, "{message}");
    assert!(message.contains("blobs/leases.log is a special file"), "named: {message}");
}

/// THE UPLOAD LOG's DOOR WALKS BEFORE IT READS, AND NEVER HANGS
/// (`Store::refuse_uploads_of_another_function`): a FIFO planted at the
/// upload log's name — where the door's read of the log would wait for good
/// on a writer that never comes — is refused by the door's own walk, named,
/// inside a bounded wait, whatever its caller ran before it.
#[cfg(unix)]
#[test]
fn the_upload_logs_door_walks_before_it_reads_and_never_hangs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    drop(open(&root, 0));
    let log = root.join("uploads.log");
    fs::remove_file(&log).unwrap();
    let made = std::process::Command::new("mkfifo").arg(&log).status().expect("mkfifo runs");
    assert!(made.success(), "a FIFO made at the upload log's name");
    let (tx, rx) = std::sync::mpsc::channel();
    // On a thread of its own: a door that read the FIFO would wait for good.
    std::thread::spawn(move || {
        let _ = tx.send(Store::refuse_uploads_of_another_function(&root).map_err(|e| (e.kind(), e.to_string())));
    });
    let answered = rx.recv_timeout(Duration::from_secs(5)).expect("the door answers inside a bounded wait");
    let (kind, message) = answered.expect_err("a FIFO refuses the door");
    assert_eq!(kind, std::io::ErrorKind::InvalidData, "{message}");
    assert!(message.contains("blobs/uploads.log is a special file"), "named: {message}");
}

/// A HARD-LINK PROBE A KILL CUT SHORT IS THE NEXT OPEN's TO CLEAR
/// (`blobs::probe_hard_link`): every open makes a second name for a file
/// inside `.link-probe/` under the root — the one capability the store needs
/// that no other act of the open exercises — and removes it before it
/// answers, so an open leaves nothing; a kill between the link and its
/// removal leaves the directory holding two names of one file, which the
/// walk passes over, its name no designation's, and the next open removes
/// it and serves: no store that answers has it standing, so no listing of
/// the designation directories meets it.
#[test]
fn a_hard_link_probe_a_kill_cut_short_is_cleared_by_the_next_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let probe = root.join(".link-probe");
    let hex = put_whole(&open(&root, 0), "k", b"a deposit", 1).hex;
    assert!(!probe.exists(), "an open's probe leaves nothing");
    fs::create_dir(&probe).unwrap();
    fs::write(probe.join("a"), b"").unwrap();
    fs::hard_link(probe.join("a"), probe.join("b")).unwrap();
    let store = open(&root, 2);
    assert!(!probe.exists(), "the probe a kill cut short, removed");
    assert_eq!(store.designation_dirs().unwrap(), vec!["blake3".to_string()], "no listing meets it");
    assert_eq!(store.blob_size("blake3", &hex).unwrap(), Some(9), "and the board serves as it stood");
}

/// OPEN COMPACTS EACH LOG TO ITS CURRENT RECORDS — NONE AMONG THEM — OVER
/// WHAT A KILL MID-COMPACTION LEFT BESIDE IT: a board whose uploads have all
/// finished or ended and whose every lease has lapsed past the horizon
/// reopens to two empty logs, and a half-written `.compact` twin a kill left
/// beside each is written over and renamed onto its log. (That open never
/// reads such a twin in place of its log — which, where nothing stands,
/// would answer the same nothing — is
/// `a_half_written_compaction_twin_is_never_read_in_place_of_its_log`'s claim.)
#[test]
fn open_compacts_both_logs_to_nothing_over_a_stale_compaction_twin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    {
        let store = open(&root, 0);
        put_whole(&store, "k", b"finished", 1);
        let ended = standing(&store, "k", 10, b"ended", 1);
        store.end_upload("k", &ended.id, 2).unwrap();
    }
    for twin in ["uploads.compact", "leases.compact"] {
        fs::write(root.join(twin), b"{\"half\":\"writ").unwrap();
    }
    let now = 1 + INTERVAL_MS + HORIZON_MS;
    let store = open(&root, now);
    for log in ["uploads.log", "leases.log"] {
        assert_eq!(fs::read_to_string(root.join(log)).unwrap(), "", "{log}: no current record, no line");
    }
    for twin in ["uploads.compact", "leases.compact"] {
        assert!(!root.join(twin).exists(), "{twin}: written over and renamed onto its log");
    }
    assert_eq!((store.uploads_of("k", now), store.live_leases_of("k", now)), (vec![], vec![]));
}

/// A KILL MID-COMPACTION LEAVES THE OLD LOG WHOLE, AND OPEN READS THE LOG —
/// NEVER THE TWIN BESIDE IT (`jsonl.rs`: "a crash mid-compaction leaves the
/// old log whole or the new one, never a mix"): beside each log holding a
/// current record — a standing upload at its offset, a live lease that
/// replaced an earlier line — stands the half-written `.compact` twin a kill
/// left; the reopen answers what the logs hold, each compacted from itself,
/// where a twin read or renamed in place of its log would answer neither.
#[test]
fn a_half_written_compaction_twin_is_never_read_in_place_of_its_log() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let (rec, hex) = {
        let store = open(&root, 0);
        put_whole(&store, "k", b"leased", 1);
        let hex = put_whole(&store, "k", b"leased", 2).hex; // a re-PUT: two lease lines, one current
        (standing(&store, "k", 10, b"abc", 3), hex)
    };
    for twin in ["uploads.compact", "leases.compact"] {
        fs::write(root.join(twin), b"{\"half\":\"writ").unwrap();
    }
    let store = open(&root, 4);
    assert_eq!(store.upload("k", &rec.id, 4).map(|r| r.offset), Some(3), "the standing upload, as its log held it");
    assert_eq!(
        store.lease_state("k", "blake3", &hex, 4),
        LeaseState::Live { size: 6, expires: 2 + INTERVAL_MS },
        "the live lease, as its log held it"
    );
    for log in ["uploads.log", "leases.log"] {
        assert_eq!(fs::read_to_string(root.join(log)).unwrap().lines().count(), 1, "{log}: compacted from itself");
    }
    for twin in ["uploads.compact", "leases.compact"] {
        assert!(!root.join(twin).exists(), "{twin}: written over and renamed onto its log");
    }
}

/// THE OPEN FREES ROOM BEFORE IT ASKS FOR ANY (`Store::open`, "WHAT FREES
/// ROOM, BEFORE WHAT TAKES IT"): the asides swept and an expired upload's
/// partial removed before the lease log's twin and the probe's directory are
/// asked for — an obstacle at each in the full volume's place: a directory
/// at the twin's name, then a name in the probe's directory no probe makes.
/// Each open is refused there, named, the aside and the expired partial
/// already gone, the room their removal made already the volume's; the
/// obstacles gone, the board opens.
#[test]
fn the_open_frees_room_before_it_asks_for_any() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let expiring = {
        let store = open(&root, 0);
        put_whole(&store, "k", b"leased twice", 1);
        put_whole(&store, "k", b"leased twice", 2); // two lease lines over one lease: rewritten at open
        standing(&store, "k", 100, b"expires", 3)
    };
    let designation_dir = root.join("blake3");
    let partial = designation_dir.join(format!(".upload-{}", expiring.id.to_hex()));
    let aside = |n: u64| designation_dir.join(format!(".retired-{}-{n}", hex_of(b"a replaced instance")));
    let now = expiring.expires;
    fs::write(aside(90), b"a replaced instance a crash left").unwrap();
    fs::create_dir(root.join("leases.compact")).unwrap();
    let refused = Store::open(&root, HORIZON, now).map(drop).expect_err("the twin cannot be made");
    assert!(refused.to_string().starts_with("blobs/leases.compact: create: "), "{refused}");
    assert!(!aside(90).exists(), "the aside swept before the twin was asked for");
    assert!(!partial.exists(), "the expired partial removed before it");
    fs::remove_dir(root.join("leases.compact")).unwrap();
    fs::write(aside(91), b"another").unwrap();
    fs::create_dir(root.join(".link-probe")).unwrap();
    fs::write(root.join(".link-probe").join("c"), b"no probe's name").unwrap();
    let refused = Store::open(&root, HORIZON, now).map(drop).expect_err("the probe cannot clear its directory");
    assert!(refused.to_string().starts_with("blobs/.link-probe/: remove: "), "{refused}");
    assert!(!aside(91).exists(), "the aside swept before the probe");
    fs::remove_dir_all(root.join(".link-probe")).unwrap();
    let store = open(&root, now);
    assert_eq!(store.upload("k", &expiring.id, now), None, "the expired upload removed");
}

/// THE ROOT's OWN ENTRY IS MADE DURABLE AT EVERY OPEN (`Store::open`; the
/// register M-I5 (a), a directory's entry durable only at its parent's
/// fsync): the open fsyncs the board's own directory after the root, so a
/// `blobs/` a first start made outlives a power loss with every deposit in
/// it. Injected by the board's directory itself, written and searched but
/// not read: the first open makes the root and meets the board's fsync
/// refused, failing named, the kind kept; the next, the root standing, meets
/// it again, as an open makes every act of its own again, rather than
/// serving over an entry no fsync made durable; readable, the board opens.
#[cfg(unix)]
#[test]
fn every_open_makes_the_roots_own_entry_durable() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let board = dir.path().join("board");
    fs::create_dir(&board).unwrap();
    let root = board.join("blobs");
    let mode = fs::metadata(&board).unwrap().permissions();
    fs::set_permissions(&board, fs::Permissions::from_mode(0o300)).unwrap();
    // A privileged process opens any directory: nothing to inject.
    let privileged = fs::File::open(&board).is_ok();
    let opens = (!privileged).then(|| {
        let first = Store::open(&root, HORIZON, 0).map(drop).map_err(|e| (e.kind(), e.to_string()));
        let made = root.is_dir();
        let again = Store::open(&root, HORIZON, 1).map(drop).map_err(|e| (e.kind(), e.to_string()));
        (first, made, again)
    });
    fs::set_permissions(&board, mode).unwrap();
    let Some((first, made, again)) = opens else { return };
    for (opened, at) in [(first, "the first open"), (again, "the next, the root standing")] {
        let (kind, message) = opened.expect_err(at);
        assert_eq!(kind, std::io::ErrorKind::PermissionDenied, "{at}: the kind kept: {message}");
        assert!(message.starts_with("board/: fsync: "), "{at}: the board's directory named by its place: {message}");
    }
    assert!(made, "the root made before the board's fsync was refused");
    drop(open(&root, 2));
}
