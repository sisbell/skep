//! THE OPERATOR's TOOLS over a board directory (`media.md` §Recovery, "THE
//! OPERATOR CAN LIST THE HOLES", "AND IS RESTORED BY THE OPERATOR's OWN
//! PULL", "NEITHER OPENS THE STORE AS skepd DOES"; the register M-I5 (d),
//! M-I5 (e), M-I6 (d), M-I6 (f); DOCTRINE D9; the ruling mt-1): the
//! INVENTORY over a stopped board — the holes by kind of fault, each
//! account's base and pending bytes, the bytes no account's scope holds and
//! the venue total, the standing and
//! expired uploads, the halt marks and a foreign designation directory —
//! writing nothing under `blobs/` and refused beside a serving daemon at
//! the kernel's lock; and the PULL — a file a committed cell names restored
//! by the PUT's order, no lease, no record, no journal entry; a file no
//! cell names refused; beside a serving daemon, held to the inventory's
//! hash, the daemon's fetch serving the restored file at its next read —
//! and the two subcommands of the one binary the operator already has.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use serde_json::Value;
use skepd::tools::{self, HoleCheck, ToolError};

use crate::common;
use crate::media::{seed_pre_fence_draft, unknown_schema_value};
use common::*;

/// Every file under `blobs/` with its length and its modification time —
/// what the inventory must leave exactly as it found it.
fn tree(root: &Path) -> BTreeMap<PathBuf, (u64, SystemTime)> {
    fn walk(dir: &Path, out: &mut BTreeMap<PathBuf, (u64, SystemTime)>) {
        for entry in fs::read_dir(dir).expect("a directory") {
            let entry = entry.expect("an entry");
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                let meta = fs::metadata(&path).expect("metadata");
                out.insert(path, (meta.len(), meta.modified().expect("mtime")));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, &mut out);
    out
}

/// The holes of an inventory as `(hash, fault)`, in hash order.
fn holes_of(v: &Value) -> Vec<(String, String)> {
    v["holes"]
        .as_array()
        .expect("holes")
        .iter()
        .map(|h| (h["hash"].as_str().expect("hash").to_string(), h["fault"].as_str().expect("fault").to_string()))
        .collect()
}

/// The accounts of an inventory as `principal → (account, base, pending)`.
fn accounts_of(v: &Value) -> BTreeMap<u64, (Option<String>, u64, u64)> {
    v["accounts"]
        .as_array()
        .expect("accounts")
        .iter()
        .map(|a| {
            (
                a["principal"].as_u64().expect("principal"),
                (a["account"].as_str().map(str::to_string), a["base"].as_u64().expect("base"), a["pending"].as_u64().expect("pending")),
            )
        })
        .collect()
}

/// M-I5 (d), M-I6 (d), (f), D9 — THE INVENTORY over a stopped board: a
/// file absent at its hex, one present at another length and one present
/// and re-hashing to other bytes are the three holes, each with the cells
/// naming it; each account's base is the index's number and its pending
/// bytes its live leases on hashes none of its cells names plus its
/// standing uploads' bytes; a live lease another build wrote, its key
/// spelling no principal of this build, is UNATTRIBUTED — in no account's
/// scope — and the venue total is their sum with the unattributed bytes, the
/// gate's own figure under the gate's own pending rule; the standing and the
/// expired uploads by count; a foreign designation directory named; the
/// re-hash skipped by `--no-rehash` leaves the hash hole unfound; every
/// file under `blobs/` and every journal segment is left byte for byte and
/// mtime for mtime as found — the inventory records no read and writes
/// nothing there; a stray `checkpoint.tmp` a crash left is removed by the
/// engine's open, as every open removes one, and reported by its size as
/// `journal.stray_checkpoint_removed`, an open that found none reporting
/// `null`; a halt mark the walk finds is listed; and beside a serving
/// daemon the inventory is refused at the kernel's lock.
#[test]
fn the_inventory_lists_the_holes_the_accounts_and_the_venue_total_and_writes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let a_bytes = seeded_bytes(3_000, 1);
    let b_bytes = seeded_bytes(4_000, 2);
    let c_bytes = seeded_bytes(5_000, 3);
    let d_bytes = seeded_bytes(6_000, 4);
    let stranger_principal;
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        for bytes in [&a_bytes, &b_bytes, &c_bytes] {
            put_whole(port, &owner, bytes);
        }
        assert_eq!(insert_cell(port, &owner, &owner_draft(port, &owner), &a_bytes, 3_000), "ok");
        assert_eq!(insert_cell(port, &owner, &owner_draft(port, &owner), &b_bytes, 4_000), "ok");
        let stranger = seat_stranger(port, 971);
        stranger_principal = 971;
        put_whole(port, &stranger.session, &d_bytes);
        assert_eq!(insert_cell(port, &stranger.session, &create_doc(port, &stranger.session, &stranger.account), &d_bytes, 6_000), "ok");
        // A standing upload of the owner's with five bytes received, and
        // one expired by the wall clock.
        let (st, _, _) = blob_create(port, Some(&owner), 10, b"hello");
        assert_eq!(st, 200);
        sd.daemon().install_media_limits(None, None, Some(300), None);
        let (st, _, _) = blob_create(port, Some(&owner), 10, b"xyz");
        assert_eq!(st, 200);
        std::thread::sleep(std::time::Duration::from_millis(500));
        // Beside the serving daemon: refused at the kernel's lock.
        assert!(
            matches!(tools::inventory(dir.path(), HoleCheck::Rehash), Err(ToolError::JournalHeld(_))),
            "held by the daemon"
        );
        sd.shutdown();
    }
    let blobs = dir.path().join("blobs");
    let blake3_dir = blobs.join("blake3");
    // The damage: `b` absent, `a` short, `d` other bytes of the same length.
    fs::remove_file(blake3_dir.join(blob_hex(&b_bytes))).unwrap();
    fs::write(blake3_dir.join(blob_hex(&a_bytes)), &a_bytes[..2_999]).unwrap();
    fs::write(blake3_dir.join(blob_hex(&d_bytes)), seeded_bytes(6_000, 44)).unwrap();
    fs::create_dir(blobs.join("sha256-tree")).unwrap();
    // A lease another build wrote, its key spelling no principal of this
    // build: in no account's scope, and in the venue's total as the gate
    // counts it.
    let leases = blobs.join("leases.log");
    let mut log = fs::read_to_string(&leases).unwrap();
    log.push_str(&format!(
        "{{\"designation\":\"blake3\",\"expires\":{},\"hex\":\"{}\",\"key\":\"another-build\",\"size\":1000}}\n",
        u64::MAX,
        "ab".repeat(32)
    ));
    fs::write(&leases, log).unwrap();
    let before = tree(&blobs);
    // The journal's segments, byte for byte: the engine's open re-cuts the
    // active segment at its own end, which moves its mtime and no byte.
    let segments = |dir: &Path| -> BTreeMap<PathBuf, Vec<u8>> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "wal"))
            .map(|p| (p.clone(), fs::read(&p).unwrap()))
            .collect()
    };
    let segments_before = segments(dir.path());
    // A checkpoint a crash left half-written under the kernel's fixed temp
    // name: the engine's open removes it, as every open does, and says so.
    let stray = dir.path().join("checkpoint.tmp");
    fs::write(&stray, [0u8; 37]).unwrap();

    let v = tools::inventory(dir.path(), HoleCheck::Rehash).expect("the inventory");
    assert_eq!(tree(&blobs), before, "nothing under blobs/ written: every file's bytes and mtime as found");
    assert_eq!(segments(dir.path()), segments_before, "a cleanly closed journal's bytes are read and left as found");
    assert!(!stray.exists(), "the open removed the stray checkpoint");
    assert_eq!(v["journal"]["stray_checkpoint_removed"].as_u64(), Some(37), "{v}");

    let mut expected_holes = vec![(blob_hex(&a_bytes), "length".to_string()), (blob_hex(&b_bytes), "absent".to_string()), (blob_hex(&d_bytes), "hash".to_string())];
    expected_holes.sort();
    assert_eq!(holes_of(&v), expected_holes, "{v}");
    for hole in v["holes"].as_array().unwrap() {
        assert_eq!(hole["designation"].as_str(), Some("blake3"));
        assert_eq!(hole["cells"].as_array().map(Vec::len), Some(1), "one cell names each: {hole}");
    }
    let accounts = accounts_of(&v);
    assert_eq!(
        accounts.get(&CLAIMANT_PRINCIPAL),
        Some(&(Some(CLAIMANT_ACCOUNT.to_string()), 7_000, 5_005)),
        "the owner: the base a + b, the pending c's lease and the standing upload's five bytes: {v}"
    );
    assert_eq!(accounts.get(&stranger_principal).map(|(_, base, pending)| (*base, *pending)), Some((6_000, 0)), "{v}");
    assert_eq!(
        v["venue_total"].as_u64(),
        Some(7_000 + 5_005 + 6_000 + 1_000),
        "every own scope and the unattributed bytes: the gate's figure"
    );
    assert_eq!(v["unattributed"].as_u64(), Some(1_000), "{v}");
    assert_eq!(v["standing_uploads"].as_u64(), Some(1));
    assert_eq!(v["expired_uploads"].as_u64(), Some(1));
    assert_eq!(v["foreign_designations"], serde_json::json!(["sha256-tree"]));
    assert_eq!(v["halts"], serde_json::json!([]));
    assert_eq!(v["references"].as_u64(), Some(3));
    assert_eq!(v["cells"].as_u64(), Some(3));
    assert_eq!(v["rehashed"].as_bool(), Some(true));
    assert_eq!(v["orphan_partials"].as_u64(), Some(0));
    assert!(v["journal"]["log_position"].as_u64().is_some_and(|p| p > 0), "{v}");

    // Without the re-hash the hash hole is not found, and the cost is one
    // read per file fewer.
    let quick = tools::inventory(dir.path(), HoleCheck::LengthOnly).expect("the inventory");
    let without_rehash: Vec<(String, String)> = expected_holes.iter().filter(|(_, fault)| fault != "hash").cloned().collect();
    assert_eq!(holes_of(&quick), without_rehash, "{quick}");
    assert_eq!(quick["rehashed"].as_bool(), Some(false));
    assert!(quick["journal"]["stray_checkpoint_removed"].is_null(), "an open that found none: {quick}");
    assert_eq!(tree(&blobs), before);

    // A halt mark, planted as another build's writing: listed.
    seed_pre_fence_draft(dir.path(), CLAIMANT_PRINCIPAL, CLAIMANT_ACCOUNT, unknown_schema_value().as_bytes());
    let v = tools::inventory(dir.path(), HoleCheck::LengthOnly).expect("the inventory");
    let halts = v["halts"].as_array().expect("halts");
    assert_eq!(halts.len(), 1, "{v}");
    assert_eq!(halts[0]["fault"].as_str(), Some("unknown_cell_schema"));
    assert_eq!(halts[0]["kind"].as_str(), Some("1.1.0.1.0.1.0.3.89"));
    assert_eq!(v["references"].as_u64(), Some(3), "a halt mark is no reference");
}

/// M-I5 (d), M-I2 (e) — THE PULL: a file a committed cell names, lost from
/// `blobs/`, is restored by the pull — beside a SERVING daemon when held
/// to the inventory's hash, the journal left unopened, the daemon's fetch
/// serving the restored file at its next read, neither log of the store's
/// touched — and refused beside it where no hash is given, at the kernel's
/// lock; a file whose bytes are not the hash's is refused and leaves no
/// temp file; over the stopped board the journal is read, a file no cell
/// names is refused as a deposit the pull never makes, the named file is
/// restored, and a pull over a present file is a REPLACE of the same bytes.
#[test]
fn the_pull_restores_a_file_a_cell_names_and_deposits_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let scratch = tempfile::tempdir().expect("tempdir");
    let bytes = seeded_bytes(20_000, 7);
    let hex = blob_hex(&bytes);
    let source = scratch.path().join("the picture");
    fs::write(&source, &bytes).unwrap();
    let unnamed = scratch.path().join("another file");
    fs::write(&unnamed, b"bytes no cell names").unwrap();
    let blake3_dir = dir.path().join("blobs").join("blake3");
    let logs = |dir: &Path| -> Vec<(u64, SystemTime)> {
        ["uploads.log", "leases.log"]
            .iter()
            .map(|name| {
                let meta = fs::metadata(dir.join("blobs").join(name)).expect("the log");
                (meta.len(), meta.modified().expect("mtime"))
            })
            .collect()
    };
    let draft;
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        put_whole(port, &owner, &bytes);
        draft = owner_draft(port, &owner);
        assert_eq!(insert_cell(port, &owner, &draft, &bytes, bytes.len() as u64), "ok");
        let i = format!("{draft}.0.1.1");
        let (st, _, body) = fetch(port, Some(&owner), &i);
        assert_eq!((st, body.len()), (200, bytes.len()), "served before the hole");
        // THE HOLE.
        fs::remove_file(blake3_dir.join(&hex)).unwrap();
        let (st, _, body) = fetch(port, Some(&owner), &i);
        assert_eq!((st, json(&body)["error"].as_str()), (404, Some("blob_missing")));
        // Beside the serving daemon: no hash, the journal held.
        assert!(matches!(tools::pull(dir.path(), &source, None), Err(ToolError::JournalHeld(_))));
        let before = logs(dir.path());
        // A wrong hash: refused, no temp file left.
        let other = blob_hex(b"other bytes");
        assert!(matches!(tools::pull(dir.path(), &source, Some(&other)), Err(ToolError::Install(e)) if e.kind() == std::io::ErrorKind::InvalidData));
        assert!(!fs::read_dir(&blake3_dir).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with(".upload-")), "no temp file left");
        assert!(!blake3_dir.join(&hex).exists());
        // Held to the inventory's hash: installed beside the daemon.
        let pulled = tools::pull(dir.path(), &source, Some(&hex)).expect("the pull");
        assert_eq!((pulled.hex.as_str(), pulled.size), (hex.as_str(), bytes.len() as u64));
        assert_eq!(pulled.path, blake3_dir.join(&hex));
        assert_eq!(fs::read(&pulled.path).unwrap(), bytes, "the file whole at the name");
        assert_eq!(logs(dir.path()), before, "no lease and no record written");
        let (st, _, body) = fetch(port, Some(&owner), &i);
        assert_eq!((st, body == bytes), (200, true), "the daemon's fetch serves the restored file at its next read");
        assert!(!fs::read_dir(&blake3_dir).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with(".upload-")));
        sd.shutdown();
    }
    // Over the stopped board: the journal read, the index consulted.
    assert!(matches!(tools::pull(dir.path(), &unnamed, None), Err(ToolError::Unnamed { .. })), "a file no cell names is refused");
    assert!(!blake3_dir.join(blob_hex(b"bytes no cell names")).exists(), "and nothing is installed");
    fs::remove_file(blake3_dir.join(&hex)).unwrap();
    let pulled = tools::pull(dir.path(), &source, None).expect("the pull over the stopped board");
    assert_eq!(pulled.hex, hex);
    assert_eq!(fs::read(blake3_dir.join(&hex)).unwrap(), bytes);
    let again = tools::pull(dir.path(), &source, None).expect("a pull over a present file replaces it");
    assert_eq!(again.size, bytes.len() as u64);
    assert_eq!(fs::read(blake3_dir.join(&hex)).unwrap(), bytes);
    // The restored file serves on the next open too.
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (st, _, body) = fetch(port, Some(&owner), &format!("{draft}.0.1.1"));
    assert_eq!((st, body == bytes), (200, true));
    sd.shutdown();
}

/// THE TWO SUBCOMMANDS of the one binary (mt-1): `skepd inventory
/// --data-dir <dir>` prints the inventory's one object on stdout and exits
/// 0; `skepd pull --data-dir <dir> --hash <hex> <file>` prints one line and
/// exits 0, and a pull of a file no cell names, the journal read, exits 1
/// with one line on stderr; neither binds a port.
#[test]
fn the_binary_runs_the_inventory_and_the_pull_as_subcommands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let scratch = tempfile::tempdir().expect("tempdir");
    let bytes = seeded_bytes(2_000, 9);
    let hex = blob_hex(&bytes);
    let source = scratch.path().join("picture");
    fs::write(&source, &bytes).unwrap();
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        put_whole(port, &owner, &bytes);
        assert_eq!(insert_cell(port, &owner, &owner_draft(port, &owner), &bytes, 2_000), "ok");
        sd.shutdown();
    }
    let blake3_dir = dir.path().join("blobs").join("blake3");
    fs::remove_file(blake3_dir.join(&hex)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_skepd"))
        .args(["inventory", "--data-dir"])
        .arg(dir.path())
        .output()
        .expect("run the inventory");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: Value = serde_json::from_slice(&out.stdout).expect("one JSON object on stdout");
    assert_eq!(holes_of(&v), vec![(hex.clone(), "absent".to_string())]);
    assert_eq!(v["venue_total"].as_u64(), Some(2_000));
    let out = Command::new(env!("CARGO_BIN_EXE_skepd"))
        .args(["pull", "--data-dir"])
        .arg(dir.path())
        .args(["--hash", &hex])
        .arg(&source)
        .output()
        .expect("run the pull");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let line = String::from_utf8_lossy(&out.stdout);
    assert!(line.starts_with(&format!("pulled {hex} (2000 bytes) into ")), "{line}");
    assert_eq!(fs::read(blake3_dir.join(&hex)).unwrap(), bytes);
    let unnamed = scratch.path().join("unnamed");
    fs::write(&unnamed, b"no cell names these").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_skepd"))
        .args(["pull", "--data-dir"])
        .arg(dir.path())
        .arg(&unnamed)
        .output()
        .expect("run the pull");
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.lines().count() == 1 && err.contains("no committed reference cell names"), "{err}");
    let out = Command::new(env!("CARGO_BIN_EXE_skepd"))
        .args(["inventory", "--data-dir"])
        .arg(scratch.path())
        .output()
        .expect("run the inventory");
    assert_eq!(out.status.code(), Some(1), "no board: refused");
    assert!(String::from_utf8_lossy(&out.stderr).contains("no board at"));
}
