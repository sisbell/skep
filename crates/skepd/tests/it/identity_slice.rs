//! THE WORLD-SEATED IDENTITY SLICE, over the wire (AUTH-2.79–2.88, AUTH-2.95,
//! AUTH-6.20): the key table a reopen serves is the table the live fold
//! answered — every key the seeding named beside every key the holder
//! enrolled, a retired key retired still — because the engine steps the
//! slice at each credential deposit's commit and checkpoints it with the
//! world, and the daemon rebuilds nothing. The probe journal that found the
//! defect (a claimed board, an account seeded from the claimant's doc 1, one
//! own-space enroll) and its two retired-key variants; the pre-claim sibling
//! the old sort served, unchanged; `/op-at N key_set` equal to the live table
//! at every position, before and after a reopen (AUTH-2.95); and the load
//! rows at the daemon: a skipped checkpoint reported with the start point
//! (AUTH-2.86), a head with no start point refusing to serve (AUTH-2.88), and
//! a position below the resolving floor answering `history_reclaimed`
//! (AUTH-2.87). The slice-shaped bases — a checkpoint written without the
//! slice, over credential deposits and over none — are the engine's own
//! cells, which doctor a checkpoint's body under a valid header; here the
//! base that cannot stand in is a damaged one, and the chain is the same.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde_json::Value;
use skep_engine::{Engine, Seq};
use skep_identity::{encode_retire, Fingerprint};
use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig, SaltSource};
use skepd::{Daemon, DaemonError, EngineError, OpenError};

use crate::common;

use common::*;

/// The live `key_set` answer for `account` (`/op`).
fn key_set(port: u16, account: &str) -> Value {
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{account}"}}"#));
    assert_eq!(v["resp"].as_str(), Some("key_set"), "{v}");
    v
}

/// The `key_set` answer for `account` as of `at` (`/op-at`): the status and
/// the body.
fn key_set_at(port: u16, at: u64, account: &str) -> (u16, Value) {
    let (st, body) = http(
        port,
        "POST",
        "/op-at",
        None,
        format!(r#"{{"at":{at},"frame":{{"op":"key_set","account":"{account}"}}}}"#).as_bytes(),
    );
    (st, json(&body))
}

/// The fingerprints one of the answer's two lists names.
fn fps(v: &Value, field: &str) -> BTreeSet<String> {
    v[field]
        .as_array()
        .unwrap_or_else(|| panic!("{field}: {v}"))
        .iter()
        .map(|e| e["fingerprint"].as_str().expect("a fingerprint").to_string())
        .collect()
}

/// The fingerprint hex `key_set` publishes for a signing key.
fn fp(sk: &SigningKey) -> String {
    Fingerprint::of(&public_key_of(sk)).to_hex()
}

fn set(fps: &[&SigningKey]) -> BTreeSet<String> {
    fps.iter().map(|sk| fp(sk)).collect()
}

/// A TABLE as the wire shows it: the enrolled and the retired fingerprints.
type Table = (BTreeSet<String>, BTreeSet<String>);

fn table(v: &Value) -> Table {
    (fps(v, "enrolled"), fps(v, "retired"))
}

/// A fresh TOP-LEVEL account delegated from the boot session at the node's
/// next prefix, for `principal`.
fn delegate_next(port: u16, principal: u64) -> String {
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":{principal}}}"#),
    );
    acked_addr(&v)
}

/// The claimant's console: the claimant's device-key session.
fn console(port: u16) -> String {
    open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key())
}

/// A hire with the key's anchor flag NAMED — `common::hire` enrolls
/// device-grade keys alone. A top-level account's genesis enters no cone, so
/// the flag meets no anchor gate at the console (AUTH-3.21: the gate reads a
/// handoff's giver, and a top-level hire has none). Answers the hired
/// account's signed session under `key`.
fn hire_flagged(port: u16, console: &str, account: &str, principal: u64, key: &SigningKey, anchor: bool) -> String {
    let ordinal = next_content_ordinal(port, Some(console), CLAIMANT_DOC1);
    let atom = signed_atom(port, console, CLAIMANT_DOC1, T_ENROLL, &[account], &enroll_atom_flagged(&[(key, anchor)]));
    let v = op(
        port,
        Some(console),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{T_ENROLL}"}}"#
        ),
    );
    let atom_addr = acked_addr(&v);
    expect_resp(&typed_link(port, console, CLAIMANT_DOC1, &[&atom_addr], &[account], T_ENROLL), "ack_addr");
    open_signed_session(port, principal, key)
}

/// A record atom DECLARED under `ty` at `home`'s next position from `token`,
/// SIGNED by the session's key (the record grade above the claim), then its
/// `make_link` to `to` — the pair the fold folds at the link's commit.
fn land_record(port: u16, token: &str, home: &str, ty: &str, to: &str, atom: &str) {
    let atom = signed_atom(port, token, home, ty, &[to], atom);
    let ordinal = next_content_ordinal(port, Some(token), home);
    let v = op(
        port,
        Some(token),
        &format!(
            r#"{{"op":"insert","doc":"{home}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{ty}"}}"#
        ),
    );
    let atom_addr = acked_addr(&v);
    expect_resp(&typed_link(port, token, home, &[&atom_addr], &[to], ty), "ack_addr");
}

/// One retire record naming `keys`' fingerprints, as its atom JSON fragment.
fn retire_atom(keys: &[&SigningKey]) -> String {
    let parsed: Vec<Fingerprint> = keys.iter().map(|sk| Fingerprint::of(&public_key_of(sk))).collect();
    json_atom(&encode_retire(&parsed))
}

/// The hired account's doc 1, minted published from its own session.
fn mint_doc_one(port: u16, signed: &str, account: &str) -> String {
    acked_addr(&op(port, Some(signed), &create_frame(account, Some(true))))
}

/// THE PROBE JOURNAL (the hire, then the holder's own enroll): a hired
/// account `A` seeded from the claimant's doc 1 with `k1`, its doc 1, and `k2`
/// enrolled into it from `A`'s own `k1` session. Answers `A`, its doc 1 and
/// the `k1` session.
fn probe(port: u16, principal: u64, k1: &SigningKey, k2: &SigningKey, anchor_hire: bool) -> (String, String, String) {
    let console = console(port);
    let a = delegate_next(port, principal);
    let a_signed = hire_flagged(port, &console, &a, principal, k1, anchor_hire);
    let a_doc1 = mint_doc_one(port, &a_signed, &a);
    land_record(port, &a_signed, &a_doc1, T_ENROLL, &a, &enroll_atom(&[k2]));
    (a, a_doc1, a_signed)
}

/// The live tables of `accounts`, read off one head: every answer's `as_of`
/// is the same position, which is what the record is keyed by.
fn live_tables(port: u16, accounts: &[&str]) -> (u64, Vec<Table>) {
    let answers: Vec<Value> = accounts.iter().map(|a| key_set(port, a)).collect();
    let at = answers[0]["as_of"].as_u64().expect("as_of");
    for v in &answers {
        assert_eq!(v["as_of"].as_u64(), Some(at), "one head for the whole record: {v}");
    }
    (at, answers.iter().map(table).collect())
}

/// `/op-at at key_set` for every account equals the recorded tables, and
/// stamps `as_of: at` (AUTH-2.95's conformance clause).
fn assert_op_at_equals(port: u16, at: u64, accounts: &[&str], tables: &[Table]) {
    for (account, expected) in accounts.iter().zip(tables) {
        let (st, v) = key_set_at(port, at, account);
        assert_eq!(st, 200, "{account} at {at}: {v}");
        assert_eq!(v["as_of"].as_u64(), Some(at), "{v}");
        assert_eq!(&table(&v), expected, "{account} at {at}: the table as of the position is the live fold's at that head");
    }
}

/// The probe journal's defect, closed (AUTH-2.79, AUTH-2.80, AUTH-2.84): a
/// claimed board, an account seeded from the claimant's doc 1 with `k1`, one
/// own-space enroll of `k2` — the live set is `{k1, k2}`, `/op-at` at the
/// head answers `{k1, k2}` (the address-order rebuild answered `{k2}`), and
/// after a reopen the live set is still `{k1, k2}` (the rebuild dropped the
/// hire's key) and a session signed with `k1` opens (it was refused).
#[test]
fn a_reopen_keeps_the_hires_key_beside_the_holders_own() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (k1, k2) = (distinct_key(41), distinct_key(42));
    let (a, before, at) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let (a, _doc1, _k1_session) = probe(port, 4100, &k1, &k2, false);
        let live = key_set(port, &a);
        assert_eq!(table(&live), (set(&[&k1, &k2]), BTreeSet::new()), "live: both keys");
        let at = live["as_of"].as_u64().expect("as_of");
        let (st, hist) = key_set_at(port, at, &a);
        assert_eq!(st, 200, "{hist}");
        assert_eq!(table(&hist), table(&live), "/op-at at the head answers the live table");
        sd.shutdown();
        (a, table(&live), at)
    };
    let sd = spawn(dir.path());
    let port = sd.port();
    assert!(claimed(port), "the claim survives the reopen");
    let after = key_set(port, &a);
    assert_eq!(table(&after), before, "the reopen keeps every key the seeding named");
    let (st, hist) = key_set_at(port, at, &a);
    assert_eq!(st, 200, "{hist}");
    assert_eq!(table(&hist), before, "/op-at after the reopen answers the same table");
    // The hire's key still opens a session — the handshake reads the
    // recovered table.
    let _k1_session = open_signed_session(port, 4100, &k1);
    let _k2_session = open_signed_session(port, 4100, &k2);
    sd.shutdown();
}

/// The retired-key variants of the probe (AUTH-2.74, AUTH-2.98 across a
/// reopen): the natural rotation — the hire's key retired from the holder's
/// own session — keeps the retired key RETIRED after a reopen (the rebuild
/// re-admitted it); and the lost device — a device enrolled then retired
/// from the anchor session the hire seated — keeps the anchor and keeps the
/// device retired (the rebuild resurrected the device and dropped the
/// anchor). The pre-claim claimant's own table rides along unchanged.
#[test]
fn the_retired_key_variants_survive_a_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (k3, k4, k5, k6) = (distinct_key(43), distinct_key(44), distinct_key(45), distinct_key(46));
    let (rotated, lost_device, before, at) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        // The rotation: hire k3, enroll k4, retire k3 from the k4 session.
        let (rotated, doc1, _k3_session) = probe(port, 4200, &k3, &k4, false);
        let k4_session = open_signed_session(port, 4200, &k4);
        land_record(port, &k4_session, &doc1, T_RETIRE, &rotated, &retire_atom(&[&k3]));
        // The lost device: hire k5 as the ANCHOR, enroll k6 (a device) from
        // the k5 session, retire k6 from that same anchor session.
        let (lost_device, doc1, k5_session) = probe(port, 4300, &k5, &k6, true);
        land_record(port, &k5_session, &doc1, T_RETIRE, &lost_device, &retire_atom(&[&k6]));

        let accounts = [CLAIMANT_ACCOUNT, rotated.as_str(), lost_device.as_str()];
        let (at, tables) = live_tables(port, &accounts);
        assert_eq!(tables[1], (set(&[&k4]), set(&[&k3])), "the rotation: k4 enrolled, k3 retired");
        assert_eq!(tables[2], (set(&[&k5]), set(&[&k6])), "the lost device: the anchor kept, the device retired");
        assert_eq!(tables[0], (set(&[&anchor_key(), &device_key()]), BTreeSet::new()), "the claimant's own");
        assert_op_at_equals(port, at, &accounts, &tables);
        sd.shutdown();
        (rotated, lost_device, tables, at)
    };
    let sd = spawn(dir.path());
    let port = sd.port();
    let accounts = [CLAIMANT_ACCOUNT, rotated.as_str(), lost_device.as_str()];
    let (head, after) = live_tables(port, &accounts);
    assert_eq!(after, before, "every table survives the reopen as the live fold held it");
    assert_eq!(head, at, "a clean reopen commits nothing of its own");
    assert_op_at_equals(port, at, &accounts, &before);
    // The anchor the rebuild dropped still opens; the device it resurrected
    // does not.
    let _anchor = open_signed_session(port, 4300, &k5);
    let (st, _) = http(port, "GET", &format!("/challenge?principal={}", 4300), None, b"");
    assert_eq!(st, 200);
    assert!(
        !signed_session_opens(port, 4300, &k6),
        "a retired key establishes no session after the reopen"
    );
    sd.shutdown();
}

/// Whether a signed handshake as `principal` under `sk` opens a session —
/// `false` on `session_rejected`, where [`open_signed_session`] would panic.
fn signed_session_opens(port: u16, principal: u64, sk: &SigningKey) -> bool {
    let (st, body) = http(port, "GET", &format!("/challenge?principal={principal}"), None, b"");
    assert_eq!(st, 200);
    let nonce = json(&body)["nonce"].as_str().expect("nonce").to_string();
    let origin = format!("http://127.0.0.1:{port}");
    let sig = sign_session(sk, &origin, &nonce, principal);
    let (st, _) = http(
        port,
        "POST",
        "/session",
        None,
        format!(r#"{{"principal":{principal},"nonce":"{nonce}","origin":"{origin}","sig":"{sig}"}}"#).as_bytes(),
    );
    st == 200
}

/// THE PRE-CLAIM SIBLING (AUTH-2.62's own-space arm — the cell the old
/// sort's claims-last rule existed to serve): a second top-level account that
/// seeds ITSELF in its own doc 1 while the board is unclaimed is keyed by
/// that genesis, folded at its commit when the registry was its own space,
/// and keeps it across a reopen. The CLAIM that cell needed next is what
/// this daemon's own gate refuses — the claim-residue producer answers
/// `claim_residue` to a claim on a board carrying a second top-level
/// principal (its face: "re-genesis before claiming") — so the journal the
/// old sort had to serve never arises through this daemon's write path; the
/// board stays unclaimed and both tables survive the reopen as the live fold
/// held them, the claimant's pre-claim genesis beside the sibling's own.
#[test]
fn a_pre_claim_siblings_own_genesis_survives_a_reopen_and_the_claim_after_it_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let kb = distinct_key(47);
    let (b, before, at) = {
        let sd = spawn_unclaimed(dir.path());
        let port = sd.port();
        ceremony_before_the_claim(port);
        let b = delegate_next(port, 4400);
        let b_bare = open_session(port, 4400);
        let b_doc1 = acked_addr(&op(port, Some(&b_bare), &create_frame(&b, None)));
        // B's own genesis, below the claim: a bare insert into the published
        // home, admitted on the declaration alone, and its link.
        let atom = enroll_atom(&[&kb]);
        let v = op(
            port,
            Some(&b_bare),
            &format!(
                r#"{{"op":"insert","doc":"{b_doc1}","at":{{"subspace":"1","ordinal":"1"}},"values":[{{"atom":{atom}}}],"deposit":"{T_ENROLL}"}}"#
            ),
        );
        let atom_addr = acked_addr(&v);
        expect_resp(&typed_link(port, &b_bare, &b_doc1, &[&atom_addr], &[&b], T_ENROLL), "ack_addr");
        assert_eq!(table(&key_set(port, &b)), (set(&[&kb]), BTreeSet::new()), "seeded in its own space");
        // The claim (step 5) meets the residue gate: refused, nothing committed.
        let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        let v = op(port, Some(&signed), &claim_frame(CLAIMANT_DOC1, CLAIMANT_ACCOUNT));
        assert_eq!(v["code"].as_str(), Some("credential_refused"), "{v}");
        assert_eq!(v["detail"].as_str(), Some("claim_residue"), "{v}");
        assert!(!claimed(port), "a refused claim commits nothing");
        let accounts = [CLAIMANT_ACCOUNT, b.as_str()];
        let (at, tables) = live_tables(port, &accounts);
        assert_eq!(tables[1], (set(&[&kb]), BTreeSet::new()), "the sibling's own genesis");
        assert_eq!(tables[0], (set(&[&anchor_key(), &device_key()]), BTreeSet::new()), "the claimant's, pre-claim");
        assert_op_at_equals(port, at, &accounts, &tables);
        sd.shutdown();
        (b, tables, at)
    };
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    assert!(!claimed(port), "still unclaimed after the reopen");
    let accounts = [CLAIMANT_ACCOUNT, b.as_str()];
    let (head, after) = live_tables(port, &accounts);
    assert_eq!(after, before, "both pre-claim tables survive the reopen as the live fold held them");
    assert_eq!(head, at, "a clean reopen commits nothing of its own");
    assert_op_at_equals(port, at, &accounts, &before);
    sd.shutdown();
}

/// AUTH-2.95's conformance clause, over a generated board: `/op-at N
/// key_set` ≡ the live `key_set` when the head was `N`, at EVERY position
/// the board passed through — the probe, both retired-key variants, a hire
/// never followed by a holder act, and the non-credential writes between —
/// before a reopen and after it, where the recovered head answers the last
/// record and every position answers as before.
#[test]
fn op_at_key_set_equals_the_live_table_at_every_position() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keys: Vec<SigningKey> = (50..58u8).map(distinct_key).collect();
    let mut records: Vec<(u64, Vec<Table>)> = Vec::new();
    let (accounts, head_before) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let console = console(port);
        // The accounts first, so every record covers the same four.
        let a = delegate_next(port, 4500);
        let rotated = delegate_next(port, 4600);
        let lost_device = delegate_next(port, 4700);
        let idle = delegate_next(port, 4800);
        let accounts: Vec<String> = vec![CLAIMANT_ACCOUNT.to_string(), a, rotated, lost_device, idle];
        let names: Vec<&str> = accounts.iter().map(String::as_str).collect();
        let mut record = |port: u16| records.push(live_tables(port, &names));
        record(port);
        // The probe.
        let a_signed = hire_flagged(port, &console, &accounts[1], 4500, &keys[0], false);
        record(port);
        let a_doc1 = mint_doc_one(port, &a_signed, &accounts[1]);
        record(port);
        land_record(port, &a_signed, &a_doc1, T_ENROLL, &accounts[1], &enroll_atom(&[&keys[1]]));
        record(port);
        // The rotation.
        let r_signed = hire_flagged(port, &console, &accounts[2], 4600, &keys[2], false);
        record(port);
        let r_doc1 = mint_doc_one(port, &r_signed, &accounts[2]);
        land_record(port, &r_signed, &r_doc1, T_ENROLL, &accounts[2], &enroll_atom(&[&keys[3]]));
        record(port);
        let k3_session = open_signed_session(port, 4600, &keys[3]);
        land_record(port, &k3_session, &r_doc1, T_RETIRE, &accounts[2], &retire_atom(&[&keys[2]]));
        record(port);
        // The lost device.
        let l_signed = hire_flagged(port, &console, &accounts[3], 4700, &keys[4], true);
        let l_doc1 = mint_doc_one(port, &l_signed, &accounts[3]);
        land_record(port, &l_signed, &l_doc1, T_ENROLL, &accounts[3], &enroll_atom(&[&keys[5]]));
        record(port);
        land_record(port, &l_signed, &l_doc1, T_RETIRE, &accounts[3], &retire_atom(&[&keys[5]]));
        record(port);
        // A hire with no holder act after it, and a second key by the console.
        let _idle = hire_flagged(port, &console, &accounts[4], 4800, &keys[6], false);
        record(port);
        // A plain write between credential acts moves no table.
        let draft = acked_addr(&op(port, Some(&a_signed), &create_frame(&accounts[1], None)));
        expect_resp(
            &op(port, Some(&a_signed), &format!(r#"{{"op":"insert","doc":"{draft}","at":{{"subspace":"1","ordinal":"1"}},"values":["prose"]}}"#)),
            "ack_addr",
        );
        record(port);
        let head = records.last().expect("records").0;
        for (at, tables) in &records {
            assert_op_at_equals(port, *at, &names, tables);
        }
        sd.shutdown();
        (accounts, head)
    };
    let sd = spawn(dir.path());
    let port = sd.port();
    let names: Vec<&str> = accounts.iter().map(String::as_str).collect();
    let (head, live) = live_tables(port, &names);
    assert_eq!(head, head_before, "a clean reopen commits nothing");
    assert_eq!(&live, &records.last().expect("records").1, "the recovered head is the last record");
    for (at, tables) in &records {
        assert_op_at_equals(port, *at, &names, tables);
    }
    sd.shutdown();
}

// ── the load rows at the daemon ────────────────────────────────────────────

/// `checkpoint.<N>` in `dir` with the greatest `N`, and that `N`.
fn newest_checkpoint(dir: &Path) -> (PathBuf, u64) {
    fs::read_dir(dir)
        .expect("list the data dir")
        .filter_map(|entry| {
            let path = entry.expect("entry").path();
            let seq: u64 = path.file_name()?.to_str()?.strip_prefix("checkpoint.")?.parse().ok()?;
            Some((path, seq))
        })
        .max_by_key(|(_, seq)| *seq)
        .expect("a checkpoint")
}

/// Flip one byte of a file in place: a damaged base, which the header's
/// checksum refuses and the fallback chain passes over.
fn flip_byte(path: &Path, offset: usize) {
    let mut bytes = fs::read(path).expect("read");
    bytes[offset] ^= 0xFF;
    fs::write(path, bytes).expect("write");
}

/// AUTH-2.84, AUTH-2.85, AUTH-2.86 at the daemon: a retained checkpoint that
/// is not a start point is passed over, the open steps back to genesis and
/// replays the TRUE table — the hire's key beside the holder's — and the
/// daemon's report, which its two startup warnings are rendered from, names
/// the skipped checkpoint and the start point it resolved from.
#[test]
fn the_open_reports_a_skipped_checkpoint_and_the_start_point_it_resolved_from() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (k1, k2) = (distinct_key(61), distinct_key(62));
    let (a, before) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let (a, _, _) = probe(port, 4900, &k1, &k2, false);
        let before = table(&key_set(port, &a));
        sd.daemon().checkpoint_now();
        assert_eq!(
            sd.daemon().recovery().map(|r| (r.start_point, r.skipped.len(), r.identity_resolved_empty)),
            Some((Seq(0), 0, false)),
            "a fresh board's open: genesis, nothing skipped, nothing resolved"
        );
        sd.shutdown();
        (a, before)
    };
    let (checkpoint, at) = newest_checkpoint(dir.path());
    flip_byte(&checkpoint, 200);
    let sd = spawn(dir.path());
    let port = sd.port();
    let recovery = sd.daemon().recovery().expect("journaled").clone();
    assert_eq!(recovery.start_point, Seq(0), "genesis stood in");
    assert_eq!(recovery.skipped.len(), 1, "{recovery:?}");
    assert_eq!(recovery.skipped[0].seq, Seq(at), "the damaged checkpoint, by name");
    assert!(!recovery.identity_resolved_empty);
    assert_eq!(table(&key_set(port, &a)), before, "replayed from genesis: the true table");
    sd.shutdown();
}

/// AUTH-2.87 and AUTH-2.88 at the daemon: with the journal reclaimed below
/// the one retained checkpoint, a `key_set` read at a position below it is
/// refused WHOLE as `history_reclaimed` while the head serves; and once that
/// one base cannot stand in either, the head has no start point and the
/// daemon refuses to open — `BadCheckpoint`, through the engine, and nothing
/// invented.
#[test]
fn below_the_floor_is_history_reclaimed_and_a_head_with_no_start_point_refuses_to_serve() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (k1, k2) = (distinct_key(63), distinct_key(64));
    let (a, early, before) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let (a, _, _) = probe(port, 5000, &k1, &k2, false);
        let live = key_set(port, &a);
        let early = live["as_of"].as_u64().expect("as_of");
        // Bulk inserts rotate the journal's segment (the recipe the chain
        // suite reclaims with).
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        let draft = acked_addr(&op(port, Some(&owner), &create_frame(CLAIMANT_ACCOUNT, None)));
        let bulk = "z".repeat(8192);
        for _ in 0..6 {
            expect_resp(
                &op(port, Some(&owner), &format!(r#"{{"op":"insert","doc":"{draft}","at":{{"subspace":"1","ordinal":"1"}},"values":["{bulk}"]}}"#)),
                "ack_addr",
            );
        }
        sd.shutdown();
        (a, early, table(&live))
    };
    // Reclaim without committing: one checkpoint at the head, retaining one.
    {
        let cfg = KernelConfig {
            durability: Durability::Fsync {
                journal_path: dir.path().to_path_buf(),
                retain_checkpoints: 1,
                burned_seq: BurnedSeqPolicy::Rollback,
            },
            checkpoint: CheckpointPolicy::Manual,
            salt: SaltSource::Seeded(0),
        };
        let engine = Engine::open(cfg).expect("engine recover");
        engine.kernel().checkpoint().expect("checkpoint reclaims below itself");
        assert!(engine.world_at(Seq(0)).is_err(), "the journal must have reclaimed genesis");
    }
    // AUTH-2.87: the head serves; the position below the floor is refused.
    let sd = spawn(dir.path());
    let port = sd.port();
    assert_eq!(table(&key_set(port, &a)), before, "the head serves the carried table");
    let (st, v) = key_set_at(port, early, &a);
    assert_eq!(st, 410, "{v}");
    assert_eq!(v["error"].as_str(), Some("history_reclaimed"), "{v}");
    sd.shutdown();
    // AUTH-2.88: the one base damaged, no start point — the open refuses.
    let (checkpoint, _) = newest_checkpoint(dir.path());
    flip_byte(&checkpoint, 200);
    let refused = Daemon::open(dir.path()).expect_err("no start point: the daemon refuses to serve");
    assert!(
        matches!(refused, DaemonError::Engine(EngineError::Open(OpenError::BadCheckpoint { .. }))),
        "the refusal is M2's exhausted chain, carried whole: {refused:?}"
    );
}
