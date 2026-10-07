//! MEDIA LANE A — THE DOOR MATRIX over the wire (the seam investigation
//! §5.1 item 3; the register M-I1 (a) THE BIND AT EVERY MINT, M-I1 (f) THE
//! BIND IS COMPLETE IN TIME, M-I3 (a) THE ARITY IS CLOSED, THE KIND IS
//! PARSED): on a claimed board every path that would mint a picture's
//! reference cell is refused by name, the whole armed set landing together
//! (wire.md §Media), and nothing commits; the vector set meets ONE verdict
//! at the daemon's parser; and every order that stood ahead of the door
//! stands.
//!
//! A DRAFT HOLDING A CELL exists on no board this build serves — every
//! `insert` of one is refused here — so the shot cells seed one the way a
//! pre-fence journal holds one: the daemon stopped, the kernel opened on its
//! own directory, the value written through M5 as the owner's principal with
//! no daemon between, the daemon respawned on the recovered journal. That is
//! the board the fence exists for (the record's §The publication seam: "A
//! CELL COMMITTED BEFORE THE BINDING IS NEVER BOUND"), and the one the
//! deployment obligation says is never served — here it is served to prove
//! what the door does with it.
//!
//! AND THE CELL INDEX (`media.md` Op inventory 1; the register M-I5 (b),
//! M-I6 (a); the ruling ms5-R): the readiness refusal at exactly its three
//! readers and nothing else, the binding's rebuild window while the walk
//! runs, the composition clause, the base as one record-derived number, and
//! the rebuild's open cost, reported.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_address::{content_subspace, elem_addr, validate, Address, ElemPos, Nat, Tumbler};
use skep_arrangement::{Caller, Deposit, VPos};
use skep_content::{HasContent, Val};
use skep_engine::{Engine, KernelConfig};
use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, SaltSource};
use skep_namespace::{HasM3, PrincipalId};

use crate::common;
use common::*;

/// The lease interval the fixtures' daemon runs under, seven days.
const LEASE_MS: u64 = 7 * 24 * 3600 * 1000;

/// The cell kind's INTERIM address (wire.md §Media), as the fixture pins it.
const KIND: &str = "1.1.0.1.0.1.0.3.89";
/// A 32-byte hash as 64 lowercase hex — BLAKE3 of the empty input; the
/// format is what the lane judges, lane B judges the file.
const HASH: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
/// The two daemon tokens, in the `auth_wire` `code:detail` convention.
const UNBOUND_CELL: &str = "credential_refused:unbound_cell";
const UNKNOWN_CELL_SCHEMA: &str = "credential_refused:unknown_cell_schema";
/// A PR-ENC-shaped def — a varint length, then bytes, `0xff` among them so
/// the value is no UTF-8 string and reads back as `atom_hex`: no JSON object.
const DEF_HEX: &str = "0bff0001020304050607";

fn fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/it/fixtures/media/cells.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("the fixture is JSON")
}

/// The canonical cell: the one form.
fn canonical_cell() -> String {
    format!(r#"{{"type":"{KIND}","hash":"{HASH}","size":5}}"#)
}

/// A value naming the kind under a form this board does not read — H1's
/// second designation. The pruner suite plants one the same way.
pub(crate) fn unknown_schema_value() -> String {
    format!(r#"{{"type":"{KIND}","hash":"{HASH}","size":5,"hash_alg":"sha256-tree"}}"#)
}

/// An `insert` of ONE composite value — `atom` already in its write form
/// (`{"atom"}` or `{"atom_hex"}`) — into `doc` at `ordinal`, declared under
/// `deposit` where one is named.
fn atom_frame(doc: &str, ordinal: u64, atom: Value, deposit: Option<&str>) -> String {
    let mut v = json!({
        "op": "insert",
        "doc": doc,
        "at": {"subspace": "1", "ordinal": ordinal.to_string()},
        "values": [atom],
    });
    if let Some(ty) = deposit {
        v["deposit"] = json!(ty);
    }
    v.to_string()
}

fn cell_frame(doc: &str, ordinal: u64, text: &str, deposit: Option<&str>) -> String {
    atom_frame(doc, ordinal, json!({"atom": text}), deposit)
}

fn address(s: &str) -> Address {
    let comps: Vec<Nat> = s.split('.').map(|c| Nat::from(c.parse::<u64>().expect("a component"))).collect();
    validate(Tumbler::new(comps).expect("nonempty")).expect("a T4-valid address")
}

/// THE PRE-FENCE JOURNAL: with no daemon holding `dir`, open the kernel on
/// it under the daemon's own configuration (`Durability::Fsync`, two
/// retained checkpoints, the every-1024 cadence) and write, as `principal`,
/// a flagless — hence private, the account having its home — draft in
/// `account` holding `bytes` at its first position, through M5 and below
/// every door of the daemon's. The kernel is released on return; the daemon
/// respawned on the directory recovers the position and reconstructs its
/// feed row. Answers the draft's address. The pruner suite seeds its halt
/// mark through it, and the open-cost measure its world.
pub(crate) fn seed_pre_fence_draft(dir: &Path, principal: u64, account: &str, bytes: &[u8]) -> String {
    let cfg = KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 2,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::EveryN(1024),
        salt: SaltSource::Seeded(0),
    };
    let engine = Engine::open(cfg).expect("engine recover");
    let p = PrincipalId(principal);
    let (draft, _) = engine
        .namespace()
        .create_new_document(p, &address(account), None)
        .expect("a later flagless mint is private");
    engine
        .vstream()
        .insert(
            Caller::Principal(p),
            &draft,
            VPos::content(Nat::from(1u32)),
            vec![Val::new(bytes.to_vec())],
            Deposit::Undeclared,
        )
        .expect("the engine, below the door, writes any bytes");
    draft.tumbler().to_string()
}

/// The refusal's whole shape for a daemon token: `credential_refused`, the
/// token as `detail`, `permanent`, the op, no `site` — and nothing else.
fn assert_token(v: &Value, op: &str, token: &str) {
    assert_eq!(
        v,
        &json!({"code": "credential_refused", "detail": token, "disposition": "permanent", "op": op, "resp": "rejected"}),
        "the token's whole shape"
    );
}

/// THE REBUILD WINDOW's whole shape: `credential_refused`,
/// `index_rebuilding` as `detail`, RETRY — the one retry-class token of the
/// door's armed set — the op, no `site`, and nothing else.
fn assert_rebuilding(v: &Value, op: &str) {
    assert_eq!(
        v,
        &json!({"code": "credential_refused", "detail": "index_rebuilding", "disposition": "retry", "op": op, "resp": "rejected"}),
        "the rebuild window's whole shape"
    );
}

/// `published_target`: permanent, no detail, no site (§The version-chain
/// refusals) — the same bytes M5 answers an undeclared insert.
fn assert_published_target(v: &Value, op: &str) {
    assert_eq!(
        v,
        &json!({"code": "published_target", "disposition": "permanent", "op": op, "resp": "rejected"}),
        "published_target's whole shape"
    );
}

/// `not_owner` naming `addr` in `site.addr`, permanent, no detail.
fn assert_not_owner(v: &Value, op: &str, addr: &str) {
    assert_eq!(
        v,
        &json!({"code": "not_owner", "disposition": "permanent", "op": op, "resp": "rejected", "site": {"addr": addr}}),
        "not_owner's whole shape"
    );
}

/// THE ONE VECTOR SET AT THE DAEMON'S PARSER (M-I3 (a); PATTERNS P5): each
/// vector of `fixtures/media/cells.json`, inserted as one composite value
/// into the owner's draft, meets the verdict the set pins — a cell is
/// `unbound_cell`, a body naming the kind under no pinned schema
/// `unknown_cell_schema`, and a body not naming the kind is an ordinary
/// value that lands. The two-hash body, the second designation (H1), the
/// extent member (ms5-D2), the uppercase hex, the 63- and 65-character
/// hashes, the body past the cap and the body that round-trips to other
/// bytes are among them, each by name. A refused vector commits nothing.
#[test]
fn the_vector_set_meets_one_verdict_at_the_daemons_parser() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = owner_draft(port, &bare);
    let fixture = fixture();
    assert_eq!(fixture["kind"].as_str(), Some(KIND), "the fixture pins the kind this suite names");
    let mut landed = 0u64;
    let (mut cells, mut unknown) = (0, 0);
    for vector in fixture["vectors"].as_array().expect("vectors") {
        let name = vector["name"].as_str().expect("a name");
        let atom = match (vector["body"].as_str(), vector["body_hex"].as_str()) {
            (Some(text), _) => json!({"atom": text}),
            (None, Some(hex)) => json!({"atom_hex": hex}),
            _ => panic!("{name}: a vector carries body or body_hex"),
        };
        let expected = match (vector["verdict"].as_str(), vector["names_kind"].as_bool()) {
            (Some("cell"), _) => UNBOUND_CELL,
            (Some("no_cell"), Some(true)) => UNKNOWN_CELL_SCHEMA,
            (Some("no_cell"), Some(false)) => "ok",
            other => panic!("{name}: an unknown verdict {other:?}"),
        };
        let before = head_position(port);
        let v = op(port, Some(&bare), &atom_frame(&draft, 1, atom, None));
        assert_eq!(verdict(&v), expected, "vector {name} ({}): {v}", vector["why"]);
        if expected == "ok" {
            landed += 1;
            // Past the head it was read at — by the records the insert
            // stages, never by one: a position per record is the kernel's.
            assert!(acked_at(&v) > before, "{name}: an ordinary value commits: {v}");
        } else {
            assert_eq!(head_position(port), before, "{name}: a refused vector commits nothing");
            if expected == UNBOUND_CELL {
                cells += 1;
            } else {
                unknown += 1;
            }
        }
        assert_eq!(content_extent(port, Some(&bare), &draft), landed, "{name}");
    }
    assert!(cells >= 3 && unknown >= 15 && landed >= 8, "{cells} cells, {unknown} unknown, {landed} landed");
    sd.shutdown();
}

/// M-I1 (a), (f) — THE DRAFT INSERT, the binding's refusal: a cell
/// inserted into the owner's draft, from a bare and from a signed session,
/// naming a hash this principal did not deposit under its own lease is
/// refused `unbound_cell` — the token's bytes exact, PERMANENT, no site,
/// no prose: the face is the client's, keyed on the token, and from lane B
/// names the deposit the cell lacks (wire.md §Media) — and nothing commits:
/// the head stands and the draft stays empty. A value naming the kind
/// under no pinned schema is refused `unknown_cell_schema` the same way;
/// prose beside it lands.
#[test]
fn a_cell_inserted_into_a_draft_is_refused_in_p10s_form_and_nothing_commits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let draft = owner_draft(port, &bare);
    let before = head_position(port);
    for token in [&bare, &signed] {
        let (st, body) =
            http(port, "POST", "/op", Some(token), cell_frame(&draft, 1, &canonical_cell(), None).as_bytes());
        assert_eq!(st, 200);
        assert_eq!(
            String::from_utf8(body).expect("utf-8"),
            r#"{"code":"credential_refused","detail":"unbound_cell","disposition":"permanent","op":"insert","resp":"rejected"}"#,
            "the refusal's bytes"
        );
        let v = op(port, Some(token), &cell_frame(&draft, 1, &unknown_schema_value(), None));
        assert_token(&v, "insert", "unknown_cell_schema");
    }
    // A cell among prose: the first value naming the kind decides, and the
    // prose beside it lands nowhere either.
    let v = op(
        port,
        Some(&bare),
        &json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"},
                "values": ["ab", {"atom": canonical_cell()}, "cd"]})
        .to_string(),
    );
    assert_token(&v, "insert", "unbound_cell");
    assert_eq!(head_position(port), before, "nothing commits");
    assert_eq!(content_extent(port, Some(&bare), &draft), 0, "the draft stays empty");
    // Prose, and a def, in the same position: ordinary values, landed.
    expect_resp(&insert_text(port, &bare, &draft, 1, "abc"), "ack_addr");
    expect_resp(&op(port, Some(&bare), &atom_frame(&draft, 4, json!({"atom_hex": DEF_HEX}), None)), "ack_addr");
    assert_eq!(content_extent(port, Some(&bare), &draft), 4);
    sd.shutdown();
}

/// M-I1 (a), M-I2 (e), M-I5 (c), M-I6 (a) — THE DRAFT INSERT's ADMITTED
/// TWIN (the door matrix's cell 1 with the binding made real): the same
/// cell, its hash the bytes' the caller deposited under its own lease by a
/// PUT, is ADMITTED into the caller's draft from a bare and from a signed
/// session — the insert commits, the draft holds the cell — while another
/// principal's insert of the same cell into its own draft is refused
/// `unbound_cell` (the deposit is not theirs), a cell whose `size` is not
/// the file's length is refused `unbound_cell` (the size check at the same
/// door). The owner's shot of the draft holding the admitted cell is
/// admitted under the live lease — the cell re-inserted into the edition —
/// and the base counts the one hash once across the two cells and the
/// member's. Once the lease lapses the deposit read lists the deposit no
/// longer, and the owner's own insert of the cell is ADMITTED STILL: its
/// own cells name the hash, a reference kept by no lease — the index's arm
/// ahead of the lease's — while a cell naming a hash it never deposited is
/// `unbound_cell` as ever, and a stranger's `unbound_cell` too.
#[test]
fn a_cell_whose_hash_the_caller_deposited_under_its_own_lease_is_admitted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bytes = b"the picture's bytes";
    let cell = cell_of(bytes, bytes.len() as u64);
    let (d_bare, d_signed) = (owner_draft(port, &bare), owner_draft(port, &bare));
    // Before the deposit: the binding's refusal.
    assert_token(&op(port, Some(&bare), &cell_frame(&d_bare, 1, &cell, None)), "insert", "unbound_cell");
    // The deposit, under the caller's own lease.
    put_whole(port, &bare, bytes);
    assert_eq!(deposits_of(port, &bare), vec![(blob_hex(bytes), bytes.len() as u64, false)]);
    let before = head_position(port);
    for (token, draft) in [(&bare, &d_bare), (&signed, &d_signed)] {
        let v = op(port, Some(token), &cell_frame(draft, 1, &cell, None));
        expect_resp(&v, "ack_addr");
        assert_eq!(delivery(port, Some(&bare), draft, 1, 1), json!([{"atom": cell}]), "the draft holds the cell");
    }
    assert!(head_position(port) > before, "the admitted inserts commit");
    // Another principal, the same cell: not its deposit.
    let stranger = seat_stranger(port, 991);
    let d_stranger = create_doc(port, &stranger.session, &stranger.account);
    assert_token(&op(port, Some(&stranger.session), &cell_frame(&d_stranger, 1, &cell, None)), "insert", "unbound_cell");
    // The size check: the deposit is whole, the cell contradicts it.
    let short = cell_of(bytes, bytes.len() as u64 - 1);
    assert_token(&op(port, Some(&bare), &cell_frame(&owner_draft(port, &bare), 1, &short, None)), "insert", "unbound_cell");
    // The owner's shot of the draft holding the admitted cell: admitted.
    let edition = published_edition(port, &signed);
    let m = acked_addr(&op(port, Some(&signed), &publish_frame(&edition, None, Some(&d_signed), &[run(&d_signed, &format!("{d_signed}.0.1.1"), 1)])));
    assert_eq!(delivery(port, None, &m, 1, 1), json!([{"atom": cell}]), "the member holds the cell");
    // The base: one hash, counted once across the two drafts' cells and the
    // member's re-inserted one; the live lease on a named hash pends nothing.
    let usage = json(&blob_deposit_read(port, Some(&bare)).2);
    assert_eq!(usage["base"].as_u64(), Some(bytes.len() as u64), "{usage}");
    assert_eq!(usage["pending"].as_u64(), Some(0), "{usage}");
    assert_eq!(sd.daemon().index_counts(), (3, 1, 0), "three cells over one hash, no halt mark");
    // The lease lapsed: the read lists the deposit no longer — and the
    // owner's own insert is admitted still, its cells naming the hash.
    sd.daemon().advance_media_clock_ms(LEASE_MS);
    assert_eq!(deposits_of(port, &bare), vec![]);
    expect_resp(&op(port, Some(&bare), &cell_frame(&owner_draft(port, &bare), 1, &cell, None)), "ack_addr");
    assert_token(&op(port, Some(&bare), &cell_frame(&owner_draft(port, &bare), 1, &cell_of(b"never deposited", 15), None)), "insert", "unbound_cell");
    assert_token(&op(port, Some(&stranger.session), &cell_frame(&d_stranger, 1, &cell, None)), "insert", "unbound_cell");
    // The owner's shot of a draft holding the cell, the lease lapsed:
    // admitted, the file whole at the cell's size.
    let m = acked_addr(&op(port, Some(&signed), &publish_frame(&edition, Some((&m, 1)), Some(&d_bare), &[run(&d_bare, &format!("{d_bare}.0.1.1"), 1)])));
    assert_eq!(delivery(port, None, &m, 1, 1), json!([{"atom": cell}]));
    // The file gone from under the reference: the deposit is gone.
    std::fs::remove_file(dir.path().join("blobs").join("blake3").join(blob_hex(bytes))).expect("the file removed");
    assert_token(&op(port, Some(&bare), &cell_frame(&owner_draft(port, &bare), 1, &cell, None)), "insert", "lease_lapsed");
    sd.shutdown();
}

/// ms5-R — THE READINESS REFUSAL REACHES THE INDEX's THREE READERS AND
/// NOTHING ELSE: with the walk held, the PUT's creation, the resume and
/// the deposit read answer `503 index_rebuilding`; the progress read and
/// the termination are served (no upload: `404 no_upload`), every text
/// read and write is served, `/changes` is served, and the door's own
/// binding arm answers off the lease arm alone — a cell no lease covers
/// answered the rebuild window's retry-class `index_rebuilding`, never a
/// permanent token, the index arm unread (s6-lam-b). The walk released, the
/// creation is admitted and the deposit read answers.
#[test]
fn the_three_readers_refuse_index_rebuilding_and_nothing_else_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_walk_held(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    assert!(!sd.daemon().index_is_ready());
    let rebuilding = |answer: (u16, Vec<(String, String)>, Vec<u8>), what: &str| {
        assert_eq!(answer.0, 503, "{what}: {}", String::from_utf8_lossy(&answer.2));
        let v = json(&answer.2);
        assert_eq!(v["error"].as_str(), Some("index_rebuilding"), "{what}: {v}");
        assert!(v["detail"].as_str().is_some_and(|d| d.contains("retry")), "{what}: retry-class, said so: {v}");
    };
    let id = "0123456789abcdef0123456789abcdef";
    rebuilding(blob_exchange_once(port, "POST", &format!("{BLOB_UPLOAD}?length=5"), Some(&bare), b"hello"), "the creation");
    rebuilding(blob_exchange_once(port, "PATCH", &format!("{BLOB_UPLOAD}/{id}?offset=0"), Some(&bare), b"x"), "the resume");
    rebuilding(blob_exchange_once(port, "GET", BLOB_UPLOAD, Some(&bare), b""), "the deposit read");
    let (st, _, body) = blob_exchange_once(port, "GET", &format!("{BLOB_UPLOAD}/{id}"), Some(&bare), b"");
    assert_eq!((st, json(&body)["error"].as_str()), (404, Some("no_upload")), "the progress read is served");
    let (st, _, body) = blob_exchange_once(port, "DELETE", &format!("{BLOB_UPLOAD}/{id}"), Some(&bare), b"");
    assert_eq!((st, json(&body)["error"].as_str()), (404, Some("no_upload")), "the termination is served");
    let draft = owner_draft(port, &bare);
    expect_resp(&insert_text(port, &bare, &draft, 1, "abc"), "ack_addr");
    assert_eq!(text_of(port, Some(&bare), &draft, 1, 3), "abc", "a text read is served");
    let (st, _) = get(port, "/changes?since=0");
    assert_eq!(st, 200, "/changes is served");
    assert_rebuilding(&op(port, Some(&bare), &cell_frame(&draft, 4, &canonical_cell(), None)), "insert");
    assert!(!sd.daemon().index_is_ready(), "nothing above readied the index");
    release_the_walk(&sd);
    assert!(sd.daemon().index_is_ready());
    let (st, _, body) = blob_deposit_read(port, Some(&bare));
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["base"].as_u64(), Some(0));
    put_whole(port, &bare, b"hello");
    sd.shutdown();
}

/// ms5-R, THE DOOR NEVER WAITS — THE REBUILD WINDOW's ANSWER (s6-lam-b; the
/// register M-I5 (b)): a cell whose lease lapsed, named by the owner's own
/// cell already, its file whole, is answered `index_rebuilding` RETRY-CLASS
/// while the walk runs — the index arm skipped, the lease arm alone would
/// refuse, and the door answers the state and never a permanent token —
/// nothing permanent lands; the walk done, the same insert is admitted
/// (the index arm) and the owner's shot too, with no re-PUT.
#[test]
fn the_binding_reads_the_lease_arm_alone_until_the_walk_completes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bytes = b"a picture whose lease lapses by the wall clock";
    let cell = cell_of(bytes, bytes.len() as u64);
    let d1 = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let bare = open_session(port, CLAIMANT_PRINCIPAL);
        sd.daemon().install_media_limits(None, None, Some(500), None);
        put_whole(port, &bare, bytes);
        let d1 = owner_draft(port, &bare);
        expect_resp(&op(port, Some(&bare), &cell_frame(&d1, 1, &cell, None)), "ack_addr");
        std::thread::sleep(Duration::from_millis(700));
        sd.shutdown();
        d1
    };
    let sd = spawn_walk_held(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let d2 = owner_draft(port, &bare);
    let edition = published_edition(port, &signed);
    let before = head_position(port);
    assert_rebuilding(&op(port, Some(&bare), &cell_frame(&d2, 1, &cell, None)), "insert");
    let v = op(port, Some(&signed), &publish_frame(&edition, None, Some(&d1), &[run(&d1, &format!("{d1}.0.1.1"), 1)]));
    assert_rebuilding(&v, "publish");
    // A cell no lease covers and none of the owner's cells names: the same
    // state in the rebuild window, the permanent `unbound_cell` once the walk
    // is done.
    let never = cell_of(b"never deposited here", 20);
    assert_rebuilding(&op(port, Some(&bare), &cell_frame(&d2, 1, &never, None)), "insert");
    assert_eq!(content_extent(port, Some(&bare), &d2), 0, "nothing permanent landed");
    assert_eq!(content_extent(port, None, &edition), 0);
    assert_eq!(head_position(port), before, "a retry-class refusal commits nothing");
    release_the_walk(&sd);
    assert_eq!(sd.daemon().index_counts(), (1, 1, 0), "the walk found d1's cell");
    assert_eq!(deposits_of(port, &bare), vec![], "no re-PUT: the lease stays lapsed");
    expect_resp(&op(port, Some(&bare), &cell_frame(&d2, 1, &cell, None)), "ack_addr");
    let m = acked_addr(&op(port, Some(&signed), &publish_frame(&edition, None, Some(&d1), &[run(&d1, &format!("{d1}.0.1.1"), 1)])));
    assert_eq!(delivery(port, None, &m, 1, 1), json!([{"atom": cell}]), "the owner's shot after the lapse, no re-PUT");
    assert_token(&op(port, Some(&bare), &cell_frame(&owner_draft(port, &bare), 1, &never, None)), "insert", "unbound_cell");
    assert_eq!(sd.daemon().index_counts(), (3, 1, 0), "the insert's and the shot's cells entered at commit");
    sd.shutdown();
}

/// The quantiles of a sorted sample, in milliseconds — the timing rows'
/// one rendering.
fn quantiles_ms(sorted: &[Duration]) -> (f64, f64, f64) {
    let q = |p: f64| sorted[((sorted.len() - 1) as f64 * p).round() as usize].as_secs_f64() * 1e3;
    (q(0.5), q(0.9), q(0.99))
}

/// THE INDEX ARM's H1 TIMING ROW (M-I2 (e); s6-leak-c; the gate's timing
/// partition — REPORTED, NEVER ASSERTED, sm-Q4): a stranger's cell over a
/// hash another account's cell names, that account's lease lapsed, answers
/// `unbound_cell` in the same TIME as the same cell over a hash no cell
/// names — the binding's index arm is read at the requester's OWN account's
/// hashes and never at the per-hash list, so another account's cell is
/// never consulted. Two boards: one where the owner deposited the bytes,
/// placed the cell and let the lease lapse, one where nobody deposited
/// anything; the stranger's insert refused `unbound_cell` on both, N trials
/// apiece, the distributions printed beside K2's rows. `H1_TRIALS` narrows
/// the count.
#[test]
#[ignore = "timing test - gate-full only"]
fn h1_a_strangers_cell_over_another_accounts_named_hash_answers_in_the_same_time() {
    let trials: usize = std::env::var("H1_TRIALS").ok().and_then(|s| s.parse().ok()).unwrap_or(300);
    let bytes = seeded_bytes(100_000, 0x11);
    let cell = cell_of(&bytes, bytes.len() as u64);
    let mut rows = Vec::new();
    for (label, placed) in [("named by another account's cell, its lease lapsed", true), ("named by no cell", false)] {
        let dir = tempfile::tempdir().expect("tempdir");
        let sd = spawn(dir.path());
        let port = sd.port();
        let bare = open_session(port, CLAIMANT_PRINCIPAL);
        if placed {
            put_whole(port, &bare, &bytes);
            assert_eq!(insert_cell(port, &bare, &owner_draft(port, &bare), &bytes, bytes.len() as u64), "ok");
            sd.daemon().advance_media_clock_ms(LEASE_MS);
            assert_eq!(deposits_of(port, &bare), vec![], "the lease lapsed");
        }
        let stranger = seat_stranger(port, 971);
        let d = create_doc(port, &stranger.session, &stranger.account);
        let frame = cell_frame(&d, 1, &cell, None);
        let mut latencies: Vec<Duration> = Vec::with_capacity(trials);
        for _ in 0..trials {
            let started = Instant::now();
            let v = op(port, Some(&stranger.session), &frame);
            latencies.push(started.elapsed());
            assert_token(&v, "insert", "unbound_cell");
        }
        latencies.sort();
        let (p50, p90, p99) = quantiles_ms(&latencies);
        println!("H1 index arm, {label}: {trials} trials, unbound_cell p50 {p50:.3} ms p90 {p90:.3} ms p99 {p99:.3} ms");
        rows.push((p50, p99));
        sd.shutdown();
    }
    println!(
        "H1 index arm: the gap (named − unnamed) at p50 {:+.3} ms, p99 {:+.3} ms — reported, not asserted (sm-Q4); K2's residue stands beside it",
        rows[0].0 - rows[1].0,
        rows[0].1 - rows[1].1
    );
}

/// THE BLIND KIND's H1 TIMING ROW (M-I2 (e); the door's blind row, s6-bd-b;
/// the gate's timing partition — REPORTED, NEVER ASSERTED, sm-Q4): the
/// door's answer to a blind cell is ADMITTED, and its TIME one, with and
/// without a file deposited under a lease whose hex equals the commitment's
/// hex — the binding is never asked for the kind, so no deposit of the
/// board's is consulted. Two boards, N trials apiece, the distributions
/// printed beside the index arm's.
#[test]
#[ignore = "timing test - gate-full only"]
fn h1_a_blind_cells_answer_takes_the_same_time_with_and_without_a_deposit_under_its_hex() {
    let trials: usize = std::env::var("H1_TRIALS").ok().and_then(|s| s.parse().ok()).unwrap_or(300);
    let bytes = seeded_bytes(100_000, 0x12);
    let commitment: [u8; 32] = *blake3::hash(&bytes).as_bytes();
    let blind = blind_cell_of(&commitment);
    let mut rows = Vec::new();
    for (label, deposited) in [("a file deposited under the commitment's hex", true), ("no deposit", false)] {
        let dir = tempfile::tempdir().expect("tempdir");
        let sd = spawn(dir.path());
        let port = sd.port();
        let bare = open_session(port, CLAIMANT_PRINCIPAL);
        if deposited {
            put_whole(port, &bare, &bytes);
        }
        let d = owner_draft(port, &bare);
        let mut latencies: Vec<Duration> = Vec::with_capacity(trials);
        for i in 0..trials {
            let frame = common::atom_frame(&d, i as u64 + 1, &blind);
            let started = Instant::now();
            let v = op(port, Some(&bare), &frame);
            latencies.push(started.elapsed());
            expect_resp(&v, "ack_addr");
        }
        latencies.sort();
        let (p50, p90, p99) = quantiles_ms(&latencies);
        println!("H1 blind row, {label}: {trials} trials, admitted p50 {p50:.3} ms p90 {p90:.3} ms p99 {p99:.3} ms");
        rows.push((p50, p99));
        sd.shutdown();
    }
    println!(
        "H1 blind row: the gap (deposited − none) at p50 {:+.3} ms, p99 {:+.3} ms — reported, not asserted (sm-Q4)",
        rows[0].0 - rows[1].0,
        rows[0].1 - rows[1].1
    );
}

/// THE COMPOSITION CLAUSE (M-I5 (b); `media.md` Op inventory 1, "THE WALK's
/// ENTRIES ARE ADDED INTO THE ONE COPY, WHICH EVERY COMMIT SINCE THAT OPEN
/// HAS ENTERED ITS OWN INTO, AND NEVER INSTALLED IN ITS PLACE"): a cell
/// inserted while the walk is held — admitted off the lease arm — is in
/// the index when the walk completes, beside the cell the walk found; its
/// file outlives its lapsed lease at the pruner's pass; and the base
/// counts both.
#[test]
fn a_cell_inserted_during_the_walk_joins_the_one_copy_and_keeps_its_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let walked = b"the picture the walk finds";
    let during = b"the picture inserted while the walk runs";
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let bare = open_session(port, CLAIMANT_PRINCIPAL);
        put_whole(port, &bare, walked);
        put_whole(port, &bare, during);
        assert_eq!(insert_cell(port, &bare, &owner_draft(port, &bare), walked, walked.len() as u64), "ok");
        sd.shutdown();
    }
    let sd = spawn_walk_held(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    assert_eq!(sd.daemon().index_counts(), (0, 0, 0), "held: the walk has entered nothing");
    assert_eq!(insert_cell(port, &bare, &owner_draft(port, &bare), during, during.len() as u64), "ok", "admitted off the live lease");
    assert_eq!(sd.daemon().index_counts(), (1, 1, 0), "the commit entered its own cell into the one copy");
    release_the_walk(&sd);
    assert_eq!(sd.daemon().index_counts(), (2, 2, 0), "the walk's entry joined it, nothing installed in its place");
    let usage = json(&blob_deposit_read(port, Some(&bare)).2);
    assert_eq!(usage["base"].as_u64(), Some((walked.len() + during.len()) as u64), "{usage}");
    sd.daemon().advance_media_clock_ms(LEASE_MS);
    let pass = sd.daemon().prune_now().expect("ready");
    assert_eq!((pass.unlinked, pass.kept), (0, 2), "{pass:?}");
    let blobs = dir.path().join("blobs").join("blake3");
    assert!(blobs.join(blob_hex(walked)).is_file());
    assert!(blobs.join(blob_hex(during)).is_file(), "the cell inserted during the walk keeps its file past its lease");
    sd.shutdown();
}

/// THE BASE PROPERTY (M-I6 (a) — RECORD-DERIVED, ONCE, IDENTICAL
/// EVERYWHERE): two opens of one data dir answer one `base` — the first
/// built by the commits' entries, the second by the walk — and it equals
/// the sum the test computes from the journal's own account: every
/// document `/changes` names as touched, read back, its cells parsed, the
/// distinct hashes summed at their size; a transclusion counts nothing and
/// the edition's re-inserted cell counts once with its original.
#[test]
fn the_base_is_one_number_across_opens_and_equals_the_journals_own_count() {
    let dir = tempfile::tempdir().expect("tempdir");
    let a = seeded_bytes(1_001, 31);
    let b = seeded_bytes(2_002, 32);
    let c = seeded_bytes(3_003, 33);
    let (first, from_the_journal) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let bare = open_session(port, CLAIMANT_PRINCIPAL);
        let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        for bytes in [&a, &b, &c] {
            put_whole(port, &bare, bytes);
        }
        let d1 = owner_draft(port, &bare);
        let d2 = owner_draft(port, &bare);
        let d3 = owner_draft(port, &bare);
        assert_eq!(insert_cell(port, &bare, &d1, &a, 1_001), "ok");
        assert_eq!(insert_cell(port, &bare, &d2, &a, 1_001), "ok", "a second cell over the same hash");
        assert_eq!(insert_cell(port, &bare, &d3, &b, 2_002), "ok");
        // `c` deposited and never placed: pending, in no base.
        let edition = published_edition(port, &signed);
        let m = acked_addr(&op(port, Some(&signed), &publish_frame(&edition, None, Some(&d1), &[run(&d1, &format!("{d1}.0.1.1"), 1)])));
        // A transclusion of the member's cell into a draft mints no cell.
        let d4 = owner_draft(port, &bare);
        expect_resp(&copy_span(port, &bare, &d4, 1, &m, 1, 1), "ack");
        let usage = json(&blob_deposit_read(port, Some(&bare)).2);
        let first = usage["base"].as_u64().expect("base");
        assert_eq!(first, 1_001 + 2_002, "{usage}");
        assert_eq!(usage["pending"].as_u64(), Some(3_003), "{usage}");
        // THE JOURNAL's OWN COUNT: every document `/changes` names at the
        // owner's class — its drafts among them — read back; the cells
        // parsed by the test's own reading of the schema.
        let (st, body) = http(port, "GET", "/changes?since=0&limit=4096", Some(&bare), b"");
        assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
        let mut docs: Vec<String> = Vec::new();
        for entry in json(&body)["changes"].as_array().expect("changes") {
            if !matches!(entry["op"].as_str(), Some("insert" | "publish" | "copy")) {
                continue;
            }
            for d in entry["docs"].as_array().expect("docs") {
                let d = d.as_str().expect("a document").to_string();
                if !docs.contains(&d) {
                    docs.push(d);
                }
            }
        }
        let mut hashes: BTreeMap<String, u64> = BTreeMap::new();
        for doc in &docs {
            let extent = content_extent(port, Some(&bare), doc);
            if extent == 0 {
                continue;
            }
            for value in values_of(port, Some(&bare), doc, 1, extent) {
                let Ok(v) = serde_json::from_slice::<Value>(&value) else { continue };
                if v["type"].as_str() != Some(KIND) {
                    continue;
                }
                let (Some(hash), Some(size)) = (v["hash"].as_str(), v["size"].as_u64()) else { continue };
                hashes.insert(hash.to_string(), size);
            }
        }
        let from_the_journal: u64 = hashes.values().sum();
        assert_eq!(hashes.len(), 2, "two distinct hashes across four cells: {hashes:?}");
        sd.shutdown();
        (first, from_the_journal)
    };
    assert_eq!(first, from_the_journal, "the base is the journal's own count");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let usage = json(&blob_deposit_read(port, Some(&bare)).2);
    assert_eq!(usage["base"].as_u64(), Some(first), "the second open's walk answers the first open's number: {usage}");
    assert_eq!(sd.daemon().index_counts(), (4, 2, 0), "four cells — three inserts and the shot's — over two hashes");
    assert_eq!(usage["pending"].as_u64(), Some(3_003), "{usage}");
    sd.shutdown();
}

/// §3.1 — THE INDEX REBUILD's OPEN COST (`#[ignore]`, the gate's timing
/// partition; REPORTED, with one interim regression bound): a world of N
/// per-byte values and K cells — two tiers, N = 10⁶ with K = 10³ and N =
/// 10⁷ with K = 10⁴ — seeded OVER THE WIRE: long-prose inserts of a
/// hundred thousand bytes apiece (the request cap bounds one insert) and
/// the cells a hundred per insert, then a checkpoint, so the reopen loads
/// it and replays no tail. Not through the engine with the daemon
/// stopped: every position so seeded is one the change feed holds no
/// record of, and the daemon's next open reconstructs each from the
/// journal — a whole-world replay apiece, a million-value checkpoint
/// loaded per position — which at a thousand positions costs the open
/// hours and measures the feed, not the index. Then measured: (a) the walk
/// alone with the prefix test, over the engine's own snapshot in the test
/// — the kept enumeration, the same walk sorted into tumbler order, and
/// the alternative walk of every registered document's content frontier
/// with one `value_at` per minted address, written here from M3's and
/// M4's public reads (the mints as peeks, the point read); (b) the parse
/// over the K composite values; (c) the time from the daemon's open to
/// the first PUT the gate admits — the record's measure — with the open's
/// own duration beside it, and the daemon's own report of its walk. The
/// bound: (c) past the open under 5 s at either tier. THE GATE RUNS THE
/// 10⁶ TIER: its profile terminates a test after ten minutes, and the 10⁷
/// tier's seeding alone takes twenty on this build; `INDEX_TIERS=large`
/// or `both` runs the 10⁷ tier explicitly, outside the gate.
#[test]
#[ignore = "timing test - gate-full only"]
fn index_rebuild_at_open_scales_with_the_world() {
    let tiers = std::env::var("INDEX_TIERS").unwrap_or_else(|_| "small".into());
    let mut plans: Vec<(usize, usize)> = Vec::new();
    if tiers != "large" {
        plans.push((1_000_000, 1_000));
    }
    if tiers != "small" {
        plans.push((10_000_000, 10_000));
    }
    for (n, k) in plans {
        let dir = tempfile::tempdir().expect("tempdir");
        let bytes = b"the one picture every cell names";
        let cell = cell_of(bytes, bytes.len() as u64);
        let seeding = Instant::now();
        {
            let sd = spawn(dir.path());
            // The seeding under a byte bound no insert reaches: each 100,000
            // byte insert is ~28 MB of journal, so the daemon's own bound
            // (24 MiB) would have its checkpoint thread checkpoint the
            // growing world after every insert and, in a debug build where
            // one takes tens of seconds, the backstop run the next inline —
            // the measure here is the open's cost over ONE checkpoint taken
            // below, which is the fixture this test was written for.
            sd.daemon().set_checkpoint_bytes_bound(1 << 60);
            let port = sd.port();
            let bare = open_session(port, CLAIMANT_PRINCIPAL);
            put_whole(port, &bare, bytes);
            // The prose: `n` per-byte values, a hundred thousand per insert
            // into one draft.
            let prose = owner_draft(port, &bare);
            let piece = 100_000usize;
            let text: String = (0..piece).map(|i| (b'a' + (i % 26) as u8) as char).collect();
            let mut placed = 0usize;
            let mut ordinal = 1u64;
            while placed < n {
                let take = piece.min(n - placed);
                expect_resp(&insert_text(port, &bare, &prose, ordinal, &text[..take]), "ack_addr");
                placed += take;
                ordinal += take as u64;
            }
            // The cells: `k` of them, a hundred per insert into drafts of
            // their own — one draft per hundred.
            let per_insert = 100usize;
            let mut entered = 0usize;
            while entered < k {
                let take = per_insert.min(k - entered);
                let draft = owner_draft(port, &bare);
                let values: Vec<Value> = (0..take).map(|_| json!({"atom": cell})).collect();
                let frame = json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": values}).to_string();
                expect_resp(&op(port, Some(&bare), &frame), "ack_addr");
                entered += take;
            }
            assert_eq!(sd.daemon().index_counts().0, k, "every cell entered at its commit");
            sd.daemon().checkpoint_now();
            sd.shutdown();
        }
        println!("rebuild n={n} k={k}: seeded over the wire in {:?}", seeding.elapsed());
        // (a) and (b), over the engine's own snapshot, the daemon stopped.
        {
            let opening = Instant::now();
            let engine = Engine::open(engine_config(dir.path())).expect("engine recover");
            let engine_open = opening.elapsed();
            let snap = engine.kernel().snapshot();
            let world = snap.world();
            let prefix = format!("{{\"type\":\"{KIND}\"");
            let walking = Instant::now();
            let (mut values, mut naming) = (0usize, 0usize);
            for (_, v) in world.content().iter() {
                values += 1;
                if v.as_bytes().starts_with(prefix.as_bytes()) {
                    naming += 1;
                }
            }
            let walk_alone = walking.elapsed();
            // The same walk SORTED into tumbler order — the checkpoint's
            // own order, which the kept enumeration does not promise:
            // what a rebuild reading the entries in that order would pay
            // beyond the walk itself.
            let sorting = Instant::now();
            let mut entries: Vec<_> = world.content().iter().collect();
            entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
            let sorted_walk = sorting.elapsed();
            drop(entries);
            let parsing = Instant::now();
            let mut parsed = 0usize;
            for (_, v) in world.content().iter() {
                if v.as_bytes().starts_with(prefix.as_bytes()) {
                    let parsed_value: Value = serde_json::from_slice(v.as_bytes()).expect("a cell is JSON");
                    assert_eq!(parsed_value["type"].as_str(), Some(KIND));
                    parsed += 1;
                }
            }
            // ONE read of the clock: two `elapsed()` calls around the `min`
            // let a later, larger reading be the subtrahend's bound while the
            // earlier, smaller one was the minuend, and a parse that took
            // about as long as the walk underflowed under the gate's load.
            let parsing_took = parsing.elapsed();
            let parse = parsing_took - walk_alone.min(parsing_took);
            // THE ALTERNATIVE WALK: every registered document's content
            // frontier — the mint asked and not staged is the chain's peek
            // — with one `value_at` per minted address.
            let alternative = Instant::now();
            let (mut alt_values, mut alt_naming) = (0usize, 0usize);
            let m3 = world.m3();
            let content = world.content();
            for (doc, _) in m3.documents() {
                let Ok((next, _)) = m3.mint_content(doc) else { continue };
                let frontier: u64 = skep_address::ordinal(next.tumbler()).to_string().parse::<u64>().expect("an ordinal") - 1;
                for i in 1..=frontier {
                    let at = elem_addr(ElemPos { doc: doc.clone(), subspace: content_subspace(), ordinal: Nat::from(i) }).expect("a content address");
                    if let Some(v) = content.value_at(at.tumbler()) {
                        alt_values += 1;
                        if v.as_bytes().starts_with(prefix.as_bytes()) {
                            alt_naming += 1;
                        }
                    }
                }
            }
            let alt_walk = alternative.elapsed();
            println!(
                "rebuild n={n} k={k}: engine open {engine_open:?}; (a) the kept walk over {values} values with the prefix test {walk_alone:?} ({naming} naming the kind), the same walk sorted into tumbler order {sorted_walk:?}; (b) the parse of {parsed} composite values {parse:?}; the alternative frontier walk over {alt_values} values {alt_walk:?} ({alt_naming} naming the kind)"
            );
            assert_eq!(naming, k);
            assert_eq!(alt_naming, k);
        }
        // (c) the time from open to the first PUT the gate admits — the
        // spawn that does not wait for the walk, so the clock below runs
        // from the open's return, the session's open inside it.
        let opening = Instant::now();
        let sd = spawn_not_waiting_for_the_index(dir.path());
        let open_took = opening.elapsed();
        let after_open = Instant::now();
        let port = sd.port();
        let bare = open_session(port, CLAIMANT_PRINCIPAL);
        let mut refusals = 0usize;
        loop {
            let (st, _, body) = blob_exchange_once(port, "POST", &format!("{BLOB_UPLOAD}?length=3"), Some(&bare), b"abc");
            if st == 200 {
                break;
            }
            assert_eq!(st, 503, "{}", String::from_utf8_lossy(&body));
            refusals += 1;
            std::thread::sleep(Duration::from_millis(2));
        }
        let to_first_put = after_open.elapsed();
        let report = sd.daemon().index_rebuild_report().expect("the walk completed");
        println!(
            "rebuild n={n} k={k}: (c) the daemon's open (the engine's recovery, the feed, the fold) {open_took:?}; from the open's return to the first admitted PUT {to_first_put:?} after {refusals} index_rebuilding refusals; the daemon's walk: {} values, {} cells, {} halt marks, {:?} ({:?} past the prefix test)",
            report.values, report.cells, report.halts, report.walk, report.parse
        );
        assert_eq!(report.cells, k);
        assert!(to_first_put < Duration::from_secs(5), "the interim bound: (c) < 5 s at n={n}, measured {to_first_put:?}");
        sd.shutdown();
    }
}

/// The daemon's own kernel configuration, for the engine opened on a data
/// dir with the daemon stopped — the open-cost measure's own walks.
fn engine_config(dir: &Path) -> KernelConfig {
    KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 2,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::EveryN(1024),
        salt: SaltSource::Seeded(0),
    }
}

/// M-I1 (a) — THE DECLARED DEPOSIT AT A PUBLISHED TARGET answers
/// `published_target` ahead of the binding, whatever the declaration: a
/// cell declared under the enrollment kind (the one `insert` M5 admits at a
/// published target, judged on its type alone) at the head's fresh
/// position, from the owner's signed and attested session — the write-path
/// check passed, the store would have admitted it — is refused by the
/// media door with M5's own code and bytes; so is an undeclared one, a
/// declared one at an arranged position, a value under an unknown schema,
/// and a cell into the home (doc 1). Nothing commits. Prose and a def
/// declared at the same position take the ordinary answer: admitted, since
/// the declared deposit tests the type and not the atom (PUB-2.60).
#[test]
fn a_declared_deposit_of_a_cell_at_a_published_target_answers_published_target_ahead_of_the_binding() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let edition = edition_with(port, &signed, "pq");
    let fresh = next_content_ordinal(port, Some(&signed), &edition);
    assert_eq!(fresh, 3);
    let before = head_position(port);
    for (ordinal, text, deposit) in [
        (fresh, canonical_cell(), Some(T_ENROLL)),
        (fresh, canonical_cell(), None),
        (1, canonical_cell(), Some(T_ENROLL)),
        (fresh, unknown_schema_value(), Some(T_ENROLL)),
        (fresh, canonical_cell(), Some(T_RETIRE)),
    ] {
        let v = op(port, Some(&signed), &cell_frame(&edition, ordinal, &text, deposit));
        assert_published_target(&v, "insert");
    }
    let home_fresh = next_content_ordinal(port, Some(&signed), CLAIMANT_DOC1);
    let v = op(port, Some(&signed), &cell_frame(CLAIMANT_DOC1, home_fresh, &canonical_cell(), Some(T_ENROLL)));
    assert_published_target(&v, "insert");
    assert_eq!(head_position(port), before, "nothing commits");
    assert_eq!(content_extent(port, None, &edition), 2);
    // The ordinary answer, in the same position: a declared deposit of
    // bytes the class test cannot read — prose, a def — is admitted.
    expect_resp(&op(port, Some(&signed), &cell_frame(&edition, fresh, "a record of sorts", Some(T_ENROLL))), "ack_addr");
    expect_resp(
        &op(port, Some(&signed), &atom_frame(&edition, fresh + 1, json!({"atom_hex": DEF_HEX}), Some(T_ENROLL))),
        "ack_addr",
    );
    assert_eq!(content_extent(port, None, &edition), 4);
    sd.shutdown();
}

/// M-I1 (a), (c) — THE SHOT'S OWNER TEST, ω exact, and the binding at the
/// shot. Over a pre-fence journal holding three drafts — the owner's with a
/// cell, the owner's with a value under an unknown schema, a sub-account's
/// with a cell — a GRANTEE's, an ANCESTOR's and a DESCENDANT's shot naming
/// the owner's draft as its staging draft, each reading it, is refused
/// `not_owner` naming the draft (nothing minted: their targets stay
/// empty); the OWNER's own shot is refused `lease_lapsed` — the walk at
/// open indexed the pre-fence cell, so the owner's own cells name the
/// hash, a reference whose file is not on disk: the deposit is gone and
/// the act is the PUT — and `unknown_cell_schema` for the unknown form,
/// entered as a halt mark and counted in no base; a stranger who cannot
/// read the draft meets the store's `withheld` attested and the check's
/// `attestation_required` unattested, BEFORE this door; and prose or a def
/// in the same position takes the ordinary answer — the reader's shot
/// lands. The whole armed set lands together: every refusal commits
/// nothing.
#[test]
fn a_readers_shot_naming_a_draft_holding_a_cell_is_refused_not_owner_and_the_owners_own_in_p10s_form() {
    let dir = tempfile::tempdir().expect("tempdir");
    // The board claimed, a sub-account seated beneath the claimant.
    let sub = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let bare = open_session(port, CLAIMANT_PRINCIPAL);
        let sub = seat_sub_account(port, &bare, 12);
        sd.shutdown();
        sub
    };
    // The pre-fence journal.
    let d_cell = seed_pre_fence_draft(dir.path(), CLAIMANT_PRINCIPAL, CLAIMANT_ACCOUNT, canonical_cell().as_bytes());
    let d_unknown =
        seed_pre_fence_draft(dir.path(), CLAIMANT_PRINCIPAL, CLAIMANT_ACCOUNT, unknown_schema_value().as_bytes());
    let d_sub = seed_pre_fence_draft(dir.path(), 12, &sub.account, canonical_cell().as_bytes());
    // The daemon over it.
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    assert_eq!(text_of(port, Some(&bare), &d_cell, 1, 1), "", "the cell is one composite value");
    assert_eq!(delivery(port, Some(&bare), &d_cell, 1, 1), json!([{"atom": canonical_cell()}]));
    // The sub-account (a descendant, reading the owner's drafts by subtree)
    // keyed by the claimant's anchor-grade handoff; a grantee keyed by a hire
    // and granted the cell's draft; a stranger keyed and granted nothing.
    let sub_signed = hire(port, &anchor, CLAIMANT_DOC1, &sub.account, 12, &distinct_key(12));
    let grantee = seat_stranger(port, 971);
    let grantee_signed = hire(port, &signed, CLAIMANT_DOC1, &grantee.account, 971, &distinct_key(71));
    deposit_grant(port, &signed, CLAIMANT_DOC1, &d_cell, Some(&grantee.account));
    let stranger = seat_stranger(port, 981);
    let stranger_signed = hire(port, &signed, CLAIMANT_DOC1, &stranger.account, 981, &distinct_key(81));
    let cell_run = |draft: &str| vec![run(draft, &format!("{draft}.0.1.1"), 1)];
    let edition = published_edition(port, &signed);
    let before = head_position(port);

    // Arm 2 — the readers: a grantee, an ancestor, a descendant.
    assert_eq!(delivery(port, Some(&grantee_signed), &d_cell, 1, 1), json!([{"atom": canonical_cell()}]), "the grantee reads the draft");
    let v = op(port, Some(&grantee_signed), &publish_frame(&grantee.doc1, None, Some(&d_cell), &cell_run(&d_cell)));
    assert_not_owner(&v, "publish", &d_cell);
    let v = op(port, Some(&signed), &publish_frame(&edition, None, Some(&d_sub), &cell_run(&d_sub)));
    assert_not_owner(&v, "publish", &d_sub);
    let v = op(port, Some(&sub_signed), &publish_frame(&sub.doc1, None, Some(&d_cell), &cell_run(&d_cell)));
    assert_not_owner(&v, "publish", &d_cell);
    // …and the unknown form from a reader: the owner test first.
    let v = op(port, Some(&sub_signed), &publish_frame(&sub.doc1, None, Some(&d_unknown), &cell_run(&d_unknown)));
    assert_not_owner(&v, "publish", &d_unknown);

    // Arms 5 and 4 — the owner's own shot: its own pre-fence cell names the
    // hash (the index's arm), the file is not there — the deposit is gone;
    // the unknown form halts, and stands in the index as a halt mark.
    let v = op(port, Some(&signed), &publish_frame(&edition, None, Some(&d_cell), &cell_run(&d_cell)));
    assert_token(&v, "publish", "lease_lapsed");
    let v = op(port, Some(&signed), &publish_frame(&edition, None, Some(&d_unknown), &cell_run(&d_unknown)));
    assert_token(&v, "publish", "unknown_cell_schema");
    assert_eq!(sd.daemon().index_counts(), (2, 1, 1), "the two pre-fence cells over one hash, one halt mark");
    let usage = json(&blob_deposit_read(port, Some(&bare)).2);
    assert_eq!(usage["base"].as_u64(), Some(5), "the pre-fence cell counts at its size; the halt mark counts nothing: {usage}");

    // Ahead of the door — the unreadable draft: the store's `withheld`
    // attested over a guess at the bytes, the check's `attestation_required`
    // unattested; neither answer turns on what the draft holds.
    let frame = publish_frame(&stranger.doc1, None, Some(&d_cell), &cell_run(&d_cell));
    let guess: Vec<&[u8]> = vec![b"not the cell"];
    assert_withheld(&op_with_publish_values(port, &stranger_signed, &frame, &guess), &d_cell);
    let v = op_as_written(port, Some(&stranger_signed), &frame);
    assert_eq!(verdict(&v), "credential_refused:attestation_required", "{v}");

    assert_eq!(head_position(port), before, "every refusal commits nothing");
    for target in [&grantee.doc1, &sub.doc1, &stranger.doc1, &edition] {
        assert_eq!(content_extent(port, None, target), 0, "{target} stays empty: no cell is minted");
    }

    // The ordinary answer in the same positions: a reader's shot re-inserting
    // the owner's prose lands, and one re-inserting a def lands — neither
    // names the kind, so neither meets the door.
    let d_prose = draft_with(port, &bare, "abc");
    let m = acked_addr(&op(port, Some(&sub_signed), &publish_frame(&sub.doc1, None, Some(&d_prose), &[run(&d_prose, &format!("{d_prose}.0.1.1"), 3)])));
    assert_eq!(m, format!("{}.1", sub.doc1));
    assert_eq!(text_of(port, None, &m, 1, 3), "abc");
    let d_def = owner_draft(port, &bare);
    expect_resp(&op(port, Some(&bare), &atom_frame(&d_def, 1, json!({"atom_hex": DEF_HEX}), None)), "ack_addr");
    let sub_edition = acked_addr(&op(port, Some(&sub_signed), &create_frame(&sub.account, Some(true))));
    let m = acked_addr(&op(port, Some(&sub_signed), &publish_frame(&sub_edition, None, Some(&d_def), &cell_run(&d_def))));
    assert_eq!(delivery(port, None, &m, 1, 1), json!([{"atom_hex": DEF_HEX}]));
    sd.shutdown();
}

/// NOTHING ELSE MOVES — every order ahead of the door stands, in its own
/// code and bytes: a stranger's insert of a cell into the owner's draft is
/// the store's `not_owner` (the door reads nothing of a document the caller
/// does not own), an unregistered document `doc_not_registered`, a bare
/// session's cell into the owner's published edition the gate's
/// `signed_session_required`, an unattested one from the signed session the
/// check's `attestation_required` — and only then, attested, the door's
/// `published_target`. A `copy` of ordinary content into a draft is
/// untouched.
#[test]
fn every_order_ahead_of_the_door_stands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let draft = owner_draft(port, &bare);
    let edition = edition_with(port, &signed, "pq");
    let stranger = seat_stranger(port, 991);
    let before = head_position(port);

    let v = op(port, Some(&stranger.session), &cell_frame(&draft, 1, &canonical_cell(), None));
    assert_not_owner(&v, "insert", &draft);
    let v = op(port, Some(&bare), &cell_frame("1.0.1.0.99", 1, &canonical_cell(), None));
    assert_eq!(verdict(&v), "doc_not_registered", "{v}");
    let v = op(port, Some(&bare), &cell_frame(&edition, 3, &canonical_cell(), Some(T_ENROLL)));
    assert_eq!(verdict(&v), GATED, "{v}");
    let v = op_as_written(port, Some(&signed), &cell_frame(&edition, 3, &canonical_cell(), Some(T_ENROLL)));
    assert_eq!(verdict(&v), "credential_refused:attestation_required", "{v}");
    let v = op(port, Some(&signed), &cell_frame(&edition, 3, &canonical_cell(), Some(T_ENROLL)));
    assert_published_target(&v, "insert");
    assert_eq!(head_position(port), before, "nothing commits");

    expect_resp(&copy_span(port, &bare, &draft, 1, &edition, 1, 2), "ack");
    assert_eq!(text_of(port, Some(&bare), &draft, 1, 2), "pq");
    sd.shutdown();
}

/// M-I1 (f) — THE FENCE STANDS BEFORE THE CLAIM TOO: on the unclaimed board,
/// where the pre-claim gate admits an `insert` into the caller's own doc 1
/// (the ceremony's own shape), a cell declared under the enrollment kind
/// into that published home is refused `published_target` by the door, and
/// an undeclared one the same; nothing commits and the board stays
/// claimable.
#[test]
fn the_fence_stands_before_the_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    ceremony_before_the_claim(port);
    let claimant = open_session(port, CLAIMANT_PRINCIPAL);
    let fresh = next_content_ordinal(port, Some(&claimant), CLAIMANT_DOC1);
    let before = head_position(port);
    let v = op(port, Some(&claimant), &cell_frame(CLAIMANT_DOC1, fresh, &canonical_cell(), Some(T_ENROLL)));
    assert_published_target(&v, "insert");
    let v = op(port, Some(&claimant), &cell_frame(CLAIMANT_DOC1, fresh, &canonical_cell(), None));
    assert_published_target(&v, "insert");
    assert_eq!(head_position(port), before, "nothing commits");
    assert!(!claimed(port));
    // The ceremony's last step, as `claim_board` makes it: the board claims
    // as it would have, the refusals having left no residue.
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    expect_resp(&op(port, Some(&signed), &claim_frame(CLAIMANT_DOC1, CLAIMANT_ACCOUNT)), "ack_addr");
    assert!(claimed(port), "the board claims as it would have");
    sd.shutdown();
}
