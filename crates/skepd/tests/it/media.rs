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

use std::path::Path;

use serde_json::{json, Value};
use skep_address::{validate, Address, Nat, Tumbler};
use skep_arrangement::{Caller, Deposit, VPos};
use skep_content::Val;
use skep_engine::{Engine, KernelConfig};
use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, SaltSource};
use skep_namespace::PrincipalId;

use crate::common;
use common::*;

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
/// second designation.
fn unknown_schema_value() -> String {
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
/// feed row. Answers the draft's address.
fn seed_pre_fence_draft(dir: &Path, principal: u64, account: &str, bytes: &[u8]) -> String {
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

/// M-I1 (a), M-I2 (e), M-I5 (c) — THE DRAFT INSERT's ADMITTED TWIN (media
/// lane B; the door matrix's cell 1 with the binding made real): the same
/// cell, its hash the bytes' the caller deposited under its own lease by a
/// PUT, is ADMITTED into the caller's draft from a bare and from a signed
/// session — the insert commits, the draft holds the cell — while another
/// principal's insert of the same cell into its own draft is refused
/// `unbound_cell` (the deposit is not theirs), a cell whose `size` is not
/// the file's length is refused `unbound_cell` (the size check at the same
/// door), and once the lease lapses the owner's own insert is refused
/// `lease_lapsed`, the deposit read listing the deposit no longer. The
/// owner's shot of the draft holding the admitted cell is admitted under
/// the live lease — the cell re-inserted into the edition.
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
    // The lease lapsed: the owner's own refusal, told apart from the
    // binding's; the read lists the deposit no longer.
    sd.daemon().advance_media_clock_ms(7 * 24 * 3600 * 1000);
    assert_eq!(deposits_of(port, &bare), vec![]);
    assert_token(&op(port, Some(&bare), &cell_frame(&owner_draft(port, &bare), 1, &cell, None)), "insert", "lease_lapsed");
    sd.shutdown();
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

/// M-I1 (a), (c) — THE SHOT'S OWNER TEST, ω exact, and the fence-only P10
/// face at the shot. Over a pre-fence journal holding three drafts — the
/// owner's with a cell, the owner's with a value under an unknown schema,
/// a sub-account's with a cell — a GRANTEE's, an ANCESTOR's and a
/// DESCENDANT's shot naming the owner's draft as its staging draft, each
/// reading it, is refused `not_owner` naming the draft (nothing minted:
/// their targets stay empty); the OWNER's own shot is refused `unbound_cell`
/// — no store exists, P10's form at the shot — and `unknown_cell_schema`
/// for the unknown form; a stranger who cannot read the draft meets the
/// store's `withheld` attested and the check's `attestation_required`
/// unattested, BEFORE this door; and prose or a def in the same position
/// takes the ordinary answer — the reader's shot lands. The whole armed set
/// lands together: every refusal commits nothing.
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

    // Arms 3 and 4 — the owner's own shot.
    let v = op(port, Some(&signed), &publish_frame(&edition, None, Some(&d_cell), &cell_run(&d_cell)));
    assert_token(&v, "publish", "unbound_cell");
    let v = op(port, Some(&signed), &publish_frame(&edition, None, Some(&d_unknown), &cell_run(&d_unknown)));
    assert_token(&v, "publish", "unknown_cell_schema");

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
