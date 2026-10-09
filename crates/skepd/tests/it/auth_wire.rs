//! The AUTH surface over real HTTP, one family per file:
//!
//! - `sessions` — the challenge→signed-session→op lifecycle, close and the
//!   death signal, `/health.auth`, the origin fences on both arms;
//! - `gates` — the publish-class and pre-claim gates' accept AND refuse
//!   cells, the first-mint door, the credential `nullify` cell;
//! - `credentials` — the refusals a credential deposit can be handed, which
//!   is where the one-way doors are: the claim's three eligibility laws
//!   (keyless, first-wins, tier — each, once wrong, unrecoverable, because
//!   a claimant never moves), the home pin and the precedence that decides
//!   a wrong-home deposit's token, the `malformed_payload:<sub>` join this
//!   crate composes rather than delegates, the caps, `preview_key` and
//!   `undecodable_key`, the credential idempotency memo (kind-BLIND, the
//!   one point it differs from M10's), `key_set` on `/op` and `/op-at`, and
//!   restart carrying the identity table back (the World's own slice,
//!   recovered with it);
//! - `blocked_prefixes` — the blocked-prefix list and the two accessors;
//! - `slot6` — slot (6) whole: the anchor gate's HANDOFF exception, told by
//!   address at the walk's terminus (AUTH-3.21) with the seat carve's one
//!   input, and the CONTENT-scoped session — the third body form, the v2
//!   bytes, and `content_session` at the head of the slot (RES-63).
//!
//! What more than one family uses lives here.

use crate::common;

use common::*;
use serde_json::Value;
use skep_identity::{
    encode_enroll, encode_retire, Enrollment, Fingerprint, PublicKey, ALG_FNDSA512_PREVIEW_ED25519,
    ALG_MLDSA65_ED25519, MAX_RECORD_BYTES,
};
use skep_signature::{HybridSigner, SeedCarrier as SigningKey};

mod blocked_prefixes;
mod credentials;
mod gates;
mod sessions;
mod slot6;

// `distinct_key`, `public_key_of`, `json_atom`, `enroll_atom` and
// `enroll_atom_flagged` are the shared helpers in `common` (lane 3.3c
// promoted them: the hire helper and the source-gate suite key delegated
// principals with the same deterministic seeds).

/// The fingerprint hex `key_set` publishes for a signing key.
fn fingerprint_hex(sk: &SigningKey) -> String {
    Fingerprint::of(&public_key_of(sk)).to_hex()
}

/// A TAG-3 hybrid signer for a seed carrier — the PREVIEW row, which the
/// fixture daemons admit (`allow_preview_keys` on) and a served board
/// refuses.
fn tag3_signer(sk: &SigningKey) -> HybridSigner {
    HybridSigner::from_seed(skep_signature::TAG_FNDSA512_PREVIEW_ED25519, &seed_of(sk))
        .expect("tag 3 is a row")
}

/// One retire record naming fingerprints, as its atom JSON fragment.
fn retire_atom(fps: &[&str]) -> String {
    let parsed: Vec<Fingerprint> =
        fps.iter().map(|h| Fingerprint::parse_hex(h).expect("64 hex")).collect();
    json_atom(&encode_retire(&parsed))
}

/// Land one credential record atom at `ordinal` of the claimant's doc 1 and
/// answer its address. The atom is a write into a published home, so it
/// needs a session the publish gate admits — a signed one on a claimed
/// board — and it carries the DEPOSIT DECLARATION (PUB-2.63; PUB-9.13's
/// DECLARED horn), since an undeclared insert into a published document is
/// the in-place edit the write path refuses (PUB-2.11). The declaration
/// names the record's CLASS (PUB-2.64): `ty` is the type the pair's
/// [`deposit`] then carries — `T_ENROLL` for an enrollment record, a
/// malformed one included, `T_RETIRE` for a retire record. Kept apart from
/// [`deposit`] for exactly that reason: the two writes meet different gates,
/// and only the second is the credential path's.
///
/// THE RECORD IS SIGNED (signed ops, 2a) for the deposit [`deposit`] makes
/// of it — homed in the claimant's doc 1, naming the claimant — under the
/// key that opened `signed_token` ([`signed_atom`]): the daemon verifies the
/// record's own `sig` at that deposit, at the grade the act needs, so a cell
/// whose deposit is anchor-grade lands its record from the ANCHOR's session.
/// A malformed atom is landed as given — the fold refuses it ahead of any
/// signature — and so is one a cell deposits elsewhere than [`deposit`]
/// does, whose refusal stands ahead of the check too.
fn land_claimant_record(port: u16, signed_token: &str, ordinal: u64, atom: &str, ty: &str) -> String {
    let atom = signed_atom(port, signed_token, CLAIMANT_DOC1, ty, &[CLAIMANT_ACCOUNT], atom);
    let v = op(
        port,
        Some(signed_token),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{ty}"}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    format!("{CLAIMANT_DOC1}.0.1.{ordinal}")
}

/// The deposit naming an already-landed record — the credential write under
/// test, and the one the precheck's ordered slots judge.
fn deposit(port: u16, token: &str, atom_addr: &str, ty: &str) -> Value {
    op(port, Some(token), &deposit_frame(None, atom_addr, ty))
}

/// [`deposit`]'s frame, optionally carrying an idempotency `id` — spelled
/// out because the credential memo is keyed on that field, so a test about
/// the memo must set it and a test about the slots must not.
fn deposit_frame(id: Option<&str>, atom_addr: &str, ty: &str) -> String {
    let id = id.map(|id| format!(r#""id":"{id}","#)).unwrap_or_default();
    format!(
        r#"{{"op":"make_link",{id}"home":"{CLAIMANT_DOC1}","from":{{"addrs":["{atom_addr}"]}},"to":{{"addrs":["{CLAIMANT_ACCOUNT}"]}},"ty":{{"addrs":["{ty}"]}}}}"#
    )
}

/// The claim ceremony's own last step, parameterized: `from` names the
/// claiming account, `to` is empty, and the deposit carries no payload at
/// all (AUTH-2.48), so — unlike [`deposit`] — it needs no record atom.
/// Every eligibility law refuses exactly this frame.
fn claim_deposit(port: u16, token: &str, doc1: &str, account: &str) -> Value {
    op(
        port,
        Some(token),
        &format!(
            r#"{{"op":"make_link","home":"{doc1}","from":{{"addrs":["{account}"]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{T_CLAIM}"]}}}}"#
        ),
    )
}

fn rejected_detail(v: &Value) -> String {
    assert_eq!(v["resp"].as_str(), Some("rejected"), "expected a rejection: {v}");
    format!(
        "{}:{}",
        v["code"].as_str().unwrap_or("?"),
        v["detail"].as_str().unwrap_or("-")
    )
}

/// The bootstrap principal, which maps to the CLAIMANT on both accessors
/// (AUTH-4.30) — so it signs with the claimant's keys, and an entry that
/// covers the claimant covers it.
const PRINCIPAL_ZERO: u64 = 0;

/// The suite's board in the registry: `--node-prefix 1.3` (REG-1.69), which
/// every listed board is launched with — so the off-board test is LIVE in
/// every vector, and a header's operator is on-board iff it sits under it.
const NODE_PREFIX: &str = "1.3";

/// A CLAIMED board (CLAIMED-PERMISSIVE) with the list's supply named and
/// the suite's node prefix: [`spawn_listed_at`] at [`NODE_PREFIX`].
fn spawn_listed(root: &std::path::Path) -> (skepd::Skepd, std::path::PathBuf) {
    spawn_listed_at(root, Some(NODE_PREFIX))
}

/// The supply file and the data dir, side by side under `root` — so a
/// restart over the same `root` meets the same file. The first issue is the
/// EMPTY list unless the file is already there, which is the restart cells'
/// case.
fn listed_dirs(root: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let list = root.join("blocked.json");
    if !list.exists() {
        issue_blocked_list(&list, BlockedHeader::default(), &[]);
    }
    let data = root.join("data");
    std::fs::create_dir_all(&data).expect("the data dir");
    (list, data)
}

/// A CLAIMED board (CLAIMED-PERMISSIVE) with the list's supply named and
/// `node_prefix` in force, or none.
fn spawn_listed_at(
    root: &std::path::Path,
    node_prefix: Option<&str>,
) -> (skepd::Skepd, std::path::PathBuf) {
    let (list, data) = listed_dirs(root);
    let sd = spawn_with_blocked_prefixes(&data, true, Some(&list), node_prefix);
    claim_board(sd.port()); // …whose own step writes H.1, for the attested writes below
    (sd, list)
}

/// A top-level member: delegated from the bootstrap principal and KEYED by a
/// hire into its genesis registry, the claimant's doc 1 (AUTH-2.62). The
/// registrar's session is the ANCHOR's, so the genesis commits whatever
/// grade the anchor gate asks of it.
fn keyed_member(port: u16, anchor: &str, id: u64, key: &SigningKey) -> String {
    let (account, _) = bootstrap_delegate(port, id);
    hire(port, anchor, CLAIMANT_DOC1, &account, id, key);
    account
}

/// Present `token` on a read and answer whether the daemon signalled its
/// death — the lazy kill's observable, on the cheapest route of the set.
fn presented_dead(port: u16, token: &str) -> bool {
    let (st, headers, _) = http_full(
        port,
        "POST",
        "/op",
        Some(token),
        br#"{"op":"next_account_prefix","parent":"1"}"#,
    );
    assert_eq!(st, 200);
    header(&headers, "Skepd-Session") == Some("closed")
}

/// The accounts the accessor cells stand on, under the claimant `X`: `X.1`
/// (the agent space, which takes no genesis — RES-80), `X.2` (a later child,
/// unseeded), and `X.2.7` (unseeded, beneath it). None holds a key set of
/// its own, so each opens BY REFERENCE.
struct ByReference {
    x1: u64,
    x2: u64,
    x2_account: String,
    x2_7: u64,
}

fn by_reference_accounts(port: u16) -> ByReference {
    let (x1, x2) = (951, 952);
    let x = open_session(port, CLAIMANT_PRINCIPAL);
    let (x1_account, _) = delegate_under(port, &x, CLAIMANT_ACCOUNT, x1);
    assert_eq!(x1_account, format!("{CLAIMANT_ACCOUNT}.1"));
    let (x2_account, x2_session) = delegate_under(port, &x, CLAIMANT_ACCOUNT, x2);
    assert_eq!(x2_account, format!("{CLAIMANT_ACCOUNT}.2"));
    // Next-form is mandatory, so `X.2.7` is the SEVENTH delegation under
    // `X.2`, and its principal the seventh id.
    let mut seventh = (String::new(), 0);
    for id in 9_571..=9_577u64 {
        seventh = (delegate_under(port, &x2_session, &x2_account, id).0, id);
    }
    assert_eq!(seventh.0, format!("{x2_account}.7"));
    ByReference { x1, x2, x2_account, x2_7: seventh.1 }
}

const ANCHOR_SESSION_REQUIRED: &str = "credential_refused:anchor_session_required";

/// Land one credential record atom at the next free position of `doc1` and
/// answer its address — [`land_claimant_record`] for a registry that is not the
/// claimant's, declared under the record's class type `ty` as that one is,
/// and SIGNED (signed ops, 2a) for the deposit naming `subject` that
/// [`enroll_for`] then makes of it, under the key that opened `session`
/// ([`signed_atom`]): the record's `sig` is verified at that deposit under
/// the set that opens `doc1`'s account, at the grade the act needs, so an
/// anchor-grade cell lands its record from the ANCHOR's session. `session`
/// is one the publish gate admits into a published home: a signed one, of
/// either scope.
fn land_record(port: u16, session: &str, doc1: &str, atom: &str, ty: &str, subject: &str) -> String {
    let atom = signed_atom(port, session, doc1, ty, &[subject], atom);
    let ordinal = next_content_ordinal(port, Some(session), doc1);
    acked_addr(&op(
        port,
        Some(session),
        &format!(
            r#"{{"op":"insert","doc":"{doc1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{ty}"}}"#
        ),
    ))
}

/// The enroll-typed deposit of an already-landed record, homed in `doc1` and
/// naming `account` — a GENESIS wherever `account` holds no set. UNJUDGED:
/// the answer is the cell.
fn enroll_for(port: u16, session: &str, doc1: &str, record: &str, account: &str) -> Value {
    typed_link(port, session, doc1, &[record], &[account], T_ENROLL)
}

/// How many keys `account`'s OWN set holds now, off the public read.
fn enrolled_count(port: u16, account: &str) -> usize {
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{account}"}}"#));
    expect_resp(&v, "key_set")["enrolled"].as_array().expect("enrolled").len()
}

/// One enroll record of a single fresh DEVICE-flagged key, by seed.
fn fresh_key_atom(seed: u8) -> String {
    enroll_atom(&[&distinct_key(seed)])
}
