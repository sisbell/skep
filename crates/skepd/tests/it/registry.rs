//! THE REGISTRY — its stable core walked as one org under a registrar: the
//! registrar's board and the binding (REG-1.1, REG-2.18 to REG-2.23,
//! REG-4.108), the console as a HARNESS — the binding write, the read-back
//! off the client's own `/changes` fold (REG-2.15 to REG-2.17), the
//! three-arm metadata read ahead of the node account's doc-1 mint
//! (REG-1.51, REG-1.52) — the endpoint deposit and its later records
//! (REG-1.9, REG-1.10, REG-1.86 (g)), THE RECORD GRADE FOR REGISTRY RECORDS
//! at both of a deposit's positions (REG-1.86 (e); SO-I4, SO-I2), the form
//! (REG-2.18 to REG-2.21, REG-2.26), the bodies' one canonical form at the
//! daemon (REG-1.86; a `type` that is not its slot's kind refused), the
//! seeding check's three arms (REG-1.28 to REG-1.32), and the
//! nested-delegation probe (REG-5.47). The audit-view refusal for the
//! registry's classes and the endpoint's effective `nullify` are
//! `nullify_class.rs`'s. Every cell names the rule it pins.
//!
//! The registrar's CONSOLE is the claimant's signed session: its key is in
//! the registrar's set, the one hand a binding write takes (REG-4.108). The
//! org's hand is its node account's own signed session, keyed by the
//! genesis enroll the console wrote into the registrar's doc 1.

use crate::common;

use std::collections::BTreeMap;

use common::*;
use serde_json::Value;
use skep_address::{validate, Address, Nat, Tumbler};
use skep_arrangement::deposit_class_types;
use skep_engine::types::pins_outside_the_registry;
use skep_registry::{
    row_at, rows, seeding_check, Body, BodyKind, Kind, Row, RowOf, SeedingRefusal, Subtype,
};

/// The node account's principal and its own key's seed, above every other
/// suite's ids.
const NODE_PRINCIPAL: u64 = 931;
const NODE_SEED: u8 = 31;
/// The nested account's principal (REG-5.47's probe).
const NESTED_PRINCIPAL: u64 = 932;

/// The registrar's board with the org's node account minted and keyed: the
/// console (the claimant's signed session), the node account — `delegate`d
/// from principal 0, its genesis enroll written into the registrar's own
/// doc 1 from the console, the credential record grade's cell as it stands
/// (REG-1.1, REG-4.110; the `hire` shape) — and the node account's own
/// signed session.
struct Board {
    console: String,
    node_account: String,
    node_signed: String,
}

fn registrar_board(port: u16) -> Board {
    let console = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let (node_account, _bare) = bootstrap_delegate(port, NODE_PRINCIPAL);
    let node_signed =
        hire(port, &console, CLAIMANT_DOC1, &node_account, NODE_PRINCIPAL, &distinct_key(NODE_SEED));
    Board { console, node_account, node_signed }
}

/// A response's verdict with the daemon's two families spelled alike —
/// `credential_refused:<token>`, `registry_refused:<token>` — as
/// [`verdict`] spells the first.
fn family_verdict(v: &Value) -> String {
    match (v["resp"].as_str(), v["code"].as_str(), v["detail"].as_str()) {
        (Some("rejected"), Some(code), Some(detail)) => format!("{code}:{detail}"),
        _ => verdict(v),
    }
}

/// The text a JSON string fragment spells — [`json_atom`]'s inverse, so a
/// signed atom's fragment can be landed as given.
fn unquote(fragment: &str) -> String {
    serde_json::from_str::<Value>(fragment)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .expect("a JSON string fragment")
}

/// An atom's text inserted DECLARED under `ty` at `home`'s next free
/// position from `signed`, AS GIVEN — no re-signing — the insert's answer
/// unjudged.
fn land(port: u16, signed: &str, home: &str, ty: &str, text: &str) -> Value {
    let ordinal = next_content_ordinal(port, Some(signed), home);
    op(
        port,
        Some(signed),
        &format!(
            r#"{{"op":"insert","doc":"{home}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{}}}],"deposit":"{ty}"}}"#,
            json_atom(text)
        ),
    )
}

/// The `make_link` typed `ty` from `from` to `to`, homed in `home`, from
/// `signed` — unjudged.
fn link(port: u16, signed: &str, home: &str, from: &[&str], to: &[&str], ty: &str) -> Value {
    op(port, Some(signed), &typed_link_frame(home, from, to, ty))
}

/// The one address a stored link's slot names, or none.
fn slot_addrs(link: &Value, slot: usize) -> Vec<String> {
    link["slots"][slot]
        .as_array()
        .map(|spans| spans.iter().filter_map(|s| s["start"].as_str().map(str::to_owned)).collect())
        .unwrap_or_default()
}

/// THE CLIENT'S OWN INDEX OF THE BINDINGS, folded off `/changes` as a GUEST
/// (REG-2.16; the resolver's prefix → binding index): every `make_link`
/// row whose link's type slot is the binding's, the atom read off its
/// `from` — in an append-only doc 1 the atom's I-ordinal is its content
/// ordinal — parsed under the canonical rule, the account off its `to`, in
/// journal order, the FIRST binding for a prefix winning (REG-2.8, REG-2.9).
/// `prefix → (the link, the holder)`.
fn fold_bindings(port: u16) -> BTreeMap<String, (String, Option<String>)> {
    let (st, body) = http(port, "GET", "/changes?since=0", None, b"");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let mut index = BTreeMap::new();
    for row in json(&body)["changes"].as_array().expect("changes") {
        if row["op"].as_str() != Some("make_link") {
            continue;
        }
        let Some(address) = row["link"].as_str() else { continue };
        let stored = read_link(port, None, address);
        if stored.is_null() || slot_addrs(&stored, 2) != [T_BINDING.to_string()] {
            continue;
        }
        let [atom] = &slot_addrs(&stored, 0)[..] else { continue };
        let ordinal: u64 = atom.rsplit('.').next().expect("an ordinal").parse().expect("a count");
        let items = delivery(port, None, &origin_of(atom), ordinal, 1);
        let text = items[0]["atom"].as_str().expect("the atom's text");
        let record = skep_registry::parse(BodyKind::Binding, text.as_bytes())
            .expect("a committed binding is a binding under the canonical rule");
        let Body::Binding(binding) = record.body else { unreachable!("a binding") };
        let holder = slot_addrs(&stored, 1).first().cloned();
        index.entry(binding.prefix.to_string()).or_insert((address.to_string(), holder));
    }
    index
}

/// The console's next-form derivation off its own index: the next node
/// prefix under `1` after `1.1`, the registry node's own, and the prefixes
/// its bindings hold.
fn next_prefix(index: &BTreeMap<String, (String, Option<String>)>) -> String {
    format!("1.{}", 2 + index.len())
}

/// REG-1.51, REG-1.52 — THE NODE ACCOUNT'S DOC 1, minted from its first
/// signed session ahead of its first endpoint deposit, idempotent by
/// reading: `doc_metadata` on the computable address `{account}.0.1` —
/// NO document (`doc_not_registered`): mint `create_new_document` with
/// `published` passed affirmatively; a PUBLISHED document: resume at the
/// deposit; a DRAFT document: refuse LOUDLY — the state the base cannot
/// produce. The doc 1's address.
fn mint_doc_one_if_absent(port: u16, signed: &str, account: &str) -> String {
    let doc1 = format!("{account}.0.1");
    let v = op(port, Some(signed), &doc_metadata_frame(&doc1));
    match v["resp"].as_str() {
        Some("rejected") => {
            assert_eq!(verdict(&v), "doc_not_registered", "the NO-document arm: {v}");
            let minted = acked_addr(&op(port, Some(signed), &create_frame(account, Some(true))));
            assert_eq!(minted, doc1, "the first mint is doc 1");
            minted
        }
        Some("doc_metadata") => {
            assert_eq!(
                v["published"].as_bool(),
                Some(true),
                "REG-1.52's DRAFT arm: a draft doc 1 is a corruption case, refused loudly: {v}"
            );
            doc1
        }
        _ => panic!("the three-arm read: {v}"),
    }
}

fn addr(s: &str) -> Address {
    let comps = s.split('.').map(|c| Nat::from(c.parse::<u64>().expect("a component")));
    validate(Tumbler::new(comps).expect("a tumbler")).expect("an address")
}

/// THE WALK (the registry's core, one org): the registrar claims the board;
/// its console mints the node account and writes its genesis; THE BINDING
/// — the canonical body signed at the record grade under the claimant's
/// key, `insert` declared under the binding's type then the `make_link`
/// from the atom to the node account — COMMITS (REG-2.18, REG-2.19,
/// REG-2.23, REG-4.108, REG-1.86 (e)), its two rows on `/changes` read by a
/// GUEST: the atom's row carrying `key` and no `attest`, the link's row
/// carrying neither — signed by its record's own `sig`, as a credential
/// deposit's link row is; THE READ-BACK (REG-2.16): two clients fold their
/// own index off `/changes` and agree on the prefix's holder; THE NODE
/// ACCOUNT'S DOC 1 minted published from its first signed session behind
/// the three-arm read, resumed on a second read (REG-1.51, REG-1.52); THE
/// ENDPOINT signed under the node account's key — COMMITS (REG-1.9); a
/// LATER endpoint naming the first link's address in `replaces` — COMMITS,
/// and so does one naming a link no longer current: the daemon checks the
/// form of `replaces` and never its currency, which is the reader's
/// (REG-1.10, REG-1.86 (g), REG-2.24).
#[test]
fn the_registrar_binds_a_prefix_two_consoles_read_it_back_and_the_org_deposits_its_endpoint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = registrar_board(port);

    // THE BINDING, at the next prefix off the console's own index.
    let index = fold_bindings(port);
    assert!(index.is_empty(), "no binding yet: {index:?}");
    let prefix = next_prefix(&index);
    assert_eq!(prefix, "1.2");
    let before = head_position(port);
    let (atom, v) = deposit_registry_record(
        port,
        &board.console,
        CLAIMANT_DOC1,
        T_BINDING,
        &[&board.node_account],
        &binding_body(&prefix, None),
    );
    let binding = acked_addr(&v);
    let link_at = acked_at(&v);
    let stored = read_link(port, None, &binding);
    assert_eq!(slot_addrs(&stored, 0), [atom.clone()], "from the atom's verified I-address");
    assert_eq!(slot_addrs(&stored, 1), [board.node_account.clone()], "to the account bound");
    assert_eq!(slot_addrs(&stored, 2), [T_BINDING.to_string()]);

    // THE TWO ROWS on /changes, read by a GUEST (D12; wire.md §The change
    // feed): the atom's row testifies the writing session; the link's row,
    // signed by its record, serves neither `key` nor `attest`.
    let (st, body) = http(port, "GET", &format!("/changes?since={before}"), None, b"");
    assert_eq!(st, 200);
    let page = json(&body);
    let rows = page["changes"].as_array().expect("changes");
    assert_eq!(rows.len(), 2, "before={before} link_at={link_at}: {page}");
    let (atom_row, link_row) = (&rows[0], &rows[1]);
    assert_eq!(atom_row["op"].as_str(), Some("insert"));
    assert!(atom_row["key"].as_str().is_some_and(|k| k != "bare"), "the atom's row: {atom_row}");
    assert!(atom_row.get("attest").is_none(), "the atom's row: {atom_row}");
    assert_eq!(link_row["op"].as_str(), Some("make_link"));
    assert_eq!(link_row["link"].as_str(), Some(binding.as_str()));
    assert!(link_row.get("key").is_none(), "the link's row carries no key: {link_row}");
    assert!(link_row.get("attest").is_none(), "the link's row carries no attest: {link_row}");

    // THE READ-BACK (REG-2.16): two clients, one index each, one answer.
    let (one, two) = (fold_bindings(port), fold_bindings(port));
    assert_eq!(one, two, "two consoles derive one index");
    assert_eq!(one.get(&prefix), Some(&(binding.clone(), Some(board.node_account.clone()))));
    assert_eq!(next_prefix(&one), "1.3", "the next console takes the next prefix");

    // THE NODE ACCOUNT'S DOC 1 (REG-1.51, REG-1.52), then THE ENDPOINT.
    let doc1 = mint_doc_one_if_absent(port, &board.node_signed, &board.node_account);
    assert_eq!(doc1, format!("{}.0.1", board.node_account));
    assert_eq!(doc1, mint_doc_one_if_absent(port, &board.node_signed, &board.node_account), "resumed");
    let first = deposit_endpoint(port, &board.node_signed, &doc1, &["https://acme.example"], None);
    let stored = read_link(port, None, &first);
    assert!(slot_addrs(&stored, 1).is_empty(), "targetless: {stored}");
    let later = deposit_endpoint(port, &board.node_signed, &doc1, &["https://acme.example.net"], Some(&first));
    assert_ne!(later, first);
    let stale = deposit_endpoint(port, &board.node_signed, &doc1, &["https://acme.example.org"], Some(&first));
    assert_ne!(stale, later, "a record naming a state no longer current commits and is inert at the reader");
    sd.shutdown();
}

/// REG-2.21 — THE TARGETLESS BINDING: a binding naming NO account is a
/// binding-typed link with no target, the one spelling of expulsion and
/// every retirement; it carries the same body and COMMITS, and the
/// read-back shows the prefix held by nobody.
#[test]
fn a_targetless_binding_commits_and_reads_back_as_no_holder() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = registrar_board(port);
    let bound = deposit_binding(port, &board.console, "1.2", Some(&board.node_account), None);
    let retired = deposit_binding(port, &board.console, "1.2", None, Some(&bound));
    assert!(slot_addrs(&read_link(port, None, &retired), 1).is_empty());
    let unbound = deposit_binding(port, &board.console, "1.3", None, None);
    let index = fold_bindings(port);
    assert_eq!(index.get("1.3"), Some(&(unbound, None)), "a prefix bound to nobody");
    assert_eq!(index.get("1.2").map(|(l, _)| l), Some(&bound), "first wins at the walk; the retirement is a later record");
    sd.shutdown();
}

/// SO-I4; the exemption widened (REG-1.86 (e)) — an UNSIGNED binding atom
/// above the claim is refused at its `insert`, `record_sig_required`,
/// PERMANENT, under the credential family's code (the insert is the plain
/// path's), nothing landed: a record of the declared kind carrying no `sig`
/// is no exempt atom, and the earliest act the fault is decidable from
/// refuses it.
#[test]
fn an_unsigned_binding_atom_above_the_claim_is_refused_at_its_insert() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = registrar_board(port);
    let before = head_position(port);
    let v = land(port, &board.console, CLAIMANT_DOC1, T_BINDING, &binding_body("1.2", None));
    assert_eq!(family_verdict(&v), "credential_refused:record_sig_required", "{v}");
    assert_eq!(v["disposition"].as_str(), Some("permanent"));
    let v = land(port, &board.console, CLAIMANT_DOC1, T_ENDPOINT, &endpoint_body(&["https://a.example"], None));
    assert_eq!(family_verdict(&v), "credential_refused:record_sig_required", "{v}");
    assert_eq!(head_position(port), before, "nothing landed, no orphan");
    sd.shutdown();
}

/// REG-1.86 (e); SO-I2 — THE TRIAL'S REFUSALS at the binding's `make_link`,
/// each under the registry's own code: a record signed by a key NOT in the
/// claimant's set (the set that opens the registrar's doc 1) is
/// `attestation_invalid:signature`; a record whose `sig` is hex of no row's
/// width is `attestation_invalid:malformed`; both PERMANENT, nothing
/// committed at the link — each atom, carrying a `sig`, landed exempt and
/// stays an orphan no link names.
#[test]
fn a_binding_signed_by_a_foreign_key_or_a_malformed_sig_is_refused_at_its_link() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = registrar_board(port);
    let to = [board.node_account.as_str()];
    let body = binding_body("1.2", None);
    // A key outside the claimant's set.
    let foreign = hybrid_signer(&distinct_key(77));
    let text = signed_registry_text(port, &foreign, CLAIMANT_DOC1, T_BINDING, &to, &body)
        .expect("the frame composes");
    let atom = acked_addr(&land(port, &board.console, CLAIMANT_DOC1, T_BINDING, &text));
    let before = head_position(port);
    let v = link(port, &board.console, CLAIMANT_DOC1, &[&atom], &to, T_BINDING);
    assert_eq!(family_verdict(&v), "registry_refused:attestation_invalid:signature", "{v}");
    assert_eq!(v["disposition"].as_str(), Some("permanent"));
    assert_eq!(head_position(port), before, "no link committed");
    // A `sig` of no row's width.
    let record = skep_registry::parse(BodyKind::Binding, body.as_bytes()).expect("canonical");
    let text = skep_registry::encode(&record.body, Some("abcd"));
    let atom = acked_addr(&land(port, &board.console, CLAIMANT_DOC1, T_BINDING, &text));
    let before = head_position(port);
    let v = link(port, &board.console, CLAIMANT_DOC1, &[&atom], &to, T_BINDING);
    assert_eq!(family_verdict(&v), "registry_refused:attestation_invalid:malformed", "{v}");
    assert_eq!(head_position(port), before, "no link committed");
    assert!(fold_bindings(port).is_empty(), "no binding stands: the atoms are orphans no link names");
    sd.shutdown();
}

/// REG-2.18, REG-1.9 — THE HOME PIN: a binding homed outside a doc 1 — a
/// published edition of the claimant's — is refused `not_doc_one` at its
/// link; its signed atom, outside the exemption's reach, took the entry
/// signature and committed as an ordinary deposit.
#[test]
fn a_binding_homed_outside_a_doc_1_is_refused_not_doc_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = registrar_board(port);
    let edition = published_edition(port, &board.console);
    let to = [board.node_account.as_str()];
    let text = signed_atom(port, &board.console, &edition, T_BINDING, &to, &json_atom(&binding_body("1.2", None)));
    let v = land(port, &board.console, &edition, T_BINDING, &unquote(&text));
    let atom = acked_addr(&v);
    assert!(sd.daemon().attestation_at(skep_kernel::Seq(acked_at(&v))).unwrap().is_some(), "outside a doc 1 the atom takes the entry signature");
    let v = link(port, &board.console, &edition, &[&atom], &to, T_BINDING);
    assert_eq!(family_verdict(&v), "registry_refused:not_doc_one", "{v}");
    assert_eq!(v["disposition"].as_str(), Some("permanent"));
    sd.shutdown();
}

/// REG-1.32 — ON THE UNCLAIMED BOARD a binding's link is refused
/// `claim_first`: the only registry rows below the claim are the seeded
/// pins, and the record grade judges nothing there (A5) — the bare atom
/// lands, as the ceremony's own does, and its link does not.
#[test]
fn a_binding_on_the_unclaimed_board_is_refused_claim_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    ceremony_before_the_claim(port);
    let claimant = open_session(port, CLAIMANT_PRINCIPAL);
    let (node_account, _) = bootstrap_delegate(port, NODE_PRINCIPAL);
    let atom = acked_addr(&land(port, &claimant, CLAIMANT_DOC1, T_BINDING, &binding_body("1.2", None)));
    let v = link(port, &claimant, CLAIMANT_DOC1, &[&atom], &[&node_account], T_BINDING);
    assert_eq!(family_verdict(&v), "registry_refused:claim_first", "{v}");
    assert_eq!(v["disposition"].as_str(), Some("permanent"));
    assert!(!claimed(port));
    sd.shutdown();
}

/// SO-I2 (g)(iv); REG-1.32 — THE SYSTEM ACCOUNT'S DOC 1 ADMITS NO REGISTRY
/// RECORD. On the UNCLAIMED board a bare session bound as the system
/// principal inserting a binding atom into `1.1.0.1`'s doc 1 is refused
/// `system_account_keyless` at the pre-claim gate — the arm that refuses a
/// credential kind there, widened. On the CLAIMED board no session is the
/// system principal's and the account holds no key, so no atom is ever read
/// there: a binding link homed in that doc 1 from the registrar's console,
/// naming a position in it, is refused `registry_form` — the record read
/// finds no atom — before any trial; the trial would answer
/// `attestation_invalid:not_enrolled_at_position` over the account's empty
/// set, which the policy module's own cell pins. The system account's key
/// set stays empty.
#[test]
fn the_system_accounts_doc_1_admits_no_registry_record() {
    const SYSTEM_PRINCIPAL: u64 = 9_000_000_000_000_000;
    const SYSTEM_ACCOUNT: &str = "1.1.0.1";
    const SYSTEM_DOC1: &str = "1.1.0.1.0.1";
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_configured(dir.path(), true);
    let port = sd.port();
    let system = open_session(port, SYSTEM_PRINCIPAL);
    let before = head_position(port);
    let v = land(port, &system, SYSTEM_DOC1, T_BINDING, &binding_body("1.2", None));
    assert_eq!(family_verdict(&v), "credential_refused:system_account_keyless", "{v}");
    let v = land(port, &system, SYSTEM_DOC1, T_ENDPOINT, &endpoint_body(&["https://a.example"], None));
    assert_eq!(family_verdict(&v), "credential_refused:system_account_keyless", "{v}");
    assert_eq!(head_position(port), before, "nothing landed");
    claim_board(port);
    let board = registrar_board(port);
    let position = format!("{SYSTEM_DOC1}.0.1.1");
    let v = link(port, &board.console, SYSTEM_DOC1, &[&position], &[&board.node_account], T_BINDING);
    assert_eq!(family_verdict(&v), "registry_refused:registry_form", "{v}");
    let set = op(port, None, &format!(r#"{{"op":"key_set","account":"{SYSTEM_ACCOUNT}"}}"#));
    assert_eq!(set["enrolled"].as_array().map(Vec::len), Some(0), "{set}");
    sd.shutdown();
}

/// REG-2.19 to REG-2.21, REG-2.23, REG-2.26, REG-1.86 (g) — THE FORM, each
/// fault `registry_form`, PERMANENT, nothing committed: a binding's `to` of
/// two addresses; a `to` naming a document; a `to` naming an unregistered
/// account; a `from` of two addresses; a `replaces` member on the link (the
/// member rides the signed body); an `emit` typed binding; and an endpoint
/// with a target — its carriage is a link from the atom with NO target.
#[test]
fn a_form_fault_is_refused_registry_form() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = registrar_board(port);
    let node = board.node_account.as_str();
    let signed = |to: &[&str], ty: &str, body: &str| -> String {
        let text = signed_atom(port, &board.console, CLAIMANT_DOC1, ty, to, &json_atom(body));
        acked_addr(&land(port, &board.console, CLAIMANT_DOC1, ty, &unquote(&text)))
    };
    let binding_atom = signed(&[node], T_BINDING, &binding_body("1.2", None));
    let endpoint_atom = signed(&[], T_ENDPOINT, &endpoint_body(&["https://acme.example"], None));
    let before = head_position(port);
    let form = "registry_refused:registry_form";
    let cells: Vec<(&str, Value)> = vec![
        ("a to of two addresses", link(port, &board.console, CLAIMANT_DOC1, &[&binding_atom], &[node, CLAIMANT_ACCOUNT], T_BINDING)),
        ("a to naming a document", link(port, &board.console, CLAIMANT_DOC1, &[&binding_atom], &[CLAIMANT_DOC1], T_BINDING)),
        ("a to naming an unregistered account", link(port, &board.console, CLAIMANT_DOC1, &[&binding_atom], &["1.0.99"], T_BINDING)),
        ("a from of two addresses", link(port, &board.console, CLAIMANT_DOC1, &[&binding_atom, &endpoint_atom], &[node], T_BINDING)),
        ("an endpoint with a target", link(port, &board.console, CLAIMANT_DOC1, &[&endpoint_atom], &[node], T_ENDPOINT)),
        (
            "a replaces member on the link",
            op_as_written(
                port,
                Some(&board.console),
                &format!(
                    r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":["{binding_atom}"]}},"to":{{"addrs":["{node}"]}},"ty":{{"addrs":["{T_BINDING}"]}},"replaces":"{CLAIMANT_DOC1}.0.2.1"}}"#
                ),
            ),
        ),
        (
            "an emit typed binding",
            op_as_written(
                port,
                Some(&board.console),
                &format!(
                    r#"{{"op":"emit","home":"{CLAIMANT_DOC1}","ty":[{{"start":"{T_BINDING}","width":"0.0.0.0.0.0.0.0.1"}}],"from":"{binding_atom}","to":[]}}"#
                ),
            ),
        ),
    ];
    for (what, v) in &cells {
        assert_eq!(family_verdict(v), form, "{what}: {v}");
        assert_eq!(v["disposition"].as_str(), Some("permanent"), "{what}: {v}");
    }
    assert_eq!(head_position(port), before, "nothing committed");
    // …and the well-formed link from the same atom commits: the faults were
    // the links', never the record's.
    expect_resp(&link(port, &board.console, CLAIMANT_DOC1, &[&binding_atom], &[node], T_BINDING), "ack_addr");
    sd.shutdown();
}

/// REG-1.86 (a), (d); the one canonical form — THE RECORD VALUE at the
/// link: a body whose `type` is `"endpoint"` under a binding slot is
/// `malformed_record:wrong_type`, a body with a JSON number
/// `malformed_record:number`, a body with a space `malformed_record:not_canonical`
/// — each PERMANENT, the atom having landed as an ordinary attested deposit
/// (no record of the declared kind, so no exemption) and no link
/// committed.
#[test]
fn a_body_that_is_no_record_of_the_slots_kind_is_refused_malformed_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = registrar_board(port);
    let node = board.node_account.as_str();
    let cases = [
        ("wrong_type", endpoint_body(&["https://acme.example"], None)),
        ("number", r#"{"type":"binding","prefix":15}"#.to_string()),
        ("not_canonical", r#"{"type": "binding", "prefix": "1.5"}"#.to_string()),
    ];
    for (cause, text) in cases {
        let v = land(port, &board.console, CLAIMANT_DOC1, T_BINDING, &text);
        let atom = acked_addr(&v);
        assert!(sd.daemon().attestation_at(skep_kernel::Seq(acked_at(&v))).unwrap().is_some(), "{cause}: no record of the kind, so the atom took the entry signature");
        let before = head_position(port);
        let v = link(port, &board.console, CLAIMANT_DOC1, &[&atom], &[node], T_BINDING);
        assert_eq!(family_verdict(&v), format!("registry_refused:malformed_record:{cause}"), "{v}");
        assert_eq!(v["disposition"].as_str(), Some("permanent"));
        assert_eq!(head_position(port), before);
    }
    sd.shutdown();
}

/// REG-1.18, REG-1.37 — a declared `insert` under a registry row the deposit
/// class does not hold — the disavowal `3.58.2`, the takedown record's base
/// reading `3.57.1`, the policy link's bare ordinal `3.58` — is refused
/// `published_target` at M5's door, as a declaration under any type outside
/// the class is: those rows join the class where their schemas are pinned.
#[test]
fn a_declared_insert_under_an_unpinned_registry_row_is_refused_at_the_door() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = registrar_board(port);
    for row in ["1.1.0.1.0.1.0.3.58.2", "1.1.0.1.0.1.0.3.57.1", "1.1.0.1.0.1.0.3.58"] {
        let v = land(port, &board.console, CLAIMANT_DOC1, row, r#"{"type":"disavowal"}"#);
        assert_eq!(verdict(&v), "published_target", "{row}: {v}");
    }
    sd.shutdown();
}

/// REG-1.28 to REG-1.32 — THE SEEDING CHECK as the daemon's genesis hand
/// runs it: the shipped lists pass over the domain the daemon reads — the
/// engine's pins outside the registry, the three credential constants and
/// M5's deposit-class members that are no registry row — so every board in
/// this suite is a genesis that completed; and each arm refuses a list this
/// cell builds, through the check function: a foreign row placed inside the
/// policy link's kind (disjointness), the LIFTED row dropped
/// (completeness), a sixth kind row (the count). The daemon's lists are
/// compiled constants with no hook to mutate them, so no daemon is opened
/// over a failing list here: the refusal's rendering, which the open's
/// error carries, is pinned on the function's answer.
#[test]
fn the_seeding_check_passes_the_shipped_lists_and_refuses_each_arm_on_a_mutated_list() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    assert!(claimed(sd.port()), "the open ran the check and the genesis completed");
    let domain: Vec<Address> = pins_outside_the_registry()
        .into_iter()
        .cloned()
        .chain([T_ENROLL, T_RETIRE, T_CLAIM].iter().map(|c| addr(c)))
        .chain(deposit_class_types().iter().filter(|ty| row_at(ty).is_none()).cloned())
        .collect();
    assert_eq!(domain.len(), 8 + 3 + 2);
    assert_eq!(seeding_check(rows(), &domain), Ok(()));

    let mut collided = domain.clone();
    collided.push(addr("1.1.0.1.0.1.0.3.58.6"));
    let refusal = seeding_check(rows(), &collided).unwrap_err();
    assert!(matches!(refusal, SeedingRefusal::Disjointness { .. }), "{refusal}");
    assert!(refusal.to_string().contains("1.1.0.1.0.1.0.3.58.6"), "{refusal}");

    let incomplete: Vec<Row> = rows()
        .iter()
        .filter(|r| r.of != RowOf::Subtype(Subtype::TakedownLifted))
        .cloned()
        .collect();
    let refusal = seeding_check(&incomplete, &domain).unwrap_err();
    assert_eq!(
        refusal,
        SeedingRefusal::Completeness { missing: RowOf::Subtype(Subtype::TakedownLifted) }
    );

    let mut sixth: Vec<Row> = rows().to_vec();
    sixth.push(Row {
        of: RowOf::Kind(Kind::Binding),
        address: addr("1.1.0.1.0.1.0.3.54"),
        type_value: Some("binding"),
    });
    let refusal = seeding_check(&sixth, &domain).unwrap_err();
    assert_eq!(refusal, SeedingRefusal::Count { kind_rows: 6, row: None });
    assert_eq!(refusal.arm(), "count");
    sd.shutdown();
}

/// REG-5.47 — THE BUILD-ROUND PROBE: whether M3's delegation handles a
/// NESTED account — next-form under an owned prefix, ω-gated to its owner
/// — exactly as at the root. From the node account's signed session,
/// `delegate` its first sub-account; open that principal's signed session —
/// it holds no set of its own and opens BY REFERENCE against the node
/// account's (AUTH-4.30 (i)); mint its doc 1 behind the three-arm read; and
/// deposit an endpoint there, signed under that key, the trial's candidates
/// the set that opens the nested account's home. Horn A where every step
/// commits as at the root; a refusal anywhere is Horn B and names itself.
#[test]
fn reg_5_47_a_nested_delegation_takes_an_endpoint_as_the_root_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = registrar_board(port);
    let v = op(
        port,
        Some(&board.node_signed),
        &format!(r#"{{"op":"next_account_prefix","parent":"{}"}}"#, board.node_account),
    );
    let nested = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("next-form under the node account").to_string();
    assert_eq!(nested, format!("{}.1", board.node_account), "next-form under an owned prefix");
    let v = op(
        port,
        Some(&board.node_signed),
        &format!(r#"{{"op":"delegate","new_prefix":"{nested}","new_id":{NESTED_PRINCIPAL}}}"#),
    );
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "Horn B at the delegation: {v}");
    let nested_signed = open_signed_session(port, NESTED_PRINCIPAL, &distinct_key(NODE_SEED));
    let doc1 = mint_doc_one_if_absent(port, &nested_signed, &nested);
    assert_eq!(doc1, format!("{nested}.0.1"));
    let (_, v) = deposit_registry_record(
        port,
        &nested_signed,
        &doc1,
        T_ENDPOINT,
        &[],
        &endpoint_body(&["https://legal.acme.example"], None),
    );
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "Horn B at the nested endpoint: {v}");
    let later = deposit_endpoint(port, &nested_signed, &doc1, &["https://legal.acme.example.net"], Some(&acked_addr(&v)));
    assert!(!later.is_empty(), "Horn A: the nested account's endpoint and its later record commit as at the root");
    sd.shutdown();
}
