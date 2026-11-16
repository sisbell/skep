//! THE REGISTRATION KIND AT THE BOARD — the board accepting a door's
//! admission records as the rules pin them (REG-1.23, REG-2.26, REG-2.27;
//! REG-4.78, REG-4.81, REG-4.104, REG-4.185): each deposit-carrying row —
//! a request's two kinds, the three answers, the vouch — an atom plus a
//! link at the record grade, as a binding is; the rows that carry no
//! deposit — the kind's own, the parent rows `request` and `reply`, the
//! approval, a link alone — taking no atom; the `to` each row's own; a
//! request's signed `shape` naming the row its link is typed; the bodies
//! under the canonical rule and each kind's cap at the daemon; and the
//! approval link committing link-alone at the entry grade. The audit-view
//! refusal for the kind's rows is `nullify_class.rs`'s, and the rows'
//! seeding `vocabulary.rs`'s. Every cell names the rule it pins.
//!
//! THE HANDS: the registrar's console is the claimant's signed session,
//! which writes the answers and the approval link into the binding-writing
//! account's own doc 1; the WRITER of a request and of a vouch is an
//! account under the board holding its own doc 1 — the org's node account
//! here, standing for an intake scribe, a root sponsor or a voucher — which
//! writes into that doc 1 under its own key. The board checks no more of a
//! request than its form: whether its home is an admitted one, its door
//! this door's, its freshness value unspent and its signer enrolled are a
//! console's (REG-4.78).
//!
//! Every walk runs on an ENFORCING board, as `registry.rs`'s do; the two
//! cells whose subject is another board — an unclaimed one, and a bare
//! session's — open their own.

use crate::common;
use crate::registry::{
    family_verdict, land, link, mint_doc_one_if_absent, registrar_board, slot_addrs, unquote,
    Board,
};

use common::*;
use serde_json::Value;
use skep_registry::{
    encode_registration, parse_registration, RegistrationBody, RegistrationKind,
    MAX_REGISTRATION_REQUEST_BYTES, MAX_REGISTRY_RECORD_BYTES,
};

const FORM: &str = "registry_refused:registry_form";

/// The six rows that carry a deposit, in the table's order.
const DEPOSIT_ROWS: [&str; 6] = [
    T_REQUEST_FRESH,
    T_REQUEST_BOARD_CARRIES_ON,
    T_REPLY_APPROVED,
    T_REPLY_REFUSED,
    T_REPLY_DENIED,
    T_VOUCH,
];

/// A row's ordinal path, as a request's `shape` spells it.
fn shape_of(ty: &str) -> String {
    ty.strip_prefix("1.1.0.1.0.1.0.").expect("a commons type").to_string()
}

/// A body of the row `ty`, well-formed: a request whose `shape` is its own
/// row's, an answer, or a first vouch.
fn body_of(ty: &str) -> String {
    match ty {
        T_REQUEST_FRESH | T_REQUEST_BOARD_CARRIES_ON => request_body(ty, &shape_of(ty)),
        T_REPLY_APPROVED | T_REPLY_REFUSED | T_REPLY_DENIED => answer_body(ty),
        T_VOUCH => vouch_body(None),
        other => panic!("{other} carries no body"),
    }
}

/// The registrar's board with a writer's home: the node account's doc 1,
/// minted from its own signed session.
struct Door {
    board: Board,
    writer: String,
}

fn door(port: u16) -> Door {
    let board = registrar_board(port);
    let writer = mint_doc_one_if_absent(port, &board.node_signed, &board.node_account);
    Door { board, writer }
}

impl Door {
    /// The hand, the home and the `to` a row's well-formed deposit takes: a
    /// request and a vouch from the writer into its own doc 1, to the
    /// board's binding-writing account; an answer from the console into
    /// the registrar's doc 1, to `request`.
    fn seat<'a>(&'a self, ty: &str, request: &'a str) -> (&'a str, &'a str, [&'a str; 1]) {
        match ty {
            T_REPLY_APPROVED | T_REPLY_REFUSED | T_REPLY_DENIED => {
                (&self.board.console, CLAIMANT_DOC1, [request])
            }
            _ => (&self.board.node_signed, &self.writer, [CLAIMANT_ACCOUNT]),
        }
    }

    /// A well-formed record of the row `ty` deposited from its own seat —
    /// `(the atom, the link's answer)`.
    fn deposit(&self, port: u16, ty: &str, request: &str) -> (String, Value) {
        let (signed, home, to) = self.seat(ty, request);
        deposit_registry_record(port, signed, home, ty, &to, &body_of(ty))
    }

    /// `text`, signed for the row's seat, landed as an atom — its address.
    fn signed_atom(&self, port: u16, ty: &str, request: &str, text: &str) -> String {
        let (signed, home, to) = self.seat(ty, request);
        let atom = signed_registry_atom(port, signed, home, ty, &to, text);
        acked_addr(&land(port, signed, home, ty, &unquote(&atom)))
    }
}

/// The text of the atom at `atom`, as a guest reads it.
fn atom_text(port: u16, atom: &str) -> String {
    let ordinal: u64 = atom.rsplit('.').next().expect("an ordinal").parse().expect("a count");
    let items = delivery(port, None, &origin_of(atom), ordinal, 1);
    items[0]["atom"].as_str().expect("the atom's text").to_string()
}

/// REG-1.23, REG-2.26, REG-2.27; R7 (a), R8 — EACH DEPOSIT-CARRYING ROW
/// COMMITS FROM A DOC 1 UNDER THE KEY OF THAT HOME's SET: a request of each
/// kind and a vouch from the writer's own doc 1, signed under the writer's
/// key, `to` the board's binding-writing account; each of the three answers
/// from the registrar's doc 1, signed under the claimant's key, `to` the
/// request's link; and a re-vouch naming the vouch it follows. Each is the
/// atom's `insert`, declared under the row's own address and exempt from
/// the entry signature, then the `make_link` typed that row, verified at
/// the record grade — its two rows on `/changes` read by a GUEST as a
/// binding's are: the atom's carrying `key` and no `attest`, the link's
/// carrying neither. And the atom a guest reads back is the row's record
/// under the canonical rule, its `sig` the writing hand's.
#[test]
fn each_deposit_carrying_row_commits_from_a_doc_1_under_its_homes_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_enforcing(dir.path());
    let port = sd.port();
    assert_enforcing(port);
    let d = door(port);
    let mut request = String::new();
    for ty in DEPOSIT_ROWS {
        let before = head_position(port);
        let (signed, home, to) = d.seat(ty, &request);
        let (atom, v) = d.deposit(port, ty, &request);
        assert_eq!(v["resp"].as_str(), Some("ack_addr"), "{ty}: {v}");
        let deposited = acked_addr(&v);
        assert!(deposited.starts_with(&format!("{home}.0.2.")), "{ty}: homed in {home}");
        let stored = read_link(port, None, &deposited);
        assert_eq!(slot_addrs(&stored, 0), std::slice::from_ref(&atom), "{ty}: from the atom");
        assert_eq!(slot_addrs(&stored, 1), to, "{ty}: to the row's own target");
        assert_eq!(slot_addrs(&stored, 2), [ty.to_string()], "{ty}: typed its own row");

        let (st, body) = http(port, "GET", &format!("/changes?since={before}"), None, b"");
        assert_eq!(st, 200);
        let page = json(&body);
        let rows = page["changes"].as_array().expect("changes");
        assert_eq!(rows.len(), 2, "{ty}: the atom and its link: {page}");
        let (atom_row, link_row) = (&rows[0], &rows[1]);
        assert_eq!(atom_row["op"].as_str(), Some("insert"), "{ty}");
        assert!(atom_row["key"].as_str().is_some_and(|k| k != "bare"), "{ty}: {atom_row}");
        assert!(atom_row.get("attest").is_none(), "{ty}: the atom is exempt: {atom_row}");
        assert_eq!(link_row["link"].as_str(), Some(deposited.as_str()), "{ty}");
        assert!(link_row.get("key").is_none() && link_row.get("attest").is_none(), "{ty}: {link_row}");

        let kind = RegistrationKind::at(&skep_resolve::parse_address(ty).expect("an address"))
            .expect("a body-bearing registration row");
        let text = atom_text(port, &atom);
        let record = parse_registration(kind, text.as_bytes())
            .unwrap_or_else(|r| panic!("{ty}: the committed atom is refused {r}"));
        assert!(record.sig.is_some(), "{ty}: the record carries the writing hand's sig");
        assert_eq!(record.canonical_sigless(), body_of(ty), "{ty}: the body as composed");
        let _ = signed;
        if ty == T_REQUEST_FRESH {
            request = deposited;
        }
    }
    // A re-vouch names the vouch it follows; the board checks the member's
    // form and never its currency.
    let first = acked_addr(&d.deposit(port, T_VOUCH, "").1);
    let (_, v) = deposit_registry_record(
        port,
        &d.board.node_signed,
        &d.writer,
        T_VOUCH,
        &[CLAIMANT_ACCOUNT],
        &vouch_body(Some(&first)),
    );
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "a re-vouch: {v}");
    sd.shutdown();
}

/// REG-1.32; RES-26 — FROM A BARE SESSION AND ON AN UNCLAIMED BOARD each
/// row's deposit is refused as the built tokens say. On the unclaimed
/// board the bare atom lands, as the ceremony's own does, and its link is
/// `claim_first`: the only registry rows below the claim are the seeded
/// pins. On a claimed board a bare session's link is
/// `signed_session_required` under the registry's family, and its atom —
/// an insert into a published home — the same under the credential's.
#[test]
fn a_bare_session_and_an_unclaimed_board_refuse_each_row_as_built() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    ceremony_before_the_claim(port);
    let claimant = open_session(port, CLAIMANT_PRINCIPAL);
    for ty in DEPOSIT_ROWS {
        let atom = acked_addr(&land(port, &claimant, CLAIMANT_DOC1, ty, &body_of(ty)));
        let v = link(port, &claimant, CLAIMANT_DOC1, &[&atom], &[CLAIMANT_ACCOUNT], ty);
        assert_eq!(family_verdict(&v), "registry_refused:claim_first", "{ty}: {v}");
        assert_eq!(v["disposition"].as_str(), Some("permanent"), "{ty}");
    }
    assert!(!claimed(port));
    sd.shutdown();

    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    assert!(claimed(port));
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let before = head_position(port);
    for ty in DEPOSIT_ROWS {
        let v = land(port, &bare, CLAIMANT_DOC1, ty, &body_of(ty));
        assert_eq!(family_verdict(&v), "credential_refused:signed_session_required", "{ty}: {v}");
        let position = format!("{CLAIMANT_DOC1}.0.1.1");
        let v = link(port, &bare, CLAIMANT_DOC1, &[&position], &[CLAIMANT_ACCOUNT], ty);
        assert_eq!(family_verdict(&v), "registry_refused:signed_session_required", "{ty}: {v}");
        assert_eq!(v["disposition"].as_str(), Some("permanent"), "{ty}");
    }
    assert_eq!(head_position(port), before, "nothing committed");
    sd.shutdown();
}

/// REG-1.18, REG-1.21, REG-1.23 — THE ROWS THAT CARRY NO DEPOSIT TAKE NO
/// ATOM: a declared `insert` under the registration's kind row `3.54`,
/// under a parent row — `request` `3.54.1`, `reply` `3.54.2` — or under the
/// approval `3.54.4`, a link alone, is refused `published_target` at M5's
/// door, as a declaration under any type outside the deposit class is; and
/// so is one under a row beneath a parent that no lane has landed. A
/// parent row is the wire type of no deposit: a `make_link` typed one names
/// no record and takes the plain path, an ordinary attested link.
#[test]
fn a_row_that_carries_no_deposit_takes_no_atom() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_enforcing(dir.path());
    let port = sd.port();
    assert_enforcing(port);
    let d = door(port);
    let before = head_position(port);
    let unlanded = format!("{T_REQUEST}.3");
    for row in [T_REGISTRATION, T_REQUEST, T_REPLY, T_APPROVAL, unlanded.as_str()] {
        for body in [body_of(T_REQUEST_FRESH), body_of(T_REPLY_REFUSED)] {
            let v = land(port, &d.board.console, CLAIMANT_DOC1, row, &body);
            assert_eq!(verdict(&v), "published_target", "{row}: {v}");
        }
    }
    assert_eq!(head_position(port), before, "nothing landed");
    for parent in [T_REGISTRATION, T_REQUEST, T_REPLY] {
        let v = link(port, &d.board.console, CLAIMANT_DOC1, &[CLAIMANT_DOC1], &[CLAIMANT_ACCOUNT], parent);
        assert_eq!(v["resp"].as_str(), Some("ack_addr"), "{parent}: an ordinary link: {v}");
        let attested = sd.daemon().attestation_at(skep_kernel::Seq(acked_at(&v))).expect("a read");
        assert!(attested.is_some(), "{parent}: the plain path's entry signature, no record's");
    }
    sd.shutdown();
}

/// REG-4.78, REG-4.81, REG-4.185; REG-1.23 — THE `to` IS THE ROW's. A
/// request's of either kind and a vouch's MUST be the board's own
/// binding-writing account, which the daemon knows as the board's
/// claimant: another account, no target and two targets are each
/// `registry_form`, permanent, nothing committed, and the claimant's
/// account commits. An answer's MUST be one address: none and two are
/// `registry_form`; and the board checks no more — an answer whose `to`
/// names a link that is no request, a document or an account COMMITS,
/// whether it names a request being its reader's to judge.
#[test]
fn a_rows_to_is_its_own_and_an_answers_is_one_address() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_enforcing(dir.path());
    let port = sd.port();
    assert_enforcing(port);
    let d = door(port);
    let node = d.board.node_account.as_str();
    let writer_signed = d.board.node_signed.as_str();

    for ty in [T_REQUEST_FRESH, T_REQUEST_BOARD_CARRIES_ON, T_VOUCH] {
        let wrong: [&[&str]; 4] = [&[node], &[], &[CLAIMANT_ACCOUNT, node], &[CLAIMANT_DOC1]];
        for to in wrong {
            // Signed for the very link it rides, so the fault is the `to`'s
            // and never the signature's.
            let atom = signed_registry_atom(port, writer_signed, &d.writer, ty, to, &body_of(ty));
            let atom = acked_addr(&land(port, writer_signed, &d.writer, ty, &unquote(&atom)));
            let before = head_position(port);
            let v = link(port, writer_signed, &d.writer, &[&atom], to, ty);
            assert_eq!(family_verdict(&v), FORM, "{ty} to {to:?}: {v}");
            assert_eq!(v["disposition"].as_str(), Some("permanent"), "{ty} to {to:?}");
            assert_eq!(head_position(port), before, "{ty} to {to:?}: nothing committed");
        }
        let (_, v) = d.deposit(port, ty, "");
        assert_eq!(v["resp"].as_str(), Some("ack_addr"), "{ty} to the binding-writing account: {v}");
    }

    let request = acked_addr(&d.deposit(port, T_REQUEST_FRESH, "").1);
    let binding = deposit_binding(port, &d.board.console, "1.2", Some(node), None);
    for ty in [T_REPLY_APPROVED, T_REPLY_REFUSED, T_REPLY_DENIED] {
        let console = d.board.console.as_str();
        let wrong: [&[&str]; 2] = [&[], &[&request, &binding]];
        for to in wrong {
            let atom = signed_registry_atom(port, console, CLAIMANT_DOC1, ty, to, &body_of(ty));
            let atom = acked_addr(&land(port, console, CLAIMANT_DOC1, ty, &unquote(&atom)));
            let before = head_position(port);
            let v = link(port, console, CLAIMANT_DOC1, &[&atom], to, ty);
            assert_eq!(family_verdict(&v), FORM, "{ty} to {to:?}: {v}");
            assert_eq!(head_position(port), before, "{ty} to {to:?}: nothing committed");
        }
        // One address, whatever it names: the request, a binding's link, a
        // document, an account.
        for to in [request.as_str(), binding.as_str(), CLAIMANT_DOC1, node] {
            let (_, v) =
                deposit_registry_record(port, console, CLAIMANT_DOC1, ty, &[to], &body_of(ty));
            assert_eq!(v["resp"].as_str(), Some("ack_addr"), "{ty} to {to}: {v}");
        }
    }
    sd.shutdown();
}

/// REG-4.104, REG-4.204; REG-1.23, REG-1.86 (c) — THE ROW A REQUEST's LINK
/// IS TYPED IS THE ROW ITS SIGNED `shape` NAMES, by the row's ordinal path:
/// a request of either kind whose `shape` names the other request row, the
/// parent row, the kind's row, another registry row or no address at all
/// is refused at its link, `registry_form`, permanent — a payload a
/// transcribing hand typed another row than the applicant signed — and one
/// whose `shape` is its own row's commits. The body's `type` is held to the
/// slot beside it: a fresh body under the board-carries-on row is no record
/// of that row, `malformed_record:wrong_type`.
#[test]
fn a_request_whose_link_is_typed_another_row_than_its_shape_names_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_enforcing(dir.path());
    let port = sd.port();
    assert_enforcing(port);
    let d = door(port);
    let signed = d.board.node_signed.as_str();
    let to = [CLAIMANT_ACCOUNT];
    for (ty, other) in
        [(T_REQUEST_FRESH, T_REQUEST_BOARD_CARRIES_ON), (T_REQUEST_BOARD_CARRIES_ON, T_REQUEST_FRESH)]
    {
        let wrong = [
            shape_of(other),
            shape_of(T_REQUEST),
            shape_of(T_REGISTRATION),
            shape_of(T_BINDING),
            ty.to_string(),
            format!("{}.1", shape_of(ty)),
            String::new(),
        ];
        for shape in wrong {
            let atom = d.signed_atom(port, ty, "", &request_body(ty, &shape));
            let before = head_position(port);
            let v = link(port, signed, &d.writer, &[&atom], &to, ty);
            assert_eq!(family_verdict(&v), FORM, "{ty} with shape {shape:?}: {v}");
            assert_eq!(v["disposition"].as_str(), Some("permanent"), "{ty} with shape {shape:?}");
            assert_eq!(head_position(port), before, "{ty} with shape {shape:?}: nothing committed");
        }
        let atom = d.signed_atom(port, ty, "", &request_body(ty, &shape_of(ty)));
        let v = link(port, signed, &d.writer, &[&atom], &to, ty);
        assert_eq!(v["resp"].as_str(), Some("ack_addr"), "{ty} with its own row's shape: {v}");
        // The other kind's body under this row: the `type` against the slot.
        let v = land(port, signed, &d.writer, ty, &request_body(other, &shape_of(ty)));
        let atom = acked_addr(&v);
        let v = link(port, signed, &d.writer, &[&atom], &to, ty);
        assert_eq!(
            family_verdict(&v),
            "registry_refused:malformed_record:wrong_type",
            "{ty} over the other kind's body: {v}"
        );
    }
    sd.shutdown();
}

/// REG-1.86 (a), (d), (e), (h) — THE BODIES AT THE DAEMON: a record of a
/// registration row carrying no `sig` is refused at its `insert`,
/// `record_sig_required`, as a binding's is; a body that is no record of
/// the slot's row under the canonical rule lands as an ordinary attested
/// deposit and is refused at its link with the parser's cause — a parent
/// row's name for a `type`, the body spaced, a principal past the
/// exactly-representable range, a `fault` outside its three values, a
/// `clause` that is no digit string, a fingerprint in capitals, the
/// board's three members apart; and THE CAP IS PER KIND — a request signed
/// to exactly 64 KiB commits and one byte more is `past_cap`, and an answer
/// one byte past 16 KiB is `past_cap` still.
#[test]
fn the_bodies_are_held_to_the_canonical_rule_and_each_kinds_cap_at_the_daemon() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_enforcing(dir.path());
    let port = sd.port();
    assert_enforcing(port);
    let d = door(port);
    let request = acked_addr(&d.deposit(port, T_REQUEST_FRESH, "").1);

    // No `sig`: refused at the insert, nothing landed.
    let before = head_position(port);
    for ty in DEPOSIT_ROWS {
        let (signed, home, _) = d.seat(ty, &request);
        let v = land(port, signed, home, ty, &body_of(ty));
        assert_eq!(family_verdict(&v), "credential_refused:record_sig_required", "{ty}: {v}");
        assert_eq!(v["disposition"].as_str(), Some("permanent"), "{ty}");
    }
    assert_eq!(head_position(port), before, "nothing landed, no orphan");

    // No record of the slot's row: the parser's cause at the link.
    let fresh = body_of(T_REQUEST_FRESH);
    let approved = body_of(T_REPLY_APPROVED);
    let cases: Vec<(&str, &str, String)> = vec![
        (T_REQUEST_FRESH, "wrong_type", fresh.replacen(r#""type":"fresh""#, r#""type":"request""#, 1)),
        (T_REPLY_APPROVED, "wrong_type", approved.replacen(r#""type":"approved""#, r#""type":"reply""#, 1)),
        (T_REPLY_APPROVED, "not_canonical", approved.replace("\":\"", "\": \"")),
        (T_REPLY_APPROVED, "number", approved.replace("7402918836251", "9007199254740992")),
        (T_REPLY_APPROVED, "number", approved.replace(r#""1209600""#, "1209600")),
        (
            T_REPLY_APPROVED,
            "missing_member:board_principal",
            approved.replace(r#","collection_interval""#, r#","board_address":"1.0.1","collection_interval""#),
        ),
        (T_REPLY_APPROVED, "unknown_member", approved.replace(r#","policy":"#, r#","realm":"9f","policy":"#)),
        (T_REPLY_REFUSED, "unknown_value:fault", body_of(T_REPLY_REFUSED).replace("freshness-spent", "not-welcome")),
        (T_REPLY_DENIED, "not_digits:clause", body_of(T_REPLY_DENIED).replace(r#""clause":"2""#, r#""clause":"two""#)),
        (T_VOUCH, "not_hex:fingerprints", body_of(T_VOUCH).replace("0a0a", "0A0A")),
        (T_REQUEST_FRESH, "not_hex:fresh", fresh.replace("5e5e", "5E5E")),
        (
            T_REQUEST_BOARD_CARRIES_ON,
            "unknown_member",
            body_of(T_REQUEST_BOARD_CARRIES_ON).replace(r#","signer":"#, r#","board":"{}","signer":"#),
        ),
        (T_REQUEST_FRESH, "missing_member:board", fresh.replace(r#","board":"{\"type\":\"skep-enroll\",\"board\":true}""#, "")),
    ];
    for (ty, cause, text) in cases {
        assert_ne!(text, body_of(ty), "{ty} {cause}: the case differs from the well-formed body");
        let (signed, home, to) = d.seat(ty, &request);
        let v = land(port, signed, home, ty, &text);
        let atom = acked_addr(&v);
        let attested = sd.daemon().attestation_at(skep_kernel::Seq(acked_at(&v))).expect("a read");
        assert!(attested.is_some(), "{ty} {cause}: no record of the row, so the atom took the entry signature");
        let before = head_position(port);
        let v = link(port, signed, home, &[&atom], &to, ty);
        assert_eq!(family_verdict(&v), format!("registry_refused:malformed_record:{cause}"), "{ty}: {v}");
        assert_eq!(v["disposition"].as_str(), Some("permanent"), "{ty} {cause}");
        assert_eq!(head_position(port), before, "{ty} {cause}: no link committed");
    }

    // THE CAP PER KIND. A request's `node` is padded so the signed body is
    // exactly the request's cap, then one byte more; an approved answer's
    // `door_origin` the same against every other body's.
    let padded = |ty: &str, pad: usize| -> String {
        let kind = RegistrationKind::at(&skep_resolve::parse_address(ty).expect("an address"))
            .expect("a body-bearing row");
        let record = parse_registration(kind, body_of(ty).as_bytes()).expect("canonical");
        let body = match record.body {
            RegistrationBody::Fresh(mut r) => {
                r.node = "n".repeat(pad);
                RegistrationBody::Fresh(r)
            }
            RegistrationBody::Approved(mut a) => {
                a.door_origin = Some("o".repeat(pad));
                RegistrationBody::Approved(a)
            }
            other => panic!("{:?} is not padded here", other.kind()),
        };
        encode_registration(&body, None)
    };
    for (ty, cap) in [
        (T_REQUEST_FRESH, MAX_REGISTRATION_REQUEST_BYTES),
        (T_REPLY_APPROVED, MAX_REGISTRY_RECORD_BYTES),
    ] {
        let (signed, home, to) = d.seat(ty, &request);
        let signed_len = |pad: usize| -> (String, usize) {
            let atom = signed_registry_atom(port, signed, home, ty, &to, &padded(ty, pad));
            let text = unquote(&atom);
            let len = text.len();
            (text, len)
        };
        let (_, probe) = signed_len(1);
        let fill = cap + 1 - probe;
        let (at_cap, len) = signed_len(fill);
        assert_eq!(len, cap, "{ty}: a signed body of exactly its cap");
        let atom = acked_addr(&land(port, signed, home, ty, &at_cap));
        let v = link(port, signed, home, &[&atom], &to, ty);
        assert_eq!(v["resp"].as_str(), Some("ack_addr"), "{ty} at its cap: {v}");
        let (one_past, len) = signed_len(fill + 1);
        assert_eq!(len, cap + 1, "{ty}: one byte past its cap");
        let atom = acked_addr(&land(port, signed, home, ty, &one_past));
        let before = head_position(port);
        let v = link(port, signed, home, &[&atom], &to, ty);
        assert_eq!(
            family_verdict(&v),
            "registry_refused:malformed_record:past_cap",
            "{ty} one byte past its cap: {v}"
        );
        assert_eq!(head_position(port), before, "{ty}: no link committed");
    }
    sd.shutdown();
}

/// The address of the genesis link the console wrote for `account`: the
/// enroll-typed link in the registrar's doc 1 whose `to` is the account,
/// found off the feed as a guest finds it.
fn genesis_link_of(port: u16, account: &str) -> String {
    let (st, body) = http(port, "GET", "/changes?since=0", None, b"");
    assert_eq!(st, 200);
    json(&body)["changes"]
        .as_array()
        .expect("changes")
        .iter()
        .filter(|row| row["op"].as_str() == Some("make_link"))
        .filter_map(|row| row["link"].as_str().map(str::to_owned))
        .find(|address| {
            let stored = read_link(port, None, address);
            slot_addrs(&stored, 2) == [T_ENROLL.to_string()] && slot_addrs(&stored, 1) == [account.to_string()]
        })
        .expect("the account's genesis link")
}

/// REG-2.26, REG-1.86 (e); P-1 — THE APPROVAL LINK COMMITS LINK-ALONE AT
/// THE ENTRY GRADE: a `make_link` typed the approval row `3.54.4`, from the
/// registrar's signed session in the binding-writing account's own doc 1 —
/// beside the binding it writes in the same act — FROM the genesis the
/// approval wrote TO the request answered, each named by its link's
/// address, commits on the plain path: no atom, no record, the entry
/// signature in its marker slot, so its row on `/changes` carries `attest`
/// and no `key`. It names no record kind, so the registry sequence takes
/// none of it: a bare session's is the plain path's own refusal.
#[test]
fn an_approval_link_commits_link_alone_at_the_entry_grade() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_enforcing(dir.path());
    let port = sd.port();
    assert_enforcing(port);
    let d = door(port);
    let request = acked_addr(&d.deposit(port, T_REQUEST_FRESH, "").1);
    let genesis = genesis_link_of(port, &d.board.node_account);
    let binding = deposit_binding(port, &d.board.console, "1.2", Some(&d.board.node_account), None);
    let before = head_position(port);
    let v = link(port, &d.board.console, CLAIMANT_DOC1, &[&genesis], &[&request], T_APPROVAL);
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "the approval link: {v}");
    let approval = acked_addr(&v);
    assert!(approval.starts_with(&format!("{CLAIMANT_DOC1}.0.2.")), "homed beside the binding {binding}");
    let stored = read_link(port, None, &approval);
    assert_eq!(slot_addrs(&stored, 0), [genesis], "from the genesis the approval wrote");
    assert_eq!(slot_addrs(&stored, 1), [request], "to the request answered");
    assert_eq!(slot_addrs(&stored, 2), [T_APPROVAL.to_string()]);
    let (st, body) = http(port, "GET", &format!("/changes?since={before}"), None, b"");
    assert_eq!(st, 200);
    let page = json(&body);
    let rows = page["changes"].as_array().expect("changes");
    assert_eq!(rows.len(), 1, "a link alone, no atom: {page}");
    assert_eq!(rows[0]["op"].as_str(), Some("make_link"));
    assert!(rows[0].get("attest").is_some() && rows[0].get("key").is_none(), "the entry grade: {}", rows[0]);
    let attested = sd.daemon().attestation_at(skep_kernel::Seq(acked_at(&v))).expect("a read");
    assert!(attested.is_some(), "the entry signature in the marker slot");
    sd.shutdown();
}
