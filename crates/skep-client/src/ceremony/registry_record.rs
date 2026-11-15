//! The one registry-record composition (REG-1.86; REG-2.23; P28).
//!
//! A registry record is two positions in the writing account's own doc 1: a
//! record atom, then a typed link from it (REG-1.9; REG-2.26). The daemon
//! parses two kinds at the record grade, the binding's and the endpoint's
//! (REG-1.86 (a), (e)), and this composition holds, for both, the order the
//! credential deposit holds for its own records: the sig-less canonical
//! body, by `skep_registry::encode` and by no encoder of this crate's (a
//! body is admitted only as its own canonical re-encoding, REG-1.86 (h));
//! the `record` frame over it — `board` the head document `H.1`'s pair,
//! `account` the home's account, `doc` the home, the kind's type address,
//! the link's target, the `replaces` and lineage rows empty — signed by the
//! hand the caller passes, the `sig` appended canonically last; the cap, 16
//! KiB with the `sig` counted, judged on the signed bytes before any write;
//! then the insert declared under the kind's type and its re-read `from`
//! (`deposit::verified_atom`: the link names the verified I-address the
//! insert acked, for the whole deposit class, REG-2.23), and the link
//! carrying the same type, with no `replaces` member of its own — the
//! member rides the signed body (REG-1.86 (g)).
//!
//! The hand is a key of the set that opens the home's account: the board
//! judges the record's `sig` under that set at the link, and this
//! composition re-checks nothing the board judges. For an endpoint the home
//! is the node account's doc 1 and the hand a key of that account's own
//! set — the board's owner, never the service that hosts the board
//! (REG-4.120).
//!
//! **The endpoint is the kind composed in public.** [`deposit_endpoint`]
//! reads the deposit a later one must name, then deposits;
//! [`deposit_endpoint_naming`] deposits a record naming what its caller
//! says. A binding's writer reads the binding walk first, and no code of
//! this crate deposits one: the half both kinds share (`deposit_record`)
//! is private.
//!
//! **What a later deposit names** (REG-1.10). A deposit is honored only
//! where its `replaces` names the deposit current in that doc 1 at its own
//! position, or names none where none has stood; current, for that test, is
//! read on the audit view — the latest deposit that stood, nullified or
//! not. [`endpoint_history`] is that read: every link ever made over the
//! home's content ([`frames::find_links_v_history`], the wire's audit-view
//! read), kept where it is homed there and typed the endpoint's, in the
//! home's link order, which is journal order within one home; each record
//! read off its atom and parsed under the canonical rule; then
//! [`fold_endpoints`], the rule's own walk, pure. No verdict is judged
//! here: the daemon admitted each record's `sig` under the home's set at
//! its own link, and a reader that verifies judges them again for itself.
//! Nothing is erased by a later deposit: the one it replaces stays in the
//! home, read as replaced.

use serde_json::Value;
use skep_address::Address;
use skep_identity::BoardTerm;
use skep_registry::{encode, parse, t_binding, t_endpoint, Body, BodyKind, Endpoint, Origins, MAX_REGISTRY_RECORD_BYTES};

use crate::address::{document_of, parse_address};
use crate::board::{acked_addr, acked_at, answers, frames, Answer, Board, Rejection, Token};
use crate::ceremony::deposit::{closed_face, shape_face, verified_atom};
use crate::halt::Halt;
use crate::sign::{sig_hex, RecordFrame, Signer};

/// The rows one window of the audit-view read asks for.
const HISTORY_WINDOW: u64 = 256;

/// One endpoint deposit to make (REG-1.9).
pub struct EndpointDeposit<'a> {
    /// The home: the node account's own doc 1.
    pub home: &'a str,
    /// The board's origins in the owner's order, at least one.
    ///
    /// The order is the one a reader tries them in (REG-3.34). Each is
    /// written as given: whether a reader admits it is the reader's check.
    pub origins: &'a [String],
    /// The writing hand: a key of the set that opens the home's account.
    pub hand: &'a dyn Signer,
    /// AUTH-5.6's per-session id, one per deposit.
    ///
    /// The insert and the link take `<id>.insert` and `<id>.link`.
    pub id: &'a str,
}

/// A registry record deposited: both writes acked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deposited {
    /// The record atom's address.
    pub atom: String,
    /// The link's address — the handle a later record names (REG-2.24).
    pub link: String,
    /// The link's position: the deposit's place in journal order (REG-1.10).
    pub at: u64,
    /// The deposit the record names in `replaces`, where it names one.
    pub replaces: Option<String>,
}

/// One endpoint deposit as a doc 1 holds it, folded (REG-1.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRecord {
    /// The link's address.
    pub link: String,
    /// The origins the record names, in its order.
    pub origins: Vec<String>,
    /// The deposit the record names in `replaces`, where it names one.
    pub replaces: Option<String>,
    /// Whether the deposit stood: honored by [`fold_endpoints`]'s rule.
    pub honored: bool,
    /// Whether a `nullify` took the deposit off the active view (REG-1.11).
    ///
    /// A nullified deposit that stood is still the one a later deposit
    /// names.
    pub nullified: bool,
}

/// Folds `records`, in journal order, by the endpoint's currency rule.
///
/// It is REG-1.10's walk, as a mirror's index makes it: a deposit is
/// honored where its `replaces` names the latest deposit that stood before
/// it, or names none where none has stood, and is inert otherwise — an old
/// record deposited again, one naming a deposit no longer the latest, a
/// second first deposit. Each record's `honored` is set by the walk; its
/// `nullified` is read and never judged, since a nullified deposit that
/// stood is still what the next one names.
///
/// **Precondition.** `records` are one home's deposits in journal order.
pub fn fold_endpoints(mut records: Vec<EndpointRecord>) -> Vec<EndpointRecord> {
    let mut stood: Option<String> = None;
    for record in &mut records {
        record.honored = record.replaces == stood;
        if record.honored {
            stood = Some(record.link.clone());
        }
    }
    records
}

/// Returns the latest deposit of `history` that stood, where one has.
///
/// It is the deposit the next one names in `replaces` (REG-1.10): the last
/// honored one, nullified or not.
pub fn latest_stood(history: &[EndpointRecord]) -> Option<&EndpointRecord> {
    history.iter().rev().find(|record| record.honored)
}

/// Reads the endpoint deposits homed in `home`, in journal order, folded.
///
/// The read is the audit view's (the module's doc), under `token` or as a
/// guest: a published doc 1 answers both. A home that is not registered,
/// or holds no content, has no deposit. A link whose atom does not read
/// back, or whose bytes are no endpoint record under the canonical rule,
/// is no deposit and is passed over, as a mirror passes over it.
///
/// # Errors
///
/// The death signal under `token`, faced; the board's refusal of a read
/// other than `doc_not_registered` at the home; an answer of a shape this
/// client does not know, a window that does not move past its cursor among
/// them, faced as the board's fault; and [`Board::op`]'s errors.
pub fn endpoint_history(board: &Board, token: Option<&Token>, home: &str) -> Result<Vec<EndpointRecord>, Halt> {
    let during = "reading the home's endpoint deposits";
    let extent = match read(board, token, &frames::span_set(home), during)? {
        Ok(v) => answers::content_extent(&v),
        Err((r, _)) if r.key() == "doc_not_registered" => return Ok(Vec::new()),
        Err((r, v)) => return Err(r.refused(&v)),
    };
    if extent == 0 {
        return Ok(Vec::new());
    }
    // Every link ever made over the home's content, active or retracted.
    let mut rows = Vec::new();
    let mut cur: Option<String> = None;
    loop {
        let v = answered(board, token, &frames::find_links_v_history(home, &[(1, extent)], cur.as_deref(), HISTORY_WINDOW), during)?;
        let Some(window) = answers::history(&v) else { return Err(shape_face(&v)) };
        rows.extend(window.links.into_iter().filter(|row| document_of(&row.a).as_deref() == Some(home)));
        if window.exhausted {
            break;
        }
        if window.next.is_none() || window.next == cur {
            return Err(Halt::face(
                format!("{home} answered a window of its links that does not move past its cursor"),
                "`find_links_v_history` answered `exhausted: false` and no later `next` (wire.md §Link discovery reads)",
                "this is a fault in the board, not in your keys; nothing was written",
            ));
        }
        cur = window.next;
    }
    // The home's link order: journal order within one home.
    rows.sort_by_key(|row| link_order(&row.a));
    rows.dedup_by(|a, b| a.a == b.a);
    let ty = t_endpoint().to_string();
    let mut records = Vec::new();
    let mut image: Option<Value> = None;
    for row in rows {
        let v = answered(board, token, &frames::read_link(&row.a), during)?;
        let Some(Some(link)) = answers::link_value(&v) else { continue };
        if !link.typed_exactly(&ty) {
            continue;
        }
        let [from] = link.from.as_slice() else { continue };
        if !from.is_unit() || document_of(&from.start).as_deref() != Some(home) {
            continue;
        }
        if image.is_none() {
            image = Some(answered(board, token, &frames::image(home, 1, extent), during)?);
        }
        let runs = image.as_ref().and_then(|image| answers::i_runs(image, extent));
        let Some(ordinal) = runs.and_then(|runs| answers::ordinal_of(&runs, &from.start)) else { continue };
        let v = answered(board, token, &frames::retrieve_v(home, ordinal, 1), during)?;
        let Some(bytes) = answers::first_atom(&v) else { continue };
        let Ok(record) = parse(BodyKind::Endpoint, &bytes) else { continue };
        let Body::Endpoint(endpoint) = record.body else { continue };
        records.push(EndpointRecord {
            link: row.a,
            origins: endpoint.origins.into_vec(),
            replaces: endpoint.replaces.map(|a| a.to_string()),
            honored: false,
            nullified: row.retracted_at.is_some(),
        });
    }
    Ok(fold_endpoints(records))
}

/// Deposits an endpoint naming the deposit current in its home (REG-1.10).
///
/// It reads [`endpoint_history`] under `token` and names the latest deposit
/// that stood in `replaces` — none on the home's first — then deposits
/// ([`deposit_endpoint_naming`]). The deposit it replaces stays in the
/// home; nothing is erased.
///
/// # Errors
///
/// [`endpoint_history`]'s errors, then [`deposit_endpoint_naming`]'s.
pub fn deposit_endpoint(board: &Board, token: &Token, d: &EndpointDeposit<'_>) -> Result<Deposited, Halt> {
    let history = endpoint_history(board, Some(token), d.home)?;
    let replaces = latest_stood(&history).map(|record| record.link.as_str());
    deposit_endpoint_naming(board, token, d, replaces)
}

/// Deposits an endpoint whose `replaces` names what the caller says.
///
/// `replaces` is the link's address of the deposit this one replaces, in
/// the local form of the board the home is on, or `None`, the empty state
/// (REG-1.86 (g)). The board checks the member's form and never its
/// currency: a record naming anything but the deposit current at its own
/// position commits, and is inert at every reader (REG-1.10).
/// [`deposit_endpoint`] is the form that reads what to name.
///
/// # Errors
///
/// A deposit naming no origin, or a `replaces` that is no address, is this
/// client's caller's fault, faced before any read; then `deposit_record`'s
/// errors.
pub fn deposit_endpoint_naming(board: &Board, token: &Token, d: &EndpointDeposit<'_>, replaces: Option<&str>) -> Result<Deposited, Halt> {
    let Some(origins) = Origins::new(d.origins.to_vec()) else {
        return Err(Halt::face(
            "the endpoint names no origin",
            "an endpoint's origins are an ordered list of at least one (REG-1.86: `[]` is a body no reader holds)",
            "name the board's origin; nothing was written",
        ));
    };
    let replaces = match replaces {
        None => None,
        Some(text) => Some(parse_address(text).ok_or_else(|| {
            Halt::face(format!("`{text}` is no address"), "an endpoint's `replaces` is the link's address of the deposit it replaces (REG-1.86 (g))", "this is this client's frame; nothing was written")
        })?),
    };
    deposit_record(board, token, d.home, None, &Body::Endpoint(Endpoint { origins, replaces }), d.hand, d.id)
}

/// Returns the type address a body's kind is deposited under.
///
/// It is the kind's own row (REG-1.21): the insert's declaration, the
/// link's type slot and the frame's type row alike.
fn type_of(body: &Body) -> &'static Address {
    match body.kind() {
        BodyKind::Binding => t_binding(),
        BodyKind::Endpoint => t_endpoint(),
    }
}

/// Returns the signed canonical record of `body`, homed in `home`.
///
/// It is the sig-less canonical projection, the `record` frame over it —
/// `term` the board's `H.1` pair, `home_account` the home's account, the
/// kind's type address, `to` the link's target, the `replaces` and lineage
/// rows empty — and `hand`'s `sig` appended canonically last (REG-1.86
/// (e), (h)). Pure: the caller makes the two reads it takes.
///
/// # Errors
///
/// A frame that does not compose, an address of it being none; then a
/// signed body past the cap (REG-1.86 (h)), judged on the signed bytes.
fn compose(term: BoardTerm, home_account: &str, home: &str, to: &[&str], body: &Body, hand: &dyn Signer) -> Result<String, Halt> {
    let ty = type_of(body).to_string();
    let sigless = encode(body, None);
    let frame = RecordFrame { alg: hand.public_key().alg(), board: term, home_account, home, ty: &ty, to, sigless: sigless.as_bytes() }
        .compose()
        .ok_or_else(|| Halt::face("the record frame could not be composed", "an address of the deposit did not parse", "this is this client's frame; nothing was written"))?;
    let signed = encode(body, Some(&sig_hex(&hand.sign(&frame))));
    if signed.len() > MAX_REGISTRY_RECORD_BYTES {
        return Err(Halt::face(
            format!("the record is {} bytes signed, past the cap of {MAX_REGISTRY_RECORD_BYTES}", signed.len()),
            "a registry record's body is at most 16 KiB, its `sig` counted (REG-1.86 (h)): past it the board refuses the record and no reader holds it",
            "name fewer or shorter origins; nothing was written",
        ));
    }
    Ok(signed)
}

/// Deposits one registry record: the composition's kind-general half.
///
/// `to` is the link's target — the account a binding binds, none for a
/// targetless binding and for an endpoint (REG-2.26's carriage). The record
/// is composed and signed ([`compose`]) over the board's `H.1` pair and the
/// home's account, both read here, inserted declared under its kind's type
/// and read back ([`verified_atom`]), then linked from the verified atom
/// under the same type.
///
/// # Errors
///
/// In order, the first three before any write: a board with no `H.1`; a
/// home with no owner; [`compose`]'s halts; then the verified atom's — a
/// home that is not registered faced as the mint owed ahead of the deposit
/// (REG-1.51); the link closed, an answer of a shape this client does not
/// know, and the registry sequence's refusals, faced ([`link_face`]).
fn deposit_record(board: &Board, token: &Token, home: &str, to: Option<&str>, body: &Body, hand: &dyn Signer, id: &str) -> Result<Deposited, Halt> {
    let to: Vec<&str> = to.into_iter().collect();
    let Some(term) = board.board_term()? else {
        return Err(Halt::face(
            "this board has no H.1 yet",
            "a registry record carries its hand's `sig` over the record frame, whose `board` term is `H.1`'s pair, and the board answers no head: it is unclaimed, or it owes its head",
            "retry once the board has written its head; nothing was written",
        ));
    };
    let home_account = board
        .effective_owner(home)?
        .map(|owner| owner.prefix)
        .ok_or_else(|| Halt::face("the home has no owner", format!("`effective_owner({home})` answered null"), "this is this client's frame and never your act; nothing was written"))?;
    let record = compose(term, &home_account, home, &to, body, hand)?;
    let ty = type_of(body).to_string();
    let atom = verified_atom(board, token, home, &record, &ty, &format!("{id}.insert")).map_err(|halt| match Halt::from(halt) {
        Halt::Refused(r) if r.code == "doc_not_registered" => Halt::face(
            format!("the home {home} is not minted, and nothing was written"),
            "doc_not_registered: a deposit into a doc 1 that does not exist is refused — no document holds it (REG-1.51)",
            "the account's own signed session mints its doc 1 ahead of its first deposit: `skep deposit` mints it, and so does `skep bind`",
        ),
        halt => halt,
    })?;
    let v = match board.op(Some(token), &frames::make_link(home, &[&atom], &to, &ty, Some(&format!("{id}.link"))))? {
        Answer::Closed => return Err(closed_face("linking the record")),
        Answer::Document(v) => v,
    };
    if let (Some(link), Some(at)) = (acked_addr(&v), acked_at(&v)) {
        return Ok(Deposited { atom, link: link.to_string(), at, replaces: body.replaces().map(|a| a.to_string()) });
    }
    let Some(r) = Rejection::of(&v) else { return Err(shape_face(&v)) };
    Err(link_face(&r, &v, home))
}

/// Faces the registry sequence's refusals at the link (wire.md §Registry).
///
/// The record's atom stands in the home, inert, where the link is refused.
/// The form, the home pin and the record's own value are this client's
/// frame; the `sig`'s trial is the hand's standing at the home's account;
/// everything else is the board's refusal as it answered.
fn link_face(r: &Rejection, v: &Value, home: &str) -> Halt {
    let token = r.token();
    match r.key() {
        "claim_first" => Halt::face(
            "this board is unclaimed, and it takes no registry record",
            format!("{token}: a registry record is deposited above the claim alone (REG-1.32)"),
            "the board's claim comes first; the record's atom stands in the home, linked by nothing",
        ),
        "signed_session_required" => Halt::face(
            "a registry record takes a signed session",
            format!("{token}: this session is bare"),
            "sign in with a key the account has enrolled; the commands that deposit open their own signed session",
        ),
        k if k.starts_with("attestation_invalid") => Halt::face(
            format!("the board judged the record's `sig` and refused it at {home}"),
            format!(
                "{token}: the `sig` is tried under the set that opens the home's account as of this write (REG-1.86 (e)) — the key that \
                 signed is not enrolled there, or the board had no head"
            ),
            "sign with a key enrolled at the account the home belongs to — the board's owner signs its own endpoint, never its host \
             (REG-4.120); `board_unavailable` is a reorder: retry once the head is written. The record's atom stands in the home, \
             linked by nothing",
        ),
        "attestation_required" | "not_doc_one" | "registry_form" => Halt::face(
            "the board refused this client's frame",
            format!("{token}: the home, the `sig` or the link's slots this client composed are wrong (never your act)"),
            "this is a fault in this client, not in your keys; the record's atom stands in the home, linked by nothing",
        ),
        k if k.starts_with("malformed_record") => Halt::face(
            "the record did not parse at the board",
            format!("{token}: the bytes this client composed are no record of the link's kind under the canonical rule (REG-1.86 (h))"),
            "this is a fault in this client, not in your keys; the record's atom stands in the home, linked by nothing",
        ),
        _ => r.refused(v),
    }
}

/// Returns the sort key that puts one home's links in the order minted.
///
/// It is tumbler order over the dotted spelling: a home's link subspace
/// mints its ordinals in order, so within one home it is journal order.
fn link_order(link: &str) -> Vec<u64> {
    link.split('.').map(|component| component.parse().unwrap_or(u64::MAX)).collect()
}

/// Returns the document one read is answered with, or its rejection.
///
/// # Errors
///
/// [`Board::op`]'s errors; the death signal, faced.
fn read(board: &Board, token: Option<&Token>, frame: &Value, during: &str) -> Result<Result<Value, (Rejection, Value)>, Halt> {
    match board.op(token, frame)? {
        Answer::Closed => Err(closed_face(during)),
        Answer::Document(v) => Ok(match Rejection::of(&v) {
            Some(r) => Err((r, v)),
            None => Ok(v),
        }),
    }
}

/// Returns the document one read is answered with.
///
/// # Errors
///
/// [`read`]'s errors, and the board's refusal as it answered.
fn answered(board: &Board, token: Option<&Token>, frame: &Value, during: &str) -> Result<Value, Halt> {
    read(board, token, frame, during)?.map_err(|(r, v)| r.refused(&v))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use skep_identity::RecordRows;

    use super::*;
    use crate::board::fake::{self, Fake};
    use crate::sign::signer_from_seed;

    const ACCOUNT: &str = "1.0.2";
    const HOME: &str = "1.0.2.0.1";

    fn term() -> BoardTerm {
        BoardTerm { log_position: 394, chain: [7; 32] }
    }

    fn record(link: &str, replaces: Option<&str>, nullified: bool) -> EndpointRecord {
        EndpointRecord { link: link.into(), origins: vec!["https://acme.example".into()], replaces: replaces.map(str::to_string), honored: false, nullified }
    }

    /// REG-1.86 (e), (h): the composition is the vector set's canonical form.
    ///
    /// Every body the set admits, of both kinds, composes to bytes the
    /// owner's parser admits as that body, whose sig-less projection is the
    /// set's own canonical bytes; the `sig` verifies under the hand's key
    /// over the `record` frame the board tries it under — the home's
    /// account, the home, the kind's type, the target, the `replaces` and
    /// lineage rows empty — and under no other key. The cap is judged on the
    /// signed bytes: a record at it composes, and one byte past it halts.
    #[test]
    fn the_composed_record_is_the_vector_sets_canonical_form_and_its_sig_verifies_under_the_hand() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../skep-registry/tests/vectors/records.json");
        let set: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))).expect("the vector set is JSON");
        assert_eq!(set["cap"].as_u64(), Some(MAX_REGISTRY_RECORD_BYTES as u64), "the set pins the cap this composition judges");
        let (hand, other) = (signer_from_seed(&[31; 32]), signer_from_seed(&[32; 32]));
        let address = |text: &str| parse_address(text).expect("an address");
        let mut composed = Vec::new();
        for vector in set["vectors"].as_array().expect("vectors").iter().filter(|v| v["parse"] == "ok") {
            let name = vector["name"].as_str().expect("a name");
            let kind = if vector["kind"] == "binding" { BodyKind::Binding } else { BodyKind::Endpoint };
            let body = parse(kind, vector["bytes"].as_str().expect("an admitted vector's bytes are text").as_bytes()).unwrap_or_else(|e| panic!("{name}: {e}")).body;
            let to: &[&str] = if kind == BodyKind::Binding { &[ACCOUNT] } else { &[] };
            let Ok(signed) = compose(term(), ACCOUNT, HOME, to, &body, &hand) else {
                assert!(encode(&body, None).len() > MAX_REGISTRY_RECORD_BYTES / 2, "{name}: only a body near the cap is past it signed");
                continue;
            };
            let read = parse(kind, signed.as_bytes()).unwrap_or_else(|e| panic!("{name}: the composed bytes are no record: {e}"));
            assert_eq!(read.body, body, "{name}");
            assert_eq!(Some(read.canonical_sigless().as_str()), vector["canonical_sigless"].as_str(), "{name}: the set's canonical bytes");
            let (ty, to) = (type_of(&body), to.iter().map(|a| address(a)).collect::<Vec<_>>());
            let rows = RecordRows { ty, to: &to, replaces: None, lineage_fork_point: None, sigless_canonical_record: vector["canonical_sigless"].as_str().expect("canonical").as_bytes() };
            let frame = skep_identity::RecordFrame { board: term(), home_account: &address(ACCOUNT), home: &address(HOME), rows }.to_bytes(hand.public_key().alg());
            let blob = crate::hex::decode(read.sig.as_deref().unwrap_or_else(|| panic!("{name}: composed without its `sig`"))).expect("the sig is hex");
            assert_eq!(skep_signature::verify(Signer::tag(&hand), Signer::public_key(&hand), &frame, &blob), Ok(()), "{name}: under the hand's key");
            assert!(skep_signature::verify(Signer::tag(&other), Signer::public_key(&other), &frame, &blob).is_err(), "{name}: under no other key");
            composed.push(kind);
        }
        assert!(composed.len() >= 12 && composed.contains(&BodyKind::Binding) && composed.contains(&BodyKind::Endpoint), "the set's admitted bodies of both kinds were composed: {}", composed.len());
        let endpoint = |len: usize| Body::Endpoint(Endpoint { origins: Origins::new(vec!["a".repeat(len)]).expect("one origin"), replaces: None });
        let room = MAX_REGISTRY_RECORD_BYTES + 1 - compose(term(), ACCOUNT, HOME, &[], &endpoint(1), &hand).expect("a short record").len();
        assert_eq!(compose(term(), ACCOUNT, HOME, &[], &endpoint(room), &hand).expect("a record at the cap").len(), MAX_REGISTRY_RECORD_BYTES);
        let past = compose(term(), ACCOUNT, HOME, &[], &endpoint(room + 1), &hand).expect_err("one byte past the cap");
        assert!(past.exit_code() == 3 && past.to_string().contains(&format!("{} bytes signed, past the cap of {MAX_REGISTRY_RECORD_BYTES}", MAX_REGISTRY_RECORD_BYTES + 1)), "{past}");
    }

    /// REG-1.10: a deposit stands only where it names the latest that stood.
    ///
    /// The first names none; a later one names the latest that stood, and
    /// one naming none where one stands, or a deposit no longer the latest,
    /// is inert and is never what the next one names; a nullified deposit
    /// that stood is still the one named.
    #[test]
    fn the_fold_honors_a_deposit_naming_the_latest_that_stood_and_no_other() {
        let history = fold_endpoints(vec![
            record("l1", None, false),
            record("l2", Some("l1"), false),
            record("l3", None, false),
            record("l4", Some("l1"), false),
            record("l5", Some("l2"), true),
            record("l6", Some("l5"), false),
        ]);
        assert_eq!(history.iter().map(|r| r.honored).collect::<Vec<_>>(), [true, true, false, false, true, true]);
        assert_eq!(latest_stood(&history[..4]).map(|r| r.link.as_str()), Some("l2"), "past two inert deposits");
        assert_eq!(latest_stood(&history[..5]).map(|r| r.link.as_str()), Some("l5"), "nullified, and still the one the next names");
        let first = fold_endpoints(vec![record("l1", Some("l0"), false)]);
        assert!(!first[0].honored && latest_stood(&first).is_none(), "a first deposit naming a state where none has stood is inert");
        assert!(latest_stood(&[]).is_none());
    }

    /// The read is the audit view's, of the home's own endpoint links alone.
    ///
    /// Every link ever made over the home's content is paged; one homed
    /// elsewhere is never read, one of another type and one whose atom is no
    /// endpoint record are passed over; a retracted deposit is read as
    /// nullified and still folded. A home with no content, or not
    /// registered, has no deposit.
    #[test]
    fn the_history_is_the_homes_endpoint_links_on_the_audit_view() {
        let link = |n: u64| format!("{HOME}.0.2.{n}");
        let ty = t_endpoint().to_string();
        let board = move |extent: u64| {
            let (link, ty) = (link, ty.clone());
            Fake::new(move |req| {
                let f = fake::frame(req);
                let stored = |from: u64, ty: &str| json!({"as_of": 9, "at": 5, "resp": "link_value", "link": {"slots": [frames::unit_span(&format!("{HOME}.0.1.{from}")), [], frames::unit_span(ty)]}});
                let row = |a: String, retracted: Option<u64>| json!({"a": a, "at": 5, "retracted_at": retracted});
                let atom = |text: &str| fake::json(200, json!({"as_of": 9, "items": [{"atom": text}], "resp": "delivery"}));
                match (f["op"].as_str().unwrap_or("?"), f["a"].as_str().unwrap_or(""), f["specs"][0]["span"]["start"].as_str().unwrap_or("")) {
                    ("retrieve_doc_v_span_set", ..) if extent == 0 => fake::json(200, json!({"as_of": 9, "resp": "span_set", "set": []})),
                    ("retrieve_doc_v_span_set", ..) => fake::json(200, json!({"as_of": 9, "resp": "span_set", "set": [{"start": "1.1", "width": format!("0.{extent}")}]})),
                    ("find_links_v_history", ..) if f["cur"].is_null() => fake::json(200, json!({"as_of": 9, "resp": "links", "links": [row(link(1), Some(8)), row(link(2), None)], "next": link(2), "exhausted": false})),
                    ("find_links_v_history", ..) => {
                        assert_eq!(f["cur"], json!(link(2)), "the page past the first's `next`");
                        fake::json(200, json!({"as_of": 9, "resp": "links", "links": [row(link(3), None), row(link(4), None), row("1.0.9.0.1.0.2.1".into(), None)], "next": null, "exhausted": true}))
                    }
                    ("read_link", a, _) if a == link(1) => fake::json(200, stored(1, &ty)),
                    ("read_link", a, _) if a == link(2) => fake::json(200, stored(2, frames::T_GRANT)),
                    ("read_link", a, _) if a == link(3) => fake::json(200, stored(3, &ty)),
                    ("read_link", a, _) if a == link(4) => fake::json(200, stored(4, &ty)),
                    ("image", ..) => fake::json(200, json!({"as_of": 9, "resp": "runs", "runs": [{"i_start": format!("{HOME}.0.1.1"), "width": extent.to_string()}]})),
                    ("retrieve_v", _, "1.1") => atom(r#"{"type":"endpoint","origins":["https://a.example"]}"#),
                    ("retrieve_v", _, "1.3") => atom(&format!(r#"{{"type":"endpoint","origins":["https://b.example","https://c.example"],"replaces":"{}"}}"#, link(1))),
                    ("retrieve_v", _, "1.4") => atom(r#"{"type": "endpoint", "origins": ["https://spaced.example"]}"#),
                    other => panic!("the history's read sends no {other:?}"),
                }
            })
        };
        let history = endpoint_history(&fake::board(&board(4)), None, HOME).expect("the history");
        let (first, later) = (EndpointRecord { link: format!("{HOME}.0.2.1"), origins: vec!["https://a.example".into()], replaces: None, honored: true, nullified: true }, format!("{HOME}.0.2.3"));
        assert_eq!(history, [first.clone(), EndpointRecord { link: later.clone(), origins: vec!["https://b.example".into(), "https://c.example".into()], replaces: Some(first.link.clone()), honored: true, nullified: false }]);
        assert_eq!(latest_stood(&history).map(|r| r.link.clone()), Some(later));
        let empty = board(0);
        assert_eq!(endpoint_history(&fake::board(&empty), None, HOME), Ok(Vec::new()));
        assert_eq!(empty.log(), ["POST /op retrieve_doc_v_span_set"], "a home with no content is asked nothing more");
        let unminted = Fake::new(|_| fake::json(200, json!({"code": "doc_not_registered", "disposition": "permanent", "op": "retrieve_doc_v_span_set", "resp": "rejected"})));
        assert_eq!(endpoint_history(&fake::board(&unminted), None, HOME), Ok(Vec::new()), "a home not yet minted holds no deposit");
    }
}
