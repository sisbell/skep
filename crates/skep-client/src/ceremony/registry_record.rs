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
//! **The endpoint.** [`deposit_endpoint`] reads the deposit a later one
//! must name, then deposits; [`deposit_endpoint_naming`] deposits a record
//! naming what its caller says.
//!
//! **The binding** (REG-2.18, REG-2.19). [`deposit_binding`] writes one
//! prefix bound to one account — or to none, a retirement's one spelling —
//! in the binding-writing account's own doc 1, signed by a key of that
//! account's set. A binding's writer reads the binding walk first:
//! [`binding_history`] is every binding ever homed there, in journal order
//! and folded by the walk's own rule ([`fold_bindings`]; REG-2.8 to
//! REG-2.10), [`holder_of`] the binding current at a prefix, and
//! [`next_prefix`] next-form — the prefix past every prefix a binding has
//! ever named (REG-2.3).
//!
//! **The registration's answers and its approval link** (REG-1.86;
//! REG-4.79). [`deposit_answer`] writes an approved, a refused or a denied
//! answer: the row's canonical body by `skep_registry::encode_registration`,
//! signed and deposited as a binding is, its link typed the answer's own
//! row and its `to` the request's link, one address. [`link_approval`]
//! writes the approval, a link alone: no atom and no record, from the
//! genesis the approval wrote to the request it answers, under the entry
//! signature a plain link carries (REG-1.86 (e)). [`registration_at`] reads
//! one registration record back off its link, and [`links_homed`] lists a
//! home's links under one row. The half every atom-plus-link kind shares
//! (`deposit_record`) is private.
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
use skep_identity::{entry_body_make_link, unit_span, BoardTerm, DocTerm, EntrySlot, LinkSlots};
use skep_registry::{
    encode, encode_registration, parse, parse_registration, t_approval, t_binding, t_endpoint, Binding, Body, BodyKind, Endpoint, Origins, ParseRefusal, RegistrationBody, RegistrationKind,
    RegistrationRecord, MAX_REGISTRY_RECORD_BYTES,
};

use super::attest_member;
use crate::address::{document_of, parse_address};
use crate::board::{acked_addr, acked_at, answers, frames, Answer, Board, LinkValue, Rejection, Token};
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
            image = Some(imaged(board, token, &frames::image(home, 1, extent), during)?);
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
    deposit_record(board, token, d.home, None, Composed::Record(&Body::Endpoint(Endpoint { origins, replaces })), d.hand, d.id)
}

/// A body this composition deposits, of either family.
///
/// It is a binding's or an endpoint's, or one of the registration kind's:
/// each family has its own types and its own encoder in `skep_registry`,
/// and the deposit is one for both.
#[derive(Clone, Copy)]
enum Composed<'a> {
    /// A binding's body or an endpoint's.
    Record(&'a Body),
    /// A registration row's body.
    Registration(&'a RegistrationBody),
}

impl Composed<'_> {
    /// Returns the type address the body's kind is deposited under.
    ///
    /// It is the kind's own row (REG-1.21): the insert's declaration, the
    /// link's type slot and the frame's type row alike.
    fn ty(&self) -> &'static Address {
        match self {
            Composed::Record(body) => type_of(body),
            Composed::Registration(body) => &body.kind().row().address,
        }
    }

    /// Returns the body in its canonical form, with its `sig` where given.
    fn encode(&self, sig: Option<&str>) -> String {
        match self {
            Composed::Record(body) => encode(body, sig),
            Composed::Registration(body) => encode_registration(body, sig),
        }
    }

    /// Returns the kind's cap, in bytes, the `sig` counted (REG-1.86 (h)).
    fn cap(&self) -> usize {
        match self {
            Composed::Record(_) => MAX_REGISTRY_RECORD_BYTES,
            Composed::Registration(body) => body.kind().cap(),
        }
    }

    /// Returns the deposit the body names in `replaces`, where it names one.
    fn replaces(&self) -> Option<String> {
        match self {
            Composed::Record(body) => body.replaces().map(ToString::to_string),
            Composed::Registration(RegistrationBody::Vouch(vouch)) => vouch.replaces.as_ref().map(ToString::to_string),
            Composed::Registration(_) => None,
        }
    }
}

/// Returns the type address a binding's or an endpoint's body rides.
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
/// signed body past its kind's cap (REG-1.86 (h)), judged on the signed
/// bytes.
fn compose(term: BoardTerm, home_account: &str, home: &str, to: &[&str], body: Composed<'_>, hand: &dyn Signer) -> Result<String, Halt> {
    let ty = body.ty().to_string();
    let sigless = body.encode(None);
    let frame = RecordFrame { alg: hand.public_key().alg(), board: term, home_account, home, ty: &ty, to, sigless: sigless.as_bytes() }
        .compose()
        .ok_or_else(|| Halt::face("the record frame could not be composed", "an address of the deposit did not parse", "this is this client's frame; nothing was written"))?;
    let signed = body.encode(Some(&sig_hex(&hand.sign(&frame))));
    let cap = body.cap();
    if signed.len() > cap {
        return Err(Halt::face(
            format!("the record is {} bytes signed, past the cap of {cap}", signed.len()),
            "a registry record's body is held to its kind's cap, its `sig` counted (REG-1.86 (h)): past it the board refuses the record and no reader holds it",
            "name fewer or shorter members; nothing was written",
        ));
    }
    Ok(signed)
}

/// Deposits one registry record: the composition's kind-general half.
///
/// `to` is the link's target — the account a binding binds, none for a
/// targetless binding and for an endpoint, the request's link for an
/// answer (REG-2.26's carriage). The record
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
fn deposit_record(board: &Board, token: &Token, home: &str, to: Option<&str>, body: Composed<'_>, hand: &dyn Signer, id: &str) -> Result<Deposited, Halt> {
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
    let ty = body.ty().to_string();
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
        return Ok(Deposited { atom, link: link.to_string(), at, replaces: body.replaces() });
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

/// One binding to write (REG-2.18, REG-2.19).
pub struct BindingDeposit<'a> {
    /// The home: the binding-writing account's own doc 1 (REG-2.4).
    pub home: &'a str,
    /// The prefix bound, in the local form of the board the home is on.
    pub prefix: &'a Address,
    /// The account the prefix is bound to — the link's target; `None` for
    /// a targetless binding, a retirement's one spelling (REG-2.21).
    pub account: Option<&'a str>,
    /// The link's address of the binding this one replaces at the prefix;
    /// `None` on an allocation, which names the empty state (REG-2.9).
    pub replaces: Option<&'a str>,
    /// The writing hand: a key of the set that opens the home's account.
    pub hand: &'a dyn Signer,
    /// AUTH-5.6's per-session id, one per deposit.
    pub id: &'a str,
}

/// Deposits a binding: one prefix bound to one account, or to none.
///
/// The record is the binding's canonical body — the prefix, and `replaces`
/// where it names one — signed by `d.hand` and deposited as every registry
/// record is; the link runs from the atom to the account bound (REG-2.19).
/// The board judges the form and the `sig` and never the binding's
/// standing: two bindings of one prefix both commit, and which holds the
/// prefix is the walk's to say ([`fold_bindings`]; REG-2.16), so a writer
/// reads back what it bound.
///
/// # Errors
///
/// A `replaces` that is no address is this client's caller's fault, faced
/// before any read; then `deposit_record`'s errors.
pub fn deposit_binding(board: &Board, token: &Token, d: &BindingDeposit<'_>) -> Result<Deposited, Halt> {
    let replaces = match d.replaces {
        None => None,
        Some(text) => Some(parse_address(text).ok_or_else(|| {
            Halt::face(format!("`{text}` is no address"), "a binding's `replaces` is the link's address of the binding it replaces (REG-1.86 (g))", "this is this client's frame; nothing was written")
        })?),
    };
    let body = Body::Binding(Binding { prefix: d.prefix.clone(), replaces });
    deposit_record(board, token, d.home, d.account, Composed::Record(&body), d.hand, d.id)
}

/// One binding as a doc 1 holds it, folded (REG-2.8 to REG-2.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingRecord {
    /// The link's address.
    pub link: String,
    /// The link's position: the binding's place in journal order.
    pub at: Option<u64>,
    /// The prefix the binding names.
    pub prefix: String,
    /// The account it binds the prefix to; `None` at a targetless binding.
    pub account: Option<String>,
    /// The binding it names in `replaces`, where it names one.
    pub replaces: Option<String>,
    /// Whether the walk honors it: set by [`fold_bindings`].
    pub honored: bool,
}

/// Folds `records`, in journal order, by the binding walk's rule.
///
/// It is REG-2.8 to REG-2.10, as a mirror's index makes it. At each prefix
/// the first binding naming no `replaces` is the allocation. A later one is
/// honored only where it names the binding current at that prefix and
/// binds the account the allocation named, or none; every other is inert —
/// a second allocation of a held prefix, a binding naming another account,
/// one naming a binding no longer current. Each record's `honored` is set
/// by the walk.
///
/// **Precondition.** `records` are one home's bindings in journal order.
pub fn fold_bindings(mut records: Vec<BindingRecord>) -> Vec<BindingRecord> {
    // Per prefix: the account the allocation named, and the link current.
    let mut standing: Vec<(String, Option<String>, String)> = Vec::new();
    for record in &mut records {
        match standing.iter_mut().find(|(prefix, ..)| *prefix == record.prefix) {
            None => {
                record.honored = record.replaces.is_none();
                if record.honored {
                    standing.push((record.prefix.clone(), record.account.clone(), record.link.clone()));
                }
            }
            Some((_, allocated, current)) => {
                let names_current = record.replaces.as_deref() == Some(current.as_str());
                let same_or_none = record.account.is_none() || record.account == *allocated;
                record.honored = names_current && same_or_none;
                if record.honored {
                    *current = record.link.clone();
                }
            }
        }
    }
    records
}

/// Returns the binding current at `prefix`, where the walk holds one.
///
/// It is the last honored binding of `history` naming the prefix: the
/// allocation, or the latest record that replaced it. Its `account` is the
/// prefix's holder, `None` where the prefix is retired.
pub fn holder_of<'h>(history: &'h [BindingRecord], prefix: &str) -> Option<&'h BindingRecord> {
    history.iter().rev().find(|record| record.honored && record.prefix == prefix)
}

/// Returns the next prefix by next-form (REG-2.3), off the bindings alone.
///
/// The bindings are the whole of its input: the answer is the prefix one
/// past the greatest a binding of `history` has ever named beneath `under`
/// — honored or inert, held or retired — so a prefix named once is never
/// named again. `under` is the tier the home binds for, `first` the first
/// prefix it allocates: at the registry's root `1` and `2`, the root's own
/// `1.1` being the registry's board. `None` where the count passes `u64` or
/// the prefix is no address.
pub fn next_prefix(history: &[BindingRecord], under: &str, first: u64) -> Option<Address> {
    let child = |prefix: &str| -> Option<u64> {
        let last = prefix.strip_prefix(under)?.strip_prefix('.')?;
        if last.is_empty() || !last.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        last.parse().ok()
    };
    let named = history.iter().filter_map(|record| child(&record.prefix)).max();
    let next = match named {
        Some(greatest) => greatest.checked_add(1)?.max(first),
        None => first,
    };
    parse_address(&format!("{under}.{next}"))
}

/// Reads the bindings homed in `home`, in journal order, folded.
///
/// The read is every link typed the binding's homed there
/// ([`links_homed`]), each read back with its atom and parsed under the
/// canonical rule, in the home's link order, which is journal order within
/// one home; then [`fold_bindings`]. A binding's link is read on the audit
/// view, so a `nullify` clears nothing (REG-2.14) and none is asked about.
/// A link whose atom does not read back, or whose bytes are no binding, is
/// no binding and is passed over, as a mirror passes over it. A home that
/// is not registered, or holds no binding, has none.
///
/// # Errors
///
/// The death signal under `token`, faced; the board's refusal of a read;
/// an answer of a shape this client does not know; and [`Board::op`]'s
/// errors.
pub fn binding_history(board: &Board, token: Option<&Token>, home: &str) -> Result<Vec<BindingRecord>, Halt> {
    let mut links = links_homed(board, token, home, &t_binding().to_string())?;
    links.sort_by_key(|link| link_order(link));
    links.dedup();
    let ty = t_binding().to_string();
    let mut atoms = Atoms::new(board, token);
    let mut records = Vec::new();
    for link in links {
        let Some(stored) = stored_link(board, token, &link)? else { continue };
        if !stored.value.typed_exactly(&ty) {
            continue;
        }
        let Some(atom) = one_address(&stored.value.from) else { continue };
        let Some(bytes) = atoms.read(home, atom)? else { continue };
        let Ok(record) = parse(BodyKind::Binding, &bytes) else { continue };
        let Body::Binding(binding) = record.body else { continue };
        // A target that is not one account's address names no holder this
        // walk reads: a targetless binding has none.
        let account = match stored.value.to.as_slice() {
            [] => None,
            _ => match one_address(&stored.value.to) {
                Some(account) => Some(account.to_string()),
                None => continue,
            },
        };
        records.push(BindingRecord { link, at: stored.value.at, prefix: binding.prefix.to_string(), account, replaces: binding.replaces.map(|a| a.to_string()), honored: false });
    }
    Ok(fold_bindings(records))
}

/// One answer to write on a request's thread (REG-4.79; REG-1.86).
pub struct AnswerDeposit<'a> {
    /// The home: the binding-writing account's own doc 1, the one residence
    /// an answer grounds an act from.
    pub home: &'a str,
    /// The request answered, by its link's address: the answer's `to`.
    pub request: &'a str,
    /// The answer's body: an approved, a refused or a denied answer's.
    pub body: &'a RegistrationBody,
    /// The writing hand: a key of the set that opens the home's account.
    pub hand: &'a dyn Signer,
    /// AUTH-5.6's per-session id, one per deposit.
    pub id: &'a str,
}

/// Deposits an answer on a request's thread.
///
/// The record is the answer's canonical body under its own row — approved,
/// refused or denied (REG-4.90, REG-4.85, REG-4.99) — signed by `d.hand`
/// and deposited as every registry record is: the link typed that row,
/// from the atom to the request's link, one address (REG-4.81).
///
/// # Errors
///
/// A body that is no answer's — a request's or a vouch's — is this
/// client's caller's fault, faced before any read; then `deposit_record`'s
/// errors.
pub fn deposit_answer(board: &Board, token: &Token, d: &AnswerDeposit<'_>) -> Result<Deposited, Halt> {
    if !matches!(d.body.kind(), RegistrationKind::Approved | RegistrationKind::Refused | RegistrationKind::Denied) {
        return Err(Halt::face(
            "the record is no answer",
            "an answer is the approved, the refused or the denied row's body (REG-1.15); a request and a vouch are written by other hands",
            "this is this client's frame; nothing was written",
        ));
    }
    deposit_record(board, token, d.home, Some(d.request), Composed::Registration(d.body), d.hand, d.id)
}

/// A link written alone: its address and its position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Linked {
    /// The link's address.
    pub link: String,
    /// The link's position.
    pub at: u64,
}

/// Writes the approval link: from a genesis to the request it answers.
///
/// It is a link alone, typed the registration kind's approval row and
/// homed in `home`, the binding-writing account's own doc 1 (REG-4.123
/// step 1; REG-1.86): `from` the address of the genesis link the approval
/// wrote, `to` the request's link. It names no record kind, so it takes
/// the plain path and the entry signature a link into a published home
/// carries: the `attest` over the `make_link` body, the frame's `account`
/// the session's own and its `doc` the home, signed by `signer`, the
/// session's key. `own` is the account the session acts as.
///
/// # Errors
///
/// A board with no `H.1` yet halts, nothing sent; an address that does not
/// parse is this client's frame; the session closed; an `attestation_*`
/// refusal is faced as this client's own frame; any other refusal, an
/// answer that is no `ack_addr`, and the reads' errors halt.
#[allow(clippy::too_many_arguments)]
pub fn link_approval(board: &Board, token: &Token, own: &str, home: &str, genesis: &str, request: &str, signer: &dyn Signer, id: &str) -> Result<Linked, Halt> {
    let Some(term) = board.board_term()? else {
        return Err(Halt::face(
            "this board has no H.1 yet, so the approval link cannot be written",
            "a link into a published home carries an `attest` naming `H.1`'s pair as its board term, and the board answers no head",
            "retry once the board has written its head; nothing was written",
        ));
    };
    let frame_fault = || Halt::face("the approval link's frame could not be composed", "an address of the link did not parse", "this is this client's frame; nothing was written");
    let (own, home_address) = (parse_address(own).ok_or_else(frame_fault)?, parse_address(home).ok_or_else(frame_fault)?);
    let (from, to, ty) = ([unit_span(&parse_address(genesis).ok_or_else(frame_fault)?)], [unit_span(&parse_address(request).ok_or_else(frame_fault)?)], [unit_span(t_approval())]);
    let body = entry_body_make_link(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) });
    let mut frame = frames::make_link(home, &[genesis], &[request], &t_approval().to_string(), Some(id));
    frame["attest"] = attest_member(term, &own, DocTerm::One(&home_address), &body, signer);
    let v = match board.op(Some(token), &frame)? {
        Answer::Closed => return Err(closed_face("writing the approval link")),
        Answer::Document(v) => v,
    };
    if let (Some(link), Some(at)) = (acked_addr(&v), acked_at(&v)) {
        return Ok(Linked { link: link.to_string(), at });
    }
    let Some(r) = Rejection::of(&v) else { return Err(shape_face(&v)) };
    if r.key().starts_with("attestation_") {
        return Err(Halt::face(
            "the board judged the approval link's attest and refused",
            format!("{}: the frame this client composed did not verify under the set that opens the account as of the base, or the board had no head", r.token()),
            "this is this client's frame and never your act; `board_unavailable` is a reorder — retry once the head is written",
        ));
    }
    Err(r.refused(&v))
}

/// One link as its home stores it, read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredLink {
    /// The link's address.
    pub link: String,
    /// The document the link is homed in.
    pub home: String,
    /// The link's three slots and the position of the commit that made it.
    pub value: LinkValue,
    /// The board's testimony of when that position committed, in
    /// milliseconds since the epoch; `None` where it holds no reading.
    pub time: Option<u64>,
}

/// Reads the link at `link` back, where one stands.
///
/// `None` where the address holds no link, or is no link's address.
///
/// # Errors
///
/// The death signal under `token`, faced; the board's refusal of the read;
/// an answer of a shape this client does not know; and [`Board::op`]'s
/// errors.
pub fn stored_link(board: &Board, token: Option<&Token>, link: &str) -> Result<Option<StoredLink>, Halt> {
    let Some(home) = document_of(link) else { return Ok(None) };
    let v = answered(board, token, &frames::read_link(link), "reading a link")?;
    match answers::link_value(&v) {
        Some(Some(value)) => Ok(Some(StoredLink { link: link.to_string(), home, value, time: v["time"].as_u64() })),
        Some(None) => Ok(None),
        None => Err(shape_face(&v)),
    }
}

/// Returns the one address a stored slot names, where it names exactly one.
///
/// A slot named by address stores one unit span an address; `None` for an
/// empty slot, one of several spans, and a span that is no unit span.
pub fn one_address(slot: &[crate::board::LinkSpan]) -> Option<&str> {
    match slot {
        [span] if span.is_unit() => Some(span.start.as_str()),
        _ => None,
    }
}

/// The addresses one window of a link search asks for.
const LINK_WINDOW: u64 = 256;

/// Lists the links homed in `home` whose type lies at or under `ty`.
///
/// It is the windowed four-set over the home and the type, drained (wire.md
/// §Link discovery reads): a `home` naming one document reads that
/// document's links and takes no permit. The board matches both slots by
/// overlap, so the list also names links a reader does not want — one
/// homed elsewhere whose home span only contains this one is none, the
/// list being kept to links whose own address lies in `home`, but one
/// typed a row above `ty` stands in it: a reader keeps by the stored type.
/// A home that is not registered has none.
///
/// # Errors
///
/// The death signal under `token`, faced; the board's refusal of a read
/// other than `doc_not_registered`; a window that does not move past its
/// cursor, faced as the board's fault; and [`Board::op`]'s errors.
pub fn links_homed(board: &Board, token: Option<&Token>, home: &str, ty: &str) -> Result<Vec<String>, Halt> {
    let (home_span, ty_span) = (frames::unit_span(home), frames::unit_span(ty));
    let (home_spans, ty_spans) = (home_span.as_array().cloned().unwrap_or_default(), ty_span.as_array().cloned().unwrap_or_default());
    let mut out = drained(board, token, |cur| frames::window_four(frames::Slot::Spans(&home_spans), frames::Slot::Any, frames::Slot::Any, frames::Slot::Spans(&ty_spans), cur, LINK_WINDOW))?;
    out.retain(|link| document_of(link).as_deref() == Some(home));
    Ok(out)
}

/// Lists the links whose type lies at or under `ty` and whose `to` touches
/// `to`.
///
/// It is the windowed search over a type and a target, drained — the queue
/// read's shape (REG-4.78): both slots constrained, so no class scan and no
/// permit. The board matches both by overlap, so a reader keeps by the
/// stored slots ([`stored_link`], [`one_address`]).
///
/// # Errors
///
/// [`links_homed`]'s errors.
pub fn links_to(board: &Board, token: Option<&Token>, ty: &str, to: &str) -> Result<Vec<String>, Halt> {
    drained(board, token, |cur| frames::window_ftt(ty, to, cur, LINK_WINDOW))
}

/// Drains a windowed link read: every page, from no cursor to the last.
///
/// # Errors
///
/// [`links_homed`]'s errors.
fn drained(board: &Board, token: Option<&Token>, page: impl Fn(Option<&str>) -> Value) -> Result<Vec<String>, Halt> {
    let during = "listing a home's links";
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    loop {
        let v = match read(board, token, &page(cur.as_deref()), during)? {
            Ok(v) => v,
            Err((r, _)) if r.key() == "doc_not_registered" => return Ok(out),
            Err((r, v)) => return Err(r.refused(&v)),
        };
        let Some(window) = answers::link_page(&v) else { return Err(shape_face(&v)) };
        out.extend(window.batch);
        if window.exhausted {
            return Ok(out);
        }
        if window.next.is_none() || window.next == cur {
            return Err(Halt::face(
                "the board answered a window of links that does not move past its cursor",
                "a windowed link read answered `exhausted: false` and no later `next` (wire.md §Link discovery reads)",
                "this is a fault in the board, not in your keys; nothing was written",
            ));
        }
        cur = window.next;
    }
}

/// A reader of record atoms, holding one image a home.
///
/// A record's bytes are reached through its home's arrangement and never by
/// identity (AUTH-2.114): the atom's V-ordinal off the home's I-map, then
/// the value arranged there. The map of a home is read once and kept; an
/// atom it does not hold — one deposited since — reads the map again
/// before it is answered absent.
pub struct Atoms<'b> {
    board: &'b Board,
    token: Option<&'b Token>,
    maps: Vec<(String, u64, Vec<answers::IRun>)>,
}

impl<'b> Atoms<'b> {
    /// Returns a reader over `board`, under `token` or as a guest.
    pub fn new(board: &'b Board, token: Option<&'b Token>) -> Atoms<'b> {
        Atoms { board, token, maps: Vec::new() }
    }

    /// Reads the bytes of the atom at `atom`, arranged in `home`.
    ///
    /// `None` where the home is not registered or holds no content, where
    /// its arrangement does not hold the atom, and where the value there
    /// is no atom's.
    ///
    /// # Errors
    ///
    /// The death signal under the token, faced; the board's refusal of a
    /// read other than `doc_not_registered` at the home; and
    /// [`Board::op`]'s errors.
    pub fn read(&mut self, home: &str, atom: &str) -> Result<Option<Vec<u8>>, Halt> {
        let during = "reading a record";
        let held = |maps: &[(String, u64, Vec<answers::IRun>)]| maps.iter().find(|(h, ..)| h == home).and_then(|(_, _, runs)| answers::ordinal_of(runs, atom));
        let ordinal = match held(&self.maps) {
            Some(ordinal) => ordinal,
            None => {
                let extent = match read(self.board, self.token, &frames::span_set(home), during)? {
                    Ok(v) => answers::content_extent(&v),
                    Err((r, _)) if r.key() == "doc_not_registered" => return Ok(None),
                    Err((r, v)) => return Err(r.refused(&v)),
                };
                if extent == 0 {
                    return Ok(None);
                }
                let image = imaged(self.board, self.token, &frames::image(home, 1, extent), during)?;
                let Some(runs) = answers::i_runs(&image, extent) else { return Ok(None) };
                self.maps.retain(|(h, ..)| h != home);
                self.maps.push((home.to_string(), extent, runs));
                let Some(ordinal) = held(&self.maps) else { return Ok(None) };
                ordinal
            }
        };
        let v = answered(self.board, self.token, &frames::retrieve_v(home, ordinal, 1), during)?;
        Ok(answers::first_atom(&v))
    }
}

/// One registration record read off its link (REG-1.86).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationEntry {
    /// The link, read back.
    pub stored: StoredLink,
    /// The row the link is typed: the kind the body is parsed under.
    pub kind: RegistrationKind,
    /// The atom's bytes.
    pub bytes: Vec<u8>,
    /// The record the bytes spell under that row, or the parse's refusal.
    pub record: Result<RegistrationRecord, ParseRefusal>,
}

/// Reads the registration record at `link`, where one stands.
///
/// The link's stored type names the row — a request's kind, an answer or
/// the vouch — and the atom its `from` names is read through `atoms` and
/// parsed under that row. `None` where no link stands there, where its
/// type is no body-bearing registration row, where its `from` is not one
/// atom of its own home, and where the atom does not read back.
///
/// # Errors
///
/// [`stored_link`]'s errors and [`Atoms::read`]'s.
pub fn registration_at(board: &Board, token: Option<&Token>, atoms: &mut Atoms<'_>, link: &str) -> Result<Option<RegistrationEntry>, Halt> {
    let Some(stored) = stored_link(board, token, link)? else { return Ok(None) };
    let Some(kind) = one_address(&stored.value.ty).and_then(parse_address).and_then(|ty| RegistrationKind::at(&ty)) else { return Ok(None) };
    let Some(atom) = one_address(&stored.value.from).filter(|atom| document_of(atom).as_deref() == Some(stored.home.as_str())).map(str::to_string) else { return Ok(None) };
    let Some(bytes) = atoms.read(&stored.home, &atom)? else { return Ok(None) };
    let record = parse_registration(kind, &bytes);
    Ok(Some(RegistrationEntry { stored, kind, bytes, record }))
}

/// Returns the sort key that puts one home's links in the order minted.
///
/// It is tumbler order over the dotted spelling: a home's link subspace
/// mints its ordinals in order, so within one home it is journal order.
pub(crate) fn link_order(link: &str) -> Vec<u64> {
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

/// Returns the whole image the `image` frame `frame` asks for.
///
/// It is [`answered`] for a home in more runs than one answer carries: the
/// pages read in order as one state ([`answers::whole_image_read`]), the
/// document a `runs` answer holding every run.
///
/// # Errors
///
/// [`answers::whole_image_read`]'s errors; the death signal, faced; and
/// the board's refusal as it answered.
fn imaged(board: &Board, token: Option<&Token>, frame: &Value, during: &str) -> Result<Value, Halt> {
    match answers::whole_image_read(board, token, frame)? {
        Answer::Closed => Err(closed_face(during)),
        Answer::Document(v) => match Rejection::of(&v) {
            Some(r) => Err(r.refused(&v)),
            None => Ok(v),
        },
    }
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
            let Ok(signed) = compose(term(), ACCOUNT, HOME, to, Composed::Record(&body), &hand) else {
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
        let room = MAX_REGISTRY_RECORD_BYTES + 1 - compose(term(), ACCOUNT, HOME, &[], Composed::Record(&endpoint(1)), &hand).expect("a short record").len();
        assert_eq!(compose(term(), ACCOUNT, HOME, &[], Composed::Record(&endpoint(room)), &hand).expect("a record at the cap").len(), MAX_REGISTRY_RECORD_BYTES);
        let past = compose(term(), ACCOUNT, HOME, &[], Composed::Record(&endpoint(room + 1)), &hand).expect_err("one byte past the cap");
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

    /// A home in more runs than one answer carries is read whole.
    ///
    /// The home holds 5,000 runs and the record's atom is the 4,500th: the
    /// endpoint history and the atom read each image the home in two
    /// frames and read the atom at its own ordinal, on the second page (the
    /// mutant that takes the first page for the image finds no atom there,
    /// so the history holds no deposit and the atom reads as absent).
    #[test]
    fn a_long_homes_records_are_read_through_its_whole_image() {
        let home = std::sync::Arc::new(answers::paging::Paged::of(HOME, 5_000));
        let atom = home.runs[4_499].0.clone();
        let link = format!("{HOME}.0.2.1");
        let record = r#"{"type":"endpoint","origins":["https://a.example"]}"#;
        let board = {
            let (home, atom, link) = (home.clone(), atom.clone(), link.clone());
            Fake::new(move |req| {
                let f = fake::frame(req);
                match f["op"].as_str().unwrap_or("?") {
                    "retrieve_doc_v_span_set" => fake::json(200, json!({"as_of": 9, "resp": "span_set", "set": [{"start": "1.1", "width": "0.5000"}]})),
                    "find_links_v_history" => fake::json(200, json!({"as_of": 9, "resp": "links", "links": [{"a": link, "at": 5, "retracted_at": null}], "next": null, "exhausted": true})),
                    "read_link" => fake::json(200, json!({"as_of": 9, "at": 5, "resp": "link_value", "link": {"slots": [frames::unit_span(&atom), [], frames::unit_span(&t_endpoint().to_string())]}})),
                    "image" => fake::json(200, home.answer(&f, None)),
                    "retrieve_v" if f["specs"][0]["span"]["start"] == "1.4500" => fake::json(200, json!({"as_of": 9, "items": [{"atom": record}], "resp": "delivery"})),
                    other => panic!("the read sends no {other:?}: {f}"),
                }
            })
        };
        let history = endpoint_history(&fake::board(&board), None, HOME).expect("the history");
        assert_eq!(history, [EndpointRecord { link, origins: vec!["https://a.example".into()], replaces: None, honored: true, nullified: false }]);
        assert_eq!(home.served(), [(None, 1, 5_000, false), (None, 4_097, 904, true)], "the image whole, two frames");
        let dialed = fake::board(&board);
        let mut atoms = Atoms::new(&dialed, None);
        assert_eq!(atoms.read(HOME, &atom).expect("the atom's read"), Some(record.as_bytes().to_vec()));
        assert_eq!(home.served().len(), 4, "the atoms' own image, two frames more");
    }
}
