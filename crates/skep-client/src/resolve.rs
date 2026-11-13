//! The registry walk over this crate's one dialer.
//!
//! This crate implements `skep_resolve::Transport` over its `Dialer`
//! (`client.md` §1.1's dependency paragraph), so the shell dials the board
//! the registry names and never one the serving board's word names (P25),
//! and no cycle forms and no second trait is minted. The registry answers
//! the board and never an account's set: the reader's verifier takes no key
//! set from it (`verify`'s row).
//!
//! **The mirror's dial.** A registry mirror reaches the root its hint names
//! through this crate's dialer, an `https` root and an `http` one alike
//! ([`mirror_dial`]; REG-3.2, REG-3.12): the resolver links no TLS library,
//! so this dialer's `tls` arm is the one `https` path a mirror has, and an
//! `http` root rides the same dialer rather than the resolver's own client —
//! one transport, one set of bounds and one error map for both schemes
//! (`client.md` §1.1: one outbound dialer). A build without `tls` refuses an
//! `https` root by name, [`TransportError::NotHeld`], as the resolver's own
//! client does.
//!
//! **The bounds are the resolver's.** A mirror's reads keep the two bounds
//! the resolver's own client reads under, never a frame's
//! ([`mirror_dialer`]): each read and write within a minute, since a feed
//! page on a large board outlasts a frame's bound, and no answer read past
//! the feed's page byte budget and its envelope. The cap decides what a
//! mirror folds — a typed read takes an answer past it as one it cannot
//! read — so it is held at two places: the mirror's dialer reads no further
//! than it, and this transport refuses a body past it whichever dialer
//! carried it.
//!
//! **The root hint, read off a board.** A reader reaches a registry through
//! one line, its root hint: the registry's origins in the order they are
//! tried, then the realm, the fingerprint of the registry's genesis key set
//! (REG-3.2, REG-3.39). [`root_hint`] composes that line for a board it is
//! pointed at: it reads the board's claim and the claimant's genesis record
//! as a guest, through the read a mirror's realm check makes
//! (`skep_resolve::Mirror::read_genesis`; REG-3.42) and no other, so the
//! realm it names is the one a mirror opened from the line compares and
//! passes. The fork point of a forked lineage is the caller's to name
//! ([`fork_point`]; REG-3.40): no read answers one. What stops the read is
//! a member of this crate's halt family.
//!
//! **A cross-board address, resolved.** A cross-board address is one global
//! tumbler ([`global_address`]). Its node field is the prefix of the org
//! that holds it (REG-1.62), and the registry says which board answers to
//! that prefix by one link (REG-3.7); the rest of the address is read at
//! that board, in the board's local form, the prefix swapped for `1`
//! (REG-1.61; REG-1.63's ingress swap). [`resolve_address`] resolves the
//! prefix off a mirror of the registry kept under a directory of the
//! caller's — [`mirror_home`] names the one beside a key store, keyed by
//! the hint's genesis fingerprint — and answers the walk's named state
//! (REG-3.80) with the address's two parts, a [`Resolved`]. Every call
//! opens the mirror against the root the hint names, which reads the
//! registry to its head before the walk, so a binding or a deposit made
//! since the last call is seen: no answer is given from a copy alone, and
//! nothing is remembered as absent (REG-3.10). A deeper node field than any
//! standing on the registry is the walk's own to answer (REG-3.82); it is
//! never split another way. The walk dials no org's board, so the two faces
//! read at the dial — BOUND-BUT-DISCLAIMED (REG-3.81) and the
//! live-enforcement face (REG-3.84) — are not answered here. What a command
//! prints of the answer as data is the answer's own ([`Resolved::line`],
//! [`Resolved::object`]); the words of a face are its embedder's.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use skep_address::{validate, Address, Nat, Tumbler};
use skep_identity::{Enrolled, Fingerprint};
use skep_resolve::{BoardError, GuestCost, Method, Mirror, MirrorError, Refusal, Transport, TransportError, FEED_COPY, FETCH_CACHE};
use skep_util::file;

use crate::dial::{DialError, Dialer, PlainHttp, Request};
use crate::halt::{clipped, Halt, Refused};
use crate::origin::{NotCanonical, Origin};

/// The root hint's names, as [`root_hint`] answers them.
///
/// They are the resolver's own, named here so an embedder that holds this
/// crate alone — the `skep` command — reads the line back
/// (`RootHint::parse`), computes a realm (`RealmId::genesis_fingerprint`)
/// and reads what the genesis read found, with no dependency line of its
/// own.
pub use skep_resolve::{Genesis, RealmId, RootHint};

/// The walk's names, as [`resolve_address`] takes and answers them.
///
/// They are the resolver's own, named here for the same embedder: the
/// resolver's own resolution of a host name and the transports it holds,
/// which the walk is handed; how a mirror came to hold its base; and the
/// named state the walk answers, with every part a face is made of, so an
/// embedder words each face with no dependency line of its own.
pub use skep_resolve::{
    BindingRecord, EndpointDial, EndpointRecord, Judged, MemberKind, MemberOutcome, NameResolver, Opened, Resolution, Standing, Successor, SystemResolver, Term, Transports, Unreachable, Verdict,
};

/// The per-call read/write bound of a mirror's exchange.
///
/// It is the resolver's own, `skep-resolve`'s `http::IO_TIMEOUT`: a page of
/// the feed or a historical read is seconds on a loaded board, and a minute
/// is headroom. The crate keeps the figure private, so it is spelled again
/// here and this module's suite holds the two equal.
const RESOLVER_IO_TIMEOUT: Duration = Duration::from_secs(60);

/// The most bytes the resolver reads of one answer.
///
/// It is the resolver's own, `skep-resolve`'s `http::MAX_ANSWER_BYTES`: a
/// feed page at the page byte budget, 2 MiB, and 4 KiB for the head and the
/// page's envelope (wire.md §The change feed, Paging). Spelled again here
/// for the same reason, and held equal the same way.
const RESOLVER_ANSWER_CAP: usize = 2 * 1024 * 1024 + 4 * 1024;

/// `skep_resolve::Transport` over one `Dialer` at one origin.
///
/// An answer whose body runs past the resolver's answer cap is
/// [`TransportError::TooLarge`], whichever dialer read it.
pub struct DialerTransport {
    dialer: Arc<dyn Dialer>,
    origin: Origin,
}

impl std::fmt::Debug for DialerTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DialerTransport({})", self.origin)
    }
}

impl DialerTransport {
    /// Returns the transport for `origin` through `dialer`.
    pub fn new(dialer: Arc<dyn Dialer>, origin: Origin) -> DialerTransport {
        DialerTransport { dialer, origin }
    }
}

impl Transport for DialerTransport {
    fn exchange(&self, method: Method, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        let method = match method {
            Method::Get => crate::dial::Method::Get,
            Method::Post => crate::dial::Method::Post,
        };
        let req = Request { method, path: path.to_string(), headers: Vec::new(), body: body.to_vec() };
        let resp = self.dialer.exchange(&self.origin, &req).map_err(transport_error)?;
        if resp.body.len() > RESOLVER_ANSWER_CAP {
            return Err(TransportError::TooLarge { cap: RESOLVER_ANSWER_CAP });
        }
        Ok((resp.status, resp.body))
    }
}

/// Returns the resolver's class for a dial that failed.
///
/// One class decides what the resolver does: an answer past the cap,
/// [`TransportError::TooLarge`], is one a typed read takes as its own
/// cannot-read (`skep_resolve::Board`), so it is kept exactly. The rest a
/// mirror names beside each origin it tried, told apart by type, and each
/// keeps its side of this crate's line: an answer the board gave
/// ([`DialError::answered`]) is [`TransportError::Response`] or
/// [`TransportError::TooLarge`], and nothing else is.
///
/// - [`DialError::NotHeld`] is [`TransportError::NotHeld`]: no `tls` arm in
///   this build, and no board reached.
/// - [`DialError::Resolve`] is [`TransportError::Resolve`].
/// - [`DialError::Connect`] and [`DialError::Tls`] are
///   [`TransportError::Connect`]: no connection was made and no byte of the
///   request left — refused, unreachable or past the connect bound, a TLS
///   handshake broken off or past its bound, or a peer the TLS layer
///   refused, an untrusted certificate among them, its text led by `tls:`.
/// - [`DialError::Timeout`], [`DialError::Io`], [`DialError::Truncated`] and
///   [`DialError::Request`] are [`TransportError::Io`], the request not
///   written or the response not read whole: a read or a write past its
///   bound once connected (a board gone silent), a connection closed before
///   the answer's head or its declared body was whole (a board that hung
///   up), and a request this dialer would not write.
/// - [`DialError::Response`] is [`TransportError::Response`]: bytes that are
///   no HTTP response.
/// - [`DialError::TooLarge`] is [`TransportError::TooLarge`], its cap the
///   dialer's.
///
/// The match names every class and has no wildcard arm, so a class the
/// dialer gains is placed here before the crate builds.
fn transport_error(e: DialError) -> TransportError {
    match e {
        DialError::NotHeld(scheme) => TransportError::NotHeld(scheme),
        DialError::Resolve(text) => TransportError::Resolve(text),
        DialError::Connect(text) => TransportError::Connect(text),
        DialError::Tls(text) => TransportError::Connect(format!("tls: {text}")),
        DialError::Timeout(text) => TransportError::Io(format!("timed out: {text}")),
        DialError::Io(text) => TransportError::Io(text),
        truncated @ DialError::Truncated { .. } => TransportError::Io(truncated.to_string()),
        DialError::Request(text) => TransportError::Io(format!("malformed request: {text}")),
        DialError::Response(text) => TransportError::Response(text),
        DialError::TooLarge { cap } => TransportError::TooLarge { cap },
    }
}

/// The resolver's `Origin` as this crate's, where the two grammars agree.
///
/// Both reproduce the daemon's (AUTH-4.2); [`NotCanonical`] where they
/// diverge.
impl TryFrom<&skep_resolve::Origin> for Origin {
    type Error = NotCanonical;

    fn try_from(o: &skep_resolve::Origin) -> Result<Origin, NotCanonical> {
        o.as_str().parse()
    }
}

/// Returns a `Dial` for `skep_resolve::Mirror` over `dialer`.
///
/// It has the shipped dial's shape, this crate's transport behind it. Every
/// origin rides `dialer`, an `https` one and an `http` one alike, and the
/// per-call bound is `dialer`'s own: [`mirror_dial`] is this over the dialer
/// that keeps the resolver's.
pub fn dial(dialer: Arc<dyn Dialer>) -> impl Fn(&skep_resolve::Origin) -> Result<Box<dyn Transport>, TransportError> {
    move |o: &skep_resolve::Origin| {
        let origin = Origin::try_from(o).map_err(|_| TransportError::Response(format!("{o} is not a canonical origin here")))?;
        Ok(Box::new(DialerTransport::new(dialer.clone(), origin)) as Box<dyn Transport>)
    }
}

/// Returns the dialer a registry mirror's reads go through.
///
/// It is [`PlainHttp`] under the resolver's two bounds in a frame's place:
/// each read and each write within a minute, and no answer read past the
/// resolver's answer cap — the bytes on the wire counted, the head with the
/// body, as the resolver's own client counts them. Its exchange is held to
/// this crate's deadline besides, made from those two bounds, which the
/// resolver's own client does not keep.
pub fn mirror_dialer() -> PlainHttp {
    PlainHttp::bounded(RESOLVER_IO_TIMEOUT, RESOLVER_ANSWER_CAP)
}

/// Returns the `Dial` a registry mirror opens through.
///
/// It is [`dial`] over [`mirror_dialer`]: the path an `https` root takes,
/// where the build holds the `tls` arm, and the path an `http` root takes
/// too (REG-3.2: a hint may name both).
pub fn mirror_dial() -> impl Fn(&skep_resolve::Origin) -> Result<Box<dyn Transport>, TransportError> {
    dial(Arc::new(mirror_dialer()))
}

/// Parses a fork point as a root hint's `fork:` term spells one (REG-3.40).
///
/// It is the resolver's own reading of an address — the one a hint's line
/// is parsed and built under, each component a decimal natural of any size
/// within the board's own wire caps — so a fork point this admits is one
/// the line carries and reads back. `None` for any other text.
pub fn fork_point(text: &str) -> Option<Address> {
    skep_resolve::parse_address(text)
}

/// Reads a registry board's root hint off the board, as a guest.
///
/// The hint names `board` first and then each of `also`, in the order
/// given — the order a reader tries them in (REG-3.2) — then the realm, and
/// `fork` beside it where the caller names one (REG-3.40; it is never
/// inferred). The realm is read at `board` alone, through `dialer`, with no
/// key and no session: the board's first claim and the key set its
/// claimant's genesis record enrolls, fingerprinted (REG-3.39 — the genesis
/// set, never the living one), by the read a mirror's realm check makes
/// (`skep_resolve::Mirror::read_genesis`), which pages the board's feed no
/// further than the claim. An origin of `also` is taken on the caller's
/// word: it is written into the line and never dialed.
///
/// The second member is what that read found — the claim's position, the
/// claimant, the genesis fingerprint the hint carries, and the reads made.
/// A registry mirror's dialer is the one to pass ([`mirror_dialer`]): a
/// feed page outruns a frame's bounds.
///
/// # Errors
///
/// A [`Halt`], in the order they are met:
///
/// 1. A halt's face where an origin given is one the resolver's grammar
///    refuses, before any read: the two grammars reproduce the daemon's
///    one (AUTH-4.2), so this is a fault of the build.
/// 2. [`Halt::Dial`] where the board was not reached or did not answer —
///    the dial, `/health` or a later read — or answered what the wire does
///    not give.
/// 3. [`Halt::Refused`] where the board answered and refused a read: a
///    status outside the read's shape, a `rejected` answer, a board that
///    stayed busy past the retries, a feed whose start it has reclaimed.
/// 4. A halt's face naming `board` where its claim names no genesis
///    record, or the record could not be read whole: no realm can be
///    computed.
/// 5. A halt's face naming `board` where its feed ends with no claim: an
///    unclaimed board has no realm.
/// 6. A halt's face where `fork` is an address the line cannot carry — one
///    past the board's own wire caps, which [`fork_point`] never answers.
pub fn root_hint(dialer: Arc<dyn Dialer>, board: &Origin, also: &[Origin], fork: Option<Address>) -> Result<(RootHint, Genesis), Halt> {
    let listed = std::iter::once(board).chain(also).map(|origin| {
        skep_resolve::Origin::parse(origin.as_str()).ok_or_else(|| {
            Halt::face(
                format!("the origin {origin} is one this build's resolver does not read as canonical"),
                "the client's origin grammar and the resolver's both reproduce the daemon's (AUTH-4.2), and here they part",
                "this is a fault of this build: report it with the origin",
            )
        })
    });
    let listed: Vec<skep_resolve::Origin> = listed.collect::<Result<_, Halt>>()?;
    let genesis = Mirror::read_genesis(&listed[0], &dial(dialer)).map_err(|e| hint_halt(board, e))?;
    let hint = RootHint::new(listed, genesis.fingerprint, fork).map_err(|e| {
        Halt::face(
            format!("the root hint of the board at {board} was read and cannot be written as one line"),
            e.to_string(),
            "name the fork point as the board's own wire spells an address",
        )
    })?;
    Ok((hint, genesis))
}

/// Returns the halt a genesis read's refusal at `board` comes to.
///
/// An unclaimed board and a claim with no genesis record are states a
/// person acts on, each a face naming the board; a root that did not answer
/// is its one origin's own error, and that and every other read's refusal
/// is the family's member for it ([`board_halt`]). A class the resolver
/// names later is a face carrying its words.
fn hint_halt(board: &Origin, e: MirrorError) -> Halt {
    match e {
        MirrorError::NoClaim => Halt::face(
            format!("the board at {board} is unclaimed: it has no realm, so no root hint"),
            "a realm is the fingerprint of the key set its claimant's genesis record enrolls (REG-3.39), and this board's change feed ends with no claim",
            "claim the board (`skep claim`), then read its hint again",
        ),
        MirrorError::NoGenesis => Halt::face(
            format!("the claim of the board at {board} names no genesis record: no realm can be computed"),
            "no enroll record naming the claimant stands on the feed before its claim, or the one that stands could not be read whole; the realm is that record's key set and never the set the account holds now (REG-3.39)",
            "check that the origin names a skep board; a claimed board whose claimant's genesis record cannot be read is a board fault",
        ),
        MirrorError::Unreachable { mut tried } if !tried.is_empty() => board_halt(tried.swap_remove(0).1),
        MirrorError::Board(e) => board_halt(e),
        other => Halt::face(format!("the root hint of the board at {board} was not read"), other.to_string(), "read it again; where it stops here again, report it with these words"),
    }
}

/// Returns the halt family's member for a board read that failed.
///
/// A board not reached, or one whose answer the wire does not give, is
/// transport ([`Halt::Dial`]); a board that answered and refused is its
/// refusal ([`Halt::Refused`]): a status outside the read's shape under the
/// `error` its body names (this client's `http_error` where it names none,
/// its detail then the body, clipped), a `rejected` answer under its own
/// code, a board busy past the retries as the `503` it answered, and a
/// reclaimed feed as the wire's `410 history_reclaimed`, its detail the
/// floor.
fn board_halt(e: BoardError) -> Halt {
    let refused = |status: u16, code: &str, detail: Option<String>, op: Option<String>, body: Value| {
        Halt::Refused(Refused { status, code: code.to_string(), detail, op, body })
    };
    match e {
        BoardError::Transport(e) => Halt::Dial(dial_error(e)),
        BoardError::Malformed(what) => Halt::Dial(DialError::Response(what)),
        BoardError::Status { status, body } => {
            let answer: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            let detail = match answer["detail"].as_str() {
                Some(detail) => Some(detail.to_string()),
                None if answer["error"].is_string() => None,
                None => Some(clipped(&body, MAX_BODY_SAID).to_string()),
            };
            let code = answer["error"].as_str().unwrap_or("http_error").to_string();
            refused(status, &code, detail, None, answer)
        }
        BoardError::Rejected { op, code, detail } => refused(200, &code, detail, Some(op), Value::Null),
        BoardError::Busy => refused(503, "http_error", Some(BoardError::Busy.to_string()), None, Value::Null),
        BoardError::Reclaimed { floor } => {
            let detail = floor.map(|floor| format!("the oldest position still answerable is {floor}"));
            refused(410, "history_reclaimed", detail, None, Value::Null)
        }
        other => Halt::Dial(DialError::Response(other.to_string())),
    }
}

/// The most bytes of a board's answer a refusal's detail says.
///
/// A status outside a read's shape carries the body as served, which the
/// board sizes: a face is read by a person.
const MAX_BODY_SAID: usize = 200;

/// Returns this crate's class for a resolver transport's error.
///
/// It is [`transport_error`] read the other way, class for class, so a read
/// the resolver made over this crate's dialer halts under the class the
/// dialer named: the text keeps what the map folded into it — a TLS
/// refusal's `tls:` lead under [`DialError::Connect`], a bound run past
/// under [`DialError::Io`]. A class the resolver names later is an answer
/// the wire does not give.
fn dial_error(e: TransportError) -> DialError {
    match e {
        TransportError::NotHeld(scheme) => DialError::NotHeld(scheme),
        TransportError::Resolve(text) => DialError::Resolve(text),
        TransportError::Connect(text) => DialError::Connect(text),
        TransportError::Io(text) => DialError::Io(text),
        TransportError::Response(text) => DialError::Response(text),
        TransportError::TooLarge { cap } => DialError::TooLarge { cap },
        other => DialError::Response(other.to_string()),
    }
}

/// Resolves `prefix` as a guest reader over the registry board at `registry`.
///
/// It is a reader with no mirror (REG-3.24, REG-3.33), its verdicts
/// `UndeterminableHere` — `resolve(prefix)` → the board's endpoint as a
/// named state, priced.
///
/// # Errors
///
/// The walk's [`BoardError`], where the registry board refuses or cannot
/// answer a read its scan makes.
pub fn guest_resolve(dialer: Arc<dyn Dialer>, registry: &Origin, prefix: &Address) -> Result<(Resolution, GuestCost), BoardError> {
    let board = skep_resolve::Board::new(Box::new(DialerTransport::new(dialer, registry.clone())));
    skep_resolve::guest_resolve(&board, prefix, &SystemResolver, &Transports::default())
}

/// The directory under a key store that holds its registry mirrors.
///
/// It stands beside `keys/`, `bindings` and `lock`, one custody class to a
/// directory (`client.md` §3.1): a mirror is a copy of a registry board's
/// feed, and holds no key.
const REGISTRY_DIR: &str = "registry";

/// The lock file's name under a mirror's directory.
const MIRROR_LOCK: &str = "lock";

/// Returns the directory a registry's mirror is kept in beside a key store.
///
/// It is `<store>/registry/<genesis>/`: `store` the key store's directory,
/// and `<genesis>` the genesis fingerprint the hint's realm id opens with,
/// 64 lowercase hex (REG-3.39). The directory is keyed by the genesis so
/// that two registries — a dev registry and another — keep two copies and
/// neither retires the other's (REG-3.17); a hint re-pointed within one
/// genesis meets the copy held there, which the mirror's own open resumes
/// by its check or refuses (REG-3.18, REG-3.19). Nothing is made here:
/// [`resolve_address`] makes the directory it is handed.
pub fn mirror_home(store: &Path, hint: &RootHint) -> PathBuf {
    store.join(REGISTRY_DIR).join(hint.realm().genesis.to_hex())
}

/// Parses a cross-board address as the wire spells one.
///
/// It is the resolver's own reading of an address, the one [`fork_point`]
/// reads a fork point by: each component a decimal natural of any size
/// within the board's own wire caps, a leading zero naming its one address.
/// `None` for any other text — a sign, an empty component, a tumbler that
/// is no address.
pub fn global_address(text: &str) -> Option<Address> {
    skep_resolve::parse_address(text)
}

/// What [`resolve_address`] answers: the walk's state and the address's parts.
///
/// The state is the resolver's, a named value and never a blank (REG-3.80).
/// The answer says beside it what was resolved — the prefix, the address's
/// node field — and where the rest of the address is read, its local form;
/// and how the registry was read for it: at which root, to which head, the
/// copy begun or resumed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Resolved {
    /// The address asked.
    pub address: Address,
    /// The prefix resolved: the address's node field (REG-1.62).
    pub prefix: Address,
    /// The walk's answer for the prefix, as a named state (REG-3.80).
    pub resolution: Resolution,
    /// The address in the local form of the board its prefix names.
    ///
    /// It is the address with its node field swapped for `1`, as that
    /// board's ingress normalizes it (REG-1.61, REG-1.63). `None` for a
    /// bare prefix, an address of no account field, which names no place on
    /// a board. It is the address's own arithmetic, the same on every face;
    /// BOUND alone names a board to read it at.
    pub local: Option<Address>,
    /// How the mirror came to hold its base at this call.
    ///
    /// From genesis where the directory held no copy (REG-3.12), or a held
    /// copy checked against the root and resumed (REG-3.18).
    pub opened: Opened,
    /// The registry root that answered, where the mirror names one.
    ///
    /// It is the first of the hint's origins, in the hint's order, to
    /// answer.
    pub root: Option<skep_resolve::Origin>,
    /// The registry's head: the position the mirror was read to (REG-3.10).
    pub head: u64,
}

impl Resolved {
    /// Returns the one line a BOUND address is answered by.
    ///
    /// It is the origin of the endpoint member the walk would dial — the
    /// first in the org's order whose terms pass and whose transport is
    /// held (REG-3.34) — and then, a space between, the address in that
    /// board's local form, where the address names a place on it. `None`
    /// on every other face: no board is named to dial.
    pub fn line(&self) -> Option<String> {
        let Resolution::Bound { dial, .. } = &self.resolution else { return None };
        Some(match &self.local {
            Some(local) => format!("{} {local}", dial.origin),
            None => dial.origin.to_string(),
        })
    }

    /// Returns the face and its facts as one JSON object (REG-3.80).
    ///
    /// Every face carries `face`, its name as the resolver spells it
    /// (`Resolution::face`), `address`, the address asked, and `prefix`. A
    /// face with a standing carries `account` — `null` at a retired
    /// binding — `binding`, the current one, and `history`, every verified
    /// binding at the prefix in journal order. A face naming a bound
    /// account carries `keys`, the set that opens it as of the registry's
    /// head — `null` where this reader could not read it, never an empty
    /// list — `endpoint`, the current deposit or `null`, and `members`,
    /// each member's outcome in the org's order. Beside those, by face:
    /// BOUND, `dial`, the member the walk would dial, and `local`, the
    /// local form or `null` for a bare prefix; RETIRED-WITH-HISTORY,
    /// `successor`; BOUND-BUT-UNREACHABLE, `cause` and, at a dead origin,
    /// `member`; unreachable-by-policy, `member`, `term` and, on the host
    /// term, `yielded`; THE DIAL NOT MADE, `member` and `kind`; THE HOP NOT
    /// MADE, `parent`, the parent's own face as an object of this form, less
    /// the address.
    pub fn object(&self) -> Value {
        let mut object = face_object(&self.resolution);
        object["address"] = text(&self.address);
        if matches!(self.resolution, Resolution::Bound { .. }) {
            object["local"] = optional(self.local.as_ref());
        }
        object
    }
}

/// Resolves a cross-board address to the board it lives on (REG-3.7).
///
/// The address is one global tumbler: its node field is the prefix
/// resolved, and its local form — the prefix swapped for `1` — is where the
/// rest is read at the board that prefix names (REG-1.62, REG-1.63). The
/// prefix is resolved off the registry mirror under `mirror_dir`, opened at
/// this call against the root `hint` names, through `dialer`, as a guest: a
/// directory holding no copy is read from the registry's genesis
/// (REG-3.12), a held copy is checked against the root and resumed
/// (REG-3.18), and either way the mirror is at the registry's head before
/// the walk, so the answer holds as of that head and never of a copy held
/// across calls (REG-3.10). `names` is this resolver's own resolution of a
/// host name and `transports` what it can dial (REG-3.34, REG-3.35); the
/// walk opens no socket to an org's board.
///
/// The directory is made where it is absent, with every directory above it
/// that is, each `0700`; the copy's two files and the lock beside them are
/// `0600`. The lock is held from before the copy is read until the walk has
/// answered, so two calls over one directory take turns and the second
/// resumes what the first wrote. A registry mirror's dialer is the one to
/// pass ([`mirror_dialer`]).
///
/// # Errors
///
/// A [`Halt`], in the order they are met:
///
/// 1. A halt's face naming the directory where it, its lock or a file of
///    the copy cannot be made.
/// 2. Where no root of the hint answers, the first root's own halt —
///    [`Halt::Dial`] where it was not reached or answered what the wire
///    does not give, [`Halt::Refused`] where it answered and refused — its
///    words naming each further root beside its own error.
/// 3. A halt's face naming the directory where the held copy does not
///    read.
/// 4. A halt's face naming the directory where the root does not answer
///    for the held copy — a position diverging, a head below the copy's, a
///    chain contradicted (REG-3.19) — or where its genesis key set does not
///    fingerprint to the hint's realm (REG-3.42).
/// 5. A halt's face naming the hint's roots where the board that answered
///    is unclaimed, or its claim names no genesis record.
/// 6. [`Halt::Dial`] or [`Halt::Refused`] where a read of the registry
///    past `/health` fails, at the open or at the walk's read of the bound
///    account's key set; a line of the copy that cannot be written is the
///    face of 3.
pub fn resolve_address(
    dialer: Arc<dyn Dialer>,
    hint: &RootHint,
    mirror_dir: &Path,
    address: &Address,
    names: &dyn NameResolver,
    transports: &Transports,
) -> Result<Resolved, Halt> {
    let (prefix, local) = (prefix_of(address), local_form(address));
    let _held = hold(mirror_dir)?;
    let halted = |e: MirrorError| mirror_halt(hint, mirror_dir, e);
    let mut mirror = Mirror::open(hint, mirror_dir, &dial(dialer)).map_err(halted)?;
    let resolution = skep_resolve::resolve(&mut mirror, &prefix, names, transports).map_err(halted)?;
    Ok(Resolved { address: address.clone(), prefix, resolution, local, opened: mirror.opened().clone(), root: mirror.root().cloned(), head: mirror.head() })
}

/// Returns the prefix a cross-board address is resolved by.
///
/// It is the address's node field (T4b's `N`), whole: the prefix of the org
/// that holds the address (REG-1.62). A node field deeper than any standing
/// on the registry is resolved as it is, and answered by the walk
/// (REG-3.82).
fn prefix_of(address: &Address) -> Address {
    address_of(address.node_field().to_vec())
}

/// Returns a cross-board address in the local form of the board holding it.
///
/// It is the address with its node field swapped for `1`, which on a board
/// means this node (REG-1.61): `N.x` read as `1.x`, the swap a board's
/// ingress makes (REG-1.63). `None` for an address of no account field, a
/// bare prefix.
fn local_form(address: &Address) -> Option<Address> {
    address.account_field()?;
    let past_the_node = address.tumbler().iter().skip(address.node_field().len()).cloned();
    Some(address_of(std::iter::once(Nat::from(1u32)).chain(past_the_node).collect()))
}

/// Returns the address `components` spell.
///
/// Its two callers hand it an address's own node field, and `1` before an
/// address's components past its node field: each is a sequence a valid
/// address's clauses carry over to — it opens on a nonzero component, ends
/// as the address does or on a node field's last, and holds the separators
/// the address holds past its node field, or none.
fn address_of(components: Vec<Nat>) -> Address {
    let tumbler = Tumbler::new(components).expect("a node field, and `1` before an address's tail, is nonempty");
    validate(tumbler).expect("a valid address's node field, and its tail behind `1`, is a valid address")
}

/// Makes a mirror's directory, takes its lock and makes the copy's files.
///
/// The directory and every missing directory above it are made `0700`. The
/// lock is `lock` under it, `0600`, taken exclusively and held until the
/// file answered is dropped. The copy's two files are made empty, `0600`,
/// where they are absent, so each mode is set as its file is born (SP-7):
/// the resolver opens them with no mode of its own, and reads an empty file
/// as no copy held.
///
/// # Errors
///
/// A halt's face naming the directory, where the directory, the lock or a
/// file cannot be made, or the lock cannot be taken.
fn hold(dir: &Path) -> Result<File, Halt> {
    let unmade = |what: &str, e: io::Error| {
        Halt::face_at(
            dir,
            format!("the registry mirror's {what} could not be made"),
            e.to_string(),
            "check that the directory beside the key store can be written, and that nothing but a directory stands at its name",
        )
    };
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir).map_err(|e| unmade("directory", e))?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(dir.join(MIRROR_LOCK)).map_err(|e| unmade("lock", e))?;
    lock.lock().map_err(|e| unmade("lock", e))?;
    for name in [FEED_COPY, FETCH_CACHE] {
        match file::write_once(&dir.join(name), b"", 0o600) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(unmade(name, e)),
        }
    }
    Ok(lock)
}

/// Returns the halt a mirror's refusal comes to, under `hint` at `dir`.
///
/// A root that did not answer and a read the board refused are the family's
/// members for them, as a root hint's read maps them ([`board_halt`]): the
/// first root's where none answered, the further roots named beside it
/// ([`further`]). Every other refusal is a state a person acts on: a face
/// naming the directory where it is about the copy held there — the copy
/// not read, the root not answering for it, the realm another's — and a
/// face naming the hint's roots where the board is unclaimed or its claim
/// names no genesis record. A class the resolver names later is a face
/// carrying its words.
fn mirror_halt(hint: &RootHint, dir: &Path, e: MirrorError) -> Halt {
    let roots = || hint.origins().iter().map(|origin| origin.as_str()).collect::<Vec<_>>().join(", ");
    match e {
        MirrorError::Unreachable { mut tried } if !tried.is_empty() => {
            let first = board_halt(tried.remove(0).1);
            further(first, tried)
        }
        MirrorError::Board(e) => board_halt(e),
        MirrorError::Refused(Refusal::RealmMismatch { expected, found }) => Halt::face_at(
            dir,
            "the registry the root hint names is of another realm than the hint's",
            format!(
                "the root's genesis fingerprint is {found}, and the hint's realm names {expected}: a realm is the fingerprint of the key set its registry's claimant enrolled at its genesis (REG-3.39), compared at the claim before a line of the copy is written (REG-3.42)"
            ),
            "check the root hint against the registry's own line, which `skep hint` prints for its board: a root of another lineage takes its own hint",
        ),
        MirrorError::Refused(refusal) => Halt::face_at(
            dir,
            "the registry's root does not answer for the copy held of it",
            format!(
                "{refusal}: a held copy is resumed only where every position it holds comes back the same from the root, read from genesis (REG-3.18), and a root that cannot answer for what it served is another lineage (REG-3.19), so the copy stands as it was and nothing is resolved from it"
            ),
            "where the hint was pointed at this root on purpose — a fork, a registry brought up from a backup — move the directory aside and run this again: the mirror is then read afresh from that root's genesis (REG-3.17); otherwise correct the hint",
        ),
        MirrorError::NoClaim => Halt::face(
            format!("the board the root hint names ({}) is unclaimed: it is no registry", roots()),
            "a registry's bindings are its claimant's (REG-2.8), and this board's change feed ends with no claim",
            "check the root hint: its roots name a claimed registry board",
        ),
        MirrorError::NoGenesis => Halt::face(
            format!("the claim of the board the root hint names ({}) names no genesis record: its realm cannot be compared", roots()),
            "no enroll record naming the claimant stands on the feed before its claim, or the one that stands could not be read whole; the realm is that record's key set (REG-3.39), and a mirror compares it before it resolves anything (REG-3.42)",
            "check that the root hint names a skep registry; a claimed board whose claimant's genesis record cannot be read is a board fault",
        ),
        MirrorError::Copy(words) => Halt::face_at(
            dir,
            "the registry mirror's copy could not be read or written",
            within(dir, &words),
            "check the directory's permissions and its room; a copy that does not read is moved aside by hand, and the next run reads the registry afresh from its genesis",
        ),
        other => Halt::face("the registry was not read", other.to_string(), "run it again; where it stops here again, report it with these words"),
    }
}

/// Names the hint's further roots beside the first root's halt.
///
/// A mirror opens at the first root that answers, so where none does each
/// was tried, in the hint's order. The halt is the first's, its exit code
/// with it, and its words gain the rest, each origin beside its own error.
/// A member that carries no words of its own — a transport this build does
/// not hold, an answer past the cap — stands as it is.
fn further(first: Halt, rest: Vec<(skep_resolve::Origin, BoardError)>) -> Halt {
    if rest.is_empty() {
        return first;
    }
    let rest: Vec<String> = rest.iter().map(|(origin, e)| format!("{origin}: {e}")).collect();
    let also = format!("the hint's further roots did not answer either — {}", rest.join(", "));
    let beside = |words: String| format!("{words}; {also}");
    match first {
        Halt::Dial(DialError::Resolve(words)) => Halt::Dial(DialError::Resolve(beside(words))),
        Halt::Dial(DialError::Connect(words)) => Halt::Dial(DialError::Connect(beside(words))),
        Halt::Dial(DialError::Io(words)) => Halt::Dial(DialError::Io(beside(words))),
        Halt::Dial(DialError::Response(words)) => Halt::Dial(DialError::Response(beside(words))),
        Halt::Refused(refused) => {
            let detail = match &refused.detail {
                Some(detail) => beside(detail.clone()),
                None => also.clone(),
            };
            Halt::Refused(Refused { detail: Some(detail), ..refused })
        }
        wordless => wordless,
    }
}

/// Returns a copy failure's words with the mirror's directory cut from them.
///
/// The resolver names a file of the copy by its whole path; a face names
/// the directory beside its words and never in them (`Halt::face_at`), so
/// the file is said as it stands within the directory (SP-13).
fn within(dir: &Path, words: &str) -> String {
    let dir = dir.display().to_string();
    if dir.is_empty() {
        return words.to_string();
    }
    words.replace(&format!("{dir}{}", std::path::MAIN_SEPARATOR), "").replace(&dir, "the directory")
}

/// Returns a face as one JSON object: its name, and the facts it carries.
///
/// [`Resolved::object`] states the form. The match names every face and has
/// no wildcard arm, so a face the resolver gains is given its members here
/// before the crate builds.
fn face_object(resolution: &Resolution) -> Value {
    let mut object = match resolution {
        Resolution::Unregistered { prefix } => json!({ "prefix": text(prefix) }),
        Resolution::RetiredWithHistory { standing, successor } => {
            let mut object = standing_object(standing);
            object["successor"] = match successor {
                Some(successor) => json!({ "account": text(&successor.account), "prefix": optional(successor.prefix.as_ref()) }),
                None => Value::Null,
            };
            object
        }
        Resolution::BoundButUnreachable { standing, keys, endpoint, cause, members } => {
            let mut object = bound_object(standing, keys.as_deref(), endpoint.as_ref(), members);
            match cause {
                Unreachable::NoEndpointYet => object["cause"] = json!("no_endpoint_yet"),
                Unreachable::NullifiedLast => object["cause"] = json!("nullified_last"),
                Unreachable::DeadOrigin { member } => {
                    object["cause"] = json!("dead_origin");
                    object["member"] = json!(member);
                }
            }
            object
        }
        Resolution::UnreachableByPolicy { standing, keys, endpoint, member, term, members } => {
            let mut object = bound_object(standing, keys.as_deref(), Some(endpoint), members);
            object["member"] = json!(member);
            term_into(&mut object, term);
            object
        }
        Resolution::DialNotMade { standing, keys, endpoint, member, kind, members } => {
            let mut object = bound_object(standing, keys.as_deref(), Some(endpoint), members);
            object["member"] = json!(member);
            object["kind"] = json!(kind.name());
            object
        }
        Resolution::HopNotMade { prefix, parent } => json!({ "prefix": text(prefix), "parent": face_object(parent) }),
        Resolution::Bound { standing, keys, endpoint, dial, members } => {
            let mut object = bound_object(standing, keys.as_deref(), Some(endpoint), members);
            object["dial"] = json!({
                "origin": dial.origin.as_str(),
                "member": dial.member_index,
                "kind": dial.kind.name(),
                "addresses": dial.addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
            });
            object
        }
        Resolution::BoundButDisclaimed { standing, asserted_prefix } => {
            let mut object = standing_object(standing);
            object["asserted_prefix"] = json!(asserted_prefix);
            object
        }
        Resolution::LiveEnforcement { standing, claimant, local_trust } => {
            let mut object = standing_object(standing);
            object["claimant"] = optional(claimant.as_ref());
            object["local_trust"] = json!(local_trust);
            object
        }
    };
    object["face"] = json!(resolution.face());
    object
}

/// Returns a standing's members: the prefix, the account, the bindings.
fn standing_object(standing: &Standing) -> Value {
    json!({
        "prefix": text(&standing.prefix),
        "account": optional(standing.current.record.account.as_ref()),
        "binding": binding_object(&standing.current),
        "history": standing.history.iter().map(binding_object).collect::<Vec<_>>(),
    })
}

/// Returns a bound account's members beside its standing's.
///
/// They are the key set, `null` where the reader could not read it and
/// never an empty list in its place; the current endpoint, or `null`; and
/// each member's outcome, in the org's order.
fn bound_object(standing: &Standing, keys: Option<&[Enrolled]>, endpoint: Option<&Judged<EndpointRecord>>, members: &[MemberOutcome]) -> Value {
    let mut object = standing_object(standing);
    object["keys"] = match keys {
        Some(keys) => keys.iter().map(|enrolled| json!({ "fingerprint": Fingerprint::of(&enrolled.key).to_hex(), "anchor": enrolled.anchor })).collect(),
        None => Value::Null,
    };
    object["endpoint"] = match endpoint {
        Some(endpoint) => {
            let mut deposit = json!({
                "link": text(&endpoint.link),
                "position": endpoint.position,
                "home": text(&endpoint.home),
                "origins": endpoint.record.origins,
                "replaces": optional(endpoint.record.replaces.as_ref()),
            });
            verdict_into(&mut deposit, &endpoint.verdict);
            deposit
        }
        None => Value::Null,
    };
    object["members"] = members.iter().map(member_object).collect();
    object
}

/// Returns a binding as the index holds it, its verdict beside it.
fn binding_object(binding: &Judged<BindingRecord>) -> Value {
    let mut object = json!({
        "link": text(&binding.link),
        "position": binding.position,
        "home": text(&binding.home),
        "account": optional(binding.record.account.as_ref()),
        "replaces": optional(binding.record.replaces.as_ref()),
        "honored": binding.record.honored,
    });
    verdict_into(&mut object, &binding.verdict);
    object
}

/// Writes a record's verdict into its object (REG-1.86 (e)).
///
/// `verdict` is one of the signed-ops record §3.5's five values, as that
/// record spells them, and `signed_by` the signing key's fingerprint beside
/// SIGNED.
fn verdict_into(object: &mut Value, verdict: &Verdict) {
    object["verdict"] = json!(match verdict {
        Verdict::BeforeAttestation => "BEFORE-ATTESTATION",
        Verdict::Signed(_) => "SIGNED",
        Verdict::Unsigned => "UNSIGNED",
        Verdict::Disavowed => "DISAVOWED",
        Verdict::UndeterminableHere => "UNDETERMINABLE HERE",
    });
    if let Verdict::Signed(key) = verdict {
        object["signed_by"] = json!(key.to_hex());
    }
}

/// Returns one endpoint member's outcome at this resolver (REG-3.34).
fn member_object(member: &MemberOutcome) -> Value {
    let addresses = |addresses: &[std::net::IpAddr]| addresses.iter().map(ToString::to_string).collect::<Vec<_>>();
    match member {
        MemberOutcome::WouldDial { origin, kind, addresses: passed } => {
            json!({ "member": origin.as_str(), "outcome": "would_dial", "kind": kind.name(), "addresses": addresses(passed) })
        }
        MemberOutcome::Refused { member, term } => {
            let mut object = json!({ "member": member, "outcome": "refused" });
            term_into(&mut object, term);
            object
        }
        MemberOutcome::NotDialed { origin, kind } => json!({ "member": origin.as_str(), "outcome": "not_dialed", "kind": kind.name() }),
        MemberOutcome::Dead { origin } => json!({ "member": origin.as_str(), "outcome": "dead" }),
    }
}

/// Writes the term that refused a member into its object (REG-3.80).
///
/// `term` is `scheme` or `host`; on the host term `yielded` is the address
/// tested — the literal, or every address this resolver's own resolution of
/// the name yielded, this resolver's yield and never the record's.
fn term_into(object: &mut Value, term: &Term) {
    match term {
        Term::Scheme => object["term"] = json!("scheme"),
        Term::Host { yielded } => {
            object["term"] = json!("host");
            object["yielded"] = yielded.iter().map(ToString::to_string).collect();
        }
    }
}

/// Returns an address as its dotted text.
fn text(address: &Address) -> Value {
    Value::String(address.to_string())
}

/// Returns an address as its dotted text, `null` where there is none.
fn optional(address: Option<&Address>) -> Value {
    address.map_or(Value::Null, text)
}

#[cfg(test)]
mod tests;
