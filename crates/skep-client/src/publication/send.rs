//! The send of a built publication, and the faces of its answer.
//!
//! It is the link-sets design §5.7 and wire.md §The publish shot and
//! head-float, with the refusal table. The frame goes through `Board::op`
//! under the session's token with the request's `id`; its `attest` is the
//! entry frame over the body the one body builder composed from the request
//! as built — never a body the lists do not match — under `H.1`'s pair.
//!
//! **Never unsigned where a signature is owed.** A board whose head record
//! stands and cannot be read halts the send naming why, claimed or not
//! (`Board::board_head`; SP-14), and a claimed board serving no head record
//! answers [`Refusal::HeadUnreadable`], the halt's data, never a warning: no
//! frame leaves either. A board no one has claimed, serving no head record,
//! alone takes the frame without an `attest`. The board's own
//! `attestation_invalid:board_unavailable` — its head owed past that read,
//! or a record its own build does not read (wire.md §Credential refusals) —
//! answers [`Refusal::HeadUnreadable`] too, never this library's fault: the
//! frame was refused, nothing was published, and a retry is admitted once
//! the board holds a head it reads. A frame sent unsigned to a board read
//! as no one's and refused `attestation_required` met a claim that landed
//! past that read, its head written: the board refused it before its
//! transaction (wire.md §Credential refusals, a reorder), so the head is
//! read again and the same request sent ONCE more, signed over that pair,
//! its answer a signed frame's; a second read that finds no head to sign
//! over answers [`Refusal::HeadUnreadable`], nothing sent.
//!
//! **The `id` policy.** The same `id` on the same session for a lost answer:
//! one re-ask after a transport fault, which a pending frame answers when its
//! turn comes and a committed write answers from its memo. A refusal is not
//! memoized, so a request re-composed or re-signed — the one re-sign, and
//! the one signed send after a claim — takes a fresh `id`. After
//! `500 internal_panic`, a dead session or a second transport fault the board
//! is read first — the landed test — before any re-send, never the memo
//! alone.
//!
//! **The refusal family**, each a typed arm with its `site`:
//! `already_published` → the landed test on the member it names — pass, the
//! acknowledgment (the twin read as the ack); fail, the twin face's data;
//! `kept_place_moved` → the entry, THE DRAFT that no longer honours the
//! place (`site.addr`: the rendering draft, or a draft `also` names — each
//! re-windowed in the one commit, skep #739 — and the rendering draft where
//! an older board names none) and the race's key, the feed's newest row
//! under THAT draft since the request's reads and its `key`, for the
//! caller's re-read and re-statement; `stray_place_unrecorded`, naming the
//! draft alike → this library's own bug; `publication_over_budget` → the price's verdict re-run: a race where
//! this price admitted the request, the library's own bug where it did not;
//! `not_owner` naming the draft → the unowned draft, named; `not_owner` on
//! `doc` or the account → named too; `claim_refused` → the edition named
//! already holds a member, so the claim is a first version's no longer
//! (skep #692) — the caller sends the shot without it; `supersede_refused`
//! → the entry and its cause typed, `head_moved` carrying the trunk's head
//! the board refused the whole publication against — the caller composes
//! again on it, nothing re-sent — never this library's fault (the merge
//! bridge lane); the six deposit tokens
//! → own-bug arms with their entry and detail; `attestation_invalid:signature`
//! → one re-sign with the skipped deposits dropped — presence re-read for
//! every `retract`, `read_with` and `supersede` entry — under a fresh `id`;
//! `attestation_required` at a frame sent unsigned → the one signed send
//! above, under a fresh `id`;
//! `attestation_invalid:board_unavailable` → the board's own state, the head
//! arm above; every other `attestation_*` token, `attestation_required` at a
//! signed frame among them → the library's own fault;
//! `unparseable` on a request carrying an optional member → the older-board
//! arm; `base_superseded` → the board's refusal of a request naming NO base
//! while `doc` holds a member — a shape this library never sends at the
//! document form, where the request's base is the one `draft_base` read (a
//! draft begun from the bare document lands as the first member's daughter,
//! told as its standing), so the arm stands for a raw caller of this
//! library, naming the trunk's first member; the shot's own table's other
//! codes → the library's own fault; `withheld`, `signed_session_required`,
//! `doc_not_registered` as the merge names them; everything else the board's
//! refusal verbatim.

use serde_json::Value;
use skep_address::Address;
use skep_identity::{entry_frame, BoardTerm, DocTerm};

use crate::address::parse_address;
use crate::board::frames;
use crate::board::{acked_addr, acked_at, Answer, BoardHead, ChangesAnswer, ChangesQuery, Rejection, Site, T_RETRACTION};
use crate::halt::Halt;
use crate::sign::sig_hex;

use super::landed::{landed_with, Base, Missing, Verdict};
use super::panel::read_with_stands;
use super::request::{claimed_by_own, AlsoPlaces, Request};
use super::{trunk_of, Door, Fault, Inputs, Publisher};

/// How the acknowledgment was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckVia {
    /// The board's answer to the frame.
    Answer,
    /// `already_published` read as the acknowledgment: the landed test
    /// passed at the member the refusal named.
    Twin,
    /// A lost answer: the draft's records named the member.
    Records,
    /// A lost answer: the walk from the base found the member.
    Walk,
    /// A lost answer at the mint form: the edition claim named the edition.
    EditionClaim,
}

/// The acknowledgment: the member, its position, the edition where the
/// request minted one, and whether the claim rode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    /// The member minted — `E.1` of the edition at the mint form.
    pub member: Address,
    /// The commit's position.
    pub at: u64,
    /// The edition minted, at the mint form.
    pub edition: Option<Address>,
    /// How it was reached.
    pub via: AckVia,
    /// Whether the edition claim rode in the write — the request's own
    /// `claim`, echoed (skep #692).
    pub claim: bool,
    /// The daughters the write claimed superseded — the request's
    /// `supersede` as sent, each one claim in the commit, `in_claims` at the
    /// daughter answering the member (the merge bridge lane). A daughter an
    /// active claim of the person's own already named was dropped before
    /// the send and is not among them.
    pub supersede: Vec<Address>,
}

/// Why the board refused a `supersede` entry — its `detail` (wire.md
/// §Rejection codes, `supersede_refused`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupersedeCause {
    /// `head_moved`: a member stands and the request's base is not the
    /// trunk's head, so the shot would mint the base's daughter — the whole
    /// list refused ahead of every entry's own check, nothing committed
    /// (the plan's (6)). The caller composes again on the head.
    HeadMoved {
        /// The trunk's head, `site.addr`, the head to compose again on.
        head: Option<Address>,
    },
    /// `not_member`: the daughter is no registered version member of `doc`'s
    /// own chain — the trunk itself, a document or member outside the chain,
    /// an element address, a member not yet minted, or any entry at the mint
    /// form.
    NotMember,
    /// `base`: the daughter is the member the shot appends to.
    Base,
    /// `duplicate`: a second entry naming one daughter, at the second.
    Duplicate,
}

impl SupersedeCause {
    /// Returns the cause a `supersede_refused` rejection's `detail` names,
    /// `head_moved` carrying the head `site.addr` names; `None` for a detail
    /// this client does not know.
    pub(crate) fn of(detail: Option<&str>, site: &Site) -> Option<SupersedeCause> {
        Some(match detail? {
            "head_moved" => SupersedeCause::HeadMoved { head: site.addr.as_deref().and_then(parse_address) },
            "not_member" => SupersedeCause::NotMember,
            "base" => SupersedeCause::Base,
            "duplicate" => SupersedeCause::Duplicate,
            _ => return None,
        })
    }

    /// Returns the cause's `detail` token as the wire spells it.
    pub fn token(&self) -> &'static str {
        match self {
            SupersedeCause::HeadMoved { .. } => "head_moved",
            SupersedeCause::NotMember => "not_member",
            SupersedeCause::Base => "base",
            SupersedeCause::Duplicate => "duplicate",
        }
    }
}

/// The race's key at `kept_place_moved`: the feed's newest row under the
/// draft the refusal names — the rendering draft, or a draft `also` names —
/// since the request's reads, and whose it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaceKey {
    /// The row's position.
    pub at: u64,
    /// The row's `key` — a fingerprint, `bare`, `system`; `None` where lost
    /// or where the row is a signed entry.
    pub key: Option<String>,
    /// Whether the row carries its own `attest`.
    pub signed: bool,
}

/// This library's own faults (A-288's own-bug class): nothing a person can
/// act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnFault {
    /// `stray_place_unrecorded` at the `runs` entry, in the draft named.
    StrayPlace {
        /// The entry.
        index: u64,
        /// The draft being re-windowed at the place — the rendering draft,
        /// or one `also` names (`site.addr`; the rendering draft where an
        /// older board names none).
        draft: Address,
    },
    /// One of the six deposit tokens at an entry.
    Deposit {
        /// The code.
        code: String,
        /// The entry in its own list.
        index: Option<u64>,
        /// The cause, where the code carries one.
        detail: Option<String>,
    },
    /// The shot's own table refused the frame's substance — `base_superseded`
    /// aside, [`Refusal::BaseSuperseded`].
    Shot {
        /// The code.
        code: String,
    },
    /// The frame's attest refused: the signature twice, or with no skipped
    /// deposit to drop, or any other `attestation_*` token but two —
    /// `board_unavailable`, the board's own state
    /// ([`Refusal::HeadUnreadable`]), and `attestation_required` at a frame
    /// sent unsigned, which is sent once more, signed.
    Attest {
        /// The detail.
        detail: Option<String>,
    },
    /// `publication_over_budget` where this price refused the request too.
    Budget {
        /// The daemon's detail.
        detail: Option<String>,
    },
}

/// The refusals the send answers, each with what its face needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `already_published` at a member that fails the landed test: another's
    /// commit — the twin face.
    Twin {
        /// The member the words are published in.
        member: Address,
        /// What the member lacks of this request, where it holds the runs.
        missing: Option<Missing>,
    },
    /// `kept_place_moved`: a draft the commit re-windows moved the entry's
    /// words since its place was read — the caller re-reads and re-states.
    KeptPlaceMoved {
        /// The `runs` entry.
        index: u64,
        /// The draft that no longer honours the place — the rendering
        /// draft, or one `also` names, each re-windowed in the one commit
        /// (`site.addr`; the rendering draft where an older board names
        /// none).
        draft: Address,
        /// Whose write moved them, where the feed tells: the newest row
        /// under `draft` since the request's reads.
        race: Option<RaceKey>,
    },
    /// `not_owner` naming a draft the request names — the rendering draft,
    /// or one `also` names: a publication keeps its records in the drafts
    /// whose words it re-mints, each of which must be the person's own.
    UnownedDraft {
        /// The draft at fault.
        draft: Address,
    },
    /// `not_owner` naming `doc` or the account.
    NotOwner {
        /// The address named.
        addr: Option<Address>,
    },
    /// `claim_refused`: the edition `doc` names already holds a member, so
    /// the edition claim — a first version's alone — is refused; the caller
    /// sends the shot without it. The board judges the edition's members,
    /// never this library.
    ClaimRefused {
        /// The edition, `site.addr`.
        edition: Option<Address>,
    },
    /// `supersede_refused`: the board refused a `supersede` entry, the whole
    /// publication with it and nothing committed — the plan's judgement of
    /// the daughters, never this library's frame (the merge bridge lane). At
    /// `head_moved` the trunk's head moved under the request, so the shot
    /// would have landed as a daughter: the arm crosses as the board answered
    /// it, nothing re-sent, and the caller composes the publication again on
    /// the head the cause names.
    SupersedeRefused {
        /// The entry in `supersede`, `site.index` — 0 at `head_moved`, the
        /// list refused whole.
        index: u64,
        /// The cause, `detail`.
        cause: SupersedeCause,
    },
    /// `withheld`: a window's origin is not readable to the session.
    WindowWithheld {
        /// The origin's document.
        origin: Option<Address>,
    },
    /// `signed_session_required`: the session is bare.
    NeedsSignedSession,
    /// `doc_not_registered`.
    NoSuchDocument,
    /// `unparseable` on a request carrying an optional member: the board may
    /// run an older skep than this client; nothing was published.
    OlderBoard {
        /// The board's detail.
        detail: Option<String>,
    },
    /// The board holds no head record it signs against: never sent unsigned,
    /// and nothing published.
    ///
    /// It answers a claimed board serving no head record, no frame sent; the
    /// board's own refusal of the frame,
    /// `attestation_invalid:board_unavailable` — its head owed past this
    /// library's read, or a record its own build does not read (SP-14); and
    /// a frame sent unsigned and refused `attestation_required` where the
    /// head read again serves no record to sign over, nothing sent after it.
    /// A record that stands and this library cannot read is the read's halt
    /// ([`Fault::Halt`]), never sent either.
    HeadUnreadable,
    /// The death signal: the session ended before or at the write. The
    /// caller opens a session and runs the landed test before any re-send.
    SessionEnded,
    /// `publication_over_budget` where this price admitted the request: a
    /// race with the board's state.
    BudgetRace {
        /// The daemon's detail.
        detail: Option<String>,
    },
    /// A minting records-less request whose answer was lost and whose
    /// edition claim no read finds: the publication may already stand.
    MayAlreadyStand,
    /// `base_superseded`: the request named no base and the board holds
    /// `doc`'s first member — the birth shape once the chain has opened;
    /// nothing was published. A request this library builds at the document
    /// form always names its base, the one read off the board, and a draft
    /// begun from the bare document lands as the first member's daughter
    /// ([`super::Standing::SupersededFirst`]), so the arm is reached by a raw
    /// caller of this library alone.
    BaseSuperseded {
        /// The first member of the request's `doc`, `⟨doc⟩.1`.
        first: Address,
    },
    /// This library's own fault.
    OwnFault(OwnFault),
    /// The board's refusal, verbatim.
    Other(Halt),
}

/// What the send answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sent {
    /// The publication committed.
    Acknowledged(Ack),
    /// The board refused, or the composition did.
    Refused(Refusal),
    /// The answer was lost and the board says nothing committed: the caller
    /// re-sends the same request.
    NotLanded,
}

/// The shot's own table's codes, each the library's own fault —
/// `base_superseded` aside, its own arm ([`Refusal::BaseSuperseded`]).
const SHOT_CODES: [&str; 8] = ["base_not_in_chain", "base_extent_too_large", "bad_run", "dangling_source", "source_not_registered", "too_many_runs", "too_many_values", "private_source_versionless"];

/// The six deposit tokens.
const DEPOSIT_CODES: [&str; 6] = ["link_home_refused", "old_refused", "duplicate_original", "read_with_in_links", "retract_refused", "read_with_refused"];

/// Sends the request, once, with its arms.
///
/// `request` is re-composed in place at the one re-sign, and takes a fresh
/// `id` there and at the one signed send after a claim (the module's doc).
///
/// # Errors
///
/// The reads' faults; the `H.1` and `/health` reads' halts — the read
/// before the frame and the one after a claim — a head record that stands
/// and cannot be read among them, which sends nothing (SP-14); and a
/// transport fault the landed test could not read past.
pub fn send(p: &Publisher<'_>, inputs: &Inputs, request: &mut Request) -> Result<Sent, Fault> {
    let door = Door::new(p.board, p.token);
    send_with(&door, p, inputs, request)
}

/// Sends through `door`.
pub(crate) fn send_with(door: &Door<'_>, p: &Publisher<'_>, inputs: &Inputs, request: &mut Request) -> Result<Sent, Fault> {
    door.step("send");
    // The pair the frame signs over: none on a board read as no one's, until
    // the head is read again after the board answers `attestation_required`.
    let mut term = match p.board.board_head()? {
        BoardHead::Term(term) => Some(term),
        BoardHead::Unclaimed => None,
        BoardHead::Owed { .. } => return Ok(Sent::Refused(Refusal::HeadUnreadable)),
    };
    let account = parse_address(p.account).ok_or_else(|| Fault::Halt(Halt::face("the account cannot be spelled", p.account.to_string(), "this is a fault in this library; nothing was written")))?;
    let attest = |request: &Request, term: Option<BoardTerm>| -> Option<Value> {
        let term = term?;
        let alg = p.signer.public_key().alg();
        let bytes = entry_frame(alg, term, &account, DocTerm::One(request.term()), &request.body());
        Some(serde_json::json!({"alg": alg, "sig": sig_hex(&p.signer.sign(&bytes))}))
    };
    let mut resigned = false;
    loop {
        let frame = request.frame(attest(request, term));
        let answer = match p.board.op(Some(p.token), &frame) {
            // One re-ask under the same id on the same session.
            Err(Halt::Dial(_)) => match p.board.op(Some(p.token), &frame) {
                Err(Halt::Dial(_)) => return lost(door, p, inputs, request),
                other => other,
            },
            other => other,
        };
        let v = match answer {
            Ok(Answer::Closed) => return Ok(Sent::Refused(Refusal::SessionEnded)),
            Ok(Answer::Document(v)) => v,
            Err(Halt::Refused(r)) if r.status == 500 => return lost(door, p, inputs, request),
            Err(h) => return Err(Fault::Halt(h)),
        };
        if let (Some(addr), Some(at)) = (acked_addr(&v), acked_at(&v)) {
            let member = parse_address(addr).ok_or_else(|| super::shape(&frame, &v))?;
            let edition = request.mint.as_ref().and_then(|_| trunk_of(addr)).and_then(|t| parse_address(&t));
            return Ok(Sent::Acknowledged(Ack { member, at, edition, via: AckVia::Answer, claim: request.claim, supersede: request.supersede.clone() }));
        }
        let Some(r) = Rejection::of(&v) else { return Err(super::shape(&frame, &v)) };
        let site = r.site().clone();
        let detail = r.detail().map(str::to_string);
        let refusal = match r.key() {
            "already_published" => {
                let Some(member) = site.addr.as_deref().and_then(parse_address) else { return Err(super::shape(&frame, &v)) };
                match landed_with(door, p, inputs, request, Base::Member(member.clone()))? {
                    Verdict::Passed(ack) => return Ok(Sent::Acknowledged(ack)),
                    Verdict::Anothers { member, missing } => Refusal::Twin { member, missing: Some(missing) },
                    Verdict::NotFound | Verdict::MayAlreadyStand => Refusal::Twin { member, missing: None },
                }
            }
            "kept_place_moved" => {
                let draft = named_draft(&site, inputs);
                let race = race_key(p, &draft, request.as_of)?;
                Refusal::KeptPlaceMoved { index: site.index.unwrap_or(0), draft, race }
            }
            "stray_place_unrecorded" => Refusal::OwnFault(OwnFault::StrayPlace { index: site.index.unwrap_or(0), draft: named_draft(&site, inputs) }),
            "publication_over_budget" => {
                if request.price.admits() {
                    Refusal::BudgetRace { detail }
                } else {
                    Refusal::OwnFault(OwnFault::Budget { detail })
                }
            }
            "not_owner" => {
                let addr = site.addr.as_deref().and_then(parse_address);
                match &addr {
                    Some(a) if request.draft.as_ref() == Some(a) || request.also.contains(a) => Refusal::UnownedDraft { draft: a.clone() },
                    _ => Refusal::NotOwner { addr },
                }
            }
            "claim_refused" => Refusal::ClaimRefused { edition: site.addr.as_deref().and_then(parse_address) },
            // The plan's judgement of the daughters: the board's verdict with
            // its entry and cause, never this frame's fault; a detail this
            // client does not know is the board's refusal verbatim.
            "supersede_refused" => match SupersedeCause::of(detail.as_deref(), &site) {
                Some(cause) => Refusal::SupersedeRefused { index: site.index.unwrap_or(0), cause },
                None => Refusal::Other(r.refused(&v)),
            },
            "attestation_invalid:signature" if !resigned => {
                let (retract_skipped, read_with_skipped, supersede_skipped) = skipped(door, p, request)?;
                if retract_skipped.is_empty() && read_with_skipped.is_empty() && supersede_skipped.is_empty() {
                    Refusal::OwnFault(OwnFault::Attest { detail })
                } else {
                    request.without(&retract_skipped, &read_with_skipped, &supersede_skipped);
                    resigned = true;
                    continue;
                }
            }
            "attestation_invalid:signature" => Refusal::OwnFault(OwnFault::Attest { detail }),
            // A claim landed between the head's read and this frame's turn:
            // the frame went unsigned, and the board refused it before its
            // transaction (a reorder). The head is read again and the request
            // sent once more, signed, under a fresh `id`; the pair read is
            // what makes it once — a signed frame refused so is the arm
            // below, the library's own fault.
            "attestation_required" if term.is_none() => match p.board.board_head()? {
                BoardHead::Term(read) => {
                    term = Some(read);
                    request.id = super::fresh_id();
                    continue;
                }
                BoardHead::Unclaimed | BoardHead::Owed { .. } => Refusal::HeadUnreadable,
            },
            "malformed" if r.op() == Some("unparseable") && carries_members(request) => Refusal::OlderBoard { detail },
            "withheld" => Refusal::WindowWithheld { origin: site.addr.as_deref().and_then(parse_address) },
            "signed_session_required" => Refusal::NeedsSignedSession,
            "doc_not_registered" => Refusal::NoSuchDocument,
            "base_superseded" => match request.doc.as_ref().and_then(|doc| parse_address(&format!("{doc}.1"))) {
                Some(first) => Refusal::BaseSuperseded { first },
                None => Refusal::Other(r.refused(&v)),
            },
            code if DEPOSIT_CODES.contains(&code) => Refusal::OwnFault(OwnFault::Deposit { code: code.to_string(), index: site.index, detail }),
            code if SHOT_CODES.contains(&code) || code == "malformed" => Refusal::OwnFault(OwnFault::Shot { code: code.to_string() }),
            // The board's state, never this library's frame (a reorder): its
            // head owed past the read, or a record its build does not read.
            "attestation_invalid:board_unavailable" => Refusal::HeadUnreadable,
            k if k.starts_with("attestation_") => Refusal::OwnFault(OwnFault::Attest { detail }),
            _ => Refusal::Other(r.refused(&v)),
        };
        return Ok(Sent::Refused(refusal));
    }
}

/// Whether the request carries a member an older daemon would not parse —
/// a `claim` at the document form among them, which a board before skep
/// #692 refused `malformed`.
fn carries_members(request: &Request) -> bool {
    !request.entries.is_empty() || !request.retract.is_empty() || !request.read_with.is_empty() || !request.supersede.is_empty() || request.places.iter().any(Option::is_some) || request.also_places.iter().any(AlsoPlaces::carries_a_place) || request.mint.is_some() || request.claim
}

/// Returns the draft a re-window refusal names — `site.addr`, the draft
/// that no longer honours the place at the entry, the rendering draft or
/// one `also` names — and the rendering draft where the board names none
/// (an older board, before every named draft was re-windowed).
fn named_draft(site: &Site, inputs: &Inputs) -> Address {
    site.addr.as_deref().and_then(parse_address).unwrap_or_else(|| inputs.draft.clone())
}

/// A lost answer: the board read first, through the landed test from the
/// base the request's shape names — the records where any run is a named
/// draft's, the rendering draft's or an `also` draft's.
fn lost(door: &Door<'_>, p: &Publisher<'_>, inputs: &Inputs, request: &Request) -> Result<Sent, Fault> {
    let base = if request.runs.iter().any(|r| Some(&r.origin) == request.draft.as_ref() || request.also.contains(&r.origin)) {
        Base::Records
    } else if request.mint.is_some() {
        Base::EditionClaims
    } else {
        Base::Walk
    };
    Ok(match landed_with(door, p, inputs, request, base)? {
        Verdict::Passed(ack) => Sent::Acknowledged(ack),
        Verdict::Anothers { member, missing } => Sent::Refused(Refusal::Twin { member, missing: Some(missing) }),
        Verdict::NotFound => Sent::NotLanded,
        Verdict::MayAlreadyStand => Sent::Refused(Refusal::MayAlreadyStand),
    })
}

/// Re-reads presence for every `retract`, `read_with` and `supersede`
/// entry: the indices the board's plan would skip.
fn skipped(door: &Door<'_>, p: &Publisher<'_>, request: &Request) -> Result<(Vec<usize>, Vec<usize>, Vec<usize>), Fault> {
    door.step("resign");
    let mut retract = Vec::new();
    for (i, mark) in request.retract.iter().enumerate() {
        let mark = mark.to_string();
        if !door.addrs(&mark, &frames::find_links_ftt(T_RETRACTION, &mark))?.is_empty() {
            retract.push(i);
        }
    }
    let mut read_with = Vec::new();
    if let Some(trunk) = &request.doc {
        let trunk = trunk.to_string();
        for (i, set) in request.read_with.iter().enumerate() {
            if read_with_stands(door, p, &trunk, &set.to_string())? {
                read_with.push(i);
            }
        }
    }
    let mut supersede = Vec::new();
    for (i, daughter) in request.supersede.iter().enumerate() {
        if claimed_by_own(door, p, daughter)? {
            supersede.push(i);
        }
    }
    Ok((retract, read_with, supersede))
}

/// Reads the race's key: the newest row under `draft` — the draft the
/// refusal names, whose run moved — since `since` on the drafts page, under
/// the token.
fn race_key(p: &Publisher<'_>, draft: &Address, since: u64) -> Result<Option<RaceKey>, Fault> {
    let draft = draft.to_string();
    let mut newest: Option<RaceKey> = None;
    let mut cursor = since;
    loop {
        let query = ChangesQuery { since: cursor, under: Some(&draft), drafts: true, limit: None };
        match p.board.changes(Some(p.token), &query)? {
            ChangesAnswer::Page(page) => {
                if let Some(row) = page.changes.last() {
                    newest = Some(RaceKey { at: row["at"].as_u64().unwrap_or(0), key: row["key"].as_str().map(str::to_string), signed: row.get("attest").is_some() });
                }
                if !page.more {
                    return Ok(newest);
                }
                cursor = page.last;
            }
            ChangesAnswer::HistoryReclaimed { floor } => {
                let next = floor.map_or(cursor + 1, |f| f.saturating_sub(1));
                if next <= cursor {
                    return Ok(newest);
                }
                cursor = next;
            }
            ChangesAnswer::TooLarge { .. } => return Ok(newest),
            ChangesAnswer::Closed => return Err(Fault::SessionEnded),
        }
    }
}
