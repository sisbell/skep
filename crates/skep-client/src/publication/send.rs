//! THE SEND AND THE FACES (the link-sets design §5.7; wire.md §The publish
//! shot and head-float, the refusal table).
//!
//! The frame goes through `Board::op` under the session's token with the
//! request's `id`; its `attest` is the entry frame over the body the one
//! body builder composed from the request AS BUILT — never a body the
//! lists do not match — under `H.1`'s pair. A publication is NEVER SENT
//! UNSIGNED on a claimed board: a board whose head record cannot be read
//! and whose `/health` names a claimant answers [`Refusal::HeadUnreadable`],
//! the halt's data, never the warn arm (the owner's ruling (3)); a board no
//! one has claimed takes the frame without an `attest`.
//!
//! THE `id` POLICY: the same `id` on the same session for a lost answer —
//! one re-ask after a transport fault, which a pending frame answers when
//! its turn comes and a committed write answers from its memo; a refusal
//! is not memoized, so a request re-composed or re-signed takes a FRESH
//! `id`; after `500 internal_panic`, a dead session or a second transport
//! fault the board is READ FIRST — the landed test — before any re-send,
//! never the memo alone.
//!
//! THE REFUSAL FAMILY, each a typed arm with its `site`: `already_published`
//! → the landed test on the member it names — pass, the acknowledgment (the
//! twin read as the ack); fail, the twin face's data; `kept_place_moved` →
//! the entry and the race's KEY, the feed's newest row under the draft since
//! the request's reads and its `key`, for the caller's re-read and
//! re-statement; `stray_place_unrecorded` → this library's own bug;
//! `publication_over_budget` → the price's verdict re-run: a race where this
//! price admitted the request, the library's own bug where it did not;
//! `not_owner` naming the draft → the unowned draft, named; `not_owner` on
//! `doc` or the account → named too; `claim_refused` → the edition named
//! already holds a member, so the claim is a first version's no longer (skep
//! #692) — the caller sends the shot without it; the six deposit tokens → own-bug arms
//! with their entry and detail; `attestation_invalid:signature` → ONE
//! re-sign with the skipped deposits dropped — presence re-read for every
//! `retract` and `read_with` entry — under a fresh `id`; `unparseable` on a
//! request carrying an optional member → the older-board arm; the shot's own
//! table's codes → the library's own fault; `withheld`,
//! `signed_session_required`, `doc_not_registered` as the merge names them;
//! everything else the board's refusal verbatim.

use serde_json::Value;
use skep_address::Address;
use skep_identity::{entry_frame, DocTerm};

use crate::address::parse_address;
use crate::board::frames;
use crate::board::{acked_addr, acked_at, Answer, ChangesAnswer, ChangesQuery, Rejection, T_RETRACTION};
use crate::halt::Halt;
use crate::sign::sig_hex;

use super::landed::{landed_with, Base, Missing, Verdict};
use super::panel::read_with_stands;
use super::request::Request;
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
}

/// The race's key at `kept_place_moved`: the feed's newest row under the
/// draft since the request's reads, and whose it was.
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
    /// `stray_place_unrecorded` at the `runs` entry.
    StrayPlace {
        /// The entry.
        index: u64,
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
    /// The shot's own table refused the frame's substance.
    Shot {
        /// The code.
        code: String,
    },
    /// The signature refused twice, or with no skipped deposit to drop.
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
    /// `kept_place_moved`: the draft moved the entry's words since the
    /// place was read — the caller re-reads and re-states.
    KeptPlaceMoved {
        /// The `runs` entry.
        index: u64,
        /// Whose write moved them, where the feed tells.
        race: Option<RaceKey>,
    },
    /// `not_owner` naming the draft: a publication keeps its records in the
    /// draft it was staged in.
    UnownedDraft {
        /// The draft.
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
    /// The board is claimed and its head record cannot be read: never sent
    /// unsigned.
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

/// The shot's own table's codes, each the library's own fault.
const SHOT_CODES: [&str; 9] = ["base_superseded", "base_not_in_chain", "base_extent_too_large", "bad_run", "dangling_source", "source_not_registered", "too_many_runs", "too_many_values", "private_source_versionless"];

/// The six deposit tokens.
const DEPOSIT_CODES: [&str; 6] = ["link_home_refused", "old_refused", "duplicate_original", "read_with_in_links", "retract_refused", "read_with_refused"];

/// Sends the request, once, with its arms.
///
/// `request` is re-composed in place at the one re-sign, under a fresh
/// `id`.
///
/// # Errors
///
/// The reads' faults, the `H.1` and `/health` reads' halts, and a transport
/// fault the landed test could not read past.
pub fn send(p: &Publisher<'_>, inputs: &Inputs, request: &mut Request) -> Result<Sent, Fault> {
    let door = Door::new(p.board, p.token);
    send_with(&door, p, inputs, request)
}

/// Sends through `door`.
pub(crate) fn send_with(door: &Door<'_>, p: &Publisher<'_>, inputs: &Inputs, request: &mut Request) -> Result<Sent, Fault> {
    door.step("send");
    let term = p.board.board_term()?;
    if term.is_none() && p.board.health()?.claimant().is_some() {
        return Ok(Sent::Refused(Refusal::HeadUnreadable));
    }
    let account = parse_address(p.account).ok_or_else(|| Fault::Halt(Halt::face("the account cannot be spelled", p.account.to_string(), "this is a fault in this library; nothing was written")))?;
    let attest = |request: &Request| -> Option<Value> {
        let term = term?;
        let alg = p.signer.public_key().alg();
        let bytes = entry_frame(alg, term, &account, DocTerm::One(request.term()), &request.body());
        Some(serde_json::json!({"alg": alg, "sig": sig_hex(&p.signer.sign(&bytes))}))
    };
    let mut resigned = false;
    loop {
        let frame = request.frame(attest(request));
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
            return Ok(Sent::Acknowledged(Ack { member, at, edition, via: AckVia::Answer, claim: request.claim }));
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
            "kept_place_moved" => Refusal::KeptPlaceMoved { index: site.index.unwrap_or(0), race: race_key(p, inputs, request.as_of)? },
            "stray_place_unrecorded" => Refusal::OwnFault(OwnFault::StrayPlace { index: site.index.unwrap_or(0) }),
            "publication_over_budget" => {
                if request.price.admits() {
                    Refusal::BudgetRace { detail }
                } else {
                    Refusal::OwnFault(OwnFault::Budget { detail })
                }
            }
            "not_owner" => {
                let addr = site.addr.as_deref().and_then(parse_address);
                match (&addr, &request.draft) {
                    (Some(a), Some(draft)) if a == draft => Refusal::UnownedDraft { draft: draft.clone() },
                    _ => Refusal::NotOwner { addr },
                }
            }
            "claim_refused" => Refusal::ClaimRefused { edition: site.addr.as_deref().and_then(parse_address) },
            "attestation_invalid:signature" if !resigned => {
                let (retract_skipped, read_with_skipped) = skipped(door, p, request)?;
                if retract_skipped.is_empty() && read_with_skipped.is_empty() {
                    Refusal::OwnFault(OwnFault::Attest { detail })
                } else {
                    request.without(&retract_skipped, &read_with_skipped);
                    resigned = true;
                    continue;
                }
            }
            "attestation_invalid:signature" => Refusal::OwnFault(OwnFault::Attest { detail }),
            "malformed" if r.op() == Some("unparseable") && carries_members(request) => Refusal::OlderBoard { detail },
            "withheld" => Refusal::WindowWithheld { origin: site.addr.as_deref().and_then(parse_address) },
            "signed_session_required" => Refusal::NeedsSignedSession,
            "doc_not_registered" => Refusal::NoSuchDocument,
            code if DEPOSIT_CODES.contains(&code) => Refusal::OwnFault(OwnFault::Deposit { code: code.to_string(), index: site.index, detail }),
            code if SHOT_CODES.contains(&code) || code == "malformed" => Refusal::OwnFault(OwnFault::Shot { code: code.to_string() }),
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
    !request.entries.is_empty() || !request.retract.is_empty() || !request.read_with.is_empty() || request.places.iter().any(Option::is_some) || request.mint.is_some() || request.claim
}

/// A lost answer: the board read first, through the landed test from the
/// base the request's shape names.
fn lost(door: &Door<'_>, p: &Publisher<'_>, inputs: &Inputs, request: &Request) -> Result<Sent, Fault> {
    let base = if request.runs.iter().any(|r| Some(&r.origin) == request.draft.as_ref()) {
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

/// Re-reads presence for every `retract` and `read_with` entry: the indices
/// the board's plan would skip.
fn skipped(door: &Door<'_>, p: &Publisher<'_>, request: &Request) -> Result<(Vec<usize>, Vec<usize>), Fault> {
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
    Ok((retract, read_with))
}

/// Reads the race's key: the newest row under the draft since `since` on the
/// drafts page, under the token.
fn race_key(p: &Publisher<'_>, inputs: &Inputs, since: u64) -> Result<Option<RaceKey>, Fault> {
    let draft = inputs.draft.to_string();
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
