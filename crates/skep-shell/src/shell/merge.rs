//! The merge rows of `client.md` §4b.1 — `merge.compose`, `merge.land`,
//! `merge.undo`, `merge.withdraw` — and the compositions they stand on,
//! each reached from [`Shell::call`] alone: THE MERGE BRIDGE LANE, the
//! bridge of B3-S11's THE MERGE SCENE over `skep_client::merge` (the merge
//! record, `_designs/CLIENT/2026-10-14-reconciling-versions-design.md`
//! §1.5 and §7, in the skep-ux-design repository).
//!
//! THE FAMILY runs the merge library for the page: the page composes no
//! write. Every write this family makes is the library's — the landing's
//! one `set_arrangement` into the draft (`stage` first at a fresh one), the
//! shot, the record, the undo's and the withdrawal's one write each —
//! signed by the session's hand as the publication family's are; and every
//! answer is DATA with a code or a kind, never a string a person reads (the
//! strings `ux/copy.md`'s and the UI lane's).
//!
//! **`merge.compose`** — `{doc, alternative, into?}`, or THE DRAFT SIDE,
//! `{doc, draft, into?}` — composes the merge of the trunk's head with a
//! daughter of the person's own, or with a draft of the family behind the
//! head, and LANDS it: M as the whole arrangement of `into` by the
//! library's one write, typed against the composition's read of the draft,
//! the draft's recorded base re-recorded to the head and the merge marked
//! beside it; a newer version published since compose is never refused,
//! the write landing on the head used and `head_moved` told (LAND AND
//! TELL); a draft changed since the compose's read refused
//! `arrangement_moved`, the board's verdict, nothing landed. `into` IS THE
//! PAGE's: the draft "continue in" lands at where it holds nothing
//! unpublished, a level draft of the family staged from the head where one
//! stands, else none — a FRESH draft staged from the head first, two
//! commits (R3) — decided before the act off the feed rows the page holds
//! and followed here, never decided afresh; read as UNTRUSTED input, its
//! `doc_metadata` read before anything is composed and a published draft
//! or another account's refused `not_owner` (skep #799). The head is THE
//! TRUNK's HEAD as the board stands, found by probing up the trunk from the
//! member the side lies under — a daughter's parent, a draft side's
//! recorded base — one `doc_metadata` per member until `doc_not_registered`,
//! which needs no feed walk and meets no retention floor. THE RE-OPEN: where
//! the marker on `into` names this daughter — or, at the draft side, this
//! draft — the draft already carries this merge: the report with NOTHING
//! LANDED, composed on the marker's head, the side read as compose read it
//! — a daughter being immutable, and a draft side at the marker's position
//! where a write under it landed since (by `/op-at`), else its image as it
//! stands, which is the same — and each unsettled gap's state read off the
//! draft as it stands, settled by the person where the draft no longer
//! arranges the gap's default as M placed it: its runs removed whole, or
//! reordered; an edit inside a run's words settles nothing. THE MERGED ARM:
//! a daughter an active supersession claim of the person's own already
//! names, read by one `in_claims` at the daughter, is answered `merged`,
//! naming the member the claim's `new` names, NOTHING LANDED, and where no
//! record of the person's names that merge, the record is written then
//! through the library's `record_published` — the resume of a stop between
//! the shot and its record (P14). A standing record of the key naming a
//! draft landing is read before a fresh draft is asked for: the draft's
//! marker naming this merge is the re-open; else the landing goes into
//! that draft, the library's same-landing rule (skep #790), and the library
//! is never handed `into` none while such a record stands (the survey §5
//! item 2).
//!
//! **`merge.land`** — `{resolutions?}` — publishes the merge from the draft
//! the standing composition landed in, THE SHOT CARRYING THE SUPERSESSION
//! CLAIM, then the record: ONE PATH for the shot, the publication family's
//! — the panel standing for the draft, which the page opened over it with
//! the switches and answers it last sent, or one this row opens over the
//! whole draft (every private row OFF, every window kept private, the draft
//! side named `also` so its words re-mint as the document's own), confirmed
//! by the family's one composition, signature and send
//! (`Shell::confirm_standing`) — so the claim is composed in one place,
//! the open's read of the marker (`shell/publication.rs`, **The claim**),
//! and rides only where the marker's head is the trunk's head as read at
//! the open; never at the draft side, whose side is a private draft. After
//! the acknowledgment THE MERGE RECORD, the library's `record_published` —
//! the member and position the board acknowledged, the claims read back at
//! the daughter, written once in the account's merge journal with its
//! public link, or the standing one answered — never a second shot. The
//! answer is the landing with the acknowledgment's data, the panel's
//! re-statement, or its typed refusal: the race, `supersede_refused` with
//! `head_moved`, crosses as the board answered it, nothing re-sent, the
//! composition gone, to be made again on the head it names (skep #806).
//! `resolutions`, `{⟨gap⟩: ⟨choice⟩}`, are UNTRUSTED: each gap id and
//! choice checked against the composition the shell holds — a gap of the
//! report, a side among the gap's runs, an anchor the gap names — anything
//! else refused `malformed_args`, nothing landed; a checked one settles the
//! gap in the record as the person's, `resolved_by: person`.
//!
//! **`merge.undo`** takes the standing composition's landing back out of
//! the draft by the library's `undo`, one `set_arrangement` typed against
//! THE EDITOR's OWN LAST ACK on the draft, as every burst is typed (R6 with
//! P3's editor rule): the position of the principal's latest arrangement
//! write on it that this shell acknowledged, a burst's or a
//! `set_arrangement`'s, never a link's (`Holds::last_arranged`), or the
//! landing's position where that is later — so the person's own later
//! changes, taken back first on the editor's stack, never leave it
//! refused, and a change since by another hand refuses it
//! `arrangement_moved`, nothing wiped — while the session that landed it
//! stands; **`merge.withdraw`** — `{draft}` —
//! takes the merge out of any marked draft and keeps its words, in any
//! session, by the library's `withdraw`. Each replaces the landing's
//! record where one stands.
//!
//! **The compositions** ([`Merges`]): one per (board, principal), the
//! latest composed standing — a second compose replaces it, there being no
//! re-open of a composition as there is of a panel: the re-open is the
//! marker's, the board's — recording the session it was composed under and
//! dying with it, dropped by the bus's watcher at `session-died` as the
//! panels are, saying nothing: a composition's state crosses in its calls'
//! answers alone, and the contract names no event for the family. `land`
//! and `undo` with nothing standing answer `no_merge`.
//!
//! **The door.** Every row meets the shell's one write door before any
//! read it makes (`Shell::write_door`, through `Shell::signed`), with the
//! write it is about to make: `compose` with the landing's first write —
//! `stage` where no `into` is named and a fresh draft may be staged,
//! `set_arrangement` into the draft named — and over that draft whole;
//! `land` with `publish`, over the draft the composition landed in and the
//! draft side the shot names `also`; `undo` and `withdraw` with
//! `set_arrangement`, each over the draft it sets whole. So under a stopped
//! node, a poisoned write path or halted writes each row is refused
//! `stopped`, `poisoned` or `halted` naming that op, nothing read and
//! nothing dialed (skep #850), and over a draft holding lines of the
//! principal's the board has not kept — in any state — each whole-draft
//! write is refused `held_lines` naming the draft and the count, nothing
//! dialed (§3c.4, THE HELD-LINES GATE; skep #849): the held lines would
//! otherwise land on an arrangement the landing, the undo or the withdrawal
//! rewrote under them, and come back as a move the person never made. A
//! composition that lands into a prior record's draft in a fresh one's
//! place (skep #790) asks the door for that draft before the landing's
//! write, since the named draft was asked and that one was not. The two
//! re-opens past the door — the shot's restart re-open, the record after
//! the acknowledgment — are not refused at it again.
//!
//! **The refusals** cross as typed data: the library's own by name where
//! the contract names one — `unreadable {doc}`, `no_such_document {doc}`,
//! `base_unknown {side, reason}`, `two_drafts`, `over_cap {n, cap}`,
//! `not_owner {addr}`, `no_merge`, `nothing_to_undo {draft, why}` — the
//! rest under `merge_refused {arm, …}`; the board's verdicts verbatim,
//! `arrangement_moved` with its `site.as_of` and `site.current` among them;
//! the death signal met at a read or a write under the session's token —
//! the library's `SessionEnded` arm — ends the session, `session_died`;
//! every other halt crosses as itself.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde_json::{json, Map, Value};
use skep_address::{validate, Address, Nat, Tumbler};
use skep_client::address::{account_of, doc_1_of, document_of};
use skep_client::board::{frames, merge_marker, ChangesAnswer, ChangesQuery, MergeMarker, Rejection};
use skep_client::halt::Halt;
use skep_client::merge::{self as lib, Family, Gap, GapKind, NoUndo, Placement, ResolvedBy, Role, Run, SideAt, SideIx};
use skep_client::publication::{OriginAnswer, Run as SelectionRun};

use super::publication::{address_arg, clipped, via_name, Confirmation, OpenArgs, Signed};
use super::{optional, Shell, Write, Writer};
use crate::refusal::{Name, Refusal};
use crate::sessions::SessionEntry;
use crate::wire::bounded_address;

/// Returns the merge record kind's type address this shell names for
/// `account`: the account's own doc 1.
///
/// The kind is the record's class and its link's type slot
/// (`Inputs::kind`), which the journal and every record of the account are
/// found by. The merge record's decision 9 names a commons row for it,
/// interim and UNPINNED — no row of the vocabulary table, which every
/// registry-row literal in shipped code is held to (skepd's R7) — so this
/// shell names a type of the person's own instead: their doc 1, resident
/// once the account is claimed, one address per account on every device,
/// so a record this shell writes on one device is found on every other.
/// The `skep merge` command names its kind by `--kind`; one naming this
/// account's doc 1 reads and writes the same journal.
fn merge_kind(account: &str) -> Option<Address> {
    bounded_address(&doc_1_of(account))
}

/// Which form a composition took: the daughter, or the draft side.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Form {
    /// A daughter of the trunk's chain, the person's own.
    Daughter(Address),
    /// A draft of the family behind the head, the merge's side.
    Draft(Address),
}

impl Form {
    fn side(&self) -> &Address {
        match self {
            Form::Daughter(a) | Form::Draft(a) => a,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Form::Daughter(_) => "daughter",
            Form::Draft(_) => "draft",
        }
    }
}

/// One composition the shell holds: the library's, and where it stands.
#[derive(Debug, Clone)]
struct Composition {
    /// The session it was composed under; it dies with it.
    session: String,
    form: Form,
    merged: lib::Merged,
    /// The draft M stands in — landed by the composition, or already
    /// carrying it at a re-open.
    into: Address,
}

/// The compositions the shell holds, by (board reference, principal).
#[derive(Debug, Default)]
pub(super) struct Merges {
    standing: Mutex<BTreeMap<(String, u64), Composition>>,
}

impl Merges {
    fn standing(&self, key: &(String, u64)) -> Option<Composition> {
        self.standing.lock().expect("the compositions' lock").get(key).cloned()
    }

    fn stand(&self, key: (String, u64), composition: Composition) {
        self.standing.lock().expect("the compositions' lock").insert(key, composition);
    }

    fn take(&self, key: &(String, u64)) -> Option<Composition> {
        self.standing.lock().expect("the compositions' lock").remove(key)
    }

    /// Drops every composition that stood under `session_reference`: the
    /// session died with it standing (the family's one session rule).
    pub(super) fn ended(&self, session_reference: &str) {
        self.standing.lock().expect("the compositions' lock").retain(|_, c| c.session != session_reference);
    }
}

// ── address arithmetic over the trunk ─────────────────────────────────────

/// Returns a member's version components after the trunk `doc`'s.
///
/// `None` where `a` is not under `doc`, is `doc` itself, or lies in one of
/// its subspaces.
pub(super) fn version_components(doc: &Address, a: &Address) -> Option<Vec<Nat>> {
    let doc: Vec<Nat> = doc.tumbler().iter().cloned().collect();
    let comps: Vec<Nat> = a.tumbler().iter().cloned().collect();
    let version = comps.strip_prefix(doc.as_slice())?;
    if version.is_empty() || version.contains(&Nat::from(0u32)) {
        return None;
    }
    Some(version.to_vec())
}

/// Returns whether `a` is a trunk member of `doc` — one version component.
pub(super) fn is_trunk_member(doc: &Address, a: &Address) -> bool {
    version_components(doc, a).is_some_and(|v| v.len() == 1)
}

/// Returns whether `a` is a daughter of `doc`'s chain — a member under a
/// trunk member, two or more version components — which a published chain
/// makes published by construction.
pub(super) fn is_daughter(doc: &Address, a: &Address) -> bool {
    version_components(doc, a).is_some_and(|v| v.len() >= 2)
}

/// Returns the trunk member after `head`: its last component plus one.
pub(super) fn next_trunk_member(head: &Address) -> Option<Address> {
    with_last(head, |n| n.checked_add(1))
}

/// Returns the trunk member before `member`, where it is not the first.
fn trunk_member_before(member: &Address) -> Option<Address> {
    with_last(member, |n| (n > 1).then(|| n - 1))
}

/// Returns `a` with its last component mapped by `f`.
fn with_last(a: &Address, f: impl FnOnce(u64) -> Option<u64>) -> Option<Address> {
    let mut comps: Vec<Nat> = a.tumbler().iter().cloned().collect();
    let last = u64::try_from(comps.last()?).ok()?;
    *comps.last_mut()? = Nat::from(f(last)?);
    validate(Tumbler::new(comps).ok()?).ok()
}

/// Returns the trunk member `a` lies under: `doc` and the first version
/// component.
fn trunk_member_above(doc: &Address, a: &Address) -> Option<Address> {
    let first = version_components(doc, a)?.into_iter().next()?;
    let comps = doc.tumbler().iter().cloned().chain(std::iter::once(first));
    validate(Tumbler::new(comps).ok()?).ok()
}

// ── the reads the rows make themselves ────────────────────────────────────

/// What one `doc_metadata` of a draft tells the family.
struct DraftFacts {
    published: bool,
    owner: String,
    base: Option<Address>,
    marker: Option<MergeMarker>,
}

impl Shell {
    /// Reads a draft's facts off one `doc_metadata`: its publication bit,
    /// its owner, its recorded base and its merge marker.
    ///
    /// # Errors
    ///
    /// `metadata_read`'s, then `shape` where the answer is no `doc_metadata`
    /// answer this shell reads.
    fn draft_facts(&self, session: &SessionEntry, draft: &Address) -> Result<DraftFacts, Refusal> {
        let v = self.metadata_read(session, draft)?;
        let shape = || Refusal::shell(Name::SHAPE, json!({"op": "doc_metadata", "body": clipped(&v.to_string(), 200)}));
        let marker = merge_marker(&v).ok_or_else(shape)?;
        let published = v["published"].as_bool().ok_or_else(shape)?;
        let owner = v["owner"].as_str().ok_or_else(shape)?.to_string();
        let base = v["base"].as_str().and_then(bounded_address);
        Ok(DraftFacts { published, owner, base, marker })
    }

    /// Reads the draft the landing goes into, UNTRUSTED (skep #799).
    ///
    /// # Errors
    ///
    /// `draft_facts`'s; then `not_owner` naming it where it is published or
    /// another account's.
    fn landing_target(&self, session: &SessionEntry, account: &str, into: &Address) -> Result<DraftFacts, Refusal> {
        let facts = self.draft_facts(session, into)?;
        if facts.published || facts.owner != account {
            return Err(Refusal::shell(Name::NOT_OWNER, json!({"addr": into.to_string()})));
        }
        Ok(facts)
    }

    /// Returns the trunk's head as the board stands, probing up from
    /// `start`, a registered trunk member of `doc`: one `doc_metadata` per
    /// member after it until one is not registered.
    ///
    /// # Errors
    ///
    /// A probe's refusals but `no_such_document`, which is its answer.
    fn trunk_head(&self, session: &SessionEntry, start: &Address) -> Result<Address, Refusal> {
        let mut head = start.clone();
        loop {
            let Some(next) = next_trunk_member(&head) else { return Ok(head) };
            match self.metadata_read(session, &next) {
                Ok(_) => head = next,
                Err(Refusal::Shell { name, .. }) if name == Name::NO_SUCH_DOCUMENT => return Ok(head),
                Err(e) => return Err(e),
            }
        }
    }

    /// Returns the member an active supersession claim of `account`'s own
    /// names as the daughter's successor, with the claims so naming it, by
    /// one `in_claims` at the daughter — THE MERGED ARM's read.
    ///
    /// # Errors
    ///
    /// `unreadable` and `no_such_document` naming the daughter, the board's
    /// other verdicts verbatim, `unreachable`, `session_died`.
    fn own_claim_naming(&self, session: &SessionEntry, daughter: &Address, account: &str) -> Result<Option<(Address, Vec<Address>)>, Refusal> {
        let text = daughter.to_string();
        let v = self.family_read(session, &frames::in_claims(&text))?;
        if let Some(r) = Rejection::of(&v) {
            return Err(match r.key() {
                "withheld" => Refusal::shell(Name::UNREADABLE, json!({"doc": text})),
                "doc_not_registered" => Refusal::shell(Name::NO_SUCH_DOCUMENT, json!({"doc": text})),
                _ => Refusal::from(r.refused(&v)),
            });
        }
        let mut member = None;
        let mut claims = Vec::new();
        for row in v["claims"].as_array().into_iter().flatten() {
            let active = row["active"].as_bool().unwrap_or(true);
            let owned = row["home"].as_str().and_then(account_of).as_deref() == Some(account);
            if !active || !owned {
                continue;
            }
            if let (Some(new), Some(claim)) = (row["new"].as_str().and_then(bounded_address), row["claim"].as_str().and_then(bounded_address)) {
                member.get_or_insert(new);
                claims.push(claim);
            }
        }
        Ok(member.map(|m| (m, claims)))
    }

    /// Returns whether a write under `draft` landed after position `since`,
    /// read off the drafts supplement — the test that tells a re-open's side
    /// read from its image as it stands, which equals the marker's state,
    /// from one read at the marker's position.
    ///
    /// A floor the feed no longer answers below is read as moved: the side
    /// is then read at the marker's position, which the board answers or
    /// refuses by name.
    ///
    /// # Errors
    ///
    /// The feed's halts, and `session_died` where the read met the death
    /// signal.
    fn moved_since(&self, session: &SessionEntry, draft: &Address, since: u64) -> Result<bool, Refusal> {
        let text = draft.to_string();
        let mut limit = None;
        loop {
            match session.board.changes(Some(&session.token), &ChangesQuery { since, under: Some(&text), drafts: true, limit })? {
                ChangesAnswer::Page(page) => return Ok(!page.changes.is_empty()),
                ChangesAnswer::HistoryReclaimed { .. } => return Ok(true),
                ChangesAnswer::TooLarge { fits } => limit = Some(fits),
                ChangesAnswer::Closed => return Err(self.died(session)),
                // An answer this shell does not read: the side is read at
                // the marker's position, which the board answers by name.
                _ => return Ok(true),
            }
        }
    }

    /// Maps the merge library's refusal to the shell's (the module doc, **The
    /// refusals**), the session ended where the library answers its end.
    pub(super) fn merge_refusal(&self, session: &SessionEntry, r: lib::Refusal) -> Refusal {
        use lib::Refusal as R;
        let s = |a: &Address| a.to_string();
        let other = |arm: &str, members: Value| {
            let mut detail = json!({"arm": arm});
            if let Value::Object(members) = members {
                for (k, v) in members {
                    detail[k] = v;
                }
            }
            Refusal::shell(Name::MERGE_REFUSED, detail)
        };
        match r {
            R::Unreadable(doc) => Refusal::shell(Name::UNREADABLE, json!({"doc": s(&doc)})),
            R::NoSuchDocument(doc) => Refusal::shell(Name::NO_SUCH_DOCUMENT, json!({"doc": s(&doc)})),
            R::BaseUnknown(side) => Refusal::shell(Name::BASE_UNKNOWN, json!({"side": s(side.address()), "reason": "base_unknown"})),
            R::BareSource { side, source } => Refusal::shell(Name::BASE_UNKNOWN, json!({"side": s(side.address()), "reason": "bare_source", "source": s(&source)})),
            R::DraftBaseDisagrees { side, named, served } => Refusal::shell(Name::BASE_UNKNOWN, json!({"side": s(side.address()), "reason": "draft_base_disagrees", "named": s(&named), "served": s(&served)})),
            R::ForkBaseNamed { fork, base } => other("fork_base_named", json!({"fork": s(&fork), "base": s(&base)})),
            R::TwoDrafts => Refusal::shell(Name::TWO_DRAFTS, json!({})),
            R::OverCap { runs, cap } => Refusal::shell(Name::OVER_CAP, json!({"n": runs, "cap": cap})),
            R::NotOwner { draft } | R::UnownedDraft { draft } => Refusal::shell(Name::NOT_OWNER, json!({"addr": s(&draft)})),
            R::Published { doc } => Refusal::shell(Name::NOT_OWNER, json!({"addr": s(&doc), "published": true})),
            R::NothingToUndo { draft, why } => {
                let mut detail = json!({"draft": s(&draft)});
                match why {
                    NoUndo::Inherited => detail["why"] = json!("inherited"),
                    NoUndo::Published { version } => {
                        detail["why"] = json!("published");
                        detail["version"] = json!(s(&version));
                    }
                    NoUndo::TakenBack => detail["why"] = json!("taken_back"),
                }
                Refusal::shell(Name::NOTHING_TO_UNDO, detail)
            }
            R::NoMerge { draft } => Refusal::shell(Name::NO_MERGE, json!({"draft": s(&draft)})),
            R::NotPast { draft, at, current } => other("not_past", json!({"draft": s(&draft), "at": at, "current": current})),
            R::TooFragmented { doc, runs_seen } => other("too_fragmented", json!({"doc": s(&doc), "runs_seen": runs_seen})),
            R::HistoryBusy => other("history_busy", json!({})),
            R::HistoryReclaimed { at, floor } => other("history_reclaimed", json!({"at": at, "floor": floor})),
            R::BeyondHead { at, head, .. } => other("beyond_head", json!({"at": at, "head": head})),
            R::NotAPosition { at, nearest, .. } => other("not_a_position", json!({"at": at, "nearest": nearest})),
            R::ForkBaseMoved { fork, source, head } => other("fork_base_moved", json!({"fork": s(&fork), "source": s(&source), "head": s(&head)})),
            R::BaseNotInChain { into, head } => other("base_not_in_chain", json!({"into": s(&into), "head": s(&head)})),
            R::WindowWithheld(origin) => other("window_withheld", json!({"origin": s(&origin)})),
            R::NeedsSignedSession => other("needs_signed_session", json!({})),
            R::SupersedeRefused { index, cause } => {
                let head = match &cause {
                    lib::SupersedeCause::HeadMoved { head } => head.as_ref().map(ToString::to_string),
                    _ => None,
                };
                other("supersede_refused", json!({"index": index, "detail": cause.token(), "head": head}))
            }
            R::SessionEnded(_) => self.died(session),
            R::Halt(h) => Refusal::from(h),
        }
    }

    // ── The rows ─────────────────────────────────────────────────────────

    /// Answers `merge.compose(session, {doc, alternative, into?})`, or THE
    /// DRAFT SIDE's `merge.compose(session, {doc, draft, into?})`, with the
    /// report (the module doc; `shapes`' `MergeReport`).
    ///
    /// # Errors
    ///
    /// In this order:
    ///
    /// 1. `malformed_args` naming an optional member present in another
    ///    form — `alternative`, `draft`, `into` — then `doc` where it is no
    ///    bare document address, `alternative` where it is no daughter of
    ///    `doc`'s chain, `into` where it is the draft side itself,
    ///    `alternative or draft` where neither is given and `draft` where
    ///    both are;
    /// 2. `malformed_args` naming `session`, then `session_ended`; the
    ///    write door's, in its order — `write_in_bare_session`, then
    ///    `another_window`, naming the call; `stopped`, `poisoned` or
    ///    `halted` where a hold stands at the board, naming `stage` where no
    ///    `into` is named, else `set_arrangement`; `held_lines` naming `into`
    ///    and the lines of the principal's standing on it the board has not
    ///    kept — nothing read at any of the four; `store_unreadable`,
    ///    `no_account`;
    /// 3. at a daughter, the `in_claims` read's: `unreadable`,
    ///    `no_such_document`, the board's verdicts, `unreachable`,
    ///    `session_died`; then the merged arm's composition and record, as
    ///    step 5's and `merge.land`'s record;
    /// 4. `into`'s read, as step 3's reads, and `not_owner` naming it where
    ///    it is published or another account's; at the draft side the
    ///    draft's read, and `base_unknown` where the board records no base
    ///    for it in `doc`'s chain; the head's probe's;
    /// 5. the composition's (`skep_client::merge::compose`): `base_unknown`
    ///    with its reason, `two_drafts`, `unreadable`, `no_such_document`,
    ///    `merge_refused` with its arm, the board's verdicts verbatim; then
    ///    `over_cap` where M passes the cap, nothing landed;
    /// 6. where the landing goes into a prior record's draft in a fresh
    ///    one's place, the write door's again for that draft, `held_lines`
    ///    among them, nothing landed; then the landing's
    ///    (`skep_client::merge::land`): the board's
    ///    `arrangement_moved` verbatim, nothing landed; `merge_refused`
    ///    with `fork_base_moved`, `base_not_in_chain`, `window_withheld` or
    ///    `needs_signed_session`; `not_owner`; a halt's face — the board's
    ///    head owed, the landing standing with its record unwritten; and
    ///    `session_died` where a read or the write met the death signal.
    pub(super) fn merge_compose(&self, args: &Value) -> Result<Value, Refusal> {
        // The row's own members first, each refused in another form before
        // the session is looked up — the order every row keeps.
        let alternative = optional(args, "alternative", address_arg)?;
        let draft = optional(args, "draft", address_arg)?;
        let into = optional(args, "into", address_arg)?;
        let doc = address_arg(&args["doc"]).ok_or_else(|| Refusal::malformed("doc"))?;
        let doc_text = doc.to_string();
        if document_of(&doc_text).as_deref() != Some(doc_text.as_str()) {
            return Err(Refusal::malformed("doc"));
        }
        let form = match (alternative, draft) {
            (Some(a), None) => {
                if !is_daughter(&doc, &a) {
                    return Err(Refusal::malformed("alternative"));
                }
                Form::Daughter(a)
            }
            (None, Some(d)) => {
                // NEVER the behind draft itself (B3-S11's THE DRAFT SIDE):
                // it stands beside the new one untouched.
                if into.as_ref() == Some(&d) {
                    return Err(Refusal::malformed("into"));
                }
                Form::Draft(d)
            }
            (None, None) => return Err(Refusal::malformed("alternative or draft")),
            (Some(_), Some(_)) => return Err(Refusal::malformed("draft")),
        };
        let session = self.session(&args["session"])?;
        // The one write door, over the landing's first write: `stage` where a
        // fresh draft may be staged, `set_arrangement` into the draft named,
        // which is asked for its held lines.
        let first_write = if into.is_some() { "set_arrangement" } else { "stage" };
        let signed = self.signed(&session, Write::call("merge.compose", first_write).over(into.iter().map(ToString::to_string)))?;
        let key = Self::family_key(&session);
        let kind = merge_kind(&signed.account).ok_or_else(|| Refusal::shell(Name::NO_ACCOUNT, json!({})))?;
        // THE MERGED ARM: a daughter a claim of the person's own already
        // names, nothing composed into a draft and nothing landed.
        if let Form::Daughter(daughter) = &form {
            if let Some((member, claims)) = self.own_claim_naming(&session, daughter, &signed.account)? {
                return self.merged_arm(&session, &signed, &doc, daughter, &member, claims, &kind);
            }
        }
        // `into`, UNTRUSTED: read before anything is composed.
        let target = match &into {
            Some(into) => Some(self.landing_target(&session, &signed.account, into)?),
            None => None,
        };
        // The trunk member the side lies under: a daughter's parent, a
        // draft side's recorded base.
        let start = match &form {
            Form::Daughter(d) => trunk_member_above(&doc, d),
            Form::Draft(d) => self.draft_facts(&session, d)?.base.and_then(|b| trunk_member_above(&doc, &b)),
        };
        let Some(start) = start else {
            return Err(Refusal::shell(Name::BASE_UNKNOWN, json!({"side": form.side().to_string(), "reason": "base_unknown"})));
        };
        // THE RE-OPEN: the marker on `into` naming this side, composed on
        // the head the marker names; else the trunk's head as it stands.
        let side_text = form.side().to_string();
        let reopen = target.as_ref().and_then(|t| t.marker.clone()).filter(|m| m.sides.iter().any(|s| *s == side_text)).filter(|m| bounded_address(&m.head).is_some_and(|h| is_trunk_member(&doc, &h)));
        let head = match &reopen {
            Some(m) => bounded_address(&m.head).expect("filtered to a trunk member"),
            None => self.trunk_head(&session, &start)?,
        };
        let side = match &form {
            Form::Daughter(d) => lib::Side::Member(d.clone()),
            Form::Draft(d) => {
                // The side as compose read it: at the marker's position
                // where a write under it landed since, else its image as it
                // stands, the same state.
                let position = match reopen.as_ref().and_then(|m| m.at) {
                    Some(at) if self.moved_since(&session, d, at)? => Some(at),
                    _ => None,
                };
                lib::Side::Draft { at: d.clone(), position }
            }
        };
        let inputs = lib::Inputs { doc: doc.clone(), head, base: None, sides: vec![side], options: lib::Options::default(), kind: kind.clone() };
        let merged = lib::compose(&session.board, Some(&session.token), &inputs).map_err(|r| self.merge_refusal(&session, r))?;
        if let (Some(marker), Some(into)) = (&reopen, &into) {
            return self.reopened(&session, key, form, merged, into, marker.at);
        }
        if merged.composed.counts.m > merged.cap {
            return Err(Refusal::shell(Name::OVER_CAP, json!({"n": merged.composed.counts.m, "cap": merged.cap})));
        }
        // A fresh draft asked for while a record of the key names a draft
        // landing (the survey §5 item 2): the draft's marker naming this
        // merge is the re-open; else that draft is landed into, the same
        // landing (skep #790), and the library is handed `into` none only
        // where no such record stands.
        let mut landing_into = into.clone();
        if landing_into.is_none() {
            if let Some(lib::RecordLanding::Draft { draft: prior, .. }) = merged.prior.as_ref().and_then(|p| p.landed.clone()) {
                if let Ok(facts) = self.draft_facts(&session, &prior) {
                    let carries = facts.marker.as_ref().is_some_and(|m| m.sides.iter().any(|s| *s == side_text) && m.head == merged.inputs.head.to_string());
                    if carries {
                        let at = facts.marker.as_ref().and_then(|m| m.at);
                        return self.reopened(&session, key, form, merged, &prior, at);
                    }
                    if !facts.published && facts.owner == signed.account {
                        landing_into = Some(prior);
                    }
                }
            }
        }
        // A prior record's draft landed into in a fresh one's place (skep
        // #790) is a draft the door has not asked for its held lines: asked
        // now, before the landing's write, as the named draft was.
        if let Some(prior) = landing_into.as_ref().filter(|prior| into.as_ref() != Some(*prior)) {
            self.write_door(Writer::Session(&session), &Write::call("merge.compose", "set_arrangement").over([prior.to_string()]))?;
        }
        let merger = lib::Merger { token: &session.token, account: &signed.account, signer: &*signed.signer };
        let landed = lib::land(&session.board, &merged, lib::Landing::Draft { merger, into: landing_into.clone(), journal: None }).map_err(|r| self.merge_refusal(&session, r))?;
        let lib::Landed::Draft { into: landed_in, position, record, head_moved } = landed else {
            return Err(Refusal::from(Halt::face("the draft landing answered no draft", "`skep_client::merge::land` with a draft landing answers `Landed::Draft` on every path", "report it: the shell's merge row is behind the library")));
        };
        let composition = Composition { session: session.reference.clone(), form, merged, into: landed_in.clone() };
        let answer = report_json(&composition.merged, &composition.form, "landed", json!({"into": landed_in.to_string(), "position": position, "fresh": landing_into.is_none(), "head_moved": head_moved.map(|h| h.to_string()), "record_link": record.to_string()}));
        self.merges.stand(key, composition);
        Ok(answer)
    }

    /// Answers the re-open: the report with nothing landed, each unsettled
    /// gap's state read off `into` as it stands (the module doc).
    ///
    /// # Errors
    ///
    /// The draft's image read's (`whole_draft`).
    fn reopened(&self, session: &SessionEntry, key: (String, u64), form: Form, mut merged: lib::Merged, into: &Address, at: Option<u64>) -> Result<Value, Refusal> {
        let image = self.whole_draft(session, into)?;
        settle_by_edit(&mut merged, &image);
        let position = at.unwrap_or(merged.as_of);
        let composition = Composition { session: session.reference.clone(), form, merged, into: into.clone() };
        let answer = report_json(&composition.merged, &composition.form, "reopened", json!({"into": into.to_string(), "position": position, "fresh": false, "head_moved": Value::Null}));
        self.merges.stand(key, composition);
        Ok(answer)
    }

    /// Answers THE MERGED ARM: the member a claim of the person's own names
    /// the daughter superseded by, and the record of that merge — the
    /// standing one, or written now through the library's
    /// `record_published` where none names it (the module doc).
    ///
    /// # Errors
    ///
    /// The composition's, as `merge.compose`'s step 5; the member's
    /// `doc_metadata` read's; the record's, as `merge.land`'s record.
    fn merged_arm(&self, session: &SessionEntry, signed: &Signed, doc: &Address, daughter: &Address, member: &Address, claims: Vec<Address>, kind: &Address) -> Result<Value, Refusal> {
        // The head the merge was composed on: the member's predecessor on
        // the trunk, or the trunk member a daughter member lies under.
        let head = if is_trunk_member(doc, member) { trunk_member_before(member) } else { trunk_member_above(doc, member) };
        let Some(head) = head.filter(|h| is_trunk_member(doc, h)) else {
            return Err(Refusal::shell(Name::MERGE_REFUSED, json!({"arm": "claim_names_no_member", "member": member.to_string()})));
        };
        let inputs = lib::Inputs { doc: doc.clone(), head, base: None, sides: vec![lib::Side::Member(daughter.clone())], options: lib::Options::default(), kind: kind.clone() };
        let merged = lib::compose(&session.board, Some(&session.token), &inputs).map_err(|r| self.merge_refusal(session, r))?;
        let standing = merged.prior.as_ref().filter(|p| matches!(&p.landed, Some(lib::RecordLanding::Member { member: m, .. }) if m == member));
        // The record: the standing one, its body the report's, else written
        // now — the resume of a stop between the shot and its record.
        let (record_link, claims, body) = match standing {
            Some(prior) => (prior.link.clone(), claims, Some(prior.to_value())),
            None => {
                let position = self.metadata_read(session, member)?["at"].as_u64().unwrap_or(merged.as_of);
                let merger = lib::Merger { token: &session.token, account: &signed.account, signer: &*signed.signer };
                match lib::record_published(&session.board, &merged, merger, member, position, None).map_err(|r| self.merge_refusal(session, r))? {
                    lib::Landed::Member { record, claims, .. } => (Some(record), claims, None),
                    _ => (None, claims, None),
                }
            }
        };
        let form = Form::Daughter(daughter.clone());
        let mut extra = json!({"member": member.to_string(), "claims": claims.iter().map(ToString::to_string).collect::<Vec<_>>(), "record_link": record_link.map(|l| l.to_string())});
        if let Some(body) = body {
            extra["record"] = body;
        }
        Ok(report_json(&merged, &form, "merged", extra))
    }

    /// Answers `merge.land(session, {resolutions?})` with the landing, the
    /// panel's re-statement or its typed refusal (the module doc; `shapes`'
    /// `MergeLanded`).
    ///
    /// # Errors
    ///
    /// In this order: `malformed_args` naming `resolutions` where it is
    /// present and no object; `malformed_args` naming `session`, then
    /// `session_ended`; `no_merge` naming the session where no composition
    /// stands under its board and principal; `malformed_args` naming
    /// `resolutions` where a gap id names no gap of the composition or a
    /// choice is none the gap admits; the write door's, in its order —
    /// `write_in_bare_session`, `another_window`, `stopped`, `poisoned` or
    /// `halted` naming `publish`, `held_lines` naming the draft the
    /// composition landed in or the draft side and the lines of the
    /// principal's standing on it — nothing read at any; `store_unreadable`,
    /// `no_account`; the panel's open's where the shell opens one
    /// (`publication.open`'s steps 4 to 6); then `publication.confirm`'s
    /// from `write_in_bare_session` on — the door asked again over the
    /// panel's drafts, a draft the page's panel names `also` among them,
    /// nothing composed. The record's refusal after an acknowledgment is no
    /// error: the member stands, and the answer carries it as `unrecorded`.
    pub(super) fn merge_land(&self, args: &Value) -> Result<Value, Refusal> {
        let resolutions = optional(args, "resolutions", |v| v.as_object().cloned())?;
        let session = self.session(&args["session"])?;
        let key = Self::family_key(&session);
        let Some(mut composition) = self.merges.standing(&key) else {
            return Err(Refusal::shell(Name::NO_MERGE, json!({"session": session.reference})));
        };
        if let Some(resolutions) = &resolutions {
            apply_resolutions(&mut composition.merged, resolutions)?;
            self.merges.stand(key.clone(), composition.clone());
        }
        let into = composition.into.clone();
        // The one write door, over the shot's drafts: the draft the
        // composition landed in and, at the draft side, the side the shot
        // names `also`; the panel's own `also` drafts are asked again as the
        // shot is confirmed (`Shell::confirm_standing`).
        let side = match &composition.form {
            Form::Draft(d) => Some(d.clone()),
            Form::Daughter(_) => None,
        };
        let signed = self.signed(&session, Write::call("merge.land", "publish").over(std::iter::once(&into).chain(side.as_ref()).map(ToString::to_string)))?;
        // The panel: the page's over the draft, or one opened here over the
        // whole draft, the draft side named `also`.
        let (state, opened_here) = match self.publications.stood_for(&key, &into, &session.reference) {
            Some(state) => (state, false),
            None => {
                let also = match &composition.form {
                    Form::Draft(d) => vec![d.clone()],
                    Form::Daughter(_) => Vec::new(),
                };
                let (state, _) = self.open_panel(&session, &signed, OpenArgs { draft: into.clone(), also, doc: Some(composition.merged.inputs.doc.clone()), mint: None, claim: false, selection: None, notes: None, readable_drafts: None, published: None })?;
                self.publications.stand(key.clone(), state.clone());
                (state, true)
            }
        };
        let switches = state.switches.clone();
        let mut answers = state.answers.clone();
        if opened_here {
            for window in &state.panel.windows {
                answers.entry(window.run).or_insert(OriginAnswer::KeepPrivate);
            }
        }
        match self.confirm_standing(&session, &key, &state, switches, answers, "merge.land")? {
            Confirmation::Acknowledged { session: current, ack } => {
                let signed = self.signed_within_call(&current, "merge.land")?;
                let merger = lib::Merger { token: &current.token, account: &signed.account, signer: &*signed.signer };
                let recorded = lib::record_published(&current.board, &composition.merged, merger, &ack.member, ack.at, None);
                self.merges.take(&key);
                self.acknowledged(&current, &key, &into, &ack);
                let daughter = !is_trunk_member(&composition.merged.inputs.doc, &ack.member);
                let mut v = json!({
                    "outcome": "landed",
                    "member": ack.member.to_string(),
                    "at": ack.at,
                    "via": via_name(ack.via),
                    "claim": ack.claim,
                    "supersede": ack.supersede.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "daughter": daughter,
                    "record": Value::Null,
                    "claims": Vec::<Value>::new(),
                    "retries": composition.merged.inputs.options.retries,
                });
                match recorded {
                    Ok(lib::Landed::Member { record, claims, retries, .. }) => {
                        v["record"] = json!(record.to_string());
                        v["claims"] = json!(claims.iter().map(ToString::to_string).collect::<Vec<_>>());
                        v["retries"] = json!(retries);
                    }
                    Ok(_) => {}
                    Err(r) => v["unrecorded"] = self.merge_refusal(&current, r).to_value(),
                }
                Ok(v)
            }
            Confirmation::Answered(answer) => {
                // The race: the composition made again on the head the
                // refusal names.
                if answer["arm"] == "supersede_refused" && answer["detail"] == "head_moved" {
                    self.merges.take(&key);
                }
                Ok(answer)
            }
        }
    }

    /// Answers `merge.undo(session)` with `{draft, position, record,
    /// restored}` (the module doc; `shapes`' `Undone`).
    ///
    /// The undo is typed against the principal's latest arrangement write on
    /// the draft the hold noted, or the landing's position where that is
    /// later, the library taking the later of the two.
    ///
    /// # Errors
    ///
    /// In this order: `malformed_args` naming `session`, then
    /// `session_ended`; `no_merge` naming the session where no composition
    /// stands; the write door's, in its order — `write_in_bare_session`,
    /// `another_window`, `stopped`, `poisoned` or `halted` naming
    /// `set_arrangement`, `held_lines` naming the draft the composition
    /// landed in and the lines of the principal's standing on it — nothing
    /// read at any; `store_unreadable`, `no_account`; the library's
    /// (`skep_client::merge::undo`): `unreadable`,
    /// `no_such_document`, `not_owner`, `nothing_to_undo` with its reason,
    /// `no_merge` naming the draft, `merge_refused` with `history_reclaimed`,
    /// `over_cap` where the state before the landing, mapped through the
    /// records, is in more runs than one write may name, the board's
    /// `arrangement_moved` verbatim, a halt's face, and `session_died`.
    pub(super) fn merge_undo(&self, args: &Value) -> Result<Value, Refusal> {
        let session = self.session(&args["session"])?;
        let key = Self::family_key(&session);
        let Some(composition) = self.merges.standing(&key) else {
            return Err(Refusal::shell(Name::NO_MERGE, json!({"session": session.reference})));
        };
        // The one write door, over the draft the undo sets whole.
        let signed = self.signed(&session, Write::call("merge.undo", "set_arrangement").over([composition.into.to_string()]))?;
        let merger = lib::Merger { token: &session.token, account: &signed.account, signer: &*signed.signer };
        let kind = merge_kind(&signed.account).ok_or_else(|| Refusal::shell(Name::NO_ACCOUNT, json!({})))?;
        // THE EDITOR's OWN LAST ACK on the draft (P3).
        let own_ack = self.holds.last_arranged(&session, &composition.into.to_string());
        let undone = lib::undo(&session.board, merger, &composition.into, &kind, own_ack, None).map_err(|r| self.merge_refusal(&session, r))?;
        self.merges.take(&key);
        Ok(json!({
            "draft": undone.draft.to_string(),
            "position": undone.position,
            "record": undone.record.map(|r| r.to_string()),
            "restored": undone.restored.map(|(base, extent)| json!({"base": base.to_string(), "extent": extent})),
        }))
    }

    /// Answers `merge.withdraw(session, {draft})` with `{draft, position,
    /// record}` (the module doc; `shapes`' `Withdrawn`).
    ///
    /// # Errors
    ///
    /// In this order: `malformed_args` naming `draft`; `malformed_args`
    /// naming `session`, then `session_ended`; the write door's, in its
    /// order — `write_in_bare_session`, `another_window`, `stopped`,
    /// `poisoned` or `halted` naming `set_arrangement`, `held_lines` naming
    /// `draft` and the lines of the principal's standing on it — nothing
    /// read at any; `store_unreadable`, `no_account`; the library's
    /// (`skep_client::merge::withdraw`): `unreadable`, `no_such_document`,
    /// `not_owner`, `no_merge` naming the draft, the board's
    /// `arrangement_moved` verbatim, a halt's face, and `session_died`.
    pub(super) fn merge_withdraw(&self, args: &Value) -> Result<Value, Refusal> {
        let draft = address_arg(&args["draft"]).ok_or_else(|| Refusal::malformed("draft"))?;
        let session = self.session(&args["session"])?;
        let key = Self::family_key(&session);
        // The one write door, over the draft the withdrawal sets whole.
        let signed = self.signed(&session, Write::call("merge.withdraw", "set_arrangement").over([draft.to_string()]))?;
        let merger = lib::Merger { token: &session.token, account: &signed.account, signer: &*signed.signer };
        let kind = merge_kind(&signed.account).ok_or_else(|| Refusal::shell(Name::NO_ACCOUNT, json!({})))?;
        let withdrawn = lib::withdraw(&session.board, merger, &draft, &kind, None).map_err(|r| self.merge_refusal(&session, r))?;
        if self.merges.standing(&key).is_some_and(|c| c.into == draft) {
            self.merges.take(&key);
        }
        Ok(json!({"draft": withdrawn.draft.to_string(), "position": withdrawn.position, "record": withdrawn.record.map(|r| r.to_string())}))
    }
}

// ── the resolutions, and the gaps' state at a re-open ─────────────────────

/// Applies the page's `resolutions` to the composition's gaps, each checked
/// as UNTRUSTED input against the composition (the module doc).
///
/// Each is `⟨gap id⟩: ⟨choice⟩` — `keep_both` (the default kept), `omit`,
/// `{order: [sides]}` (each a side among the gap's runs, none twice),
/// `{keep_only: side}`, `{after: anchor}` or `{before: anchor}` (the gap's
/// own anchor) — settling the gap in the record as the person's.
///
/// # Errors
///
/// `malformed_args` naming `resolutions` at the first that fails its check;
/// nothing is applied past it.
fn apply_resolutions(merged: &mut lib::Merged, resolutions: &Map<String, Value>) -> Result<(), Refusal> {
    let malformed = || Refusal::malformed("resolutions");
    for (gap, choice) in resolutions {
        let id: u32 = gap.parse().map_err(|_| malformed())?;
        let ix = merged.record.gaps.iter().position(|g| g.id.0 == id).ok_or_else(malformed)?;
        let gap = &merged.record.gaps[ix];
        let sides: Vec<u8> = gap.runs.iter().map(|(s, _)| s.0).collect();
        let side_of = |v: &Value| v.as_u64().and_then(|n| u8::try_from(n).ok()).filter(|n| sides.contains(n)).map(SideIx);
        let anchor_of = |v: &Value, anchor: &Option<Address>| v.as_str().and_then(bounded_address).filter(|a| anchor.as_ref() == Some(a)).map(|_| ());
        let placed = match choice {
            Value::String(s) if s == "keep_both" => None,
            Value::String(s) if s == "omit" => Some(Placement::Omitted),
            Value::Object(o) if o.len() == 1 => {
                if let Some(order) = o.get("order") {
                    let order: Vec<SideIx> = order.as_array().ok_or_else(malformed)?.iter().map(side_of).collect::<Option<_>>().ok_or_else(malformed)?;
                    if order.is_empty() || order.iter().enumerate().any(|(k, s)| order[..k].contains(s)) {
                        return Err(malformed());
                    }
                    Some(Placement::Order(order))
                } else if let Some(side) = o.get("keep_only") {
                    Some(Placement::Order(vec![side_of(side).ok_or_else(malformed)?]))
                } else if let Some(after) = o.get("after") {
                    anchor_of(after, &gap.after).ok_or_else(malformed)?;
                    Some(Placement::After)
                } else if let Some(before) = o.get("before") {
                    anchor_of(before, &gap.before).ok_or_else(malformed)?;
                    Some(Placement::Before)
                } else {
                    return Err(malformed());
                }
            }
            _ => return Err(malformed()),
        };
        for gaps in [&mut merged.record.gaps, &mut merged.composed.gaps] {
            if let Some(g) = gaps.get_mut(ix) {
                if let Some(placed) = &placed {
                    g.placed = placed.clone();
                }
                g.settled = true;
                g.resolved_by = Some(ResolvedBy::Person);
            }
        }
    }
    Ok(())
}

/// Reads each unsettled gap's state off the draft's image as it stands (the
/// module doc, THE RE-OPEN): a gap whose default the draft no longer
/// arranges as M placed it — its runs removed whole, or reordered — is
/// settled by the person; an edit inside a run's words, which keeps every
/// position in its order, settles nothing.
fn settle_by_edit(merged: &mut lib::Merged, image: &[SelectionRun]) {
    let ordinal_of = |origin: &Address, i: u64| -> Option<u64> {
        let mut at = 1u64;
        for r in image {
            if r.origin == *origin && i >= r.i_start && i < r.reach() {
                return Some(at + (i - r.i_start));
            }
            at = at.saturating_add(r.width);
        }
        None
    };
    for ix in 0..merged.record.gaps.len() {
        let gap = &merged.record.gaps[ix];
        if gap.settled {
            continue;
        }
        let default: Vec<&Run> = match &gap.placed {
            Placement::Omitted => continue,
            Placement::Order(order) => order.iter().flat_map(|s| gap.runs.iter().filter(move |(side, _)| side == s).map(|(_, r)| r)).collect(),
            Placement::After | Placement::Before => gap.runs.iter().map(|(_, r)| r).collect(),
        };
        if default.is_empty() {
            continue;
        }
        let firsts: Vec<Option<u64>> = default.iter().map(|r| ordinal_of(&r.origin, r.i_start)).collect();
        let lasts: Vec<Option<u64>> = default.iter().map(|r| ordinal_of(&r.origin, r.i_start + r.width.saturating_sub(1))).collect();
        let removed_whole = firsts.iter().chain(&lasts).all(Option::is_none);
        let placed: Vec<u64> = firsts.iter().flatten().copied().collect();
        let in_order = placed.windows(2).all(|w| w[0] < w[1]);
        if removed_whole || !in_order {
            for gaps in [&mut merged.record.gaps, &mut merged.composed.gaps] {
                if let Some(g) = gaps.get_mut(ix) {
                    g.settled = true;
                    g.resolved_by = Some(ResolvedBy::Person);
                }
            }
        }
    }
}

// ── The shapes, as the page reads them ───────────────────────────────────

/// Returns the report as `merge.compose` answers it (`shapes`' `MergeReport`).
fn report_json(merged: &lib::Merged, form: &Form, outcome: &str, extra: Value) -> Value {
    let mut v = json!({
        "outcome": outcome,
        "doc": merged.inputs.doc.to_string(),
        "head": merged.inputs.head.to_string(),
        "base": merged.record.base.to_string(),
        "side": form.side().to_string(),
        "form": form.name(),
        "sides": merged.record.sides.iter().map(side_json).collect::<Vec<_>>(),
        "runs": merged.composed.runs.iter().zip(&merged.families).map(|(p, f)| run_json(&p.run, p.side, *f)).collect::<Vec<_>>(),
        "gaps": merged.record.gaps.iter().map(gap_json).collect::<Vec<_>>(),
        "counts": {"a": merged.composed.counts.a, "b": merged.composed.counts.b, "m": merged.composed.counts.m},
        "cap": merged.cap,
        "over_cap": merged.composed.counts.m > merged.cap,
        "record": merged.record.to_value(),
        "as_of": merged.as_of,
    });
    if let Value::Object(members) = extra {
        for (k, value) in members {
            v[k] = value;
        }
    }
    v
}

fn side_json(side: &SideAt) -> Value {
    match side {
        SideAt::Member { at, role } => json!({"at": at.to_string(), "role": role.as_str(), "position": Value::Null}),
        SideAt::Draft { at, position } => json!({"at": at.to_string(), "role": Role::Draft.as_str(), "position": position}),
    }
}

fn run_json(run: &Run, side: Option<SideIx>, family: Family) -> Value {
    let family = match family {
        Family::Own => "own",
        Family::Window => "window",
        Family::DraftNative => "draft_native",
    };
    json!({"origin": run.origin.to_string(), "i_start": run.i_start, "width": run.width, "side": side.map(|s| s.0), "family": family})
}

fn gap_json(g: &Gap) -> Value {
    let kind = match g.kind {
        GapKind::Order => "order",
        GapKind::Anchor => "anchor",
        GapKind::Corner => "corner",
        GapKind::Cut => "cut",
        GapKind::Collision => "collision",
        GapKind::Moves => "moves",
    };
    let placed = match &g.placed {
        Placement::Order(sides) => Value::from(sides.iter().map(|s| s.0).collect::<Vec<u8>>()),
        Placement::After => Value::from("after"),
        Placement::Before => Value::from("before"),
        Placement::Omitted => Value::from("omitted"),
    };
    let resolved_by = match &g.resolved_by {
        None => Value::Null,
        Some(ResolvedBy::Rule) => Value::from("rule"),
        Some(ResolvedBy::Person) => Value::from("person"),
        Some(ResolvedBy::Agent) => Value::from("agent"),
        Some(ResolvedBy::Answer(a)) => Value::from(format!("answer:{a}")),
    };
    json!({
        "id": g.id.0,
        "kind": kind,
        "after": g.after.as_ref().map(ToString::to_string),
        "before": g.before.as_ref().map(ToString::to_string),
        "runs": g.runs.iter().map(|(side, run)| json!({"side": side.0, "i_start": run.address_at(0).map(|a| a.to_string()), "width": run.width})).collect::<Vec<_>>(),
        "placed": placed,
        "settled": g.settled,
        "resolved_by": resolved_by,
    })
}
