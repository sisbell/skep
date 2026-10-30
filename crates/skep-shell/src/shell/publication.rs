//! The publication rows of `client.md` §4b.1 — `publication.open`,
//! `publication.count`, `publication.confirm`, `publication.cancel` — and
//! the panels they stand on, each reached from [`Shell::call`] alone.
//!
//! THE FAMILY runs skep-client's publication composition for the page
//! (decision 1 (b)): the page composes no write (S-35 (a)); the shell
//! enumerates, holds the panel, counts, composes, signs and sends inside
//! `confirm`, and hands back DATA — every member a code, a kind or an
//! address, never a string a person reads (the strings `ux/copy.md`'s and
//! the UI lane's). `open` runs the library's `enumerate` → `panel` and
//! prices the request as it would stand with every private row OFF and
//! every window kept private — the widest request the default switches
//! make — and answers the panel `{rows, formatting, read_with, count,
//! price, windows, hold?}`; `count` answers the four numbers and the price
//! over the rows as switched, off the held panel, PURE LOCAL — no frame
//! sent, the price the open's request re-priced with the entries the
//! switches add, each end spelled by its stored slot's shape (an address
//! form, an I-span form, the member-position form for a span on the
//! draft's own words); `confirm` runs the re-read, the build, the price's
//! verdict, the send and the landed test, and answers ONCE with the
//! acknowledgment, the re-statement or a typed refusal; `cancel` drops the
//! standing panel, idempotent.
//!
//! **The panels** ([`Publications`]). One family per (board, principal): the
//! STANDING panel — the ceremony that stands, the one `count`, `confirm` and
//! `cancel` act on — and the HELD ones behind it, one per draft, which those
//! three never touch. An `open` on another draft puts the standing panel
//! behind it, held with the moment it was put there; an `open` on a held
//! draft with no selection, or the held one, re-opens it as it stands — the
//! switches and answers the page last sent it, `hold: {since}`, the windows
//! re-read and never from the read's cache — while a differing selection
//! ends the hold, the held answers lost, a fresh panel answered (item 1
//! (a)). Every panel records the session it was opened or last touched
//! under and dies with it: the bus's watcher ([`Publications::ended`])
//! drops a dead session's panels and says `ended` for each, whichever
//! thread met the death (§4b.1's one session rule; §4b.2).
//!
//! **Before any frame.** A bare session is refused `write_in_bare_session`
//! at `open` and at `confirm`, since a publication is a write and the
//! keyless session reads alone; a hold standing at the board — the own node
//! stopped, the write path poisoned, the writes halted — refuses `confirm`
//! at once with the hold's cause, never composing (§3c.4;
//! `Holds::unholdable_refusal`); the price's verdict refuses `over_cap`,
//! and a request changing nothing, a window unanswered or an origin to
//! publish first is `inert`. Every member of every call is read as
//! UNTRUSTED input: an address by §1.6's grammar within the component
//! budget, a switch by a row the panel holds, an answer by a window it
//! names, each refused `malformed_args` naming the member.
//!
//! **The base** is the shell's own read, never the page's: the trunk's
//! head member — the last registered `E.k`, walked from `E.1` where
//! `doc_metadata(E)` names a birth — and its content extent; an edition
//! with no member yet, or the mint form, is the birth shape.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use skep_address::Address;
use skep_client::address::is_address_text;
use skep_client::board::{frames, Answer, LinkSpan, LinkValue, Rejection};
use skep_client::halt::Halt;
use skep_client::publication::{self as lib, Ack, AckVia, Base, Built, Confirmed, Destination, Fault, Inert, Missing, OriginAnswer, OwnFault, Placement, Publisher, RaceKey, Refusal as PubRefusal, Restatement, RowKind, Sent, Switches, Term, Verdict};
use skep_client::sheet::render_inert;
use skep_client::sign::Signer;

use super::{optional, Shell};
use crate::events::EventBus;
use crate::feed::Searcher;
use crate::refusal::{Name, Refusal};
use crate::sessions::{self, SessionEntry, SessionKind};
use crate::wire::bounded_address;
use crate::EventName;

/// One panel the shell holds: the composition's first steps and what the
/// page last sent it.
#[derive(Debug, Clone)]
struct PanelState {
    /// The board reference the panel stands at.
    board: String,
    /// The session it was opened or last touched under; it dies with it.
    session: String,
    inputs: lib::Inputs,
    enumeration: lib::Enumeration,
    panel: lib::Panel,
    /// The request as built at the open — every private row OFF, every
    /// window kept private — whose runs, places and body pieces the count's
    /// price is taken over; `None` where that build was inert.
    base: Option<lib::Request>,
    /// The switches the page last sent (`count`, `confirm`).
    switches: Switches,
    /// The answers the page last sent, by the run's index in the selection.
    answers: BTreeMap<usize, OriginAnswer>,
    /// When the panel was put behind another, in unix milliseconds; `None`
    /// while it stands.
    since: Option<u64>,
}

impl PanelState {
    fn draft(&self) -> &Address {
        &self.inputs.draft
    }
}

/// One (board, principal)'s family: the standing panel and the held ones.
#[derive(Debug, Default)]
struct Family {
    standing: Option<PanelState>,
    held: Vec<PanelState>,
}

/// The panels the shell holds, by (board reference, principal).
#[derive(Debug, Default)]
pub(super) struct Publications {
    families: Mutex<BTreeMap<(String, u64), Family>>,
}

/// Returns the wall clock in unix milliseconds.
fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

impl Publications {
    /// Returns the standing panel of `key`'s family, cloned.
    fn standing(&self, key: &(String, u64)) -> Option<PanelState> {
        self.families.lock().expect("the panels' lock").get(key).and_then(|f| f.standing.clone())
    }

    /// Returns the panel of `draft` in `key`'s family — standing or held —
    /// cloned.
    fn of_draft(&self, key: &(String, u64), draft: &Address) -> Option<PanelState> {
        let families = self.families.lock().expect("the panels' lock");
        let family = families.get(key)?;
        family.standing.iter().chain(&family.held).find(|s| s.draft() == draft).cloned()
    }

    /// Makes `state` the standing panel of its family.
    ///
    /// A standing panel of another draft is put behind it, held from now;
    /// a held panel of `state`'s draft is replaced.
    fn stand(&self, key: (String, u64), state: PanelState) {
        let mut families = self.families.lock().expect("the panels' lock");
        let family = families.entry(key).or_default();
        family.held.retain(|s| s.draft() != state.draft());
        if let Some(mut standing) = family.standing.take() {
            if standing.draft() != state.draft() {
                standing.since = Some(now_ms());
                family.held.push(standing);
            }
        }
        family.standing = Some(state);
    }

    /// Drops the panel of `draft` in `key`'s family, standing or held.
    fn drop_draft(&self, key: &(String, u64), draft: &Address) {
        let mut families = self.families.lock().expect("the panels' lock");
        if let Some(family) = families.get_mut(key) {
            if family.standing.as_ref().is_some_and(|s| s.draft() == draft) {
                family.standing = None;
            }
            family.held.retain(|s| s.draft() != draft);
        }
    }

    /// Runs `f` over the standing panel of `key`'s family, where one stands.
    fn update(&self, key: &(String, u64), f: impl FnOnce(&mut PanelState)) {
        if let Some(state) = self.families.lock().expect("the panels' lock").get_mut(key).and_then(|f| f.standing.as_mut()) {
            f(state);
        }
    }

    /// Takes the standing panel of `key`'s family out, where one stands.
    fn take_standing(&self, key: &(String, u64)) -> Option<PanelState> {
        self.families.lock().expect("the panels' lock").get_mut(key).and_then(|f| f.standing.take())
    }

    /// Drops every panel that stood under `session_reference`, saying `ended`
    /// for each (§4b.2): the session died with the panel standing or held.
    pub(super) fn ended(&self, bus: &EventBus, session_reference: &str) {
        let gone: Vec<PanelState> = {
            let mut families = self.families.lock().expect("the panels' lock");
            let mut gone = Vec::new();
            for family in families.values_mut() {
                if family.standing.as_ref().is_some_and(|s| s.session == session_reference) {
                    gone.extend(family.standing.take());
                }
                let (dead, kept): (Vec<PanelState>, Vec<PanelState>) = std::mem::take(&mut family.held).into_iter().partition(|s| s.session == session_reference);
                family.held = kept;
                gone.extend(dead);
            }
            gone
        };
        for state in gone {
            bus.emit(EventName::Publication, json!({"board": state.board, "session": state.session, "draft": state.draft().to_string(), "state": "ended"}));
        }
    }
}

/// The signer and the account a session publishes as: the publisher's hand.
struct Signed {
    signer: Box<dyn Signer>,
    account: String,
}

impl Signed {
    fn publisher<'a>(&'a self, session: &'a SessionEntry) -> Publisher<'a> {
        Publisher { board: &session.board, token: &session.token, account: &self.account, signer: &*self.signer }
    }
}

/// Returns a call argument as an address in its one spelling, where it is one.
fn address_arg(v: &Value) -> Option<Address> {
    v.as_str().filter(|text| is_address_text(text)).and_then(bounded_address)
}

/// Returns a call argument as a list of addresses, where it is one.
fn addresses_arg(v: &Value) -> Option<Vec<Address>> {
    v.as_array()?.iter().map(address_arg).collect()
}

/// Returns a call argument as the selection's runs, where it is one.
///
/// Each is `{origin, i_start, width}`, the width at least one.
fn runs_arg(v: &Value) -> Option<Vec<lib::Run>> {
    v.as_array()?
        .iter()
        .map(|r| {
            let origin = address_arg(&r["origin"])?;
            let i_start = r["i_start"].as_u64()?;
            let width = r["width"].as_u64().filter(|w| *w > 0)?;
            Some(lib::Run::new(origin, i_start, width))
        })
        .collect()
}

/// Returns `text` cut to its first `n` bytes at a character boundary, with a
/// mark where it was cut: a board's answer in a refusal's detail.
fn clipped(text: &str, n: usize) -> String {
    if text.len() <= n {
        return text.to_string();
    }
    let mut end = n;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// Returns the content extent a `span_set` answer names.
fn extent_of(v: &Value) -> Option<u64> {
    if v["resp"].as_str() != Some("span_set") {
        return None;
    }
    v["set"].as_array()?.iter().map(|s| s["width"].as_str()?.rsplit('.').next()?.parse::<u64>().ok()).sum()
}

impl Shell {
    /// Returns the hand a session publishes with.
    ///
    /// # Errors
    ///
    /// Returns `write_in_bare_session` naming `call` where the session holds
    /// no key — the keyless session reads alone, and a publication is a
    /// write; `store_unreadable` where its key file cannot be read; and
    /// `no_account` where the board answered the session no account.
    fn signed(&self, session: &SessionEntry, call: &str) -> Result<Signed, Refusal> {
        let SessionKind::Signed { fingerprint, .. } = &session.facts.kind else {
            return Err(Refusal::shell(Name::WRITE_IN_BARE_SESSION, json!({"call": call})));
        };
        let signer = sessions::signer(&self.store, &self.store.key_path(fingerprint))?;
        let account = session.facts.account.clone().ok_or_else(|| Refusal::shell(Name::NO_ACCOUNT, json!({})))?;
        Ok(Signed { signer, account })
    }

    /// Returns the family's key for a session: its board and its principal.
    fn family_key(session: &SessionEntry) -> (String, u64) {
        (session.board_reference.clone(), session.facts.principal)
    }

    /// Makes one read under the session for the family's own reads.
    ///
    /// # Errors
    ///
    /// Returns the board's refusal or `unreachable`, and `session_died`
    /// where the read met the death signal, the session ended.
    fn family_read(&self, session: &SessionEntry, frame: &Value) -> Result<Value, Refusal> {
        match session.board.op(Some(&session.token), frame)? {
            Answer::Closed => Err(self.died(session)),
            Answer::Document(v) => Ok(v),
        }
    }

    /// Maps a composition's fault to the shell's refusal, the death ending
    /// the session.
    fn fault(&self, session: &SessionEntry, call: &str, fault: Fault) -> Refusal {
        match fault {
            Fault::Unreadable(doc) => Refusal::shell(Name::UNREADABLE, json!({"doc": doc.to_string()})),
            Fault::NoSuchDocument(doc) => Refusal::shell(Name::NO_SUCH_DOCUMENT, json!({"doc": doc.to_string()})),
            Fault::SessionEnded => self.died(session),
            Fault::Busy => Refusal::shell(Name::BUSY, json!({"call": call, "reissues": lib::SCAN_BUSY_REISSUES})),
            Fault::SelectionNotArranged { index } => Refusal::shell(Name::SELECTION_NOT_ARRANGED, json!({"index": index})),
            Fault::Shape { op, body } => Refusal::shell(Name::SHAPE, json!({"op": op, "body": body})),
            Fault::Halt(h) => Refusal::from(h),
        }
    }

    /// Returns the trunk's head member and its content extent: the base.
    ///
    /// It is `None` — the birth shape — where `doc_metadata(trunk)` names no
    /// birth; else the last registered `trunk.k`, walked from `k = 1`, with
    /// its `span_set` extent.
    ///
    /// # Errors
    ///
    /// Returns `unreadable` and `no_such_document` for the trunk, the board's
    /// other refusals verbatim, `unreachable`, and `session_died`.
    fn trunk_head(&self, session: &SessionEntry, trunk: &Address) -> Result<Option<(Address, u64)>, Refusal> {
        let trunk_text = trunk.to_string();
        let meta = self.family_read(session, &frames::doc_metadata(&trunk_text))?;
        if let Some(r) = Rejection::of(&meta) {
            return Err(match r.key() {
                "withheld" => Refusal::shell(Name::UNREADABLE, json!({"doc": trunk_text})),
                "doc_not_registered" => Refusal::shell(Name::NO_SUCH_DOCUMENT, json!({"doc": trunk_text})),
                _ => Refusal::from(r.refused(&meta)),
            });
        }
        if meta["birth"].is_null() {
            return Ok(None);
        }
        let mut head: Option<String> = None;
        for k in 1u64.. {
            let member = format!("{trunk_text}.{k}");
            let v = self.family_read(session, &frames::doc_metadata(&member))?;
            match Rejection::of(&v) {
                Some(r) if r.key() == "doc_not_registered" => break,
                Some(r) => return Err(Refusal::from(r.refused(&v))),
                None => head = Some(member),
            }
        }
        let Some(head) = head else { return Ok(None) };
        let set = self.family_read(session, &frames::span_set(&head))?;
        if let Some(r) = Rejection::of(&set) {
            return Err(Refusal::from(r.refused(&set)));
        }
        let extent = extent_of(&set).ok_or_else(|| Refusal::shell(Name::SHAPE, json!({"op": "retrieve_doc_v_span_set", "body": clipped(&set.to_string(), 200)})))?;
        let head = bounded_address(&head).ok_or_else(|| Refusal::shell(Name::SHAPE, json!({"op": "doc_metadata", "body": head})))?;
        Ok(Some((head, extent)))
    }

    /// Returns the draft's whole arrangement as I-runs: the selection where
    /// the page passes none (P1's select-all).
    ///
    /// # Errors
    ///
    /// Returns `unreadable`, `no_such_document`, the board's refusals,
    /// `unreachable`, `session_died`, and `shape` for an answer the shell
    /// cannot read.
    fn whole_draft(&self, session: &SessionEntry, draft: &Address) -> Result<Vec<lib::Run>, Refusal> {
        let text = draft.to_string();
        let refused = |r: &Rejection, v: &Value| -> Refusal {
            match r.key() {
                "withheld" => Refusal::shell(Name::UNREADABLE, json!({"doc": text})),
                "doc_not_registered" => Refusal::shell(Name::NO_SUCH_DOCUMENT, json!({"doc": text})),
                _ => Refusal::from(r.refused(v)),
            }
        };
        let set = self.family_read(session, &frames::span_set(&text))?;
        if let Some(r) = Rejection::of(&set) {
            return Err(refused(&r, &set));
        }
        let extent = extent_of(&set).ok_or_else(|| Refusal::shell(Name::SHAPE, json!({"op": "retrieve_doc_v_span_set", "body": clipped(&set.to_string(), 200)})))?;
        let mut runs: Vec<lib::Run> = Vec::new();
        // Read in parts past the run budget, halving on `image_too_large`.
        let mut pending = vec![(1u64, extent)];
        while let Some((from, width)) = pending.pop() {
            if width == 0 {
                continue;
            }
            let v = self.family_read(session, &frames::image(&text, from, width))?;
            if let Some(r) = Rejection::of(&v) {
                if r.key() == "image_too_large" && width > 1 {
                    let left = width / 2;
                    pending.push((from + left, width - left));
                    pending.push((from, left));
                    continue;
                }
                return Err(refused(&r, &v));
            }
            let shape = || Refusal::shell(Name::SHAPE, json!({"op": "image", "body": clipped(&v.to_string(), 200)}));
            for run in v["runs"].as_array().ok_or_else(shape)? {
                let i_start = run["i_start"].as_str().ok_or_else(shape)?;
                let w: u64 = run["width"].as_str().and_then(|w| w.parse().ok()).ok_or_else(shape)?;
                let (prefix, first) = i_start.rsplit_once('.').ok_or_else(shape)?;
                let first: u64 = first.parse().map_err(|_| shape())?;
                let origin = skep_client::address::document_of(i_start).and_then(|d| bounded_address(&d)).ok_or_else(shape)?;
                match runs.last_mut() {
                    Some(last) if last.chain() == prefix && last.reach() == first => last.width += w,
                    _ => runs.push(lib::Run::new(origin, first, w)),
                }
            }
        }
        Ok(runs)
    }

    /// Returns the shell's own lists off the document index: the person's
    /// drafts and their published documents, each under the session's
    /// account, in the listing's order.
    ///
    /// # Errors
    ///
    /// Returns `feed_stopped` once the board's feed thread has stopped.
    fn own_lists(&self, session: &Arc<SessionEntry>) -> Result<(Vec<Address>, Vec<Address>), Refusal> {
        let listing = self.feed(&session.board_reference).places(Searcher::Session(Arc::clone(session)), None)?;
        let account = session.facts.account.clone().unwrap_or_default();
        let (mut drafts, mut published) = (Vec::new(), Vec::new());
        for doc in listing["docs"].as_array().into_iter().flatten() {
            let Some(addr) = doc["doc"].as_str().and_then(bounded_address) else { continue };
            let text = addr.to_string();
            if !(text == account || text.starts_with(&format!("{account}."))) {
                continue;
            }
            match doc["kind"].as_str() {
                Some("draft") => drafts.push(addr),
                Some("edition") => published.push(addr),
                _ => {}
            }
        }
        Ok((drafts, published))
    }

    /// Emits the `publication` event (§4b.2) for `draft` under `session`.
    fn publication_event(&self, session: &SessionEntry, draft: &Address, state: &str, extra: Value) {
        let mut data = json!({"board": session.board_reference, "session": session.reference, "draft": draft.to_string(), "state": state});
        if let Value::Object(members) = extra {
            for (k, v) in members {
                data[k] = v;
            }
        }
        self.bus.emit(EventName::Publication, data);
    }

    /// Answers `publication.open(session, {draft, doc?, mint?, claim?,
    /// selection?, notes?, readable_drafts?, published?})` with the panel.
    ///
    /// The panel is `{rows, formatting, read_with, count, price, windows,
    /// hold?}` (the module doc): a held or standing panel of the draft
    /// re-opened as it stands where the selection is none or the same, its
    /// windows re-read; else the composition's first steps run afresh over
    /// the session's board, the base the shell's own read, the shell's own
    /// lists where the page passes none.
    ///
    /// # Errors
    ///
    /// In this order: `malformed_args` naming `session`, then
    /// `session_ended`; `malformed_args` naming `draft`, then each optional
    /// member present in another form, then `doc or mint` where neither is
    /// given and `mint` where both are; `write_in_bare_session` naming the
    /// call; `store_unreadable`, `no_account`; `feed_stopped` where the
    /// shell's own lists are owed and the board's feed thread has stopped;
    /// then the reads': `unreadable`, `no_such_document`, `busy`,
    /// `selection_not_arranged`, `shape`, the board's own verdicts verbatim,
    /// `unreachable`, and `session_died` where a read met the death signal.
    pub(super) fn publication_open(&self, args: &Value) -> Result<Value, Refusal> {
        // The row's own members first, each refused in another form before
        // the session is looked up — the order every row keeps.
        let doc = optional(args, "doc", address_arg)?;
        let mint = optional(args, "mint", address_arg)?;
        let claim = optional(args, "claim", Value::as_bool)?.unwrap_or(false);
        let selection = optional(args, "selection", runs_arg)?;
        let notes = optional(args, "notes", addresses_arg)?;
        let readable_drafts = optional(args, "readable_drafts", addresses_arg)?;
        let published = optional(args, "published", addresses_arg)?;
        let draft = address_arg(&args["draft"]).ok_or_else(|| Refusal::malformed("draft"))?;
        match (&doc, &mint) {
            (None, None) => return Err(Refusal::malformed("doc or mint")),
            (Some(_), Some(_)) => return Err(Refusal::malformed("mint")),
            _ => {}
        }
        let session = self.session(&args["session"])?;
        let signed = self.signed(&session, "publication.open")?;
        let key = Self::family_key(&session);
        // A panel of this draft standing or held: re-opened as it stands
        // where the selection is none or the one it holds (item 1 (a)).
        if let Some(mut state) = self.publications.of_draft(&key, &draft) {
            if selection.as_ref().is_none_or(|s| *s == state.inputs.selection) {
                let p = signed.publisher(&session);
                state.panel.windows = lib::windows(&p, &state.inputs).map_err(|f| self.fault(&session, "publication.open", f))?;
                let hold = state.since.map(|since| json!({"since": since}));
                state.session = session.reference.clone();
                state.since = None;
                let answer = panel_json(&state, hold);
                self.publications.stand(key, state);
                return Ok(answer);
            }
            // A differing selection ends the hold: the held answers lost.
            self.publications.drop_draft(&key, &draft);
        }
        let (own_drafts, own_published) = if readable_drafts.is_none() || published.is_none() { self.own_lists(&session)? } else { (Vec::new(), Vec::new()) };
        let selection = match selection {
            Some(s) => s,
            None => self.whole_draft(&session, &draft)?,
        };
        let base = match &doc {
            Some(trunk) => self.trunk_head(&session, trunk)?,
            None => None,
        };
        let mut readable_drafts = readable_drafts.unwrap_or(own_drafts);
        if !readable_drafts.contains(&draft) {
            readable_drafts.push(draft.clone());
        }
        let inputs = lib::Inputs { doc, mint, claim, base, draft: draft.clone(), selection, notes: notes.unwrap_or_default(), readable_drafts, published: published.unwrap_or(own_published) };
        let p = signed.publisher(&session);
        let fault = |f: Fault| self.fault(&session, "publication.open", f);
        let enumeration = lib::enumerate(&p, &inputs).map_err(fault)?;
        let panel = lib::panel(&p, &inputs, &enumeration).map_err(fault)?;
        let base = match lib::build(&p, &inputs, &enumeration, &panel, &pricing_confirmed(&panel)).map_err(fault)? {
            Built::Request(request) => Some(*request),
            Built::Inert(_) => None,
        };
        let state = PanelState { board: session.board_reference.clone(), session: session.reference.clone(), inputs, enumeration, panel, base, switches: Switches::default(), answers: BTreeMap::new(), since: None };
        let answer = panel_json(&state, None);
        self.publications.stand(key, state);
        Ok(answer)
    }

    /// Reads a `count` or `confirm` call's `switches` and `answers` in their
    /// form, before the session is looked up.
    ///
    /// # Errors
    ///
    /// Returns `malformed_args` naming `switches` where it is present and no
    /// object, `switches.on` where that is no list of addresses,
    /// `switches.destinations` where that is no object, and `answers` where
    /// it is no object of strings.
    fn confirmed_form(args: &Value) -> Result<(Vec<Address>, Map<String, Value>, Map<String, Value>), Refusal> {
        optional(args, "switches", |v| v.is_object().then_some(()))?;
        let on = optional(&args["switches"], "on", addresses_arg).map_err(|_| Refusal::malformed("switches.on"))?.unwrap_or_default();
        let destinations = optional(&args["switches"], "destinations", Value::as_object).map_err(|_| Refusal::malformed("switches.destinations"))?.cloned().unwrap_or_default();
        let answers = optional(args, "answers", |v| v.as_object().filter(|m| m.values().all(Value::is_string)))?.cloned().unwrap_or_default();
        Ok((on, destinations, answers))
    }

    /// Binds a call's `switches` and `answers`, read in their form, to the
    /// standing panel.
    ///
    /// # Errors
    ///
    /// Returns `malformed_args` naming `switches.on` (a home no private row
    /// of the panel holds), `switches.destinations` (a home no such row
    /// holds, a destination the row does not spell, or a set that is no
    /// published document of the person's), or `answers` (a run no window
    /// names, an answer the row does not spell, or `counterpart` where none
    /// was offered).
    fn confirmed_args(state: &PanelState, on: Vec<Address>, destinations: &Map<String, Value>, answers: &Map<String, Value>) -> Result<(Switches, BTreeMap<usize, OriginAnswer>), Refusal> {
        let switchable = |home: &Address| state.panel.rows.iter().any(|r| r.home == *home && !matches!(r.kind, RowKind::Public { .. }));
        let mut switches = Switches::default();
        for home in on {
            if !switchable(&home) {
                return Err(Refusal::malformed("switches.on"));
            }
            switches.on.insert(home);
        }
        for (home, destination) in destinations {
            let home = address_arg(&Value::from(home.as_str())).filter(|h| switchable(h)).ok_or_else(|| Refusal::malformed("switches.destinations"))?;
            let destination = match destination {
                Value::String(member) if member == "member" => Destination::Member,
                Value::Object(m) => {
                    let set = address_arg(&m["set"]).ok_or_else(|| Refusal::malformed("switches.destinations"))?;
                    if !state.inputs.published.contains(&set) {
                        return Err(Refusal::malformed("switches.destinations"));
                    }
                    Destination::Set(set)
                }
                _ => return Err(Refusal::malformed("switches.destinations")),
            };
            switches.destinations.insert(home, destination);
        }
        let mut bound = BTreeMap::new();
        for (run, answer) in answers {
            let run: usize = run.parse().map_err(|_| Refusal::malformed("answers"))?;
            let window = state.panel.windows.iter().find(|w| w.run == run).ok_or_else(|| Refusal::malformed("answers"))?;
            let answer = match answer.as_str() {
                Some("publish_first") => OriginAnswer::PublishFirst,
                Some("drop") => OriginAnswer::Drop,
                Some("keep_private") => OriginAnswer::KeepPrivate,
                Some("counterpart") if window.counterpart.is_some() => OriginAnswer::Counterpart,
                _ => return Err(Refusal::malformed("answers")),
            };
            bound.insert(run, answer);
        }
        Ok((switches, bound))
    }

    /// Answers `publication.count(session, {switches, answers})`.
    ///
    /// It answers `{count, price}` off the standing panel, pure local: the
    /// four numbers as the switches and the answers stand now, and the
    /// price re-run over the rows as switched (the module doc).
    ///
    /// # Errors
    ///
    /// In this order: the arguments' form (`confirmed_form`);
    /// `malformed_args` naming `session`, then `session_ended`; `no_panel`
    /// where no panel stands under the session's board and principal; then
    /// the arguments against the panel (`confirmed_args`).
    pub(super) fn publication_count(&self, args: &Value) -> Result<Value, Refusal> {
        let (on, destinations, raw_answers) = Self::confirmed_form(args)?;
        let session = self.session(&args["session"])?;
        let key = Self::family_key(&session);
        let mut state = self.publications.standing(&key).ok_or_else(|| Refusal::shell(Name::NO_PANEL, json!({"session": session.reference})))?;
        let (switches, answers) = Self::confirmed_args(&state, on, &destinations, &raw_answers)?;
        state.switches = switches.clone();
        state.answers = answers.clone();
        let count = lib::count(&state.panel, &state.switches, &state.inputs);
        let price = local_price(&state);
        let reference = session.reference.clone();
        self.publications.update(&key, |s| {
            s.switches = switches;
            s.answers = answers;
            s.session = reference;
        });
        Ok(json!({"count": count_json(&count), "price": price_json(&price)}))
    }

    /// Answers `publication.cancel(session)` with `{}`: the standing panel
    /// dropped, nothing sent, nothing written.
    ///
    /// A held panel of another draft stands; no panel standing answers `{}`
    /// all the same, and says nothing.
    ///
    /// # Errors
    ///
    /// Returns `malformed_args` naming `session`, then `session_ended`.
    pub(super) fn publication_cancel(&self, args: &Value) -> Result<Value, Refusal> {
        let session = self.session(&args["session"])?;
        let key = Self::family_key(&session);
        if let Some(state) = self.publications.take_standing(&key) {
            self.publication_event(&session, state.draft(), "cancelled", json!({}));
        }
        Ok(json!({}))
    }

    /// Answers `publication.confirm(session, {switches, answers})` with the
    /// acknowledgment, the re-statement or a typed refusal (the module doc).
    ///
    /// Inside the one call: the standing hold asked before anything is
    /// composed; the re-read, a difference answered as the re-statement with
    /// nothing sent and the panel re-stated for the next confirm; the build,
    /// an inert request refused `inert`; the price's verdict, `over_cap`; a
    /// claimed board whose head record cannot be read, `head_unreadable`;
    /// then `sent`, the library's send with its one re-ask, its re-sign and
    /// its landed test, a lost answer the board holds nothing of re-sent
    /// once; the outcome's event; and at the board's `kept_place_moved` the
    /// re-read run again in this call, its difference answered as the
    /// re-statement with the race's key, the refusal crossing only where it
    /// finds none. A death at the write ends the session: where the restart
    /// arm re-opens it the landed test runs under the new session before
    /// any re-send, else the `session_ended` arm, the panels gone with the
    /// session.
    ///
    /// # Errors
    ///
    /// In this order: the arguments' form (`confirmed_form`);
    /// `malformed_args` naming `session`, then `session_ended`; `no_panel`;
    /// the arguments against the panel (`confirmed_args`);
    /// `write_in_bare_session`; `stopped`, `poisoned` or `halted` where a
    /// hold stands at the board; `store_unreadable`, `no_account`; then the
    /// reads' and the send's faults as `publication.open` names them. A
    /// refusal of the composition or the board is the RESULT's third shape,
    /// never an error here.
    pub(super) fn publication_confirm(&self, args: &Value) -> Result<Value, Refusal> {
        let (on, destinations, raw_answers) = Self::confirmed_form(args)?;
        let session = self.session(&args["session"])?;
        let key = Self::family_key(&session);
        let state = self.publications.standing(&key).ok_or_else(|| Refusal::shell(Name::NO_PANEL, json!({"session": session.reference})))?;
        let (switches, answers) = Self::confirmed_args(&state, on, &destinations, &raw_answers)?;
        {
            let (switches, answers, reference) = (switches.clone(), answers.clone(), session.reference.clone());
            self.publications.update(&key, |s| {
                s.switches = switches;
                s.answers = answers;
                s.session = reference;
            });
        }
        let draft = state.draft().clone();
        let signed = self.signed(&session, "publication.confirm")?;
        if let Some(refusal) = self.holds.unholdable_refusal(&session.board_reference, "publish") {
            self.publication_event(&session, &draft, "refused", json!({"arm": refusal.name()}));
            return Err(refusal);
        }
        let inputs = &state.inputs;
        let p = signed.publisher(&session);
        let fault = |f: Fault| self.fault(&session, "publication.confirm", f);
        let rr = lib::reread(&p, inputs, &state.enumeration, &state.panel).map_err(fault)?;
        if let Some(restatement) = rr.restatement {
            let (enumeration, panel) = (rr.enumeration, rr.panel);
            self.publications.update(&key, |s| {
                s.enumeration = enumeration;
                s.panel = panel;
            });
            self.publication_event(&session, &draft, "restated", json!({}));
            return Ok(restated_json(&restatement, None));
        }
        let confirmed = Confirmed { switches, answers };
        let mut request = match lib::build(&p, inputs, &rr.enumeration, &rr.panel, &confirmed).map_err(fault)? {
            Built::Request(request) => *request,
            Built::Inert(inert) => {
                self.publication_event(&session, &draft, "refused", json!({"arm": "inert"}));
                return Ok(refused_json("inert", json!({"inert": inert_json(&inert)})));
            }
        };
        if !request.price.admits() {
            self.publication_event(&session, &draft, "refused", json!({"arm": "over_cap"}));
            return Ok(refused_json("over_cap", json!({"over": over_json(&request.price)})));
        }
        // Never unsigned on a claimed board: the library refuses it too, but
        // the check here keeps `sent` from being said of a frame that never
        // leaves.
        if session.board.board_term()?.is_none() && session.board.health()?.claimant().is_some() {
            self.publication_event(&session, &draft, "refused", json!({"arm": "head_unreadable"}));
            return Ok(refused_json("head_unreadable", json!({})));
        }
        self.publication_event(&session, &draft, "sent", json!({}));
        // The send, under the session that stands — re-opened once where the
        // death signal met the write and the restart arm let it.
        let mut current: Arc<SessionEntry> = Arc::clone(&session);
        let mut signed = signed;
        let mut sends = 0u32;
        let mut reopened = false;
        loop {
            sends += 1;
            let p = signed.publisher(&current);
            let sent = lib::send(&p, inputs, &mut request).map_err(|f| self.fault(&current, "publication.confirm", f))?;
            match sent {
                Sent::Acknowledged(ack) => return Ok(self.acknowledged(&current, &key, &draft, &ack)),
                Sent::NotLanded if sends < 2 => continue,
                Sent::NotLanded => {
                    let face = Halt::face("the acknowledgment was lost twice and the board holds nothing of the request", "the landed test found no member holding the request's runs after each lost answer", "confirm again: nothing was published");
                    let refusal = Refusal::from(face).to_value();
                    self.publication_event(&current, &draft, "refused", json!({"arm": "other"}));
                    return Ok(refused_json("other", json!({"refusal": refusal})));
                }
                Sent::Refused(PubRefusal::KeptPlaceMoved { index, race }) => {
                    let p = signed.publisher(&current);
                    let again = lib::reread(&p, inputs, &state.enumeration, &state.panel).map_err(|f| self.fault(&current, "publication.confirm", f))?;
                    return Ok(match again.restatement {
                        Some(restatement) => {
                            let (enumeration, panel) = (again.enumeration, again.panel);
                            self.publications.update(&key, |s| {
                                s.enumeration = enumeration;
                                s.panel = panel;
                            });
                            self.publication_event(&current, &draft, "restated", json!({}));
                            restated_json(&restatement, race.as_ref())
                        }
                        None => {
                            self.publication_event(&current, &draft, "refused", json!({"arm": "kept_place_moved"}));
                            refused_json("kept_place_moved", json!({"index": index, "race": race.as_ref().map(race_json)}))
                        }
                    });
                }
                Sent::Refused(PubRefusal::SessionEnded) if !reopened => {
                    reopened = true;
                    // The death at the write: the session ended by the one
                    // sequence — the panels under it gone with it, `ended`
                    // said by the bus's watcher — and re-opened where the
                    // restart arm lets it.
                    let died = self.died(&current).to_value();
                    let Some(next) = died["reason"]["session"].as_str().and_then(|r| self.sessions.get(r)) else {
                        return Ok(refused_json("session_ended", json!({"reason": died["reason"]})));
                    };
                    current = next;
                    signed = self.signed(&current, "publication.confirm")?;
                    let p = signed.publisher(&current);
                    let base = if request.runs.iter().any(|r| r.origin == inputs.draft) {
                        Base::Records
                    } else if request.mint.is_some() {
                        Base::EditionClaims
                    } else {
                        Base::Walk
                    };
                    match lib::landed(&p, inputs, &request, base).map_err(|f| self.fault(&current, "publication.confirm", f))? {
                        Verdict::Passed(ack) => return Ok(self.acknowledged(&current, &key, &draft, &ack)),
                        Verdict::NotFound => continue,
                        Verdict::Anothers { member, missing } => return Ok(self.refused(&current, &draft, PubRefusal::Twin { member, missing: Some(missing) })),
                        Verdict::MayAlreadyStand => return Ok(self.refused(&current, &draft, PubRefusal::MayAlreadyStand)),
                    }
                }
                Sent::Refused(refusal) => return Ok(self.refused(&current, &draft, refusal)),
            }
        }
    }

    /// Answers the acknowledgment: the standing panel dropped, the event said.
    fn acknowledged(&self, session: &SessionEntry, key: &(String, u64), draft: &Address, ack: &Ack) -> Value {
        self.publications.drop_draft(key, draft);
        self.publication_event(session, draft, "acknowledged", json!({"member": ack.member.to_string(), "edition": ack.edition.as_ref().map(ToString::to_string), "at": ack.at}));
        ack_json(ack)
    }

    /// Answers a typed refusal: the event said with its arm.
    fn refused(&self, session: &SessionEntry, draft: &Address, refusal: PubRefusal) -> Value {
        let (arm, members) = refusal_arm(&refusal);
        self.publication_event(session, draft, "refused", json!({"arm": arm}));
        refused_json(arm, members)
    }
}

/// Returns the confirmation the open prices with: every private row OFF,
/// every window kept private — the widest request the defaults make.
fn pricing_confirmed(panel: &lib::Panel) -> Confirmed {
    let answers = panel.windows.iter().map(|w| (w.run, OriginAnswer::KeepPrivate)).collect();
    Confirmed { switches: Switches::default(), answers }
}

/// Returns the price of the standing panel as switched, pure local.
///
/// It is the open's request with the entries the switches add — the
/// formatting line's marks into the member, each switched-on row's links
/// into its destination — the job list's retractions and the count's
/// read-withs, re-priced through the library's own price over the body as
/// built; `Price::default()`, which admits, where the open's build was
/// inert. An end is spelled by its stored slot's shape: the address form
/// where every span is a unit span, the member-position form where any
/// span lies on the draft's own words (priced as the request would spell
/// it), the I-span form otherwise — an upper bound, as the price is.
fn local_price(state: &PanelState) -> lib::Price {
    let Some(base) = &state.base else { return lib::Price::default() };
    let mut request = base.clone();
    let e = &state.enumeration;
    let panel = &state.panel;
    let draft_chain = format!("{}.0.1", state.inputs.draft);
    let spell = |slot: &[LinkSpan]| -> lib::End {
        if slot.is_empty() || slot.iter().all(LinkSpan::is_unit) {
            return lib::End::Addrs(slot.iter().map(|s| s.start.clone()).collect());
        }
        let spans: Vec<lib::ISpan> = slot.iter().filter_map(lib::ISpan::of).collect();
        if spans.len() != slot.len() {
            return lib::End::Addrs(slot.iter().map(|s| s.start.clone()).collect());
        }
        if spans.iter().any(|s| s.chain == draft_chain) {
            return lib::End::Member(spans.iter().map(|s| (s.first, s.width)).collect());
        }
        lib::End::Spans(spans)
    };
    let mut entries = Vec::new();
    let mut add = |candidate: usize, home: lib::EntryHome| {
        let c = &e.candidates[candidate];
        entries.push(lib::Entry { home, from: spell(&c.value.from), to: spell(&c.value.to), ty: spell(&c.value.ty), old: Some(c.link.clone()), candidate });
    };
    for &mark in &panel.formatting.marks {
        add(mark, lib::EntryHome::Member);
    }
    for row in &panel.rows {
        if matches!(row.kind, RowKind::Public { .. }) || !state.switches.on.contains(&row.home) {
            continue;
        }
        let home = match state.switches.destination(&row.home) {
            Destination::Member => lib::EntryHome::Member,
            Destination::Set(set) => lib::EntryHome::Set(set),
        };
        for &i in &row.links {
            add(i, home.clone());
        }
    }
    request.entries = entries;
    request.retract = panel.formatting.job_list().iter().map(|r| r.mark.clone()).collect();
    let count = lib::count(panel, &state.switches, &state.inputs);
    request.read_with = count.read_with.clone();
    request.count = count;
    let homes = e.homes.len() + state.inputs.published.iter().filter(|s| !e.homes.iter().any(|(h, _)| h == *s)).count();
    request.priced(homes, e.image.len())
}

// ── The shapes, as the page reads them ───────────────────────────────────

fn addresses_json(list: &[Address]) -> Value {
    Value::Array(list.iter().map(|a| Value::from(a.to_string())).collect())
}

fn span_json(s: &LinkSpan) -> Value {
    json!({"start": s.start, "width": s.width})
}

fn link_slots_json(v: &LinkValue) -> Value {
    json!({"from": v.from.iter().map(span_json).collect::<Vec<_>>(), "to": v.to.iter().map(span_json).collect::<Vec<_>>(), "ty": v.ty.iter().map(span_json).collect::<Vec<_>>(), "at": v.at})
}

fn ispan_json(s: &lib::ISpan) -> Value {
    json!({"chain": s.chain, "first": s.first, "width": s.width})
}

fn kind_json(kind: &RowKind) -> Value {
    match kind {
        RowKind::Own => json!("own"),
        RowKind::Notes => json!("notes"),
        RowKind::Private => json!("private"),
        RowKind::Public { read_with } => json!({"public": {"read_with": read_with}}),
    }
}

fn row_json(e: &lib::Enumeration, row: &lib::Row) -> Value {
    json!({
        "home": row.home.to_string(),
        "kind": kind_json(&row.kind),
        "label": render_inert(&String::from_utf8_lossy(&row.label)),
        "links": row.links.iter().map(|i| e.candidates[*i].link.to_string()).collect::<Vec<_>>(),
        "types": row.types.iter().map(|t| json!({"ty": t.ty, "n": t.n, "far": t.far})).collect::<Vec<_>>(),
        "line": {"p": row.line.p, "d": row.line.d, "c": row.line.c, "t": row.line.t, "u": row.line.u},
        "read_through": row.read_through,
    })
}

fn formatting_json(e: &lib::Enumeration, f: &lib::Formatting) -> Value {
    let removals: Vec<Value> = f
        .job_list()
        .iter()
        .map(|r| {
            json!({
                "record": r.record.to_string(),
                "mark": r.mark.to_string(),
                "mark_value": link_slots_json(&r.mark_value),
                "on_selection": r.on_selection,
                "spent": r.spent,
                "remake": r.remake.map(|i| e.candidates[i].link.to_string()),
            })
        })
        .collect();
    json!({"marks": f.marks.iter().map(|i| e.candidates[*i].link.to_string()).collect::<Vec<_>>(), "cut": f.cut, "removals": removals})
}

fn count_json(c: &lib::Count) -> Value {
    json!({"l": c.l, "n": c.n, "r": c.r, "e": c.e, "claim": c.claim, "read_with": addresses_json(&c.read_with)})
}

fn term_json(t: Term) -> &'static str {
    match t {
        Term::Runs => "runs",
        Term::Places => "places",
        Term::Links => "links",
        Term::Retract => "retract",
        Term::ReadWith => "read_with",
        Term::Body => "body",
        Term::Values => "values",
        Term::Reads => "reads",
        Term::Bytes => "bytes",
    }
}

fn over_json(p: &lib::Price) -> Value {
    Value::Array(p.over.iter().map(|(term, by)| json!({"term": term_json(*term), "by": by})).collect())
}

fn price_json(p: &lib::Price) -> Value {
    json!({"lists": p.lists, "body": p.body, "values": p.values, "reads": p.reads, "bytes": p.bytes, "over": over_json(p)})
}

fn window_json(w: &lib::Window) -> Value {
    let mut v = json!({"run": w.run, "origin": w.origin.to_string(), "owner": w.owner, "i_start": w.i_start, "width": w.width});
    if let Some(c) = &w.counterpart {
        v["counterpart"] = json!({"run": c.run, "draft": c.draft.to_string(), "record": c.record.to_string(), "from": ispan_json(&c.from), "to": ispan_json(&c.to)});
    }
    v
}

/// Returns the panel as `publication.open` answers it.
fn panel_json(state: &PanelState, hold: Option<Value>) -> Value {
    let e = &state.enumeration;
    let panel = &state.panel;
    let count = lib::count(panel, &state.switches, &state.inputs);
    let read_with: Map<String, Value> = panel.read_with.iter().map(|(set, stands)| (set.to_string(), Value::from(*stands))).collect();
    let mut v = json!({
        "rows": panel.rows.iter().map(|r| row_json(e, r)).collect::<Vec<_>>(),
        "formatting": formatting_json(e, &panel.formatting),
        "read_with": Value::Object(read_with),
        "count": count_json(&count),
        "price": price_json(&local_price(state)),
        "windows": panel.windows.iter().map(window_json).collect::<Vec<_>>(),
    });
    if let Some(hold) = hold {
        v["hold"] = hold;
    }
    v
}

fn via_json(via: AckVia) -> &'static str {
    match via {
        AckVia::Answer => "answer",
        AckVia::Twin => "twin",
        AckVia::Records => "records",
        AckVia::Walk => "walk",
        AckVia::EditionClaim => "edition_claim",
    }
}

/// Returns the acknowledgment as `publication.confirm` answers it.
fn ack_json(ack: &Ack) -> Value {
    json!({"outcome": "acknowledged", "member": ack.member.to_string(), "edition": ack.edition.as_ref().map(ToString::to_string), "claim": ack.claim, "at": ack.at, "via": via_json(ack.via)})
}

fn placement_json(p: &Placement) -> Value {
    match p {
        Placement::Whole { ordinal } => json!({"whole": {"ordinal": ordinal}}),
        Placement::Split(pieces) => json!({"split": pieces.iter().map(|(o, f, w)| json!([o, f, w])).collect::<Vec<_>>()}),
        Placement::Absent => json!("absent"),
    }
}

fn race_json(race: &RaceKey) -> Value {
    json!({"at": race.at, "key": race.key, "signed": race.signed})
}

/// Returns the re-statement as `publication.confirm` answers it.
fn restated_json(r: &Restatement, race: Option<&RaceKey>) -> Value {
    let mut v = json!({
        "outcome": "restated",
        "left": addresses_json(&r.left),
        "superseded": addresses_json(&r.superseded),
        "came": addresses_json(&r.came),
        "removals_undone": addresses_json(&r.removals_undone),
        "removals_came": addresses_json(&r.removals_came),
        "selection": r.selection.iter().map(|(run, placement)| json!({"run": run, "placement": placement_json(placement)})).collect::<Vec<_>>(),
    });
    if let Some(race) = race {
        v["race"] = race_json(race);
    }
    v
}

fn inert_json(inert: &Inert) -> Value {
    match inert {
        Inert::Unanswered(runs) => json!({"unanswered": runs}),
        Inert::PublishFirst(runs) => json!({"publish_first": runs}),
        Inert::Unchanged => json!("unchanged"),
    }
}

fn missing_json(m: &Missing) -> Value {
    match m {
        Missing::Copy(i) => json!({"copy": i}),
        Missing::Retraction(i) => json!({"retraction": i}),
    }
}

fn own_fault_json(f: &OwnFault) -> Value {
    match f {
        OwnFault::StrayPlace { index } => json!({"kind": "stray_place", "index": index}),
        OwnFault::Deposit { code, index, detail } => json!({"kind": "deposit", "code": code, "index": index, "detail": detail}),
        OwnFault::Shot { code } => json!({"kind": "shot", "code": code}),
        OwnFault::Attest { detail } => json!({"kind": "attest", "detail": detail}),
        OwnFault::Budget { detail } => json!({"kind": "budget", "detail": detail}),
    }
}

/// Returns a refusal's arm as the page faces it, and the arm's members.
fn refusal_arm(refusal: &PubRefusal) -> (&'static str, Value) {
    match refusal {
        PubRefusal::Twin { member, missing } => ("twin", json!({"member": member.to_string(), "missing": missing.as_ref().map(missing_json)})),
        PubRefusal::KeptPlaceMoved { index, race } => ("kept_place_moved", json!({"index": index, "race": race.as_ref().map(race_json)})),
        PubRefusal::UnownedDraft { draft } => ("unowned_draft", json!({"draft": draft.to_string()})),
        PubRefusal::NotOwner { addr } => ("not_owner", json!({"addr": addr.as_ref().map(ToString::to_string)})),
        PubRefusal::ClaimRefused { edition } => ("claim_refused", json!({"edition": edition.as_ref().map(ToString::to_string)})),
        PubRefusal::WindowWithheld { origin } => ("window_withheld", json!({"origin": origin.as_ref().map(ToString::to_string)})),
        PubRefusal::NeedsSignedSession => ("needs_signed_session", json!({})),
        PubRefusal::NoSuchDocument => ("no_such_document", json!({})),
        PubRefusal::OlderBoard { detail } => ("older_board", json!({"detail": detail})),
        PubRefusal::HeadUnreadable => ("head_unreadable", json!({})),
        PubRefusal::SessionEnded => ("session_ended", json!({})),
        PubRefusal::BudgetRace { detail } => ("budget_race", json!({"detail": detail})),
        PubRefusal::MayAlreadyStand => ("may_already_stand", json!({})),
        PubRefusal::OwnFault(fault) => ("own_fault", json!({"fault": own_fault_json(fault)})),
        PubRefusal::Other(halt) => ("other", json!({"refusal": Refusal::from(halt.clone()).to_value()})),
    }
}

/// Returns a refusal as `publication.confirm` answers it: `{outcome:
/// refused, arm, …}`, the arm's members beside it.
fn refused_json(arm: &str, members: Value) -> Value {
    let mut v = json!({"outcome": "refused", "arm": arm});
    if let Value::Object(members) = members {
        for (k, value) in members {
            v[k] = value;
        }
    }
    v
}
