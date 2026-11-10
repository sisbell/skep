//! The publication rows of `client.md` §4b.1 — `publication.open`,
//! `publication.count`, `publication.confirm`, `publication.cancel` — the
//! panels they stand on, and `publication.standing`, the read of a draft's
//! standing beside them, each reached from [`Shell::call`] alone.
//!
//! THE FAMILY runs skep-client's publication composition for the page
//! (decision 1 (b)): the page composes no write (S-35 (a)); the shell
//! enumerates, holds the panel, counts, composes, signs and sends inside
//! `confirm`, and hands back DATA — every member a code, a kind or an
//! address, never a string a person reads (the strings `ux/copy.md`'s and
//! the UI lane's). `open` reads the draft's base and types its standing
//! (**The base**), runs the library's `enumerate` → `panel` and prices the
//! request as it would stand with every private row OFF, every window part
//! a record names taken by its counterpart and every other kept private —
//! the widest request the default switches make — and answers the panel
//! `{rows, formatting, read_with, count, price, windows, parts, inherited,
//! merge_records, edition_links, p3_stands, standing?, head?, left_behind,
//! hold?}`
//! — each row with THE FOLD (E4 1.8): `unchanged` its links unchanged since
//! the recorded base by the fold's test, by address, `fold` the two counts,
//! links unchanged and not, and `changed_types` and `unchanged_types` the
//! links of each side folded by type with their far documents (E4 1.3), all
//! decided against the image of the member the request's `base` names, read
//! once at the open and kept for the confirm's re-read; `edition_links` how
//! many of the document's own links lie on the words the shot re-inserts,
//! read once at the open — the count of the link-sets design §5.2's line
//! for them, the shot leaving each on the draft's earlier words;
//! `p3_stands` whether P3 stands (E4 1.4), that count above zero among what
//! it stands on;
//! `windows` each
//! own-origin window in its PARTS, each part with the answers it admits
//! (B3-S11 P2 (i)), a window awaiting its answer counting toward nothing;
//! `parts` what each part's answer brings, the answered row's clause's
//! data;
//! `merge_records` the merge records the publication leaves out, per named
//! draft, since no publication publishes one;
//! `count` is THE CALL PER ANSWER: it re-keys the held panel by the
//! answers at the windows' parts — the rows and their candidates, the
//! formatting line, the windows, what each part's answer brings, each
//! row's fold and whether P3 stands — from the open's reads alone, and
//! answers `{count, price, rows, formatting, windows, parts, edition_links,
//! p3_stands}` with the four numbers and
//! the price over the rows as switched, PURE LOCAL — no frame sent, the
//! price the open's request re-priced with the entries the switches add,
//! each end spelled by its stored slot's shape (an address form, an I-span
//! form, the member-position form for a span on the draft's own words);
//! `confirm` runs the re-read, the build, the price's verdict, the send and
//! the landed test, and answers ONCE with the acknowledgment, the
//! re-statement — a moved base or standing, a window part named since, an
//! entry the board refused by its lineage among what it states — or a
//! typed refusal;
//! `cancel` drops the standing panel, idempotent.
//!
//! **The panels** ([`Publications`]). One family per (board, principal): the
//! STANDING panel — the ceremony that stands, the one `count`, `confirm` and
//! `cancel` act on — and the HELD ones behind it, one per draft, which those
//! three never touch. An `open` on another draft puts the standing panel
//! behind it, held with the moment it was put there; an `open` on a held
//! draft with no selection, or the held one, re-opens it as it stands — the
//! switches and answers the page last sent it, the base its first open
//! read and the family it left behind, `hold: {since}`, the base's standing
//! typed again and the windows re-read, never from the read's cache — where
//! a part's naming changed since, its origin published meanwhile, the
//! open's reads run again and the answers carried onto the parts as they
//! stand, one a part no longer admits asked again — while a differing
//! selection ends the hold, the held answers lost, a fresh panel answered
//! (item 1 (a)). Every panel records the session it was
//! opened or last touched under and dies with it: the bus's watcher
//! ([`Publications::ended`]) drops a dead session's panels and says `ended`
//! for each, whichever thread met the death (§4b.1's one session rule;
//! §4b.2).
//!
//! **Before any frame.** `open` and `confirm` meet the shell's one write
//! door through `Shell::signed` (`Shell::write_door`): a bare session is
//! refused `write_in_bare_session` at both, since a publication is a write
//! and the keyless session reads alone, and a session at a board whose held
//! store another shell holds `another_window` at both, the second window
//! reading alone there (§3c.3); `confirm`, which writes, meets the door's
//! other two questions as well — a hold standing at the board — the own
//! node stopped, the write path poisoned, the writes halted — refuses it at
//! once with the hold's cause, `publish` the op named, never composing
//! (§3c.4; `Holds::unholdable_refusal`), and a line of the principal's the
//! board has not kept standing on the rendering draft or on a draft `also`
//! names, in any state, refuses it `held_lines` naming that draft and the
//! count, nothing sent (§3c.4, THE HELD-LINES GATE; `Holds::held_lines`):
//! the shot would otherwise re-window the draft under words the person
//! typed and the board has not kept, and no path of the library's waits for
//! held lines before a shot. `open`, which writes nothing, meets neither.
//! The price's verdict refuses `over_cap`,
//! and a request changing nothing, a window unanswered or an origin to
//! publish first is `inert`. Every member of every call is read as
//! UNTRUSTED input: an address by §1.6's grammar within the component
//! budget, a switch by a row the panel holds, an answer by a window part it
//! holds, keyed `⟨run⟩.⟨part⟩`, and one the part admits — the counterpart
//! or `drop` where a record names its words, `publish_first`, `drop` or
//! `keep_private` where none does — each refused `malformed_args` naming
//! the member.
//!
//! **The lineage re-statement** (B3-S11 P4). Where the board refuses an
//! entry by its lineage — `old_refused`, `superseded` or `retracted`: its
//! words already carry its copy, or its original stands retracted —
//! `confirm` reads again with that original left out of the offer, keeps it
//! left out for the panel's later confirms, and answers `restated` with
//! `left_out` naming the entry, the original and the cause, and `race`
//! where a change of the person's since the request's reads explains it —
//! never the own-bug class alone, the formatting line having no switch.
//!
//! **The family** (the Nelson way, B3-S10; `client.md` §4b.1 item 60):
//! `draft` is the RENDERING draft — the draft whose arrangement the
//! selection renders, the home of the kept places and of the records for
//! its own identity — and `also`, optional, names the OTHER private drafts
//! of the person's own whose words the publication re-mints as the
//! document's own, each keeping its own records: the staging draft and the
//! alternatives made from it, never the notes document (Q1 (a)). The shell
//! reads `also` as it reads every member — addresses by §1.6's grammar, a
//! repeat or the `draft` among them `malformed_args` naming `also` — and
//! hands the list to the library, which treats a run of any named draft as
//! the document's own words: no window, the rendering draft's kept place
//! beside it and, per draft `also` names, that draft's own kept places off
//! its image (the wire's `also_places`), so the one write re-windows every
//! named draft at its own places (skep #739) — the shell composes nothing
//! of it — the statement's count answered as `inherited` in its place. A
//! named draft that moved a run since the panel is left as it stands at
//! that run and heals at its own next publication; one that moves it
//! between the re-read and the commit is the board's `kept_place_moved`
//! naming it. The panel is
//! keyed by the rendering draft alone (one standing panel per draft); a
//! draft named `also` may hold a panel of its own in the family, standing
//! or held, which this open leaves untouched.
//!
//! **The base** is the shell's own read off the board, never the page's
//! (B3-S10; `client.md` §4b.1 item 61): at the document form the library's
//! `draft_base` reads the base the board records for the draft — the
//! version its `stage` copied, `doc` itself while the chain is empty, moved
//! to the member each publication of the draft makes — and the extent the
//! copy took, off one `doc_metadata` of the draft. So a draft publishes
//! against the same base on every device and after any index is rebuilt:
//! after the version it was made from, or as that version's DAUGHTER where
//! the trunk has moved past it (PUB-2.44), never over the newer words.
//! Where the board records no base in `doc`'s chain, `open` refuses
//! `base_unrecorded` naming the draft, `doc` and the `reason` — `no_record`
//! (a draft minted and never staged), `other_chain` (a base in another
//! document's chain) or `free_standing` (an alternative of a draft the board
//! records no base for) — and never takes the chain's head in its place.
//! THE STANDING (D4 (a)+(b′), (d)) is that base typed against the chain's
//! head by the library's `standing` — a base under a trunk member `behind`
//! by its address (skep #807), the bare document by a read of its first
//! member and a trunk member by a read of the members past it — and told
//! before any act, never refused: `at_head`; `behind`, the shot landing the
//! base's daughter, with `head` the trunk's newest member, the one the
//! corner names; `first`, the bare document while its chain is empty; or
//! `superseded_first`, a draft begun from the bare document whose first
//! member now stands — the shot lands beside that member, as its daughter,
//! and the head does not move. `confirm` reads the base and types the
//! standing again beside its re-read. A base that differs from the panel's
//! in any way, member or extent — another publication of this draft, a
//! merge landed in it since — is re-stated with the new `base`, nothing
//! sent (D4 (b′); `Restated.base`), and the re-read and the panel are
//! composed on it for the next confirm: the claim composed again off the
//! marker (**The claim**) and, where the open read the whole draft, the
//! selection re-taken from the draft as it stands, since the draft's text
//! moved under "publish all of this draft" (P4's command; PUB-3.108's "what
//! the draft now arranges") — the re-statement's `selection` then empty, the
//! runs' indices no longer lining up, its answers carried by word where the
//! run index holds them and asked again where it does not, a draft emptied
//! since keeping the held runs, each re-stated absent, so the next confirm
//! refuses `selection_not_arranged` and no empty version lands. A selection
//! the page passed stays held and re-stated over what is left of it. A
//! standing moved since the panel — a sibling's shot landing while it
//! stood, `at_head` → `behind`, `first` → `superseded_first`, or a newer
//! head named while the draft stays `behind` — is re-stated with the new
//! `standing` and its `head`, nothing sent, and a base the board no longer
//! records is refused as at `open`. The request's `base` is the
//! member the panel was last read and tested against, the open's or the
//! moved one a re-statement named — the panel's fold and key (iii) decided
//! against its image — so the panel and the board's validation (3) test
//! one member by one rule. The reads run once the session stands and before
//! the index or the draft is read, so a refusal waits on neither; the mint
//! form has no chain and is the birth shape, with no standing. A `base` the
//! page sends is no member of the row and is read by nothing.
//!
//! **The claim** (the merge bridge lane; `client.md` §4b.1's merge row,
//! `land`; B3-S11's THE MERGE SCENE). At the document form the open reads
//! the draft's MERGE MARKER off the same board record — `doc_metadata`'s
//! `merge`, the sides a merge landed in the draft names, the head it was
//! composed on and the landing's position — and composes the request's
//! `supersede` from it: THE PUBLISHED DAUGHTERS among the marker's sides,
//! told from a private draft side by their address alone (a member of
//! `doc`'s own chain under a trunk member, which is published by
//! construction), and ONLY WHERE THE MARKER'S HEAD IS THE TRUNK'S HEAD AS
//! READ AT THE OPEN — a direct comparison: the marker's head a trunk member
//! of `doc` and one probe of the member after it answering
//! `doc_not_registered` — never inferred from the base's standing. So the
//! claim rides at a draft carrying a merge composed on the current head, on
//! every device and in any session alike, the marker being the board's and
//! never session memory; it never rides at an unmarked draft, at a marked
//! draft behind the head (B3-S11's "this draft's merge ends with it"), or
//! at a draft-side merge, whose side is a private draft no public claim
//! supersedes. The panel carries it as `count.supersede`, the
//! acknowledgment as `supersede`, what rode; a daughter an active claim of
//! the person's own already names is dropped by the library before the
//! body is signed, as the board's plan skips it. A head that moves under
//! the shot after the open is the board's to refuse, whole —
//! `supersede_refused` with `head_moved` — crossing as the typed arm of the
//! refusal, nothing re-sent (skep #806); the re-read before the send
//! re-states a moved standing first, so the race is met only between the
//! re-read and the commit. The marker is read again, and the claim composed
//! again from it, at a held panel's re-open with its standing, at a confirm
//! that finds the draft's base moved (**The base**) and at a `merge.land`
//! over a panel read under another marker (**The landing**).
//!
//! **The landing** (`merge.land`, B3-S11's THE MERGE SCENE; skep #949). The
//! panel the page left standing over the draft a composition landed in was
//! read under one merge marker: none where it was opened before the compose,
//! an earlier merge's where it was opened over one, and a re-open keeps the
//! marker with the selection it read. Where the draft now carries another,
//! the row keys the panel on the draft as it stands before the shot
//! (`Shell::landing_panel`), as a confirm on a moved base keys it: the base
//! read and typed again, the claim composed again from the marker, a panel
//! of the whole draft re-taking what the draft arranges, the draft side
//! named `also` as a panel the row opens itself names it, and the panel
//! read again whole. A panel of the whole draft then goes on to the shot in
//! the one call, what the merge changed being the person's own act, save
//! where the re-read's `came` names a link on a private row switched on: a
//! row ON publishes every link it holds, and that one the panel never
//! offered, so the re-statement goes first, `selection` and `parts` empty,
//! the runs' indices no longer lining up (PUB-3.108). A selection the page
//! passed stays held, and any difference, a moved base or standing among
//! them, is re-stated with nothing sent. A panel read under the marker the
//! draft carries lands as the open read it, its windows re-read where no
//! merge was marked at the open.
//!
//! **The family left behind** (skep #744): every draft `also` names, then —
//! where the publication becomes the head, its standing `at_head` or
//! `first` — every other draft of the person's own whose recorded base is
//! this draft's, by the library's `left_behind`, one `doc_metadata` per
//! draft of the shell's own list (the document index's drafts under the
//! session's account, read for it even where the page passes
//! `readable_drafts`). It is read at a fresh open alone: a re-opened panel
//! keeps the family it first left behind, and `confirm` reads it never.
//!
//! **The standing read** (`publication.standing`; skep #864) answers the
//! base, the standing and the family left behind apart from any panel, for
//! a corner that says where a draft stands before the person starts
//! publishing: it runs the reads above for the `draft`, `doc` and `also`
//! the page names, reads no image or link and composes nothing, holds
//! nothing — no panel stands after it and one standing is untouched — and
//! says no event. It is a read, so it asks the write door nothing and a
//! second window answers it; a session with no key is refused, since the
//! reads go through the same publisher's hand.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use skep_address::Address;
use skep_client::address::is_address_text;
use skep_client::board::{frames, merge_marker, Answer, LinkSpan, LinkValue, MergeMarker, Rejection};
use skep_client::halt::Halt;
use skep_client::publication::{self as lib, Ack, AckVia, Base, Built, Confirmed, Destination, Fault, Inert, LineageCause, Missing, OriginAnswer, OwedAnswer, OwnFault, PartKey, Placement, Publisher, RaceKey, Refusal as PubRefusal, Restatement, RowKind, Sent, Standing, SupersedeCause, Switches, Term, Unrecorded, Verdict};
use skep_client::sheet::render_inert;
use skep_client::sign::Signer;

use super::merge::{is_daughter, is_trunk_member, next_trunk_member};
use super::{optional, Shell, Write, Writer};
use crate::events::EventBus;
use crate::feed::Searcher;
use crate::refusal::{Name, Refusal};
use crate::sessions::{self, SessionEntry};
use crate::wire::bounded_address;
use crate::EventName;

/// One panel the shell holds: the composition's first steps and what the
/// page last sent it.
#[derive(Debug, Clone)]
pub(super) struct PanelState {
    /// The board reference the panel stands at.
    board: String,
    /// The session it was opened or last touched under; it dies with it.
    session: String,
    pub(super) inputs: lib::Inputs,
    /// The enumeration, composed under the answers that stand.
    pub(super) enumeration: lib::Enumeration,
    /// The panel, composed under the answers that stand.
    pub(super) panel: lib::Panel,
    /// The request as built at the open — every private row OFF, every
    /// window part a record names taken by its counterpart and every other
    /// kept private — whose runs, places and body pieces the count's price
    /// is taken over; `None` where that build was inert.
    base: Option<lib::Request>,
    /// The switches the page last sent (`count`, `confirm`).
    pub(super) switches: Switches,
    /// The answers the page last sent, by window part.
    pub(super) answers: BTreeMap<PartKey, OriginAnswer>,
    /// The originals left out of the offer: each one the board refused by
    /// its lineage at a confirm of this panel (B3-S11 P4).
    left_out: BTreeSet<Address>,
    /// When the panel was put behind another, in unix milliseconds; `None`
    /// while it stands.
    since: Option<u64>,
    /// The base's standing as last typed — at the open, at a re-open, at a
    /// confirm that re-stated it; `None` at the mint form.
    standing: Option<Standing>,
    /// The drafts of the family this publication leaves behind, as the open
    /// read them.
    left_behind: Vec<Address>,
    /// Whether the open read the whole draft, no selection passed.
    ///
    /// A base that moves re-takes it (the module doc, **The base**).
    whole: bool,
    /// The merge marker the draft carried when the selection was read, read
    /// before it; `None` at an unmarked draft and at the mint form.
    ///
    /// A re-open keeps it with the selection it holds; a confirm or a landing
    /// that keys the inputs on the draft as it stands replaces it (the module
    /// doc, **The landing**).
    marker: Option<MergeMarker>,
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

    /// Makes the panel of `draft` in `key`'s family the standing one, where
    /// one stands or is held, and returns it cloned — `merge.land`'s read of
    /// the panel the page opened over the draft its composition landed in.
    ///
    /// A held one is re-stood as it was put behind, its switches and answers
    /// kept and its session re-marked `session`; `None` where the family
    /// holds no panel of the draft.
    pub(super) fn stood_for(&self, key: &(String, u64), draft: &Address, session: &str) -> Option<PanelState> {
        let mut state = self.of_draft(key, draft)?;
        state.session = session.to_string();
        state.since = None;
        self.stand(key.clone(), state.clone());
        Some(state)
    }

    /// Makes `state` the standing panel of its family.
    ///
    /// A standing panel of another draft is put behind it, held from now;
    /// a held panel of `state`'s draft is replaced.
    pub(super) fn stand(&self, key: (String, u64), state: PanelState) {
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

/// The signer and the account a session publishes as: the publisher's hand
/// — and the merger's, which the `merge` family lends it to.
pub(super) struct Signed {
    pub(super) signer: Box<dyn Signer>,
    pub(super) account: String,
}

impl Signed {
    pub(super) fn publisher<'a>(&'a self, session: &'a SessionEntry) -> Publisher<'a> {
        Publisher { board: &session.board, token: &session.token, account: &self.account, signer: &*self.signer }
    }
}

/// Returns a call argument as an address in its one spelling, where it is one.
pub(super) fn address_arg(v: &Value) -> Option<Address> {
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
pub(super) fn clipped(text: &str, n: usize) -> String {
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
    /// Returns the hand a session publishes with, at the family's door.
    ///
    /// Every row of the publication and merge families and the restore
    /// takes it before any read or frame, so each meets the shell's one
    /// write door (`Shell::write_door`) with `write`, the row's write as the
    /// door reads it — the call its refusal names, the wire op the standing
    /// hold judges it by, the drafts it sets whole.
    ///
    /// # Errors
    ///
    /// In this order: the write door's, naming the call —
    /// `write_in_bare_session` where the session holds no key, the keyless
    /// session reading alone and a publication being a write; then
    /// `another_window` where another shell holds the held store of the
    /// session's board (§3c.3); then `stopped`, `poisoned` or `halted` where
    /// a hold stands at the board and the row's write is of a kind the hold
    /// never holds, naming that op; then `held_lines` naming the draft and
    /// the count where a draft the row writes whole holds lines of the
    /// principal's the board has not kept (§3c.4) — then
    /// [`Shell::signed_within_call`]'s.
    pub(super) fn signed(&self, session: &SessionEntry, write: Write<'_>) -> Result<Signed, Refusal> {
        self.write_door(Writer::Session(session), &write)?;
        self.signed_within_call(session, write.call_name())
    }

    /// Returns the hand of a session a call stands under past its door.
    ///
    /// It is the session the door admitted ([`Shell::signed`]), or the
    /// restart arm's re-open of it: a write that met the door is followed to
    /// its end — its landed test, its record — and not refused at it again.
    /// A read that asks no door takes it too, `publication.standing`, whose
    /// library reads stand on the publisher's hand.
    ///
    /// # Errors
    ///
    /// Returns `write_in_bare_session` naming `call` where the session holds
    /// no key; `store_unreadable` where its key file cannot be read; and
    /// `no_account` where the board answered the session no account.
    pub(super) fn signed_within_call(&self, session: &SessionEntry, call: &str) -> Result<Signed, Refusal> {
        let Some(fingerprint) = session.key() else {
            return Err(Refusal::shell(Name::WRITE_IN_BARE_SESSION, json!({"call": call})));
        };
        let signer = sessions::signer(&self.store, &self.store.key_path(fingerprint))?;
        let account = session.facts.account.clone().ok_or_else(|| Refusal::shell(Name::NO_ACCOUNT, json!({})))?;
        Ok(Signed { signer, account })
    }

    /// Returns the family's key for a session: its board and its principal.
    pub(super) fn family_key(session: &SessionEntry) -> (String, u64) {
        (session.board_reference.clone(), session.facts.principal)
    }

    /// Makes one read under the session for the family's own reads.
    ///
    /// # Errors
    ///
    /// Returns the board's refusal or `unreachable`, and `session_died`
    /// where the read met the death signal, the session ended.
    pub(super) fn family_read(&self, session: &SessionEntry, frame: &Value) -> Result<Value, Refusal> {
        match session.board.op(Some(&session.token), frame)? {
            Answer::Closed => Err(self.died(session)),
            Answer::Document(v) => Ok(v),
        }
    }

    /// Reads `doc_metadata(doc)` under the session, answering the document.
    ///
    /// # Errors
    ///
    /// Returns `unreadable` and `no_such_document` naming `doc` for the
    /// board's `withheld` and `doc_not_registered`, its other verdicts
    /// verbatim, `unreachable`, and `session_died` where the read met the
    /// death signal.
    pub(super) fn metadata_read(&self, session: &SessionEntry, doc: &Address) -> Result<Value, Refusal> {
        let text = doc.to_string();
        let v = self.family_read(session, &frames::doc_metadata(&text))?;
        match Rejection::of(&v) {
            Some(r) => Err(match r.key() {
                "withheld" => Refusal::shell(Name::UNREADABLE, json!({"doc": text})),
                "doc_not_registered" => Refusal::shell(Name::NO_SUCH_DOCUMENT, json!({"doc": text})),
                _ => Refusal::from(r.refused(&v)),
            }),
            None => Ok(v),
        }
    }

    /// Returns whether `head`, a trunk member of `doc`, is the trunk's head
    /// as the board stands: the member after it read and not registered.
    ///
    /// It is the one DIRECT comparison the claim rides on (the module doc,
    /// **The claim**): one `doc_metadata` of the next trunk member, never a
    /// standing typed off a base. A head that is no trunk member of `doc`
    /// stands as no head.
    ///
    /// # Errors
    ///
    /// The probe's: `unreadable` naming the member, the board's other
    /// verdicts verbatim, `unreachable`, `session_died`.
    pub(super) fn head_stands(&self, session: &SessionEntry, doc: &Address, head: &Address) -> Result<bool, Refusal> {
        if !is_trunk_member(doc, head) {
            return Ok(false);
        }
        let Some(next) = next_trunk_member(head) else { return Ok(false) };
        match self.metadata_read(session, &next) {
            Ok(_) => Ok(false),
            Err(Refusal::Shell { name, .. }) if name == Name::NO_SUCH_DOCUMENT => Ok(true),
            Err(e) => Err(e),
        }
    }

    /// Returns the merge marker a draft carries, off one `doc_metadata`.
    ///
    /// # Errors
    ///
    /// The draft's `doc_metadata` read's (`metadata_read`), `shape` where
    /// its answer is no `doc_metadata` answer.
    fn draft_marker(&self, session: &SessionEntry, draft: &Address) -> Result<Option<MergeMarker>, Refusal> {
        let v = self.metadata_read(session, draft)?;
        merge_marker(&v).ok_or_else(|| Refusal::shell(Name::SHAPE, json!({"op": "doc_metadata", "body": clipped(&v.to_string(), 200)})))
    }

    /// Returns the supersession claim a draft's publication carries: the
    /// published daughters `marker` — the draft's merge marker — names,
    /// where its head is the trunk's head as read now (the module doc,
    /// **The claim**).
    ///
    /// Empty at an unmarked draft, at a marked draft whose head the trunk
    /// has moved past, and at a draft-side merge, whose marker names no
    /// daughter; a side that is no member of `doc`'s chain under a trunk
    /// member — a private draft — is never claimed.
    ///
    /// # Errors
    ///
    /// The head probe's (`head_stands`).
    fn marker_claim(&self, session: &SessionEntry, doc: &Address, marker: Option<&MergeMarker>) -> Result<Vec<Address>, Refusal> {
        let Some(marker) = marker else { return Ok(Vec::new()) };
        let Some(head) = bounded_address(&marker.head) else { return Ok(Vec::new()) };
        if !self.head_stands(session, doc, &head)? {
            return Ok(Vec::new());
        }
        Ok(marker.sides.iter().filter_map(|s| bounded_address(s)).filter(|s| is_daughter(doc, s)).collect())
    }

    /// Maps a composition's fault to the shell's refusal, the death ending
    /// the session.
    pub(super) fn fault(&self, session: &SessionEntry, call: &str, fault: Fault) -> Refusal {
        match fault {
            Fault::Unreadable(doc) => Refusal::shell(Name::UNREADABLE, json!({"doc": doc.to_string()})),
            Fault::NoSuchDocument(doc) => Refusal::shell(Name::NO_SUCH_DOCUMENT, json!({"doc": doc.to_string()})),
            Fault::SessionEnded => self.died(session),
            Fault::Busy => Refusal::shell(Name::BUSY, json!({"call": call, "reissues": lib::SCAN_BUSY_REISSUES})),
            Fault::SelectionNotArranged { index } => Refusal::shell(Name::SELECTION_NOT_ARRANGED, json!({"index": index})),
            Fault::OnlyMergeRecords { draft } => Refusal::shell(Name::ONLY_MERGE_RECORDS, json!({"draft": draft.to_string()})),
            Fault::Shape { op, body } => Refusal::shell(Name::SHAPE, json!({"op": op, "body": body})),
            Fault::Halt(h) => Refusal::from(h),
        }
    }

    /// Returns `draft`'s base in `doc`'s chain with its extent, read off the
    /// board, and its standing against the chain's head (**The base**).
    ///
    /// Every standing is carried, none refused: `superseded_first` — the
    /// bare document as the base, its first member standing — lands the shot
    /// beside that member as its daughter, as `behind` lands it beside its
    /// base.
    ///
    /// # Errors
    ///
    /// In this order: the base's reads' faults, as `fault` maps them for
    /// `call`; `base_unrecorded` naming the draft, `doc` and the `reason`
    /// where the board records no base for the draft in `doc`'s chain; the
    /// standing's probe's faults.
    fn typed_base(&self, session: &SessionEntry, p: &Publisher<'_>, call: &str, doc: &Address, draft: &Address) -> Result<((Address, u64), Standing), Refusal> {
        let fault = |f: Fault| self.fault(session, call, f);
        let (base, copied) = match lib::draft_base(p, doc, draft).map_err(fault)? {
            lib::base::Base::Recorded { base, copied } => (base, copied),
            lib::base::Base::Unrecorded(why) => return Err(Refusal::shell(Name::BASE_UNRECORDED, json!({"draft": draft.to_string(), "doc": doc.to_string(), "reason": unrecorded_json(why)}))),
        };
        let standing = lib::standing(p, doc, &base).map_err(fault)?;
        Ok(((base, copied), standing))
    }

    /// Returns the draft's base and its standing read again for a panel that
    /// stands, the `publication` event saying `refused` for a base the board
    /// no longer records.
    ///
    /// # Errors
    ///
    /// [`Shell::typed_base`]'s.
    fn typed_base_again(&self, session: &SessionEntry, p: &Publisher<'_>, call: &str, doc: &Address, draft: &Address) -> Result<((Address, u64), Standing), Refusal> {
        self.typed_base(session, p, call, doc, draft).inspect_err(|refusal| {
            if matches!(refusal, Refusal::Shell { name, .. } if *name == Name::BASE_UNRECORDED) {
                self.publication_event(session, draft, "refused", json!({"arm": refusal.name()}));
            }
        })
    }

    /// Returns `state`'s inputs keyed on the draft as it stands: `base` its
    /// recorded base and `marker` its merge marker, each read again.
    ///
    /// A confirm comes here where `base` differs from the panel's (the module
    /// doc, **The base**), a landing where `marker` differs from the panel's
    /// (**The landing**). The claim is composed again off the marker, the
    /// head probed as the open probes it; and where the open read the whole
    /// draft the selection is the draft's whole arrangement as it stands, a
    /// draft emptied since keeping the held runs.
    ///
    /// # Errors
    ///
    /// The head probe's (`marker_claim`), then `whole_draft`'s.
    fn inputs_keyed(&self, session: &SessionEntry, state: &PanelState, trunk: &Address, base: (Address, u64), marker: Option<&MergeMarker>) -> Result<lib::Inputs, Refusal> {
        let mut inputs = state.inputs.clone();
        inputs.base = Some(base);
        inputs.supersede = self.marker_claim(session, trunk, marker)?;
        inputs.merge_landing = inputs.merge_landing || marker.is_some();
        if state.whole {
            let selection = self.whole_draft(session, state.draft())?;
            if !selection.is_empty() {
                inputs.selection = selection;
            }
        }
        Ok(inputs)
    }

    /// Returns the draft's whole arrangement as I-runs: the selection where
    /// the page passes none (P1's select-all).
    ///
    /// # Errors
    ///
    /// Returns `unreadable`, `no_such_document`, the board's refusals,
    /// `unreachable`, `session_died`, and `shape` for an answer the shell
    /// cannot read.
    pub(super) fn whole_draft(&self, session: &SessionEntry, draft: &Address) -> Result<Vec<lib::Run>, Refusal> {
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
    pub(super) fn own_lists(&self, session: &Arc<SessionEntry>) -> Result<(Vec<Address>, Vec<Address>), Refusal> {
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

    /// Answers `publication.open(session, {draft, also?, doc?, mint?, claim?,
    /// selection?, notes?, readable_drafts?, published?})` with the panel.
    ///
    /// The panel is `{rows, formatting, read_with, count, price, windows,
    /// parts, inherited, merge_records, edition_links, p3_stands, standing?,
    /// head?, left_behind, hold?}` (the module doc): a held or standing panel
    /// of the draft re-opened as it stands where the selection is none or the
    /// same,
    /// its base's standing typed again and its windows re-read (`also`, the
    /// base and the family left behind as it held them); else the draft's
    /// base read off the board and its standing
    /// typed (**The base**), the family it leaves behind read (**The family
    /// left behind**) and the composition's first steps run afresh over the
    /// session's board, the shell's own lists where the page passes none,
    /// the family's other drafts `also` names re-minted beside the rendering
    /// draft (**The family**). `standing` is absent at the mint form, and
    /// `left_behind` empty there.
    ///
    /// # Errors
    ///
    /// In this order:
    ///
    /// 1. `malformed_args` naming an optional member present in another
    ///    form — `doc`, `mint`, `claim`, `selection`, `notes`,
    ///    `readable_drafts`, `published`, then `also` for a list that is no
    ///    list of addresses — then naming `draft`, then `also` for a repeated
    ///    entry or the `draft` among them, then `doc or mint` where neither is
    ///    given and `mint` where both are;
    /// 2. `malformed_args` naming `session`, then `session_ended`;
    ///    `write_in_bare_session`, then `another_window`, naming the call;
    ///    `store_unreadable`, `no_account`;
    /// 3. a held or standing panel re-opened: at the document form its base
    ///    read and its standing typed again, refused as at step 4; then its
    ///    windows read's faults, as the reads' below;
    /// 4. at the document form, the base read's: `no_such_document` or
    ///    `unreadable` naming `doc` or the draft, `busy`, `session_died`,
    ///    `shape`, the board's own verdicts verbatim, `unreachable` — then
    ///    `base_unrecorded` naming the draft, `doc` and the `reason` where
    ///    the board records no base for the draft in `doc`'s chain; then the
    ///    standing's probe's, as the base read's — the standing itself is
    ///    told, whichever it is, a draft begun from the bare document whose
    ///    first member now stands told `superseded_first` and landing beside
    ///    that member as its daughter;
    /// 5. `feed_stopped` where the shell's own lists are owed — the page
    ///    passing no `readable_drafts` or no `published`, or the standing
    ///    `at_head` or `first` — and the board's feed thread has stopped;
    /// 6. the reads' — the draft's arrangement where no selection is passed,
    ///    the family left behind, the enumeration, the panel: `unreadable`,
    ///    `no_such_document`, `busy`, `selection_not_arranged`,
    ///    `only_merge_records` naming the draft where every position of the
    ///    selection holds a merge record, `shape`, the board's own verdicts
    ///    verbatim, `unreachable`, and `session_died` where a read met the
    ///    death signal.
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
        let also = optional(args, "also", addresses_arg)?.unwrap_or_default();
        let draft = address_arg(&args["draft"]).ok_or_else(|| Refusal::malformed("draft"))?;
        admit_also(&draft, &also)?;
        match (&doc, &mint) {
            (None, None) => return Err(Refusal::malformed("doc or mint")),
            (Some(_), Some(_)) => return Err(Refusal::malformed("mint")),
            _ => {}
        }
        let session = self.session(&args["session"])?;
        let signed = self.signed(&session, Write::unjudged("publication.open"))?;
        let key = Self::family_key(&session);
        let (state, hold) = self.open_panel(&session, &signed, OpenArgs { draft, also, doc, mint, claim, selection, notes, readable_drafts, published, merge_landing: false })?;
        let answer = panel_json(&state, hold);
        self.publications.stand(key, state);
        Ok(answer)
    }

    /// Opens the panel of `args.draft` under `session`, the open's own work
    /// past its arguments: the panel of the draft re-opened as it stands
    /// where the family holds one and the selection is none or the one it
    /// holds, with its standing typed again, its marker read again and its
    /// windows re-read — the hold's `{since}` beside it where it was held —
    /// else the composition's first steps run afresh (the module doc). The
    /// panel is answered, not stood: the caller stands it. `merge.land`
    /// opens the panel of the draft its composition landed in through it
    /// where the page opened none.
    ///
    /// # Errors
    ///
    /// Steps 3 to 6 of [`Shell::publication_open`]'s.
    pub(super) fn open_panel(&self, session: &Arc<SessionEntry>, signed: &Signed, args: OpenArgs) -> Result<(PanelState, Option<Value>), Refusal> {
        let OpenArgs { draft, also, doc, mint, claim, selection, notes, readable_drafts, published, merge_landing } = args;
        let key = Self::family_key(session);
        let p = signed.publisher(session);
        let fault = |f: Fault| self.fault(session, "publication.open", f);
        // A panel of this draft standing or held: re-opened as it stands
        // where the selection is none or the one it holds (item 1 (a)), its
        // base's standing typed again and its claim composed again off the
        // marker as it stands now.
        if let Some(mut state) = self.publications.of_draft(&key, &draft) {
            if selection.as_ref().is_none_or(|s| *s == state.inputs.selection) {
                if let Some(trunk) = &state.inputs.doc {
                    state.standing = Some(self.typed_base(session, &p, "publication.open", trunk, &draft)?.1);
                    let marker = self.draft_marker(session, &draft)?;
                    state.inputs.supersede = self.marker_claim(session, trunk, marker.as_ref())?;
                    state.inputs.merge_landing = state.inputs.merge_landing || merge_landing || marker.is_some();
                }
                // The windows re-read: where a part's naming changed — its
                // origin published meanwhile, or a merge landed since whose
                // windows are asked — the open's reads run again and the
                // answers are carried onto the parts as they stand, one no
                // longer admitted asked again.
                Self::reread_windows(&p, &mut state, fault)?;
                let hold = state.since.map(|since| json!({"since": since}));
                state.session = session.reference.clone();
                state.since = None;
                return Ok((state, hold));
            }
            // A differing selection ends the hold: the held answers lost.
            self.publications.drop_draft(&key, &draft);
        }
        // The base: the draft's own, read off the board and typed against
        // the chain's head — never the head where nothing names it; the
        // birth shape at the mint form, which has no chain to stand in. THE
        // CLAIM beside it: the marker's published daughters, where the
        // marker's head is the trunk's head (the module doc, **The claim**).
        let (base, standing, supersede, merge_landing, marker) = match &doc {
            Some(trunk) => {
                let (base, standing) = self.typed_base(session, &p, "publication.open", trunk, &draft)?;
                let marker = self.draft_marker(session, &draft)?;
                let supersede = self.marker_claim(session, trunk, marker.as_ref())?;
                (Some(base), Some(standing), supersede, merge_landing || marker.is_some(), marker)
            }
            None => (None, None, Vec::new(), merge_landing, None),
        };
        // The shell's own lists: where the page passes none, and for the
        // family this publication leaves behind where it becomes the head.
        let heads = matches!(standing, Some(Standing::AtHead | Standing::First));
        let (own_drafts, own_published) = if readable_drafts.is_none() || published.is_none() || heads { self.own_lists(session)? } else { (Vec::new(), Vec::new()) };
        let whole = selection.is_none();
        let selection = match selection {
            Some(s) => s,
            None => self.whole_draft(session, &draft)?,
        };
        let mut readable = readable_drafts.unwrap_or_else(|| own_drafts.clone());
        if !readable.contains(&draft) {
            readable.push(draft.clone());
        }
        let inputs = lib::Inputs { doc, mint, claim, base, draft: draft.clone(), also, selection, notes: notes.unwrap_or_default(), readable_drafts: readable, published: published.unwrap_or(own_published), supersede, merge_landing };
        let left_behind = match (&inputs.doc, &inputs.base, &standing) {
            (Some(trunk), Some((base, _)), Some(standing)) => lib::left_behind(&p, trunk, base, &inputs.draft, &inputs.also, standing, &own_drafts).map_err(fault)?,
            _ => Vec::new(),
        };
        let enumeration = lib::enumerate(&p, &inputs).map_err(fault)?;
        let panel = lib::panel(&p, &inputs, &enumeration).map_err(fault)?;
        let base = widest(&p, &inputs, &enumeration, &panel).map_err(fault)?;
        let state = PanelState { board: session.board_reference.clone(), session: session.reference.clone(), inputs, enumeration, panel, base, switches: Switches::default(), answers: BTreeMap::new(), left_out: BTreeSet::new(), since: None, standing, left_behind, whole, marker };
        Ok((state, None))
    }

    /// Re-reads the windows of `state`, the open's reads run again where a
    /// part's naming changed (the module doc): the panel is re-composed
    /// from those reads alone, the answers carried onto the parts as they
    /// stand, a run a re-statement showed at several places staying carried
    /// at as many.
    ///
    /// # Errors
    ///
    /// The reads' faults, as `fault` maps them.
    fn reread_windows(p: &Publisher<'_>, state: &mut PanelState, fault: impl Fn(Fault) -> Refusal) -> Result<(), Refusal> {
        let windows = lib::windows(p, &state.inputs).map_err(&fault)?;
        if !state.enumeration.renamed(&windows).is_empty() {
            let read = lib::enumerate_again(p, &state.inputs, &state.enumeration).map_err(&fault)?;
            state.answers = state.enumeration.answers_onto(&read.windows);
            state.enumeration = read.composed(&state.inputs, &state.answers, &state.left_out);
            state.panel = lib::panel(p, &state.inputs, &state.enumeration).map_err(&fault)?;
            state.base = widest(p, &state.inputs, &state.enumeration, &state.panel).map_err(&fault)?;
        }
        Ok(())
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
    /// The answers are bound first, since they decide the panel's rows: the
    /// switches are bound to the rows the panel holds as those answers
    /// compose it (`Panel::composed`), read off the open's reads alone.
    ///
    /// # Errors
    ///
    /// In this order: `malformed_args` naming `answers` (a key that is no
    /// `⟨run⟩.⟨part⟩` of a window part the panel holds, an answer the row
    /// does not spell, or one the part does not admit — keep-private or
    /// publish-first where a record names the part's words, the counterpart
    /// where none does); then naming `switches.on` (a home no private row of
    /// the panel so composed holds) or `switches.destinations` (a home no
    /// such row holds, a destination the row does not spell, or a set that
    /// is no published document of the person's).
    fn confirmed_args(state: &PanelState, on: Vec<Address>, destinations: &Map<String, Value>, answers: &Map<String, Value>) -> Result<(Switches, BTreeMap<PartKey, OriginAnswer>), Refusal> {
        let bound = Self::bound_answers(state, answers)?;
        let composed = state.enumeration.composed(&state.inputs, &bound, &state.left_out);
        let panel = state.panel.composed(&state.inputs, &composed);
        let switchable = |home: &Address| panel.rows.iter().any(|r| r.home == *home && !matches!(r.kind, RowKind::Public { .. }));
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
        Ok((switches, bound))
    }

    /// Binds the `answers` of a call to the window parts of `state`.
    ///
    /// # Errors
    ///
    /// `malformed_args` naming `answers`: a key that is no `⟨run⟩.⟨part⟩` of
    /// a window part the panel holds, an answer the row does not spell, or
    /// one the part does not admit — keep-private or publish-first where a
    /// record names the part's words, publish-first at another account's
    /// words, the counterpart where no record names them.
    pub(super) fn bound_answers(state: &PanelState, answers: &Map<String, Value>) -> Result<BTreeMap<PartKey, OriginAnswer>, Refusal> {
        let mut bound = BTreeMap::new();
        for (key, answer) in answers {
            let key = part_key(key).ok_or_else(|| Refusal::malformed("answers"))?;
            let part = state.enumeration.windows.iter().find(|w| w.run == key.run).and_then(|w| w.parts.get(key.part)).ok_or_else(|| Refusal::malformed("answers"))?;
            let answer = match answer.as_str() {
                Some("publish_first") => OriginAnswer::PublishFirst,
                Some("drop") => OriginAnswer::Drop,
                Some("keep_private") => OriginAnswer::KeepPrivate,
                Some("counterpart") => OriginAnswer::Counterpart,
                _ => return Err(Refusal::malformed("answers")),
            };
            if !part.admits(answer) {
                return Err(Refusal::malformed("answers"));
            }
            bound.insert(key, answer);
        }
        Ok(bound)
    }

    /// Answers `publication.count(session, {switches, answers})`.
    ///
    /// It answers `{count, price, rows, formatting, windows, parts,
    /// edition_links, p3_stands}` off the standing panel, pure local: the
    /// panel re-keyed by the answers at the windows' parts from the open's
    /// reads alone — the rows and their candidates with each row's fold and
    /// its two folds by type, the formatting line, the windows, what each
    /// part's answer brings, whether P3 stands — the four numbers as the
    /// switches and the answers stand now, and the price re-run over the
    /// rows as switched (the module doc).
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
        state.switches = switches;
        state.answers = answers;
        state.enumeration = state.enumeration.composed(&state.inputs, &state.answers, &state.left_out);
        state.panel = state.panel.composed(&state.inputs, &state.enumeration);
        let count = lib::count(&state.panel, &state.switches, &state.inputs);
        let answer = json!({
            "count": count_json(&count),
            "price": price_json(&local_price(&state)),
            "rows": state.panel.rows.iter().map(|r| row_json(&state.enumeration, r)).collect::<Vec<_>>(),
            "formatting": formatting_json(&state.enumeration, &state.panel.formatting),
            "windows": state.enumeration.windows.iter().map(window_json).collect::<Vec<_>>(),
            "parts": state.panel.parts.iter().map(part_counts_json).collect::<Vec<_>>(),
            "edition_links": state.panel.edition_links,
            "p3_stands": state.panel.p3_stands,
        });
        let reference = session.reference.clone();
        self.publications.update(&key, |s| {
            s.switches = state.switches;
            s.answers = state.answers;
            s.enumeration = state.enumeration;
            s.panel = state.panel;
            s.session = reference;
        });
        Ok(answer)
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

    /// Answers `publication.standing(session, {draft, doc, also?})` with
    /// `{base, standing, head?, left_behind}`.
    ///
    /// `base` is the draft's recorded base in `doc`'s chain, `standing` where
    /// it stands against `doc`'s newest version, `head` that newest version
    /// where the standing is `behind`, and `left_behind` the family the
    /// draft's publication would leave behind: `also`, then the drafts on
    /// its base where it would become the head (the module doc).
    ///
    /// # Errors
    ///
    /// In this order:
    ///
    /// 1. `malformed_args` naming `also` where it is no list of addresses,
    ///    then naming `draft`, then `doc`, then `also` for a repeated entry
    ///    or the `draft` among them;
    /// 2. `malformed_args` naming `session`, then `session_died` or
    ///    `session_ended` ([`Shell::session`]);
    /// 3. [`Shell::signed_within_call`]'s — `write_in_bare_session` naming
    ///    the call under a session with no key, then `store_unreadable`,
    ///    `no_account`;
    /// 4. the base read and the standing's, as `publication.open`'s step 4
    ///    names them: `no_such_document` or `unreadable` naming `doc` or
    ///    the draft, `busy`, `session_died`, `shape`, the board's own
    ///    verdicts verbatim, `unreachable`, and `base_unrecorded` naming the
    ///    draft, `doc` and the `reason` — a `doc` whose chain the draft's
    ///    base is not in among them;
    /// 5. `feed_stopped` where the standing is `at_head` or `first` and the
    ///    shell's own list of drafts is owed;
    /// 6. the family's reads, as the base read's.
    pub(super) fn publication_standing(&self, args: &Value) -> Result<Value, Refusal> {
        const CALL: &str = "publication.standing";
        let also = optional(args, "also", addresses_arg)?.unwrap_or_default();
        let draft = address_arg(&args["draft"]).ok_or_else(|| Refusal::malformed("draft"))?;
        let doc = address_arg(&args["doc"]).ok_or_else(|| Refusal::malformed("doc"))?;
        admit_also(&draft, &also)?;
        let session = self.session(&args["session"])?;
        let signed = self.signed_within_call(&session, CALL)?;
        let p = signed.publisher(&session);
        let ((base, _), standing) = self.typed_base(&session, &p, CALL, &doc, &draft)?;
        let own_drafts = if matches!(standing, Standing::AtHead | Standing::First) { self.own_lists(&session)?.0 } else { Vec::new() };
        let left_behind = lib::left_behind(&p, &doc, &base, &draft, &also, &standing, &own_drafts).map_err(|f| self.fault(&session, CALL, f))?;
        let mut answer = json!({"base": base.to_string(), "left_behind": addresses_json(&left_behind)});
        put_standing(&mut answer, &standing);
        Ok(answer)
    }

    /// Answers `publication.confirm(session, {switches, answers})` with the
    /// acknowledgment, the re-statement or a typed refusal (the module doc).
    ///
    /// Inside the one call: the standing hold asked before anything is
    /// composed; at the document form the draft's base read again and its
    /// standing typed again (**The base**); the panel composed under the
    /// answers and the re-read composed under them as they carry onto its
    /// windows, keyed on a base that moved, a difference — a moved base or
    /// standing among them, beside the enumeration's or alone, and a window
    /// part named since, whose answer is asked again unless it left the
    /// words out — answered as the re-statement with nothing sent and the
    /// panel re-stated for the next confirm; the build, a selection the
    /// draft has wholly left refused `selection_not_arranged` and an inert
    /// request refused `inert`; the price's verdict, `over_cap`; a head
    /// record that stands and cannot be read, or a claimed board that serves
    /// none, `head_unreadable` with the refusal that says why (SP-14); then
    /// `sent`, the library's send with its one re-ask, its re-sign and its
    /// landed test, a lost answer the board holds nothing of re-sent once;
    /// the outcome's event; and at the board's `kept_place_moved` — naming
    /// the draft that moved, the rendering draft or one `also` names — the
    /// re-read run again in this call, its difference answered as the
    /// re-statement with the race's key, the refusal, naming the draft,
    /// crossing only where it finds none; and at a refusal of an entry by
    /// its lineage, THE LINEAGE RE-STATEMENT (the module doc). A
    /// death at the write ends the session: where the restart arm re-opens
    /// it the landed test runs under the new session before any re-send,
    /// else the `session_ended` arm, the panels gone with the session.
    ///
    /// # Errors
    ///
    /// In this order: the arguments' form (`confirmed_form`);
    /// `malformed_args` naming `session`, then `session_ended`; `no_panel`;
    /// the arguments against the panel (`confirmed_args`);
    /// the write door's, in its order — `write_in_bare_session`, then
    /// `another_window`, then `stopped`, `poisoned` or `halted` naming
    /// `publish` where a hold stands at the board, then `held_lines` naming
    /// the draft and the count where the rendering draft or a draft `also`
    /// names holds lines of the principal's the board has not kept — then
    /// `store_unreadable`, `no_account`; at the document form the base's
    /// re-read and the standing's,
    /// refused as `publication.open`'s step 4 — `base_unrecorded` with the
    /// `publication` event's `refused` naming it (a base or a standing moved
    /// since the panel, `first` → `superseded_first` among them, is the
    /// re-statement, never a refusal, a moved base's own reads — its marker,
    /// the head probe, at a panel of the whole draft the draft's arrangement
    /// — failing as `publication.open`'s steps 4 and 6 name them); then the
    /// reads' and the send's faults as `publication.open` names them,
    /// `selection_not_arranged` naming run 0 among them where the draft
    /// arranges nothing of the held selection, the board term's read among
    /// them (`SessionEntry::signing_term`). A refusal of the composition or
    /// the board is the RESULT's third shape, never an error here.
    pub(super) fn publication_confirm(&self, args: &Value) -> Result<Value, Refusal> {
        let (on, destinations, raw_answers) = Self::confirmed_form(args)?;
        let session = self.session(&args["session"])?;
        let key = Self::family_key(&session);
        let state = self.publications.standing(&key).ok_or_else(|| Refusal::shell(Name::NO_PANEL, json!({"session": session.reference})))?;
        let (switches, answers) = Self::confirmed_args(&state, on, &destinations, &raw_answers)?;
        let draft = state.draft().clone();
        match self.confirm_standing(&session, &key, &state, switches, answers, "publication.confirm")? {
            Confirmation::Acknowledged { session, ack } => Ok(self.acknowledged(&session, &key, &draft, &ack)),
            Confirmation::Owed(owed) => Ok(refused_json("inert", json!({"inert": inert_json(&Inert::Unanswered(owed))}))),
            Confirmation::Answered(answer) => Ok(answer),
        }
    }

    /// Keys `state`, the page's panel over the draft a composition landed
    /// in, for `merge.land`, answering the re-statement the row answers in
    /// its place, where one is owed (the module doc, **The landing**).
    ///
    /// `side` is the composition's draft side, where it has one. A panel
    /// read under the merge marker the draft carries, and a mint-form panel,
    /// which stands in no chain and reads no marker, are left as they stand,
    /// the windows re-read where no merge was marked at the open. A panel
    /// read under another is keyed on the draft as it stands and read again
    /// whole, its answers carried onto what it reads now, and stood for the
    /// row to confirm. Its re-statement, the difference between the panel
    /// the page last held and this one, is owed where the page passed the
    /// selection, and at a panel of the whole draft only where the merge
    /// brought a link onto a private row the page switched on (PUB-3.108).
    /// Nothing is sent here.
    ///
    /// # Errors
    ///
    /// In this order, each naming `merge.land`, the composition's reads
    /// refused as `publication.open` refuses them: where the panel stands in
    /// a chain, the marker's read (`draft_marker`); then the windows' reads
    /// (`reread_windows`), or the keying's — the base's and the standing's
    /// (`typed_base`), `base_unrecorded` with the `publication` event's
    /// `refused` naming it, the head probe's (`marker_claim`), `whole_draft`'s,
    /// the re-read's and the pricing's.
    pub(super) fn landing_panel(&self, session: &SessionEntry, signed: &Signed, key: &(String, u64), state: &mut PanelState, side: Option<&Address>) -> Result<Option<Value>, Refusal> {
        let p = signed.publisher(session);
        let fault = |f: Fault| self.fault(session, "merge.land", f);
        let draft = state.draft().clone();
        let read = match state.inputs.doc.clone() {
            Some(trunk) => Some((trunk, self.draft_marker(session, &draft)?)),
            None => None,
        };
        let Some((trunk, marker)) = read.filter(|(_, marker)| *marker != state.marker) else {
            if !state.inputs.merge_landing {
                state.inputs.merge_landing = true;
                Self::reread_windows(&p, state, fault)?;
                self.publications.stand(key.clone(), state.clone());
            }
            return Ok(None);
        };
        let (base, standing) = self.typed_base_again(session, &p, "merge.land", &trunk, &draft)?;
        let mut inputs = self.inputs_keyed(session, state, &trunk, base, marker.as_ref())?;
        inputs.merge_landing = true;
        if let Some(side) = side.filter(|side| !inputs.also.contains(side)) {
            inputs.also.push(side.clone());
        }
        // The re-read against the panel as the page last held it, composed
        // under its own answers, as at a confirm.
        let held = Confirmed { switches: state.switches.clone(), answers: state.answers.clone(), left_out: state.left_out.clone() };
        let first = held.compose(&state.inputs, &state.enumeration);
        let first_panel = state.panel.composed(&state.inputs, &first);
        let rr = lib::reread(&p, &inputs, &first, &first_panel).map_err(fault)?;
        let mut restatement = rr.restatement;
        if Some(&standing) != state.standing.as_ref() {
            restatement.get_or_insert_with(Restatement::default).standing = Some(standing.clone());
        }
        if inputs.base != state.inputs.base {
            restatement.get_or_insert_with(Restatement::default).base = inputs.base.as_ref().map(|(member, _)| member.clone());
        }
        let owed = if state.whole {
            let switched_on = |row: &&lib::Row| !matches!(row.kind, RowKind::Public { .. }) && state.switches.on.contains(&row.home);
            let brought = |came: &[Address]| rr.panel.rows.iter().filter(switched_on).any(|row| row.links.iter().any(|&i| came.contains(&rr.enumeration.candidates[i].link)));
            restatement.filter(|r| brought(&r.came)).map(|mut r| {
                r.selection.clear();
                r.parts.clear();
                r
            })
        } else {
            restatement
        };
        state.answers = rr.enumeration.answers.clone();
        state.enumeration = rr.enumeration;
        state.panel = rr.panel;
        state.inputs = inputs;
        state.marker = marker;
        state.standing = Some(standing);
        state.base = match widest(&p, &state.inputs, &state.enumeration, &state.panel) {
            // Nothing of the selection stands to price; the build then
            // refuses it by name (`selection_not_arranged`).
            Err(Fault::SelectionNotArranged { .. }) => None,
            priced => priced.map_err(fault)?,
        };
        self.publications.stand(key.clone(), state.clone());
        Ok(owed.map(|restatement| {
            self.publication_event(session, &draft, "restated", json!({}));
            restated_json(&restatement, None, None)
        }))
    }

    /// Confirms the standing panel `state` with `switches` and `answers` —
    /// the one request composed, signed and sent — answering the
    /// acknowledgment with the session it was reached under, or the
    /// re-statement's or the typed refusal's answer as the row spells it
    /// (the module doc; [`Shell::publication_confirm`]). The panel is
    /// updated with the switches, the answers and the session; the
    /// acknowledgment's panel drop and event are the caller's
    /// ([`Shell::acknowledged`]), since `merge.land` writes the merge record
    /// between the two. `call` names the row for the refusals that name it.
    ///
    /// # Errors
    ///
    /// [`Shell::publication_confirm`]'s from `write_in_bare_session` on.
    pub(super) fn confirm_standing(&self, session: &Arc<SessionEntry>, key: &(String, u64), state: &PanelState, switches: Switches, answers: BTreeMap<PartKey, OriginAnswer>, call: &str) -> Result<Confirmation, Refusal> {
        {
            let (switches, answers, reference) = (switches.clone(), answers.clone(), session.reference.clone());
            self.publications.update(key, |s| {
                s.switches = switches;
                s.answers = answers;
                s.session = reference;
            });
        }
        let draft = state.draft().clone();
        let inputs = &state.inputs;
        // The one write door, over the shot: the rendering draft and every
        // draft `also` names are the drafts it sets whole. A refusal of the
        // board's or the drafts' state — a standing hold, held lines — is
        // the panel's `refused` event too, as the hold's was; the door's
        // first two name no state of the request's and say none.
        let write = Write::call(call, "publish").over(std::iter::once(&draft).chain(&inputs.also).map(ToString::to_string));
        let signed = match self.signed(session, write) {
            Ok(signed) => signed,
            Err(refusal) => {
                if matches!(&refusal, Refusal::Shell { name, .. } if [Name::STOPPED, Name::POISONED, Name::HALTED, Name::HELD_LINES].contains(name)) {
                    self.publication_event(session, &draft, "refused", json!({"arm": refusal.name()}));
                }
                return Err(refusal);
            }
        };
        let p = signed.publisher(session);
        let fault = |f: Fault| self.fault(session, call, f);
        // The base read again and its standing typed again (D4 (b′)): a base
        // the board no longer records is refused as at the open, by name; a
        // base or a standing that moved is re-stated below, a moved base
        // re-keying the panel on it.
        let (standing, moved) = match &inputs.doc {
            Some(trunk) => {
                let (base, standing) = self.typed_base_again(session, &p, call, trunk, &draft)?;
                let moved = if Some(&base) == inputs.base.as_ref() {
                    None
                } else {
                    let marker = self.draft_marker(session, &draft)?;
                    Some((self.inputs_keyed(session, state, trunk, base, marker.as_ref())?, marker))
                };
                (Some(standing), moved)
            }
            None => (None, None),
        };
        // The panel composed under the answers confirmed, and the re-read
        // composed under them as they carry onto its windows: the two
        // diffed over one composition (B3-S11 P4). The re-read of a moved
        // base runs over the inputs re-keyed on it, the panel's own for the
        // next confirm.
        let confirmed = Confirmed { switches, answers, left_out: state.left_out.clone() };
        let first = confirmed.compose(inputs, &state.enumeration);
        let first_panel = state.panel.composed(inputs, &first);
        let rr = lib::reread(&p, moved.as_ref().map_or(inputs, |(keyed, _)| keyed), &first, &first_panel).map_err(fault)?;
        // A moved base or standing rides the enumeration's re-statement
        // where one stands, or is re-stated alone; a re-taken selection's
        // own placements are no difference, its run indices the new list's.
        let mut restatement = rr.restatement;
        if standing != state.standing {
            restatement.get_or_insert_with(Restatement::default).standing = standing.clone();
        }
        if let Some((moved, _)) = &moved {
            let moved_base = restatement.get_or_insert_with(Restatement::default);
            moved_base.base = moved.base.as_ref().map(|(member, _)| member.clone());
            if moved.selection != inputs.selection {
                moved_base.selection.clear();
            }
        }
        if let Some(restatement) = restatement {
            // The answers as they carry onto the re-read's parts: one at a
            // part named, un-named or re-named since asked again, unless it
            // left the words out.
            let (enumeration, panel) = (rr.enumeration, rr.panel);
            self.publications.update(key, |s| {
                s.answers = enumeration.answers.clone();
                s.enumeration = enumeration;
                s.panel = panel;
                s.standing = standing;
                if let Some((moved, marker)) = moved {
                    s.inputs = moved;
                    s.marker = marker;
                }
            });
            self.publication_event(session, &draft, "restated", json!({}));
            return Ok(Confirmation::Answered(restated_json(&restatement, None, None)));
        }
        let mut request = match lib::build(&p, inputs, &rr.enumeration, &rr.panel, &confirmed).map_err(fault)? {
            Built::Request(request) => *request,
            Built::Inert(inert) => {
                self.publication_event(session, &draft, "refused", json!({"arm": "inert"}));
                return Ok(match inert {
                    Inert::Unanswered(owed) => Confirmation::Owed(owed),
                    other => Confirmation::Answered(refused_json("inert", json!({"inert": inert_json(&other)}))),
                });
            }
        };
        if !request.price.admits() {
            self.publication_event(session, &draft, "refused", json!({"arm": "over_cap"}));
            return Ok(Confirmation::Answered(refused_json("over_cap", json!({"over": over_json(&request.price)}))));
        }
        // Never unsigned where a signature is owed (SP-14): the library
        // refuses it too, but the check here keeps `sent` from being said of
        // a frame that never leaves.
        match self.holds.signing_term(session) {
            Ok(_) => {}
            Err(refusal @ Refusal::Halt { name: Name::HEAD_UNREADABLE, .. }) => {
                self.publication_event(session, &draft, "refused", json!({"arm": "head_unreadable"}));
                return Ok(Confirmation::Answered(refused_json("head_unreadable", json!({"refusal": refusal.to_value()}))));
            }
            Err(refusal) => return Err(refusal),
        }
        self.publication_event(session, &draft, "sent", json!({}));
        // The send, under the session that stands — re-opened once where the
        // death signal met the write and the restart arm let it.
        let mut current: Arc<SessionEntry> = Arc::clone(session);
        let mut signed = signed;
        let mut sends = 0u32;
        let mut reopened = false;
        loop {
            sends += 1;
            let p = signed.publisher(&current);
            let sent = lib::send(&p, inputs, &mut request).map_err(|f| self.fault(&current, call, f))?;
            match sent {
                Sent::Acknowledged(ack) => return Ok(Confirmation::Acknowledged { session: current, ack }),
                Sent::NotLanded if sends < 2 => continue,
                Sent::NotLanded => {
                    let face = Halt::face("the acknowledgment was lost twice and the board holds nothing of the request", "the landed test found no member holding the request's runs after each lost answer", "confirm again: nothing was published");
                    let refusal = Refusal::from(face).to_value();
                    self.publication_event(&current, &draft, "refused", json!({"arm": "other"}));
                    return Ok(Confirmation::Answered(refused_json("other", json!({"refusal": refusal}))));
                }
                Sent::Refused(PubRefusal::KeptPlaceMoved { index, draft: moved, race }) => {
                    let p = signed.publisher(&current);
                    let again = lib::reread(&p, inputs, &first, &first_panel).map_err(|f| self.fault(&current, call, f))?;
                    return Ok(Confirmation::Answered(match again.restatement {
                        Some(restatement) => {
                            let (enumeration, panel) = (again.enumeration, again.panel);
                            self.publications.update(key, |s| {
                                s.answers = enumeration.answers.clone();
                                s.enumeration = enumeration;
                                s.panel = panel;
                            });
                            self.publication_event(&current, &draft, "restated", json!({}));
                            restated_json(&restatement, race.as_ref(), None)
                        }
                        None => self.refused(&current, &draft, PubRefusal::KeptPlaceMoved { index, draft: moved, race }),
                    }));
                }
                // THE LINEAGE RE-STATEMENT (B3-S11 P4): the board refused an
                // entry by its lineage — its words already carry its copy, or
                // its original stands retracted. The enumeration is read
                // again with that original left out, and what the version
                // now publishes re-stated for a fresh confirmation, nothing
                // sent: never the own-bug face alone.
                Sent::Refused(PubRefusal::Lineage { index, original, cause, race }) => {
                    let p = signed.publisher(&current);
                    let mut left_out = confirmed.left_out.clone();
                    left_out.insert(original.clone());
                    let first = first.composed(inputs, &first.answers, &left_out);
                    let first_panel = first_panel.composed(inputs, &first);
                    let again = lib::reread(&p, inputs, &first, &first_panel).map_err(|f| self.fault(&current, call, f))?;
                    let restatement = again.restatement.unwrap_or_default();
                    let (enumeration, panel) = (again.enumeration, again.panel);
                    self.publications.update(key, |s| {
                        s.answers = enumeration.answers.clone();
                        s.left_out = left_out;
                        s.enumeration = enumeration;
                        s.panel = panel;
                    });
                    self.publication_event(&current, &draft, "restated", json!({}));
                    return Ok(Confirmation::Answered(restated_json(&restatement, race.as_ref(), Some((index, &original, cause)))));
                }
                Sent::Refused(PubRefusal::SessionEnded) if !reopened => {
                    reopened = true;
                    // The death at the write: the session ended by the one
                    // sequence — the panels under it gone with it, `ended`
                    // said by the bus's watcher — and re-opened where the
                    // restart arm lets it.
                    let died = self.died(&current).to_value();
                    let Some(next) = died["reason"]["session"].as_str().and_then(|r| self.sessions.get(r)) else {
                        return Ok(Confirmation::Answered(refused_json("session_ended", json!({"reason": died["reason"]}))));
                    };
                    current = next;
                    signed = self.signed_within_call(&current, call)?;
                    let p = signed.publisher(&current);
                    // The records base where any run is a named draft's —
                    // the rendering draft's or an `also` draft's — the
                    // library reading each draft's records in turn.
                    let base = if request.runs.iter().any(|r| inputs.is_named_draft(&r.origin)) {
                        Base::Records
                    } else if request.mint.is_some() {
                        Base::EditionClaims
                    } else {
                        Base::Walk
                    };
                    match lib::landed(&p, inputs, &request, base).map_err(|f| self.fault(&current, call, f))? {
                        Verdict::Passed(ack) => return Ok(Confirmation::Acknowledged { session: current, ack }),
                        Verdict::NotFound => continue,
                        Verdict::Anothers { member, missing } => return Ok(Confirmation::Answered(self.refused(&current, &draft, PubRefusal::Twin { member, missing: Some(missing) }))),
                        Verdict::MayAlreadyStand => return Ok(Confirmation::Answered(self.refused(&current, &draft, PubRefusal::MayAlreadyStand))),
                    }
                }
                Sent::Refused(refusal) => return Ok(Confirmation::Answered(self.refused(&current, &draft, refusal))),
            }
        }
    }

    /// Answers the acknowledgment: the standing panel dropped, the event said.
    pub(super) fn acknowledged(&self, session: &SessionEntry, key: &(String, u64), draft: &Address, ack: &Ack) -> Value {
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

/// The members of `publication.open` past the session, as the row reads
/// them: what [`Shell::open_panel`] opens a panel from.
pub(super) struct OpenArgs {
    /// The rendering draft.
    pub(super) draft: Address,
    /// The other drafts of the family whose words the shot re-mints.
    pub(super) also: Vec<Address>,
    /// The published document, at the document form.
    pub(super) doc: Option<Address>,
    /// The parent account, at the mint form.
    pub(super) mint: Option<Address>,
    /// Whether the one write carries the edition claim.
    pub(super) claim: bool,
    /// The selection; the whole draft where none.
    pub(super) selection: Option<Vec<lib::Run>>,
    /// The person's notes documents.
    pub(super) notes: Option<Vec<Address>>,
    /// The person's drafts the page lists, which no step of the composition
    /// reads; the shell's own list where none.
    pub(super) readable_drafts: Option<Vec<Address>>,
    /// The person's published documents; the shell's own list where none.
    pub(super) published: Option<Vec<Address>>,
    /// Whether the panel carries a merge the draft's marker may not name.
    pub(super) merge_landing: bool,
}

/// What [`Shell::confirm_standing`] answers.
pub(super) enum Confirmation {
    /// The request was acknowledged under `session` — the one the confirm
    /// began under, or the one re-opened in its place after a death at the
    /// write — and the panel still stands for the caller to drop
    /// ([`Shell::acknowledged`]).
    Acknowledged { session: Arc<SessionEntry>, ack: Ack },
    /// The window parts that need an answer: the row's refusal to say
    /// (`publication.confirm`'s `inert`, `merge.land`'s own).
    Owed(Vec<OwedAnswer>),
    /// The re-statement or the typed refusal, as the row answers it.
    Answered(Value),
}

/// Returns the confirmation the open prices with: every private row OFF,
/// every window part a record names taken by its counterpart and every
/// other kept private — the widest request the defaults make.
pub(super) fn pricing_confirmed(e: &lib::Enumeration) -> Confirmed {
    let answers = e.windows.iter().flat_map(|w| w.parts.iter().enumerate().map(move |(k, part)| (w.key(k), if part.named() { OriginAnswer::Counterpart } else { OriginAnswer::KeepPrivate }))).collect();
    Confirmed { switches: Switches::default(), answers, left_out: BTreeSet::new() }
}

/// Returns the request the open prices the count over: the widest the
/// defaults make (`pricing_confirmed`), `None` where it is inert.
///
/// # Errors
///
/// The build's faults.
fn widest(p: &Publisher<'_>, inputs: &lib::Inputs, e: &lib::Enumeration, panel: &lib::Panel) -> Result<Option<lib::Request>, Fault> {
    Ok(match lib::build(p, inputs, e, panel, &pricing_confirmed(e))? {
        Built::Request(request) => Some(*request),
        Built::Inert(_) => None,
    })
}

/// Refuses an `also` that does not name the family's other drafts.
///
/// # Errors
///
/// `malformed_args` naming `also` where it repeats a draft or names `draft`,
/// the rendering draft.
fn admit_also(draft: &Address, also: &[Address]) -> Result<(), Refusal> {
    if also.iter().enumerate().any(|(k, a)| a == draft || also[..k].contains(a)) {
        return Err(Refusal::malformed("also"));
    }
    Ok(())
}

/// Returns an answer's key, `⟨run⟩.⟨part⟩`, as the part it names.
fn part_key(text: &str) -> Option<PartKey> {
    let (run, part) = text.split_once('.')?;
    Some(PartKey { run: run.parse().ok()?, part: part.parse().ok()? })
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
    let job_list = panel.formatting.job_list();
    request.retract = job_list.iter().map(|r| r.mark.clone()).collect();
    request.originals = lib::originals_of(&job_list);
    let count = lib::count(panel, &state.switches, &state.inputs);
    request.read_with = count.read_with.clone();
    request.count = count;
    let homes = e.homes.len() + state.inputs.published.iter().filter(|s| !e.homes.iter().any(|(h, _)| h == *s)).count();
    request.priced(homes, e.image.len(), &e.also_run_counts())
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

pub(super) fn ispan_json(s: &lib::ISpan) -> Value {
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

/// Returns a row's fold by type as the row answers it.
fn type_folds_json(folds: &[lib::TypeFold]) -> Vec<Value> {
    folds.iter().map(|t| json!({"ty": t.ty, "n": t.n, "far": t.far})).collect()
}

fn row_json(e: &lib::Enumeration, row: &lib::Row) -> Value {
    json!({
        "home": row.home.to_string(),
        "kind": kind_json(&row.kind),
        "label": render_inert(&String::from_utf8_lossy(&row.label)),
        "links": row.links.iter().map(|i| e.candidates[*i].link.to_string()).collect::<Vec<_>>(),
        "types": type_folds_json(&row.types),
        "line": {"p": row.line.p, "d": row.line.d, "c": row.line.c, "t": row.line.t, "u": row.line.u},
        "read_through": row.read_through,
        "unchanged": row.links.iter().filter(|i| e.candidates[**i].unchanged).map(|i| e.candidates[*i].link.to_string()).collect::<Vec<_>>(),
        "fold": {"unchanged": row.fold.unchanged, "changed": row.fold.changed},
        "changed_types": type_folds_json(&row.changed_types),
        "unchanged_types": type_folds_json(&row.unchanged_types),
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
                "original": r.original.as_ref().map(|o| o.link.to_string()),
                "rest": r.original.as_ref().map(|o| o.rest.iter().map(ispan_json).collect::<Vec<_>>()).unwrap_or_default(),
            })
        })
        .collect();
    json!({"marks": f.marks.iter().map(|i| e.candidates[*i].link.to_string()).collect::<Vec<_>>(), "cut": f.cut, "removals": removals})
}

fn count_json(c: &lib::Count) -> Value {
    json!({"l": c.l, "n": c.n, "r": c.r, "e": c.e, "claim": c.claim, "read_with": addresses_json(&c.read_with), "supersede": addresses_json(&c.supersede)})
}

fn term_json(t: Term) -> &'static str {
    match t {
        Term::Runs => "runs",
        Term::Places => "places",
        Term::Links => "links",
        Term::Retract => "retract",
        Term::ReadWith => "read_with",
        Term::Originals => "originals",
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

/// Returns an answer as the page spells it.
pub(super) fn answer_json(answer: OriginAnswer) -> &'static str {
    match answer {
        OriginAnswer::PublishFirst => "publish_first",
        OriginAnswer::Drop => "drop",
        OriginAnswer::KeepPrivate => "keep_private",
        OriginAnswer::Counterpart => "counterpart",
    }
}

/// Returns a window as the panel answers it, each part with the answers it
/// admits and, where a record names its words, the record and the
/// counterpart.
fn window_json(w: &lib::Window) -> Value {
    let parts: Vec<Value> = w
        .parts
        .iter()
        .enumerate()
        .map(|(k, part)| {
            let admits: Vec<&str> = [OriginAnswer::Counterpart, OriginAnswer::PublishFirst, OriginAnswer::Drop, OriginAnswer::KeepPrivate].into_iter().filter(|a| part.admits(*a)).map(answer_json).collect();
            let mut v = json!({"part": k, "from": ispan_json(&part.span), "ordinal": part.ordinal, "admits": admits});
            if let (Some(record), Some(to)) = (&part.record, part.counterpart()) {
                v["record"] = json!(record.link.to_string());
                v["to"] = ispan_json(&to);
            }
            v
        })
        .collect();
    json!({"run": w.run, "origin": w.origin.to_string(), "owner": w.owner, "i_start": w.i_start, "width": w.width, "parts": parts})
}

/// Returns what one window part's answer brings, as the panel and the count
/// answer it: `{run, part, marks, links, kept_marks}`.
fn part_counts_json(c: &lib::PartCounts) -> Value {
    json!({"run": c.part.run, "part": c.part.part, "marks": c.marks, "links": c.links, "kept_marks": c.kept_marks})
}

/// Returns the statement's count for one draft `also` names, as the panel
/// answers it: `{draft, passages}`.
fn inherited_json(i: &lib::Inherited) -> Value {
    json!({"draft": i.draft.to_string(), "passages": i.passages})
}

/// Returns one named draft's merge records the publication leaves out, as
/// the panel answers them: `{draft, n}`.
fn merge_records_json(m: &lib::MergeRecords) -> Value {
    json!({"draft": m.draft.to_string(), "n": m.n})
}

/// Returns a base's standing as the panel and the re-statement spell it.
fn standing_json(s: &Standing) -> &'static str {
    match s {
        Standing::AtHead => "at_head",
        Standing::Behind { .. } => "behind",
        Standing::First => "first",
        Standing::SupersededFirst { .. } => "superseded_first",
    }
}

/// Sets a base's standing on an answer that carries it, the panel, the
/// re-statement or the standing read: `standing`, and at `behind` `head`,
/// the trunk's newest member.
fn put_standing(answer: &mut Value, s: &Standing) {
    answer["standing"] = json!(standing_json(s));
    if let Standing::Behind { head } = s {
        answer["head"] = json!(head.to_string());
    }
}

/// Returns why the board records no base as `base_unrecorded` names it.
fn unrecorded_json(why: Unrecorded) -> &'static str {
    match why {
        Unrecorded::NoRecord => "no_record",
        Unrecorded::OtherChain => "other_chain",
        Unrecorded::FreeStanding => "free_standing",
    }
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
        "windows": e.windows.iter().map(window_json).collect::<Vec<_>>(),
        "parts": panel.parts.iter().map(part_counts_json).collect::<Vec<_>>(),
        "inherited": panel.inherited.iter().map(inherited_json).collect::<Vec<_>>(),
        "merge_records": panel.merge_records.iter().map(merge_records_json).collect::<Vec<_>>(),
        "edition_links": panel.edition_links,
        "p3_stands": panel.p3_stands,
        "left_behind": addresses_json(&state.left_behind),
    });
    if let Some(standing) = &state.standing {
        put_standing(&mut v, standing);
    }
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
    json!({"outcome": "acknowledged", "member": ack.member.to_string(), "edition": ack.edition.as_ref().map(ToString::to_string), "claim": ack.claim, "supersede": addresses_json(&ack.supersede), "at": ack.at, "via": via_json(ack.via)})
}

/// Returns the acknowledgment's `via` as the rows spell it.
pub(super) fn via_name(via: AckVia) -> &'static str {
    via_json(via)
}

fn placement_json(p: &Placement) -> Value {
    match p {
        Placement::Whole { ordinal } => json!({"whole": {"ordinal": ordinal}}),
        Placement::Places(ordinals) => json!({"places": ordinals}),
        Placement::Split(pieces) => json!({"split": pieces.iter().map(|(o, f, w)| json!([o, f, w])).collect::<Vec<_>>()}),
        Placement::Absent => json!("absent"),
    }
}

fn race_json(race: &RaceKey) -> Value {
    json!({"at": race.at, "key": race.key, "signed": race.signed})
}

/// Returns the re-statement as `publication.confirm` answers it: with the
/// race's key where one follows the refusal, and the entry the board refused
/// by its lineage — its index, its original and the cause — where that
/// refusal left it out.
pub(super) fn restated_json(r: &Restatement, race: Option<&RaceKey>, lineage: Option<(u64, &Address, LineageCause)>) -> Value {
    let mut v = json!({
        "outcome": "restated",
        "left": addresses_json(&r.left),
        "superseded": addresses_json(&r.superseded),
        "came": addresses_json(&r.came),
        "removals_undone": addresses_json(&r.removals_undone),
        "removals_came": addresses_json(&r.removals_came),
        "selection": r.selection.iter().map(|(run, placement)| json!({"run": run, "placement": placement_json(placement)})).collect::<Vec<_>>(),
    });
    if !r.parts.is_empty() {
        v["parts"] = json!(r.parts.iter().map(|(key, record)| json!({"run": key.run, "part": key.part, "record": record.as_ref().map(ToString::to_string)})).collect::<Vec<_>>());
    }
    if let Some((entry, original, cause)) = lineage {
        v["left_out"] = json!([{"entry": entry, "original": original.to_string(), "cause": cause.token()}]);
    }
    if let Some(race) = race {
        v["race"] = race_json(race);
    }
    if let Some(base) = &r.base {
        v["base"] = json!(base.to_string());
    }
    if let Some(standing) = &r.standing {
        put_standing(&mut v, standing);
    }
    v
}

/// Returns the sets each private row OFF leaves private, with their counts,
/// the panel composed under `answers` (the merge record's §1.5: `merge.land`
/// names each set left private after the act).
pub(super) fn left_private_json(state: &PanelState, answers: &BTreeMap<PartKey, OriginAnswer>, switches: &Switches) -> Value {
    let composed = state.enumeration.composed(&state.inputs, answers, &state.left_out);
    let panel = state.panel.composed(&state.inputs, &composed);
    Value::Array(panel.rows.iter().filter(|r| !matches!(r.kind, RowKind::Public { .. }) && !switches.on.contains(&r.home) && !r.links.is_empty()).map(|r| json!({"set": r.home.to_string(), "links": r.links.len()})).collect())
}

fn inert_json(inert: &Inert) -> Value {
    match inert {
        Inert::Unanswered(owed) => json!({"unanswered": owed.iter().map(|o| json!({"run": o.part.run, "part": o.part.part, "named": o.named})).collect::<Vec<_>>()}),
        Inert::PublishFirst(parts) => json!({"publish_first": parts.iter().map(|k| json!({"run": k.run, "part": k.part})).collect::<Vec<_>>()}),
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
        OwnFault::StrayPlace { index, draft } => json!({"kind": "stray_place", "index": index, "draft": draft.to_string()}),
        OwnFault::Deposit { code, index, detail } => json!({"kind": "deposit", "code": code, "index": index, "detail": detail}),
        OwnFault::Shot { code } => json!({"kind": "shot", "code": code}),
        OwnFault::Attest { detail } => json!({"kind": "attest", "detail": detail}),
        OwnFault::Budget { detail } => json!({"kind": "budget", "detail": detail}),
    }
}

/// Returns a refusal's arm as the page faces it, and the arm's members.
pub(super) fn refusal_arm(refusal: &PubRefusal) -> (&'static str, Value) {
    match refusal {
        PubRefusal::Twin { member, missing } => ("twin", json!({"member": member.to_string(), "missing": missing.as_ref().map(missing_json)})),
        PubRefusal::KeptPlaceMoved { index, draft, race } => ("kept_place_moved", json!({"index": index, "draft": draft.to_string(), "race": race.as_ref().map(race_json)})),
        PubRefusal::UnownedDraft { draft } => ("unowned_draft", json!({"draft": draft.to_string()})),
        PubRefusal::NotOwner { addr } => ("not_owner", json!({"addr": addr.as_ref().map(ToString::to_string)})),
        PubRefusal::ClaimRefused { edition } => ("claim_refused", json!({"edition": edition.as_ref().map(ToString::to_string)})),
        PubRefusal::SupersedeRefused { index, cause } => {
            let head = match cause {
                SupersedeCause::HeadMoved { head } => head.as_ref().map(ToString::to_string),
                _ => None,
            };
            ("supersede_refused", json!({"index": index, "detail": cause.token(), "head": head}))
        }
        PubRefusal::WindowWithheld { origin } => ("window_withheld", json!({"origin": origin.as_ref().map(ToString::to_string)})),
        PubRefusal::NeedsSignedSession => ("needs_signed_session", json!({})),
        PubRefusal::NoSuchDocument => ("no_such_document", json!({})),
        PubRefusal::OlderBoard { detail } => ("older_board", json!({"detail": detail})),
        PubRefusal::HeadUnreadable => ("head_unreadable", json!({})),
        PubRefusal::SessionEnded => ("session_ended", json!({})),
        PubRefusal::BudgetRace { detail } => ("budget_race", json!({"detail": detail})),
        PubRefusal::MayAlreadyStand => ("may_already_stand", json!({})),
        PubRefusal::BaseSuperseded { first } => ("base_superseded", json!({"first": first.to_string()})),
        // The confirm answers a lineage refusal by its re-statement
        // (`Shell::confirm_standing`); the arm's members are its own.
        PubRefusal::Lineage { index, original, cause, race } => ("lineage", json!({"index": index, "original": original.to_string(), "cause": cause.token(), "race": race.as_ref().map(race_json)})),
        PubRefusal::OwnFault(fault) => ("own_fault", json!({"fault": own_fault_json(fault)})),
        PubRefusal::Other(halt) => ("other", json!({"refusal": Refusal::from(halt.clone()).to_value()})),
    }
}

/// Returns a refusal as `publication.confirm` answers it: `{outcome:
/// refused, arm, …}`, the arm's members beside it.
pub(super) fn refused_json(arm: &str, members: Value) -> Value {
    let mut v = json!({"outcome": "refused", "arm": arm});
    if let Value::Object(members) = members {
        for (k, value) in members {
            v[k] = value;
        }
    }
    v
}
