//! THE SHOT's WINDOW PARTS — what the merge's one shot answers at a window
//! of the merged list (the merge record's §1.5).
//!
//! The merge lands on the trunk with one shot from the head, and it writes
//! no draft first, so its window runs are found here and composed through
//! the publication family's one core ([`parts`](crate::publication::parts)):
//! each `Family::Window` origin's state read once, a published origin not
//! asked, every other origin's records read, its runs cut into parts at
//! their edges, each part's answer composed. The caller gives its answers
//! ([`Answers`]) by the key a person reads — a part a record names by the
//! version that publishes its words, ⟨E.j⟩ ([`WindowPart::version`]), any
//! other part by its origin — and no answer is composed for it: with a part
//! unanswered, or an answer that fits nothing, the step refuses before the
//! landing's first write, every part named whole
//! ([`Refusal::WindowPartsOwed`]). The refusal is final in meaning and the
//! same for every caller: `skep merge --publish`, the shell's `merge.land`
//! through [`owed_parts`], and an agent's merge tool once one lands.
//!
//! **What the step reads** (the reads of §1.5 in their order): one
//! `doc_metadata` per distinct window origin at the head, other than a draft
//! the landing names, whose words the shot re-mints; each unpublished
//! origin's records in that origin's own account (`Record::of`), a window
//! onto another account's origin among them, none where the origin answers
//! `withheld`, since a registered private document this merger may not read
//! gives up no words and no records; the feed row of each record's commit
//! for the version it names; and the first and last words of each part the
//! refusal or the acknowledgment says.
//!
//! **Where a part stands.** A part's own place is its M-ordinal. The words
//! it stands after are read off M, the merged text, since the shot lands in
//! no draft; at the draft landing [`owed_parts`] reads them off the draft.
//!
//! **The re-read.** Just before the send the records are read again
//! ([`recheck`]): a part named, un-named or named by another record since
//! its answer was given, whose answer does not carry ([`answers_onto`]), is
//! refused again with nothing published (PUB-3.108). A leave-out carries.
//!
//! **The answered list** ([`applied`]). What a composition places, what the
//! read-first compares a member with and what a record's verification
//! recomputes are one function of M and the recorded answers, so a landing
//! whose parts were answered reads as landed and verifies `Equal`. A part
//! kept private stays in M's own words, a part windowed becomes the words
//! its record names — the document's own when they lie in its chain, whose
//! bytes the shot signs by value, read through the window's own span — and
//! a part left out is gone.
//!
//! **The draft's kept places** ([`kept_places`]; wire.md §The publish shot
//! and head-float, the kept places). A shot that renders a draft side sends
//! beside each run of the draft's words the place the draft holds it at, so
//! the one commit re-windows the draft onto the published words and leaves it
//! showing none of them as its own (the link-sets design §5.7 (viii); B3-S11
//! P5). The runs that take a place are the draft's own words the shot
//! re-mints and a part answered by its counterpart, whose words the draft
//! holds as a window ([`AnsweredRun::takes_a_place`]); the trunk's words, a
//! plain window and a part kept private take none, as the board refuses a
//! place beside them (`stray_place_unrecorded`). The places are read off the
//! draft's own image at the composition's one position, never another
//! side's, so M's coalescing is undone where the draft cuts a run: one run of
//! M the draft holds at two places goes out as two, each at its own place,
//! and no place is named twice. What the draft does not arrange takes none.
//!
//! The merged list's words are the person's document's, and every word a
//! refusal says comes back as data (SP-10); the program that embeds this
//! library says them, rendered inert (SP-15).

use std::collections::BTreeMap;

use skep_address::Address;

use crate::address::{account_of, parse_address};
use crate::board::answers::IRun;
use crate::halt::Halt;
use crate::publication::parts::{composed_parts, origin_state, parts_of, window_records, OriginState};
use crate::publication::{self, answers_onto, compose_part, owned_by, renamed, Door, Fault, ISpan, OriginAnswer as Answer, OwedAnswer, PartComposition, PartKey, Publisher, Window};

use super::compose::{Item, PlacedRun, Run, SideIx};
use super::land::{own_fault_face, Merger, Writer};
use super::reads::{content_prefix, session_ended, values_for, Family, Merged, Refusal, Side};
use super::record::{PartAnswer, RecordedAnswer};

/// The positions read for a part's first words, or for the words before it.
const WORDS_READ: u64 = 64;

/// The most words a passage's first words hold.
const WORDS_SHOWN: usize = 8;

/// The most characters a passage's words are cut to.
const WORDS_BOUND: usize = 200;

/// The caller's answers at a shot's window parts (the merge record's §7).
///
/// Each answer is keyed by what the person reads: a part a record names by
/// the version that publishes its words (⟨E.j⟩), any other part by its
/// origin. No answer stands for "all", and none is given for the caller.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Answers {
    /// Window the published words a record names: by ⟨E.j⟩.
    pub window: Vec<Address>,
    /// Leave the words out: by ⟨E.j⟩ where a record names them, by ⟨origin⟩
    /// where none does.
    pub leave_out: Vec<Address>,
    /// Keep the words behind a placeholder: by ⟨origin⟩.
    pub keep_private: Vec<Address>,
}

/// One part as a refusal or an acknowledgment names it (the merge record's
/// §1.5, THE SHOT's WINDOW PARTS).
///
/// It is facts alone (SP-10): the words, the pair and the answers, the sides
/// showing the placeholder and the owner; the embedder says them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowPart {
    /// The part: `run` the run of M, or of the draft's selection at the
    /// panel's route, and `part` its place in the run's window.
    pub key: PartKey,
    /// The part's first words; `None` where this merger may not read them.
    pub words: Option<String>,
    /// The words it stands after in the merged text.
    ///
    /// `None` at the merged text's start; an empty text where the words
    /// before it are ones this merger may not read.
    pub after: Option<String>,
    /// The part's first position in the merged list, from 1.
    pub ordinal: u64,
    /// The part's origin.
    pub origin: Address,
    /// The origin's owner, where it is not the merger.
    pub owner: Option<String>,
    /// The part's words, on the origin's chain.
    pub span: ISpan,
    /// The record that names the part's words as published, where one does.
    pub record: Option<Address>,
    /// The published words the record names, ⟨E.j⟩'s span of them.
    pub counterpart: Option<ISpan>,
    /// ⟨E.j⟩, the member the record's commit minted; the document its `to`
    /// lies in where the feed no longer holds the commit's row.
    pub version: Option<Address>,
    /// Each published side showing the part as a placeholder: the head, a
    /// daughter, or both.
    pub sides: Vec<Address>,
    /// The answers the part admits, in the panel's order.
    pub admits: Vec<Answer>,
    /// The answer given, where one stands.
    pub answer: Option<Answer>,
    /// Whether a record named the part only after its answer was given.
    pub named_since: bool,
}

/// One of the three answers a caller gives by key ([`Answers`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    /// [`Answers::window`].
    Window,
    /// [`Answers::leave_out`].
    LeaveOut,
    /// [`Answers::keep_private`].
    KeepPrivate,
}

/// An answer the caller gave that a part of the merge cannot take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Misfit {
    /// The answer fits no part of this merge.
    FitsNothing {
        /// The answer given.
        flag: Flag,
        /// Its key.
        key: Address,
        /// Where the key is an origin all of whose words in this merge a
        /// record names as published: the versions that publish them.
        published_in: Vec<Address>,
    },
    /// Two answers name the same words.
    TwoAnswers {
        /// The first of the two answers.
        first: Flag,
        /// The second.
        second: Flag,
        /// The key both name.
        key: Address,
    },
}

/// The shot's window parts as the step composed them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ShotParts {
    /// M's windows, in their parts, as first read.
    pub(super) windows: Vec<Window>,
    /// The answers standing at their parts.
    pub(super) answered: BTreeMap<PartKey, Answer>,
    /// The list the shot places ([`applied`]).
    pub(super) runs: Vec<AnsweredRun>,
    /// Each answer as the record keeps it.
    pub(super) recorded: Vec<PartAnswer>,
    /// Each answer as the acknowledgment says it.
    pub(super) given: Vec<WindowPart>,
}

impl ShotParts {
    /// Returns the text naming the shot's writes (the `land` module's doc).
    ///
    /// It is the key's text, and the answers' where any was given: a merge
    /// composed again with other answers is a write of its own.
    pub(super) fn text(&self, merged: &Merged) -> String {
        let key = merged.key.text();
        if self.recorded.is_empty() {
            return key;
        }
        let answers: Vec<String> = self.recorded.iter().map(|a| format!("{}.{}+{}:{}", a.from.origin, a.from.i_start, a.from.width, a.answer.as_str())).collect();
        format!("{key}~{}", answers.join(","))
    }
}

/// One run of the list a shot places: a run of M as the answers leave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AnsweredRun {
    /// The run.
    pub(super) run: Run,
    /// Its family in the shot.
    pub(super) family: Family,
    /// The side a value read prefers.
    pub(super) side: Option<SideIx>,
    /// The run its values are read through.
    ///
    /// It is the run itself, or the window's own span where the run is the
    /// published words a record names.
    pub(super) through: Run,
}

impl AnsweredRun {
    /// Returns whether the shot sends the draft's place beside this run.
    ///
    /// It is the draft's words the shot re-mints and a part answered by its
    /// counterpart (the module's doc); the board refuses any other run a
    /// place (`stray_place_unrecorded`; wire.md §The publish shot and
    /// head-float).
    fn takes_a_place(&self) -> bool {
        self.family == Family::DraftNative || self.through != self.run
    }

    /// Returns the run's `width` positions from `offset`.
    fn piece(&self, offset: u64, width: u64) -> AnsweredRun {
        let cut = |r: &Run| Run::new(r.origin.clone(), r.i_start + offset, width);
        AnsweredRun { run: cut(&self.run), family: self.family, side: self.side, through: cut(&self.through) }
    }
}

/// Returns the list a shot sends, each piece beside its kept place.
///
/// `runs` are cut where the draft whose `image` is given cuts them, and each
/// piece carries the draft's own place of its words, `None` for a run that
/// takes no place and for words the draft does not arrange (the module's
/// doc). A piece is the longest stretch of a run the draft holds at one
/// place no earlier piece has named; a stretch it holds nowhere, or only at
/// places already named, goes with no place. Each place is named once, so
/// words the draft arranges twice take its occurrences in V-order, the k-th
/// copy in M the k-th place. The board re-windows the entries in order, each
/// moving only its own width, so the places stay true from the first entry
/// to the last. With no `image` every run stands uncut with no place.
pub(super) fn kept_places(runs: &[AnsweredRun], image: Option<&[IRun]>) -> Vec<(AnsweredRun, Option<u64>)> {
    let Some(image) = image else {
        return runs.iter().map(|answered| (answered.clone(), None)).collect();
    };
    // The draft's stretches no piece has named, in V-order.
    let mut free: Vec<IRun> = image.to_vec();
    let mut out = Vec::with_capacity(runs.len());
    for answered in runs {
        if !answered.takes_a_place() {
            out.push((answered.clone(), None));
            continue;
        }
        let through = &answered.through;
        let chain = content_prefix(&through.origin);
        let mut cursor = through.i_start;
        while cursor < through.reach() {
            let holding = free.iter().position(|r| r.prefix == chain && r.first <= cursor && cursor < r.first + r.width);
            let (width, place) = match holding {
                Some(k) => {
                    let r = free.remove(k);
                    let width = (through.reach() - cursor).min(r.first + r.width - cursor);
                    let place = r.ordinal + (cursor - r.first);
                    // What the piece leaves of the stretch, either side of it.
                    let before = cursor - r.first;
                    let after = r.first + r.width - cursor - width;
                    if after > 0 {
                        free.insert(k, IRun { prefix: r.prefix.clone(), first: cursor + width, width: after, ordinal: place + width });
                    }
                    if before > 0 {
                        free.insert(k, IRun { prefix: r.prefix, first: r.first, width: before, ordinal: r.ordinal });
                    }
                    (width, Some(place))
                }
                None => {
                    let next = free.iter().filter(|r| r.prefix == chain && r.first > cursor).map(|r| r.first).min().unwrap_or(through.reach()).min(through.reach());
                    (next - cursor, None)
                }
            };
            out.push((answered.piece(cursor - through.i_start, width), place));
            cursor += width;
        }
    }
    out
}

/// Returns M as `answers` leave it — the list a shot places, the read-first
/// compares a member with and a record's verification recomputes.
///
/// A run no answer covers stands; a part kept private stands in its own
/// words; a part left out is gone; a part windowed becomes the published
/// words its record names, the document's own family where they lie in
/// `doc`, a window elsewhere. A run is cut only at an answer's edges.
pub(super) fn applied(runs: &[PlacedRun], families: &[Family], doc: &Address, answers: &[PartAnswer]) -> Vec<AnsweredRun> {
    let mut out = Vec::with_capacity(runs.len());
    for (placed, family) in runs.iter().zip(families) {
        let run = &placed.run;
        let mut cursor = run.i_start;
        while cursor < run.reach() {
            let covering = answers.iter().find(|a| a.from.origin == run.origin && a.from.i_start <= cursor && cursor < a.from.reach());
            let end = match covering {
                Some(a) => a.from.reach().min(run.reach()),
                None => answers.iter().filter(|a| a.from.origin == run.origin && a.from.i_start > cursor).map(|a| a.from.i_start).min().unwrap_or(run.reach()).min(run.reach()),
            };
            let piece = Run::new(run.origin.clone(), cursor, end - cursor);
            match covering {
                None => out.push(AnsweredRun { run: piece.clone(), family: *family, side: placed.side, through: piece }),
                Some(a) => match (a.answer, &a.to) {
                    (RecordedAnswer::KeepPrivate, _) => out.push(AnsweredRun { run: piece.clone(), family: *family, side: placed.side, through: piece }),
                    (RecordedAnswer::LeaveOut, _) => {}
                    (RecordedAnswer::Window, Some(to)) => {
                        let published = Run::new(to.origin.clone(), to.i_start + (cursor - a.from.i_start), end - cursor);
                        let family = if to.origin == *doc { Family::Own } else { Family::Window };
                        out.push(AnsweredRun { run: published, family, side: placed.side, through: piece });
                    }
                    (RecordedAnswer::Window, None) => {}
                },
            }
            cursor = end;
        }
    }
    out
}

/// Returns the shot's window parts composed from `answers` — the merge
/// record's §1.5, before the landing's first write.
///
/// # Errors
///
/// The reads' refusals, each as itself: a window origin of the person's own
/// that answers `withheld`, [`Refusal::Unreadable`]; the death signal under
/// the merger's token, [`Refusal::SessionEnded`]; a dial fault. Then
/// [`Refusal::WindowPartsOwed`] where a part stands unanswered or an answer
/// fits nothing, nothing sent.
pub(super) fn step(writer: &Writer<'_>, merged: &Merged, answers: &Answers, draft: Option<&Address>) -> Result<ShotParts, Refusal> {
    let door = Door::new(writer.board, writer.merger.token);
    let windows = read_windows(&door, writer.merger.account, merged, draft).map_err(|f| refused(f, writer))?;
    let versions = versions_of(&door, &publisher(writer), &windows).map_err(|f| refused(f, writer))?;
    let (answered, misfits) = bound(&windows, &versions, answers);
    let mut owed = Vec::new();
    let mut recorded = Vec::new();
    for window in &windows {
        for (key, composition) in composed_parts(window, &answered) {
            let part = &window.parts[key.part];
            let from = Run::new(window.origin.clone(), part.span.first, part.span.width);
            match composition {
                PartComposition::ByReference(published) => recorded.push(PartAnswer { from, answer: RecordedAnswer::Window, to: Some(Run::new(published.origin, published.i_start, published.width)) }),
                PartComposition::KeptPrivate(_) => recorded.push(PartAnswer { from, answer: RecordedAnswer::KeepPrivate, to: None }),
                PartComposition::LeftOut => recorded.push(PartAnswer { from, answer: RecordedAnswer::LeaveOut, to: None }),
                // No answer of the shot's composes publish-first: the words
                // of a part left to be published first stay owed.
                PartComposition::PublishFirst | PartComposition::Owed => owed.push(key),
            }
        }
    }
    let reads = PartReads { writer, merged, source: Source::Merged, versions: &versions };
    let given = windows
        .iter()
        .flat_map(|w| (0..w.parts.len()).map(move |k| (w, k)))
        .filter(|(w, k)| answered.contains_key(&w.key(*k)))
        .map(|(w, k)| reads.part(w, k, answered.get(&w.key(k)).copied(), false, false))
        .collect::<Result<Vec<_>, Refusal>>()?;
    if !owed.is_empty() || !misfits.is_empty() {
        let parts = windows
            .iter()
            .flat_map(|w| (0..w.parts.len()).map(move |k| (w, k)))
            .filter(|(w, k)| owed.contains(&w.key(*k)))
            .map(|(w, k)| reads.part(w, k, None, true, false))
            .collect::<Result<Vec<_>, Refusal>>()?;
        return Err(Refusal::WindowPartsOwed { parts, misfits, given });
    }
    let runs = applied(&merged.composed.runs, &merged.families, &merged.inputs.doc, &recorded);
    Ok(ShotParts { windows, answered, runs, recorded, given })
}

/// Reads the shot's window parts again just before the send (§1.5).
///
/// A part named, un-named or re-named since the step whose answer does not
/// carry onto it is refused again with nothing published (PUB-3.108); a
/// leave-out carries.
///
/// # Errors
///
/// As [`step`]'s reads', then [`Refusal::WindowPartsOwed`] naming each part
/// named since its answer was given.
pub(super) fn recheck(writer: &Writer<'_>, merged: &Merged, shot: &ShotParts, draft: Option<&Address>) -> Result<(), Refusal> {
    let door = Door::new(writer.board, writer.merger.token);
    let now = read_windows(&door, writer.merger.account, merged, draft).map_err(|f| refused(f, writer))?;
    let moved = renamed(&shot.windows, &now);
    if moved.is_empty() {
        return Ok(());
    }
    let carried = answers_onto(&shot.windows, &shot.answered, &now);
    let versions = versions_of(&door, &publisher(writer), &now).map_err(|f| refused(f, writer))?;
    let reads = PartReads { writer, merged, source: Source::Merged, versions: &versions };
    let mut parts = Vec::new();
    for (key, _) in moved {
        if carried.contains_key(&key) {
            continue;
        }
        let window = now.iter().find(|w| w.run == key.run).expect("a part `renamed` answered is a part of `now`");
        parts.push(reads.part(window, key.part, None, true, true)?);
    }
    if parts.is_empty() {
        return Ok(());
    }
    Err(Refusal::WindowPartsOwed { parts, misfits: Vec::new(), given: shot.given.clone() })
}

/// Returns the refusal the panel's route owes for `owed`, parts of the
/// draft `into` the composition landed in — the same refusal the shot makes
/// (`Refusal::WindowPartsOwed`'s `parts`).
///
/// # Errors
///
/// The reads' refusals, each as itself: the versions' feed row, the words'
/// `retrieve_v`; the death signal under the merger's token,
/// [`Refusal::SessionEnded`].
pub fn owed_parts(board: &crate::board::Board, merged: &Merged, merger: Merger<'_>, into: &Address, windows: &[Window], owed: &[OwedAnswer]) -> Result<Vec<WindowPart>, Refusal> {
    let writer = Writer::new(board, merger, super::reads::OnEnd::Rerun);
    let door = Door::new(board, merger.token);
    let versions = versions_of(&door, &publisher(&writer), windows).map_err(|f| refused(f, &writer))?;
    let reads = PartReads { writer: &writer, merged, source: Source::Draft(into), versions: &versions };
    owed.iter()
        .map(|o| {
            let window = windows.iter().find(|w| w.run == o.part.run).ok_or_else(|| own_fault_face("an owed part names no window", format!("{:?}", o.part)))?;
            reads.part(window, o.part.part, None, true, false)
        })
        .collect()
}

/// Returns each answer standing at `windows`' parts as the acknowledgment
/// says it — the panel's route's `Landed::Member::answers`.
///
/// # Errors
///
/// As [`owed_parts`]'s.
pub fn given_parts(board: &crate::board::Board, merged: &Merged, merger: Merger<'_>, into: &Address, windows: &[Window], answers: &BTreeMap<PartKey, Answer>) -> Result<Vec<WindowPart>, Refusal> {
    let writer = Writer::new(board, merger, super::reads::OnEnd::Rerun);
    let door = Door::new(board, merger.token);
    let versions = versions_of(&door, &publisher(&writer), windows).map_err(|f| refused(f, &writer))?;
    let reads = PartReads { writer: &writer, merged, source: Source::Draft(into), versions: &versions };
    windows
        .iter()
        .flat_map(|w| (0..w.parts.len()).map(move |k| (w, k)))
        .filter(|(w, k)| answers.contains_key(&w.key(*k)))
        .map(|(w, k)| reads.part(w, k, answers.get(&w.key(k)).copied(), false, false))
        .collect()
}

/// Returns the record's answers for `windows` under `answers` — what a
/// publication the merger's own panel sent is recorded with
/// (`record_published`).
pub fn part_answers(windows: &[Window], answers: &BTreeMap<PartKey, Answer>) -> Vec<PartAnswer> {
    let mut out = Vec::new();
    for window in windows {
        for (k, part) in window.parts.iter().enumerate() {
            let from = Run::new(window.origin.clone(), part.span.first, part.span.width);
            match compose_part(window, k, answers.get(&window.key(k)).copied().filter(|a| part.admits(*a))) {
                PartComposition::ByReference(published) => out.push(PartAnswer { from, answer: RecordedAnswer::Window, to: Some(Run::new(published.origin, published.i_start, published.width)) }),
                PartComposition::KeptPrivate(_) => out.push(PartAnswer { from, answer: RecordedAnswer::KeepPrivate, to: None }),
                PartComposition::LeftOut => out.push(PartAnswer { from, answer: RecordedAnswer::LeaveOut, to: None }),
                PartComposition::PublishFirst | PartComposition::Owed => {}
            }
        }
    }
    out
}

/// Returns the publication family's hand for the merger, for the reads the
/// step shares with it.
fn publisher<'a>(writer: &Writer<'a>) -> Publisher<'a> {
    Publisher { board: writer.board, token: writer.merger.token, account: writer.merger.account, signer: writer.merger.signer }
}

/// Reads M's windows through `door` — the one read the step and the
/// re-read share.
///
/// Each run of M's `Family::Window` is read for its origin's state, one
/// `doc_metadata` per distinct origin at the head, a draft the landing
/// names passed over as the document's own re-minted words; an unpublished
/// origin's records are read in its own account, none where it answers
/// `withheld`, and the run is cut into its parts ([`parts_of`]).
///
/// # Errors
///
/// [`origin_state`]'s and [`window_records`]'s faults, a window of the
/// merger's own answering `withheld` among them.
fn read_windows(door: &Door<'_>, account: &str, merged: &Merged, draft: Option<&Address>) -> Result<Vec<Window>, Fault> {
    let mut states: BTreeMap<String, OriginState> = BTreeMap::new();
    let mut out = Vec::new();
    let mut ordinal = 1u64;
    for (i, (placed, family)) in merged.composed.runs.iter().zip(&merged.families).enumerate() {
        let run = &placed.run;
        let at = ordinal;
        ordinal = ordinal.saturating_add(run.width);
        if *family != Family::Window || draft == Some(&run.origin) {
            continue;
        }
        let origin = run.origin.to_string();
        let state = match states.get(&origin).copied() {
            Some(state) => state,
            None => {
                let state = origin_state(door, &origin)?;
                states.insert(origin.clone(), state);
                state
            }
        };
        let foreign = !owned_by(&origin, account);
        match state {
            OriginState::Published => continue,
            OriginState::Withheld if !foreign => return Err(Fault::Unreadable(run.origin.clone())),
            OriginState::Private | OriginState::Withheld => {}
        }
        let piece = publication::Run::new(run.origin.clone(), run.i_start, run.width);
        let owner = account_of(&origin).unwrap_or_default();
        let records = if state == OriginState::Private { window_records(door, &owner, &piece)? } else { Vec::new() };
        let parts = parts_of(&piece, at, &records, foreign);
        out.push(Window { run: i, origin: run.origin.clone(), owner, i_start: run.i_start, width: run.width, parts });
    }
    Ok(out)
}

/// Returns ⟨E.j⟩ per record link: the member the record's commit minted, the
/// document its `to` lies in where the feed holds no row of it.
///
/// # Errors
///
/// [`member_at`](crate::publication::landed::member_at)'s.
fn versions_of(door: &Door<'_>, p: &Publisher<'_>, windows: &[Window]) -> Result<BTreeMap<String, Address>, Fault> {
    let mut out = BTreeMap::new();
    for record in windows.iter().flat_map(|w| &w.parts).filter_map(|part| part.record.as_ref()) {
        let link = record.link.to_string();
        if out.contains_key(&link) {
            continue;
        }
        let trunk = record.to.document();
        let minted = match (trunk.as_deref(), record.at) {
            (Some(trunk), Some(at)) => publication::landed::member_at(door, p, trunk, at)?,
            _ => None,
        };
        let version = minted.or_else(|| trunk.as_deref().and_then(parse_address)).unwrap_or_else(|| record.link.clone());
        out.insert(link, version);
    }
    Ok(out)
}

/// Binds `answers` to `windows`' parts, by their keys (the module's doc).
///
/// A part a record names takes [`Flag::Window`] or [`Flag::LeaveOut`] under
/// its version, a part no record names [`Flag::KeepPrivate`] or
/// [`Flag::LeaveOut`] under its origin. Answers that fit nothing, and two
/// answers for the same words, are misfits.
fn bound(windows: &[Window], versions: &BTreeMap<String, Address>, answers: &Answers) -> (BTreeMap<PartKey, Answer>, Vec<Misfit>) {
    let version_of = |record: &crate::publication::Record| versions.get(&record.link.to_string()).cloned();
    let mut out = BTreeMap::new();
    for window in windows {
        for (k, part) in window.parts.iter().enumerate() {
            let answer = match &part.record {
                Some(record) => match version_of(record) {
                    Some(version) if answers.window.contains(&version) => Some(Answer::Counterpart),
                    Some(version) if answers.leave_out.contains(&version) => Some(Answer::Drop),
                    _ => None,
                },
                None if answers.keep_private.contains(&window.origin) => Some(Answer::KeepPrivate),
                None if answers.leave_out.contains(&window.origin) => Some(Answer::Drop),
                None => None,
            };
            if let Some(answer) = answer {
                out.insert(window.key(k), answer);
            }
        }
    }
    let named_in = |origin: &Address| -> Vec<Address> {
        let mut out: Vec<Address> = Vec::new();
        for (window, part) in windows.iter().flat_map(|w| w.parts.iter().map(move |p| (w, p))) {
            if window.origin == *origin {
                if let Some(version) = part.record.as_ref().and_then(version_of) {
                    if !out.contains(&version) {
                        out.push(version);
                    }
                }
            }
        }
        out
    };
    let names_version = |key: &Address| windows.iter().flat_map(|w| &w.parts).any(|p| p.record.as_ref().and_then(version_of).as_ref() == Some(key));
    let unnamed_of = |origin: &Address| windows.iter().filter(|w| w.origin == *origin).flat_map(|w| &w.parts).any(|p| !p.named());
    let mut misfits = Vec::new();
    for key in &answers.window {
        if answers.leave_out.contains(key) {
            misfits.push(Misfit::TwoAnswers { first: Flag::Window, second: Flag::LeaveOut, key: key.clone() });
        }
        if !names_version(key) {
            misfits.push(Misfit::FitsNothing { flag: Flag::Window, key: key.clone(), published_in: Vec::new() });
        }
    }
    for key in &answers.keep_private {
        if answers.leave_out.contains(key) {
            misfits.push(Misfit::TwoAnswers { first: Flag::KeepPrivate, second: Flag::LeaveOut, key: key.clone() });
        }
        if !unnamed_of(key) {
            misfits.push(Misfit::FitsNothing { flag: Flag::KeepPrivate, key: key.clone(), published_in: named_in(key) });
        }
    }
    for key in &answers.leave_out {
        if !names_version(key) && !unnamed_of(key) {
            misfits.push(Misfit::FitsNothing { flag: Flag::LeaveOut, key: key.clone(), published_in: named_in(key) });
        }
    }
    (out, misfits)
}

/// Where a part's words are read.
enum Source<'a> {
    /// Off M, the merged text: the shot lands in no draft.
    Merged,
    /// Off the draft the composition landed in.
    Draft(&'a Address),
}

/// What one part's words and naming are read through.
struct PartReads<'a> {
    writer: &'a Writer<'a>,
    merged: &'a Merged,
    source: Source<'a>,
    versions: &'a BTreeMap<String, Address>,
}

impl PartReads<'_> {
    /// Returns `window`'s `k`-th part as a refusal or an acknowledgment
    /// names it, reading the words before it where `want_after`.
    ///
    /// # Errors
    ///
    /// The words' reads' refusals; a position none of the images holds, the
    /// shot's own fault.
    fn part(&self, window: &Window, k: usize, answer: Option<Answer>, want_after: bool, named_since: bool) -> Result<WindowPart, Refusal> {
        let part = &window.parts[k];
        let (writer, merged, source) = (self.writer, self.merged, &self.source);
        let reading = Run::new(window.origin.clone(), part.span.first, part.span.width.min(WORDS_READ));
        let words = first_words(writer, merged, source, &reading, part.ordinal)?;
        let after = if want_after { words_before(writer, merged, source, part.ordinal)? } else { None };
        let record = part.record.as_ref().map(|r| r.link.clone());
        let version = part.record.as_ref().and_then(|r| self.versions.get(&r.link.to_string()).cloned());
        Ok(WindowPart {
            key: window.key(k),
            words,
            after,
            ordinal: part.ordinal,
            origin: window.origin.clone(),
            owner: (window.owner != writer.merger.account).then(|| window.owner.clone()),
            span: part.span.clone(),
            record,
            counterpart: part.counterpart(),
            version,
            sides: sides_showing(merged, &part.span),
            admits: part.admitted(),
            answer,
            named_since,
        })
    }
}

/// Returns each published side of `merged` showing `span` as a placeholder.
///
/// The published sides are the head and every daughter side (the merge
/// record's §1.5): a side shows a placeholder where it arranges a run of
/// `span`'s own origin chain, which stands behind the placeholder for a
/// reader of that version; a draft side or a fork side is no published
/// version.
fn sides_showing(merged: &Merged, span: &ISpan) -> Vec<Address> {
    let mut out = Vec::new();
    for (i, map) in merged.maps.iter().enumerate() {
        let published = i == 0 || matches!(merged.inputs.sides.get(i - 1), Some(Side::Member(_)));
        if published && map.runs.iter().any(|r| r.prefix == span.chain && r.first < span.reach() && span.first < r.first + r.width) {
            out.push(map.doc.clone());
        }
    }
    out
}

/// Reads the first words of a part.
///
/// `None` where this merger may not read the words.
///
/// # Errors
///
/// The read's refusals but `withheld`, which answers `None`.
fn first_words(writer: &Writer<'_>, merged: &Merged, source: &Source<'_>, reading: &Run, ordinal: u64) -> Result<Option<String>, Refusal> {
    let items = match source {
        Source::Merged => values_for(&writer.reader, &merged.maps, None, reading),
        Source::Draft(into) => writer.reader.values(into, None, ordinal, reading.width),
    };
    match items {
        Ok(items) => Ok(Some(spell_first(&items))),
        Err(Refusal::Unreadable(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Reads the words before position `ordinal` of the merged text.
///
/// `None` at the merged text's start; words that cannot be read answer an
/// empty text.
///
/// # Errors
///
/// The reads' refusals but `withheld`.
fn words_before(writer: &Writer<'_>, merged: &Merged, source: &Source<'_>, ordinal: u64) -> Result<Option<String>, Refusal> {
    if ordinal <= 1 {
        return Ok(None);
    }
    let from = ordinal.saturating_sub(WORDS_READ).max(1);
    let mut items: Vec<Item> = Vec::new();
    match source {
        Source::Draft(into) => match writer.reader.values(into, None, from, ordinal - from) {
            Ok(read) => items = read,
            Err(Refusal::Unreadable(_)) => {}
            Err(e) => return Err(e),
        },
        Source::Merged => {
            let mut at = 1u64;
            for placed in &merged.composed.runs {
                let run = &placed.run;
                let (lo, hi) = (at.max(from), (at + run.width).min(ordinal));
                if lo < hi {
                    let piece = Run::new(run.origin.clone(), run.i_start + (lo - at), hi - lo);
                    match values_for(&writer.reader, &merged.maps, placed.side.map(|s| s.0 as usize), &piece) {
                        Ok(read) => items.extend(read),
                        Err(Refusal::Unreadable(_)) => items.clear(),
                        Err(e) => return Err(e),
                    }
                }
                at = at.saturating_add(run.width);
            }
        }
    }
    Ok(Some(spell_last(&items)))
}

/// Returns a passage's first words, spelled from its values (SP-17).
fn spell_first(items: &[Item]) -> String {
    let text = text_of(items);
    let words: Vec<&str> = text.split_whitespace().take(WORDS_SHOWN).collect();
    clipped(&words.join(" "))
}

/// Returns a passage's last words, spelled from its values (SP-17).
fn spell_last(items: &[Item]) -> String {
    let text = text_of(items);
    let words: Vec<&str> = text.split_whitespace().collect();
    clipped(&words[words.len().saturating_sub(WORDS_SHOWN)..].join(" "))
}

/// Returns the values' bytes as text.
fn text_of(items: &[Item]) -> String {
    String::from_utf8_lossy(&items.concat()).into_owned()
}

/// Returns `text` cut to [`WORDS_BOUND`] characters.
fn clipped(text: &str) -> String {
    text.chars().take(WORDS_BOUND).collect()
}

/// Returns the merge's refusal for a window read's fault.
fn refused(fault: Fault, writer: &Writer<'_>) -> Refusal {
    match fault {
        Fault::Unreadable(doc) => Refusal::Unreadable(doc),
        Fault::NoSuchDocument(doc) => Refusal::NoSuchDocument(doc),
        Fault::SessionEnded => session_ended("reading the merge's window parts", writer.reader.on_end()),
        Fault::Halt(h) => Refusal::Halt(h),
        Fault::Busy => Refusal::Halt(Halt::face("the board was busy reading a window's records", "scan_busy or history_busy past the bounded reissues", "run this again in a moment; nothing was written")),
        Fault::Shape { op, body } => Refusal::Halt(Halt::face(format!("`{op}` answered a document this client cannot read"), body, "this board is not speaking the wire this client expects; nothing was written")),
        other => own_fault_face("a window read met a fault it does not expect", format!("{other}")),
    }
}
