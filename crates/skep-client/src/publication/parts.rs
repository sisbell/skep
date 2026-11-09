//! THE WINDOW PARTS — the rules of a window's parts, once, over placed runs
//! and their records, with no draft in them (the link-sets design §5.7;
//! B3-S11 P2 (i); the merge record's §1.5, THE SHOT's WINDOW PARTS).
//!
//! A window is a run onto a document that a publication's reader would not
//! read. It is cut into PARTS at its records' edges ([`parts_of`]): a
//! stretch one record names as published, or a stretch none names. Each
//! part admits its own answers ([`Part::admits`]): a part a record names is
//! taken by its counterpart or left out, and never kept private, whose
//! placeholder would withhold words anyone reads at the version that
//! published them; a part no record names is kept private behind a
//! placeholder or left out, and where the words are the person's own, they
//! may publish them first ([`Part::foreign`] says where they are not). An
//! answer composes one part ([`compose_part`]), an unanswered part comes to
//! an [`OwedAnswer`] that names it whole, and a part named, un-named or
//! re-named since its answer is asked again ([`renamed`], [`answers_onto`]).
//!
//! Two routes call this module, and neither holds a rule of its own. The
//! publication family hands it the draft's placements (`windows_with`,
//! `build_with`, `Enumeration::composed`); the merge library's shot hands it
//! the merged list's placed runs (`merge::windows`). The same part admits
//! the same answers and composes the same way on both.
//!
//! **Which windows ask** (`OriginState`). A window onto a published
//! document asks nothing. Another account's unpublished document is asked at
//! a merge only (`Inputs::merge_landing`): a reader of the new version meets
//! a placeholder there, so the landing does not keep it unasked. Its reads
//! never decide the question by the document's words: a document the reader
//! may not read answers `withheld`, and is asked with no words and no
//! records read. The records of a window are read in the origin's own
//! account, since only the owner writes them (`window_records`).

use std::collections::BTreeMap;

use skep_address::Address;

use crate::board::frames::{self, Slot, T_CORRESPONDENCE};

use super::enumerate::{read_record_as, Record};
use super::{Door, Fault, ISpan, Run};

/// The caller's answer at one part of a window (B3-S11 P2 (i); the link-sets
/// design §5.7).
///
/// Which answers a part admits is the part's to say ([`Part::admits`]): a
/// part a record names takes the counterpart or [`Answer::Drop`], a part no
/// record names publish-first, [`Answer::Drop`] or keep-private.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Publish the origin first: NOT this request, which stays inert.
    PublishFirst,
    /// Leave the part's words out of the request.
    Drop,
    /// Send the part as a window onto the private origin, no place beside
    /// it: readers see a placeholder there.
    KeepPrivate,
    /// Window the published words the part's record names, re-composed by
    /// reference with the part's kept place, so the commit re-windows the
    /// draft there through the record.
    Counterpart,
}

/// A part of a window: the window's run and the part's place in it — the
/// key an answer is given at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartKey {
    /// The window's run, by its index in the list of placed runs.
    pub run: usize,
    /// The part, by its index in the window's parts.
    pub part: usize,
}

/// One part of a window: a stretch of its words one record names as
/// published, or a stretch none names (B3-S11 P2 (i), its scope sentence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// The part's words, on the origin's chain.
    pub span: ISpan,
    /// The V-ordinal the placement arranges the part's first word at — the
    /// draft's own, where it is the kept place its counterpart takes, or
    /// the merged list's at the shot.
    pub ordinal: u64,
    /// The record that names the part's words as published, where one does;
    /// its `to` is the counterpart.
    pub record: Option<Record>,
    /// Whether the part's words are another account's.
    ///
    /// Publishing them first is then no answer of the person's.
    pub foreign: bool,
}

impl Part {
    /// Returns whether a record names the part's words as published.
    pub fn named(&self) -> bool {
        self.record.is_some()
    }

    /// Returns whether the part admits `answer`.
    ///
    /// At a part a record names: the counterpart and [`Answer::Drop`], never
    /// keep-private or publish-first, whose placeholder would withhold words
    /// anyone reads at the version that published them. At a part no record
    /// names: [`Answer::Drop`], keep-private and, where the words are the
    /// person's own, publish-first.
    pub fn admits(&self, answer: Answer) -> bool {
        match answer {
            Answer::Drop => true,
            Answer::Counterpart => self.named(),
            Answer::KeepPrivate => !self.named(),
            Answer::PublishFirst => !self.named() && !self.foreign,
        }
    }

    /// Returns every answer the part admits, in the order the panel states
    /// them.
    pub fn admitted(&self) -> Vec<Answer> {
        [Answer::Counterpart, Answer::PublishFirst, Answer::Drop, Answer::KeepPrivate].into_iter().filter(|a| self.admits(*a)).collect()
    }

    /// Returns the published words the part's record names at the part's
    /// offset — THE COUNTERPART; `None` at a part no record names.
    pub fn counterpart(&self) -> Option<ISpan> {
        self.record.as_ref().and_then(|r| r.map(&self.span.chain, self.span.first, self.span.reach()))
    }
}

/// One window of a list of placed runs, in its parts (the link-sets design
/// §5.7; B3-S11 P2 (i)).
///
/// It is a run onto a document whose words a reader of the publication
/// would not read, whose answers are asked. A run of a named draft, whose
/// words are re-minted, is none, nor is one the placement does not arrange,
/// which carries nothing and is owed no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    /// The run's index in the list of placed runs.
    pub run: usize,
    /// The origin: the person's unpublished draft, or at a merge another
    /// account's unpublished document (`Inputs::merge_landing`).
    pub origin: Address,
    /// The origin's owner account, off its address.
    pub owner: String,
    /// Where in the origin's I-space the passage was written: the run's
    /// first ordinal.
    pub i_start: u64,
    /// The run's width.
    pub width: u64,
    /// The window's parts, in the placement's order: each piece the
    /// placement arranges of the run, cut where a record's naming starts
    /// or ends.
    pub parts: Vec<Part>,
}

impl Window {
    /// Returns the key of the window's `part`-th part.
    pub fn key(&self, part: usize) -> PartKey {
        PartKey { run: self.run, part }
    }
}

/// Returns `piece`, a window's run as its placement places it at `ordinal`,
/// cut into its parts — the one cut of a window at its records' edges.
///
/// Each stretch the first record covering its first word names, up to the
/// end of that record's `from`, and each stretch no record covers, up to
/// the next record's first word. `foreign` says the words are another
/// account's ([`Part::foreign`]).
pub fn parts_of(piece: &Run, ordinal: u64, records: &[Record], foreign: bool) -> Vec<Part> {
    let chain = piece.chain();
    let mut out = Vec::new();
    let mut cursor = piece.i_start;
    while cursor < piece.reach() {
        let covering = records.iter().find(|r| r.from.overlap(&chain, cursor, cursor + 1).is_some());
        let end = match covering {
            Some(r) => r.from.reach().min(piece.reach()),
            None => records.iter().filter_map(|r| (r.from.chain == chain && r.from.first > cursor).then_some(r.from.first)).min().unwrap_or(piece.reach()).min(piece.reach()),
        };
        out.push(Part { span: ISpan { chain: chain.clone(), first: cursor, width: end - cursor }, ordinal: ordinal + (cursor - piece.i_start), record: covering.cloned(), foreign });
        cursor = end;
    }
    out
}

/// A window's state at one origin, as one read of its `doc_metadata` tells
/// it — the question of whether it asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OriginState {
    /// Published: every reader of the version reads its words, and nothing
    /// is asked.
    Published,
    /// Unpublished, and readable to this reader.
    Private,
    /// A registered document this reader may not read (wire.md §The read
    /// predicate): asked, with no words and no records read.
    Withheld,
}

/// Reads the state of a window's origin.
///
/// # Errors
///
/// [`Door::metadata`]'s, `withheld` answered as [`OriginState::Withheld`].
pub(crate) fn origin_state(door: &Door<'_>, origin: &str) -> Result<OriginState, Fault> {
    match door.metadata(origin) {
        Ok(meta) if meta.published => Ok(OriginState::Published),
        Ok(_) => Ok(OriginState::Private),
        Err(Fault::Unreadable(_)) => Ok(OriginState::Withheld),
        Err(e) => Err(e),
    }
}

/// Reads the records of a window's origin whose `from` covers part of `run`.
///
/// One four-set read over the record class homed in the origin, `from` the
/// run, each record read once and kept by the reader's own test, held to
/// `account` — the origin's own account, since only its owner's commit
/// mints a record homed in it (the link-sets design §5.5).
///
/// # Errors
///
/// The reads' faults.
pub(crate) fn window_records(door: &Door<'_>, account: &str, run: &Run) -> Result<Vec<Record>, Fault> {
    let unit = |a: &str| frames::unit_span(a).as_array().cloned().unwrap_or_default();
    let origin = run.origin.to_string();
    let home = unit(&origin);
    let subtype = unit(T_CORRESPONDENCE);
    let span = [frames::i_span(&run.i_start_text(), run.width)];
    let mut out: Vec<Record> = Vec::new();
    for hit in door.addrs(&origin, &frames::find_links_four(Slot::Spans(&home), Slot::Spans(&span), Slot::Any, Slot::Spans(&subtype)))? {
        if let Some(record) = read_record_as(door, account, &hit)? {
            if record.from.overlap(&run.chain(), run.i_start, run.reach()).is_some() && !out.iter().any(|r| r.link == record.link) {
                out.push(record);
            }
        }
    }
    Ok(out)
}

/// What one part's answer composes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartComposition {
    /// The part by reference to the published words its record names.
    ByReference(Run),
    /// The part as a window onto its origin, no place beside it: a
    /// placeholder to readers.
    KeptPrivate(Run),
    /// Nothing: the part's words left out.
    LeftOut,
    /// Not this request: the caller publishes the origin first.
    PublishFirst,
    /// No answer stands at the part.
    Owed,
}

/// Returns the answer standing at `window`'s `k`-th part in `answers`, where
/// the part admits it.
pub fn answer_at(window: &Window, k: usize, answers: &BTreeMap<PartKey, Answer>) -> Option<Answer> {
    let part = window.parts.get(k)?;
    answers.get(&window.key(k)).copied().filter(|a| part.admits(*a))
}

/// Composes `window`'s `k`-th part from `answer` — THE ONE RULE both routes
/// compose a part by.
///
/// The counterpart is the part by reference to its record's `to`; keep
/// private is the part's own words behind a placeholder; a part left out
/// composes nothing; no answer is an owed answer, the part's words never
/// composed for the caller, and so is a counterpart this client cannot
/// spell.
pub fn compose_part(window: &Window, k: usize, answer: Option<Answer>) -> PartComposition {
    let Some(part) = window.parts.get(k) else { return PartComposition::Owed };
    match answer {
        Some(Answer::Counterpart) => match part.counterpart().and_then(|s| s.run()) {
            Some(published) => PartComposition::ByReference(published),
            None => PartComposition::Owed,
        },
        Some(Answer::KeepPrivate) => PartComposition::KeptPrivate(Run::new(window.origin.clone(), part.span.first, part.span.width)),
        Some(Answer::Drop) => PartComposition::LeftOut,
        Some(Answer::PublishFirst) => PartComposition::PublishFirst,
        None => PartComposition::Owed,
    }
}

/// A part whose answer is owed, named whole (the merge record's §1.5).
///
/// It carries what a refusal names of it: the part, the words and where
/// they were written, the origin and its owner, the record naming it and
/// the published words it names, and the answers it admits. Which answers
/// the part admits decides which inert reason the panel draws.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwedAnswer {
    /// The part.
    pub part: PartKey,
    /// Whether a record names the part's words as published.
    pub named: bool,
    /// The origin.
    pub origin: Address,
    /// The origin's owner account, off its address.
    pub owner: String,
    /// The part's words, on the origin's chain.
    pub span: ISpan,
    /// The record naming the part, where one does.
    pub record: Option<Address>,
    /// The published words the record names, where one does.
    pub counterpart: Option<ISpan>,
    /// Whether the words are another account's.
    pub foreign: bool,
    /// The answers the part admits, in the panel's order.
    pub admits: Vec<Answer>,
}

impl OwedAnswer {
    /// Returns the owed answer naming `window`'s `k`-th part.
    ///
    /// # Panics
    ///
    /// Panics where `k` is no part of `window`.
    pub fn of(window: &Window, k: usize) -> OwedAnswer {
        let part = &window.parts[k];
        OwedAnswer {
            part: window.key(k),
            named: part.named(),
            origin: window.origin.clone(),
            owner: window.owner.clone(),
            span: part.span.clone(),
            record: part.record.as_ref().map(|r| r.link.clone()),
            counterpart: part.counterpart(),
            foreign: part.foreign,
            admits: part.admitted(),
        }
    }
}

/// Returns the part of `windows` holding the first word of `part`, a part
/// of the window over the placed run `run`, with its index.
fn part_holding<'w>(windows: &'w [Window], run: usize, part: &Part) -> Option<(usize, &'w Part)> {
    let window = windows.iter().find(|w| w.run == run)?;
    window.parts.iter().enumerate().find(|(_, before)| before.span.overlap(&part.span.chain, part.span.first, part.span.first + 1).is_some())
}

/// Returns each part of `now` — a later read of the same runs' windows —
/// whose naming differs from `before`'s at its first word.
///
/// A part is named, un-named or named by another record since, or a part
/// `before` held nothing of. Each comes with the record naming it now.
pub fn renamed(before: &[Window], now: &[Window]) -> Vec<(PartKey, Option<Address>)> {
    let mut out = Vec::new();
    for window in now {
        for (k, part) in window.parts.iter().enumerate() {
            let naming = part.record.as_ref().map(|r| r.link.clone());
            let held = part_holding(before, window.run, part).map(|(_, p)| p.record.as_ref().map(|r| r.link.clone()));
            if held.as_ref() != Some(&naming) {
                out.push((window.key(k), naming));
            }
        }
    }
    out
}

/// Returns `answers`, standing over `before`, carried onto `now`, a later
/// read of the same runs' windows (PUB-3.108).
///
/// Each part of `now` takes the answer of the part `before` holds its first
/// word at, where the two are named alike and the part admits it; where
/// their naming differs a leave-out alone stands, every other answer asked
/// again.
pub fn answers_onto(before: &[Window], answers: &BTreeMap<PartKey, Answer>, now: &[Window]) -> BTreeMap<PartKey, Answer> {
    let mut out = BTreeMap::new();
    for window in now {
        for (k, part) in window.parts.iter().enumerate() {
            let Some((j, held)) = part_holding(before, window.run, part) else { continue };
            let Some(answer) = before.iter().find(|w| w.run == window.run).and_then(|w| answer_at(w, j, answers)) else { continue };
            let alike = held.record.as_ref().map(|r| &r.link) == part.record.as_ref().map(|r| &r.link);
            if (alike || answer == Answer::Drop) && part.admits(answer) {
                out.insert(window.key(k), answer);
            }
        }
    }
    out
}

/// Returns each of `window`'s parts' compositions under `answers`, in the
/// parts' order.
pub fn composed_parts(window: &Window, answers: &BTreeMap<PartKey, Answer>) -> Vec<(PartKey, PartComposition)> {
    (0..window.parts.len()).map(|k| (window.key(k), compose_part(window, k, answer_at(window, k, answers)))).collect()
}
