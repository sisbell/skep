//! The query: the one grammar, [`Query::parse`], and the evaluator.
//!
//! The evaluator runs over the pair behind `Index::query` (`search.md` §3.2;
//! §1.4; the `pair` module). The shell bounds the string's length as
//! untrusted input ahead of it (`client.md` §4e.5); the crate takes what it
//! is given and parses it to §3.2's forms, each a [`Form`]:
//!
//! * A word — one term, cut by the tokenizer's own rule (`token::segments`),
//!   "tokenized by §2.3's rule as the text was".
//! * A prefix — "the last word of the string is a prefix unless the string
//!   ends in whitespace: the keystroke's case", expanded over the sorted
//!   dictionary by binary search, the terms taken "by document frequency
//!   descending until the next would pass the bound, the term equal to the
//!   prefix taken first wherever the dictionary holds it, and the bound
//!   reported as `more_terms: true`" — [`EXPANSION_BOUND_ENTRIES`].
//! * A phrase — a quoted run `"…"`, "matched by adjacent token ordinals in
//!   one unit, never across a `Gap`"; a quoted single word is a word.
//! * A phrase-prefix — "a quoted run whose closing quote is absent, the last
//!   word a prefix": its fixed words first, "and its last word expands over
//!   the terms that occur at the ordinal after the fixed phrase's occurrences
//!   and lie in the prefix's dictionary range — each read off the stored text
//!   at the occurrence's end …, one token cut there, the occurrences bounded
//!   as the keystroke's positions are", those terms then taken in the
//!   expansion's order, so `"the publish s` finds `shot`.
//! * A split chunk — "a whitespace-delimited chunk the tokenizer splits into
//!   two or more tokens (a rule id, a hyphenated word, an unspaced CJK run, a
//!   URL) — is an implicit phrase, matched as a quoted run is, and a
//!   phrase-prefix while it is the string's last chunk and no whitespace
//!   follows it": `PUB-5.115` finds the unit that holds it and not
//!   `AUTH-5.115` beside `PUB-1.2`; `東京都` finds the run.
//! * Several bare words — a conjunction: "every term (or its expansion)
//!   present in the unit", ranked by BM25 with the tightest window holding
//!   one occurrence of each as the hit's span (`hit`).
//! * A fuzzy word (D15, its shape proposed) — "a complete query word of five
//!   or more characters that is no term of the pair's dictionary … is
//!   expanded to the terms within one edit of it — an insertion, a deletion,
//!   a substitution or an adjacent transposition of one character (a Unicode
//!   scalar value …; a Cyrillic substitution is one edit, not two bytes') —
//!   the candidates ranked by document frequency, at most the expansion's
//!   bound per word, counted in the same postings entries; and at most three
//!   complete words of one query are expanded …, the three nearest the
//!   string's end, the others matched as typed and the `Answer` saying so by
//!   `fuzzy_bounded: true`"; "a word that is a term takes no expansion"; "The
//!   last word while it is still a prefix is not fuzzy"; "Inside a phrase a
//!   fuzzy word matches at its ordinal as any term does"; every hit matched
//!   through a correction says so (`matched`).
//! * No operators: "what parses as none of the above is a word".
//!
//! **The evaluator, bounded and flagged** (PATTERNS P29's except clause — a
//! flagged ranked top-k "when it carries a flag the caller reads and states
//! its order"): "A keystroke's whole evaluation is bounded by the positions
//! it merges — the fixed words' and the expansion's alike, an entry being one
//! occurrence (a token ordinal and its range), never a (term, unit) pair …:
//! the evaluator walks the query's words rarest first, and where the next
//! merge would pass the bound it stops and answers the units it has scored,
//! ranked, with `Answer.positions_bounded: true` …, its order stated: the
//! units a rarest-first walk reaches first, in the rarest word's postings
//! order" — [`POSITIONS_BOUND`]. Here the forms are walked rarest first —
//! the fewest live entries first — the first form's postings merged by
//! unit, the published index's then the supplement's, each unit matched
//! whole before the next is reached; every later form checked over the
//! units so far, in that order; a stop keeps the units matched on every form
//! walked when it came, scored on those, and drops the rest; `total` is then
//! a lower bound and `truncated` is set. Each keystroke's query is evaluated
//! from scratch. The three bounds are interim pins whose constants quote
//! §7.1; each is a flag on the answer and never a silent cut.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use crate::hit::{self, Answer, Hit, Marked, Matched, Span};
use crate::index::{Index, Occurrence, Posting, TermId, UnitId};
use crate::pair::{Pair, QueryOpts, Role};
use crate::rank::{self, Statistics};
use crate::token::segments;
use crate::unit::{Item, Unit};

/// The expansion's bound, in postings entries, an entry one occurrence.
///
/// The bound is §3.2's "the expansion bounded by the postings entries it
/// merges — an interim pin, reported at M2" and §7.1's "the prefix
/// expansion's bound, in postings entries merged". An interim pin, derived
/// from §7.1's M2 pin as the design states none: the per-keystroke
/// phrase-prefix answer at 10⁴ documents is pinned at "≤ 16 ms (one frame) —
/// the crate's `Answer` timed against the whole frame"; the merge is given
/// half the frame, 8 ms, the other half the ranking's sort and `limit`'s
/// snippets; an occurrence merged costs at most one dependent memory
/// access, about 100 ns at DRAM latency — the pessimistic floor a
/// sequential walk of 16-byte occurrences beats by an order — so 8 ms merges
/// 80,000 occurrences, and the power of two at or below it is the bound, in
/// the form the workspace writes its budgets (`1 << 17` delivery items,
/// `1 << 16` compare pairs). A bare prefix is the keystroke's commonest form
/// — M2's sample draws 0–2 full words before the prefix — so the expansion
/// alone may fill the merge's budget, and the positions bound is what stops
/// a keystroke with fixed words beside it. The fuzzy word's per-word cap is
/// this same figure.
///
/// Confirmed at M2 (`tests/it/budgets.rs`, a release build over the 10⁴ cut
/// fed through a dev board): the evaluator's cost measures 54 ns per
/// position merged, with 0.8 µs per unit scored beside it, over 1,500 bare
/// prefixes drawn by token frequency — within a factor of two of the 100 ns
/// assumed, so the figure stands (half a frame over the measured cost would
/// admit `1 << 17`); the keystroke sample's p99 is 15.7 ms at this bound,
/// with `more_terms` on 555 of 1,200 keystrokes. What the measurement also
/// shows, for the design: at 10⁴ the commonest completions — `the`, 827,000
/// occurrences — exceed the bound alone, so a one-letter prefix expands to
/// its own term and the bound's flag, never to them.
pub const EXPANSION_BOUND_ENTRIES: usize = 1 << 16;

/// The positions bound on a keystroke's whole evaluation.
///
/// The bound is §3.2's "bounded by the positions it merges — the fixed
/// words' and the expansion's alike, an entry being one occurrence …, never
/// a (term, unit) pair — an interim pin, reported at M2" and §7.1's "the
/// keystroke's whole evaluation's bound, in positions merged, an entry one
/// occurrence". An interim pin, derived as [`EXPANSION_BOUND_ENTRIES`] is:
/// half of M2's one frame at a pessimistic 100 ns an occurrence, 80,000
/// positions, the power of two at or below it. Every live unit's posting the
/// walk merges counts — a form's own, a phrase's other words', an
/// intersection's — and where the next would pass it the evaluation stops
/// with `positions_bounded: true`; the reads that size an expansion or
/// count a df are not merges and count nothing.
///
/// Confirmed at M2 with [`EXPANSION_BOUND_ENTRIES`] and by the same
/// measurement (54 ns per position merged; the keystrokes at the bound p50
/// 6.8 ms, p99 15.4 ms); `positions_bounded` is set on 281 of 1,200
/// keystrokes at 10⁴, and the phrase-prefix `"of the d` the design names
/// answers in 3.3 ms under it. What it costs, for the design: a quoted
/// phrase of common words over long units admits each fixed word's whole
/// occurrence list per unit walked, so a five-word title phrase holding
/// `the` stops at the bound over the records tier before reaching the record
/// that bears it.
pub const POSITIONS_BOUND: usize = 1 << 16;

/// The fuzzy words bound: at most three complete words of a query expand.
///
/// §3.2 and §7.1's fuzzy M2 row state it: "at most three complete words of
/// one query are expanded (an interim pin, reported at the fuzzy M2 row),
/// the three nearest the string's end, the others matched as typed and the
/// `Answer` saying so by `fuzzy_bounded: true`".
pub const FUZZY_WORDS: usize = 3;

/// The fuzzy word's minimum length, counted in Unicode scalar values.
///
/// §3.2 and §7.1 state it: "a complete query word of five or more
/// characters".
pub const FUZZY_MIN_CHARS: usize = 5;

/// The prefix minimum: the fewest characters a trailing prefix word holds.
///
/// §7.1 states it: "the prefix minimum, 1 character" — a trailing word of
/// this many characters or more is a prefix.
pub const PREFIX_MIN_CHARS: usize = 1;

/// One query word: as the person typed it, and the term it is.
///
/// The typed form is the segment's own bytes, what `matched` reports; the
/// term is cut by the tokenizer's rule (§3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word {
    /// The word as typed, unfolded.
    pub typed: String,
    /// The folded, lowercased term the text's word is.
    pub term: String,
}

/// One of §3.2's forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Form {
    /// A complete word: one term, or a fuzzy word's candidates.
    Word(Word),
    /// The string's last word while it is a prefix: the keystroke's form.
    Prefix(Word),
    /// A quoted run, or a split chunk's implicit phrase: adjacent ordinals.
    Phrase(Vec<Word>),
    /// An unclosed quote, or a split chunk at the string's end.
    ///
    /// The fixed words come first, then a prefix over the terms that follow
    /// them.
    PhrasePrefix {
        /// The complete words, adjacent.
        fixed: Vec<Word>,
        /// The last word, a prefix.
        prefix: Word,
    },
}

/// A parsed query: §3.2's forms in the string's order, a conjunction.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Query {
    forms: Vec<Form>,
}

/// One chunk of the string.
///
/// A chunk is a quoted run, closed or not, or a whitespace-delimited chunk.
struct Chunk<'a> {
    text: &'a str,
    closed: bool,
}

fn chunks(text: &str) -> Vec<Chunk<'_>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < text.len() {
        let c = text[i..].chars().next().expect("inside the string");
        if c.is_whitespace() {
            i += c.len_utf8();
            continue;
        }
        if c == '"' {
            let open = i + 1;
            match text[open..].find('"') {
                Some(k) => {
                    out.push(Chunk { text: &text[open..open + k], closed: true });
                    i = open + k + 1;
                }
                None => {
                    out.push(Chunk { text: &text[open..], closed: false });
                    i = text.len();
                }
            }
            continue;
        }
        let end =
            text[i..].find(|c: char| c.is_whitespace() || c == '"').map_or(text.len(), |k| i + k);
        out.push(Chunk { text: &text[i..end], closed: false });
        i = end;
    }
    out
}

impl Query {
    /// Parses `text` by the one grammar (§3.2).
    ///
    /// The string's chunks — a quoted run, closed or unclosed, or a
    /// whitespace-delimited chunk — are each cut by the tokenizer's rule into
    /// words; a chunk of one word is a [`Form::Word`], of several a
    /// [`Form::Phrase`]; the string's last chunk, where it is no closed quote
    /// and no whitespace follows it, is a [`Form::Prefix`] or a
    /// [`Form::PhrasePrefix`] instead; a chunk the rule cuts to nothing —
    /// punctuation alone — is no form. An empty string, or one of no words,
    /// is the empty query, which answers no hit.
    pub fn parse(text: &str) -> Query {
        let open_end = !text.ends_with(char::is_whitespace);
        let chunks = chunks(text);
        let count = chunks.len();
        let mut forms = Vec::new();
        for (i, chunk) in chunks.into_iter().enumerate() {
            let mut words: Vec<Word> = segments(chunk.text)
                .map(|s| Word {
                    typed: chunk.text[s.offset..s.offset + s.len].to_string(),
                    term: s.term,
                })
                .collect();
            let trailing = i + 1 == count && open_end && !chunk.closed;
            let is_prefix = trailing
                && words.last().map_or(false, |w| w.term.chars().count() >= PREFIX_MIN_CHARS);
            match (words.len(), is_prefix) {
                (0, _) => {}
                (1, false) => forms.push(Form::Word(words.remove(0))),
                (1, true) => forms.push(Form::Prefix(words.remove(0))),
                (_, false) => forms.push(Form::Phrase(words)),
                (_, true) => {
                    let prefix = words.pop().expect("two or more words");
                    forms.push(Form::PhrasePrefix { fixed: words, prefix });
                }
            }
        }
        Query { forms }
    }

    /// Returns the forms in the string's order.
    pub fn forms(&self) -> &[Form] {
        &self.forms
    }

    /// Returns whether the query holds no form.
    pub fn is_empty(&self) -> bool {
        self.forms.is_empty()
    }
}

/// The two bounds as values: the suites' seam.
///
/// A unit test meets each bound at a size it holds; `Index::query` passes
/// [`Bounds::PINNED`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Bounds {
    /// The expansion's bound and the fuzzy word's per-word cap, in entries.
    pub(crate) expansion: usize,
    /// The whole evaluation's bound, in positions merged.
    pub(crate) positions: usize,
}

impl Bounds {
    /// The pinned constants.
    pub(crate) const PINNED: Bounds =
        Bounds { expansion: EXPANSION_BOUND_ENTRIES, positions: POSITIONS_BOUND };
}

/// A unit of the pair: which member, and its id there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Slot {
    side: usize,
    unit: UnitId,
}

/// A live term of one member's dictionary.
#[derive(Debug, Clone, Copy)]
struct TermRef<'a> {
    side: usize,
    id: TermId,
    term: &'a str,
}

/// One element of a form, scored as one combined term (§3.3).
///
/// It is a word's one term on each member holding it, or the union a
/// prefix's expansion or a fuzzy word's candidates make; `df` the units of
/// the pair in the union, `entries` its live postings entries — the walk's
/// cost and order — and `fuzzy` the typed word this element corrects, for
/// `matched`.
#[derive(Debug, Default)]
struct Element<'a> {
    terms: Vec<TermRef<'a>>,
    df: usize,
    entries: usize,
    fuzzy: Option<String>,
}

/// A form resolved against the pair's dictionaries.
enum Resolved<'a> {
    /// A word, a prefix or a fuzzy word: one element.
    Union(Element<'a>),
    /// A phrase: its words' elements, adjacent.
    Phrase(Vec<Element<'a>>),
    /// A phrase-prefix: the fixed words' elements, and the prefix.
    ///
    /// The walk supplies the prefix's candidates.
    Completion { fixed: Vec<Element<'a>>, prefix: String },
}

impl<'a> Resolved<'a> {
    fn elements(&self) -> &[Element<'a>] {
        match self {
            Resolved::Union(e) => std::slice::from_ref(e),
            Resolved::Phrase(es) | Resolved::Completion { fixed: es, .. } => es,
        }
    }

    /// Returns the element walked first: the one of fewest live entries.
    ///
    /// Of equals, it is the first.
    fn driver(&self) -> usize {
        let elements = self.elements();
        (0..elements.len())
            .min_by_key(|&i| elements[i].entries)
            .expect("a form holds at least one element")
    }

    /// Returns the walk's cost: the driver's live entries.
    fn cost(&self) -> usize {
        self.elements()[self.driver()].entries
    }

    /// Returns whether some element has no term.
    ///
    /// Such an element is a word that is no term and takes no expansion, or
    /// an expansion that found none; the form, and the conjunction, then
    /// match nothing.
    fn matches_nothing(&self) -> bool {
        self.elements().iter().any(|e| e.terms.is_empty())
    }
}

/// One token of a match, for the span, the marks and `matched`.
#[derive(Debug, Clone)]
struct Tok<'a> {
    offset: u64,
    len: u32,
    term: &'a str,
    element: usize,
}

/// The token after a fixed phrase's occurrence, cut off the stored text.
#[derive(Debug, Clone)]
struct Next {
    offset: u64,
    len: u32,
    term: String,
}

/// One match of a form in a unit.
///
/// It holds its extent in offsets from the unit's start, its tokens, and —
/// for a phrase-prefix's fixed occurrence — the token that follows it.
#[derive(Debug, Clone)]
struct Match<'a> {
    start: u64,
    end: u64,
    tokens: Vec<Tok<'a>>,
    next: Option<Next>,
}

/// The positions bound's counter (§3.2): what the evaluation has merged.
struct Walk {
    merged: usize,
    bound: usize,
    stopped: bool,
}

/// The evaluation stopped at its positions bound.
struct Stopped;

impl Walk {
    /// Admits `n` more positions to the merge where the bound allows them.
    ///
    /// # Errors
    ///
    /// `Stopped` where the walk is already stopped or `n` more positions
    /// would pass the bound; the walk is then stopped and nothing more is
    /// merged.
    fn admit(&mut self, n: usize) -> Result<(), Stopped> {
        if self.stopped || self.merged + n > self.bound {
            self.stopped = true;
            return Err(Stopped);
        }
        self.merged += n;
        Ok(())
    }
}

/// The flags, each set exactly where its bound is met.
#[derive(Default)]
struct Flags {
    more_terms: bool,
    fuzzy_bounded: bool,
    positions_bounded: bool,
}

/// What a complete word resolves to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Decision {
    /// A term of the pair's dictionary: no expansion.
    Exact,
    /// No term, five characters or more, within the fuzzy budget.
    Fuzzy,
    /// No term, matched as typed: nothing.
    AsTyped,
}

/// Evaluates `query` over the pair: `Index::query`'s body (§3.2, §3.3, §3.1).
pub(crate) fn evaluate(pair: &Pair<'_>, query: &Query, opts: &QueryOpts, bounds: Bounds) -> Answer {
    let sides: Vec<&Index> = pair.indexes().collect();
    let stats = Statistics::merged(sides.iter().copied());
    let mut flags = Flags::default();
    if query.forms.is_empty() || stats.units == 0 {
        return Answer::default();
    }
    let mut forms = resolve(&sides, query, bounds, &mut flags);
    if forms.iter().any(Resolved::matches_nothing) {
        return answer(Vec::new(), 0, opts, &flags);
    }

    // The walk order: rarest first, the string's order among equals.
    let mut order: Vec<usize> = (0..forms.len()).collect();
    order.sort_by_key(|&f| forms[f].cost());
    let mut walk = Walk { merged: 0, bound: bounds.positions, stopped: false };
    // Per unit reached, the matches of each form walked, in the query's order.
    let mut found: BTreeMap<Slot, Vec<Option<Vec<Match<'_>>>>> = BTreeMap::new();

    // The first form: its driver's postings merged by unit, the published
    // index's then the supplement's, each unit matched whole.
    let first = order[0];
    {
        let form = &forms[first];
        let d = form.driver();
        let element = &form.elements()[d];
        'sides: for side in 0..sides.len() {
            let body = &sides[side].body;
            let lists: Vec<(&[Posting], &str)> = element
                .terms
                .iter()
                .filter(|t| t.side == side)
                .map(|t| (&body.terms[t.id].postings[..], t.term))
                .collect();
            let mut merge = Merge::new(lists);
            while let Some((unit, group)) = merge.next() {
                if body.live(unit).is_none() {
                    continue;
                }
                let n: usize = group.iter().map(|(p, _)| p.occurrences.len()).sum();
                if walk.admit(n).is_err() {
                    break 'sides;
                }
                let slot = Slot { side, unit };
                match matches_of(&sides, form, slot, Some((d, by_ordinal(group))), &mut walk) {
                    Err(Stopped) => break 'sides,
                    Ok(matches) if matches.is_empty() => {}
                    Ok(matches) => {
                        let mut per = vec![None; forms.len()];
                        per[first] = Some(matches);
                        found.insert(slot, per);
                    }
                }
            }
        }
    }

    // Every later form over the units so far, in their order: an intersection.
    for &f in &order[1..] {
        if walk.stopped {
            break;
        }
        let form = &forms[f];
        let slots: Vec<Slot> = found.keys().copied().collect();
        for slot in slots {
            if walk.stopped {
                found.remove(&slot);
                continue;
            }
            match matches_of(&sides, form, slot, None, &mut walk) {
                Err(Stopped) => {
                    found.remove(&slot);
                }
                Ok(matches) if matches.is_empty() => {
                    found.remove(&slot);
                }
                Ok(matches) => {
                    found.get_mut(&slot).expect("a slot found")[f] = Some(matches);
                }
            }
        }
    }
    flags.positions_bounded = walk.stopped;

    // The phrase-prefixes' candidates, off the tokens that follow their
    // fixed occurrences, in the expansion's order and bounded.
    let mut completions: Vec<Option<Element<'_>>> = (0..forms.len()).map(|_| None).collect();
    for f in 0..forms.len() {
        if let Resolved::Completion { fixed, prefix } = &forms[f] {
            let union = complete(&sides, f, fixed.len(), prefix, &mut found, bounds, &mut flags);
            completions[f] = Some(union);
        }
    }
    let idfs: Vec<f64> = forms
        .iter_mut()
        .zip(completions)
        .map(|(form, completion)| {
            let fixed: f64 = form.elements().iter().map(|e| rank::idf(stats.units, e.df)).sum();
            match completion {
                Some(union) => fixed + rank::idf(stats.units, union.df),
                None => fixed,
            }
        })
        .collect();

    // The score, the span and the order.
    let mut scored: Vec<Scored<'_>> = found
        .into_iter()
        .map(|(slot, per)| {
            let (unit, dl) = sides[slot.side].body.live(slot.unit).expect("a walked unit is live");
            let mut score = 0.0;
            let mut lists: Vec<Vec<(u64, u64)>> = Vec::new();
            let mut walked: Vec<usize> = Vec::new();
            for (f, matches) in per.iter().enumerate() {
                if let Some(matches) = matches {
                    score += rank::term_score(idfs[f], matches.len(), dl, stats.avgdl);
                    lists.push(matches.iter().map(|m| (m.start, m.end)).collect());
                    walked.push(f);
                }
            }
            let (lo, hi, chosen) = hit::tightest(&lists).expect("every form walked matched");
            // The rarest form walked — the highest idf, the first of equals —
            // centres a wide conjunction's snippet.
            let rarest = (0..walked.len())
                .max_by(|&a, &b| idfs[walked[a]].total_cmp(&idfs[walked[b]]).then(b.cmp(&a)))
                .expect("a form walked");
            let focus = lists[rarest][chosen[rarest]];
            let occurrences = lists.iter().map(Vec::len).sum();
            Scored {
                slot,
                unit,
                score,
                span: Span { start: unit.start() + lo, width: hi - lo },
                focus,
                occurrences,
                per,
            }
        })
        .collect();
    scored.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.unit.key().doc().cmp(b.unit.key().doc()))
            .then_with(|| a.unit.member().cmp(&b.unit.member()))
            .then_with(|| a.span.start.cmp(&b.span.start))
    });
    let total = scored.len();

    // The displayed hits alone take a snippet, a standing and their matches.
    let hits: Vec<Hit> = scored
        .into_iter()
        .skip(opts.offset)
        .take(opts.limit)
        .map(|s| {
            let marked: Vec<Marked<'_>> = s
                .per
                .iter()
                .flatten()
                .flatten()
                .flat_map(|m| m.tokens.iter())
                .map(|t| Marked { offset: t.offset, len: t.len, term: t.term })
                .collect();
            let snippet = hit::snippet(s.unit, s.span, s.focus, &marked);
            let mut corrected: BTreeSet<(usize, usize, &str, &str)> = BTreeSet::new();
            for (f, matches) in s.per.iter().enumerate() {
                let Some(matches) = matches else { continue };
                for (e, element) in forms[f].elements().iter().enumerate() {
                    let Some(typed) = &element.fuzzy else { continue };
                    for t in matches.iter().flat_map(|m| m.tokens.iter()) {
                        if t.element == e {
                            corrected.insert((f, e, typed.as_str(), t.term));
                        }
                    }
                }
            }
            let role = if s.slot.side == 0 { Role::Published } else { Role::Supplement };
            Hit {
                doc: s.unit.key().doc().clone(),
                member: s.unit.member().cloned(),
                as_of: s.unit.as_of(),
                span: s.span,
                score: s.score,
                snippet: Some(snippet),
                kind: s.unit.kind(),
                standing: pair.standing(role, s.unit),
                occurrences: s.occurrences,
                matched: corrected
                    .into_iter()
                    .map(|(_, _, word, term)| Matched {
                        word: word.to_string(),
                        term: term.to_string(),
                    })
                    .collect(),
            }
        })
        .collect();
    answer(hits, total, opts, &flags)
}

/// A unit matched and scored, before the window is cut.
struct Scored<'a> {
    slot: Slot,
    unit: &'a Unit,
    score: f64,
    span: Span,
    focus: (u64, u64),
    occurrences: usize,
    per: Vec<Option<Vec<Match<'a>>>>,
}

/// Builds the answer from the hits listed and the facts about them (§3.1).
fn answer(hits: Vec<Hit>, total: usize, opts: &QueryOpts, flags: &Flags) -> Answer {
    let truncated = total > opts.offset + hits.len() || flags.positions_bounded;
    Answer {
        hits,
        total,
        truncated,
        more_terms: flags.more_terms,
        fuzzy_bounded: flags.fuzzy_bounded,
        positions_bounded: flags.positions_bounded,
    }
}

/// Resolves the forms against the pair's dictionaries (§3.2).
///
/// Each complete word becomes a term, a fuzzy expansion within the budget,
/// or nothing; each prefix its bounded expansion; a phrase-prefix's prefix
/// is left to the walk.
fn resolve<'a>(
    sides: &[&'a Index],
    query: &Query,
    bounds: Bounds,
    flags: &mut Flags,
) -> Vec<Resolved<'a>> {
    // The complete words in the string's order — never the trailing prefix —
    // and what each is, decided from the string's end: a term takes no
    // expansion; no term of five characters or more is fuzzy while the
    // budget lasts, the three nearest the end; past it, as typed, flagged.
    let complete: Vec<&Word> = query
        .forms
        .iter()
        .flat_map(|form| match form {
            Form::Word(w) => vec![w],
            Form::Prefix(_) => Vec::new(),
            Form::Phrase(ws) | Form::PhrasePrefix { fixed: ws, .. } => ws.iter().collect(),
        })
        .collect();
    let mut decisions = vec![Decision::AsTyped; complete.len()];
    let mut budget = FUZZY_WORDS;
    for (i, word) in complete.iter().enumerate().rev() {
        if sides.iter().any(|index| index.body.live_term(&word.term).is_some()) {
            decisions[i] = Decision::Exact;
        } else if word.term.chars().count() >= FUZZY_MIN_CHARS {
            if budget > 0 {
                budget -= 1;
                decisions[i] = Decision::Fuzzy;
            } else {
                flags.fuzzy_bounded = true;
            }
        }
    }
    let mut next = 0usize;
    let mut element_of = |word: &Word, flags: &mut Flags| -> Element<'a> {
        let decision = decisions[next];
        next += 1;
        match decision {
            Decision::Exact => exact(sides, &word.term),
            Decision::Fuzzy => fuzzy(sides, word, bounds.expansion, flags),
            Decision::AsTyped => Element::default(),
        }
    };
    let mut resolved = Vec::with_capacity(query.forms.len());
    for form in &query.forms {
        resolved.push(match form {
            Form::Word(w) => Resolved::Union(element_of(w, flags)),
            Form::Prefix(w) => Resolved::Union(prefix(sides, &w.term, bounds.expansion, flags)),
            Form::Phrase(ws) => Resolved::Phrase(ws.iter().map(|w| element_of(w, flags)).collect()),
            Form::PhrasePrefix { fixed, prefix } => Resolved::Completion {
                fixed: fixed.iter().map(|w| element_of(w, flags)).collect(),
                prefix: prefix.term.clone(),
            },
        });
    }
    resolved
}

/// Looks `term` up on every member that holds it live.
///
/// It returns the term's refs on those members and its df over the pair.
fn lookup<'a>(sides: &[&'a Index], term: &str) -> (Vec<TermRef<'a>>, usize) {
    let mut refs = Vec::new();
    let mut df = 0;
    for (side, index) in sides.iter().enumerate() {
        if let Some((spelling, id)) = index.body.live_term(term) {
            refs.push(TermRef { side, id, term: spelling });
            df += index.body.terms[id].live_units;
        }
    }
    (refs, df)
}

/// Returns the element of a word that is a term: BM25's one term (§3.3).
///
/// The element holds the term on each member holding it.
fn exact<'a>(sides: &[&'a Index], term: &str) -> Element<'a> {
    let (terms, df) = lookup(sides, term);
    let entries = terms.iter().map(|t| sides[t.side].body.live_entries(t.id)).sum();
    Element { terms, df, entries, fuzzy: None }
}

/// A candidate of an expansion: the term's refs and its df over the pair.
struct Candidate<'a> {
    refs: Vec<TermRef<'a>>,
    df: usize,
}

/// Returns the candidates keyed by the dictionary's own spelling.
///
/// They are merged over the members: `terms` yields each member's live
/// terms to admit.
fn candidates<'a>(
    sides: &[&'a Index],
    terms: impl Fn(usize, &'a Index) -> Vec<(&'a str, TermId)>,
) -> BTreeMap<&'a str, Candidate<'a>> {
    let mut out: BTreeMap<&'a str, Candidate<'a>> = BTreeMap::new();
    for (side, index) in sides.iter().enumerate() {
        for (term, id) in terms(side, index) {
            let candidate = out.entry(term).or_insert(Candidate { refs: Vec::new(), df: 0 });
            candidate.refs.push(TermRef { side, id, term });
            candidate.df += index.body.terms[id].live_units;
        }
    }
    out
}

/// Expands the candidates into one element under the expansion's bound.
///
/// The candidates are, by §3.2, "taken by document frequency descending
/// until the next would pass the bound, the term equal to the prefix taken
/// first wherever the dictionary holds it, and the bound reported as
/// `more_terms: true`" — equal frequencies in the dictionary's order. The
/// prefix's own term, the term the word itself is, is assured its place,
/// its merge the positions bound's to stop; the completions after it are
/// counted in their live entries. The union is one combined term (§3.3): df
/// the units in the union.
fn expand<'a>(
    sides: &[&'a Index],
    candidates: BTreeMap<&'a str, Candidate<'a>>,
    own: Option<&str>,
    bound: usize,
    more_terms: &mut bool,
) -> Element<'a> {
    let mut ordered: Vec<(&'a str, Candidate<'a>)> = candidates.into_iter().collect();
    ordered.sort_by(|a, b| b.1.df.cmp(&a.1.df));
    if let Some(own) = own {
        if let Some(at) = ordered.iter().position(|(term, _)| *term == own) {
            let first = ordered.remove(at);
            ordered.insert(0, first);
        }
    }
    let mut terms = Vec::new();
    let mut entries = 0usize;
    for (i, (term, candidate)) in ordered.into_iter().enumerate() {
        let cost: usize =
            candidate.refs.iter().map(|r| sides[r.side].body.live_entries(r.id)).sum();
        let is_own = i == 0 && own == Some(term);
        if !is_own && entries + cost > bound {
            *more_terms = true;
            break;
        }
        entries += cost;
        terms.extend(candidate.refs);
    }
    let df = union_df(sides, &terms);
    Element { terms, df, entries, fuzzy: None }
}

/// Counts the units of the pair holding any term of the union, each once.
fn union_df(sides: &[&Index], terms: &[TermRef<'_>]) -> usize {
    if let [one] = terms {
        return sides[one.side].body.terms[one.id].live_units;
    }
    let mut units: BTreeSet<Slot> = BTreeSet::new();
    for t in terms {
        let body = &sides[t.side].body;
        for posting in &body.terms[t.id].postings {
            if body.live(posting.unit).is_some() {
                units.insert(Slot { side: t.side, unit: posting.unit });
            }
        }
    }
    units.len()
}

/// Returns a prefix's expansion (§3.2).
///
/// The expansion takes the dictionary range under the prefix on each
/// member, by binary search, then [`expand`].
fn prefix<'a>(sides: &[&'a Index], term: &str, bound: usize, flags: &mut Flags) -> Element<'a> {
    let found = candidates(sides, |_, index| index.body.live_terms_under(term));
    expand(sides, found, Some(term), bound, &mut flags.more_terms)
}

/// Returns a fuzzy word's expansion (`search.md` §3.2 D15).
///
/// The expansion takes every live term within one edit of the word, by a
/// linear scan of each member's dictionary, then [`expand`] at the per-word
/// cap; the element names the word it corrects.
fn fuzzy<'a>(sides: &[&'a Index], word: &Word, bound: usize, flags: &mut Flags) -> Element<'a> {
    let found = candidates(sides, |_, index| {
        index.body.live_terms().filter(|(term, _)| one_edit_apart(&word.term, term)).collect()
    });
    let mut element = expand(sides, found, None, bound, &mut flags.more_terms);
    element.fuzzy = Some(word.typed.clone());
    element
}

/// Returns whether `b` is one edit from `a`, by §3.2's one edit.
///
/// One edit is one character inserted, deleted or substituted, or two
/// adjacent characters transposed — characters being Unicode scalar values,
/// "a Cyrillic substitution is one edit, not two bytes'". Equal strings are
/// no edit apart.
pub fn one_edit_apart(a: &str, b: &str) -> bool {
    let (la, lb) = (a.chars().count(), b.chars().count());
    if la.abs_diff(lb) > 1 {
        return false;
    }
    let (mut ai, mut bi) = (a.chars(), b.chars());
    loop {
        match (ai.clone().next(), bi.clone().next()) {
            (Some(x), Some(y)) if x == y => {
                ai.next();
                bi.next();
            }
            _ => break,
        }
    }
    let (ra, rb) = (ai.as_str(), bi.as_str());
    if ra.is_empty() && rb.is_empty() {
        return false;
    }
    if la == lb {
        let (mut xa, mut xb) = (ra.chars(), rb.chars());
        let (x1, y1) = (xa.next(), xb.next());
        if xa.as_str() == xb.as_str() {
            return true;
        }
        let (x2, y2) = (xa.next(), xb.next());
        return x1 == y2 && x2 == y1 && xa.as_str() == xb.as_str();
    }
    let (longer, shorter) = if la > lb { (ra, rb) } else { (rb, ra) };
    let mut rest = longer.chars();
    rest.next();
    rest.as_str() == shorter
}

/// The driver's walk over one element on one member.
///
/// The union's postings are merged by unit id, each unit yielded once with
/// its postings of every term in the union — "the rarest word's postings
/// order".
struct Merge<'a> {
    lists: Vec<(&'a [Posting], &'a str)>,
    cursors: Vec<usize>,
    heap: BinaryHeap<Reverse<(UnitId, usize)>>,
}

impl<'a> Merge<'a> {
    fn new(lists: Vec<(&'a [Posting], &'a str)>) -> Merge<'a> {
        let mut heap = BinaryHeap::new();
        for (i, (list, _)) in lists.iter().enumerate() {
            if let Some(first) = list.first() {
                heap.push(Reverse((first.unit, i)));
            }
        }
        Merge { cursors: vec![0; lists.len()], lists, heap }
    }

    fn next(&mut self) -> Option<(UnitId, Vec<(&'a Posting, &'a str)>)> {
        let Reverse((unit, _)) = *self.heap.peek()?;
        let mut group = Vec::new();
        while let Some(&Reverse((u, i))) = self.heap.peek() {
            if u != unit {
                break;
            }
            self.heap.pop();
            let (list, term) = self.lists[i];
            group.push((&list[self.cursors[i]], term));
            self.cursors[i] += 1;
            if let Some(after) = list.get(self.cursors[i]) {
                self.heap.push(Reverse((after.unit, i)));
            }
        }
        Some((unit, group))
    }
}

/// Returns a unit's occurrences over several postings, in ordinal order.
///
/// Each occurrence comes with its term.
fn by_ordinal<'a>(group: Vec<(&'a Posting, &'a str)>) -> Vec<(Occurrence, &'a str)> {
    let mut out: Vec<(Occurrence, &'a str)> = group
        .into_iter()
        .flat_map(|(posting, term)| posting.occurrences.iter().map(move |&o| (o, term)))
        .collect();
    out.sort_by_key(|(o, _)| o.ordinal);
    out
}

/// Returns an element's occurrences in one unit, admitted to the walk.
///
/// Each term's posting is found by binary search.
///
/// # Errors
///
/// `Stopped` where the positions bound stopped the walk.
fn at<'a>(
    sides: &[&'a Index],
    element: &Element<'a>,
    slot: Slot,
    walk: &mut Walk,
) -> Result<Vec<(Occurrence, &'a str)>, Stopped> {
    let body = &sides[slot.side].body;
    let group: Vec<(&Posting, &str)> = element
        .terms
        .iter()
        .filter(|t| t.side == slot.side)
        .filter_map(|t| body.posting(t.id, slot.unit).map(|p| (p, t.term)))
        .collect();
    walk.admit(group.iter().map(|(p, _)| p.occurrences.len()).sum())?;
    Ok(by_ordinal(group))
}

/// Returns a form's matches in one unit (§3.2).
///
/// A union matches at its every occurrence; a phrase at its adjacent
/// ordinals; a phrase-prefix at its fixed occurrences, each with the token
/// that follows it. `driver` is the element already walked with its
/// occurrences; every other element is fetched here.
///
/// # Errors
///
/// `Stopped` where fetching an element meets the positions bound.
fn matches_of<'a>(
    sides: &[&'a Index],
    form: &Resolved<'a>,
    slot: Slot,
    driver: Option<(usize, Vec<(Occurrence, &'a str)>)>,
    walk: &mut Walk,
) -> Result<Vec<Match<'a>>, Stopped> {
    let elements = form.elements();
    let mut lists: Vec<Option<Vec<(Occurrence, &'a str)>>> = vec![None; elements.len()];
    if let Some((d, occurrences)) = driver {
        lists[d] = Some(occurrences);
    }
    for (i, element) in elements.iter().enumerate() {
        if lists[i].is_none() {
            lists[i] = Some(at(sides, element, slot, walk)?);
        }
    }
    let lists: Vec<Vec<(Occurrence, &'a str)>> =
        lists.into_iter().map(|l| l.expect("filled above")).collect();
    let mut matches = match form {
        Resolved::Union(_) => lists[0]
            .iter()
            .map(|&(o, term)| Match {
                start: o.offset,
                end: o.offset + u64::from(o.len),
                tokens: vec![Tok { offset: o.offset, len: o.len, term, element: 0 }],
                next: None,
            })
            .collect(),
        Resolved::Phrase(_) | Resolved::Completion { .. } => adjacent(&lists, form.driver()),
    };
    if let Resolved::Completion { .. } = form {
        let (unit, _) = sides[slot.side].body.live(slot.unit).expect("a walked unit is live");
        matches.retain_mut(|m| {
            m.next = next_token(unit, m.end);
            m.next.is_some()
        });
    }
    Ok(matches)
}

/// Returns a phrase's matches: adjacent token ordinals in one unit.
///
/// §3.2's phrase is "matched by adjacent token ordinals in one unit": for
/// each occurrence of the driver element, the other elements are found at
/// the ordinals before and after it, each by binary search; the match runs
/// from the first token's offset to the last's end.
fn adjacent<'a>(lists: &[Vec<(Occurrence, &'a str)>], driver: usize) -> Vec<Match<'a>> {
    let mut matches = Vec::new();
    for &(anchor, _) in &lists[driver] {
        let Some(first) = anchor.ordinal.checked_sub(driver as u32) else { continue };
        let mut tokens = Vec::with_capacity(lists.len());
        for (i, list) in lists.iter().enumerate() {
            let Some(want) = first.checked_add(i as u32) else { break };
            match list.binary_search_by_key(&want, |(o, _)| o.ordinal) {
                Ok(j) => {
                    let (o, term) = list[j];
                    tokens.push(Tok { offset: o.offset, len: o.len, term, element: i });
                }
                Err(_) => break,
            }
        }
        if tokens.len() == lists.len() {
            let last = tokens.last().expect("one token per element");
            matches.push(Match {
                start: tokens[0].offset,
                end: last.offset + u64::from(last.len),
                tokens,
                next: None,
            });
        }
    }
    matches
}

/// The lookahead a next-token cut starts with.
///
/// It is doubled while the segment found reaches its end.
const LOOKAHEAD: usize = 256;

/// Returns the token at the ordinal after a fixed occurrence ending at `end`.
///
/// This is the phrase-prefix's cut (§3.2), "read off the stored text at the
/// occurrence's end …, one token cut there" — the first segment the
/// tokenizer's rule keeps in the text item's valid stretch after `end`; none
/// where the item ends, a `Gap` follows, or an invalid byte breaks the
/// stretch, each a token break the item table already marks, and none where
/// the first `LOOKAHEAD` bytes hold no segment the rule keeps, though the
/// tokenizer's next token may stand past them. The stretch is read in a
/// bounded lookahead, widened while the segment found reaches its edge, so
/// the read grows with the token found and not with the item.
fn next_token(unit: &Unit, end: u64) -> Option<Next> {
    let index = unit.item_at(end.checked_sub(1)?)?;
    let Item::Text { start, bytes } = &unit.items()[index] else { return None };
    let rest = &bytes[(end - (start - unit.start())) as usize..];
    let mut look = LOOKAHEAD;
    loop {
        let window = &rest[..rest.len().min(look)];
        let valid = window.utf8_chunks().next()?.valid();
        let segment = segments(valid).next()?;
        let reaches_edge = segment.offset + segment.len >= valid.len();
        if reaches_edge && window.len() < rest.len() && valid.len() + 4 >= window.len() {
            look *= 2;
            continue;
        }
        return Some(Next {
            offset: end + segment.offset as u64,
            len: u32::try_from(segment.len).expect("a segment under the lookahead"),
            term: segment.term,
        });
    }
}

/// Completes phrase-prefix `f` from the terms that follow its occurrences.
///
/// Over form `f`'s fixed occurrences in every unit reached, the terms that
/// follow them and lie in the prefix's range are the candidates (§3.2's
/// phrase-prefix), taken in the order "the prefix's own term first and
/// document frequency descending" and bounded as an expansion is; each
/// fixed occurrence whose next token is a taken term becomes a match through
/// it, the rest fall, and a unit left with none leaves the answer. Where the
/// fixed phrase passed the positions bound the candidates are those the
/// units reached supply — the dictionary range's terms that follow them —
/// and the answer is flagged. The union element returned scores as one
/// combined term beside the fixed words' (§3.3).
fn complete<'a>(
    sides: &[&'a Index],
    f: usize,
    fixed: usize,
    prefix: &str,
    found: &mut BTreeMap<Slot, Vec<Option<Vec<Match<'a>>>>>,
    bounds: Bounds,
    flags: &mut Flags,
) -> Element<'a> {
    let mut following: BTreeMap<&'a str, Candidate<'a>> = BTreeMap::new();
    for per in found.values() {
        let Some(matches) = &per[f] else { continue };
        for next in matches.iter().filter_map(|m| m.next.as_ref()) {
            if !next.term.starts_with(prefix) || following.contains_key(next.term.as_str()) {
                continue;
            }
            let (refs, df) = lookup(sides, &next.term);
            if let Some(first) = refs.first() {
                following.insert(first.term, Candidate { refs, df });
            }
        }
    }
    let union = expand(sides, following, Some(prefix), bounds.expansion, &mut flags.more_terms);
    let taken: BTreeMap<&str, &'a str> = union.terms.iter().map(|t| (t.term, t.term)).collect();
    found.retain(|_, per| {
        let Some(matches) = per[f].as_mut() else { return true };
        matches.retain_mut(|m| match &m.next {
            Some(next) => match taken.get(next.term.as_str()) {
                Some(&term) => {
                    m.end = next.offset + u64::from(next.len);
                    m.tokens.push(Tok { offset: next.offset, len: next.len, term, element: fixed });
                    true
                }
                None => false,
            },
            None => false,
        });
        !matches.is_empty()
    });
    union
}

#[cfg(test)]
mod tests;
