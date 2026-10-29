//! THE PANEL's DATA (the link-sets design §5.2) and THE COUNT (§5.6;
//! PUB-3.8's four terms).
//!
//! The rows, one per home the enumeration grouped, in the design's order:
//! the draft's own set first, then the notes set(s) in the caller's order,
//! then the person's other sets, PRIVATE before PUBLIC — the state off
//! `doc_metadata`, one read per home; each row's label the home's first
//! line, read by one `retrieve_doc_v_span_set` and one `retrieve_v` per
//! home; per row the offered links folded by TYPE with each type's count
//! and each far document, and the line's counts as DATA — ⟨p⟩ links
//! pointing into private documents, ⟨d⟩ links with an end wholly on words
//! of the draft the selection leaves out, ⟨c⟩ links with an end running
//! past the selection's cut, ⟨t⟩ links typed by a private document, ⟨u⟩
//! revisions of links already published. THE FORMATTING LINE, in the
//! draft's own set alone, holds the links the line's TEST keeps: exactly one
//! of `from` and `to` non-empty, the type slot exactly one unit span in the
//! formatting types' own subtrees — `3.20` heading, `3.21` paragraph and its
//! family, `3.23` inline and its family save `3.23.4` mark — and no other
//! span save a parameter inside the registry document. THE HELD REMOVALS are
//! its job list: `D`'s `3.24` records, read home-constrained and kept by
//! the exact type, each naming a published mark by address; the mark read
//! once; a removal whose mark is off the selection stays off the line; one
//! whose retraction already STANDS (the retraction-stands read) is spent
//! and dropped; the ⟨r⟩/⟨e⟩ split by the job list's overlap with the line's
//! own marks of the same type — a RE-MAKE is the mark's `links` entry and
//! the removal's `retract` entry, counted once in ⟨e⟩ and in neither ⟨n⟩
//! nor ⟨r⟩. A PUBLIC row states whether `E` is read with the set — the
//! read-with presence read over the person's published homes (W1 (a)) —
//! and draws no switch; the same read runs for every published document of
//! the person's, the possible destinations, so the count knows which
//! read-with a destination still needs. Every row's SWITCH is the caller's
//! input ([`Switches`]: a private row OFF by default, the formatting line no
//! switch, a public row its state).

use std::collections::{BTreeMap, BTreeSet};

use skep_address::Address;

use crate::address::{document_of, parse_address};
use crate::board::answers::LinkValue;
use crate::board::frames::{self, Slot, REGISTRY_DOCUMENT, T_HELD_REMOVAL, T_READ_WITH};
use crate::board::T_RETRACTION;

use super::enumerate::{touches, Candidate, Enumeration};
use super::{home_of_link, owned_by, Door, Fault, ISpan, Inputs, Publisher};

/// The formatting types' subtrees (the link-sets design §5.2; the registry's
/// vocabulary): heading `3.20`, the paragraph family `3.21`, the inline
/// family `3.23`.
pub const FORMATTING_TYPES: [&str; 3] = ["1.1.0.1.0.1.0.3.20", "1.1.0.1.0.1.0.3.21", "1.1.0.1.0.1.0.3.23"];

/// The one member of the inline family the line does NOT take: `3.23.4`
/// mark, a highlight, offered in its set's own row (proposal 15).
pub const INLINE_MARK: &str = "1.1.0.1.0.1.0.3.23.4";

/// How many positions of a home the label read takes at most: the first
/// line is cut at the first newline within them.
pub const LABEL_POSITIONS: u64 = 256;

/// A row's kind, and the order rows stand in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowKind {
    /// The draft's own set — the text being published.
    Own,
    /// A notes document the caller named.
    Notes,
    /// Another private set of the person's.
    Private,
    /// A set in a published document of the person's.
    Public {
        /// Whether `E` is read with the set now.
        read_with: bool,
    },
}

/// The links of one type in a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeFold {
    /// The type slot's address.
    pub ty: String,
    /// How many of the row's links carry it.
    pub n: usize,
    /// Each far document the links of this type point into, in address
    /// order.
    pub far: Vec<String>,
}

/// The line's counts, as data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LineCounts {
    /// Links with an end into a private document.
    pub p: usize,
    /// Links with an end wholly on words of this draft the selection leaves
    /// out.
    pub d: usize,
    /// Links with an end that runs past the selection's cut.
    pub c: usize,
    /// Links typed by a private document.
    pub t: usize,
    /// Revisions of links already published, not offered.
    pub u: usize,
}

/// One row of the panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The home — the set.
    pub home: Address,
    /// Its kind.
    pub kind: RowKind,
    /// The home's first line, as its bytes read.
    pub label: Vec<u8>,
    /// The offered links on the row: indices into the enumeration's
    /// candidates, the formatting line's left out.
    pub links: Vec<usize>,
    /// The links folded by type.
    pub types: Vec<TypeFold>,
    /// The line's counts.
    pub line: LineCounts,
    /// How many of the row's links the read-through reached: the private
    /// move's share where the row is left off.
    pub read_through: usize,
}

/// One held removal of the draft: the formatting line's job list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removal {
    /// The `3.24` record in the draft.
    pub record: Address,
    /// The published mark it names, by address.
    pub mark: Address,
    /// The mark's value as stored.
    pub mark_value: LinkValue,
    /// Whether the mark is on the selection's words.
    pub on_selection: bool,
    /// Whether a retraction of the mark already stands — spent, no entry.
    pub spent: bool,
    /// The formatting-line mark that re-makes it, where one does: an index
    /// into the enumeration's candidates.
    pub remake: Option<usize>,
}

impl Removal {
    /// Whether the removal is on the job list: on the selection and not
    /// spent.
    pub fn listed(&self) -> bool {
        self.on_selection && !self.spent
    }
}

/// The formatting line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Formatting {
    /// The marks on the line: indices into the enumeration's candidates.
    pub marks: Vec<usize>,
    /// How many of them run past the selection's cut.
    pub cut: usize,
    /// The held removals, listed or not.
    pub removals: Vec<Removal>,
}

impl Formatting {
    /// Returns the job list: the removals on the selection, not spent.
    pub fn job_list(&self) -> Vec<&Removal> {
        self.removals.iter().filter(|r| r.listed()).collect()
    }
}

/// The panel's data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Panel {
    /// The rows, in the design's order.
    pub rows: Vec<Row>,
    /// The formatting line.
    pub formatting: Formatting,
    /// Per published document of the person's, whether `E` is read with it
    /// now — the destinations' states.
    pub read_with: BTreeMap<Address, bool>,
    /// The frames sent, per step.
    pub frames: Vec<(&'static str, usize)>,
}

/// Where a switched-on private row's links are published into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    /// The member the shot mints — the page at that version.
    Member,
    /// A published document of the person's, one pick away.
    Set(Address),
}

/// The rows' switches — the caller's input.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Switches {
    /// The private rows switched ON, by home; every other private row is
    /// off, the formatting line has no switch and a public row only its
    /// state.
    pub on: BTreeSet<Address>,
    /// A switched-on row's destination; the member where unnamed.
    pub destinations: BTreeMap<Address, Destination>,
}

impl Switches {
    /// Returns the destination of `home`'s row.
    pub fn destination(&self, home: &Address) -> Destination {
        self.destinations.get(home).cloned().unwrap_or(Destination::Member)
    }
}

/// THE COUNT's four numbers (PUB-3.8), and the claim clause.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Count {
    /// ⟨l⟩: the switched-on sets' `links` entries plus the `read_with`
    /// entries.
    pub l: usize,
    /// ⟨n⟩: the formatting line's `links` entries that re-make nothing.
    pub n: usize,
    /// ⟨r⟩: the `retract` entries no re-make covers.
    pub r: usize,
    /// ⟨e⟩: the re-makes — one `links` entry and one `retract` entry each.
    pub e: usize,
    /// Whether the one write carries the edition claim.
    pub claim: bool,
    /// The `read_with` entries the count carries: each switched-on private
    /// row's destination other than the member, once, where `E` is not
    /// already read with it.
    pub read_with: Vec<Address>,
}

/// Returns whether `value` is a mark the formatting line takes.
pub fn is_formatting(value: &LinkValue) -> bool {
    if value.from.is_empty() == value.to.is_empty() {
        return false;
    }
    let mut named = 0usize;
    for span in &value.ty {
        let under = |root: &str| span.start == root || span.start.starts_with(&format!("{root}."));
        if span.is_unit() && FORMATTING_TYPES.iter().any(|t| under(t)) && !under(INLINE_MARK) {
            named += 1;
        } else if !under(REGISTRY_DOCUMENT) {
            return false;
        }
    }
    named == 1
}

/// Returns the positions of `value`'s ends on `selection`, as ranges.
fn on_selection(value: &LinkValue, selection: &[super::Run]) -> Vec<(String, u64, u64)> {
    let mut out = Vec::new();
    for s in value.from.iter().chain(&value.to).filter_map(ISpan::of) {
        for r in selection {
            if let Some((lo, hi)) = r.overlap(&s.chain, s.first, s.reach()) {
                out.push((s.chain.clone(), lo, hi));
            }
        }
    }
    out
}

fn ranges_overlap(a: &[(String, u64, u64)], b: &[(String, u64, u64)]) -> bool {
    a.iter().any(|(ca, la, ha)| b.iter().any(|(cb, lb, hb)| ca == cb && la.max(lb) < ha.min(hb)))
}

/// Builds the panel's data from the enumeration.
///
/// # Errors
///
/// The reads' faults, as `enumerate`'s.
pub fn panel(p: &Publisher<'_>, inputs: &Inputs, enumeration: &Enumeration) -> Result<Panel, Fault> {
    let door = Door::new(p.board, p.token);
    panel_with(&door, p, inputs, enumeration)
}

/// Builds the panel's data through `door`.
pub(crate) fn panel_with(door: &Door<'_>, p: &Publisher<'_>, inputs: &Inputs, e: &Enumeration) -> Result<Panel, Fault> {
    let draft = inputs.draft.to_string();
    let trunk = inputs.doc.as_ref().map(ToString::to_string);

    // The formatting line: the draft's own set's marks by the line's test.
    door.step("formatting");
    let own: Vec<usize> = e.homes.iter().find(|(h, _)| *h == inputs.draft).map(|(_, i)| i.clone()).unwrap_or_default();
    let marks: Vec<usize> = own.iter().copied().filter(|&i| e.candidates[i].offered() && is_formatting(&e.candidates[i].value)).collect();
    let cut = marks
        .iter()
        .filter(|&&i| e.candidates[i].end_spans().iter().any(|s| s.touches(&inputs.selection) && !s.within(&inputs.selection)))
        .count();

    // The held removals: D's 3.24 records, the mark read, the retraction read.
    door.step("removals");
    let unit = |a: &str| frames::unit_span(a).as_array().cloned().unwrap_or_default();
    let mut removals = Vec::new();
    let hits = door.addrs(&draft, &frames::find_links_four(Slot::Spans(&unit(&draft)), Slot::Any, Slot::Any, Slot::Spans(&unit(T_HELD_REMOVAL))))?;
    for hit in hits {
        let Some(value) = door.link(&hit)? else { continue };
        if !value.typed_exactly(T_HELD_REMOVAL) {
            continue;
        }
        let Some(mark) = value.to.first().filter(|s| s.is_unit()).map(|s| s.start.clone()) else { continue };
        if home_of_link(&mark).is_none() {
            continue;
        }
        let Some(mark_value) = door.link(&mark)? else { continue };
        let on_selection = touches(&mark_value, &inputs.selection);
        let spent = !door.addrs(&mark, &frames::find_links_ftt(T_RETRACTION, &mark))?.is_empty();
        let (Some(record), Some(mark_addr)) = (parse_address(&hit), parse_address(&mark)) else { continue };
        let remake = (on_selection && !spent)
            .then(|| {
                let mark_on = on_selection_of(&mark_value, &inputs.selection);
                marks.iter().copied().find(|&i| {
                    let c = &e.candidates[i];
                    c.value.type_address() == mark_value.type_address() && ranges_overlap(&on_selection_of(&c.value, &inputs.selection), &mark_on)
                })
            })
            .flatten();
        removals.push(Removal { record, mark: mark_addr, mark_value, on_selection, spent, remake });
    }

    // The rows: state, label, the fold by type, the line's counts.
    door.step("homes");
    let mut rows: Vec<Row> = Vec::new();
    for (home, indices) in &e.homes {
        let home_text = home.to_string();
        let published = door.metadata(&home_text)?.published;
        let kind = if *home == inputs.draft {
            RowKind::Own
        } else if inputs.notes.contains(home) {
            RowKind::Notes
        } else if published {
            RowKind::Public { read_with: false }
        } else {
            RowKind::Private
        };
        let links: Vec<usize> = indices.iter().copied().filter(|i| e.candidates[*i].offered() && !marks.contains(i)).collect();
        let u = indices.iter().filter(|i| e.candidates[**i].revised).count();
        rows.push(Row { home: home.clone(), kind, label: Vec::new(), links, types: Vec::new(), line: LineCounts { u, ..LineCounts::default() }, read_through: 0 });
    }
    rows.sort_by_key(|r| match r.kind {
        RowKind::Own => (0, 0, r.home.to_string()),
        RowKind::Notes => (1, inputs.notes.iter().position(|n| *n == r.home).unwrap_or(0), String::new()),
        RowKind::Private => (2, 0, address_key(&r.home.to_string())),
        RowKind::Public { .. } => (3, 0, address_key(&r.home.to_string())),
    });

    door.step("far");
    for row in &mut rows {
        let mut folds: BTreeMap<String, (usize, BTreeSet<String>)> = BTreeMap::new();
        let mut line = row.line;
        for &i in &row.links {
            let c: &Candidate = &e.candidates[i];
            if matches!(c.via, super::enumerate::Via::ReadThrough(_)) {
                row.read_through += 1;
            }
            let mut far: BTreeSet<String> = BTreeSet::new();
            let (mut p_hit, mut d_hit, mut c_hit) = (false, false, false);
            for span in c.value.from.iter().chain(&c.value.to) {
                match ISpan::of(span) {
                    Some(s) => {
                        let touching = s.touches(&inputs.selection);
                        if touching && !s.within(&inputs.selection) {
                            c_hit = true;
                        }
                        if !touching {
                            let doc = s.document().unwrap_or_default();
                            if doc == draft {
                                d_hit = true;
                            } else if !doc.is_empty() {
                                far.insert(doc);
                            }
                        }
                    }
                    None => {
                        if let Some(doc) = document_of(&span.start) {
                            far.insert(doc);
                        }
                    }
                }
            }
            for doc in &far {
                if trunk.as_deref() == Some(doc.as_str()) {
                    continue;
                }
                if !door.metadata(doc)?.published {
                    p_hit = true;
                }
            }
            let ty = c.value.type_address().unwrap_or("").to_string();
            if let Some(doc) = document_of(&ty) {
                if doc != REGISTRY_DOCUMENT && !door.metadata(&doc)?.published {
                    line.t += 1;
                }
            }
            line.p += usize::from(p_hit);
            line.d += usize::from(d_hit);
            line.c += usize::from(c_hit);
            let entry = folds.entry(ty).or_insert((0, BTreeSet::new()));
            entry.0 += 1;
            entry.1.extend(far);
        }
        row.line = line;
        row.types = folds.into_iter().map(|(ty, (n, far))| TypeFold { ty, n, far: far.into_iter().collect() }).collect();
    }

    door.step("labels");
    for row in &mut rows {
        let home = row.home.to_string();
        let extent = if row.home == inputs.draft { e.extent } else { door.extent(&home)? };
        let width = extent.min(LABEL_POSITIONS);
        if width > 0 {
            let bytes: Vec<u8> = door.values(&home, 1, width)?.into_iter().flatten().collect();
            let end = bytes.iter().position(|b| *b == b'\n').unwrap_or(bytes.len());
            row.label = bytes[..end].to_vec();
        }
    }

    door.step("read_with");
    let mut read_with: BTreeMap<Address, bool> = BTreeMap::new();
    if let Some(edition) = &trunk {
        for set in &inputs.published {
            let set_text = set.to_string();
            if set_text == *edition {
                continue;
            }
            let stands = read_with_stands(door, p, edition, &set_text)?;
            read_with.insert(set.clone(), stands);
        }
    }
    for row in &mut rows {
        if let RowKind::Public { read_with: state } = &mut row.kind {
            *state = read_with.get(&row.home).copied().unwrap_or(false);
        }
    }

    Ok(Panel { rows, formatting: Formatting { marks, cut, removals }, read_with, frames: door.counts() })
}

fn on_selection_of(value: &LinkValue, selection: &[super::Run]) -> Vec<(String, u64, u64)> {
    on_selection(value, selection)
}

/// Returns an address's components as numbers, the address order's key.
fn address_key(a: &str) -> String {
    a.split('.').map(|c| format!("{:020}", c.parse::<u64>().unwrap_or(0))).collect::<Vec<_>>().join(".")
}

/// Returns whether a read-with from `edition` to `set` stands in a PUBLISHED
/// home the person owns — the presence the daemon's plan reads (W1 (a)):
/// the rows the three slots match, each kept where its stored `from` and
/// `to` are exactly the two unit spans, its home's account the person's off
/// the address and its home published.
pub(crate) fn read_with_stands(door: &Door<'_>, p: &Publisher<'_>, edition: &str, set: &str) -> Result<bool, Fault> {
    let unit = |a: &str| frames::unit_span(a).as_array().cloned().unwrap_or_default();
    let hits = door.addrs(set, &frames::find_links_four(Slot::Any, Slot::Spans(&unit(edition)), Slot::Spans(&unit(set)), Slot::Spans(&unit(T_READ_WITH))))?;
    for hit in hits {
        let Some(home) = home_of_link(&hit) else { continue };
        if !owned_by(home, p.account) {
            continue;
        }
        let Some(value) = door.link(&hit)? else { continue };
        let exact = |slot: &[crate::board::answers::LinkSpan], start: &str| slot.len() == 1 && slot[0].start == start && slot[0].is_unit();
        if !(exact(&value.from, edition) && exact(&value.to, set)) {
            continue;
        }
        if door.metadata(home)?.published {
            return Ok(true);
        }
    }
    Ok(false)
}

/// THE COUNT (PUB-3.8): the four numbers from the rows as switched, and the
/// claim clause.
pub fn count(panel: &Panel, switches: &Switches, inputs: &Inputs) -> Count {
    let mut l = 0usize;
    let mut read_with: Vec<Address> = Vec::new();
    for row in &panel.rows {
        if matches!(row.kind, RowKind::Public { .. }) || !switches.on.contains(&row.home) {
            continue;
        }
        l += row.links.len();
        if let Destination::Set(set) = switches.destination(&row.home) {
            let stands = panel.read_with.get(&set).copied().unwrap_or(false);
            if !stands && !read_with.contains(&set) && inputs.doc.as_ref() != Some(&set) {
                read_with.push(set);
            }
        }
    }
    l += read_with.len();
    let remakes: BTreeSet<usize> = panel.formatting.removals.iter().filter(|r| r.listed()).filter_map(|r| r.remake).collect();
    let e = panel.formatting.removals.iter().filter(|r| r.listed() && r.remake.is_some()).count();
    let n = panel.formatting.marks.iter().filter(|m| !remakes.contains(m)).count();
    let r = panel.formatting.removals.iter().filter(|r| r.listed() && r.remake.is_none()).count();
    // The claim clause where the caller asks the claim, at either form:
    // whether the edition may take it is the board's to refuse.
    Count { l, n, r, e, claim: inputs.claim, read_with }
}
