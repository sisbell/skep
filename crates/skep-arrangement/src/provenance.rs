//! The append-only content-provenance relation R (§A/§9).
//!
//! It records what each document has ever contained — the spans appended
//! for it, and the run-list a snapshot named for it — and holds the
//! historical reads that answer off the two.

use serde::{Deserialize, Serialize};
use skep_address::{classify_spans, Address, Span, SpanRel, SpanSet};

use crate::decode::{element_by_element, entry_by_entry};
use crate::run::Run;
use crate::run_list::table::{Decoded, Keyed, Root, Writer};
use crate::run_list::RunList;

/// R, keyed by placing document: every content span a document ever contained.
///
/// The spans are kept in placement order (ASN-0047 P2: a pair `(a, d)`
/// records that `d` contained the I-address `a`, and no transition removes
/// one).
///
/// **Append-only is the card**, and it is structural: this type offers
/// [`append`](Provenance::append), [`named`](Provenance::named) and reads,
/// and no way to drop or rewrite a
/// pair. That absence is why a deleted address keeps its provenance without
/// any op having to promise it, and why R is non-recomputable from the
/// current arrangement — a deletion contracts the arrangement and leaves R
/// standing, so SHOWDELETIONS has something to subtract from. Recovered by
/// replay like the arrangement itself, never rebuilt.
///
/// **Two parts**, per placing document. `appended` holds a span for each
/// run a placement or an edit put into the document, in placement order.
/// `named` holds, for a document a snapshot minted, the run-list it was
/// born sharing as that list stood at the mint — one handle on the tree
/// its source held then, so naming costs the fold no run, and the list is
/// kept as it stood however the document or its source move afterwards.
/// What a document ever contained is the two together
/// ([`ever_contained`](Provenance::ever_contained)): the named list's runs
/// and then the spans appended since. A member a shot minted holds neither
/// for its mint: its arrangement never contracts, so the reads on
/// [`M5State`](crate::M5State) take R↾member off the arrangement itself.
///
/// **Span shape**, and there are two doors that keep it: every span the fold
/// records is a [`Run::iextent`] — level-uniform and element-level.
/// [`append`](Provenance::append) takes runs and lifts them itself, so no
/// caller can record a span of another shape, and the serde shadow below
/// re-enters the level-uniformity clause on the decode path, so no
/// checkpoint can present a span that breaks that clause either. The reads
/// rest on that: it is what makes
/// [`M5State::deletions`](crate::M5State::deletions)' per-class
/// `difference_sets` infallible, M1's set ops gating on level-uniformity as
/// well as on length — and a `.expect` on a public read is not a thing to
/// leave standing on checkpoint integrity when the type can hold it instead.
///
/// Two maps, each keyed by the placing document's `Address` — which orders
/// and serializes as its bare tumbler, and re-validates on the way back in.
///
/// **Two serde forms.** The one derived here writes the appended spans' map
/// and then the named lists', each list as its runs in V-order: the form a
/// rendering of the slice by its run sequences takes. A checkpoint writes
/// the other ([`rooted`](Provenance::rooted)): the same two maps, each
/// named list the id of its root in the slice's node table, so a named
/// list is written once with whatever arrangement still shares its nodes —
/// and written at all, a named list being reached from R alone once its
/// source has moved on.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ProvenanceShadow")]
pub(crate) struct Provenance {
    appended: im::OrdMap<Address, im::Vector<Span>>,
    named: im::OrdMap<Address, RunList>,
}

/// The deserialization mint path: the serde `try_from` shadow.
///
/// [`Run`] and M1's `Address`/`Span`/`Tumbler` each carry one too. The map is
/// decoded entry by entry ([`entry_by_entry`]) and each document's spans
/// element by element ([`EverContainedShadow`]) — each key re-entering
/// `validate` and each span re-entering T12 through their own shadows, and no
/// count the checkpoint body declares, the map's or a document's, sizing a
/// reservation — and then the span-shape clause the reads depend on is
/// re-established here, so a checkpoint whose R holds a span that is not
/// level-uniform, which no [`Run::iextent`] is, is a decode failure M2
/// reports as corruption rather than a value that panics
/// [`M5State::deletions`](crate::M5State::deletions) on the next
/// SHOWDELETIONS, on a worker thread, per request.
///
/// **Level-uniformity is the clause**, and it is the minimal one: it is what
/// M1's `level_class` gates on, hence exactly what the per-class
/// `difference_sets` needs. Element-level-ness is not re-checked — no read
/// faults on its absence, and asking it here would be a second definition of
/// a run start rather than the one [`Run::admits_start`] owns. One length
/// comparison per recorded span, once, at checkpoint load.
///
/// It reads exactly what a `Provenance` writes — the same two maps in the
/// same order, each appended value a newtype over the same vector, and
/// bincode encodes a newtype as its inner value — and `Serialize` is derived
/// on `Provenance` itself, so the shadow costs the encoding nothing. The
/// named lists decode entry by entry too, each through the run-list's own
/// door, which reads it run by run and establishes its maximal merge.
#[derive(Deserialize)]
struct ProvenanceShadow {
    #[serde(deserialize_with = "entry_by_entry")]
    appended: im::OrdMap<Address, EverContainedShadow>,
    #[serde(deserialize_with = "entry_by_entry")]
    named: im::OrdMap<Address, RunList>,
}

/// R in the table form, as a checkpoint writes it.
///
/// The appended spans' map as it stands, then the named lists' map with
/// each list the [`Root`] the slice's node table answered for it.
#[derive(Serialize)]
#[serde(rename = "Provenance")]
pub(crate) struct Rooted<'l> {
    appended: &'l im::OrdMap<Address, im::Vector<Span>>,
    named: Keyed<'l, Address, RunList, Root>,
}

/// R in the table form, as the decode door reads it: [`Rooted`]'s shadow.
///
/// Both maps are decoded entry by entry and each document's spans element
/// by element, as [`ProvenanceShadow`] decodes them; the named lists are
/// ids until [`resolved`](RootedShadow::resolved) takes them off the table.
#[derive(Deserialize)]
#[serde(rename = "Provenance")]
pub(crate) struct RootedShadow {
    #[serde(deserialize_with = "entry_by_entry")]
    appended: im::OrdMap<Address, EverContainedShadow>,
    #[serde(deserialize_with = "entry_by_entry")]
    named: im::OrdMap<Address, Root>,
}

impl RootedShadow {
    /// Returns the relation decoded, its named lists taken off `table`.
    ///
    /// # Errors
    ///
    /// The span-shape clause [`ProvenanceShadow`] holds, in its words, and
    /// the table's own refusal of a root (`Decoded::list`).
    pub(crate) fn resolved<E: serde::de::Error>(self, table: &mut Decoded) -> Result<Provenance, E> {
        let appended = level_uniform(self.appended).map_err(E::custom)?;
        let mut named = im::OrdMap::new();
        for (doc, root) in self.named {
            named.insert(doc, table.list(root).map_err(E::custom)?);
        }
        Ok(Provenance { appended, named })
    }
}

/// Returns the appended spans as decoded, held to the span-shape clause.
///
/// # Errors
///
/// Names the clause where a recorded span is not level-uniform.
fn level_uniform(
    decoded: im::OrdMap<Address, EverContainedShadow>,
) -> Result<im::OrdMap<Address, im::Vector<Span>>, &'static str> {
    let appended: im::OrdMap<Address, im::Vector<Span>> =
        decoded.into_iter().map(|(doc, EverContainedShadow(spans))| (doc, spans)).collect();
    if appended.values().flatten().all(Span::is_level_uniform) {
        Ok(appended)
    } else {
        Err("provenance: every recorded span is a run I-extent (level-uniform)")
    }
}

/// One document's R↾doc as [`ProvenanceShadow`] decodes it.
///
/// Its recorded spans are read element by element ([`element_by_element`]),
/// so a span count the checkpoint body does not carry is refused where the
/// input runs out rather than reserved for. A carrier and nothing else — the
/// conversion below unwraps it into the relation.
#[derive(Clone, Deserialize)]
struct EverContainedShadow(#[serde(deserialize_with = "element_by_element")] im::Vector<Span>);

impl TryFrom<ProvenanceShadow> for Provenance {
    type Error = &'static str;
    fn try_from(s: ProvenanceShadow) -> Result<Provenance, &'static str> {
        Ok(Provenance { appended: level_uniform(s.appended)?, named: s.named })
    }
}

impl Provenance {
    /// Returns R in the table form, each named list taken as a root of
    /// `table`.
    ///
    /// The lists are taken in address order, the order the form writes
    /// them, so the table's walk meets them in the order the bytes name
    /// them.
    pub(crate) fn rooted<'l>(&'l self, table: &mut Writer<'l>) -> Rooted<'l> {
        Rooted { appended: &self.appended, named: Keyed::of(&self.named, |list| table.root(list)) }
    }

    /// Returns R with the I-extents of `runs` appended to R↾doc.
    ///
    /// It is persistent — the receiver is untouched. Called from the placing
    /// folds, co-located with the arrangement update they pair with, so one
    /// new state carries both halves of J1★. The only mutator, and it only
    /// ever lengthens a document's sequence.
    ///
    /// Takes the runs rather than their spans: the lift is the one this type
    /// admits, so performing it here makes the span-shape invariant above
    /// true at the mutator instead of owed by each caller.
    #[must_use = "append returns the extended relation; R is persistent and the receiver is untouched"]
    pub(crate) fn append<'r>(
        &self,
        doc: &Address,
        runs: impl IntoIterator<Item = &'r Run>,
    ) -> Provenance {
        let mut spans = self.appended.get(doc).cloned().unwrap_or_default();
        spans.extend(runs.into_iter().map(Run::iextent));
        Provenance { appended: self.appended.update(doc.clone(), spans), named: self.named.clone() }
    }

    /// Returns R with `list` named as what `doc` contained at its mint.
    ///
    /// It is the snapshot's record: the run-list `doc` was born sharing, as
    /// it stood — handed over as one more handle on the tree its source
    /// holds, so nothing is read and no span is built — in place of a span
    /// a run. Persistent, as [`append`](Provenance::append) is. A document
    /// is minted once, so its list is named once; naming one again replaces
    /// the list, which no fold arm does.
    #[must_use = "named returns the extended relation; R is persistent and the receiver is untouched"]
    pub(crate) fn named(&self, doc: &Address, list: RunList) -> Provenance {
        Provenance { appended: self.appended.clone(), named: self.named.update(doc.clone(), list) }
    }

    /// Returns R↾doc as this relation holds it: the iextent cover of the
    /// list a snapshot named for `doc`, then of the spans appended for it.
    ///
    /// That is every content span it was born holding or placed since,
    /// whether or not the arrangement still holds it, in that order — the
    /// named list's runs in V-order, then the appended spans in placement
    /// order — and the `deletions` operand (Conflicts #8). Raw and possibly
    /// mixed-length; it never crosses a module seam. Nothing of a member a
    /// shot minted is here for its mint: the reads on
    /// [`M5State`](crate::M5State) add its arrangement.
    pub(crate) fn ever_contained(&self, doc: &Address) -> SpanSet {
        let named = self.named.get(doc).into_iter().flat_map(RunList::iter).map(Run::iextent);
        let appended = self.appended.get(doc).into_iter().flatten().cloned();
        named.chain(appended).collect()
    }

    /// Returns how many spans [`ever_contained`](Provenance::ever_contained)
    /// yields for `doc`.
    ///
    /// That is one per run of the list a snapshot named for it and one per
    /// run it has placed since, whether or not the arrangement still holds
    /// it. Two map lookups, reading no span; absent ⇒ 0.
    pub(crate) fn recorded_span_count(&self, doc: &Address) -> usize {
        self.named.get(doc).map_or(0, RunList::run_count) + self.appended.get(doc).map_or(0, |spans| spans.len())
    }

    /// Returns whether `doc` has any entry in R at all.
    ///
    /// An entry is an appended span or a named list. It distinguishes absent
    /// from empty, which the reads deliberately do not
    /// (both answer ⟨⟩) — the empty-source fork's "no redundant entry" claim
    /// is about the maps, so the test that pins it needs a way to ask.
    #[cfg(test)]
    pub(crate) fn is_recorded(&self, doc: &Address) -> bool {
        self.appended.contains_key(doc) || self.named.contains_key(doc)
    }

    /// Returns the list a snapshot named for `doc`, where one did.
    ///
    /// For the tests that hold a named list to the tree it shares.
    #[cfg(test)]
    pub(crate) fn named_list(&self, doc: &Address) -> Option<&RunList> {
        self.named.get(doc)
    }

    /// Returns every list a snapshot named, in address order.
    ///
    /// For the tests that count the nodes a slice's lists hold between them.
    #[cfg(test)]
    pub(crate) fn named_lists(&self) -> impl Iterator<Item = &RunList> + '_ {
        self.named.values()
    }

    /// Returns how many spans are appended for `doc`, its named list apart.
    ///
    /// For the tests that pin what a record appends and what it only names.
    #[cfg(test)]
    pub(crate) fn appended_span_count(&self, doc: &Address) -> usize {
        self.appended.get(doc).map_or(0, |spans| spans.len())
    }

    /// Returns the documents with a recorded span not `Separated` from
    /// `coverage`, in tumbler order, each once.
    ///
    /// A document's recorded spans are the runs of its named list and the
    /// spans appended for it. A span counts where it is not `Separated`
    /// from some span of `coverage` ([`touches`]),
    /// under M1's total, length-gate-free `classify_spans` — so a mixed-length
    /// coverage is answered without the level-class discipline. v1 scans the
    /// maps (Open decision #3: an index over R would live here, R's owner, not
    /// in the query that composes on it); each `OrdMap` walk is in tumbler
    /// order, a document found in the named lists and again among the
    /// appended spans is kept once, and a key is already the placing
    /// document's `Address`, so the answer is assembled rather than
    /// reconstructed.
    ///
    /// **Cost**, since nothing here bounds it: at most one `classify_spans`
    /// per (recorded span × coverage span) over the whole relation — a
    /// document's walk stops at its first match — each deriving both
    /// operands' endpoints, and R only ever grows (P2). A named list is
    /// walked once for each document it is named for, whichever documents
    /// share its nodes.
    /// [`M5State::docs_ever_containing`](crate::M5State::docs_ever_containing)
    /// states what this answer means to a caller, and who owns that bound.
    pub(crate) fn docs_ever_containing(&self, coverage: &SpanSet) -> std::collections::BTreeSet<Address> {
        let by_name = self
            .named
            .iter()
            .filter(|(_, list)| list.iter().any(|run| touches(&run.iextent(), coverage)))
            .map(|(doc, _)| doc.clone());
        let by_span = self
            .appended
            .iter()
            .filter(|(_, spans)| spans.iter().any(|placed| touches(placed, coverage)))
            .map(|(doc, _)| doc.clone());
        by_name.chain(by_span).collect()
    }
}

/// Returns whether `placed` is not `Separated` from some span of `coverage`.
///
/// The one test the R⁻¹ candidates are found by, over a recorded span and
/// over a run of an arrangement read as one alike: M1's `classify_spans`,
/// total for any pair, so overlap and adjacency both count.
pub(crate) fn touches(placed: &Span, coverage: &SpanSet) -> bool {
    coverage.iter().any(|cover| classify_spans(placed, cover) != SpanRel::Separated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{ca, doc1, doc2, run, t, vdoc};

    #[test]
    fn appending_accumulates_and_never_shortens() {
        // §9/P2: a second append for the same document extends the sequence —
        // there is no path that shortens it, which is what SHOWDELETIONS and
        // the historical candidate read both rest on.
        let (first, second, other) = (run(&ca(1), 2), run(&ca(5), 1), run(&ca(1), 1));
        let p = Provenance::default();
        assert!(!p.is_recorded(&doc1()));
        let p = p.append(&doc1(), [&first]);
        let p = p.append(&doc1(), [&second]);
        assert!(p.is_recorded(&doc1()));
        assert_eq!(p.ever_contained(&doc1()).len(), 2);
        // The recorded spans are the runs' own I-extents — the shape the reads
        // rest on, established by the mutator rather than by these callers.
        let recorded: Vec<_> = p.ever_contained(&doc1()).iter().cloned().collect();
        assert_eq!(recorded, vec![first.iextent(), second.iextent()]);
        // A different document keeps its own R↾doc; the historical read walks
        // both in Tumbler order.
        let p = p.append(&doc2(), [&other]);
        let cov = SpanSet::singleton(other.iextent());
        assert_eq!(p.docs_ever_containing(&cov).into_iter().collect::<Vec<_>>(), vec![doc1(), doc2()]);
        // A document that has placed nothing is absent, and reads empty.
        assert!(!p.is_recorded(&vdoc()));
        assert!(p.ever_contained(&vdoc()).is_empty());
    }

    #[test]
    fn decoding_the_relation_re_establishes_the_span_shape_the_reads_rest_on() {
        // §9: the span-shape clause is what makes `M5State::deletions`'
        // per-class `difference_sets` infallible — M1's set ops gate on
        // level-uniformity as well as on length — so the decode path holds it
        // as the mutator does. A span that is not level-uniform, which no
        // `Run::iextent` is, is a decode failure M2 reports as corruption, not
        // a value that panics a public read on the next SHOWDELETIONS.
        //
        // The bytes are made by encoding the shadow's own shape, which is the
        // exact form a corrupt checkpoint would present.
        #[derive(Serialize)]
        struct Wire {
            appended: im::OrdMap<Address, im::Vector<Span>>,
            named: im::OrdMap<Address, Vec<Run>>,
        }
        let wire = |spans: Vec<Span>| {
            bincode::serialize(&Wire {
                appended: im::OrdMap::unit(doc1(), spans.into_iter().collect::<im::Vector<Span>>()),
                named: im::OrdMap::new(),
            })
            .expect("the shadow encodes")
        };
        // T12-valid (action point 1 ≤ #start 8) and not level-uniform — the
        // shape `iextent` cannot make and `difference_sets` faults on.
        let skew = Span::new(ca(1).tumbler().clone(), t(&[1])).expect("T12");
        assert!(!skew.is_level_uniform());
        assert!(
            bincode::deserialize::<Provenance>(&wire(vec![skew])).is_err(),
            "a span no run I-extent could produce is not provenance"
        );
        // A well-formed relation decodes to itself, and its bytes are exactly
        // what the shadow's shape writes — the door is a check on the decode
        // path and not a second encoding.
        let placed = run(&ca(1), 2);
        let good = Provenance::default().append(&doc1(), [&placed]);
        let bytes = bincode::serialize(&good).expect("the relation encodes");
        assert_eq!(bytes, wire(vec![placed.iextent()]));
        assert_eq!(
            bincode::deserialize::<Provenance>(&bytes).expect("a run I-extent decodes"),
            good
        );
        // A named list rides behind the appended spans as a run-list writes
        // itself, and decodes through the run-list's own door: two
        // I-adjacent runs a checkpoint presents apart come back as one.
        let list = |runs: Vec<Run>| -> RunList {
            bincode::deserialize(&bincode::serialize(&runs).expect("runs encode")).expect("a list decodes")
        };
        let named = good.named(&doc2(), list(vec![run(&ca(1), 2), run(&ca(5), 1)]));
        let bytes = bincode::serialize(&named).expect("the relation encodes");
        assert_eq!(bincode::deserialize::<Provenance>(&bytes).expect("it decodes"), named);
        assert_eq!(named.recorded_span_count(&doc2()), 2);
        assert_eq!(named.recorded_span_count(&doc1()), 1);
        let apart = bincode::serialize(&Wire {
            appended: im::OrdMap::new(),
            named: im::OrdMap::unit(doc2(), vec![run(&ca(1), 2), run(&ca(3), 1)]),
        })
        .expect("the shadow encodes");
        let merged: Provenance = bincode::deserialize(&apart).expect("it decodes");
        assert_eq!(merged.recorded_span_count(&doc2()), 1, "the list's maximal merge is re-established");
    }
}
