//! §A/§9 — the append-only content-provenance relation R: what each document
//! has ever contained, and the historical read that answers off it.

use serde::{Deserialize, Serialize};
use skep_address::{classify_spans, Address, Span, SpanRel, SpanSet};

use crate::run::Run;

/// R, keyed by placing document — every content span a document has ever
/// contained, in placement order (ASN-0047 P2: a pair `(a, d)` records that
/// `d` contained the I-address `a`, and no transition removes one).
///
/// APPEND-ONLY IS THE CARD, and it is structural: this type offers
/// [`append`](Provenance::append) and reads, and NO way to drop or rewrite a
/// pair. That absence is why a deleted address keeps its provenance without
/// any op having to promise it, and why R is non-recomputable from the
/// current arrangement — a deletion contracts the arrangement and leaves R
/// standing, so SHOWDELETIONS has something to subtract from. Recovered by
/// replay like the arrangement itself, never rebuilt.
///
/// SPAN SHAPE, and there are TWO doors that keep it: every recorded span is a
/// [`Run::iextent`] — level-uniform and element-level.
/// [`append`](Provenance::append) takes RUNS and lifts them itself, so no
/// caller can record a span of another shape, and the serde shadow below
/// re-enters the level-uniformity clause on the decode path, so no checkpoint
/// can present one either. The reads rest on that: it is what makes
/// [`M5State::deletions`](crate::M5State::deletions)' per-class
/// `difference_sets` infallible, M1's set ops gating on level-uniformity as
/// well as on length — and a `.expect` on a public read is not a thing to
/// leave standing on checkpoint integrity when the type can hold it instead.
///
/// A single-field newtype over the mandated slice shape, so the checkpoint
/// encoding is the map's own (bincode writes a newtype struct as its inner
/// value), keyed by the placing document's `Address` — which orders and
/// serializes as its bare tumbler, and re-validates on the way back in.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ProvenanceShadow")]
pub(crate) struct Provenance(im::OrdMap<Address, im::Vector<Span>>);

/// The deserialization mint path (the serde `try_from` shadow, as [`Run`] and
/// M1's `Address`/`Span`/`Tumbler` each carry one): the map is decoded — each
/// key re-entering `validate` and each span re-entering T12 through their own
/// shadows — and then the SPAN SHAPE clause the reads depend on is
/// re-established here, so a checkpoint whose R holds a span no
/// [`Run::iextent`] could have produced is a decode failure M2 reports as
/// corruption rather than a value that panics
/// [`M5State::deletions`](crate::M5State::deletions) on the next
/// SHOWDELETIONS, on a worker thread, per request.
///
/// LEVEL-UNIFORMITY IS THE CLAUSE, and it is the minimal one: it is what M1's
/// `level_class` gates on, hence exactly what the per-class `difference_sets`
/// needs. Element-level-ness is not re-checked — no read faults on its
/// absence, and asking it here would be a second definition of a run start
/// rather than the one [`Run::admits_start`] owns. One length comparison per
/// recorded span, once, at checkpoint load.
///
/// It reads exactly what a `Provenance` writes — the same newtype over the
/// same map — and `Serialize` is derived on `Provenance` itself, so the
/// shadow costs the encoding nothing.
#[derive(Deserialize)]
struct ProvenanceShadow(im::OrdMap<Address, im::Vector<Span>>);

impl TryFrom<ProvenanceShadow> for Provenance {
    type Error = &'static str;
    fn try_from(s: ProvenanceShadow) -> Result<Provenance, &'static str> {
        if s.0
            .iter()
            .flat_map(|(_, spans)| spans.iter())
            .all(Span::is_level_uniform)
        {
            Ok(Provenance(s.0))
        } else {
            Err("provenance: every recorded span is a run I-extent (level-uniform)")
        }
    }
}

impl Provenance {
    /// Append the I-extents of `runs` to `doc`'s record (persistent — the
    /// receiver is untouched). Called from the placing folds, co-located with
    /// the arrangement update they pair with, so one new state carries both
    /// halves of J1★. The ONLY mutator, and it only ever lengthens a
    /// document's sequence.
    ///
    /// Takes the runs rather than their spans: the lift is the one this type
    /// admits, so performing it here makes the span-shape invariant above
    /// true at the mutator instead of owed by each caller.
    #[must_use = "append returns the extended record; R is persistent and the receiver is untouched"]
    pub(crate) fn append<'r>(
        &self,
        doc: &Address,
        runs: impl IntoIterator<Item = &'r Run>,
    ) -> Provenance {
        let mut col = self.0.get(doc).cloned().unwrap_or_default();
        col.extend(runs.into_iter().map(Run::iextent));
        Provenance(self.0.update(doc.clone(), col))
    }

    /// R↾doc: the iextent cover of content spans `doc` has ever contained —
    /// every span it placed, whether or not the arrangement still holds it,
    /// and the `deletions` operand (Conflicts #8). Raw and possibly
    /// mixed-length; it never crosses a module seam.
    pub(crate) fn ever_contained(&self, doc: &Address) -> SpanSet {
        self.0
            .get(doc)
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_else(SpanSet::empty)
    }

    /// Has `doc` a record at all? Distinguishes ABSENT from empty, which the
    /// reads deliberately do not (both answer ⟨⟩) — the empty-source fork's
    /// "no redundant entry" claim is about the map, so the test that pins it
    /// needs a way to ask.
    #[cfg(test)]
    pub(crate) fn is_recorded(&self, doc: &Address) -> bool {
        self.0.contains_key(doc)
    }

    /// Every document with some placed span not `Separated` from some span of
    /// `coverage`, under M1's total, length-gate-free `classify_spans` — so a
    /// mixed-length coverage is answered without the level-class discipline.
    /// v1 scans the map (Open decision #3: an index over R would live here,
    /// R's owner, not in the query that composes on it); the `OrdMap` walk is
    /// what makes the result's tumbler order deterministic, and a key is
    /// already the placing document's `Address`, so the answer is assembled
    /// rather than reconstructed.
    ///
    /// COST, since nothing here bounds it: one `classify_spans` per (recorded
    /// span × coverage span) over the WHOLE relation, each deriving both
    /// operands' endpoints, and R only ever grows (P2).
    /// [`M5State::docs_ever_containing`](crate::M5State::docs_ever_containing)
    /// states what this answer means to a caller, and who owns that bound.
    pub(crate) fn docs_ever_containing(&self, coverage: &SpanSet) -> Vec<Address> {
        let mut out = Vec::new();
        for (doc, spans) in self.0.iter() {
            let hit = spans
                .iter()
                .any(|p| coverage.iter().any(|c| classify_spans(p, c) != SpanRel::Separated));
            if hit {
                out.push(doc.clone());
            }
        }
        out
    }
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
        // The recorded spans are the runs' own extents — the shape the reads
        // rest on, established by the mutator rather than by these callers.
        let recorded: Vec<_> = p.ever_contained(&doc1()).iter().cloned().collect();
        assert_eq!(recorded, vec![first.iextent(), second.iextent()]);
        // A different document keeps its own record; the historical read walks
        // both in Tumbler order.
        let p = p.append(&doc2(), [&other]);
        let cov = SpanSet::singleton(other.iextent());
        assert_eq!(p.docs_ever_containing(&cov), vec![doc1(), doc2()]);
        // A document that has placed nothing is absent, and reads empty.
        assert!(!p.is_recorded(&vdoc()));
        assert!(p.ever_contained(&vdoc()).is_empty());
    }

    #[test]
    fn decoding_a_record_re_establishes_the_span_shape_the_reads_rest_on() {
        // §9: the SPAN SHAPE clause is what makes `M5State::deletions`'
        // per-class `difference_sets` infallible — M1's set ops gate on
        // level-uniformity as well as on length — so the decode path holds it
        // as the mutator does. A span no `Run::iextent` could have produced is
        // a decode failure M2 reports as corruption, not a value that panics a
        // public read on the next SHOWDELETIONS.
        //
        // The bytes are made by encoding the shadow's own shape, which is the
        // exact form a corrupt checkpoint would present.
        #[derive(Serialize)]
        struct Wire(im::OrdMap<Address, im::Vector<Span>>);
        let wire = |spans: Vec<Span>| {
            bincode::serialize(&Wire(im::OrdMap::unit(
                doc1(),
                spans.into_iter().collect::<im::Vector<Span>>(),
            )))
            .expect("the shadow encodes")
        };
        // T12-valid (action point 1 ≤ #start 8) and NOT level-uniform — the
        // shape `iextent` cannot make and `difference_sets` faults on.
        let skew = Span::new(ca(1).tumbler().clone(), t(&[1])).expect("T12");
        assert!(!skew.is_level_uniform());
        assert!(
            bincode::deserialize::<Provenance>(&wire(vec![skew])).is_err(),
            "a span no run extent could produce is not a provenance record"
        );
        // A well-formed record decodes to itself, and its bytes are exactly
        // what the shadow's shape writes — the door is a check on the decode
        // path and not a second encoding.
        let placed = run(&ca(1), 2);
        let good = Provenance::default().append(&doc1(), [&placed]);
        let bytes = bincode::serialize(&good).expect("the record encodes");
        assert_eq!(bytes, wire(vec![placed.iextent()]));
        assert_eq!(
            bincode::deserialize::<Provenance>(&bytes).expect("a run extent decodes"),
            good
        );
    }
}
