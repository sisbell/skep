//! §A/§9 — the append-only content-provenance relation R: what each document
//! has ever contained, and the historical read that answers off it.

use serde::{Deserialize, Serialize};
use skep_address::{classify_spans, validate, Address, Span, SpanRel, SpanSet, Tumbler};

/// R, keyed by placing document — every content span a document has ever
/// contained, in placement order (ASN-0047 P2: a pair `(a, d)` records that
/// `d` contained the I-address `a`, and no transition removes one).
///
/// APPEND-ONLY IS THE CARD, and it is structural: this type offers
/// [`record`](Provenance::record) and reads, and NO way to drop or rewrite a
/// pair. That absence is why a deleted address keeps its provenance without
/// any op having to promise it, and why R is non-recomputable from the
/// current arrangement — a deletion contracts the arrangement and leaves R
/// standing, so SHOWDELETIONS has something to subtract from. Recovered by
/// replay like the arrangement itself, never rebuilt.
///
/// A single-field newtype over the mandated slice shape, so the checkpoint
/// encoding is the map's own (bincode writes a newtype struct as its inner
/// value).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Provenance(im::OrdMap<Tumbler, im::Vector<Span>>);

impl Provenance {
    /// Append `spans` to `doc`'s record (persistent — the receiver is
    /// untouched). Called from the placing folds, co-located with the
    /// arrangement update they pair with, so one new state carries both
    /// halves of J1★.
    pub(crate) fn record(
        &self,
        doc: &Address,
        spans: impl IntoIterator<Item = Span>,
    ) -> Provenance {
        let k = doc.tumbler();
        let mut col = self.0.get(k).cloned().unwrap_or_default();
        col.extend(spans);
        Provenance(self.0.update(k.clone(), col))
    }

    /// R↾doc: the iextent cover of content spans `doc` has ever contained —
    /// every span it placed, whether or not the arrangement still holds it,
    /// and the `deletions` operand (Conflicts #8). Raw and possibly
    /// mixed-length; it never crosses a module seam.
    pub(crate) fn ever_contained(&self, doc: &Address) -> SpanSet {
        self.0
            .get(doc.tumbler())
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_else(SpanSet::empty)
    }

    /// Has `doc` a record at all? Distinguishes ABSENT from empty, which the
    /// reads deliberately do not (both answer ⟨⟩) — the empty-source fork's
    /// "no redundant entry" claim is about the map, so the test that pins it
    /// needs a way to ask.
    #[cfg(test)]
    pub(crate) fn is_recorded(&self, doc: &Address) -> bool {
        self.0.contains_key(doc.tumbler())
    }

    /// Every document with some placed span not `Separated` from some span of
    /// `coverage`, under M1's total, length-gate-free `classify_spans` — so a
    /// mixed-length coverage is answered without the level-class discipline.
    /// v1 scans the map (Open decision #3: an index over R would live here,
    /// R's owner, not in the query that composes on it); the `OrdMap` walk is
    /// what makes the result's Tumbler order deterministic, and the key of a
    /// recorded document is a registered document's tumbler, hence T4-valid.
    /// [`M5State::docs_ever_containing`](crate::M5State::docs_ever_containing)
    /// states what this answer means to a caller.
    pub(crate) fn docs_ever_containing(&self, coverage: &SpanSet) -> Vec<Address> {
        let mut out = Vec::new();
        for (k, spans) in self.0.iter() {
            let hit = spans
                .iter()
                .any(|p| coverage.iter().any(|c| classify_spans(p, c) != SpanRel::Separated));
            if hit {
                out.push(
                    validate(k.clone())
                        .expect("prov keys are registered-document tumblers (T4-valid)"),
                );
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{ca, doc1, doc2, run, vdoc};

    #[test]
    fn recording_accumulates_and_never_supersedes() {
        // §9/P2: a second record for the same document extends the sequence —
        // there is no path that shortens it, which is what SHOWDELETIONS and
        // the historical candidate read both rest on.
        let p = Provenance::default();
        assert!(!p.is_recorded(&doc1()));
        let p = p.record(&doc1(), [run(&ca(1), 2).iextent()]);
        let p = p.record(&doc1(), [run(&ca(5), 1).iextent()]);
        assert!(p.is_recorded(&doc1()));
        assert_eq!(p.ever_contained(&doc1()).len(), 2);
        // A different document keeps its own record; the historical read walks
        // both in Tumbler order.
        let p = p.record(&doc2(), [run(&ca(1), 1).iextent()]);
        let cov = SpanSet::singleton(run(&ca(1), 1).iextent());
        assert_eq!(p.docs_ever_containing(&cov), vec![doc1(), doc2()]);
        // A document that has placed nothing is absent, and reads empty.
        assert!(!p.is_recorded(&vdoc()));
        assert!(p.ever_contained(&vdoc()).is_empty());
    }
}
