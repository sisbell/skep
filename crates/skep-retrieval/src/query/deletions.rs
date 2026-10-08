//! §D SHOWDELETIONS (ASN-0075): the cross-document combine of CURRENT and
//! DELETED, both ways, and the CURRENT enumeration only it uses.

use skep_address::Address;
use skep_arrangement::{M5State, Run};

use super::{sorted_addr_set, Query, RetrievalWorld};
use crate::error::DeletionsError;
use crate::types::Deletions;

/// The enumeration of `CURRENT(·, d)` (ASN-0075's predicate; ASN-0124 calls
/// the set `ran_C(d)`) — every content I-address `d`'s arrangement currently
/// binds, in V order. M5's own `content_image` is the same set and is private,
/// so it is NOT called here.
///
/// Walking the CONTENT runs is not a narrowing of `CURRENT` but its whole
/// extent: ASN-0075 defines the predicate over `a ∈ dom(C)`, so
/// `{a : CURRENT(a, d)} = ran(M(d)) ∩ dom(C) = ran_C(d)` and no link run is
/// skipped — there is none to skip (D-SUBSP).
///
/// `CURRENT` is a set and this is an enumeration WITH MULTIPLICITY: an
/// address placed at two V-positions of `d` by intra-document transclusion is
/// yielded twice, so the caller dedups as the stream arrives
/// (`sorted_addr_set`).
///
/// LAZY, and that is the point rather than a style: `d`'s arrangement binds
/// `n_C(d)` content positions — one per value placed, however many bytes it
/// holds — and each position enumerated is an OWNED `Address`: a `Vec<Nat>`
/// of element components, order hundreds of bytes and a handful of
/// allocations. Handing back a `Vec` would make the peak live heap of a
/// two-document combine the size of both documents, from a request naming two
/// addresses and nothing else; streaming makes it the size of the part the
/// caller's filter keeps. Each run's positions are enumerated by the run that
/// owns them — `Run::addrs`, over M5's lent run-list, so no run is cloned to
/// be walked and the stream holds one cursor into the snapshot's arrangement.
///
/// Enumerating the content runs alone therefore loses nothing AND needs no
/// filter behind it: `DELETED(a, d)` requires `(a, d) ∈ R`, and R is appended
/// only where content is placed — seating a link records nothing in it — so a
/// link position enumerated here could only be filtered away again.
fn current_content<'a>(m5: &'a M5State, d: &Address) -> impl Iterator<Item = Address> + 'a {
    m5.content_runs(d).flat_map(Run::addrs)
}

impl<W: RetrievalWorld> Query<'_, W> {
    /// SHOWDELETIONS (ASN-0075) — gate, then membership-test the
    /// cross-document combine IN M6 from M5's per-document primitives:
    /// `DeletedFromAWithB = { a : CURRENT(a, d_b) ∧ DELETED(a, d_a) }` and its
    /// symmetric twin. Never opens M4; both halves read off the one pinned
    /// snapshot (single consistent `(M, R)` — no torn-read phantom deletion).
    ///
    /// Reads the arrangement and the provenance record of each address as
    /// NAMED, and does not float (crate doc, *Which arrangement an operation
    /// answers from*): `CURRENT` is enumerated from, and `DELETED` tested
    /// against, the two addresses given.
    ///
    /// Both documents must be registered (Err otherwise; `d_a` checked
    /// first); registered-empty is fine and yields empty halves. Each half is
    /// a set of the EXISTING I-addresses (D-IDENT — never copies), returned
    /// deduplicated and T1-ascending: the dedup is the comprehension's, the
    /// ordering M6's own presentation, which D-ORD licenses (T1-orderability
    /// is a property of the addresses) and does not require (the operation
    /// transports no ordering of its own).
    ///
    /// Whole for two readable arguments (PUB-6.15): no predicate; each half is
    /// the addresses themselves whatever their origins' readability, the two
    /// arguments' consult being M10's pre-dispatch.
    ///
    /// BOTH HALVES ARE CONTENT I-ADDRESSES BY DEFINITION (D-SUBSP): ASN-0075
    /// classifies `(a, d)` with `a ∈ dom(C)`, so `CURRENT` and `DELETED` are
    /// defined only there and both output sets are `{a ∈ dom(C) : …}` — every
    /// such `a` has `subspace_I(a) = s_C`, and `dom(C) ∩ dom(L) = ∅` (L14), so
    /// no link address can appear in either half whatever the enumeration does.
    /// The operation's domain is what confines it, not this implementation's
    /// choice of walk.
    ///
    /// TIME IS UNBOUNDED AND M6 DOES NOT BOUND IT — and it is not bounded by
    /// the answer either. No span narrows the request, so both documents are
    /// enumerated WHOLE, and two terms are paid in full even when the two
    /// share nothing and both halves come back empty:
    ///
    /// * `|R↾d_a| log |R↾d_a| + |R↾d_b| log |R↾d_b|` for the two
    ///   `M5State::deletions` calls that build the covers — each rebuilds and
    ///   SORTS the document's whole provenance record, M5 stating the cost
    ///   where it is paid; R never shrinks, so a document that has deleted far
    ///   more than it holds carries a record far larger than its arrangement.
    /// * `n_C(d_b)·|deletions(d_a)| + n_C(d_a)·|deletions(d_b)|` for the
    ///   membership pass — one `denotes` test, a linear scan of the cover, per
    ///   enumerated position. THIS TERM DOMINATES, and it needs nothing
    ///   stored: `n_C` is VIRTUAL, M5 capping the runs a placing request stores
    ///   and no position count, so one COPY of 4096 specs places a run 4096
    ///   times and a copy of a document onto its own tail doubles its extent.
    ///   A few placing requests set it, not anything written.
    ///
    /// M6 owns no admission control and no refusal for any of it, and has no
    /// number to refuse at: the request is two addresses, so no request-size
    /// cap sees it, and a budget on the pass would deny the operation on any
    /// ordinary large document. Rate and concurrency bound how many workers
    /// such requests hold — M10's, as the request lifecycle's owner — and not
    /// how long one request holds one. What bounds that is computing each half
    /// from intervals — one document's deleted cover intersected, level class
    /// by level class, with the other's current image — which needs the
    /// level-class discipline M5 owns and has not published as a read.
    ///
    /// MEMORY IS THE ANSWER'S AND THE TWO COVERS'. The covers
    /// `M5State::deletions` hands back are held through both combine passes,
    /// each at most `|R↾d| + #runs(d)` spans — its document's provenance
    /// record, cut where the current image falls — and each built through
    /// M5's own transient of several copies of `R↾d`. Beside them the
    /// enumeration streams and each half is built as the set it denotes —
    /// every address inserted as it arrives and a duplicate dropped on arrival
    /// — so what else is held live is the deduped halves and the address in
    /// hand, never a materialized copy of either document's position list,
    /// however many times its extent repeats an address. Past the covers, the
    /// worst case is the honest one: two documents where each has deleted what
    /// the other still holds, whose answer genuinely is that many addresses.
    pub fn show_deletions(
        &self,
        d_a: &Address,
        d_b: &Address,
    ) -> Result<Deletions, DeletionsError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        for d in [d_a, d_b] {
            if !m3.is_registered_document(d) {
                return Err(DeletionsError::DocNotRegistered(d.clone()));
            }
        }
        let deletions_a = m5.deletions(d_a); // { a : DELETED(a, d_a) } as a per-level-class cover
        let deletions_b = m5.deletions(d_b); // { a : DELETED(a, d_b) }
        // CURRENT in the one document ∧ DELETED from the other, both ways.
        // CURRENT(·, d) is enumerated by `current_content`, which asks each
        // content run for its addresses exactly as RETRIEVEV does; DELETED(·, d)
        // is tested by membership in M5's per-document deleted cover
        // (`deletions(d).denotes(a)`) — exact UNCONDITIONALLY by
        // `difference_sets`' denotational contract
        // (`⟦deletions(d)⟧ = {x : DELETED(x, d)}` whatever the cover's internal
        // span packing), so there are no false positives.
        let deleted_from_a_with_b =
            sorted_addr_set(current_content(m5, d_b).filter(|a| deletions_a.denotes(a.tumbler())));
        let deleted_from_b_with_a =
            sorted_addr_set(current_content(m5, d_a).filter(|a| deletions_b.denotes(a.tumbler())));
        Ok(Deletions {
            deleted_from_a_with_b,
            deleted_from_b_with_a,
        })
    }
}
