//! §A / §3–§8 folds — M5's `WorldState` slice ([`M5State`]), its sole journal
//! delta ([`M5Rec`]), and the pure fold ([`M5State::apply_m5`]).

use num_traits::Zero;
use serde::{Deserialize, Serialize};
use skep_address::{content_subspace, link_subspace, Address, Nat, Tumbler};

use crate::prov::Provenance;
use crate::run::Run;
use crate::runlist::RunList;

/// One document's POOM: the content and link run-lists (§Core data model).
/// Exactly these two subspaces exist, which is a fact about the arrangement
/// and so is answered by [`list`](DocArrangement::list) rather than restated
/// by each read that routes on a subspace numeral.
#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct DocArrangement {
    pub(crate) content: RunList,
    pub(crate) link: RunList,
}

impl DocArrangement {
    /// The run-list `subspace` selects, or `None` when it names neither —
    /// `s_C` and `s_L` (M1's numerals) being the only two that exist. Every
    /// subspace-routed read folds that `None` to its own empty answer.
    pub(crate) fn list(&self, subspace: &Nat) -> Option<&RunList> {
        if *subspace == content_subspace() {
            Some(&self.content)
        } else if *subspace == link_subspace() {
            Some(&self.link)
        } else {
            None
        }
    }
}

/// Authoritative folded state: the per-document POOM, and [`Provenance`]
/// co-located beside it (ASN-0075). The arrangement is authoritative MUTABLE
/// state recovered by replay — NOT a recomputable hint (ASN-0047 P3);
/// provenance is the append-only history housed next to it, and it is a type
/// of its own whose surface offers no removal, so the permanence R promises
/// holds by construction. Both key by the document's `Tumbler` —
/// M5's choice of key form, not a constraint from M1, which orders `Address`
/// itself — so every `&Address` method converts with `doc.tumbler()`.
/// `arrangements` is sparse: an absent doc ⇒ empty arrangement (the
/// eager-lazy split with M3). v1 has no derived-hint fields ⇒
/// [`rebuild_derived`](M5State::rebuild_derived) is the identity.
///
/// Serialization needs the `im` crate's `serde` feature and
/// `Tumbler: Serialize/DeserializeOwned` (M1's `num-bigint` serde feature) —
/// both carried by this crate's dependencies (Build precondition).
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct M5State {
    pub(crate) arrangements: im::OrdMap<Tumbler, DocArrangement>,
    pub(crate) prov: Provenance,
}

/// M5's sole journal delta — effect-level (carries concrete
/// addresses/ordinals so the fold needs no upstream access and never
/// re-mints; Conflicts #4). Each variant is `#[non_exhaustive]`, so NO
/// foreign crate can build an `M5Rec` by struct literal — `stage_seat_link`
/// and the op bodies (all in M5's crate) are the only constructors, and the
/// M/R-coupling cannot be bypassed. The engine only `From`-lifts and folds an
/// already-built value; [`M5State::apply_m5`] matches in M5's own crate, so
/// it destructures freely — the engine never does.
#[derive(Clone, Serialize, Deserialize)]
pub enum M5Rec {
    /// INSERT/COPY: splice `runs` at content ordinal `at` + R-append each
    /// placed run's iextent (J1★).
    #[non_exhaustive]
    ContentPlace { doc: Address, at: Nat, runs: Vec<Run> },
    /// DELETE: contract + reseat (no C, no R — ASN-0117 P0/P2).
    #[non_exhaustive]
    ContentRemove { doc: Address, from: Nat, width: Nat },
    /// REARRANGE: the 3|4 ORDINALS of the cut sequence, tile-by-placement (no
    /// C, no R). A cut is a V-position (ASN-0119); the record carries
    /// `ord(cⱼ)` for each, the subspace being fixed to s_C by the op's own
    /// validation.
    #[non_exhaustive]
    ContentReorder { doc: Address, cut_ordinals: Vec<Nat> },
    /// MAKELINK seating (no R — J-LV).
    #[non_exhaustive]
    LinkSeat { doc: Address, link: Address },
    /// CREATENEWVERSION (share + R-append). LINEARIZATION-AT-FOLD: the fold
    /// reads `source`'s then-current arrangement at THIS record's
    /// commit/replay slot — the record's effect is defined against the state
    /// at its commit position, not a pre-staged value. Exact under v1's
    /// single-applier M2 realization (nothing lands between a transact's base
    /// and its commit); any future M2 concurrency realization that lets
    /// disjoint-key commits land in that window MUST re-examine this record
    /// first (or move to the explicit-runs form, Open decision #4).
    #[non_exhaustive]
    VersionSnapshot { source: Address, new: Address },
}

impl M5State {
    /// Σ₀ for M5: `{}` arrangements, `{}` provenance. Deterministic, per M2's
    /// byte-identical-genesis caller contract.
    pub fn genesis() -> M5State {
        M5State::default()
    }

    /// The arrangements map with `doc`'s content run-list replaced by `f` of
    /// the current one — an absent doc reading as the empty arrangement, per
    /// the lazy convention. Stating the read-modify-write once leaves each
    /// editing fold arm showing only what distinguishes it: which run-list
    /// operation it performs, and what it does to R.
    fn with_content(
        &self,
        doc: &Address,
        f: impl FnOnce(&RunList) -> RunList,
    ) -> im::OrdMap<Tumbler, DocArrangement> {
        let mut arr = self
            .arrangements
            .get(doc.tumbler())
            .cloned()
            .unwrap_or_default();
        arr.content = f(&arr.content);
        self.arrangements.update(doc.tumbler().clone(), arr)
    }

    /// The link-subspace twin of [`with_content`](M5State::with_content).
    fn with_link(
        &self,
        doc: &Address,
        f: impl FnOnce(&RunList) -> RunList,
    ) -> im::OrdMap<Tumbler, DocArrangement> {
        let mut arr = self
            .arrangements
            .get(doc.tumbler())
            .cloned()
            .unwrap_or_default();
        arr.link = f(&arr.link);
        self.arrangements.update(doc.tumbler().clone(), arr)
    }

    /// The pure/deterministic M2 fold (§3–§8 folds; M2's `apply` obligation),
    /// dispatched by the engine's `World::apply` from its `Record::M5`
    /// variant — on live commit and on replay alike.
    ///
    /// TOTALITY DOMAIN (§10): total over minted-or-validly-recovered records
    /// — an `M5Rec` reaches this fold only via validated staging (every op
    /// validates its preconditions before `stg.push`) or trusted recovery
    /// (M2 journal/checkpoint integrity). An out-of-contract record (a
    /// `ContentPlace.at` past the append boundary, a `ContentRemove`
    /// overrunning the run-list, a cut vector violating R-PRE) can arise only
    /// from corruption, is outside the input class, and is not re-validated
    /// here; the run-list clamps keep the fold panic-free regardless.
    /// Determinism for `VersionSnapshot` holds because records replay in
    /// journal order, so `source`'s arrangement is reconstructed to its
    /// fork-point value before the snapshot reads it.
    pub fn apply_m5(&self, r: &M5Rec) -> M5State {
        match r {
            // §3/§5 fold: splice + eager coalesce, and append each placed
            // run's iextent to R IN THE SAME fold — one new M5State, one M2
            // root install, so a reader never observes M-updated-without-R
            // (J1★ ⇒ P4★/P4a; with INSERT's composite, J0 ⇒ P7a).
            M5Rec::ContentPlace { doc, at, runs } => M5State {
                arrangements: self.with_content(doc, |c| c.splice_in(at, runs)),
                prov: self.prov.record(doc, runs.iter().map(Run::iextent)),
            },
            // §4 fold: split at `from` and `from + width`, drop the middle,
            // concat + eager coalesce. C and R untouched (NonDestruction is
            // structural — M5 has no content-reclamation path; P2 keeps every
            // R pair). A text delete never touches the link run-list (P4).
            M5Rec::ContentRemove { doc, from, width } => M5State {
                arrangements: self.with_content(doc, |c| c.remove_range(from, width)),
                prov: self.prov.clone(),
            },
            // §6 fold: split at cut ordinals, tile by placement. Pure
            // permutation — C, L, R untouched (ASN-0119 RA1/RA6).
            M5Rec::ContentReorder { doc, cut_ordinals } => M5State {
                arrangements: self.with_content(doc, |c| c.reorder(cut_ordinals)),
                prov: self.prov.clone(),
            },
            // §8 fold: append `link` at the next link V-position n_L(d) + 1
            // (the append boundary), coalescing with the prior link run if
            // I-adjacent (sequential A_L(d) allocations are — the
            // maximally-merged link list is a valid S8★ witness). NO R append
            // (J-LV).
            M5Rec::LinkSeat { doc, link } => M5State {
                arrangements: self.with_link(doc, |l| {
                    let next = l.total_width() + Nat::from(1u32);
                    let seat = Run {
                        i_start: link.clone(),
                        width: Nat::from(1u32),
                    };
                    l.splice_in(&next, &[seat])
                }),
                prov: self.prov.clone(),
            },
            // §7 fold: share `source`'s then-current content run-list into
            // `new` (structural im share — O(1)) and append each shared run
            // as provenance (run, new). This copies the V→I MAP, not the
            // I-range (ASN-0123 V2): the share preserves multiplicity, so
            // within-document transclusion duplicates survive into the fork.
            // When the source content subspace is empty (n = 0) the fold
            // appends no provenance and skips the arrangements update,
            // leaving `new` ABSENT under the lazy convention (≡ empty) —
            // V1's zero-content footprint with no redundant entry. Source is
            // untouched (V3); the fork diverges copy-on-write (V11).
            M5Rec::VersionSnapshot { source, new } => {
                let src = self
                    .arrangements
                    .get(source.tumbler())
                    .map(|a| a.content.clone())
                    .unwrap_or_default();
                if src.total_width().is_zero() {
                    self.clone()
                } else {
                    let prov = self
                        .prov
                        .record(new, src.iter_runs().map(|(_, run)| run.iextent()));
                    let arr = DocArrangement {
                        content: src,
                        link: RunList::default(),
                    };
                    M5State {
                        arrangements: self.arrangements.update(new.tumbler().clone(), arr),
                        prov,
                    }
                }
            }
        }
    }

    /// Default identity in v1 — M5 has no skip-serialized hints (§10); adding
    /// the inverse-arrangement or reverse-provenance hint (Open decisions
    /// #2/#3) obliges an override that reseeds exactly the fold-equivalent
    /// state.
    pub fn rebuild_derived(self) -> M5State {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{ca, doc1, doc2, la, n, run, vca, vdoc};

    fn place(s: &M5State, doc: &Address, at: u32, runs: Vec<Run>) -> M5State {
        s.apply_m5(&M5Rec::ContentPlace {
            doc: doc.clone(),
            at: n(at),
            runs,
        })
    }

    #[test]
    fn content_place_splices_and_appends_provenance_in_one_fold() {
        // §3: J1★ by construction — the same fold updates M and R, so one
        // state carries both; the R entry is the placed run's iextent.
        let s0 = M5State::genesis();
        let s1 = place(&s0, &doc1(), 1, vec![run(&ca(1), 3)]);
        assert_eq!(s1.content_count(&doc1()), n(3));
        assert!(s1.content_runs(&doc1()) == vec![run(&ca(1), 3)]);
        // ever_contained ∖ image is empty right after a place…
        assert!(s1.deletions(&doc1()).is_empty());
        // …and the R side is visible through docs_ever_containing.
        let cov = skep_address::SpanSet::singleton(run(&ca(1), 3).iextent());
        assert_eq!(s1.docs_ever_containing(&cov), vec![doc1()]);
        // Purity: the receiver was untouched.
        assert_eq!(s0.content_count(&doc1()), n(0));
    }

    #[test]
    fn content_remove_touches_neither_content_store_semantics_nor_r() {
        // §4: DELETE drops arrangement entries only; R keeps the pair (P2),
        // which is exactly what SHOWDELETIONS reads.
        let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 5)]);
        let s = s.apply_m5(&M5Rec::ContentRemove {
            doc: doc1(),
            from: n(2),
            width: n(2),
        });
        assert_eq!(s.content_count(&doc1()), n(3));
        assert!(s.content_runs(&doc1()) == vec![run(&ca(1), 1), run(&ca(4), 2)]);
        // The deleted iextent [ca(2), ca(4)) is ever-contained minus image.
        let d = s.deletions(&doc1());
        let spans: Vec<_> = d.iter().cloned().collect();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].start(), ca(2).tumbler());
        assert_eq!(spans[0].reach(), *ca(4).tumbler());
        // R permanence: the placing doc is still a candidate for the deleted
        // region.
        let cov = skep_address::SpanSet::singleton(spans[0].clone());
        assert_eq!(s.docs_ever_containing(&cov), vec![doc1()]);
    }

    #[test]
    fn link_seat_appends_at_the_next_link_position_and_never_touches_r() {
        // §8: append at n_L(d) + 1; sequential A_L(d) allocations coalesce to
        // one maximally-merged run (a valid S8★ witness); J-LV — no R.
        let s = M5State::genesis();
        let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(1) });
        let s = s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(2) });
        assert_eq!(s.link_count(&doc1()), n(2));
        assert!(s.link_runs(&doc1()) == vec![run(&la(1), 2)]);
        assert_eq!(s.content_count(&doc1()), n(0));
        // J-LV: no provenance from link seating.
        let cov = skep_address::SpanSet::singleton(run(&la(1), 2).iextent());
        assert!(s.docs_ever_containing(&cov).is_empty());
    }

    #[test]
    fn version_snapshot_shares_the_map_preserving_multiplicity() {
        // ASN-0123 V2: the V→I map is copied, not the I-range — a
        // within-document transclusion duplicate survives into the fork.
        let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 2)]);
        let s = place(&s, &doc1(), 3, vec![run(&ca(1), 2)]); // duplicate placement
        assert_eq!(s.content_count(&doc1()), n(4));
        let s = s.apply_m5(&M5Rec::VersionSnapshot {
            source: doc1(),
            new: vdoc(),
        });
        assert_eq!(s.content_count(&vdoc()), n(4));
        assert!(s.content_runs(&vdoc()) == s.content_runs(&doc1()));
        // Fork provenance recorded (a candidate for the shared region).
        let cov = skep_address::SpanSet::singleton(run(&ca(1), 2).iextent());
        assert_eq!(s.docs_ever_containing(&cov), vec![doc1(), vdoc()]);
        // Source untouched (V3).
        assert!(s.content_runs(&doc1()) == vec![run(&ca(1), 2), run(&ca(1), 2)]);
    }

    #[test]
    fn version_snapshot_of_an_empty_source_leaves_the_fork_absent() {
        // §7: n = 0 ⇒ no provenance append AND no arrangements entry — the
        // lazy absent-⇒-empty convention stays clean.
        let s0 = M5State::genesis();
        let s1 = s0.apply_m5(&M5Rec::VersionSnapshot {
            source: doc2(),
            new: vdoc(),
        });
        assert!(s1.arrangements.get(vdoc().tumbler()).is_none());
        assert!(!s1.prov.is_recorded(&vdoc()));
        assert_eq!(s1.content_count(&vdoc()), n(0));
    }

    #[test]
    fn fold_is_deterministic_and_state_serde_round_trips() {
        // §10: replaying the same records yields byte-identical state
        // (bincode is M2's wire format; the OrdMap serialization is ordered,
        // hence canonical); rebuild_derived is the identity.
        let build = || {
            let s = place(&M5State::genesis(), &doc1(), 1, vec![run(&ca(1), 3)]);
            let s = s.apply_m5(&M5Rec::ContentRemove {
                doc: doc1(),
                from: n(2),
                width: n(1),
            });
            s.apply_m5(&M5Rec::LinkSeat { doc: doc1(), link: la(1) })
        };
        let a = build();
        let b = build();
        let ab = bincode::serialize(&a).expect("state serializes");
        let bb = bincode::serialize(&b).expect("state serializes");
        assert_eq!(ab, bb);
        let back: M5State = bincode::deserialize(&ab).expect("state deserializes");
        assert_eq!(bincode::serialize(&back).expect("reserializes"), ab);
        assert_eq!(back.content_count(&doc1()), n(2));
        let rb = bincode::serialize(&back.clone().rebuild_derived()).expect("serializes");
        assert_eq!(rb, ab);
    }

    #[test]
    fn m5rec_survives_a_bincode_round_trip() {
        // §A: M5Rec is THE journaled delta; the replayed record folds to the
        // same effect.
        let rec = M5Rec::ContentPlace {
            doc: doc1(),
            at: n(1),
            runs: vec![run(&ca(1), 2), run(&vca(1), 1)],
        };
        let bytes = bincode::serialize(&rec).expect("record serializes");
        let back: M5Rec = bincode::deserialize(&bytes).expect("record deserializes");
        let s1 = M5State::genesis().apply_m5(&rec);
        let s2 = M5State::genesis().apply_m5(&back);
        assert_eq!(
            bincode::serialize(&s1).expect("serializes"),
            bincode::serialize(&s2).expect("serializes")
        );
    }
}
