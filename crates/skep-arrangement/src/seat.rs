//! §C/§8 — link seating: the pure step composed into M7's MAKELINK, and its
//! contract-required standalone transact-wrapped twin.

use skep_address::{document_of, link_subspace, Address};
use skep_kernel::{Kernel, Seq, TxnError, WorldState};
use skep_namespace::M3State;

use crate::error::SeatError;
use crate::run::Run;
use crate::state::{M5Rec, M5State};
use crate::HasM5;

/// Append an already-allocated home link `link` at doc's next link
/// V-position (§8; ASN-0047 CL-OWN/CL-UNIQ/J-LV). SEMANTICS-BLIND about link
/// VALUES: whether `link ∈ dom(L)` is M7's, and M5 never reads M7 (no
/// back-edge). Its SHAPE is M5's, because the [`LinkSeat`](M5Rec::LinkSeat)
/// fold seats this very address as a [`Run`](crate::Run) start — so this is
/// where the run invariant is established for the link path, and the door
/// checks, in order:
///
/// * `NotLinkAddress` — `link` is a FULL ELEMENT POSITION
///   `doc·0·s_L·ordinal`: the element-field shape the placed run requires,
///   and the link subspace for where it belongs. Element level
///   alone would not do — a subspace BASE `doc·0·s_L` is element-level, and
///   its `subspace()` answers `s_L`, so it would pass a bare subspace test
///   and then be placed as a "width-1" run whose I-extent covers every link
///   address of the document.
/// * `NotHomeLink` — CL-OWN, `origin(link) = doc` via M1's `document_of`.
///   Shape first is what makes this question meaningful: `document_of` is
///   reflexive on a Document address, so a document seated in ITSELF would
///   otherwise pass CL-OWN and be placed as a width-1 run whose I-extent
///   covers the document's entire subtree — after which CL-UNIQ reports
///   every later link of that document as already seated, permanently.
/// * `AlreadySeated` — CL-UNIQ, which the arrangement answers for itself (a
///   link interior to a coalesced link run counts as seated).
///
/// The shape check refuses nothing M3's `mint_link` produces.
///
/// REQUIRES, and nothing here can check it: `m5` must be the WORKING state of
/// the transaction that stages the returned record — `stg.working().m5()` —
/// and that transaction must hold `M3State::link_lock_key(doc)`. `CL-UNIQ` is
/// decided against the state this reads, so a caller that decides it against
/// some other state has not decided it: read off a snapshot and stage
/// afterwards, and a link already seated between the two is seated a second
/// time at `n_L(d) + 1`, which no read reports and no operation undoes.
/// [`seat_link`] below discharges both, and M7's MAKELINK holds the same key
/// for its own K.λ mint.
///
/// Returns the delta; M7 lifts via `.into()` and stages it inside MAKELINK's
/// K.λ + K.μ⁺_L transaction. The fold appends at `n_L(d) + 1` and records NO
/// provenance (J-LV).
pub fn stage_seat_link(m5: &M5State, doc: &Address, link: &Address) -> Result<M5Rec, SeatError> {
    if !Run::admits_start(link) || link.subspace() != Some(&link_subspace()) {
        return Err(SeatError::NotLinkAddress);
    }
    if document_of(link).as_ref() != Some(doc) {
        return Err(SeatError::NotHomeLink);
    }
    if m5.seats_link(doc, link) {
        return Err(SeatError::AlreadySeated);
    }
    Ok(M5Rec::LinkSeat {
        doc: doc.clone(),
        link: link.clone(),
    })
}

/// STANDALONE OP — the Engine-Composition-Contract-required transact-wrapped
/// twin of the pure [`stage_seat_link`] (the contract demands BOTH forms for
/// any primitive that appears as a step in another store's composite, and
/// `stage_seat_link` is exactly that step for M7's MAKELINK).
///
/// ISOLATION/TEST USE ONLY: production seats a home link through MAKELINK,
/// which composes `stage_seat_link` into its transaction under M3's
/// `link_lock_key(doc)` — the same key held here; committing a seat *alone*
/// is not a production path (it would record a link V-position with no link
/// allocation in the same composite). Mirrors M4's `#[doc(hidden)] write`.
/// Returns the seated link address and the commit `Seq`.
#[doc(hidden)]
pub fn seat_link<W>(
    kernel: &Kernel<W>,
    doc: &Address,
    link: &Address,
) -> Result<(Address, Seq), TxnError<SeatError>>
where
    W: WorldState + HasM5,
    W::Record: From<M5Rec>,
{
    kernel.transact(&[M3State::link_lock_key(doc)], |stg| {
        let rec = stage_seat_link(stg.working().m5(), doc, link)?;
        stg.push(rec.into());
        Ok(link.clone())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{a, ca, doc1, doc2, la, n};

    #[test]
    fn stage_rejects_a_non_link_address_before_it_asks_whose_home_it_is() {
        // §8: the seated address becomes a Run start, so its shape is
        // checked first — and the two inputs that make the ORDER matter are
        // the ones whose origin IS the document.
        let s = M5State::genesis();
        // A document address: `document_of` is reflexive on it, so it passes
        // CL-OWN. Seated, it would be a width-1 run whose I-extent runs from
        // doc1 to doc1's successor — covering every address of the document
        // — and CL-UNIQ, which is I-extent membership, would then report
        // every later link of doc1 as already seated, for good.
        assert!(matches!(
            stage_seat_link(&s, &doc1(), &doc1()),
            Err(SeatError::NotLinkAddress)
        ));
        // A CONTENT element of the same document: also origin doc1, and
        // seating it would put a content address at a link V-position.
        assert!(matches!(
            stage_seat_link(&s, &doc1(), &ca(5)),
            Err(SeatError::NotLinkAddress)
        ));
        // An account address has no element field at all.
        assert!(matches!(
            stage_seat_link(&s, &doc1(), &a(&[1, 0, 1])),
            Err(SeatError::NotLinkAddress)
        ));
        // doc1's LINK SUBSPACE BASE — the case a bare subspace test admits.
        // It is element-level and its `subspace()` IS s_L, so CL-OWN and a
        // subspace comparison both pass it; what it is not is a position.
        // Seated, its last component would be the subspace id, so the run's
        // ordinal arithmetic would advance s_L → s_L + 1 (M1's TA7a) and its
        // I-extent would run from doc1's link base to the next subspace,
        // covering every link address doc1 can ever hold — after which
        // CL-UNIQ, which is I-extent membership, refuses all of them.
        let link_base = a(&[1, 0, 1, 0, 1, 0, 2]);
        assert_eq!(link_base.subspace(), Some(&skep_address::link_subspace()));
        assert!(matches!(
            stage_seat_link(&s, &doc1(), &link_base),
            Err(SeatError::NotLinkAddress)
        ));
        // The shape check refuses nothing M3's `mint_link` produces: a link
        // element of ANOTHER document passes it and is refused for the
        // reason it should be.
        assert!(matches!(
            stage_seat_link(&s, &doc1(), &a(&[1, 0, 1, 0, 2, 0, 2, 1])),
            Err(SeatError::NotHomeLink)
        ));
    }

    #[test]
    fn stage_rejects_a_foreign_home_and_a_reseat_and_admits_a_fresh_home_link() {
        // CL-OWN: origin(link) must be doc; CL-UNIQ: not already seated —
        // including a link INTERIOR to a coalesced link run.
        let s = M5State::genesis();
        assert!(matches!(
            stage_seat_link(&s, &doc2(), &la(1)),
            Err(SeatError::NotHomeLink)
        ));
        let rec = match stage_seat_link(&s, &doc1(), &la(1)) {
            Ok(rec) => rec,
            Err(e) => panic!("fresh home link must be admitted, got {e:?}"),
        };
        assert!(matches!(&rec, M5Rec::LinkSeat { .. }));
        let s = s.apply_m5(&rec);
        let second = match stage_seat_link(&s, &doc1(), &la(2)) {
            Ok(rec) => rec,
            Err(e) => panic!("second seat must be admitted, got {e:?}"),
        };
        let s = s.apply_m5(&second);
        // la(1) and la(2) coalesced into one width-2 run; both re-seats are
        // caught by I-extent membership.
        assert_eq!(s.link_count(&doc1()), n(2));
        assert!(matches!(
            stage_seat_link(&s, &doc1(), &la(1)),
            Err(SeatError::AlreadySeated)
        ));
        assert!(matches!(
            stage_seat_link(&s, &doc1(), &la(2)),
            Err(SeatError::AlreadySeated)
        ));
        // The pure step commits nothing: the receiver state never changed.
        assert_eq!(M5State::genesis().link_count(&doc1()), n(0));
    }
}
