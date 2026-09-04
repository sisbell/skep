//! §C/§8 — link seating: the pure step composed into M7's MAKELINK, and its
//! contract-required standalone transact-wrapped twin.

use skep_address::{document_of, Address};
use skep_kernel::{Kernel, Seq, TxnError, WorldState};
use skep_namespace::M3State;

use crate::error::SeatError;
use crate::state::{M5Rec, M5State};
use crate::HasM5;

/// Append an already-allocated home link `link` at doc's next link
/// V-position (§8; ASN-0047 CL-OWN/CL-UNIQ/J-LV). SEMANTICS-BLIND: trusts M7
/// that `link ∈ dom(L)` (M5 never reads M7 — no back-edge); M5 checks only
/// CL-OWN (`origin(link) = doc`, via M1's `document_of`) and CL-UNIQ, which
/// the arrangement answers for itself (a link interior to a coalesced link
/// run counts as seated). Returns the delta; M7
/// lifts via `.into()` and stages it inside MAKELINK's K.λ + K.μ⁺_L
/// transaction. The fold appends at `n_L(d) + 1` and records NO provenance
/// (J-LV).
pub fn stage_seat_link(m5: &M5State, doc: &Address, link: &Address) -> Result<M5Rec, SeatError> {
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
    k: &Kernel<W>,
    doc: &Address,
    link: &Address,
) -> Result<(Address, Seq), TxnError<SeatError>>
where
    W: WorldState + HasM5,
    W::Record: From<M5Rec>,
{
    k.transact(&[M3State::link_lock_key(doc)], |stg| {
        let rec = stage_seat_link(stg.working().m5(), doc, link)?;
        stg.push(rec.into());
        Ok(link.clone())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{a, doc1, doc2, la, n};

    #[test]
    fn stage_rejects_a_foreign_home_and_a_reseat_and_admits_a_fresh_home_link() {
        // CL-OWN: origin(link) must be doc; CL-UNIQ: not already seated —
        // including a link INTERIOR to a coalesced link run.
        let s = M5State::genesis();
        assert!(matches!(
            stage_seat_link(&s, &doc2(), &la(1)),
            Err(SeatError::NotHomeLink)
        ));
        // A non-element input with the wrong origin is likewise NotHomeLink.
        assert!(matches!(
            stage_seat_link(&s, &doc1(), &a(&[1, 0, 1])),
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
