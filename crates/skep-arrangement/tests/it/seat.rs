//! Link seating (§C): a home link appended, a reseat refused, R untouched,
//! and a published document seated as a draft is.

use skep_address::SpanSet;
use skep_arrangement::{seat_link, stage_seat_link, HasM5, Run, SeatError};

use crate::common::*;

#[test]
fn seating_appends_a_home_link_refuses_a_reseat_and_never_touches_r() {
    // §8: CL-OWN/CL-UNIQ; J-LV (no provenance); ASN-0117 P4 (a text delete
    // never touches the link run-list, checked at the close).
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let link1 = a(&[1, 0, 1, 0, 1, 0, 2, 1]);
    let link2 = a(&[1, 0, 1, 0, 1, 0, 2, 2]);
    let (seated, _) = seat_link(&k, &doc1(), &link1).expect("seat commits");
    assert_eq!(seated, link1);
    seat_link(&k, &doc1(), &link2).expect("second seat commits");
    {
        let s = k.snapshot();
        let m5 = s.world().m5();
        assert_eq!(m5.link_count(&doc1()), n(2));
        // Sequential link allocations coalesce to one maximally-merged run.
        let runs: Vec<&Run> = m5.link_runs(&doc1()).collect();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].i_start(), &link1);
        assert_eq!(m5.point(&doc1(), &vp(2, 2)), Some(link2.clone()));
        // J-LV: link placement is uncoupled from R.
        let cov = SpanSet::singleton(runs[0].iextent());
        assert!(m5.docs_ever_containing(&cov).is_empty());
        // The pure step reports the same guards off the snapshot slice.
        assert!(stage_seat_link(m5, &doc1(), &link1).is_err());
        assert!(stage_seat_link(m5, &doc1(), &a(&[1, 0, 1, 0, 1, 0, 2, 3])).is_ok());
    }
    assert_eq!(rejected(seat_link(&k, &doc1(), &link1)), SeatError::AlreadySeated);
    let foreign = a(&[1, 0, 1, 0, 2, 0, 2, 1]); // doc2's home link
    assert_eq!(rejected(seat_link(&k, &doc1(), &foreign)), SeatError::NotHomeLink);
    // Link survival: a text delete leaves the link subspace untouched.
    vs.delete(P1, &doc1(), vp(1, 1), n(3)).expect("delete commits");
    let s = k.snapshot();
    assert_eq!(s.world().m5().link_count(&doc1()), n(2));
    // Link writes are OUTSIDE the version-chain rule (PUB-2.12): a home link
    // seats into the PUBLISHED edition exactly as into a draft.
    let (seated, _) = seat_link(&k, &pdoc(), &a(&[1, 0, 1, 0, 3, 0, 2, 1]))
        .expect("seating into a published document is not an in-place edit");
    assert_eq!(seated, a(&[1, 0, 1, 0, 3, 0, 2, 1]));
    assert_eq!(k.snapshot().world().m5().link_count(&pdoc()), n(1));
}
