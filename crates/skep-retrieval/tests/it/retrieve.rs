//! §A RETRIEVEV (ASN-0115): exact per-position delivery in submitted order,
//! R6's silent degradations, the whole-request gate, and the masked form's
//! per-origin consult, asked once per run.

use std::cell::RefCell;

use skep_address::{Address, Span};
use skep_arrangement::{seat_link, Deposit};
use skep_namespace::PrincipalId;
use skep_retrieval::{Delivery, DeliveryItem, Query, RetrieveError, SpanFault};

use crate::common::*;

#[test]
fn retrieve_v_delivers_one_item_per_position_in_v_order_with_verbatim_bytes() {
    // ASN-0115 R2/R3: exact per-position delivery, ascending V, bytes
    // verbatim (M4 permanence/faithfulness).
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    let got = ok_of(q.retrieve_v(&[spec(doc1(), vspan(1, 1, 3))]));
    assert_eq!(
        got,
        Delivery(vec![
            DeliveryItem::Content(val(b"a")),
            DeliveryItem::Content(val(b"b")),
            DeliveryItem::Content(val(b"c")),
        ])
    );
}

#[test]
fn retrieve_v_concatenates_per_spec_in_submitted_order_without_dedup() {
    // ASN-0115 R5/R8: per-spec concatenation in the ORDER submitted, no
    // merge, no global sort; a repeated spec repeats its contribution.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    let got = ok_of(q.retrieve_v(&[
        spec(doc1(), vspan(1, 2, 2)),
        spec(doc1(), vspan(1, 1, 1)),
        spec(doc1(), vspan(1, 1, 1)),
    ]));
    assert_eq!(
        got,
        Delivery(vec![
            DeliveryItem::Content(val(b"b")),
            DeliveryItem::Content(val(b"c")),
            DeliveryItem::Content(val(b"a")),
            DeliveryItem::Content(val(b"a")),
        ])
    );
}

#[test]
fn retrieve_v_delivers_link_positions_as_address_references() {
    // ASN-0115 R3 link case: a link position's reference IS the address —
    // M4 is never consulted for it.
    let k = mem_kernel();
    insert3(&k);
    seat_link(&k, &doc1(), &la(1)).expect("seat commits");
    seat_link(&k, &doc1(), &la(2)).expect("seat commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    let got = ok_of(q.retrieve_v(&[spec(doc1(), vspan(2, 1, 2)), spec(doc1(), vspan(1, 1, 1))]));
    assert_eq!(
        got,
        Delivery(vec![
            DeliveryItem::Ref(la(1)),
            DeliveryItem::Ref(la(2)),
            DeliveryItem::Content(val(b"a")),
        ])
    );
}

#[test]
fn retrieve_v_degrades_silently_where_r6_mandates() {
    // ASN-0115 R6: gaps/overruns clip, a depth-incompatible (#start ≥ 3)
    // span and a foreign subspace yield empty contributions, a
    // registered-empty document yields empty — the request still SUCCEEDS.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    // Empty spec-set ⇒ Ok(empty).
    assert_eq!(ok_of(q.retrieve_v(&[])), Delivery(vec![]));
    // Overrun clips (accept-and-intersect upstream).
    let got = ok_of(q.retrieve_v(&[spec(doc1(), vspan(1, 2, 10))]));
    assert_eq!(
        got,
        Delivery(vec![
            DeliveryItem::Content(val(b"b")),
            DeliveryItem::Content(val(b"c")),
        ])
    );
    // Depth-incompatible: well-formed, passes the gate, resolves to ⟨⟩ —
    // the good spec's contribution survives beside it.
    let got = ok_of(q.retrieve_v(&[spec(doc1(), deep_span(1)), spec(doc1(), vspan(1, 1, 1))]));
    assert_eq!(got, Delivery(vec![DeliveryItem::Content(val(b"a"))]));
    // Foreign subspace: force-emptied upstream, never an error here.
    assert_eq!(
        ok_of(q.retrieve_v(&[spec(doc1(), vspan(3, 1, 1))])),
        Delivery(vec![])
    );
    // Registered-empty document contributes nothing.
    assert_eq!(
        ok_of(q.retrieve_v(&[spec(doc2(), vspan(1, 1, 1))])),
        Delivery(vec![])
    );
}

#[test]
fn retrieve_v_delivers_every_run_of_a_multi_block_document_in_v_order() {
    // ASN-0115 R3/R8: exactness is per ACTIVE V-POSITION, over every block
    // the span resolves to — a transcluding document resolves to several
    // runs, and an address at two V-positions is delivered twice.
    let k = mem_kernel();
    three_runs(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        ok_of(q.retrieve_v(&[spec(doc2(), vspan(1, 1, 4))])),
        Delivery(vec![
            DeliveryItem::Content(val(b"x")), // doc2's own block
            DeliveryItem::Content(val(b"a")), // transcluded [ca1, ca2]
            DeliveryItem::Content(val(b"b")),
            DeliveryItem::Content(val(b"a")), // ca1 a second time — R8, no dedup
        ])
    );
}

#[test]
fn retrieve_v_delivers_content_a_source_document_has_deleted() {
    // §Invariants: delivered content is permanent and faithful — M4 has no
    // delete, so a position a source document dropped still delivers its
    // bytes wherever it remains arranged. A document emptied by deletion is
    // registered-empty, which is a success, not a rejection.
    let k = mem_kernel();
    let vs = three_runs(&k);
    vs.delete(P1, &doc1(), vp(1, 1), n(3))
        .expect("delete commits"); // doc1 drops all three
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        ok_of(q.retrieve_v(&[spec(doc1(), vspan(1, 1, 3))])),
        Delivery::default()
    );
    assert_eq!(
        ok_of(q.retrieve_v(&[spec(doc2(), vspan(1, 2, 2))])),
        Delivery(vec![
            DeliveryItem::Content(val(b"a")),
            DeliveryItem::Content(val(b"b")),
        ])
    );
}

#[test]
fn retrieve_v_masked_withholds_each_unreadable_run_at_its_own_position() {
    // PUB-6.41/6.58, the door M10 calls: a run whose ORIGIN the reader may
    // not read is one `Withheld` item at the run's own position, carrying the
    // origin and the run's width — and two masked runs sharing an origin are
    // two items, never one of the summed width. M6 decides nothing about who
    // may read: it applies the predicate it is handed, per run.
    let k = mem_kernel();
    three_runs(&k); // doc2 = [x][ca1, ca2][ca1]: origins doc2, doc1, doc1
    let s = k.snapshot();
    let q = Query::new(&s);
    let not_doc1 = |d: &Address| *d != doc1();
    assert_eq!(
        ok_of(q.retrieve_v_masked(&[spec(doc2(), vspan(1, 1, 4))], &not_doc1)),
        Delivery(vec![
            DeliveryItem::Content(val(b"x")),
            DeliveryItem::Withheld {
                origin: doc1(),
                width: n(2)
            },
            DeliveryItem::Withheld {
                origin: doc1(),
                width: n(1)
            },
        ])
    );
    // The consult is on the run's ORIGIN, not the document named: masking
    // doc2 withholds its own run and delivers the transcluded ones.
    assert_eq!(
        ok_of(q.retrieve_v_masked(&[spec(doc2(), vspan(1, 1, 4))], &|d| *d != doc2())),
        Delivery(vec![
            DeliveryItem::Withheld {
                origin: doc2(),
                width: n(1)
            },
            DeliveryItem::Content(val(b"a")),
            DeliveryItem::Content(val(b"b")),
            DeliveryItem::Content(val(b"a")),
        ])
    );
    // The identity predicate IS the unmasked door.
    assert_eq!(
        ok_of(q.retrieve_v_masked(&[spec(doc2(), vspan(1, 1, 4))], &|_| true)),
        ok_of(q.retrieve_v(&[spec(doc2(), vspan(1, 1, 4))]))
    );
    // The width withheld is the WINDOW's share of the run, not the run's
    // whole: positions 3..4 cut the second run to one position.
    assert_eq!(
        ok_of(q.retrieve_v_masked(&[spec(doc2(), vspan(1, 3, 2))], &not_doc1)),
        Delivery(vec![
            DeliveryItem::Withheld {
                origin: doc1(),
                width: n(1)
            },
            DeliveryItem::Withheld {
                origin: doc1(),
                width: n(1)
            },
        ])
    );
    // A delivery counts a withheld run ONCE, however many positions it spans.
    assert_eq!(
        ok_of(q.retrieve_v_masked(&[spec(doc2(), vspan(1, 1, 4))], &not_doc1)).len(),
        3
    );
}

#[test]
fn retrieve_v_masked_withholds_a_link_run_against_its_home_document() {
    // A link run is consulted like any other run — against its ORIGIN, which
    // for a link is its home (CL-OWN, no special case) — and withheld whole.
    // The consult is NOT redundant with the caller's consult on the document
    // named: under head-float the run delivered is the head's, and its home
    // is the head, not the address asked about.
    let k = mem_kernel();
    let vs = deposit3(&k);
    let (fork, _) = vs
        .version(PrincipalId(1), &pdoc(), None)
        .expect("fork commits");
    assert_eq!(fork, vdoc());
    seat_link(&k, &fork, &vla(1)).expect("seat commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    // Named pdoc, the head's link run is delivered, and its home is the fork.
    assert_eq!(
        ok_of(q.retrieve_v(&[spec(pdoc(), vspan(2, 1, 1))])),
        Delivery(vec![DeliveryItem::Ref(vla(1))])
    );
    assert_eq!(
        ok_of(q.retrieve_v_masked(&[spec(pdoc(), vspan(2, 1, 1))], &|d| *d != vdoc())),
        Delivery(vec![DeliveryItem::Withheld {
            origin: vdoc(),
            width: n(1)
        }])
    );
    // Masking the address NAMED withholds nothing: no delivered run
    // originates there.
    assert_eq!(
        ok_of(q.retrieve_v_masked(&[spec(pdoc(), vspan(2, 1, 1))], &|d| *d != pdoc())),
        Delivery(vec![DeliveryItem::Ref(vla(1))])
    );
}

#[test]
fn retrieve_v_masked_consults_its_predicate_after_the_gate_and_once_per_resolved_run() {
    // `retrieve_v_masked`'s card, the clauses M10 relies on about WHEN and OF
    // WHAT its predicate is asked: only after the gate has passed the WHOLE
    // request (a rejected request consults it of nothing), and then once per
    // resolved run, in delivery order, of the run's origin — three consults
    // for four positions, and a run cut by the window still one.
    let k = mem_kernel();
    three_runs(&k); // doc2 = [x][ca1, ca2][ca1]: origins doc2, doc1, doc1
    let s = k.snapshot();
    let q = Query::new(&s);
    let asked: RefCell<Vec<Address>> = RefCell::new(Vec::new());
    let recording = |d: &Address| {
        asked.borrow_mut().push(d.clone());
        true
    };
    // Rejected on its SECOND spec: the first, which would resolve to three
    // runs, is not resolved and its origins are not consulted.
    let _ = err_of(q.retrieve_v_masked(
        &[
            spec(doc2(), vspan(1, 1, 4)),
            spec(unregistered(), vspan(1, 1, 1)),
        ],
        &recording,
    ));
    assert!(
        asked.borrow().is_empty(),
        "a rejected request consults the predicate of nothing"
    );
    // Answered whole: once per run, in run order, of each run's origin.
    let _ = ok_of(q.retrieve_v_masked(&[spec(doc2(), vspan(1, 1, 4))], &recording));
    assert_eq!(*asked.borrow(), vec![doc2(), doc1(), doc1()]);
    // A window cutting a run consults it once; a second spec of the same
    // origin consults again — per run, never memoized per origin.
    asked.borrow_mut().clear();
    let _ = ok_of(q.retrieve_v_masked(
        &[spec(doc2(), vspan(1, 3, 1)), spec(doc1(), vspan(1, 1, 3))],
        &recording,
    ));
    assert_eq!(*asked.borrow(), vec![doc1(), doc1()]);
}

#[test]
fn retrieve_v_masked_consults_its_predicate_of_the_origin_and_never_of_the_document_named() {
    // The same card: the predicate is asked of ORIGIN documents alone — which
    // may be a version address — and never of the document named. Named
    // pdoc, the head's one link run is delivered, and its home, the fork, is
    // the one document asked about; pdoc is asked about nowhere.
    let k = mem_kernel();
    let vs = deposit3(&k);
    let (fork, _) = vs
        .version(PrincipalId(1), &pdoc(), None)
        .expect("fork commits");
    seat_link(&k, &fork, &vla(1)).expect("seat commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    let asked: RefCell<Vec<Address>> = RefCell::new(Vec::new());
    let recording = |d: &Address| {
        asked.borrow_mut().push(d.clone());
        true
    };
    let _ = ok_of(q.retrieve_v_masked(&[spec(pdoc(), vspan(2, 1, 1))], &recording));
    assert_eq!(*asked.borrow(), vec![vdoc()]);
}

#[test]
fn retrieve_v_delivers_exactly_the_spans_intersection_with_the_bound_prefix() {
    // ASN-0115 R3 + R6 as the LAW they are: for every well-formed
    // ordinal-level span, the delivery is the document's V-sequence clipped
    // to [start, start + width) ∩ [1, n_C] — never an error, never a clamp to
    // anything else. Enumerated over the whole grid, so the boundaries no
    // hand-picked example visits (a start past the last position, a width
    // landing exactly on the end) are visited too.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.insert(P1, &doc1(), vp(1, 4), vec![val(b"d")], Deposit::Undeclared)
        .expect("insert commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    let text: [&[u8]; 4] = [b"a", b"b", b"c", b"d"];
    for start in 1..=6u32 {
        // Width 0 is not constructible: T12 forbids a zero width.
        for width in 1..=6u32 {
            let want: Vec<DeliveryItem> = (start..start + width)
                .filter(|p| (1..=4).contains(p))
                .map(|p| DeliveryItem::Content(val(text[p as usize - 1])))
                .collect();
            assert_eq!(
                ok_of(q.retrieve_v(&[spec(doc1(), vspan(1, start, width))])),
                Delivery(want),
                "span [1,{start}] x [0,{width}] over a four-position document"
            );
        }
    }
}

#[test]
fn retrieve_v_rejects_the_whole_request_on_any_malformed_spec() {
    // ASN-0115 well-formedness precondition: one bad spec rejects the WHOLE
    // request; the fault names the spec index; DocNotRegistered is checked
    // before the span gate within each spec.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    // Unregistered document — the error carries the offending address.
    assert!(matches!(
        err_of(q.retrieve_v(&[spec(unregistered(), vspan(1, 1, 1))])),
        RetrieveError::DocNotRegistered(d) if d == unregistered()
    ));
    // Registered-before-gate: an unregistered doc with a malformed span
    // still reports DocNotRegistered.
    assert!(matches!(
        err_of(q.retrieve_v(&[spec(unregistered(), not_ordinal_level_span())])),
        RetrieveError::DocNotRegistered(d) if d == unregistered()
    ));
    // Each SpanFault, with index attribution (the good spec at 0 does not
    // save the request — whole-request rejection).
    assert!(matches!(
        err_of(q.retrieve_v(&[
            spec(doc1(), vspan(1, 1, 1)),
            spec(doc1(), not_ordinal_level_span())
        ])),
        RetrieveError::MalformedSpec {
            index: 1,
            fault: SpanFault::NotOrdinalLevel
        }
    ));
    let not_uniform = Span::new(t(&[1, 1]), t(&[1])).expect("T12-legal");
    assert!(matches!(
        err_of(q.retrieve_v(&[spec(doc1(), not_uniform)])),
        RetrieveError::MalformedSpec {
            index: 0,
            fault: SpanFault::NotLevelUniform
        }
    ));
    let zeroed = Span::new(t(&[1, 0, 1]), t(&[0, 0, 1])).expect("T12-legal");
    assert!(matches!(
        err_of(q.retrieve_v(&[spec(doc1(), zeroed)])),
        RetrieveError::MalformedSpec {
            index: 0,
            fault: SpanFault::StartNotZeroFree
        }
    ));
    let shallow = Span::new(t(&[5]), t(&[1])).expect("T12-legal");
    assert!(matches!(
        err_of(q.retrieve_v(&[spec(doc1(), shallow)])),
        RetrieveError::MalformedSpec {
            index: 0,
            fault: SpanFault::StartTooShallow
        }
    ));
}
