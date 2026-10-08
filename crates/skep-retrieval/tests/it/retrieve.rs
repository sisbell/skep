//! §A RETRIEVEV (ASN-0115): exact per-position delivery in submitted order,
//! each stored value delivered itself and never a copy of its bytes, R6's
//! silent degradations, the whole-request gate, the delivery and walk
//! budgets, and the masked form's per-origin consult, asked once per run.

use std::cell::RefCell;

use skep_address::{Address, Span};
use skep_arrangement::{seat_link, Deposit, HasM5, VSpec, Vstream};
use skep_content::HasContent;
use skep_namespace::PrincipalId;
use skep_retrieval::{
    Delivery, DeliveryItem, Query, RetrieveError, SpanFault, MAX_COMPARE_OPERAND_BLOCKS,
    MAX_DELIVERY_ITEMS,
};

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
fn retrieve_v_delivers_each_stored_value_itself_and_never_a_copy_of_its_bytes() {
    // §A's cost argument: a content item is an `Arc` clone of the value M4
    // stores — one pointer per item however many bytes the value holds — so
    // a delivery naming one value many times (R8: no dedup) costs its item
    // count and not the bytes repeated. `Val::as_bytes` borrows the value's
    // one allocation, so the value itself and a copy are told apart by
    // address, which no `==` on a delivery can do.
    let k = mem_kernel();
    three_runs(&k); // ca1 sits at doc1's V1 and at doc2's V2 and V4
    let s = k.snapshot();
    let q = Query::new(&s);
    let stored = s
        .world()
        .content()
        .value_at(ca(1).tumbler())
        .expect("ca1 is stored");
    let delivery = ok_of(q.retrieve_v(&[
        spec(doc1(), vspan(1, 1, 1)),
        spec(doc2(), vspan(1, 2, 1)),
        spec(doc2(), vspan(1, 4, 1)),
    ]));
    assert_eq!(delivery.len(), 3);
    for item in &delivery {
        let DeliveryItem::Content(v) = item else {
            panic!("ca1 is content, delivered as {item:?}");
        };
        assert!(
            std::ptr::eq(v.as_bytes(), stored.as_bytes()),
            "a delivered {v:?} is a copy of the stored value's bytes, not the value"
        );
    }
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
    let window = ok_of(q.retrieve_v_masked(&[spec(doc2(), vspan(1, 3, 2))], &not_doc1));
    assert_eq!(
        window,
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
    // Every run of that window is masked, so it delivers nothing — and is
    // NOT empty: `is_empty` asks whether the delivery carries any item, and
    // each withheld run is one (`Delivery::is_empty`'s card).
    assert!(
        !window.is_empty(),
        "an all-masked delivery carries its withheld items: {window:?}"
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
    // Answered whole: once per run, in run order, of each run's origin —
    // doc2, the document named, among them as its own run's origin.
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
fn retrieve_v_masked_consults_its_predicate_of_the_floated_runs_origin_not_of_the_address_named() {
    // The same card: the predicate is asked of ORIGIN documents alone — which
    // may be a version address — and of the document named only where it is
    // some run's origin. Named pdoc, the head's one link run is delivered,
    // and its home, the fork, is the one document asked about; pdoc, the
    // origin of no run delivered, is asked about nowhere.
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

#[test]
fn retrieve_v_refuses_a_delivery_past_its_budget_whole() {
    // `MAX_DELIVERY_ITEMS`' card: a document's extent is VIRTUAL — one COPY
    // of 4096 specs places a 64-position run 4096 times, 2^18 positions from
    // 64 stored values — so ONE spec names a delivery the request's size says
    // nothing about. Exactly the budget is delivered, completely; one
    // position more is refused whole, never truncated (R3).
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    vs.insert(
        P1,
        &doc1(),
        vp(1, 1),
        vec![val(b"x"); 64],
        Deposit::Undeclared,
    )
    .expect("insert commits");
    let whole = VSpec {
        source: doc1(),
        span: vspan(1, 1, 64),
    };
    vs.copy(P1, &doc2(), vp(1, 1), &vec![whole; 4096])
        .expect("copy commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        s.world().m5().content_count(&doc2()),
        n(1 << 18),
        "the premise: 2^18 positions, past the budget, from 64 stored values"
    );
    let budget = u32::try_from(MAX_DELIVERY_ITEMS).expect("the budget fits a u32");
    assert_eq!(
        ok_of(q.retrieve_v(&[spec(doc2(), vspan(1, 1, budget))])).len(),
        MAX_DELIVERY_ITEMS
    );
    let e = err_of(q.retrieve_v(&[spec(doc2(), vspan(1, 1, budget + 1))]));
    assert_eq!(e, RetrieveError::TooManyItems);
    // The refusal names its budget, so a client narrows against the number.
    assert!(e.to_string().contains(&MAX_DELIVERY_ITEMS.to_string()));
    // The budget counts ITEMS, and a withheld run is one item however many
    // positions it spans: the whole document, every run masked, is 4096
    // items and is answered.
    assert_eq!(
        ok_of(q.retrieve_v_masked(&[spec(doc2(), vspan(1, 1, 1 << 18))], &|d| *d != doc1())).len(),
        4096
    );
}

#[test]
fn retrieve_v_refuses_a_spec_set_whose_spans_would_walk_past_the_walk_budget() {
    // The walk budget: M5 reaches a span by walking the run list from its
    // first run, so a spec opening past the end of a fragmented document walks
    // every run and delivers nothing — a cost the item count never sees. The
    // walk budget is the operand budget's square, so over doc2's 8192 runs one
    // spec more than `MAX_COMPARE_OPERAND_BLOCKS² / 8192` such specs is past
    // it, and the spec-set is refused before any spec is walked.
    let k = mem_kernel();
    fragmented_doc2(&k); // doc2 = 8192 one-position runs
    let s = k.snapshot();
    let q = Query::new(&s);
    let run_count = s.world().m5().content_run_count(&doc2());
    assert_eq!(run_count, 8192, "the premise: doc2 is 8192 runs");
    let past_budget = MAX_COMPARE_OPERAND_BLOCKS * MAX_COMPARE_OPERAND_BLOCKS / run_count + 1;
    assert_eq!(
        err_of(q.retrieve_v(&vec![spec(doc2(), vspan(1, 8193, 1)); past_budget])),
        RetrieveError::TooManyItems
    );
    // The control: a spec at doc2's first position walks two runs, so the
    // wire's whole 4096 are priced well inside the budget and delivered.
    assert_eq!(
        ok_of(q.retrieve_v(&vec![spec(doc2(), vspan(1, 1, 1)); 4096])).len(),
        4096
    );
    // The spec-set is priced WHOLE before its first spec is walked, so a
    // request refused for its walk consults the predicate of nothing — not
    // even of a first spec whose run it would have reached
    // (`retrieve_v_masked`'s card).
    let asked: RefCell<Vec<Address>> = RefCell::new(Vec::new());
    let recording = |d: &Address| {
        asked.borrow_mut().push(d.clone());
        true
    };
    let mut priced = vec![spec(doc2(), vspan(1, 1, 1))];
    priced.extend(vec![spec(doc2(), vspan(1, 8193, 1)); past_budget]);
    assert_eq!(
        err_of(q.retrieve_v_masked(&priced, &recording)),
        RetrieveError::TooManyItems
    );
    assert!(
        asked.borrow().is_empty(),
        "priced whole, before any spec is walked: {:?}",
        asked.borrow()
    );
}
