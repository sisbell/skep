//! Integration tests for M6's public surface. Each test states a claim the
//! design/interface actually makes (§-references inline): the registry gate
//! every operation opens with, in the form M6 owns it — `is_registered_document`
//! and never M3's wider `is_allocated`; which error wins when several
//! conditions fail at once, the FIRST fault in request order across a request
//! and the registry before the spans within one region; the silent-empty
//! degradations RETRIEVEV's R6 mandates and
//! the delivery law they are instances of (the span's intersection with the
//! bound prefix, over the whole grid of starts and widths); delivery
//! order/multiplicity across every block a span resolves to (R3/R5/R8);
//! extent synthesis from counts (D-SEQ★) and what the two extent queries
//! therefore do and do not answer (V9: the box is fixed under a content edit
//! the extents follow); origin projection at whatever depth a document sits
//! (a fork's own content, against its source's), and its reject-never-clamp
//! admissibility with the exact-extent boundary (WF_V/O13); the
//! cross-document SHOWDELETIONS combine (D-IDENT, and M6's T1 presentation
//! of each set);
//! COMPARE's address-equal join — per-block feet, overlap widths, fan-out
//! completeness, region confinement, the four-component presentation head and
//! the tail that alone orders a fan-out, the whole relation against an
//! independent per-position oracle, and the two budgets that refuse (never
//! truncate) a request whose `|P|·|Q|` outruns them — counted in blocks
//! rather than spans, at their exact boundaries, naming which operand, behind
//! a gate that runs over both operands whole;
//! FINDDOCSCONTAINING's present-tense filter (FD-SOUND) over the union of
//! every region span's coverage; that a query answers from the snapshot it
//! pinned and never mutates; and the derive policy M10 marshals against.
//!
//! This file compiles as a FOREIGN crate, so it also witnesses the derive
//! policy's consequences: every result and every error M6 hands back renders,
//! so `assert_eq!` compiles against any of them here exactly as it does for
//! M10 — a delivery included, whose content items render by BYTE LENGTH and
//! never by payload; each registry rejection's message names the document it
//! refused; and the two fault vocabularies key a map, which is the derive a
//! consumer could not supply for itself. The toy `World`/`Rec` pair is the
//! minimal engine assembly
//! the composition contract prescribes; all state is arranged through M5's
//! real `Vstream` ops (M5Rec is sealed to foreign crates).

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Span, SpanSet, Tumbler};
use skep_arrangement::{seat_link, Caller, HasM5, M5State, VPos, VSpec, Vstream};
use skep_content::{ContentStore, ContentWrite, HasContent, Val};
use skep_kernel::{CheckpointPolicy, Durability, Kernel, KernelConfig, Seq, WorldState};
use skep_namespace::{HasM3, M3Rec, M3State, PrincipalId};
use skep_retrieval::{
    CompareError, CompareReport, CorrPair, Deletions, DeletionsError, Delivery, DeliveryItem,
    ExtentError, FindError, Operand, OriginError, Query, RegionSpec, RetrieveError, SpanFault,
    Spec, MAX_COMPARE_OPERAND_BLOCKS, MAX_COMPARE_PAIRS,
};

// ---- the minimal engine assembly (composition contract) ----

#[derive(Clone, Serialize, Deserialize)]
struct World {
    m3: M3State,
    content: ContentStore,
    m5: M5State,
}

#[derive(Clone, Serialize, Deserialize)]
enum Rec {
    M3(M3Rec),
    Content(ContentWrite),
    M5(skep_arrangement::M5Rec),
}

impl From<M3Rec> for Rec {
    fn from(r: M3Rec) -> Rec {
        Rec::M3(r)
    }
}
impl From<ContentWrite> for Rec {
    fn from(r: ContentWrite) -> Rec {
        Rec::Content(r)
    }
}
impl From<skep_arrangement::M5Rec> for Rec {
    fn from(r: skep_arrangement::M5Rec) -> Rec {
        Rec::M5(r)
    }
}

impl HasM3 for World {
    fn m3(&self) -> &M3State {
        &self.m3
    }
}
impl HasContent for World {
    fn content(&self) -> &ContentStore {
        &self.content
    }
}
impl HasM5 for World {
    fn m5(&self) -> &M5State {
        &self.m5
    }
}

impl WorldState for World {
    type Record = Rec;
    fn apply(&self, r: &Rec) -> World {
        match r {
            Rec::M3(x) => World {
                m3: self.m3.apply_m3(x),
                ..self.clone()
            },
            Rec::Content(x) => World {
                content: self.content.apply_write(x),
                ..self.clone()
            },
            Rec::M5(x) => World {
                m5: self.m5.apply_m5(x),
                ..self.clone()
            },
        }
    }
}

// ---- helpers ----

fn t(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
}

fn a(comps: &[u32]) -> Address {
    validate(t(comps)).expect("test addresses are T4-valid")
}

fn n(x: u32) -> Nat {
    Nat::from(x)
}

fn doc1() -> Address {
    a(&[1, 0, 1, 0, 1])
}

fn doc2() -> Address {
    a(&[1, 0, 1, 0, 2])
}

/// Never registered.
fn unregistered() -> Address {
    a(&[1, 0, 1, 0, 9])
}

/// A second never-registered document, so a two-document rejection can say
/// WHICH one it named.
fn unregistered2() -> Address {
    a(&[1, 0, 1, 0, 8])
}

/// doc1's content element at `ordinal` (length 8), M3's minted shape.
fn ca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 1, ordinal])
}

/// doc2's content element at `ordinal` — doc2's OWN minted content, on a
/// different I-chain from doc1's [`ca`].
fn doc2_ca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 2, 0, 1, ordinal])
}

/// doc1's link element at `ordinal`.
fn la(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 2, ordinal])
}

/// doc2's link element at `ordinal`.
fn doc2_la(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 2, 0, 2, ordinal])
}

/// The version fork of doc1 (`(d_src, 1)` chain) and its length-9 content
/// elements — the mixed-length transclusion case.
fn vdoc() -> Address {
    a(&[1, 0, 1, 0, 1, 1])
}
fn vca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 1, 0, 1, ordinal])
}

fn vp(subspace: u32, ordinal: u32) -> VPos {
    VPos {
        subspace: n(subspace),
        ordinal: n(ordinal),
    }
}

/// An ordinal-level depth-2 V-span `[subspace, ordinal]` × `[0, count]`.
fn vspan(subspace: u32, ordinal: u32, count: u32) -> Span {
    Span::new(t(&[subspace, ordinal]), t(&[0, count])).expect("ordinal-level V-span is T12-valid")
}

fn val(b: &[u8]) -> Val {
    Val::new(b)
}

/// The seeded owner of doc1/doc2 — write fixtures run under it, so the ω
/// gate (ownership ruling, 2026-08-16) is exercised, not skipped.
const P1: Caller = Caller::Principal(PrincipalId(1));

fn spec(doc: Address, span: Span) -> Spec {
    Spec { doc, span }
}

fn region_spec(doc: Address, spans: Vec<Span>) -> RegionSpec {
    RegionSpec { doc, spans }
}

/// A T12-legal but non-ordinal-level width (action point 1).
fn not_ordinal_level_span() -> Span {
    Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12-legal")
}

/// A well-formed depth-3 span — depth-INCOMPATIBLE, not malformed.
fn deep_span(subspace: u32) -> Span {
    Span::new(t(&[subspace, 1, 1]), t(&[0, 0, 1])).expect("T12-legal")
}

/// Unwrap Ok — `Result::expect` under one name, so the unwrap and its failure
/// message are uniform across all seven operations. The `Debug` bound is what
/// makes a failure name WHICH rejection fired rather than only that one did:
/// every M6 error renders, and a suite this size cannot afford a panic that
/// says nothing about the answer it got.
fn ok_of<T, E: fmt::Debug>(r: Result<T, E>) -> T {
    r.expect("expected Ok, got Err")
}

/// Unwrap Err, the mirror of [`ok_of`] — printing the answer that arrived
/// where a rejection was claimed.
fn err_of<T: fmt::Debug, E>(r: Result<T, E>) -> E {
    r.expect_err("expected Err, got Ok")
}

/// Genesis with M3 pre-seeded by folding exactly the records its own
/// delegate/create_new_document ops would stage: account [1,0,1] → principal
/// 1 (owns doc1, doc2), account [1,0,2] → principal 2.
fn genesis() -> World {
    let m3 = M3State::genesis()
        .apply_m3(&M3Rec::Allocate { addr: a(&[1, 0, 1]) })
        .apply_m3(&M3Rec::RegisterPrincipal {
            prefix: a(&[1, 0, 1]),
            id: PrincipalId(1),
        })
        .apply_m3(&M3Rec::Allocate { addr: a(&[1, 0, 2]) })
        .apply_m3(&M3Rec::RegisterPrincipal {
            prefix: a(&[1, 0, 2]),
            id: PrincipalId(2),
        })
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 1]),
        })
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 2]),
        });
    World {
        m3,
        content: ContentStore::default(),
        m5: M5State::genesis(),
    }
}

fn mem_kernel() -> Kernel<World> {
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
    };
    Kernel::open(cfg, genesis()).expect("in-memory open")
}

/// doc1 arranged with content a, b, c (ca1..ca3).
fn insert3(k: &Kernel<World>) -> Vstream<'_, World> {
    let vs = Vstream::new(k);
    vs.insert(P1, &doc1(), vp(1, 1), vec![val(b"a"), val(b"b"), val(b"c")])
        .expect("insert commits");
    vs
}

/// doc1 = `[a, b, c]`; doc2 = `[x][ca1, ca2][ca1]` — its own content, then
/// two transclusions of doc1. doc2's content resolves to THREE runs and one
/// address (ca1) sits at two V-positions: the multi-block document every
/// per-run claim in this module is about.
fn three_runs(k: &Kernel<World>) -> Vstream<'_, World> {
    let vs = insert3(k);
    vs.insert(P1, &doc2(), vp(1, 1), vec![val(b"x")])
        .expect("insert commits");
    vs.copy(
        P1,
        &doc2(),
        vp(1, 2),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 2),
        }],
    )
    .expect("copy commits");
    vs.copy(
        P1,
        &doc2(),
        vp(1, 4),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 1),
        }],
    )
    .expect("copy commits");
    vs
}

/// doc1 = `[a, b, c]`; doc2 = `[ca1][ca1][own "a"]` — ca1 placed twice, then
/// doc2's own content whose BYTES equal doc1's ca1 at a different address.
/// The fan-out and value-blindness fixture.
fn fanout_doc2(k: &Kernel<World>) -> Vstream<'_, World> {
    let vs = insert3(k);
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 1),
        }],
    )
    .expect("copy commits");
    vs.copy(
        P1,
        &doc2(),
        vp(1, 2),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 1),
        }],
    )
    .expect("copy commits");
    vs.insert(P1, &doc2(), vp(1, 3), vec![val(b"a")])
        .expect("insert commits");
    vs
}

// ---- Query basics ----

#[test]
fn as_of_reports_the_pinned_seq_and_queries_never_mutate() {
    // §Public interface: as_of is the committed index this query reads (V1
    // retrospective); every operation is a pure read — no commit, ever.
    let k = mem_kernel();
    let vs = insert3(&k);
    seat_link(&k, &doc1(), &la(1)).expect("seat commits");
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 2),
        }],
    )
    .expect("copy commits");
    let before = k.current_seq();
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(q.as_of(), s.seq());
    assert_eq!(q.as_of(), before);
    // Run every operation off the one snapshot…
    let _ = ok_of(q.retrieve_v(&[spec(doc1(), vspan(1, 1, 3))]));
    let _ = ok_of(q.doc_vspan(&doc1()));
    let _ = ok_of(q.doc_vspanset(&doc1()));
    let _ = ok_of(q.show_origin_v(&doc1(), &vspan(1, 1, 3)));
    let _ = ok_of(q.show_deletions(&doc1(), &doc2()));
    let _ = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 2)])],
    ));
    let _ = ok_of(q.find_docs_containing(&[region_spec(doc2(), vec![vspan(1, 1, 2)])]));
    // …and nothing committed.
    assert_eq!(k.current_seq(), before);
}

#[test]
fn the_query_handle_is_a_borrow_and_copies_like_one() {
    // §Public interface: a Query owns nothing and holds one borrow, so it
    // copies rather than moves, and every copy reads the SAME pinned
    // snapshot — which is the whole of what "one Query per logical query"
    // protects. It renders as the coordinate it is pinned to, since the
    // snapshot behind it has no Debug of its own.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    fn consume(q: Query<'_, World>) -> Seq {
        q.as_of()
    }
    assert_eq!(consume(q), s.seq()); // by value…
    assert_eq!(q.as_of(), s.seq()); // …and q is still usable: Copy, not moved.
    let copy = q;
    assert_eq!(copy.as_of(), q.as_of());
    assert_eq!(format!("{q:?}"), format!("Query {{ as_of: {:?}, .. }}", s.seq()));
}

#[test]
fn a_query_answers_from_its_pinned_snapshot_after_later_commits() {
    // §Public interface: every operation is a pure function of ONE consistent
    // M2 snapshot — the discharge of M2's clause 6 and the single-Σ
    // requirement of ASN-0075/0122/0124. A handle taken before a commit
    // answers from the state it pinned, never from the state that followed.
    let k = mem_kernel();
    let vs = insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    vs.insert(P1, &doc1(), vp(1, 4), vec![val(b"d")])
        .expect("insert commits");
    assert_ne!(
        k.current_seq(),
        q.as_of(),
        "the fixture committed after the pin"
    );
    // Three positions, not four: the fourth is not in this query's world.
    assert_eq!(
        ok_of(q.retrieve_v(&[spec(doc1(), vspan(1, 1, 4))])),
        Delivery(vec![
            DeliveryItem::Content(val(b"a")),
            DeliveryItem::Content(val(b"b")),
            DeliveryItem::Content(val(b"c")),
        ])
    );
    // The extent is the pinned count, not the live one.
    assert_eq!(
        ok_of(q.doc_vspanset(&doc1())),
        SpanSet::singleton(Span::new(t(&[1, 1]), t(&[0, 3])).expect("T12"))
    );
    // The control: a handle taken now sees all four.
    let s2 = k.snapshot();
    let q2 = Query::new(&s2);
    assert_eq!(
        ok_of(q2.retrieve_v(&[spec(doc1(), vspan(1, 1, 4))])).len(),
        4
    );
}

#[test]
fn every_operation_refuses_an_allocated_address_that_is_not_a_document() {
    // §The distinction every operation opens with: M6 gates on M3's
    // `is_registered_document`, which is NARROWER than `is_allocated` — an
    // account address and a content element are both allocated and neither is
    // a document. Reading the wider oracle turns each of these rejections
    // into a spurious empty success.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    for d in [a(&[1, 0, 1]), ca(1)] {
        // an ACCOUNT (genesis), an ELEMENT (insert3)
        let m3 = s.world().m3();
        assert!(m3.is_allocated(&d), "the premise: {d} IS allocated");
        assert!(!m3.is_registered_document(&d), "…and is not a document");
        assert_eq!(
            err_of(q.retrieve_v(&[spec(d.clone(), vspan(1, 1, 1))])),
            RetrieveError::DocNotRegistered(d.clone())
        );
        assert_eq!(err_of(q.doc_vspan(&d)), ExtentError::DocNotRegistered);
        assert_eq!(err_of(q.doc_vspanset(&d)), ExtentError::DocNotRegistered);
        assert_eq!(
            err_of(q.show_origin_v(&d, &vspan(1, 1, 1))),
            OriginError::DocNotRegistered
        );
        assert_eq!(
            err_of(q.show_deletions(&d, &doc1())),
            DeletionsError::DocNotRegistered(d.clone())
        );
        assert_eq!(
            err_of(q.compare(&[region_spec(d.clone(), vec![vspan(1, 1, 1)])], &[])),
            CompareError::DocNotRegistered(d.clone())
        );
        assert_eq!(
            err_of(q.find_docs_containing(&[region_spec(d.clone(), vec![vspan(1, 1, 1)])])),
            FindError::DocNotRegistered(d.clone())
        );
    }
}

// ---- §A RETRIEVEV ----

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
fn retrieve_v_delivers_exactly_the_spans_intersection_with_the_bound_prefix() {
    // ASN-0115 R3 + R6 as the LAW they are: for every well-formed
    // ordinal-level span, the delivery is the document's V-sequence clipped
    // to [start, start + width) ∩ [1, n_C] — never an error, never a clamp to
    // anything else. Enumerated over the whole grid, so the boundaries no
    // hand-picked example visits (a start past the last position, a width
    // landing exactly on the end) are visited too.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.insert(P1, &doc1(), vp(1, 4), vec![val(b"d")])
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

// ---- the request gate, across the operations that take a whole request ----

#[test]
fn the_request_gate_reports_the_first_fault_in_request_order() {
    // The gate walks the request IN ORDER and the FIRST fault wins, whatever
    // its kind — which is what makes `index` / `(region, index)` /
    // `(operand, region, index)` localization mean anything. Within ONE spec
    // the registry check precedes the span gate; ACROSS specs, position
    // decides. Each request below carries two faults of DIFFERENT kinds, so
    // only the ordering can explain which is reported.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    assert!(matches!(
        err_of(q.retrieve_v(&[
            spec(doc1(), not_ordinal_level_span()),
            spec(unregistered(), vspan(1, 1, 1))
        ])),
        RetrieveError::MalformedSpec {
            index: 0,
            fault: SpanFault::NotOrdinalLevel
        }
    ));
    assert!(matches!(
        err_of(q.retrieve_v(&[
            spec(unregistered(), vspan(1, 1, 1)),
            spec(doc1(), not_ordinal_level_span()),
        ])),
        RetrieveError::DocNotRegistered(d) if d == unregistered()
    ));
    assert!(matches!(
        err_of(q.find_docs_containing(&[
            region_spec(doc1(), vec![not_ordinal_level_span()]),
            region_spec(unregistered(), vec![vspan(1, 1, 1)]),
        ])),
        FindError::MalformedSpan {
            region: 0,
            index: 0,
            fault: SpanFault::NotOrdinalLevel
        }
    ));
    assert!(matches!(
        err_of(q.compare(
            &[region_spec(doc1(), vec![not_ordinal_level_span()])],
            &[region_spec(unregistered(), vec![vspan(1, 1, 1)])],
        )),
        CompareError::MalformedSpan {
            operand: Operand::First,
            region: 0,
            index: 0,
            fault: SpanFault::NotOrdinalLevel
        }
    ));
    // ρ₂'s documents are gated too, after ρ₁'s — the operand-2 registry
    // check no single-operand request can reach.
    assert!(matches!(
        err_of(q.compare(
            &[region_spec(doc1(), vec![vspan(1, 1, 1)])],
            &[region_spec(unregistered(), vec![])],
        )),
        CompareError::DocNotRegistered(d) if d == unregistered()
    ));
}

#[test]
fn the_request_gate_checks_the_registry_before_the_spans_of_its_own_region() {
    // §Errors: within one operation enum, declaration order IS check order —
    // so `CompareError::DocNotRegistered` outranks BOTH `NotContentSubspace`
    // and `MalformedSpan`, and `FindError`'s outranks `MalformedSpan`. Each
    // request below is faulty two ways in the SAME region, so only the
    // within-region order can explain the verdict; every other gate test puts
    // its two faults in different regions, where position decides instead.
    // (RETRIEVEV's spec-level twin is pinned in
    // `retrieve_v_rejects_the_whole_request_on_any_malformed_spec`.)
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        err_of(q.compare(
            &[region_spec(unregistered(), vec![not_ordinal_level_span()])],
            &[],
        )),
        CompareError::DocNotRegistered(unregistered())
    );
    // …and above the residence check too, which itself outranks
    // well-formedness: a link-started span in an unregistered region reports
    // the registry, not the subspace.
    assert_eq!(
        err_of(q.compare(&[region_spec(unregistered(), vec![vspan(2, 1, 1)])], &[])),
        CompareError::DocNotRegistered(unregistered())
    );
    assert_eq!(
        err_of(q.find_docs_containing(&[region_spec(
            unregistered(),
            vec![not_ordinal_level_span()]
        )])),
        FindError::DocNotRegistered(unregistered())
    );
}

// ---- §B document extents ----

#[test]
fn doc_vspan_is_the_bounding_hull_of_the_per_subspace_extents() {
    // ASN-0112: σ_d — the whole-document bounding span, a bounding box
    // bridging the inter-subspace void once links exist (D-SEQ★ makes the
    // counts the extents; the anchor is the subspace origin, never negative).
    let k = mem_kernel();
    insert3(&k);
    {
        let s = k.snapshot();
        let q = Query::new(&s);
        // Content only: ([1,1], reach [1,4)).
        let got = ok_of(q.doc_vspan(&doc1()));
        let want = SpanSet::singleton(
            Span::from_endpoints(t(&[1, 1]), &t(&[1, 4])).expect("well-formed"),
        );
        assert_eq!(got, want);
    }
    seat_link(&k, &doc1(), &la(1)).expect("seat commits");
    seat_link(&k, &doc1(), &la(2)).expect("seat commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    // Cross-subspace bounding box: [1,1] .. [2, n_L + 1).
    let got = ok_of(q.doc_vspan(&doc1()));
    let want =
        SpanSet::singleton(Span::from_endpoints(t(&[1, 1]), &t(&[2, 3])).expect("well-formed"));
    assert_eq!(got, want);
    // σ_d IS the hull of the per-subspace extents — the same first start and
    // the same last reach, never a second derivation that could disagree.
    let extents = ok_of(q.doc_vspanset(&doc1()));
    let (lo, hi) = (
        extents.iter().next().expect("occupied ⇒ a first extent"),
        extents.iter().last().expect("occupied ⇒ a last extent"),
    );
    assert_eq!(
        got,
        SpanSet::singleton(
            Span::from_endpoints(lo.start().clone(), &hi.reach()).expect("well-formed")
        )
    );
    // Link-only document: the anchor moves to [2,1].
    seat_link(&k, &doc2(), &doc2_la(1)).expect("seat commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    let got = ok_of(q.doc_vspan(&doc2()));
    let want =
        SpanSet::singleton(Span::from_endpoints(t(&[2, 1]), &t(&[2, 2])).expect("well-formed"));
    assert_eq!(got, want);
}

#[test]
fn doc_vspanset_reports_per_subspace_exact_extents_prenormalized() {
    // ASN-0113 W2/W4/W13: ≤2 members, content before link, exact
    // ext(d,S) = ([S,1],[0,n_S]), already normal; ⟨⟩ for registered-empty;
    // not registered ⇒ Err (both extent ops).
    let k = mem_kernel();
    insert3(&k);
    seat_link(&k, &doc1(), &la(1)).expect("seat commits");
    seat_link(&k, &doc1(), &la(2)).expect("seat commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    let got = ok_of(q.doc_vspanset(&doc1()));
    let want: SpanSet = vec![
        Span::new(t(&[1, 1]), t(&[0, 3])).expect("T12"),
        Span::new(t(&[2, 1]), t(&[0, 2])).expect("T12"),
    ]
    .into_iter()
    .collect();
    assert_eq!(got, want);
    assert!(got.is_normalized());
    // Registered-empty ⇒ ⟨⟩ for both operations.
    assert_eq!(ok_of(q.doc_vspanset(&doc2())), SpanSet::empty());
    assert_eq!(ok_of(q.doc_vspan(&doc2())), SpanSet::empty());
    // Not registered ⇒ fail, for both.
    assert!(matches!(
        err_of(q.doc_vspan(&unregistered())),
        ExtentError::DocNotRegistered
    ));
    assert!(matches!(
        err_of(q.doc_vspanset(&unregistered())),
        ExtentError::DocNotRegistered
    ));
}

#[test]
fn a_content_edit_under_links_moves_the_extent_and_not_the_bounding_box() {
    // ASN-0112 V9, which is the whole of the routing `doc_vspan` states: the
    // cross-subspace box is a function of the two EXTREMES, so a content edit
    // keeping n_C ≥ 1 leaves it fixed while `doc_vspanset`'s content member
    // moves with n_C. A caller that must observe a content-count change asks
    // for the extents; asking for the box would tell it nothing happened.
    let k = mem_kernel();
    let vs = insert3(&k); // n_C = 3
    seat_link(&k, &doc1(), &la(1)).expect("seat commits");
    seat_link(&k, &doc1(), &la(2)).expect("seat commits"); // n_L = 2
    let before = k.snapshot();
    let q_before = Query::new(&before);
    vs.delete(P1, &doc1(), vp(1, 3), n(1))
        .expect("delete commits"); // n_C = 2, still ≥ 1
    let after = k.snapshot();
    let q_after = Query::new(&after);
    // The box is [1,1] .. [2, n_L + 1) on both sides of the edit.
    let box_ = SpanSet::singleton(
        Span::from_endpoints(t(&[1, 1]), &t(&[2, 3])).expect("well-formed"),
    );
    assert_eq!(ok_of(q_before.doc_vspan(&doc1())), box_);
    assert_eq!(ok_of(q_after.doc_vspan(&doc1())), box_);
    // The extents are not: the content member follows n_C.
    let extents = |q: &Query<'_, World>| {
        ok_of(q.doc_vspanset(&doc1()))
            .iter()
            .next()
            .expect("occupied ⇒ a content extent")
            .clone()
    };
    assert_eq!(
        extents(&q_before),
        Span::new(t(&[1, 1]), t(&[0, 3])).expect("T12")
    );
    assert_eq!(
        extents(&q_after),
        Span::new(t(&[1, 1]), t(&[0, 2])).expect("T12")
    );
}

// ---- §C SHOWORIGIN (V-arity) ----

#[test]
fn show_origin_v_projects_deduplicated_origins_in_tumbler_order() {
    // ASN-0077 O2/O5: one origin per run (block uniformity), deduplicated,
    // tumbler-ordered; the link arity reports the home document (CL-OWN).
    let k = mem_kernel();
    three_runs(&k); // doc2 = [doc2_ca1][ca1, ca2][ca1]
    seat_link(&k, &doc2(), &doc2_la(1)).expect("seat commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    // Three runs, origins {doc2, doc1, doc1} → deduped, T1-sorted.
    assert_eq!(
        ok_of(q.show_origin_v(&doc2(), &vspan(1, 1, 4))),
        vec![doc1(), doc2()]
    );
    // A sub-span lying wholly in transcluded content names doc1 alone.
    assert_eq!(
        ok_of(q.show_origin_v(&doc2(), &vspan(1, 2, 2))),
        vec![doc1()]
    );
    // Link subspace: origin is the home document, uniformly.
    assert_eq!(
        ok_of(q.show_origin_v(&doc2(), &vspan(2, 1, 1))),
        vec![doc2()]
    );
}

#[test]
fn show_origin_v_projects_an_origin_at_whatever_depth_its_document_sits() {
    // ASN-0077 O2 through M1's `document_of`: the origin is the DOCUMENT
    // PREFIX of a run's I-start, at whatever depth that document sits. A
    // version fork is a document one component deeper than its source and
    // mints LENGTH-9 content elements, so a projection that assumed the
    // source's shape would name doc1 for content doc1 never allocated — and
    // every other origin case in this suite would still pass, all of them
    // being five-component documents over eight-component elements.
    let k = mem_kernel();
    let vs = insert3(&k);
    let (fork, _) = vs.version(PrincipalId(1), &doc1()).expect("fork commits");
    assert_eq!(fork, vdoc()); // one component deeper than its source…
    let (start, _) = vs
        .insert(P1, &fork, vp(1, 4), vec![val(b"z")])
        .expect("fork edit commits");
    assert_eq!(start, vca(1)); // …and its own chain one component longer
    let s = k.snapshot();
    let q = Query::new(&s);
    // The fork's own position: the origin is the FORK, never its source.
    assert_eq!(ok_of(q.show_origin_v(&fork, &vspan(1, 4, 1))), vec![vdoc()]);
    // The shared prefix alone names only the source.
    assert_eq!(ok_of(q.show_origin_v(&fork, &vspan(1, 1, 3))), vec![doc1()]);
    // Both runs: two origins at two depths, T1-ordered — and doc1 is a PREFIX
    // of vdoc, so the listing is the shorter-first rule rather than a
    // same-length comparison.
    assert_eq!(
        ok_of(q.show_origin_v(&fork, &vspan(1, 1, 4))),
        vec![doc1(), vdoc()]
    );
}

#[test]
fn show_origin_v_admits_the_exact_extent_and_rejects_one_position_past_it() {
    // ASN-0077 WF_V(vi): the test is `resolved < ordinal(width)`, so a span
    // covering the bound prefix EXACTLY is admissible and one position more
    // is rejected — never clamped to the surviving sub-span (O13). The equal
    // case and the overrun-by-one are the two sides of that inequality.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        ok_of(q.show_origin_v(&doc1(), &vspan(1, 1, 3))),
        vec![doc1()]
    );
    assert_eq!(
        ok_of(q.show_origin_v(&doc1(), &vspan(1, 3, 1))),
        vec![doc1()]
    );
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &vspan(1, 1, 4))),
        OriginError::RangeNotPresent
    ));
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &vspan(1, 3, 2))),
        OriginError::RangeNotPresent
    ));
}

#[test]
fn show_origin_v_rejects_each_inadmissible_case_distinctly() {
    // ASN-0077 WF_V(i–vi)/O13 — reject, never clamp; the checks run in the
    // documented order: registered → well-formed → subspace → empty →
    // depth → range.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    // (i) not registered — checked first, even with a malformed span.
    assert!(matches!(
        err_of(q.show_origin_v(&unregistered(), &vspan(1, 1, 1))),
        OriginError::DocNotRegistered
    ));
    assert!(matches!(
        err_of(q.show_origin_v(&unregistered(), &not_ordinal_level_span())),
        OriginError::DocNotRegistered
    ));
    // (ii/iv) malformed — before any subspace reading (a malformed span in
    // a foreign subspace is MalformedSpan, not NoSuchSubspace).
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &not_ordinal_level_span())),
        OriginError::MalformedSpan(SpanFault::NotOrdinalLevel)
    ));
    let foreign_malformed = Span::new(t(&[3, 1]), t(&[1, 0])).expect("T12-legal");
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &foreign_malformed)),
        OriginError::MalformedSpan(SpanFault::NotOrdinalLevel)
    ));
    // Foreign subspace ∉ {s_C, s_L} — distinct from a real-but-empty one,
    // and checked before empty/depth (a deep foreign span is still foreign).
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &vspan(3, 1, 1))),
        OriginError::NoSuchSubspace
    ));
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &deep_span(3))),
        OriginError::NoSuchSubspace
    ));
    // (iii) a real but EMPTY subspace: the link side of doc1 (no links) and
    // the content side of registered-empty doc2.
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &vspan(2, 1, 1))),
        OriginError::EmptySubspace
    ));
    assert!(matches!(
        err_of(q.show_origin_v(&doc2(), &vspan(1, 1, 1))),
        OriginError::EmptySubspace
    ));
    // Empty is checked BEFORE depth: a deep LINK span over link-less doc1 is
    // EmptySubspace, not DepthIncompatible.
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &deep_span(2))),
        OriginError::EmptySubspace
    ));
    // (v) depth-incompatible: well-formed #start = 3 over the occupied
    // content subspace — its own verdict, distinct from the range case.
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &deep_span(1))),
        OriginError::DepthIncompatible
    ));
    // (vi) a depth-2 span overrunning the bound prefix — partial resolution
    // is REJECTED, never clamped to the surviving sub-span (O13).
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &vspan(1, 2, 5))),
        OriginError::RangeNotPresent
    ));
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &vspan(1, 4, 1))),
        OriginError::RangeNotPresent
    ));
}

// ---- §D SHOWDELETIONS ----

#[test]
fn show_deletions_reports_the_existing_addresses_deleted_from_one_current_in_the_other() {
    // ASN-0075 D-IDENT: each half is a set of the EXISTING I-addresses
    // deleted-from-one ∧ current-in-the-other, listed deduplicated and
    // T1-ascending (M6's presentation); slot semantics follow the argument
    // order.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 2),
        }],
    )
    .expect("copy commits"); // doc2 = [ca1, ca2]
    vs.delete(P1, &doc1(), vp(1, 2), n(1)).expect("delete commits"); // doc1 = [ca1, ca3]; deleted ca2
    vs.delete(P1, &doc2(), vp(1, 1), n(1)).expect("delete commits"); // doc2 = [ca2]; deleted ca1
    let s = k.snapshot();
    let q = Query::new(&s);
    let got = ok_of(q.show_deletions(&doc1(), &doc2()));
    assert_eq!(
        got,
        Deletions {
            deleted_from_a_with_b: vec![ca(2)], // deleted from doc1, current in doc2
            deleted_from_b_with_a: vec![ca(1)], // deleted from doc2, current in doc1
        }
    );
    // Swapping the arguments swaps the halves.
    let got = ok_of(q.show_deletions(&doc2(), &doc1()));
    assert_eq!(
        got,
        Deletions {
            deleted_from_a_with_b: vec![ca(1)],
            deleted_from_b_with_a: vec![ca(2)],
        }
    );
}

#[test]
fn show_deletions_dedups_multiplicity_and_admits_empty_documents() {
    // ASN-0075: intra-document transclusion multiplicity collapses (sets,
    // not bags); registered-empty documents are admissible with empty halves;
    // an unregistered document is the typed failure (d_a checked first).
    let k = mem_kernel();
    {
        // Registered-but-empty on both sides ⇒ empty halves.
        let s = k.snapshot();
        let q = Query::new(&s);
        let got = ok_of(q.show_deletions(&doc1(), &doc2()));
        assert_eq!(
            got,
            Deletions {
                deleted_from_a_with_b: vec![],
                deleted_from_b_with_a: vec![],
            }
        );
        assert!(matches!(
            err_of(q.show_deletions(&unregistered(), &doc1())),
            DeletionsError::DocNotRegistered(d) if d == unregistered()
        ));
        assert!(matches!(
            err_of(q.show_deletions(&doc1(), &unregistered())),
            DeletionsError::DocNotRegistered(d) if d == unregistered()
        ));
    }
    let vs = insert3(&k);
    // doc2 holds ca1 TWICE; doc1 then deletes ca1.
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 1),
        }],
    )
    .expect("copy commits");
    vs.copy(
        P1,
        &doc2(),
        vp(1, 2),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 1),
        }],
    )
    .expect("copy commits");
    vs.delete(P1, &doc1(), vp(1, 1), n(1)).expect("delete commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    let got = ok_of(q.show_deletions(&doc1(), &doc2()));
    // ca1 appears ONCE despite doc2's double placement (dedup — the halves
    // are set comprehensions).
    assert_eq!(
        got,
        Deletions {
            deleted_from_a_with_b: vec![ca(1)],
            deleted_from_b_with_a: vec![],
        }
    );
}

#[test]
fn show_deletions_orders_a_multi_address_half_by_tumbler_not_by_arrangement() {
    // A half is the whole set, listed T1-ascending — never the order the
    // containing document happens to arrange it in, which is D-ORD's own
    // clause that the operation takes no input ordering to preserve; the
    // T1 listing itself is M6's presentation. doc2 holds ca2 BEFORE ca1
    // after the rearrange, so arrangement order and T1 order disagree and
    // only one of them is the documented answer.
    let k = mem_kernel();
    let vs = insert3(&k); // doc1 = [ca1, ca2, ca3]
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 2),
        }],
    )
    .expect("copy commits"); // doc2 = [ca1, ca2]
    vs.rearrange(P1, &doc2(), &[vp(1, 1), vp(1, 2), vp(1, 3)])
        .expect("rearrange commits"); // doc2 = [ca2, ca1]
    vs.delete(P1, &doc1(), vp(1, 1), n(3))
        .expect("delete commits"); // doc1 drops all three
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        ok_of(q.show_deletions(&doc1(), &doc2())),
        Deletions {
            // Enumerated from doc2 as [ca2, ca1] and returned SORTED; ca3 is
            // deleted from doc1 but not current in doc2, so it is no member.
            deleted_from_a_with_b: vec![ca(1), ca(2)],
            deleted_from_b_with_a: vec![],
        }
    );
}

#[test]
fn show_deletions_names_the_first_unregistered_document() {
    // §Errors: both documents must be registered and `d_a` is checked FIRST,
    // so the rejection names the argument POSITION, not whichever address
    // happens to be looked at first.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        err_of(q.show_deletions(&unregistered(), &unregistered2())),
        DeletionsError::DocNotRegistered(unregistered())
    );
    assert_eq!(
        err_of(q.show_deletions(&unregistered2(), &unregistered())),
        DeletionsError::DocNotRegistered(unregistered2())
    );
}

// ---- §D COMPARE ----

#[test]
fn compare_reports_address_equal_correspondences_with_per_block_feet() {
    // ASN-0122 X12 R1 (soundness): each foot is computed WITHIN its own
    // block — u1 offsets the P block, u2 the Q block — so both feet resolve
    // to the shared address; slot 1 ⇐ ρ₁, slot 2 ⇐ ρ₂.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 2, 1),
        }],
    )
    .expect("copy commits"); // doc2 = [ca2]
    let s = k.snapshot();
    let q = Query::new(&s);
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 1)])],
    ));
    assert_eq!(rep.0.len(), 1);
    let p = &rep.0[0];
    assert_eq!(p.d1, doc1());
    assert_eq!(p.u1.subspace, n(1));
    assert_eq!(p.u1.ordinal, n(2)); // ca2 is offset 1 within doc1's block
    assert_eq!(p.d2, doc2());
    assert_eq!(p.u2.subspace, n(1));
    assert_eq!(p.u2.ordinal, n(1)); // ca2 is offset 0 within doc2's block
    assert_eq!(p.width, n(1));
    // Swapped operands swap the slots.
    let rep = ok_of(q.compare(
        &[region_spec(doc2(), vec![vspan(1, 1, 1)])],
        &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
    ));
    assert_eq!(rep.0.len(), 1);
    let p = &rep.0[0];
    assert_eq!(p.d1, doc2());
    assert_eq!(p.u1.ordinal, n(1));
    assert_eq!(p.d2, doc1());
    assert_eq!(p.u2.ordinal, n(2));
}

#[test]
fn compare_reports_the_full_width_of_each_overlap() {
    // ASN-0122 X10: a correspondence carries the WIDTH of the shared run, and
    // the width is the NARROWER operand's — the half-open clamp
    // `hi = min(p_reach, q_reach)`, exercised from each side in turn.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 3),
        }],
    )
    .expect("copy commits"); // doc2 = [ca1, ca2, ca3], one run
    let s = k.snapshot();
    let q = Query::new(&s);
    for (w1, w2, want) in [(3u32, 3u32, 3u32), (3, 2, 2), (2, 3, 2)] {
        let rep = ok_of(q.compare(
            &[region_spec(doc1(), vec![vspan(1, 1, w1)])],
            &[region_spec(doc2(), vec![vspan(1, 1, w2)])],
        ));
        assert_eq!(rep.len(), 1, "one overlap for widths ({w1}, {w2})");
        let p = &rep.as_slice()[0];
        assert_eq!(p.width, n(want), "width of the ({w1}, {w2}) overlap");
        assert_eq!(p.u1.ordinal, n(1));
        assert_eq!(p.u2.ordinal, n(1));
    }
}

#[test]
fn compare_takes_each_blocks_v_start_from_the_span_that_named_it() {
    // ASN-0122 X12 R1 soundness rests on the V-RECONSTRUCTION LEMMA: a
    // content span's FIRST bound V-position is `span.start()`, so a block's
    // V-cursor begins there and not at the subspace origin. A window opened
    // MID-document is the only input that can tell the two apart.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 3, 1),
        }],
    )
    .expect("copy commits"); // doc2 = [ca3]
    let s = k.snapshot();
    let q = Query::new(&s);
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 2, 2)])], // doc1 positions 2..3
        &[region_spec(doc2(), vec![vspan(1, 1, 1)])],
    ));
    assert_eq!(rep.len(), 1);
    let p = &rep.as_slice()[0];
    assert_eq!(p.u1.ordinal, n(3)); // ca3 IS doc1's THIRD position, not its first
    assert_eq!(p.u2.ordinal, n(1));
    assert_eq!(p.width, n(1));
}

#[test]
fn compare_presents_pairs_in_lexicographic_d1_u1_d2_u2_order() {
    // ASN-0122 X12 R3: the presentation is the FOUR-component lexicographic
    // key. The operand below is listed in exactly the reverse of the
    // presentation, and the pairs differ in `d1` and in `u1` as well as in
    // the tail, so no proper prefix of the key reproduces the answer.
    let k = mem_kernel();
    three_runs(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    let rep = ok_of(q.compare(
        &[
            region_spec(doc2(), vec![vspan(1, 4, 1), vspan(1, 2, 1)]), // emitted 1st, 2nd
            region_spec(doc1(), vec![vspan(1, 2, 1)]),                 // emitted 3rd
        ],
        &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
    ));
    // Emission order is (doc2,4), (doc2,2), (doc1,2); the presentation is not.
    let got: Vec<(Address, Nat)> = rep
        .iter()
        .map(|c| (c.d1.clone(), c.u1.ordinal.clone()))
        .collect();
    assert_eq!(got, vec![(doc1(), n(2)), (doc2(), n(2)), (doc2(), n(4))]);
}

#[test]
fn compare_orders_pairs_that_share_a_first_foot_by_their_second() {
    // ASN-0122 X12 R3, on the half of the key X11's strictness clause exists
    // for: under FAN-OUT several chains land on ONE first foot, so pairs that
    // share `(d1, u1)` are separated only by `(d2, u2)` — a presentation keyed
    // on the first foot alone would leave a fanned-out report's order
    // undetermined. Every pair below shares its first foot, so nothing but the
    // TAIL can explain the order.
    //
    // The fixture is what makes each tail component answerable. doc2 holds ca1
    // at V1 and V2 and doc1 holds it at V1, so the doc1-sourced pair TIES the
    // doc2 pair on `u2` and is separated by `d2` alone, while the two doc2
    // pairs tie on `d2` and are separated by `u2` alone. (A fixture where the
    // doc1 pair's `u2` were uniquely smallest could not tell `d2` from `u2`.)
    let k = mem_kernel();
    fanout_doc2(&k); // doc1 = [a, b, c]; doc2 = [ca1][ca1][own "a"]
    let s = k.snapshot();
    let q = Query::new(&s);
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 1)])], // ca1 — ONE first foot
        &[
            region_spec(doc2(), vec![vspan(1, 2, 1), vspan(1, 1, 1)]), // emitted 1st, 2nd
            region_spec(doc1(), vec![vspan(1, 1, 1)]),                 // emitted 3rd
        ],
    ));
    assert!(
        rep.iter()
            .all(|c| c.d1 == doc1() && c.u1 == vp(1, 1) && c.width == n(1)),
        "the premise: one shared first foot, so only the tail can order these"
    );
    // Emitted (doc2,2), (doc2,1), (doc1,1) — the exact reverse of the
    // presentation, which is `d2` ascending and then `u2` ascending.
    let got: Vec<(Address, Nat)> = rep
        .iter()
        .map(|c| (c.d2.clone(), c.u2.ordinal.clone()))
        .collect();
    assert_eq!(got, vec![(doc1(), n(1)), (doc2(), n(1)), (doc2(), n(2))]);
}

#[test]
fn compare_confines_every_pair_to_the_two_named_regions() {
    // ASN-0122 X12 R1: pairs are confined to R_Σ(ρ₁) × R_Σ(ρ₂) — the WINDOW
    // is the operand, not the document. An address the two documents share is
    // reported only when BOTH windows name it.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 2),
        }],
    )
    .expect("copy commits"); // doc2 = [ca1, ca2]
    let s = k.snapshot();
    let q = Query::new(&s);
    // ρ₁ names ca3, which doc2 does not hold at all.
    assert!(ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 3, 1)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 2)])],
    ))
    .is_empty());
    // Both documents hold ca1 and ca2, but the two windows name different ones.
    assert!(ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 1)])],
        &[region_spec(doc2(), vec![vspan(1, 2, 1)])],
    ))
    .is_empty());
    // The control: widen ρ₂ to cover ca1 and the pair appears.
    assert_eq!(
        ok_of(q.compare(
            &[region_spec(doc1(), vec![vspan(1, 1, 1)])],
            &[region_spec(doc2(), vec![vspan(1, 1, 2)])],
        ))
        .len(),
        1
    );
}

#[test]
fn compare_is_complete_under_fanout() {
    // ASN-0122 X12 R2, over `corr`'s `P × Q` comprehension: an address held
    // in several blocks yields the FULL cross-product — never a lockstep
    // merge.
    let k = mem_kernel();
    fanout_doc2(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    // One P block, two Q blocks holding the same address ⇒ 2 pairs,
    // presented in ascending u2 order.
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 1)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 2)])],
    ));
    assert_eq!(rep.len(), 2);
    assert_eq!(rep.as_slice()[0].u2.ordinal, n(1));
    assert_eq!(rep.as_slice()[1].u2.ordinal, n(2));
}

#[test]
fn compare_joins_on_address_equality_never_on_value() {
    // ASN-0122 X1/X2: the join is a relational equi-join on I-ADDRESS, so
    // equal bytes at distinct addresses do NOT correspond — and COMPARE never
    // opens M4 to find out.
    let k = mem_kernel();
    fanout_doc2(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    // The fixture's premise, which is what makes the claim below say
    // anything: doc2's third position is its OWN address, and the bytes there
    // are byte-for-byte doc1's ca1.
    assert_eq!(s.world().m5().point(&doc2(), &vp(1, 3)), Some(doc2_ca(1)));
    assert_ne!(doc2_ca(1), ca(1));
    assert_eq!(
        ok_of(q.retrieve_v(&[spec(doc2(), vspan(1, 3, 1)), spec(doc1(), vspan(1, 1, 1))])),
        Delivery(vec![
            DeliveryItem::Content(val(b"a")),
            DeliveryItem::Content(val(b"a")),
        ])
    );
    // Equal bytes, distinct addresses — and no pair follows.
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
        &[region_spec(doc2(), vec![vspan(1, 3, 1)])],
    ));
    assert!(rep.is_empty());
}

#[test]
fn compare_lists_a_repeated_window_of_one_operand_twice() {
    // ASN-0122: ⟦Γ⟧ is a set-union, so a repeated window within one operand
    // is redundant rather than wrong — it double-covers, and the report lists
    // both overlaps (denotationally conforming, deterministically ordered).
    let k = mem_kernel();
    fanout_doc2(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 1), vspan(1, 1, 1)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 1)])],
    ));
    assert_eq!(rep.len(), 2);
}

#[test]
fn compare_lists_two_pairs_that_share_a_presentation_key_in_emission_order() {
    // Two NESTED windows of ρ₁ resolve to two blocks with ONE V-start, so
    // their pairs share ALL FOUR key components and differ only in `width`,
    // which is not in the key. Both are reported (the report is
    // finer-than-maximal, and `fold_adjacent` is the identity), each carries
    // its own window's width, and the tie is broken by emission order — the
    // wider window was submitted first.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 3),
        }],
    )
    .expect("copy commits"); // doc2 = [ca1, ca2, ca3], ONE run
    let s = k.snapshot();
    let q = Query::new(&s);
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 3), vspan(1, 1, 2)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 3)])],
    ));
    let key = |c: &CorrPair| (c.d1.clone(), c.u1.clone(), c.d2.clone(), c.u2.clone());
    assert_eq!(rep.len(), 2);
    assert_eq!(key(&rep.as_slice()[0]), key(&rep.as_slice()[1]));
    assert_eq!(
        rep.iter().map(|c| c.width.clone()).collect::<Vec<_>>(),
        vec![n(3), n(2)]
    );
}

#[test]
fn compare_succeeds_emptily_on_empty_operands_and_depth_incompatible_regions() {
    // ASN-0122 X12: consulting-state degradations are SUCCESSES with nothing
    // to report — an empty spec-set, and a well-formed depth-incompatible
    // span that clips to nothing.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    assert!(ok_of(q.compare(&[], &[])).is_empty());
    assert!(ok_of(q.compare(
        &[region_spec(doc1(), vec![deep_span(1)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 2)])],
    ))
    .is_empty());
}

/// The per-position `(doc, subspace, ordinal, I-address)` triples a spec-set
/// resolves to, read straight off M5 — the independent oracle COMPARE's join
/// is checked against, computed without consulting anything M6 does.
///
/// REQUIRES depth-2 ordinal-level spans, which is what the one test that
/// calls it hands over: `get(2)` is the ordinal only at that depth.
fn positions(w: &World, regions: &[RegionSpec]) -> Vec<(Address, Nat, Nat, Address)> {
    let mut out = Vec::new();
    for r in regions {
        for span in &r.spans {
            let sub = span.start().get(1).expect("depth 2").clone();
            let from = span.start().get(2).expect("depth 2").clone();
            let end = &from + span.width().get(2).expect("ordinal-level");
            let mut ordinal = from;
            while ordinal < end {
                let p = VPos {
                    subspace: sub.clone(),
                    ordinal: ordinal.clone(),
                };
                if let Some(addr) = w.m5().point(&r.doc, &p) {
                    out.push((r.doc.clone(), sub.clone(), ordinal.clone(), addr));
                }
                ordinal += n(1);
            }
        }
    }
    out
}

/// The position pairs a report denotes: a pair of width `w` is `w` consecutive
/// position pairs on both feet (ASN-0122 X10), so this is the same currency as
/// [`positions`] and the two compare directly. Sorted, so two of these compare
/// as MULTISETS and fan-out multiplicity is checked too.
fn position_pairs(rep: &CompareReport) -> Vec<(Address, Nat, Nat, Address, Nat, Nat)> {
    let mut out = Vec::new();
    for c in rep.iter() {
        let mut offset = n(0);
        while offset < c.width {
            out.push((
                c.d1.clone(),
                c.u1.subspace.clone(),
                &c.u1.ordinal + &offset,
                c.d2.clone(),
                c.u2.subspace.clone(),
                &c.u2.ordinal + &offset,
            ));
            offset += n(1);
        }
    }
    out.sort();
    out
}

#[test]
fn compare_reports_exactly_the_address_equal_position_pairs() {
    // ASN-0122 X12 R2 (completeness) and R1 (soundness) — which R2 states
    // jointly give `⟦Γ⟧ = corr` — say the report IS the set of address-equal
    // position pairs of the two regions: a law over the whole space, not four
    // hand-picked counts. The oracle is a per-position hash join computed
    // from M5 alone, so it shares no reasoning with the block join it checks.
    let k = mem_kernel();
    three_runs(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    let oracle = |rho1: &[RegionSpec], rho2: &[RegionSpec]| {
        let (p, q) = (positions(s.world(), rho1), positions(s.world(), rho2));
        let mut out = Vec::new();
        for (d1, s1, o1, a1) in &p {
            for (d2, s2, o2, a2) in &q {
                if a1 == a2 {
                    out.push((
                        d1.clone(),
                        s1.clone(),
                        o1.clone(),
                        d2.clone(),
                        s2.clone(),
                        o2.clone(),
                    ));
                }
            }
        }
        out.sort();
        out
    };
    for (rho1, rho2, want_pairs) in [
        // Whole against whole: three position pairs, from a report of two
        // pairs — one candidate block being doc2's own content, on a chain
        // doc1 never touches.
        (
            vec![region_spec(doc2(), vec![vspan(1, 1, 4)])],
            vec![region_spec(doc1(), vec![vspan(1, 1, 3)])],
            3usize,
        ),
        // Windowed: one position pair, from a report whose second candidate
        // block is disjoint.
        (
            vec![region_spec(doc2(), vec![vspan(1, 2, 3)])],
            vec![region_spec(doc1(), vec![vspan(1, 2, 2)])],
            1,
        ),
    ] {
        let rep = ok_of(q.compare(&rho1, &rho2));
        let want = oracle(&rho1, &rho2);
        assert_eq!(want.len(), want_pairs, "the oracle's own size");
        assert_eq!(
            position_pairs(&rep),
            want,
            "report over {rho1:?} × {rho2:?}"
        );
    }
}

#[test]
fn compare_rejects_with_operand_region_index_attribution() {
    // ASN-0122 precondition: registered docs, content-subspace starts,
    // well-formed spans — each span fault localized by (operand, region,
    // index); the subspace residence check runs BEFORE the well-formedness
    // gate.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    assert!(matches!(
        err_of(q.compare(&[region_spec(unregistered(), vec![vspan(1, 1, 1)])], &[])),
        CompareError::DocNotRegistered(d) if d == unregistered()
    ));
    assert!(matches!(
        err_of(q.compare(
            &[region_spec(doc1(), vec![vspan(1, 1, 1)])],
            &[region_spec(doc1(), vec![vspan(2, 1, 1)])],
        )),
        CompareError::NotContentSubspace {
            operand: Operand::Second,
            region: 0,
            index: 0
        }
    ));
    assert!(matches!(
        err_of(q.compare(
            &[region_spec(
                doc1(),
                vec![vspan(1, 1, 1), not_ordinal_level_span()]
            )],
            &[region_spec(doc1(), vec![vspan(1, 1, 1)])],
        )),
        CompareError::MalformedSpan {
            operand: Operand::First,
            region: 0,
            index: 1,
            fault: SpanFault::NotOrdinalLevel
        }
    ));
    // A link-START span that is ALSO malformed: subspace residence wins.
    let link_malformed = Span::new(t(&[2, 1]), t(&[1, 0])).expect("T12-legal");
    assert!(matches!(
        err_of(q.compare(&[region_spec(doc1(), vec![link_malformed])], &[])),
        CompareError::NotContentSubspace {
            operand: Operand::First,
            region: 0,
            index: 0
        }
    ));
    // Position 1 IS the subspace at any start depth (Tumbler indexing is
    // 1-based and #start ≥ 1 always), so residence is decidable for every
    // span the gate loop sees, including a one-component start.
    let shallow_foreign = Span::new(t(&[5]), t(&[1])).expect("T12-legal");
    assert!(matches!(
        err_of(q.compare(&[region_spec(doc1(), vec![shallow_foreign])], &[])),
        CompareError::NotContentSubspace {
            operand: Operand::First,
            region: 0,
            index: 0
        }
    ));
    let shallow_content = Span::new(t(&[1]), t(&[1])).expect("T12-legal");
    assert!(matches!(
        err_of(q.compare(&[region_spec(doc1(), vec![shallow_content])], &[])),
        CompareError::MalformedSpan {
            operand: Operand::First,
            region: 0,
            index: 0,
            fault: SpanFault::StartTooShallow
        }
    ));
    // All three coordinates off zero at once: the SECOND span of the SECOND
    // region of the SECOND operand. Every other case here sits at region 0, so
    // nothing else can tell `region` from a constant — or from `index`, which
    // would be 2 if the span count ran globally rather than per region.
    assert!(matches!(
        err_of(q.compare(
            &[region_spec(doc1(), vec![vspan(1, 1, 1)])],
            &[
                region_spec(doc1(), vec![vspan(1, 1, 1)]),
                region_spec(doc1(), vec![vspan(1, 1, 1), not_ordinal_level_span()]),
            ],
        )),
        CompareError::MalformedSpan {
            operand: Operand::Second,
            region: 1,
            index: 1,
            fault: SpanFault::NotOrdinalLevel
        }
    ));
}

#[test]
fn compare_refuses_an_operand_past_its_block_budget() {
    // The join is |P|·|Q| and BOTH factors are the request's: a region names
    // a span list and a spec-set names a region list, each capped separately
    // upstream, so their product is capped by nothing upstream. Each operand
    // is refused on its own, and the refusal names WHICH — a client cannot
    // narrow the operand it was not told about.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    let one = || vec![region_spec(doc1(), vec![vspan(1, 1, 1)])];
    let over = vec![region_spec(
        doc1(),
        vec![vspan(1, 1, 1); MAX_COMPARE_OPERAND_BLOCKS + 1],
    )];
    assert_eq!(
        err_of(q.compare(&over, &one())),
        CompareError::TooManyBlocks {
            operand: Operand::First
        }
    );
    assert_eq!(
        err_of(q.compare(&one(), &over)),
        CompareError::TooManyBlocks {
            operand: Operand::Second
        }
    );
    // Both over budget: ρ₁ is resolved FIRST, so ρ₁ is the operand named —
    // the one request that can tell the two resolution orders apart, since
    // either order answers the two above identically.
    assert_eq!(
        err_of(q.compare(&over, &over)),
        CompareError::TooManyBlocks {
            operand: Operand::First
        }
    );
    // The cap refuses only what is PAST it, and refuses the request WHOLE:
    // at the budget the same shape still answers, and answers completely
    // (one pair per block — a truncating cap would answer with fewer and
    // break X12 R2).
    let at = vec![region_spec(
        doc1(),
        vec![vspan(1, 1, 1); MAX_COMPARE_OPERAND_BLOCKS],
    )];
    assert_eq!(
        ok_of(q.compare(&at, &one())).len(),
        MAX_COMPARE_OPERAND_BLOCKS
    );
    // The refusal says which budget and how large it is, so a client sizing
    // its next request reads the number rather than guessing it.
    let e = err_of(q.compare(&over, &one()));
    assert!(e
        .to_string()
        .contains(&MAX_COMPARE_OPERAND_BLOCKS.to_string()));
}

#[test]
fn compare_counts_blocks_and_not_spans_against_the_operand_budget() {
    // The budget's own card: beyond M10's per-array wire cap it refuses "the
    // multi-run expansion, where one span over a fragmented document resolves
    // to many blocks from a single wire element". doc2 resolves to THREE runs,
    // so the two operands below are `MAX/3` and `MAX/3 + 1` SPANS — both far
    // under any span cap — and `MAX - (MAX mod 3)` and three more BLOCKS,
    // which is the only unit that explains one being answered and the other
    // refused.
    let k = mem_kernel();
    three_runs(&k); // doc2 = [doc2_ca1][ca1, ca2][ca1] — three runs
    let s = k.snapshot();
    let q = Query::new(&s);
    let one = vec![region_spec(doc1(), vec![vspan(1, 1, 1)])];
    let spans = |count: usize| vec![region_spec(doc2(), vec![vspan(1, 1, 4); count])];
    let under = MAX_COMPARE_OPERAND_BLOCKS / 3;
    // Two of doc2's three runs hold ca1 (the third is its own content, on a
    // chain doc1 never touches), so the admitted operand reports the full
    // cross-product and is not merely "not refused".
    assert_eq!(ok_of(q.compare(&spans(under), &one)).len(), 2 * under);
    assert_eq!(
        err_of(q.compare(&spans(under + 1), &one)),
        CompareError::TooManyBlocks {
            operand: Operand::First
        }
    );
}

#[test]
fn compare_refuses_a_fanout_past_its_pair_budget() {
    // 257 × 257 = 66,049 pairs from 514 blocks — an operand count the block
    // budget admits many times over. Fan-out is bounded ONLY by counting the
    // pairs as they are produced, which is why the second budget exists and
    // why the first cannot stand in for it.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    let side = |count: usize| vec![region_spec(doc1(), vec![vspan(1, 1, 1); count])];
    let e = err_of(q.compare(&side(257), &side(257)));
    assert_eq!(e, CompareError::TooManyPairs);
    // The refusal names its own budget, as the block refusal does, so a client
    // narrows against the number rather than guessing it.
    assert!(e.to_string().contains(&MAX_COMPARE_PAIRS.to_string()));
    // Under the budget, the same shape reports the FULL cross-product
    // (X12 R2): the cap refuses, and never thins a report it admits.
    assert_eq!(ok_of(q.compare(&side(16), &side(16))).len(), 256);
    // The EQUAL case, where the two budgets must agree: a report of exactly
    // the budget is answered and only the pair PAST it refused. The premise is
    // asserted, so a change to the constant fails here rather than silently
    // leaving this an interior point.
    assert_eq!(256 * 256, MAX_COMPARE_PAIRS, "256 × 256 IS the boundary");
    assert_eq!(
        ok_of(q.compare(&side(256), &side(256))).len(),
        MAX_COMPARE_PAIRS
    );
}

#[test]
fn compare_gates_both_operands_whole_before_either_budget_can_refuse() {
    // §COMPARE, which refusal speaks: both operands are gated in FULL before
    // either is resolved, so a SHAPE fault always outranks a SIZE refusal. An
    // over-budget ρ₁ beside a malformed ρ₂ span reports the span — telling a
    // client that ρ₂ was examined too, which is the promise `TooManyBlocks`
    // rests on.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    let over = vec![region_spec(
        doc1(),
        vec![vspan(1, 1, 1); MAX_COMPARE_OPERAND_BLOCKS + 1],
    )];
    assert_eq!(
        err_of(q.compare(
            &over,
            &[region_spec(doc1(), vec![not_ordinal_level_span()])],
        )),
        CompareError::MalformedSpan {
            operand: Operand::Second,
            region: 0,
            index: 0,
            fault: SpanFault::NotOrdinalLevel,
        }
    );
    // The control: with ρ₂ well-formed, the same ρ₁ is refused for its size.
    assert_eq!(
        err_of(q.compare(&over, &[region_spec(doc1(), vec![vspan(1, 1, 1)])])),
        CompareError::TooManyBlocks {
            operand: Operand::First
        }
    );
}

// ---- §E FINDDOCSCONTAINING ----

#[test]
fn find_docs_containing_filters_to_present_tense_containers() {
    // ASN-0124 FD-SOUND: docs_ever_containing's historical superset is
    // narrowed by the project filter to CURRENT holders; the raw union may
    // be mixed-length (M5 owns the level-class discipline); bare identities,
    // tumbler-ordered.
    let k = mem_kernel();
    let vs = insert3(&k);
    let (fork, _) = vs.version(PrincipalId(1), &doc1()).expect("fork commits");
    assert_eq!(fork, vdoc()); // shares ca1..ca3
    let (start, _) = vs
        .insert(P1, &fork, vp(1, 4), vec![val(b"z")])
        .expect("fork edit commits");
    assert_eq!(start, vca(1)); // the fork's chain mints LENGTH-9 elements
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[
            VSpec {
                source: doc1(),
                span: vspan(1, 1, 1),
            },
            VSpec {
                source: fork.clone(),
                span: vspan(1, 4, 1),
            },
        ],
    )
    .expect("mixed copy commits"); // doc2 = [ca1, vca1]
    {
        let s = k.snapshot();
        let q = Query::new(&s);
        // Mixed-length coverage {[ca1,ca2), [vca1,vca2)} passes raw through
        // M6; all three docs currently hold some of it.
        assert_eq!(
            ok_of(q.find_docs_containing(&[region_spec(doc2(), vec![vspan(1, 1, 2)])])),
            vec![doc1(), vdoc(), doc2()]
        );
    }
    // doc1 drops ca1 — it stays an R-candidate (permanence) but the
    // present-tense filter removes it.
    vs.delete(P1, &doc1(), vp(1, 1), n(1)).expect("delete commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        ok_of(q.find_docs_containing(&[region_spec(doc2(), vec![vspan(1, 1, 2)])])),
        vec![vdoc(), doc2()]
    );
    // A depth-incompatible span contributes nothing — never a rejection.
    assert_eq!(
        ok_of(q.find_docs_containing(&[
            region_spec(doc1(), vec![deep_span(1)]),
            region_spec(doc2(), vec![vspan(1, 1, 2)]),
        ])),
        vec![vdoc(), doc2()]
    );
    // A link-subspace span passes the gate and stays inert: link placement
    // is R-uncoupled (J-LV), so it can add no spurious container.
    seat_link(&k, &doc1(), &la(1)).expect("seat commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        ok_of(q.find_docs_containing(&[region_spec(doc1(), vec![vspan(2, 1, 1)])])),
        Vec::<Address>::new()
    );
}

#[test]
fn find_docs_containing_unions_every_span_of_a_region() {
    // ASN-0124 FD-CONVEX/FD-COMPLETE: a region carries a SET of spans and
    // phase 1 unions every one of their images. Answering from the first span
    // alone would silently under-resolve and drop containers, which is the
    // hazard the operation names.
    let k = mem_kernel();
    three_runs(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    // Span 0 covers doc2's OWN content (doc2 alone holds it); span 1 covers
    // ca1, which doc1 holds too. Only the union names both containers.
    assert_eq!(
        ok_of(q.find_docs_containing(&[region_spec(doc2(), vec![vspan(1, 1, 1), vspan(1, 2, 1)])])),
        vec![doc1(), doc2()]
    );
    // The control that makes the line above mean something: the first span's
    // coverage alone names doc2 and nobody else.
    assert_eq!(
        ok_of(q.find_docs_containing(&[region_spec(doc2(), vec![vspan(1, 1, 1)])])),
        vec![doc2()]
    );
    // An empty request names no coverage and finds nothing.
    assert_eq!(ok_of(q.find_docs_containing(&[])), Vec::<Address>::new());
}

#[test]
fn find_docs_containing_rejects_unregistered_and_malformed_regions() {
    // ASN-0124 FD-COMPLETE: a malformed span is a typed rejection with
    // (region, index) attribution — never a silent under-resolution; a
    // registered-empty region contributes nothing.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    assert!(matches!(
        err_of(q.find_docs_containing(&[region_spec(unregistered(), vec![vspan(1, 1, 1)])])),
        FindError::DocNotRegistered(d) if d == unregistered()
    ));
    let zeroed = Span::new(t(&[1, 0, 1]), t(&[0, 0, 1])).expect("T12-legal");
    assert!(matches!(
        err_of(q.find_docs_containing(&[region_spec(doc1(), vec![vspan(1, 1, 1), zeroed])])),
        FindError::MalformedSpan {
            region: 0,
            index: 1,
            fault: SpanFault::StartNotZeroFree
        }
    ));
    assert!(matches!(
        err_of(q.find_docs_containing(&[
            region_spec(doc1(), vec![vspan(1, 1, 1)]),
            region_spec(doc1(), vec![not_ordinal_level_span()]),
        ])),
        FindError::MalformedSpan {
            region: 1,
            index: 0,
            fault: SpanFault::NotOrdinalLevel
        }
    ));
    // Registered-but-empty doc2: nothing resolves, nothing contains.
    assert_eq!(
        ok_of(q.find_docs_containing(&[region_spec(doc2(), vec![vspan(1, 1, 1)])])),
        Vec::<Address>::new()
    );
}

// ---- derive policy (the marshaling seam) ----

#[test]
fn results_and_errors_marshal_through_serialize_per_the_derive_policy() {
    // §Public interface derive policy: results/errors are Serialize (M10
    // marshals them; bincode is M2's actual wire format); CorrPair/
    // CompareReport are not — they carry M5's VPos — and marshal
    // FIELD-BY-FIELD, every leaf serializing individually, VPos's Nat fields
    // included.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 2),
        }],
    )
    .expect("copy commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    let delivery = ok_of(q.retrieve_v(&[spec(doc1(), vspan(1, 1, 3))]));
    assert!(!bincode::serialize(&delivery).expect("Delivery serializes").is_empty());
    let extent = ok_of(q.doc_vspan(&doc1()));
    assert!(!bincode::serialize(&extent).expect("SpanSet serializes").is_empty());
    let dels = ok_of(q.show_deletions(&doc1(), &doc2()));
    assert!(!bincode::serialize(&dels).expect("Deletions serializes").is_empty());
    let e = err_of(q.retrieve_v(&[spec(unregistered(), vspan(1, 1, 1))]));
    assert!(!bincode::serialize(&e).expect("RetrieveError serializes").is_empty());
    assert!(!bincode::serialize(&SpanFault::NotOrdinalLevel)
        .expect("SpanFault serializes")
        .is_empty());
    assert!(!bincode::serialize(&Operand::First)
        .expect("Operand serializes")
        .is_empty());
    // Request types serialize too (all-pub-field values).
    assert!(!bincode::serialize(&spec(doc1(), vspan(1, 1, 1)))
        .expect("Spec serializes")
        .is_empty());
    let rspec = region_spec(doc1(), vec![vspan(1, 1, 1)]);
    assert!(!bincode::serialize(&rspec)
        .expect("RegionSpec serializes")
        .is_empty());
    // CorrPair: field-by-field marshaling (no whole-value Serialize).
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 2)])],
    ));
    assert_eq!(rep.0.len(), 1);
    let p = &rep.0[0];
    assert!(!bincode::serialize(&p.d1).expect("Address serializes").is_empty());
    assert!(!bincode::serialize(&p.u1.subspace).expect("Nat serializes").is_empty());
    assert!(!bincode::serialize(&p.u1.ordinal).expect("Nat serializes").is_empty());
    assert!(!bincode::serialize(&p.d2).expect("Address serializes").is_empty());
    assert!(!bincode::serialize(&p.width).expect("Nat serializes").is_empty());
    // Withholding Serialize is not withholding everything else: a consumer
    // can clone a report, compare two of them, and print one in a failure
    // message. `assert_eq!` on M6's results and errors compiles from a
    // foreign crate, the delivery path included.
    assert_eq!(rep.clone(), rep);
    assert_eq!(
        dels,
        Deletions {
            deleted_from_a_with_b: vec![],
            deleted_from_b_with_a: vec![]
        }
    );
    assert_eq!(err_of(q.doc_vspan(&unregistered())), ExtentError::DocNotRegistered);
    assert_eq!(format!("{:?}", Operand::Second), "Second");
    assert!(!format!("{rep:?}").is_empty());
    // A delivery renders its content items by BYTE LENGTH and never by
    // payload — M4's discipline on `Val`, absorbed here rather than exported
    // to every caller that would log or diff a delivery.
    assert_eq!(
        format!("{delivery:?}"),
        "Delivery([Content(1 bytes), Content(1 bytes), Content(1 bytes)])"
    );
    assert_eq!(
        format!("{:?}", DeliveryItem::Content(val(b"hello"))),
        "Content(5 bytes)"
    );
    assert_eq!(
        format!("{:?}", DeliveryItem::Ref(la(1))),
        format!("Ref({})", la(1))
    );
    // A rendered delivery names no byte it carries.
    assert!(!format!("{:?}", DeliveryItem::Content(val(b"secret"))).contains("secret"));
    // The registry rejection names the offending document, in M1's dotted
    // decimal — the payload the variant carries, not discarded by Display.
    assert!(format!("{e}").contains(&unregistered().to_string()));
}

#[test]
fn every_rejection_is_a_std_error() {
    // §Errors: a foreign caller boxes an M6 rejection like any other error in
    // the workspace — the shape `?` into a `Box<dyn Error>` and anyhow need,
    // and one the orphan rule would forbid the caller from supplying. Each is
    // a LEAF: no variant wraps another error, so none has a source.
    fn boxed(
        e: impl std::error::Error + Send + Sync + 'static,
    ) -> Box<dyn std::error::Error + Send + Sync> {
        assert!(e.source().is_none(), "M6 rejections are leaves");
        Box::new(e)
    }
    assert!(!boxed(ExtentError::DocNotRegistered).to_string().is_empty());
    assert!(!boxed(RetrieveError::MalformedSpec {
        index: 0,
        fault: SpanFault::StartTooShallow,
    })
    .to_string()
    .is_empty());
    assert!(
        !boxed(OriginError::MalformedSpan(SpanFault::NotLevelUniform))
            .to_string()
            .is_empty()
    );
    // A boxed rejection still renders the document its variant carries.
    assert!(boxed(DeletionsError::DocNotRegistered(unregistered()))
        .to_string()
        .contains(&unregistered().to_string()));
    assert!(!boxed(CompareError::NotContentSubspace {
        operand: Operand::First,
        region: 0,
        index: 0,
    })
    .to_string()
    .is_empty());
    assert!(!boxed(FindError::MalformedSpan {
        region: 0,
        index: 0,
        fault: SpanFault::NotOrdinalLevel,
    })
    .to_string()
    .is_empty());
}

#[test]
fn every_registry_rejection_names_the_document_it_refused() {
    // §Errors: `Display` names the offending document in M1's dotted decimal
    // wherever the variant carries one — which is the whole value of carrying
    // it, a message that drops the payload localizing nothing.
    let d = unregistered().to_string();
    for message in [
        RetrieveError::DocNotRegistered(unregistered()).to_string(),
        DeletionsError::DocNotRegistered(unregistered()).to_string(),
        CompareError::DocNotRegistered(unregistered()).to_string(),
        FindError::DocNotRegistered(unregistered()).to_string(),
    ] {
        assert!(message.contains(&d), "{message} names no document");
    }
}

#[test]
fn the_fault_vocabularies_key_a_map_a_consumer_could_not_key_itself() {
    // §Errors derive policy: SpanFault and Operand carry `Hash` because a
    // consumer keying by one cannot supply the impl — both the trait and the
    // type are foreign to it. A per-(operand, fault) counter is the shape a
    // transport instruments this surface with, and until M10 derives `Hash` on
    // `FaultSite` this is the only thing standing between the derive and a
    // cleanup that removes it as unused.
    let mut counts: HashMap<(Operand, SpanFault), usize> = HashMap::new();
    for site in [
        (Operand::First, SpanFault::NotOrdinalLevel),
        (Operand::First, SpanFault::NotOrdinalLevel),
        (Operand::Second, SpanFault::NotOrdinalLevel),
        (Operand::First, SpanFault::StartTooShallow),
    ] {
        *counts.entry(site).or_default() += 1;
    }
    assert_eq!(counts[&(Operand::First, SpanFault::NotOrdinalLevel)], 2);
    assert_eq!(counts.len(), 3, "the three distinct sites key apart");
}

#[test]
fn the_answer_collections_behave_like_std_collections() {
    // §Public interface: Delivery and CompareReport are collections, so a
    // consumer walks, measures and collects one without naming the Vec
    // inside it — impls the orphan rule would forbid a consumer from adding.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 2),
        }],
    )
    .expect("copy commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    let delivery = ok_of(q.retrieve_v(&[spec(doc1(), vspan(1, 1, 3))]));
    assert_eq!(delivery.len(), 3);
    assert!(!delivery.is_empty());
    assert_eq!(delivery.iter().count(), 3);
    assert_eq!(delivery.as_slice()[0], DeliveryItem::Content(val(b"a")));
    // Borrowed walk, then an owned one that collects straight back.
    let borrowed: Vec<&DeliveryItem> = (&delivery).into_iter().collect();
    assert_eq!(borrowed.len(), 3);
    let round: Delivery = delivery.clone().into_iter().collect();
    assert_eq!(round, delivery);
    // The empty answers are the defaults, and an empty spec-set yields one.
    assert_eq!(ok_of(q.retrieve_v(&[])), Delivery::default());
    assert!(Delivery::default().is_empty());
    assert_eq!(Deletions::default(), ok_of(q.show_deletions(&doc1(), &doc2())));
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 2)])],
    ));
    assert_eq!(rep.len(), 1);
    assert!(!rep.is_empty());
    assert_eq!(rep.iter().count(), 1);
    assert_eq!(rep.as_slice()[0].d1, doc1());
    let round: CompareReport = rep.clone().into_iter().collect();
    assert_eq!(round, rep);
    assert!(CompareReport::default().is_empty());
    // A report of two documents that share no address IS the default.
    let none = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
        &[region_spec(doc1(), vec![])],
    ));
    assert_eq!(none, CompareReport::default());
}

#[test]
fn the_query_handle_and_its_answers_cross_threads() {
    // Auto traits are promises made by what a type CONTAINS, and a threaded
    // front door depends on them; a private field could revoke one with no
    // signature changing, so the promise is pinned here.
    fn is_send_sync<T: Send + Sync>() {}
    is_send_sync::<Query<'static, World>>();
    is_send_sync::<Delivery>();
    is_send_sync::<CompareReport>();
    is_send_sync::<Deletions>();
    is_send_sync::<RetrieveError>();
}
