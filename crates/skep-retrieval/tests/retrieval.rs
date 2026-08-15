//! Integration tests for M6's public surface. Each test states a claim the
//! design/interface actually makes (§-references inline): what each operation
//! admits and rejects (and WHICH error wins when several conditions fail at
//! once), the silent-empty degradations RETRIEVEV's R6 mandates, delivery
//! order/multiplicity (R3/R5/R8), extent synthesis from counts (D-CTG★),
//! origin projection and its reject-never-clamp admissibility (WF_V/O13), the
//! cross-document SHOWDELETIONS combine (D-IDENT/D-ORD), COMPARE's
//! address-equal join (per-block feet, fan-out completeness, deterministic
//! order, value-blindness), FINDDOCSCONTAINING's present-tense filter
//! (FD-SOUND) over the raw mixed-length coverage union, that queries never
//! mutate, and the derive policy M10 marshals against.
//!
//! This file compiles as a FOREIGN crate, so it also witnesses the derive
//! policy's consequences: M6's result/error types carry no `Debug`, so the
//! tests unwrap through `ok_of`/`err_of` (no `expect`) and compare with
//! `assert!`/`matches!` — exactly the constraints M10 will live under. The
//! toy `World`/`Rec` pair is the minimal engine assembly the composition
//! contract prescribes; all state is arranged through M5's real `Vstream`
//! ops (M5Rec is sealed to foreign crates).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Span, SpanSet, Tumbler};
use skep_arrangement::{seat_link, HasM5, M5State, VPos, VSpec, Vstream};
use skep_content::{ContentStore, ContentWrite, HasContent, Val};
use skep_kernel::{CheckpointPolicy, Durability, Kernel, KernelCfg, WorldState};
use skep_namespace::{HasM3, M3Rec, M3State, PrincipalId};
use skep_retrieval::{
    CompareError, Deletions, Delivery, DeliveryItem, ExtentError, FindError, Operand, OriginError,
    Query, Region, RetrieveError, Spec, SpecFault,
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
                m3: self.m3.apply_ns(x),
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
fn un() -> Address {
    a(&[1, 0, 1, 0, 9])
}

/// doc1 content element k (length 8), M3's minted shape.
fn ca(k: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 1, k])
}

/// doc1 link element k.
fn la(k: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 2, k])
}

/// doc2 link element k.
fn l2a(k: u32) -> Address {
    a(&[1, 0, 1, 0, 2, 0, 2, k])
}

/// The version fork of doc1 (`(d_src, 1)` chain) and its length-9 content
/// elements — the mixed-length transclusion case.
fn vdoc() -> Address {
    a(&[1, 0, 1, 0, 1, 1])
}
fn vca(k: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 1, 0, 1, k])
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

fn spec(doc: Address, span: Span) -> Spec {
    Spec { doc, span }
}

fn region(doc: Address, spans: Vec<Span>) -> Region {
    Region { doc, spans }
}

/// A T12-legal but non-ordinal-level width (action point 1).
fn lu_span() -> Span {
    Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12-legal")
}

/// A well-formed depth-3 span — depth-INCOMPATIBLE, not malformed.
fn deep_span(subspace: u32) -> Span {
    Span::new(t(&[subspace, 1, 1]), t(&[0, 0, 1])).expect("T12-legal")
}

/// Unwrap Ok without `E: Debug` — M6's error enums deliberately carry no
/// `Debug` (derive policy), so `Result::expect` does not compile against
/// them; this is the same constraint M10 marshals under.
fn ok_of<T, E>(r: Result<T, E>) -> T {
    match r {
        Ok(v) => v,
        Err(_) => panic!("expected Ok, got Err"),
    }
}

/// Unwrap Err without `E: Debug`.
fn err_of<T, E>(r: Result<T, E>) -> E {
    match r {
        Ok(_) => panic!("expected Err, got Ok"),
        Err(e) => e,
    }
}

/// Genesis with M3 pre-seeded by folding exactly the records its own
/// delegate/create_new_document ops would stage: account [1,0,1] → principal
/// 1 (owns doc1, doc2), account [1,0,2] → principal 2.
fn genesis() -> World {
    let m3 = M3State::genesis()
        .apply_ns(&M3Rec::Allocate { addr: t(&[1, 0, 1]) })
        .apply_ns(&M3Rec::RegisterPrincipal {
            prefix: t(&[1, 0, 1]),
            id: PrincipalId(1),
        })
        .apply_ns(&M3Rec::Allocate { addr: t(&[1, 0, 2]) })
        .apply_ns(&M3Rec::RegisterPrincipal {
            prefix: t(&[1, 0, 2]),
            id: PrincipalId(2),
        })
        .apply_ns(&M3Rec::Allocate {
            addr: t(&[1, 0, 1, 0, 1]),
        })
        .apply_ns(&M3Rec::Allocate {
            addr: t(&[1, 0, 1, 0, 2]),
        });
    World {
        m3,
        content: ContentStore::default(),
        m5: M5State::genesis(),
    }
}

fn mem_kernel() -> Kernel<World> {
    let cfg = KernelCfg {
        journal_path: PathBuf::from("/nonexistent/skep-retrieval-ignored"),
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        retain_checkpoints: 1,
    };
    Kernel::open(cfg, genesis()).expect("in-memory open")
}

/// doc1 arranged with content a, b, c (ca1..ca3).
fn insert3(k: &Kernel<World>) -> Vstream<'_, World> {
    let vs = Vstream::new(k);
    vs.insert(&doc1(), vp(1, 1), vec![val(b"a"), val(b"b"), val(b"c")])
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
        &doc2(),
        vp(1, 1),
        vec![VSpec {
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
        &[region(doc1(), vec![vspan(1, 1, 3)])],
        &[region(doc2(), vec![vspan(1, 1, 2)])],
    ));
    let _ = ok_of(q.find_docs_containing(&[region(doc2(), vec![vspan(1, 1, 2)])]));
    // …and nothing committed.
    assert_eq!(k.current_seq(), before);
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
    assert!(
        got == Delivery(vec![
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
    assert!(
        got == Delivery(vec![
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
    assert!(
        got == Delivery(vec![
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
    assert!(ok_of(q.retrieve_v(&[])) == Delivery(vec![]));
    // Overrun clips (accept-and-intersect upstream).
    let got = ok_of(q.retrieve_v(&[spec(doc1(), vspan(1, 2, 10))]));
    assert!(
        got == Delivery(vec![
            DeliveryItem::Content(val(b"b")),
            DeliveryItem::Content(val(b"c")),
        ])
    );
    // Depth-incompatible: well-formed, passes the gate, resolves to ⟨⟩ —
    // the good spec's contribution survives beside it.
    let got = ok_of(q.retrieve_v(&[spec(doc1(), deep_span(1)), spec(doc1(), vspan(1, 1, 1))]));
    assert!(got == Delivery(vec![DeliveryItem::Content(val(b"a"))]));
    // Foreign subspace: force-emptied upstream, never an error here.
    assert!(ok_of(q.retrieve_v(&[spec(doc1(), vspan(3, 1, 1))])) == Delivery(vec![]));
    // Registered-empty document contributes nothing.
    assert!(ok_of(q.retrieve_v(&[spec(doc2(), vspan(1, 1, 1))])) == Delivery(vec![]));
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
        err_of(q.retrieve_v(&[spec(un(), vspan(1, 1, 1))])),
        RetrieveError::DocNotRegistered(d) if d == un()
    ));
    // Registered-before-gate: an unregistered doc with a malformed span
    // still reports DocNotRegistered.
    assert!(matches!(
        err_of(q.retrieve_v(&[spec(un(), lu_span())])),
        RetrieveError::DocNotRegistered(d) if d == un()
    ));
    // Each SpecFault, with index attribution (the good spec at 0 does not
    // save the request — whole-request rejection).
    assert!(matches!(
        err_of(q.retrieve_v(&[spec(doc1(), vspan(1, 1, 1)), spec(doc1(), lu_span())])),
        RetrieveError::MalformedSpec {
            index: 1,
            fault: SpecFault::NotOrdinalLevel
        }
    ));
    let not_uniform = Span::new(t(&[1, 1]), t(&[1])).expect("T12-legal");
    assert!(matches!(
        err_of(q.retrieve_v(&[spec(doc1(), not_uniform)])),
        RetrieveError::MalformedSpec {
            index: 0,
            fault: SpecFault::NotLevelUniform
        }
    ));
    let zeroed = Span::new(t(&[1, 0, 1]), t(&[0, 0, 1])).expect("T12-legal");
    assert!(matches!(
        err_of(q.retrieve_v(&[spec(doc1(), zeroed)])),
        RetrieveError::MalformedSpec {
            index: 0,
            fault: SpecFault::StartNotZeroFree
        }
    ));
    let shallow = Span::new(t(&[5]), t(&[1])).expect("T12-legal");
    assert!(matches!(
        err_of(q.retrieve_v(&[spec(doc1(), shallow)])),
        RetrieveError::MalformedSpec {
            index: 0,
            fault: SpecFault::StartTooShallow
        }
    ));
}

// ---- §B document extents ----

#[test]
fn doc_vspan_synthesizes_the_bounding_span_from_counts() {
    // ASN-0112: σ_d — the whole-document bounding span, a bounding box
    // bridging the inter-subspace void once links exist (D-CTG★ makes the
    // counts the extents; min is the subspace anchor, never negative).
    let k = mem_kernel();
    insert3(&k);
    {
        let s = k.snapshot();
        let q = Query::new(&s);
        // Content only: ([1,1], reach [1,4)).
        let got = ok_of(q.doc_vspan(&doc1()));
        let want = SpanSet::singleton(
            Span::from_endpoints(t(&[1, 1]), t(&[1, 4])).expect("well-formed"),
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
        SpanSet::singleton(Span::from_endpoints(t(&[1, 1]), t(&[2, 3])).expect("well-formed"));
    assert_eq!(got, want);
    // Link-only document: the anchor moves to [2,1].
    seat_link(&k, &doc2(), &l2a(1)).expect("seat commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    let got = ok_of(q.doc_vspan(&doc2()));
    let want =
        SpanSet::singleton(Span::from_endpoints(t(&[2, 1]), t(&[2, 2])).expect("well-formed"));
    assert_eq!(got, want);
}

#[test]
fn doc_vspanset_reports_per_subspace_exact_extents_prenormalized() {
    // ASN-0113 W2/W4/W13: ≤2 members, content before link, exact
    // ext(d,S) = ([S,1],[0,n_S]), already normal; ⟨⟩ for allocated-empty;
    // unallocated ⇒ Err (both extent ops).
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
    // Unallocated ⇒ fail, for both.
    assert!(matches!(
        err_of(q.doc_vspan(&un())),
        ExtentError::DocNotRegistered
    ));
    assert!(matches!(
        err_of(q.doc_vspanset(&un())),
        ExtentError::DocNotRegistered
    ));
}

// ---- §C SHOWORIGIN (V-arity) ----

#[test]
fn show_origin_v_projects_deduplicated_origins_in_tumbler_order() {
    // ASN-0077 O2/O5: one origin per run (block uniformity), deduplicated,
    // tumbler-ordered; the link arity reports the home document (CL-OWN).
    let k = mem_kernel();
    let vs = insert3(&k);
    // doc2 = [da1][ca1, ca2][ca1]: own content + two transclusions of doc1.
    vs.insert(&doc2(), vp(1, 1), vec![val(b"x")])
        .expect("insert commits");
    vs.copy(
        &doc2(),
        vp(1, 2),
        vec![VSpec {
            source: doc1(),
            span: vspan(1, 1, 2),
        }],
    )
    .expect("copy commits");
    vs.copy(
        &doc2(),
        vp(1, 4),
        vec![VSpec {
            source: doc1(),
            span: vspan(1, 1, 1),
        }],
    )
    .expect("copy commits");
    seat_link(&k, &doc2(), &l2a(1)).expect("seat commits");
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
fn show_origin_v_rejects_each_inadmissible_case_distinctly() {
    // ASN-0077 WF_V(i–vi)/O13 — reject, never clamp; the checks run in the
    // documented order: registered → well-formed → subspace → empty →
    // depth → range.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    // (i) unallocated — checked first, even with a malformed span.
    assert!(matches!(
        err_of(q.show_origin_v(&un(), &vspan(1, 1, 1))),
        OriginError::DocNotRegistered
    ));
    assert!(matches!(
        err_of(q.show_origin_v(&un(), &lu_span())),
        OriginError::DocNotRegistered
    ));
    // (ii/iv) malformed — before any subspace reading (a malformed span in
    // a foreign subspace is MalformedSpan, not NoSuchSubspace).
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &lu_span())),
        OriginError::MalformedSpan(SpecFault::NotOrdinalLevel)
    ));
    let foreign_malformed = Span::new(t(&[3, 1]), t(&[1, 0])).expect("T12-legal");
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &foreign_malformed)),
        OriginError::MalformedSpan(SpecFault::NotOrdinalLevel)
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
    // ASN-0075 D-IDENT/D-ORD: each half is the deduped, Tumbler-ordered set
    // of the EXISTING I-addresses deleted-from-one ∧ current-in-the-other;
    // slot semantics follow the argument order.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.copy(
        &doc2(),
        vp(1, 1),
        vec![VSpec {
            source: doc1(),
            span: vspan(1, 1, 2),
        }],
    )
    .expect("copy commits"); // doc2 = [ca1, ca2]
    vs.delete(&doc1(), vp(1, 2), n(1)).expect("delete commits"); // doc1 = [ca1, ca3]; deleted ca2
    vs.delete(&doc2(), vp(1, 1), n(1)).expect("delete commits"); // doc2 = [ca2]; deleted ca1
    let s = k.snapshot();
    let q = Query::new(&s);
    let got = ok_of(q.show_deletions(&doc1(), &doc2()));
    assert!(
        got == Deletions {
            a_with_b: vec![ca(2)], // deleted from doc1, current in doc2
            b_with_a: vec![ca(1)], // deleted from doc2, current in doc1
        }
    );
    // Swapping the arguments swaps the halves.
    let got = ok_of(q.show_deletions(&doc2(), &doc1()));
    assert!(
        got == Deletions {
            a_with_b: vec![ca(1)],
            b_with_a: vec![ca(2)],
        }
    );
}

#[test]
fn show_deletions_dedups_multiplicity_and_admits_empty_documents() {
    // ASN-0075: intra-document transclusion multiplicity collapses (sets,
    // not bags); allocated-empty documents are admissible with empty halves;
    // an unregistered document is the typed failure (d_a checked first).
    let k = mem_kernel();
    {
        // Registered-but-empty on both sides ⇒ empty halves.
        let s = k.snapshot();
        let q = Query::new(&s);
        let got = ok_of(q.show_deletions(&doc1(), &doc2()));
        assert!(
            got == Deletions {
                a_with_b: vec![],
                b_with_a: vec![],
            }
        );
        assert!(matches!(
            err_of(q.show_deletions(&un(), &doc1())),
            DeletionsError::DocNotRegistered(d) if d == un()
        ));
        assert!(matches!(
            err_of(q.show_deletions(&doc1(), &un())),
            DeletionsError::DocNotRegistered(d) if d == un()
        ));
    }
    let vs = insert3(&k);
    // doc2 holds ca1 TWICE; doc1 then deletes ca1.
    vs.copy(
        &doc2(),
        vp(1, 1),
        vec![VSpec {
            source: doc1(),
            span: vspan(1, 1, 1),
        }],
    )
    .expect("copy commits");
    vs.copy(
        &doc2(),
        vp(1, 2),
        vec![VSpec {
            source: doc1(),
            span: vspan(1, 1, 1),
        }],
    )
    .expect("copy commits");
    vs.delete(&doc1(), vp(1, 1), n(1)).expect("delete commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    let got = ok_of(q.show_deletions(&doc1(), &doc2()));
    // ca1 appears ONCE despite doc2's double placement (dedup, D-ORD).
    assert!(
        got == Deletions {
            a_with_b: vec![ca(1)],
            b_with_a: vec![],
        }
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
        &doc2(),
        vp(1, 1),
        vec![VSpec {
            source: doc1(),
            span: vspan(1, 2, 1),
        }],
    )
    .expect("copy commits"); // doc2 = [ca2]
    let s = k.snapshot();
    let q = Query::new(&s);
    let rep = ok_of(q.compare(
        &[region(doc1(), vec![vspan(1, 1, 3)])],
        &[region(doc2(), vec![vspan(1, 1, 1)])],
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
        &[region(doc2(), vec![vspan(1, 1, 1)])],
        &[region(doc1(), vec![vspan(1, 1, 3)])],
    ));
    assert_eq!(rep.0.len(), 1);
    let p = &rep.0[0];
    assert_eq!(p.d1, doc2());
    assert_eq!(p.u1.ordinal, n(1));
    assert_eq!(p.d2, doc1());
    assert_eq!(p.u2.ordinal, n(2));
}

#[test]
fn compare_is_complete_under_fanout_deterministic_and_value_blind() {
    // ASN-0122 X8: an address in multiple blocks yields the full
    // cross-product; X12 R3: canonical (d1,u1,d2,u2) order; X1/X2: the join
    // is on address equality, never value (equal bytes at distinct addresses
    // do NOT correspond); duplicate windows within one operand are listed,
    // not deduped (denotationally conforming).
    let k = mem_kernel();
    let vs = insert3(&k);
    // doc2 = [ca1][ca1][da1]: ca1 placed twice, then doc2's OWN "a" (same
    // bytes as doc1's ca1, different address).
    vs.copy(
        &doc2(),
        vp(1, 1),
        vec![VSpec {
            source: doc1(),
            span: vspan(1, 1, 1),
        }],
    )
    .expect("copy commits");
    vs.copy(
        &doc2(),
        vp(1, 2),
        vec![VSpec {
            source: doc1(),
            span: vspan(1, 1, 1),
        }],
    )
    .expect("copy commits");
    vs.insert(&doc2(), vp(1, 3), vec![val(b"a")])
        .expect("insert commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    // Fan-out: one P block, two Q blocks holding the same address ⇒ 2 pairs,
    // canonically ordered by u2.
    let rep = ok_of(q.compare(
        &[region(doc1(), vec![vspan(1, 1, 1)])],
        &[region(doc2(), vec![vspan(1, 1, 2)])],
    ));
    assert_eq!(rep.0.len(), 2);
    assert_eq!(rep.0[0].u2.ordinal, n(1));
    assert_eq!(rep.0[1].u2.ordinal, n(2));
    // Value-blind: doc2's own "a" (da1) shares bytes with ca1 but no pair.
    let rep = ok_of(q.compare(
        &[region(doc1(), vec![vspan(1, 1, 3)])],
        &[region(doc2(), vec![vspan(1, 3, 1)])],
    ));
    assert_eq!(rep.0.len(), 0);
    // A repeated window within ρ₁ double-covers and is listed twice.
    let rep = ok_of(q.compare(
        &[region(doc1(), vec![vspan(1, 1, 1), vspan(1, 1, 1)])],
        &[region(doc2(), vec![vspan(1, 1, 1)])],
    ));
    assert_eq!(rep.0.len(), 2);
    // Empty operands and depth-incompatible regions are empty SUCCESSES.
    assert_eq!(ok_of(q.compare(&[], &[])).0.len(), 0);
    let rep = ok_of(q.compare(
        &[region(doc1(), vec![deep_span(1)])],
        &[region(doc2(), vec![vspan(1, 1, 2)])],
    ));
    assert_eq!(rep.0.len(), 0);
}

#[test]
fn compare_rejects_with_operand_region_index_attribution() {
    // ASN-0122 precondition: registered docs, content-subspace starts,
    // well-formed spans — each fault localized by (operand, region, index);
    // the subspace residence check runs BEFORE the well-formedness gate.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    assert!(matches!(
        err_of(q.compare(&[region(un(), vec![vspan(1, 1, 1)])], &[])),
        CompareError::DocNotRegistered(d) if d == un()
    ));
    assert!(matches!(
        err_of(q.compare(
            &[region(doc1(), vec![vspan(1, 1, 1)])],
            &[region(doc1(), vec![vspan(2, 1, 1)])],
        )),
        CompareError::NotContentSubspace {
            operand: Operand::Second,
            region: 0,
            index: 0
        }
    ));
    assert!(matches!(
        err_of(q.compare(
            &[region(doc1(), vec![vspan(1, 1, 1), lu_span()])],
            &[region(doc1(), vec![vspan(1, 1, 1)])],
        )),
        CompareError::MalformedSpan {
            operand: Operand::First,
            region: 0,
            index: 1,
            fault: SpecFault::NotOrdinalLevel
        }
    ));
    // A link-START span that is ALSO malformed: subspace residence wins.
    let link_malformed = Span::new(t(&[2, 1]), t(&[1, 0])).expect("T12-legal");
    assert!(matches!(
        err_of(q.compare(&[region(doc1(), vec![link_malformed])], &[])),
        CompareError::NotContentSubspace {
            operand: Operand::First,
            region: 0,
            index: 0
        }
    ));
}

// ---- §E FINDDOCSCONTAINING ----

#[test]
fn find_docs_containing_filters_to_present_tense_containers() {
    // ASN-0124 FD-SOUND: docs_containing's historical superset is narrowed
    // by the project filter to CURRENT holders; the raw coverage union may
    // be mixed-length (M5 owns the level-class discipline); bare identities,
    // tumbler-ordered.
    let k = mem_kernel();
    let vs = insert3(&k);
    let (fork, _) = vs.version(PrincipalId(1), &doc1()).expect("fork commits");
    assert_eq!(fork, vdoc()); // shares ca1..ca3
    let (start, _) = vs
        .insert(&fork, vp(1, 4), vec![val(b"z")])
        .expect("fork edit commits");
    assert_eq!(start, vca(1)); // the fork's chain mints LENGTH-9 elements
    vs.copy(
        &doc2(),
        vp(1, 1),
        vec![
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
            ok_of(q.find_docs_containing(&[region(doc2(), vec![vspan(1, 1, 2)])])),
            vec![doc1(), vdoc(), doc2()]
        );
    }
    // doc1 drops ca1 — it stays an R-candidate (permanence) but the
    // present-tense filter removes it.
    vs.delete(&doc1(), vp(1, 1), n(1)).expect("delete commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        ok_of(q.find_docs_containing(&[region(doc2(), vec![vspan(1, 1, 2)])])),
        vec![vdoc(), doc2()]
    );
    // A depth-incompatible span contributes nothing — never a rejection.
    assert_eq!(
        ok_of(q.find_docs_containing(&[
            region(doc1(), vec![deep_span(1)]),
            region(doc2(), vec![vspan(1, 1, 2)]),
        ])),
        vec![vdoc(), doc2()]
    );
    // A link-subspace span passes the gate and stays inert: link placement
    // is R-uncoupled (J-LV), so it can add no spurious container.
    seat_link(&k, &doc1(), &la(1)).expect("seat commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        ok_of(q.find_docs_containing(&[region(doc1(), vec![vspan(2, 1, 1)])])),
        Vec::<Address>::new()
    );
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
        err_of(q.find_docs_containing(&[region(un(), vec![vspan(1, 1, 1)])])),
        FindError::DocNotRegistered(d) if d == un()
    ));
    let zeroed = Span::new(t(&[1, 0, 1]), t(&[0, 0, 1])).expect("T12-legal");
    assert!(matches!(
        err_of(q.find_docs_containing(&[region(doc1(), vec![vspan(1, 1, 1), zeroed])])),
        FindError::MalformedSpan {
            region: 0,
            index: 1,
            fault: SpecFault::StartNotZeroFree
        }
    ));
    assert!(matches!(
        err_of(q.find_docs_containing(&[
            region(doc1(), vec![vspan(1, 1, 1)]),
            region(doc1(), vec![lu_span()]),
        ])),
        FindError::MalformedSpan {
            region: 1,
            index: 0,
            fault: SpecFault::NotOrdinalLevel
        }
    ));
    // Registered-but-empty doc2: nothing resolves, nothing contains.
    assert_eq!(
        ok_of(q.find_docs_containing(&[region(doc2(), vec![vspan(1, 1, 1)])])),
        Vec::<Address>::new()
    );
}

// ---- derive policy (the marshaling seam) ----

#[test]
fn results_and_errors_marshal_through_serialize_per_the_derive_policy() {
    // §Public interface derive policy: results/errors are Serialize (M10
    // marshals them; bincode is M2's actual wire format); CorrPair/
    // CompareReport carry no derives and marshal FIELD-BY-FIELD — every leaf
    // still serializes individually, VPos's Nat fields included.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.copy(
        &doc2(),
        vp(1, 1),
        vec![VSpec {
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
    let e = err_of(q.retrieve_v(&[spec(un(), vspan(1, 1, 1))]));
    assert!(!bincode::serialize(&e).expect("RetrieveError serializes").is_empty());
    assert!(!bincode::serialize(&SpecFault::NotOrdinalLevel)
        .expect("SpecFault serializes")
        .is_empty());
    assert!(!bincode::serialize(&Operand::First)
        .expect("Operand serializes")
        .is_empty());
    // Request types serialize too (all-pub-field values).
    assert!(!bincode::serialize(&spec(doc1(), vspan(1, 1, 1)))
        .expect("Spec serializes")
        .is_empty());
    assert!(!bincode::serialize(&region(doc1(), vec![vspan(1, 1, 1)]))
        .expect("Region serializes")
        .is_empty());
    // CorrPair: field-by-field marshaling (no whole-value Serialize).
    let rep = ok_of(q.compare(
        &[region(doc1(), vec![vspan(1, 1, 3)])],
        &[region(doc2(), vec![vspan(1, 1, 2)])],
    ));
    assert_eq!(rep.0.len(), 1);
    let p = &rep.0[0];
    assert!(!bincode::serialize(&p.d1).expect("Address serializes").is_empty());
    assert!(!bincode::serialize(&p.u1.subspace).expect("Nat serializes").is_empty());
    assert!(!bincode::serialize(&p.u1.ordinal).expect("Nat serializes").is_empty());
    assert!(!bincode::serialize(&p.d2).expect("Address serializes").is_empty());
    assert!(!bincode::serialize(&p.width).expect("Nat serializes").is_empty());
}
