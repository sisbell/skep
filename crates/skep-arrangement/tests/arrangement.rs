//! Integration tests for M5's public surface. Each test states a claim the
//! design/interface actually makes (§-references inline): what each op admits
//! and rejects (and WHICH error wins when several conditions fail at once),
//! that every mutation is one committed composite whose rejection leaves no
//! state change, the J-couplings observable through one snapshot (J0/J1★/
//! J-LV), transclusion-by-reference, NonDestruction, the fork share, the
//! level-class discipline surfaces, and that the journaled slice survives
//! serde plus M2's real checkpoint-and-replay recovery. The toy `World`/`Rec`
//! pair is the minimal engine assembly the composition contract prescribes.
//!
//! This file compiles as a FOREIGN crate, so it also witnesses the sealing
//! claims: `M5Rec` cannot be built here, `Run` fields cannot be reached or
//! mutated (accessors only), and everything below drives the system through
//! `Vstream`/`stage_seat_link`/`seat_link` alone.

use std::path::Path;

use serde::{Deserialize, Serialize};
use skep_address::{subtree_of, validate, Address, Nat, Span, SpanSet, Tumbler};
use skep_arrangement::{
    ordinal_vspan, seat_link, stage_seat_link, Caller, CopyError, DeleteError, HasM5, InsertError,
    M5State, RearrangeError, SeatError, VPos, VSpec, VersionError, Vstream,
};
use skep_content::{ContentStore, ContentWrite, HasContent, Val};
use skep_kernel::{
    BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelConfig, Snapshot, TxnError,
    WorldState,
};
use skep_namespace::{HasM3, M3Rec, M3State, PrincipalId};
use tempfile::tempdir;

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

/// doc1 content element k (length 8), M3's minted shape.
fn ca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 1, ordinal])
}

/// The version fork of doc1 (`(d_src, 1)` chain) and its length-9 elements.
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

fn vspan(subspace: u32, ordinal: u32, count: u32) -> Span {
    ordinal_vspan(&vp(subspace, ordinal), &n(count)).expect("test spans name ≥ 1 position")
}

fn val(b: &[u8]) -> Val {
    Val::new(b)
}

/// The seeded owner of doc1/doc2 — the caller every pre-ruling op runs
/// under, so the ω gate is exercised on every path, not skipped.
const P1: Caller = Caller::Principal(PrincipalId(1));

/// Genesis with M3 pre-seeded by folding exactly the records its own
/// delegate/create_new_document ops would stage: account [1,0,1] → principal
/// 1 (owns doc1, doc2), sibling account [1,0,2] → principal 2, sub-account
/// [1,0,1,1] (delegated under [1,0,1]) → principal 3 with its own document
/// [1,0,1,1,0,1] — the ownership-exactness fixtures. Deterministic, per
/// M2's byte-identical-genesis contract. The publication bits are the
/// flagless create path's (PUB-8.21): each account's first document born
/// published, doc2 private; an account's `Allocate` carries no publication
/// state.
fn genesis() -> World {
    let m3 = M3State::genesis()
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1]),
            published: false,
        })
        .apply_m3(&M3Rec::RegisterPrincipal {
            prefix: a(&[1, 0, 1]),
            id: PrincipalId(1),
        })
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 2]),
            published: false,
        })
        .apply_m3(&M3Rec::RegisterPrincipal {
            prefix: a(&[1, 0, 2]),
            id: PrincipalId(2),
        })
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 1]),
            published: false,
        })
        .apply_m3(&M3Rec::RegisterPrincipal {
            prefix: a(&[1, 0, 1, 1]),
            id: PrincipalId(3),
        })
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 1]),
            published: true,
        })
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 2]),
            published: false,
        })
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 1, 0, 1]),
            published: true,
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

fn cfg_fsync(dir: &Path) -> KernelConfig {
    KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 1,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
    }
}

/// Unwrap an op's typed rejection (`TxnError::Rejected(E)` — surfaced
/// verbatim, per M2's transact contract).
fn rejected<T, E: std::fmt::Debug>(r: Result<T, TxnError<E>>) -> E {
    match r {
        Err(TxnError::Rejected(e)) => e,
        Err(other) => panic!("expected TxnError::Rejected, got {other:?}"),
        Ok(_) => panic!("expected TxnError::Rejected, got Ok"),
    }
}

/// Read the value bytes at content V-ordinal `ord` — point (M5) then
/// value_at (M4), both off ONE snapshot.
fn read_v(s: &Snapshot<World>, doc: &Address, ord: u32) -> Vec<u8> {
    let addr = s
        .world()
        .m5()
        .point(doc, &vp(1, ord))
        .expect("ordinal is arranged");
    s.world()
        .content()
        .value_at(addr.tumbler())
        .expect("arranged content is present (S3★)")
        .as_bytes()
        .to_vec()
}

/// Leave doc1 holding `a`, `b`, `c` at content ordinals 1..3, and hand back
/// the `Vstream` the caller goes on to drive.
fn insert_abc(kernel: &Kernel<World>) -> Vstream<'_, World> {
    let vs = Vstream::new(kernel);
    vs.insert(P1, &doc1(), vp(1, 1), vec![val(b"a"), val(b"b"), val(b"c")])
        .expect("insert commits");
    vs
}

// ---- §B INSERT ----

#[test]
fn insert_mints_writes_places_and_returns_the_run_start() {
    // ASN-0116/§3: one composite; returns the run START (M9's predicate-def
    // identity) + the commit Seq; reads compose off one snapshot.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    let (start, seq) = vs
        .insert(P1, &doc1(), vp(1, 1), vec![val(b"a"), val(b"b"), val(b"c")])
        .expect("insert commits");
    assert_eq!(start, ca(1));
    assert_eq!(k.current_seq(), seq);
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(m5.content_count(&doc1()), n(3));
    // Held-lock mints are contiguous ⇒ exactly ONE placed run.
    let runs = m5.content_runs(&doc1());
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].i_start(), &ca(1));
    assert_eq!(runs[0].width(), &n(3));
    assert_eq!(m5.point(&doc1(), &vp(1, 2)), Some(ca(2)));
    assert_eq!(read_v(&s, &doc1(), 2), b"b".to_vec());
    // image is the centralized iextent lift.
    let cov = m5.image(&doc1(), &vspan(1, 1, 3));
    assert!(cov.denotes(ca(1).tumbler()));
    assert!(cov.denotes(ca(3).tumbler()));
    assert!(!cov.denotes(ca(4).tumbler()));
    // J1★ off the same snapshot: the placement is already in R.
    assert_eq!(m5.docs_ever_containing(&cov), vec![doc1()]);
}

#[test]
fn insert_appends_coalesce_and_interior_inserts_shift_the_suffix() {
    let k = mem_kernel();
    let vs = insert_abc(&k);
    // Tail append continues the frontier ⇒ I-adjacent ⇒ still one run (M12).
    let (start, _) = vs
        .insert(P1, &doc1(), vp(1, 4), vec![val(b"d")])
        .expect("append commits");
    assert_eq!(start, ca(4));
    {
        let s = k.snapshot();
        assert_eq!(s.world().m5().content_runs(&doc1()).len(), 1);
    }
    // Interior insert splits the run; the suffix shifts for free (§1).
    let (start, _) = vs
        .insert(P1, &doc1(), vp(1, 2), vec![val(b"x")])
        .expect("interior insert commits");
    assert_eq!(start, ca(5));
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(m5.content_count(&doc1()), n(5));
    assert_eq!(m5.content_runs(&doc1()).len(), 3);
    assert_eq!(read_v(&s, &doc1(), 1), b"a".to_vec());
    assert_eq!(read_v(&s, &doc1(), 2), b"x".to_vec());
    assert_eq!(read_v(&s, &doc1(), 3), b"b".to_vec());
    assert_eq!(read_v(&s, &doc1(), 5), b"d".to_vec());
}

#[test]
fn insert_rejects_in_documented_order_and_commits_nothing() {
    // §3 check order: DocNotRegistered → EmptyContent → NotContentSubspace →
    // OutOfBounds; every rejection is a clean no-op.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    let before = k.current_seq();
    let un = a(&[1, 0, 1, 0, 9]); // never registered
    assert!(matches!(
        rejected(vs.insert(P1, &un, vp(2, 0), vec![])),
        InsertError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.insert(P1, &doc1(), vp(2, 0), vec![])),
        InsertError::EmptyContent
    ));
    assert!(matches!(
        rejected(vs.insert(P1, &doc1(), vp(2, 99), vec![val(b"x")])),
        InsertError::NotContentSubspace
    ));
    assert!(matches!(
        rejected(vs.insert(P1, &doc1(), vp(1, 0), vec![val(b"x")])),
        InsertError::OutOfBounds
    ));
    // n_C = 0: the only valid insertion ordinal is 1 (FirstInsertionPosition).
    assert!(matches!(
        rejected(vs.insert(P1, &doc1(), vp(1, 2), vec![val(b"x")])),
        InsertError::OutOfBounds
    ));
    assert_eq!(k.current_seq(), before);
}

// ---- §B COPY ----

#[test]
fn copy_transcludes_by_reference_and_records_provenance() {
    // ASN-0118 CP1/CP2: no content allocated; the destination references the
    // SOURCE's I-addresses; provenance makes the destination discoverable.
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let stored_before = k.snapshot().world().content().len();
    let seq = vs
        .copy(
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
    assert_eq!(s.seq(), seq);
    assert_eq!(s.world().content().len(), stored_before); // nothing minted/written
    let m5 = s.world().m5();
    assert_eq!(m5.content_count(&doc2()), n(2));
    let runs = m5.content_runs(&doc2());
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].i_start(), &ca(1)); // doc1's address, carried verbatim (S7)
    assert_eq!(read_v(&s, &doc2(), 2), b"b".to_vec());
    // Both the origin and the transcluder are R-candidates for the region.
    let cov = SpanSet::singleton(runs[0].iextent());
    assert_eq!(m5.docs_ever_containing(&cov), vec![doc1(), doc2()]);
}

#[test]
fn self_copy_resolves_against_the_pre_edit_arrangement_preserving_multiplicity() {
    // §5: resolution precedes staging, so a self-copy sees the pre-edit
    // state; the duplicate placement survives as a second run (S5/V2-style
    // multiplicity, no cross-placement coalesce of the same origin twice).
    let k = mem_kernel();
    let vs = insert_abc(&k);
    vs.copy(
        P1,
        &doc1(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 3),
        }],
    )
    .expect("self-copy commits");
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(m5.content_count(&doc1()), n(6));
    assert_eq!(m5.content_runs(&doc1()).len(), 2); // [ca1..3][ca1..3] — no value merge (S4)
    assert_eq!(read_v(&s, &doc1(), 1), b"a".to_vec());
    assert_eq!(read_v(&s, &doc1(), 4), b"a".to_vec());
}

#[test]
fn copy_rejects_each_documented_guard() {
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let un = a(&[1, 0, 1, 0, 9]);
    // Destination checks first (as INSERT, minus EmptyContent).
    assert!(matches!(
        rejected(vs.copy(P1, &un, vp(1, 1), &[])),
        CopyError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(2, 1), &[])),
        CopyError::NotContentSubspace
    ));
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 2), &[])),
        CopyError::OutOfBounds
    ));
    // Subspace before bounds: the destination position is BOTH in the link
    // subspace and past doc2's only admissible boundary (n_C + 1 = 1).
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(2, 99), &[])),
        CopyError::NotContentSubspace
    ));
    let spec = |source: Address, span: Span| VSpec { source, span };
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 1), &[spec(un.clone(), vspan(1, 1, 1))])),
        CopyError::SourceNotRegistered
    ));
    // Destination before spec: a link-subspace destination beside a spec
    // whose source is unregistered. "Destination first, then per spec" is
    // the documented order; the other reading gives SourceNotRegistered.
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(2, 1), &[spec(un.clone(), vspan(1, 1, 1))])),
        CopyError::NotContentSubspace
    ));
    // NotOrdinalVSpan: a T12-legal but level-uniform [m, n] width is action-point-1 —
    // not an ordinal-level depth-2 V-span (Conflicts #7's precise verdict).
    let lu = Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12-legal");
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 1), &[spec(doc1(), lu)])),
        CopyError::NotOrdinalVSpan
    ));
    // NotOrdinalVSpan also on a T12-legal span whose WIDTH is deeper than two: its
    // start is a well-formed V-position and its width position 1 is zero, so
    // the width-length clause is the only thing refusing it — and admitting
    // it would resolve five ordinals for a span reaching [1, 6, 0].
    let deep_width = Span::new(t(&[1, 1]), t(&[0, 5, 0])).expect("T12-legal");
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 1), &[spec(doc1(), deep_width)])),
        CopyError::NotOrdinalVSpan
    ));
    // Content-residence guard (§5).
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 1), &[spec(doc1(), vspan(2, 1, 1))])),
        CopyError::SourceNotContentSubspace
    ));
    // Registered-but-content-empty source is a typed verdict, not a skip.
    assert!(matches!(
        rejected(vs.copy(P1, &doc1(), vp(1, 1), &[spec(doc2(), vspan(1, 1, 1))])),
        CopyError::EmptySource
    ));
    // Which of the per-spec verdicts wins, in each documented pair.
    // Shape before residence: this span is BOTH mis-shaped (action-point-1)
    // and in the link subspace, and the shape check runs first.
    let lu_link = Span::new(t(&[2, 1]), t(&[1, 0])).expect("T12-legal");
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 1), &[spec(doc1(), lu_link)])),
        CopyError::NotOrdinalVSpan
    ));
    // Residence before emptiness: doc2 is content-empty AND asked for in the
    // link subspace, and the residence check runs first.
    assert!(matches!(
        rejected(vs.copy(P1, &doc1(), vp(1, 1), &[spec(doc2(), vspan(2, 1, 1))])),
        CopyError::SourceNotContentSubspace
    ));
    // Shape before emptiness: doc2 is BOTH content-empty and asked for with
    // a mis-shaped span.
    let lu2 = Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12-legal");
    assert!(matches!(
        rejected(vs.copy(P1, &doc1(), vp(1, 1), &[spec(doc2(), lu2)])),
        CopyError::NotOrdinalVSpan
    ));
    // WHICH SPEC speaks when two are defective: the list is walked, and the
    // first spec to fail any guard decides. Here the FIRST spec's span is
    // mis-shaped and the SECOND spec's source is unregistered; the answer is
    // the first spec's verdict. Read the other way — guards outermost, specs
    // within — `SourceNotRegistered` would win, since it precedes
    // `NotOrdinalVSpan` in the per-spec order.
    let lu3 = Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12-legal");
    assert!(matches!(
        rejected(vs.copy(
            P1,
            &doc2(),
            vp(1, 1),
            &[spec(doc1(), lu3), spec(un.clone(), vspan(1, 1, 1))]
        )),
        CopyError::NotOrdinalVSpan
    ));
    // Span-level out-of-range stays accept-and-intersect: clipping to
    // nothing is EmptyResult…
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 1), &[spec(doc1(), vspan(1, 5, 2))])),
        CopyError::EmptyResult
    ));
    // …as is an empty spec list.
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 1), &[])),
        CopyError::EmptyResult
    ));
    // Two of COPY's guards are not exercised from here, both in `ops::tests`
    // instead. `DanglingSource` needs a world whose arrangement and content
    // store are seeded APART, which no engine reaches — every address this
    // one arranges was written by INSERT in the same composite, and `M5Rec`
    // cannot be built in a foreign crate. `TooManyRuns` needs a spec list
    // past `MAX_PLACED_RUNS`, which is a claim about the accumulator rather
    // than about this assembly.
}

// ---- §B DELETE ----

#[test]
fn delete_contracts_the_arrangement_and_touches_neither_content_nor_r() {
    // ASN-0117: gap closes (suffix reseats), content store untouched
    // (NonDestruction P0), R keeps the pair (P2) — which SHOWDELETIONS reads.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    vs.insert(
        P1,
        &doc1(),
        vp(1, 1),
        vec![val(b"a"), val(b"b"), val(b"c"), val(b"d"), val(b"e")],
    )
    .expect("insert commits");
    vs.delete(P1, &doc1(), vp(1, 2), n(2)).expect("delete commits");
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(m5.content_count(&doc1()), n(3));
    assert_eq!(read_v(&s, &doc1(), 1), b"a".to_vec());
    assert_eq!(read_v(&s, &doc1(), 2), b"d".to_vec()); // suffix shifted left
    assert_eq!(read_v(&s, &doc1(), 3), b"e".to_vec());
    // The deleted bytes are still in the permascroll.
    assert_eq!(
        s.world()
            .content()
            .value_at(ca(2).tumbler())
            .map(Val::as_bytes),
        Some(&b"b"[..])
    );
    // SHOWDELETIONS: ever-placed minus current image = [ca2, ca4).
    let d = m5.deletions(&doc1());
    let spans: Vec<Span> = d.iter().cloned().collect();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].start(), ca(2).tumbler());
    assert_eq!(spans[0].reach(), *ca(4).tumbler());
}

#[test]
fn delete_rejects_in_documented_order() {
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let un = a(&[1, 0, 1, 0, 9]);
    assert!(matches!(
        rejected(vs.delete(P1, &un, vp(1, 1), n(1))),
        DeleteError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.delete(P1, &doc1(), vp(2, 1), n(1))),
        DeleteError::NotContentSubspace
    ));
    assert!(matches!(
        rejected(vs.delete(P1, &doc1(), vp(1, 4), n(1))),
        DeleteError::NotArranged
    ));
    assert!(matches!(
        rejected(vs.delete(P1, &doc1(), vp(1, 2), n(3))),
        DeleteError::OutOfBounds
    ));
    assert!(matches!(
        rejected(vs.delete(P1, &doc1(), vp(1, 1), n(0))),
        DeleteError::EmptyWidth
    ));
    // Which wins when both the position and the width are bad: the position
    // check runs first, so an unarranged ordinal is reported as such even
    // when the width is zero.
    assert!(matches!(
        rejected(vs.delete(P1, &doc1(), vp(1, 9), n(0))),
        DeleteError::NotArranged
    ));
    // Subspace before position: the link subspace AND an ordinal no content
    // position holds — the subspace check runs first.
    assert!(matches!(
        rejected(vs.delete(P1, &doc1(), vp(2, 9), n(1))),
        DeleteError::NotContentSubspace
    ));
}

// ---- §B REARRANGE ----

#[test]
fn rearrange_pivot_exchanges_the_two_adjacent_regions() {
    // ASN-0119: 3 cuts [2,4,6] over a..e — α = {2,3}, β = {4,5} — tile to
    // a, d, e, b, c. Content, links, R untouched (pure permutation).
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    vs.insert(
        P1,
        &doc1(),
        vp(1, 1),
        vec![val(b"a"), val(b"b"), val(b"c"), val(b"d"), val(b"e")],
    )
    .expect("insert commits");
    vs.rearrange(P1, &doc1(), &[vp(1, 2), vp(1, 4), vp(1, 6)])
        .expect("pivot commits");
    let s = k.snapshot();
    let got: Vec<Vec<u8>> = (1..=5).map(|i| read_v(&s, &doc1(), i)).collect();
    assert_eq!(got, vec![b"a".to_vec(), b"d".to_vec(), b"e".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    assert_eq!(s.world().m5().content_count(&doc1()), n(5));
    assert!(s.world().m5().deletions(&doc1()).is_empty()); // range unchanged (RA1)
}

#[test]
fn rearrange_swap_exchanges_the_outer_regions_around_the_middle() {
    // ASN-0119: 4 cuts [1,2,3,4] — α = {1}, μ = {2}, β = {3} — tile to
    // c, b, a, d, e.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    vs.insert(
        P1,
        &doc1(),
        vp(1, 1),
        vec![val(b"a"), val(b"b"), val(b"c"), val(b"d"), val(b"e")],
    )
    .expect("insert commits");
    vs.rearrange(P1, &doc1(), &[vp(1, 1), vp(1, 2), vp(1, 3), vp(1, 4)])
        .expect("swap commits");
    let s = k.snapshot();
    let got: Vec<Vec<u8>> = (1..=5).map(|i| read_v(&s, &doc1(), i)).collect();
    assert_eq!(got, vec![b"c".to_vec(), b"b".to_vec(), b"a".to_vec(), b"d".to_vec(), b"e".to_vec()]);
}

#[test]
fn rearrange_rejects_in_documented_order() {
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let un = a(&[1, 0, 1, 0, 9]);
    assert!(matches!(
        rejected(vs.rearrange(P1, &un, &[vp(1, 1), vp(1, 2), vp(1, 3)])),
        RearrangeError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.rearrange(P1, &doc1(), &[vp(1, 1), vp(1, 2)])),
        RearrangeError::BadCutCount
    ));
    assert!(matches!(
        rejected(vs.rearrange(P1, &doc1(), &[vp(1, 2), vp(1, 2), vp(1, 3)])),
        RearrangeError::NotAscending
    ));
    assert!(matches!(
        rejected(vs.rearrange(P1, &doc1(), &[vp(2, 1), vp(1, 2), vp(1, 3)])),
        RearrangeError::NotContentSubspace
    ));
    // n_C = 3 ⇒ upper bound is 4.
    assert!(matches!(
        rejected(vs.rearrange(P1, &doc1(), &[vp(1, 1), vp(1, 2), vp(1, 5)])),
        RearrangeError::OutOfBounds
    ));
    // Which wins, in each documented pair. Count before ascent: two cuts,
    // descending.
    assert!(matches!(
        rejected(vs.rearrange(P1, &doc1(), &[vp(1, 2), vp(1, 1)])),
        RearrangeError::BadCutCount
    ));
    // Ascent before subspace: three cuts, out of order, with the middle one
    // in the link subspace.
    assert!(matches!(
        rejected(vs.rearrange(P1, &doc1(), &[vp(1, 2), vp(2, 1), vp(1, 3)])),
        RearrangeError::NotAscending
    ));
    // Subspace before bounds: ascending cuts, the first in the link
    // subspace, the last past doc1's upper bound of n_C + 1 = 4.
    assert!(matches!(
        rejected(vs.rearrange(P1, &doc1(), &[vp(2, 1), vp(1, 2), vp(1, 9)])),
        RearrangeError::NotContentSubspace
    ));
    // Bounds before emptiness, which is what makes `EmptyContentSubspace`
    // the defensive-completeness verdict its own doc says it is: doc2 is
    // registered and content-empty, so n_C + 1 = 1 admits only ordinal 1 and
    // the third cut trips OutOfBounds first. Transposing the two checks
    // would make an unreachable verdict reachable, and M10 would then have
    // to handle it.
    assert!(matches!(
        rejected(vs.rearrange(P1, &doc2(), &[vp(1, 1), vp(1, 2), vp(1, 3)])),
        RearrangeError::OutOfBounds
    ));
}

// ---- §B VERSION ----

#[test]
fn owned_version_shares_the_map_and_diverges_copy_on_write() {
    // ASN-0123: mint_version on the (d_src, 1) chain; the fork carries the
    // same V→I map; later edits diverge the fork only (V3/V11); the fork's
    // shared runs are R-recorded (J1★).
    let k = mem_kernel();
    let vs = insert_abc(&k);
    seat_link(&k, &doc1(), &a(&[1, 0, 1, 0, 1, 0, 2, 1])).expect("seat commits");
    let (fork, _) = vs
        .version(PrincipalId(1), &doc1())
        .expect("owned fork commits");
    assert_eq!(fork, vdoc());
    {
        let s = k.snapshot();
        let m5 = s.world().m5();
        assert_eq!(m5.content_runs(&fork), m5.content_runs(&doc1()));
        let cov = SpanSet::singleton(m5.content_runs(&doc1())[0].iextent());
        assert_eq!(m5.docs_ever_containing(&cov), vec![doc1(), vdoc()]);
        // V2: the snapshot is of the CONTENT subspace. The source's seated
        // link stays the source's — carried over it would sit in the fork
        // under an origin that is not the fork, which CL-OWN forbids.
        assert_eq!(m5.link_count(&fork), n(0));
        assert_eq!(m5.link_count(&doc1()), n(1));
    }
    // Edit the fork: its content chain mints LENGTH-9 elements; the source
    // is untouched.
    let (start, _) = vs
        .insert(P1, &fork, vp(1, 4), vec![val(b"z")])
        .expect("fork edit commits");
    assert_eq!(start, vca(1));
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(m5.content_count(&fork), n(4));
    assert_eq!(m5.content_count(&doc1()), n(3));
    assert_eq!(read_v(&s, &fork, 4), b"z".to_vec());
}

#[test]
fn cross_owner_version_mints_under_the_forkers_account() {
    // ASN-0123 P-tier: principal 2 (account [1,0,2]) forks doc1 — a fresh
    // document identity under ITS account, sharing doc1's content.
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let (fork, _) = vs
        .version(PrincipalId(2), &doc1())
        .expect("cross-owner fork commits");
    assert_eq!(fork, a(&[1, 0, 2, 0, 1]));
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(m5.content_runs(&fork), m5.content_runs(&doc1()));
}

#[test]
fn version_of_an_empty_source_has_a_zero_content_footprint() {
    // ASN-0123 V1: n = 0 — the fork exists (registered) with an empty
    // arrangement and no provenance.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    let (fork, _) = vs
        .version(PrincipalId(1), &doc2())
        .expect("empty-source fork commits");
    let s = k.snapshot();
    assert!(s.world().m3().is_registered_document(&fork));
    assert_eq!(s.world().m5().content_count(&fork), n(0));
    assert!(s.world().m5().content_runs(&fork).is_empty());
}

#[test]
fn version_rejects_unregistered_unknown_and_node_tier_callers() {
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let un = a(&[1, 0, 1, 0, 9]);
    assert!(matches!(
        rejected(vs.version(PrincipalId(1), &un)),
        VersionError::SourceNotRegistered
    ));
    assert!(matches!(
        rejected(vs.version(PrincipalId(99), &doc1())),
        VersionError::NotAPrincipal
    ));
    // Principal 0 is the bootstrap NODE-tier principal ([1], zeros = 0): a
    // cross-owner fork by it is outside VERSION's domain — rejected
    // explicitly, never as a downstream Mint(NotAnAccount).
    assert!(matches!(
        rejected(vs.version(PrincipalId(0), &doc1())),
        VersionError::NodeTierCrossOwner
    ));
    // Which wins when both are bad: registration first, so a fork aimed at
    // an address naming no document discloses nothing about the forker — the
    // caller here is a principal the registry does not know, and the verdict
    // is still about the source.
    assert!(matches!(
        rejected(vs.version(PrincipalId(99), &un)),
        VersionError::SourceNotRegistered
    ));
}

// ---- §B ownership gate (as amended 2026-08-16) ----

#[test]
fn edit_ops_reject_a_sibling_principal_and_commit_nothing() {
    // The probe matrix, store-level: sibling principal 2 (account [1,0,2])
    // against P1's doc1 — insert / delete / rearrange / copy-DEST all reject
    // NotOwner carrying doc1; each rejection is a clean no-op; the owner's
    // identical op still commits.
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let p2 = Caller::Principal(PrincipalId(2));
    let before = k.current_seq();
    assert!(matches!(
        rejected(vs.insert(p2, &doc1(), vp(1, 4), vec![val(b"x")])),
        InsertError::NotOwner(d) if d == doc1()
    ));
    assert!(matches!(
        rejected(vs.delete(p2, &doc1(), vp(1, 1), n(1))),
        DeleteError::NotOwner(d) if d == doc1()
    ));
    assert!(matches!(
        rejected(vs.rearrange(p2, &doc1(), &[vp(1, 1), vp(1, 2), vp(1, 3)])),
        RearrangeError::NotOwner(d) if d == doc1()
    ));
    assert!(matches!(
        rejected(vs.copy(
            p2,
            &doc1(),
            vp(1, 4),
            &[VSpec {
                source: doc1(),
                span: vspan(1, 1, 1),
            }]
        )),
        CopyError::NotOwner(d) if d == doc1()
    ));
    // The ω gate precedes every shape check INSERT makes: an empty value
    // list from a non-owner is refused as NotOwner, not as EmptyContent.
    assert!(matches!(
        rejected(vs.insert(p2, &doc1(), vp(1, 1), vec![])),
        InsertError::NotOwner(d) if d == doc1()
    ));
    assert_eq!(k.current_seq(), before, "ownership rejections leave no state change");
    vs.delete(P1, &doc1(), vp(1, 1), n(1))
        .expect("the owner's delete still commits");
}

#[test]
fn an_unregistered_document_never_yields_an_ownership_verdict() {
    // `gate_write`'s order, and the reason for it: a write aimed at an
    // address that names no document is refused for that, and the caller
    // learns nothing about who would have owned it. The caller MUST be one
    // that fails the ω check — ω of an unregistered address still resolves
    // by longest registered prefix, so P1 owns [1,0,1,0,9] and would pass,
    // leaving both orders agreeing on DocNotRegistered.
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let un = a(&[1, 0, 1, 0, 9]);
    let p2 = Caller::Principal(PrincipalId(2));
    assert!(matches!(
        rejected(vs.insert(p2, &un, vp(1, 1), vec![val(b"x")])),
        InsertError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.delete(p2, &un, vp(1, 1), n(1))),
        DeleteError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.rearrange(p2, &un, &[vp(1, 1), vp(1, 2), vp(1, 3)])),
        RearrangeError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.copy(
            p2,
            &un,
            vp(1, 1),
            &[VSpec {
                source: doc1(),
                span: vspan(1, 1, 1),
            }]
        )),
        CopyError::DocNotRegistered
    ));
}

#[test]
fn the_system_caller_bypasses_the_owner_check_but_not_registration() {
    // `Caller::System` is the in-process automation path (M9's rule firings
    // and predicate-def writes), exempt from ω by architecture rather than
    // by omission — it carries no principal, so ω could never match it. The
    // exemption is exactly one check wide: registration still gates.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    let (start, _) = vs
        .insert(Caller::System, &doc1(), vp(1, 1), vec![val(b"s")])
        .expect("the automation path writes without a principal");
    assert_eq!(start, ca(1));
    assert_eq!(
        k.snapshot().world().m5().point(&doc1(), &vp(1, 1)),
        Some(ca(1))
    );
    // And into a document owned by a different principal — the exemption is
    // not "System happens to own this one".
    let subdoc = a(&[1, 0, 1, 1, 0, 1]);
    vs.insert(Caller::System, &subdoc, vp(1, 1), vec![val(b"s")])
        .expect("no document's ω restricts the automation path");
    // Registration is not waived.
    assert!(matches!(
        rejected(vs.insert(Caller::System, &a(&[1, 0, 1, 0, 9]), vp(1, 1), vec![val(b"x")])),
        InsertError::DocNotRegistered
    ));
}

#[test]
fn ownership_is_exact_in_both_directions() {
    // Exclusive delegation (ASN-0042 O2/O3/O8): ω is EXACT account match,
    // never prefix containment — the parent account's principal does not own
    // the sub-delegated account's document, and the sub-account's principal
    // does not own the parent's.
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let sub = Caller::Principal(PrincipalId(3)); // account [1,0,1,1], under [1,0,1]
    let subdoc = a(&[1, 0, 1, 1, 0, 1]);
    // Sub-delegated child vs the parent's doc.
    assert!(matches!(
        rejected(vs.insert(sub, &doc1(), vp(1, 4), vec![val(b"x")])),
        InsertError::NotOwner(_)
    ));
    // Parent vs the child's doc.
    assert!(matches!(
        rejected(vs.insert(P1, &subdoc, vp(1, 1), vec![val(b"x")])),
        InsertError::NotOwner(_)
    ));
    // The sub-account's own principal edits its own doc.
    vs.insert(sub, &subdoc, vp(1, 1), vec![val(b"s")])
        .expect("sub-owner insert commits");
}

#[test]
fn copy_reads_foreign_sources_into_an_owned_destination() {
    // Transclusion stays unrestricted: only the DESTINATION is ω-gated.
    // Principal 2 forks the empty doc2 into its own account (denial-as-fork,
    // O10), then transcludes P1's doc1 content into it.
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let p2 = Caller::Principal(PrincipalId(2));
    let (fork, _) = vs
        .version(PrincipalId(2), &doc2())
        .expect("cross-owner fork commits");
    vs.copy(
        p2,
        &fork,
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 2),
        }],
    )
    .expect("foreign-SOURCE copy into an owned destination commits");
    let s = k.snapshot();
    assert_eq!(s.world().m5().content_count(&fork), n(2));
}

// ---- §C link seating ----

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
        let runs = m5.link_runs(&doc1());
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
}

// ---- §D/§E composed queries ----

#[test]
fn finddocscontaining_composes_candidates_with_the_project_filter() {
    // §9: docs_ever_containing is the historical superset (P2 keeps the
    // deleter as a candidate); project is the current-containment filter —
    // both off ONE snapshot.
    let k = mem_kernel();
    let vs = insert_abc(&k);
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 3),
        }],
    )
    .expect("copy commits");
    // doc1 deletes the region; doc2 still holds it.
    vs.delete(P1, &doc1(), vp(1, 1), n(3)).expect("delete commits");
    let s = k.snapshot();
    let m5 = s.world().m5();
    let region = SpanSet::singleton(
        Span::from_endpoints(ca(1).tumbler().clone(), ca(4).tumbler())
            .expect("well-formed I-extent"),
    );
    // Candidate superset: both docs have ever contained the region, doc1 as
    // FD-GHOST's ghost.
    assert_eq!(m5.docs_ever_containing(&region), vec![doc1(), doc2()]);
    // Current-containment narrows to doc2.
    assert!(m5.project(&doc1(), &region).is_empty());
    assert!(!m5.project(&doc2(), &region).is_empty());
    // And doc1's loss is exactly what SHOWDELETIONS reports.
    let d = m5.deletions(&doc1());
    let spans: Vec<Span> = d.iter().cloned().collect();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].start(), ca(1).tumbler());
}

#[test]
fn mixed_length_transclusion_flows_through_the_level_class_discipline() {
    // §2/§9: a document transcluding across heterogeneous-depth origins has
    // mixed-length covers; deletions differences per class, project stays
    // total under cross-length coverage.
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let (fork, _) = vs.version(PrincipalId(1), &doc1()).expect("fork commits");
    vs.insert(P1, &fork, vp(1, 4), vec![val(b"y"), val(b"z")])
        .expect("fork edit commits"); // mints vca(1..2), length 9
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[
            VSpec {
                source: doc1(),
                span: vspan(1, 1, 2),
            },
            VSpec {
                source: fork.clone(),
                span: vspan(1, 4, 2),
            },
        ],
    )
    .expect("mixed copy commits");
    {
        let s = k.snapshot();
        let m5 = s.world().m5();
        assert_eq!(m5.content_count(&doc2()), n(4));
        let runs = m5.content_runs(&doc2());
        assert_eq!(runs.len(), 2); // cross-length runs never coalesce
        assert_eq!(runs[0].i_start(), &ca(1));
        assert_eq!(runs[1].i_start(), &vca(1));
        // image hands back the RAW mixed-length cover.
        let cov = m5.image(&doc2(), &vspan(1, 1, 4));
        let lens: Vec<usize> = cov.iter().map(|s| s.start().len()).collect();
        assert_eq!(lens, vec![8, 9]);
        // project is fault-free under a cross-length prefix cover: doc1's
        // content-base subtree picks out only the length-8 positions.
        let base = SpanSet::singleton(subtree_of(&t(&[1, 0, 1, 0, 1, 0, 1])));
        let got = m5.project(&doc2(), &base);
        let spans: Vec<Span> = got.iter().cloned().collect();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].start(), &t(&[1, 1]));
        assert_eq!(spans[0].width(), &t(&[0, 2]));
    }
    // Delete everything in doc2: BOTH classes surface in deletions.
    vs.delete(P1, &doc2(), vp(1, 1), n(4)).expect("delete commits");
    let s = k.snapshot();
    let d = s.world().m5().deletions(&doc2());
    let mut lens: Vec<usize> = d.iter().map(|s| s.start().len()).collect();
    lens.sort_unstable();
    assert_eq!(lens, vec![8, 9]);
}

#[test]
fn reads_fold_an_absent_document_to_empty_results() {
    // §D/§E: absent doc ⇒ ⟨⟩/None/0 — M5 does not distinguish
    // registered-empty from unallocated (that is M6's, via M3).
    let k = mem_kernel();
    // doc1 is populated in BOTH subspaces and has a deletion on record, so
    // every answer below is about doc2's ABSENCE rather than about an empty
    // store: against a genesis world these reads would pass even if they
    // ignored the document they are asked about.
    let vs = insert_abc(&k);
    seat_link(&k, &doc1(), &a(&[1, 0, 1, 0, 1, 0, 2, 1])).expect("seat commits");
    vs.delete(P1, &doc1(), vp(1, 1), n(1)).expect("delete commits");
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert!(m5.resolve(&doc2(), &vspan(1, 1, 1)).is_empty());
    assert_eq!(m5.point(&doc2(), &vp(1, 1)), None);
    assert!(m5.content_runs(&doc2()).is_empty());
    assert!(m5.link_runs(&doc2()).is_empty());
    assert_eq!(m5.content_count(&doc2()), n(0));
    assert_eq!(m5.link_count(&doc2()), n(0));
    assert!(m5.deletions(&doc2()).is_empty());
    assert!(m5
        .project(&doc2(), &SpanSet::singleton(subtree_of(doc2().tumbler())))
        .is_empty());
    assert!(m5.docs_ever_containing(&SpanSet::empty()).is_empty());
    // The positive control: R is not empty, and the reads that answer ⟨⟩ for
    // doc2 answer for doc1 — so the sweep above is about the document asked
    // for, not about a store with nothing in it.
    let placed = SpanSet::singleton(
        Span::from_endpoints(ca(1).tumbler().clone(), ca(4).tumbler())
            .expect("well-formed I-extent"),
    );
    assert_eq!(m5.docs_ever_containing(&placed), vec![doc1()]);
    assert!(!m5.deletions(&doc1()).is_empty());
    assert_eq!(m5.content_count(&doc1()), n(2));
    assert_eq!(m5.link_count(&doc1()), n(1));
}

// ---- M2-driven recovery: checkpoint load + tail replay ----

#[test]
fn the_arrangement_survives_durable_recovery_by_checkpoint_and_replay() {
    // §10: M5 owns no recovery machinery — M2 loads the checkpoint
    // (deserializing the slice) and replays the tail through apply → apply_m5.
    // The insert rides the checkpoint path; the delete, the seat, the fork
    // and the post-fork source edit ride the replay path; the recovered
    // slice is byte-identical.
    let dir = tempdir().expect("tempdir");
    let link1 = a(&[1, 0, 1, 0, 1, 0, 2, 1]);
    let bytes_before;
    {
        let k = Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("open");
        let vs = Vstream::new(&k);
        vs.insert(P1, &doc1(), vp(1, 1), vec![val(b"a"), val(b"b"), val(b"c")])
            .expect("insert commits");
        k.checkpoint().expect("checkpoint");
        vs.delete(P1, &doc1(), vp(1, 2), n(1)).expect("delete commits");
        seat_link(&k, &doc1(), &link1).expect("seat commits");
        let (fork, _) = vs.version(PrincipalId(1), &doc1()).expect("fork commits");
        assert_eq!(fork, vdoc());
        // A source edit AFTER the fork: on replay the VersionSnapshot must
        // fold at its own journal slot and read doc1 as it was there, not as
        // the source ends up.
        vs.insert(P1, &doc1(), vp(1, 3), vec![val(b"d")])
            .expect("post-fork source edit commits");
        let s = k.snapshot();
        bytes_before = bincode::serialize(s.world().m5()).expect("slice serializes");
    }
    let k = Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("reopen");
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(
        bincode::serialize(m5).expect("slice serializes"),
        bytes_before
    );
    assert_eq!(m5.content_count(&doc1()), n(3));
    assert_eq!(m5.point(&doc1(), &vp(1, 2)), Some(ca(3)));
    assert_eq!(m5.link_count(&doc1()), n(1));
    let d = m5.deletions(&doc1());
    let spans: Vec<Span> = d.iter().cloned().collect();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].start(), ca(2).tumbler());
    // The fork replayed at ITS slot: it holds what doc1 held at the fork
    // point, not what doc1 holds now. Byte-identity above would fail either
    // way; these say which value is the right one.
    assert_eq!(m5.content_count(&vdoc()), n(2));
    assert_eq!(m5.point(&vdoc(), &vp(1, 1)), Some(ca(1)));
    assert_eq!(m5.point(&vdoc(), &vp(1, 2)), Some(ca(3)));
    assert_eq!(m5.point(&vdoc(), &vp(1, 3)), None);
    // The recovered arrangement still drives edits.
    let vs = Vstream::new(&k);
    vs.insert(P1, &doc1(), vp(1, 4), vec![val(b"e")])
        .expect("post-recovery insert commits");
}
