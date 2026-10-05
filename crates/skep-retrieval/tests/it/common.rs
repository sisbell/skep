//! The minimal engine assembly every suite runs on — the toy `World`/`Rec`
//! pair the composition contract prescribes — and the addresses, spans and
//! fixtures the suites share. All state is arranged through M5's real
//! `Vstream` ops, since `M5Rec` is sealed to foreign crates.

use std::fmt;

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Span, Tumbler};
use skep_arrangement::{
    deposit_class_types, Caller, Deposit, HasM5, M5State, VPos, VSpec, Vstream,
};
use skep_content::{ContentStore, ContentWrite, HasContent, Val};
use skep_kernel::{CheckpointPolicy, Durability, Kernel, KernelConfig, SaltSource, WorldState};
use skep_namespace::{HasM3, M3Rec, M3State, PrincipalId};
use skep_retrieval::{RegionSpec, Spec};

// ---- the minimal engine assembly (composition contract) ----

#[derive(Clone, Serialize, Deserialize)]
pub struct World {
    m3: M3State,
    content: ContentStore,
    m5: M5State,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Rec {
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

pub fn t(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
}

pub fn a(comps: &[u32]) -> Address {
    validate(t(comps)).expect("test addresses are T4-valid")
}

pub fn n(x: u32) -> Nat {
    Nat::from(x)
}

pub fn doc1() -> Address {
    a(&[1, 0, 1, 0, 1])
}

pub fn doc2() -> Address {
    a(&[1, 0, 1, 0, 2])
}

/// Never registered.
pub fn unregistered() -> Address {
    a(&[1, 0, 1, 0, 9])
}

/// A second never-registered document, so a two-document rejection can say
/// WHICH one it named.
pub fn unregistered2() -> Address {
    a(&[1, 0, 1, 0, 8])
}

/// doc1's content element at `ordinal` (length 8), M3's minted shape.
pub fn ca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 1, ordinal])
}

/// doc2's content element at `ordinal` — doc2's OWN minted content, on a
/// different I-chain from doc1's [`ca`].
pub fn doc2_ca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 2, 0, 1, ordinal])
}

/// doc1's link element at `ordinal`.
pub fn la(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 2, ordinal])
}

/// doc2's link element at `ordinal`.
pub fn doc2_la(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 2, 0, 2, ordinal])
}

/// Document 3 — principal 1's PUBLISHED edition `[1,0,1,0,3]`: the one owned
/// source `version` admits (PUB-2.9), whose content enters by declared
/// deposit alone (PUB-2.59).
pub fn pdoc() -> Address {
    a(&[1, 0, 1, 0, 3])
}

/// The version fork of pdoc (`(d_src, 1)` chain) and its length-9 content
/// elements — the mixed-length transclusion case.
pub fn vdoc() -> Address {
    a(&[1, 0, 1, 0, 3, 1])
}
pub fn vca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 3, 1, 0, 1, ordinal])
}

/// The fork's link element at `ordinal` — a link whose HOME is the fork.
pub fn vla(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 3, 1, 0, 2, ordinal])
}

pub fn vp(subspace: u32, ordinal: u32) -> VPos {
    VPos {
        subspace: n(subspace),
        ordinal: n(ordinal),
    }
}

/// An ordinal-level depth-2 V-span `[subspace, ordinal]` × `[0, count]`.
pub fn vspan(subspace: u32, ordinal: u32, count: u32) -> Span {
    Span::new(t(&[subspace, ordinal]), t(&[0, count])).expect("ordinal-level V-span is T12-valid")
}

pub fn val(b: &[u8]) -> Val {
    Val::new(b)
}

/// The deposit declaration every declared fixture and test carries: ENROLL's
/// type, the first of M5's deposit class types (PUB-2.11, RES-261). What they
/// deposit is prose (`b"a"`, `b"z"`) — PUB-2.60's residue, bytes of the
/// depositor's choosing under a declared class type — which the door admits
/// on the type alone.
pub fn declared() -> Deposit {
    Deposit::Declared(deposit_class_types()[0].clone())
}

/// The seeded owner of doc1/doc2 — write fixtures run under it, so the ω
/// gate (ownership ruling, 2026-08-16) is exercised, not skipped.
pub const P1: Caller = Caller::Principal(PrincipalId(1));

pub fn spec(doc: Address, span: Span) -> Spec {
    Spec { doc, span }
}

pub fn region_spec(doc: Address, spans: Vec<Span>) -> RegionSpec {
    RegionSpec { doc, spans }
}

/// A T12-legal but non-ordinal-level width (action point 1).
pub fn not_ordinal_level_span() -> Span {
    Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12-legal")
}

/// A well-formed depth-3 span — depth-INCOMPATIBLE, not malformed.
pub fn deep_span(subspace: u32) -> Span {
    Span::new(t(&[subspace, 1, 1]), t(&[0, 0, 1])).expect("T12-legal")
}

/// Unwrap Ok — `Result::expect` under one name, so the unwrap and its failure
/// message are uniform across all seven operations. The `Debug` bound is what
/// makes a failure name WHICH rejection fired rather than only that one did:
/// every M6 error renders, and a suite this size cannot afford a panic that
/// says nothing about the answer it got.
pub fn ok_of<T, E: fmt::Debug>(r: Result<T, E>) -> T {
    r.expect("expected Ok, got Err")
}

/// Unwrap Err, the mirror of [`ok_of`] — printing the answer that arrived
/// where a rejection was claimed.
pub fn err_of<T: fmt::Debug, E>(r: Result<T, E>) -> E {
    r.expect_err("expected Err, got Ok")
}

/// Genesis with M3 pre-seeded by folding exactly the records its own
/// delegate/create_new_document ops would stage: account [1,0,1] → principal
/// 1 (owns doc1, doc2, pdoc), account [1,0,2] → principal 2. doc1 and doc2
/// are PRIVATE drafts — the documents the suites' edits are admitted on
/// (PUB-2.11; doc1 as an explicit-`false` first mint, the state M3 produces
/// below the daemon's door) — and pdoc is a PUBLISHED edition. An account's
/// `Allocate` carries no publication state.
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
            addr: a(&[1, 0, 1, 0, 1]),
            published: false,
        })
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 2]),
            published: false,
        })
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 3]),
            published: true,
        });
    World {
        m3,
        content: ContentStore::default(),
        m5: M5State::genesis(),
    }
}

pub fn mem_kernel() -> Kernel<World> {
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    };
    Kernel::open(cfg, genesis()).expect("in-memory open")
}

/// doc1 arranged with content a, b, c (ca1..ca3).
pub fn insert3(k: &Kernel<World>) -> Vstream<'_, World> {
    let vs = Vstream::new(k);
    vs.insert(P1, &doc1(), vp(1, 1), vec![val(b"a"), val(b"b"), val(b"c")], Deposit::Undeclared)
        .expect("insert commits");
    vs
}

/// pdoc — the published edition — arranged with a, b, c: a DECLARED deposit
/// at its fresh positions, the one way content enters a published document
/// (PUB-2.59, PUB-9.13).
pub fn deposit3(k: &Kernel<World>) -> Vstream<'_, World> {
    let vs = Vstream::new(k);
    vs.insert(P1, &pdoc(), vp(1, 1), vec![val(b"a"), val(b"b"), val(b"c")], declared())
        .expect("deposit commits");
    vs
}

/// doc1 = `[a, b, c]`; doc2 = `[x][ca1, ca2][ca1]` — its own content, then
/// two transclusions of doc1. doc2's content resolves to THREE runs and one
/// address (ca1) sits at two V-positions: the multi-block document every
/// per-run claim in the suites is about.
pub fn three_runs(k: &Kernel<World>) -> Vstream<'_, World> {
    let vs = insert3(k);
    vs.insert(P1, &doc2(), vp(1, 1), vec![val(b"x")], Deposit::Undeclared)
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
pub fn fanout_doc2(k: &Kernel<World>) -> Vstream<'_, World> {
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
    vs.insert(P1, &doc2(), vp(1, 3), vec![val(b"a")], Deposit::Undeclared)
        .expect("insert commits");
    vs
}
