//! Shared test scaffolding: a minimal engine-side world (the composition
//! contract's assembler role, in miniature) over M3 + M4 + M5 + M7, plus
//! address/type fixtures. Addresses follow M3's minted shapes: account
//! `[1,0,1]`, documents `[1,0,1,0,d]`, content elements `[doc·0·1·k]`, link
//! elements `[doc·0·2·k]`; reserved type addresses live in subspace 9 —
//! element-level, outside {s_C, s_L} (reserved-isolation).

#![allow(dead_code)] // each integration test binary uses a subset

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Span, Tumbler};
use skep_arrangement::{HasM5, M5Rec, M5State, VPos, VSpec};
use skep_content::{ContentStore, ContentWrite, HasContent, Val};
use skep_kernel::{CheckpointPolicy, Durability, Kernel, KernelConfig, WorldState};
use skep_links::{
    enc, Behavior, Caller, Endset, HasLinks, LinkRec, LinkState, Registration, ReservedAddrs,
    Shape, TypeDecl,
};
use skep_namespace::{HasM3, M3Rec, M3State, PrincipalId};

/// The seeded owner of doc1/doc2 — every pre-ruling op runs under it, so
/// the ω gate is exercised on every path, not skipped.
pub const P1: Caller = Caller::Principal(PrincipalId(1));

/// The sibling principal (account [1,0,2]) — the ownership probes' foreign
/// caller.
pub const P2: Caller = Caller::Principal(PrincipalId(2));

// ───────────────────────── the assembled test world ─────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct World {
    pub m3: M3State,
    pub content: ContentStore,
    pub m5: M5State,
    pub links: LinkState,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Record {
    Ns(M3Rec),
    Content(ContentWrite),
    M5(M5Rec),
    Links(LinkRec),
}

impl WorldState for World {
    type Record = Record;
    fn apply(&self, r: &Record) -> World {
        match r {
            Record::Ns(x) => World {
                m3: self.m3.apply_ns(x),
                ..self.clone()
            },
            Record::Content(x) => World {
                content: self.content.apply_write(x),
                ..self.clone()
            },
            Record::M5(x) => World {
                m5: self.m5.apply_m5(x),
                ..self.clone()
            },
            Record::Links(x) => World {
                links: self.links.apply_link(x),
                ..self.clone()
            },
        }
    }
    fn rebuild_derived(self) -> Self {
        let World {
            m3,
            content,
            m5,
            links,
        } = self;
        World {
            m3,
            content,
            m5: m5.rebuild_derived(),
            links: links.rebuild_derived(),
        }
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
impl HasLinks for World {
    fn links(&self) -> &LinkState {
        &self.links
    }
}
impl From<M3Rec> for Record {
    fn from(r: M3Rec) -> Record {
        Record::Ns(r)
    }
}
impl From<ContentWrite> for Record {
    fn from(r: ContentWrite) -> Record {
        Record::Content(r)
    }
}
impl From<M5Rec> for Record {
    fn from(r: M5Rec) -> Record {
        Record::M5(r)
    }
}
impl From<LinkRec> for Record {
    fn from(r: LinkRec) -> Record {
        Record::Links(r)
    }
}

// ───────────────────────────── address fixtures ─────────────────────────────

pub fn t(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
}

pub fn a(comps: &[u32]) -> Address {
    validate(t(comps)).expect("test addresses are T4-valid")
}

pub fn n(x: u32) -> Nat {
    Nat::from(x)
}

/// Document 1: `[1,0,1,0,1]`.
pub fn doc1() -> Address {
    a(&[1, 0, 1, 0, 1])
}

/// Document 2: `[1,0,1,0,2]`.
pub fn doc2() -> Address {
    a(&[1, 0, 1, 0, 2])
}

/// doc1 content element `k`: `[1,0,1,0,1,0,1,k]`.
pub fn ca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 1, ordinal])
}

/// doc1 link element `k`: `[1,0,1,0,1,0,2,k]`.
pub fn la(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 2, ordinal])
}

/// doc2 link element `k`: `[1,0,1,0,2,0,2,k]`.
pub fn la2(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 2, 0, 2, ordinal])
}

/// Reserved/app type address `k` — element-level in subspace 9 (outside
/// {s_C, s_L}, the reserved-isolation precondition): `[9,0,9,0,9,0,9,k]`.
pub fn ra(k: u32) -> Address {
    a(&[9, 0, 9, 0, 9, 0, 9, k])
}

/// An ordinal-level depth-2 V-span `[subspace, ordinal] × [0, count]`.
pub fn vspan(subspace: u32, ordinal: u32, count: u32) -> Span {
    Span::new(t(&[subspace, ordinal]), t(&[0, count])).expect("ordinal-level V-span is T12-valid")
}

/// A depth-2 V-position.
pub fn vp(subspace: u32, ordinal: u32) -> VPos {
    VPos {
        subspace: n(subspace),
        ordinal: n(ordinal),
    }
}

/// One COPY/MAKELINK source spec.
pub fn spec(source: &Address, subspace: u32, ordinal: u32, count: u32) -> VSpec {
    VSpec {
        source: source.clone(),
        span: vspan(subspace, ordinal, count),
    }
}

// ───────────────────────────── genesis type config ─────────────────────────

/// The five reserved type addresses (ordinals 1–5 in subspace 9).
pub fn reserved() -> ReservedAddrs {
    ReservedAddrs {
        pred_def: ra(1),
        pred_stable: ra(2),
        retired: ra(3),
        supersedes: ra(4),
        retraction: ra(5),
    }
}

/// App type keys (ordinals ≥ 10 in subspace 9).
pub fn rel_ty() -> Endset {
    enc(&[ra(10)]) // Binary, idem⊤
}
pub fn multi_ty() -> Endset {
    enc(&[ra(11)]) // Multi, idem⊥
}
pub fn bh4_ty() -> Endset {
    enc(&[ra(12)]) // Unary, idem⊥, Age
}
pub fn bh3_ty() -> Endset {
    enc(&[ra(13)]) // Binary, idem⊥, ReverseLookup
}

pub fn decls() -> Vec<TypeDecl> {
    vec![
        TypeDecl {
            key: rel_ty(),
            reg: Registration {
                shape: Shape::Binary,
                idem: true,
                behaviors: im::OrdSet::new(),
            },
        },
        TypeDecl {
            key: multi_ty(),
            reg: Registration {
                shape: Shape::Multi,
                idem: false,
                behaviors: im::OrdSet::new(),
            },
        },
        TypeDecl {
            key: bh4_ty(),
            reg: Registration {
                shape: Shape::Unary,
                idem: false,
                behaviors: im::OrdSet::unit(Behavior::Age),
            },
        },
        TypeDecl {
            key: bh3_ty(),
            reg: Registration {
                shape: Shape::Binary,
                idem: false,
                behaviors: im::OrdSet::unit(Behavior::ReverseLookup),
            },
        },
    ]
}

// ─────────────────────────────── world assembly ─────────────────────────────

/// An M3 slice with a principal-owned account and two registered documents,
/// built by folding exactly the records M3's own `delegate`/
/// `create_new_document` would stage (the M5 testutil precedent), plus a
/// SIBLING account [1,0,2] → principal 2 with its own document [1,0,2,0,1]
/// — the ownership-gate probe fixtures (as amended 2026-08-16).
pub fn seeded_m3() -> M3State {
    M3State::genesis()
        .apply_ns(&M3Rec::Allocate { addr: a(&[1, 0, 1]) })
        .apply_ns(&M3Rec::RegisterPrincipal {
            prefix: a(&[1, 0, 1]),
            id: PrincipalId(1),
        })
        .apply_ns(&M3Rec::Allocate { addr: a(&[1, 0, 2]) })
        .apply_ns(&M3Rec::RegisterPrincipal {
            prefix: a(&[1, 0, 2]),
            id: PrincipalId(2),
        })
        .apply_ns(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 1]),
        })
        .apply_ns(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 2]),
        })
        .apply_ns(&M3Rec::Allocate {
            addr: a(&[1, 0, 2, 0, 1]),
        })
}

/// The sibling principal's document: `[1,0,2,0,1]` (owned by principal 2).
pub fn sib_doc() -> Address {
    a(&[1, 0, 2, 0, 1])
}

pub fn genesis_world() -> World {
    World {
        m3: seeded_m3(),
        content: ContentStore::default(),
        m5: M5State::genesis(),
        links: LinkState::genesis(reserved(), decls()).expect("test genesis type config is valid"),
    }
}

/// An in-memory kernel over the seeded genesis world (MIC-faithful; no
/// journal, no recovery).
pub fn kernel() -> Kernel<World> {
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
    };
    Kernel::open(cfg, genesis_world()).expect("in-memory open cannot fail")
}

/// Seed `count` one-byte content values into `doc`'s content subspace via
/// M5's INSERT composite (so MAKELINK has arranged content to resolve).
/// Runs as `System`: harness seeding, not an attributed write — the doc
/// under seed may belong to any fixture principal.
pub fn seed_content(k: &Kernel<World>, doc: &Address, count: u32) {
    let vals: Vec<Val> = (0..count).map(|i| Val::new(vec![b'a' + i as u8])).collect();
    skep_arrangement::Vstream::new(k)
        .insert(Caller::System, doc, vp(1, 1), vals)
        .expect("test content INSERT succeeds");
}
