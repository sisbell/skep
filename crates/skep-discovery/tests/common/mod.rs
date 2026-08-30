//! Shared test scaffolding: a minimal engine-side world (the composition
//! contract's assembler role, in miniature) over M3 + M4 + M5 + M7 — exactly
//! the bound M8 queries under, plus M4 so INSERT can arrange content — and
//! address/type fixtures. Addresses follow M3's minted shapes: account
//! `[1,0,1]`, documents `[1,0,1,0,d]`, content elements `[doc·0·1·k]`, link
//! elements `[doc·0·2·k]`; the five reserved type addresses are the compiled
//! ghost tumblers (`ReservedAddrs::format` — owner ruling, 2026-08-26).

#![allow(dead_code)] // each integration test binary uses a subset


use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Span, Tumbler};
use skep_arrangement::{HasM5, M5Rec, M5State, Run, VPos, VSpec};
use skep_content::{ContentStore, ContentWrite, HasContent, Val};
use skep_kernel::{CheckpointPolicy, Durability, Kernel, KernelConfig, WorldState};
use skep_links::{
    enc, Endset, HasLinks, LinkRec, LinkState,
};
use skep_namespace::{HasM3, M3Rec, M3State, PrincipalId};

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
    M3(M3Rec),
    Content(ContentWrite),
    M5(M5Rec),
    Links(LinkRec),
}

impl WorldState for World {
    type Record = Record;
    fn apply(&self, r: &Record) -> World {
        match r {
            Record::M3(x) => World {
                m3: self.m3.apply_m3(x),
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
        Record::M3(r)
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

/// An UNREGISTERED document address: `[1,0,1,0,7]` (the account chain's
/// frontier is 2, so 7 is beyond it).
pub fn d7() -> Address {
    a(&[1, 0, 1, 0, 7])
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

/// Reserved type address `k` — ghost tumbler `[1,1,0,1,0,1,0,1,k]` (the
/// compiled format constants for k = 1..=5; higher ordinals are ordinary
/// unregistered numbers).
pub fn ra(k: u32) -> Address {
    a(&[1, 1, 0, 1, 0, 1, 0, 1, k])
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

/// An arrangement run (M5's checked constructor).
pub fn run(start: &Address, width: u32) -> Run {
    Run::new(start.clone(), n(width)).expect("element-level start with width ≥ 1 is a valid Run")
}

// ─────────────────────────── the format type set ────────────────────────────

/// The one relation type the discovery tests deposit under — an ordinary
/// unregistered NUMBER (a type is a number; the class-keyed reads serve it
/// verbatim), carried into tuples through MAKELINK's open surface, since the
/// managed gate admits only the shipped Unary classes in this format.
pub fn rel_ty() -> Endset {
    enc(&[ra(10)])
}

// ─────────────────────────────── world assembly ─────────────────────────────

/// An M3 slice with a principal-owned account and two registered documents,
/// built by folding exactly the records M3's own `delegate`/
/// `create_new_document` would stage.
pub fn seeded_m3() -> M3State {
    M3State::genesis()
        .apply_m3(&M3Rec::Allocate { addr: a(&[1, 0, 1]) })
        .apply_m3(&M3Rec::RegisterPrincipal {
            prefix: a(&[1, 0, 1]),
            id: PrincipalId(1),
        })
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 1]),
        })
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 2]),
        })
}

pub fn genesis_world() -> World {
    World {
        m3: seeded_m3(),
        content: ContentStore::default(),
        m5: M5State::genesis(),
        links: LinkState::genesis(),
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

/// The write-fixture caller (ownership ruling, 2026-08-16): this crate
/// tests the READ layer — its writes are harness seeding, run on the
/// automation path, so the ω gate (the write stores' own concern) never
/// shapes a discovery verdict.
pub const SYS: skep_arrangement::Caller = skep_arrangement::Caller::System;

/// Seed `count` one-byte content values into `doc`'s content subspace via
/// M5's INSERT composite (so the discovery queries have arranged content).
pub fn seed_content(k: &Kernel<World>, doc: &Address, count: u32) {
    let vals: Vec<Val> = (0..count).map(|i| Val::new(vec![b'a' + i as u8])).collect();
    skep_arrangement::Vstream::new(k)
        .insert(SYS, doc, vp(1, 1), vals)
        .expect("test content INSERT succeeds");
}
