//! Shared test scaffolding: a minimal engine-side world (the composition
//! contract's assembler role, in miniature) over M3 + M4 + M5 + M7, the
//! genesis type config M9's catalog projects from, and a `Coordinator`
//! constructor wiring the engine-injected pieces (the shared registry and the
//! two op-handle factories). Address fixtures follow M3's minted shapes.

#![allow(dead_code)] // each integration test binary uses a subset

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Tumbler};
use skep_arrangement::{HasM5, M5Rec, M5State, VPos, Vstream};
use skep_content::{ContentStore, ContentWrite, HasContent, Val};
use skep_coordination::Coordinator;
use skep_kernel::{CheckpointPolicy, Durability, Kernel, KernelConfig, WorldState};
use skep_links::{
    enc, Behavior, Endset, HasLinks, LinkRec, LinkState, LinkStore, Registration, ReservedAddrs,
    Shape, TypeDecl, TypeRegistry,
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
    Ns(M3Rec),
    Content(ContentWrite),
    M5(M5Rec),
    Links(LinkRec),
}

impl WorldState for World {
    type Record = Record;
    fn apply(&self, r: &Record) -> World {
        match r {
            Record::Ns(x) => World { m3: self.m3.apply_ns(x), ..self.clone() },
            Record::Content(x) => World { content: self.content.apply_write(x), ..self.clone() },
            Record::M5(x) => World { m5: self.m5.apply_m5(x), ..self.clone() },
            Record::Links(x) => World { links: self.links.apply_link(x), ..self.clone() },
        }
    }
    fn rebuild_derived(self) -> Self {
        let World { m3, content, m5, links } = self;
        World { m3, content, m5: m5.rebuild_derived(), links: links.rebuild_derived() }
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

/// doc1 content element `k`.
pub fn ca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 1, ordinal])
}

/// doc1 link element `k`.
pub fn la(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 2, ordinal])
}

/// Reserved/app type address `k` — element-level in subspace 9 (outside
/// {s_C, s_L}: reserved-isolation).
pub fn ra(k: u32) -> Address {
    a(&[9, 0, 9, 0, 9, 0, 9, k])
}

pub fn vp(subspace: u32, ordinal: u32) -> VPos {
    VPos { subspace: n(subspace), ordinal: n(ordinal) }
}

// ───────────────────────────── genesis type config ─────────────────────────

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
pub fn marker_ty() -> Endset {
    enc(&[ra(14)]) // Unary, idem⊤ — the canonical Marker class
}

pub fn decls() -> Vec<TypeDecl> {
    vec![
        TypeDecl {
            key: rel_ty(),
            reg: Registration { shape: Shape::Binary, idem: true, behaviors: im::OrdSet::new() },
        },
        TypeDecl {
            key: multi_ty(),
            reg: Registration { shape: Shape::Multi, idem: false, behaviors: im::OrdSet::new() },
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
        TypeDecl {
            key: marker_ty(),
            reg: Registration { shape: Shape::Unary, idem: true, behaviors: im::OrdSet::new() },
        },
    ]
}

// ─────────────────────────────── world assembly ─────────────────────────────

/// An M3 slice with a principal-owned account and two registered documents,
/// built by folding exactly the records M3's own ops would stage.
pub fn seeded_m3() -> M3State {
    M3State::genesis()
        .apply_ns(&M3Rec::Allocate { addr: a(&[1, 0, 1]) })
        .apply_ns(&M3Rec::RegisterPrincipal { prefix: a(&[1, 0, 1]), id: PrincipalId(1) })
        .apply_ns(&M3Rec::Allocate { addr: a(&[1, 0, 1, 0, 1]) })
        .apply_ns(&M3Rec::Allocate { addr: a(&[1, 0, 1, 0, 2]) })
}

pub fn genesis_world() -> World {
    World {
        m3: seeded_m3(),
        content: ContentStore::default(),
        m5: M5State::genesis(),
        links: LinkState::genesis(reserved(), decls()).expect("test genesis type config is valid"),
    }
}

/// An in-memory kernel over the seeded genesis world.
pub fn kernel() -> Arc<Kernel<World>> {
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
    };
    Arc::new(Kernel::open(cfg, genesis_world()).expect("in-memory open cannot fail"))
}

/// The ONE engine-built registry (the test assembler's copy of the
/// genesis-sealed config — same validated inputs as `LinkState::genesis`).
pub fn registry() -> Arc<TypeRegistry> {
    Arc::new(TypeRegistry::build(reserved(), decls()).expect("test genesis type config is valid"))
}

fn mk_vs(k: &Kernel<World>) -> Vstream<'_, World> {
    Vstream::new(k)
}

fn mk_ls(k: &Kernel<World>) -> LinkStore<'_, World> {
    LinkStore::new(k)
}

/// The engine-assembled Coordinator over the shared kernel.
pub fn coord(k: &Arc<Kernel<World>>) -> Coordinator<World> {
    try_coord(k, registry(), reserved(), decls())
        .expect("the catalog projection validates against the same genesis config")
}

/// Assembly with caller-controlled (registry, reserved, decls) — the
/// validate-once-or-fail projection under test.
pub fn try_coord(
    k: &Arc<Kernel<World>>,
    registry: Arc<TypeRegistry>,
    reserved: ReservedAddrs,
    decls: Vec<TypeDecl>,
) -> Result<Coordinator<World>, skep_coordination::CatalogError> {
    Coordinator::new(
        Arc::clone(k),
        registry,
        reserved,
        decls,
        Box::new(mk_vs),
        Box::new(mk_ls),
    )
}

/// A LinkStore handle for direct upstream writes in tests.
pub fn links(k: &Arc<Kernel<World>>) -> LinkStore<'_, World> {
    LinkStore::new(k.as_ref())
}

/// Insert one raw content Val into `doc` (M5's placement composite) and
/// return its start address. Runs as `System` — harness seeding, the same
/// path M9's own writes take.
pub fn insert_raw(k: &Arc<Kernel<World>>, doc: &Address, bytes: Vec<u8>) -> Address {
    let snap = k.snapshot();
    let n_c = snap.world().m5().content_count(doc);
    let at = VPos { subspace: n(1), ordinal: n_c + n(1) };
    let (start, _) = Vstream::new(k.as_ref())
        .insert(skep_links::Caller::System, doc, at, vec![Val::new(bytes)])
        .expect("test content INSERT succeeds");
    start
}
