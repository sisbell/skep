//! Shared test scaffolding: a minimal engine-side world (the composition
//! contract's assembler role, in miniature) over M3 + M4 + M5 + M7 and a
//! `Coordinator` constructor wiring the engine-injected pieces (M7's own
//! format registry, the compiled constant the owner ruling of 2026-08-26
//! pins, and the two op-handle factories). Address fixtures follow
//! M3's minted shapes; the catalog's population is the shipped five, so
//! rule/marker fixtures lean on the three Unary idem⊤ classes and TO-bearing
//! tuples enter cataloged classes through the open surface.

#![allow(dead_code)] // each integration test binary uses a subset

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Tumbler};
use skep_arrangement::{HasM5, M5Rec, M5State, VPos, Vstream};
use skep_content::{ContentStore, ContentWrite, HasContent, Val};
use skep_coordination::Coordinator;
use skep_kernel::{CheckpointPolicy, Durability, Kernel, KernelConfig, WorldState};
use skep_links::{
    enc, Caller, Endset, HasLinks, LinkRec, LinkState, LinkWriter, SlotArg, TypeRegistry,
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
            Record::M3(x) => World { m3: self.m3.apply_m3(x), ..self.clone() },
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

/// doc1 content element `k`.
pub fn ca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 1, ordinal])
}

/// doc1 link element `k`.
pub fn la(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 2, ordinal])
}

/// Reserved type address `k` — ghost tumbler `[1,1,0,1,0,1,0,1,k]`
/// (`ReservedAddrs::format` assignment order for k = 1..=5: pred_def,
/// pred_stable, retired, supersedes, retraction; higher ordinals are
/// uncataloged numbers).
pub fn ra(k: u32) -> Address {
    a(&[1, 1, 0, 1, 0, 1, 0, 1, k])
}

pub fn vp(subspace: u32, ordinal: u32) -> VPos {
    VPos { subspace: n(subspace), ordinal: n(ordinal) }
}

// ─────────────────────────── the format type set ────────────────────────────

/// The cataloged classes the tests lean on. `pred_def`/`pred_stable` are the
/// two plain Unary idem⊤ classes; `retired` doubles as the MARKER class —
/// the one cataloged Unary idem⊤ class outside the PredLayer pair, which the
/// Marker action's guards demand.
pub fn pred_def_ty() -> Endset {
    enc(&[ra(1)])
}
pub fn pred_stable_ty() -> Endset {
    enc(&[ra(2)])
}
pub fn marker_ty() -> Endset {
    enc(&[ra(3)]) // the shipped Retired class
}
pub fn retraction_ty() -> Endset {
    enc(&[ra(5)])
}

/// An UNCATALOGED type number — `type_check`'s `UnregisteredType` probe and
/// the open surface's verbatim deposits.
pub fn uncataloged_ty(k: u32) -> Endset {
    enc(&[ra(k)])
}

// ─────────────────────────────── world assembly ─────────────────────────────

/// An M3 slice with a principal-owned account and two registered documents,
/// built by folding exactly the records M3's own ops would stage.
pub fn seeded_m3() -> M3State {
    M3State::genesis()
        .apply_m3(&M3Rec::Allocate { addr: a(&[1, 0, 1]) })
        .apply_m3(&M3Rec::RegisterPrincipal { prefix: a(&[1, 0, 1]), id: PrincipalId(1) })
        .apply_m3(&M3Rec::Allocate { addr: a(&[1, 0, 1, 0, 1]) })
        .apply_m3(&M3Rec::Allocate { addr: a(&[1, 0, 1, 0, 2]) })
}

pub fn genesis_world() -> World {
    World {
        m3: seeded_m3(),
        content: ContentStore::default(),
        m5: M5State::genesis(),
        links: LinkState::genesis(),
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

/// The registry the `Coordinator` is injected with: M7's own module constant,
/// cloned — so this fixture runs against the instance M7's fold and write
/// gates run against, which is what the engine hands a real `Coordinator`.
pub fn registry() -> Arc<TypeRegistry> {
    Arc::clone(skep_links::registry())
}

fn mk_vs(k: &Kernel<World>) -> Vstream<'_, World> {
    Vstream::new(k)
}

fn mk_ls(k: &Kernel<World>) -> LinkWriter<'_, World> {
    LinkWriter::new(k)
}

/// The engine-assembled Coordinator over the shared kernel — infallible: the
/// catalog is a pure read of the injected registry.
pub fn coord(k: &Arc<Kernel<World>>) -> Coordinator<World> {
    Coordinator::new(Arc::clone(k), registry(), Box::new(mk_vs), Box::new(mk_ls))
}

/// A TO-bearing tuple in a CATALOGED class, deposited through the open
/// surface (the managed gate admits only Unary tuples in this format, and
/// the open surface is shape-blind) — the M9 domain/eval tests' way of
/// putting a relation with a G slot into a class the catalog speaks about.
pub fn deposit_rel(k: &Arc<Kernel<World>>, ty: u32, from: &Address, to: &Address) -> Address {
    LinkWriter::new(k.as_ref())
        .makelink(
            Caller::System,
            &doc1(),
            SlotArg::Addrs(vec![from.clone()]),
            SlotArg::Addrs(vec![to.clone()]),
            SlotArg::Addrs(vec![ra(ty)]),
        )
        .expect("open-surface deposit")
        .0
}

/// A LinkWriter handle for direct upstream writes in tests.
pub fn links(k: &Arc<Kernel<World>>) -> LinkWriter<'_, World> {
    LinkWriter::new(k.as_ref())
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
