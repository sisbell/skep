//! Shared test scaffolding: a minimal engine-side world (the composition
//! contract's assembler role, in miniature) over M3 + M4 + M5 + M7, plus
//! address/type fixtures. Addresses follow M3's minted shapes: account
//! `[1,0,1]`, documents `[1,0,1,0,d]`, content elements `[doc·0·1·k]`, link
//! elements `[doc·0·2·k]`. The five reserved type addresses are the compiled
//! ghost tumblers (`ReservedAddrs::format` — owner ruling, 2026-08-26); the
//! registry's population is exactly the shipped five, so a managed emit
//! lands on a shipped Unary idem⊤ class and anything else is unregistered.

#![allow(dead_code)] // each integration test binary uses a subset

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Span, Tumbler};
use skep_arrangement::{HasM5, M5Rec, M5State, VPos, VSpec};
use skep_content::{ContentStore, ContentWrite, HasContent, Val};
use skep_kernel::{CheckpointPolicy, Durability, Kernel, KernelConfig, WorldState};
use skep_links::{enc, Caller, Endset, HasLinks, LinkRec, LinkState, ReservedAddrs};
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

/// Reserved type address `k` — ghost tumbler `[1,1,0,1,0,1,0,1,k]`, content
/// position `k` of the ghost doc. DOMAIN `k = 1..=5`: those are the compiled
/// format constants, in `ReservedAddrs::format`'s assignment order (pred_def,
/// pred_stable, retired, supersedes, retraction), and the ghost region has
/// exactly those five names (M3's `GHOST_POSITIONS`). A position past it is
/// ordinary mintable content of the operator's own document — reserved by
/// nothing and ghost in no sense — so a test wanting an arbitrary type NAME
/// asks [`unregistered_ta`] instead.
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

// ─────────────────────────── the format type set ────────────────────────────

/// The five reserved type addresses — the compiled format constants.
pub fn reserved() -> ReservedAddrs {
    ReservedAddrs::format()
}

/// The registered Unary idem⊤ classes an ordinary managed emit may land on:
/// `PredDef`/`PredStable`/`Retired` (the `Retraction` and `Supersedes`
/// classes are sole-writer-fenced at `emit`).
pub fn pred_def_ty() -> Endset {
    enc(&[ra(1)])
}
pub fn pred_stable_ty() -> Endset {
    enc(&[ra(2)])
}
pub fn retired_ty() -> Endset {
    enc(&[ra(3)])
}
/// The two fenced shipped classes, for the tests that probe the fences and
/// the sole-writer surfaces.
pub fn supersedes_ty() -> Endset {
    enc(&[ra(4)])
}
pub fn retraction_ty() -> Endset {
    enc(&[ra(5)])
}

/// An UNREGISTERED type's address — an ordinary content address of a foreign
/// document (`[1,0,9,0,9,0,1,k]`). A type is a number: the open surface
/// deposits it verbatim, and the managed surface refuses it `NotRegistered`,
/// because the registry's population is the shipped five and nothing else.
pub fn unregistered_ta(k: u32) -> Address {
    a(&[1, 0, 9, 0, 9, 0, 1, k])
}

/// [`unregistered_ta`] as the one-address type endset the reads take.
pub fn unregistered_ty(k: u32) -> Endset {
    enc(&[unregistered_ta(k)])
}

// ─────────────────────────────── world assembly ─────────────────────────────

/// An M3 slice with a principal-owned account and two registered documents,
/// built by folding exactly the records M3's own `delegate`/
/// `create_new_document` would stage (the M5 testutil precedent), plus a
/// SIBLING account [1,0,2] → principal 2 with its own document [1,0,2,0,1]
/// — the ownership-gate probe fixtures (as amended 2026-08-16). The
/// publication bits are the flagless create path's (PUB-8.21): each
/// account's first document born published, [1,0,1,0,2] private; an
/// account's `Allocate` carries no publication state.
pub fn seeded_m3() -> M3State {
    M3State::genesis()
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
            published: true,
        })
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 2]),
            published: false,
        })
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 2, 0, 1]),
            published: true,
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

/// Seed `doc` with `runs` content elements arranged as `runs` SEPARATE
/// I-runs: one INSERT of one value at V-position 1 each time, so every new
/// element takes a fresh I-address ahead of everything already there and the
/// V-order descends through I-space. No two neighbours are I-contiguous, so
/// `resolve` coalesces nothing and one spec over the whole document yields
/// one run per element — the expansion `seed_content`'s single wide INSERT
/// (one run, whatever its width) cannot produce.
pub fn fragment_content(k: &Kernel<World>, doc: &Address, runs: u32) {
    for i in 0..runs {
        skep_arrangement::Vstream::new(k)
            .insert(
                Caller::System,
                doc,
                vp(1, 1),
                vec![Val::new(vec![b'a' + (i % 26) as u8])],
            )
            .expect("test content INSERT succeeds");
    }
}

/// COPY `src`'s first `width` V-positions to the front of `dst`, `times`
/// over. A copy carries the source's run decomposition with it, so `dst`
/// ends holding `times × runs(src)` runs for `times` transactions — the
/// multiplicative half of the amplification a `Resolve` slot inherits.
pub fn copy_prefix(k: &Kernel<World>, src: &Address, width: u32, dst: &Address, times: u32) {
    for _ in 0..times {
        skep_arrangement::Vstream::new(k)
            .copy(Caller::System, dst, vp(1, 1), &[spec(src, 1, 1, width)])
            .expect("test content COPY succeeds");
    }
}
