//! Shared test scaffolding: a minimal engine-side world (the composition
//! contract's assembler role, in miniature) over M3 + M4 + M5 + M7 — exactly
//! the bound M8 queries under, plus M4 so INSERT can arrange content — its
//! address/type fixtures, the suite's reads of its current state, and the
//! window law and wide endset more than one family reads. Addresses follow
//! M3's minted shapes: account
//! `[1,0,1]`, documents `[1,0,1,0,d]`, content elements `[doc·0·1·k]`, link
//! elements `[doc·0·2·k]`; the five reserved type addresses are the compiled
//! ghost tumblers (`ReservedAddrs::format` — owner ruling, 2026-08-26).

#![allow(dead_code)] // each integration test binary uses a subset


use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Span, SpanSet, Tumbler};
use skep_arrangement::{reading_surface, HasM5, M5Rec, M5State, Run, VPos, VSpec};
use skep_content::{ContentStore, ContentWrite, HasContent, Val};
use skep_discovery::{
    addressably_discoverable_from_on, count_ftt_on, count_v_on, delete_orphans_on,
    findlinks_ftt_on, findlinks_v_on, image_on, in_claims_on, out_claims_on, project_on,
    retrieve_endsets_on, window_ftt_on, window_v_on, Cursor, FourSet, OrphanError, OrphanReport,
    QueryError, SupClaim, Window,
};
use skep_kernel::{CheckpointPolicy, Durability, Kernel, KernelConfig, WorldState};
use skep_links::{
    enc, Endset, HasLinks, LinkRec, LinkState, LinkWriter, SlotArg, View,
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

/// The ALL-VISIBLE class the suite's M7 fixture writes run at (lane 3.3b):
/// this miniature world carries no publication state — M3's bit is folded
/// engine-side — so every document is readable to every caller here, and no
/// M8 verdict turns on what a writer could read.
pub static EVERYONE: fn(&World, &Address) -> bool = every_document;

fn every_document(_: &World, _: &Address) -> bool {
    true
}

/// The TOTAL predicate, admitting every home — the reader this suite's M8
/// reads run at, beside [`EVERYONE`] for its writes, so every link a query
/// finds is returned. It belongs to a harness, never a request: a request
/// without a principal reads as the GUEST, which admits published documents
/// alone.
pub fn every_home(_: &Address) -> bool {
    true
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

/// The PUBLISHED document: `[1,0,1,0,3]`. Its readers answer from its trunk
/// head once it has one (head-float, PUB-2.53), and content enters it only as
/// a declared deposit ([`seed_published_content`]).
pub fn pdoc() -> Address {
    a(&[1, 0, 1, 0, 3])
}

/// `pdoc`'s first trunk member, `[1,0,1,0,3,1]` — its head, once VERSION
/// mints it.
pub fn phead() -> Address {
    a(&[1, 0, 1, 0, 3, 1])
}

/// An UNREGISTERED document address: `[1,0,1,0,7]` (the account chain's
/// frontier is 3, so 7 is beyond it).
pub fn unregistered_doc() -> Address {
    a(&[1, 0, 1, 0, 7])
}

/// doc1 content element `k`: `[1,0,1,0,1,0,1,k]`.
pub fn ca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 1, ordinal])
}

/// pdoc content element `k`: `[1,0,1,0,3,0,1,k]` — minted under pdoc's own
/// content chain wherever the deposit that minted it was placed.
pub fn pca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 3, 0, 1, ordinal])
}

/// doc2 content element `k`: `[1,0,1,0,2,0,1,k]`.
pub fn ca2(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 2, 0, 1, ordinal])
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
pub fn rel() -> Address {
    ra(10)
}

/// [`rel`] as the TYPE endset a whole tuple carries.
pub fn rel_ty() -> Endset {
    enc(&[rel()])
}

/// Deposit one link of the suite's relation type in `home`, FROM naming
/// `from` and TO naming `to`, as the automation caller — the fixture nearly
/// every test here needs — and answer its address.
pub fn link(store: &LinkWriter<'_, World>, home: &Address, from: &[Address], to: &[Address]) -> Address {
    store
        .makelink(SYS, home, SlotArg::Addrs(from.to_vec()), SlotArg::Addrs(to.to_vec()), SlotArg::Addrs(vec![rel()]))
        .expect("a fixture link of the suite's relation type is admitted")
        .0
}

// ─────────────────────────────── world assembly ─────────────────────────────

/// An M3 slice with a principal-owned account and three registered
/// documents, built by folding exactly the records M3's own `delegate`/
/// `create_new_document` would stage. The first two are PRIVATE drafts — the
/// discovery fixtures edit them in place, which a published document refuses
/// (PUB-2.11); the first as an explicit-`false` mint, the state M3 produces
/// below the daemon's first-mint door. The third, [`pdoc`], is PUBLISHED and
/// memberless: the one document here whose readers can answer from an
/// arrangement other than its own. An account's `Allocate` carries no
/// publication state.
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
        .insert(SYS, doc, vp(1, 1), vals, false)
        .expect("test content INSERT succeeds");
}

/// Seed `count` one-byte content values into the PUBLISHED `doc`, the one way
/// content enters a published document (PUB-2.11): a DECLARED deposit
/// appended at the fresh end of the arrangement its readers answer from —
/// `doc`'s own while it has no member, its trunk head's once it has one
/// (PUB-2.66). The atoms are minted under `doc`'s own content chain either
/// way; only the placement floats.
pub fn seed_published_content(k: &Kernel<World>, doc: &Address, count: u32) {
    let fresh = {
        let snap = k.snapshot();
        let w = snap.world();
        w.m5().content_count(&reading_surface(w.m3(), doc)) + n(1)
    };
    let vals: Vec<Val> = (0..count).map(|i| Val::new(vec![b'p' + i as u8])).collect();
    skep_arrangement::Vstream::new(k)
        .insert(
            SYS,
            doc,
            VPos {
                subspace: n(1),
                ordinal: fresh,
            },
            vals,
            true,
        )
        .expect("a declared deposit at the fresh end is admitted into a published document");
}

/// The published fixture, and the one shape where head-float decides an
/// answer: `pdoc` takes two positions while memberless — they land in its
/// OWN arrangement — then VERSION mints its head member, which shares that
/// arrangement, and two more deposits land in the HEAD alone. So pdoc's own
/// arrangement is frozen at its pre-chain state (`pca(1..=2)`) while every
/// reader of pdoc answers from the head (`pca(1..=4)`).
pub fn published_world() -> Kernel<World> {
    let k = kernel();
    seed_published_content(&k, &pdoc(), 2); // memberless: pdoc's own V 1..2
    let (head, _) = skep_arrangement::Vstream::new(&k)
        .version(PrincipalId(1), &pdoc(), None)
        .expect("the owner versions its published document");
    assert_eq!(head, phead(), "the chain's first member");
    seed_published_content(&k, &pdoc(), 2); // the head's V 3..4, and nowhere else
    k
}

// ───────────────────────────── the suite's reads ────────────────────────────

/// The suite's reads of the kernel's CURRENT state under the total
/// predicate: each method takes one fresh snapshot and hands it, with
/// [`every_home`], to the M8 read of the same name, so two calls read two
/// states. A harness's convenience — which is why it lives here and M8
/// publishes none.
#[derive(Clone, Copy)]
pub struct Reads<'k>(pub &'k Kernel<World>);

impl Reads<'_> {
    pub fn image(&self, d: &Address, region: &[Span]) -> Result<Vec<Run>, QueryError> {
        image_on(&self.0.snapshot(), d, region)
    }

    pub fn findlinks_v(&self, d: &Address, region: &[Span]) -> Result<Vec<Address>, QueryError> {
        findlinks_v_on(&self.0.snapshot(), d, region, &every_home)
    }

    pub fn count_v(&self, d: &Address, region: &[Span]) -> Result<usize, QueryError> {
        count_v_on(&self.0.snapshot(), d, region, &every_home)
    }

    pub fn window_v(
        &self,
        d: &Address,
        region: &[Span],
        cur: Cursor,
        n: usize,
    ) -> Result<Window, QueryError> {
        window_v_on(&self.0.snapshot(), d, region, cur, n, &every_home)
    }

    pub fn retrieve_endsets(
        &self,
        d: &Address,
        region: &[Span],
    ) -> Result<Vec<(usize, Endset)>, QueryError> {
        retrieve_endsets_on(&self.0.snapshot(), d, region, &every_home)
    }

    pub fn findlinks_ftt(&self, q: &FourSet) -> Vec<Address> {
        findlinks_ftt_on(&self.0.snapshot(), q, &every_home)
    }

    pub fn count_ftt(&self, q: &FourSet) -> usize {
        count_ftt_on(&self.0.snapshot(), q, &every_home)
    }

    pub fn window_ftt(&self, q: &FourSet, cur: Cursor, n: usize) -> Window {
        window_ftt_on(&self.0.snapshot(), q, cur, n, &every_home)
    }

    pub fn project(&self, a: &Address, slot: usize, d: &Address) -> Result<SpanSet, QueryError> {
        project_on(&self.0.snapshot(), a, slot, d, &every_home)
    }

    pub fn addressably_discoverable_from(
        &self,
        a: &Address,
        d: &Address,
    ) -> Result<bool, QueryError> {
        addressably_discoverable_from_on(&self.0.snapshot(), a, d, &every_home)
    }

    pub fn delete_orphans(
        &self,
        d: &Address,
        p: &VPos,
        width: &Nat,
    ) -> Result<OrphanReport, OrphanError> {
        delete_orphans_on(&self.0.snapshot(), d, p, width, &every_home)
    }

    pub fn in_claims(&self, y: &Address, v: View) -> Vec<SupClaim> {
        in_claims_on(&self.0.snapshot(), y, v, &every_home)
    }

    pub fn out_claims(&self, x: &Address, v: View) -> Vec<SupClaim> {
        out_claims_on(&self.0.snapshot(), x, v, &every_home)
    }
}

// ───────────────────── the window law and a wide endset ─────────────────────

/// Drain one window read to exhaustion at batch size `n`, holding EVERY page
/// to what a returned `Window` promises — `batch` strictly ascending and no
/// longer than the clamped `n`, `next` its ≺-max or else the cursor
/// unchanged, `exhausted` iff the batch is short — and answer the
/// concatenation. A post-filter moved after the slice keeps the concatenation
/// and breaks a page, so the pages are where it shows. Bounded by `limit`
/// pages, so a window that never reports exhaustion fails rather than hangs.
pub fn drain_window(n: usize, limit: usize, page: impl Fn(Cursor) -> Window) -> Vec<Address> {
    let clamped = n.max(1);
    let mut drained = Vec::new();
    let mut cur: Cursor = None;
    for _ in 0..limit {
        let w = page(cur.clone());
        assert!(
            w.batch.windows(2).all(|p| p[0] < p[1]),
            "batch strictly ascending: {w:?}"
        );
        assert!(w.batch.len() <= clamped, "at most n = {n} links: {w:?}");
        assert_eq!(
            w.exhausted,
            w.batch.len() < clamped,
            "exhausted iff short, n = {n}: {w:?}"
        );
        assert_eq!(
            w.next,
            w.batch.last().cloned().or(cur),
            "next is the batch's max, else the cursor: {w:?}"
        );
        drained.extend(w.batch);
        if w.exhausted {
            return drained;
        }
        cur = w.next;
    }
    panic!("the window never reported exhaustion within {limit} pages at n = {n}");
}

/// A FROM endset of `spans` addresses touching doc1's position 1: `ca(1)` is
/// the span a region naming that position touches, and the rest name
/// unarranged positions of doc1. Endsets collapse by VALUE, so the filler is
/// keyed: the same `key` gives the same endset, distinct keys give distinct
/// ones.
pub fn wide_from(key: u32, spans: u32) -> Vec<Address> {
    let mut addrs = vec![ca(1)];
    addrs.extend((1..spans).map(|j| ca(1000 + key * spans + j)));
    addrs
}
