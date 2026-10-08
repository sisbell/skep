//! The minimal engine assembly every suite runs on — the toy `World`/`Rec`
//! pair the composition contract prescribes: the `HasM3`/`HasContent`/`HasM5`
//! read accessors, the `From` record lifts, `apply` dispatching into each
//! store's fold — and the helpers the suites share.

use std::path::Path;

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Span, Tumbler};
use skep_arrangement::{
    deposit_class_types, ordinal_vspan, Base, Caller, Deposit, HasM5, M5State, Run, ShotRun, VPos,
    Vstream,
};
use skep_content::{ContentStore, ContentWrite, HasContent, Val};
use skep_kernel::{
    BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelConfig, SaltSource, Snapshot,
    TxnError, WorldState,
};
use skep_namespace::{HasM3, M3Rec, M3State, PrincipalId};

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

/// Document 1 — principal 1's working DRAFT (private), the target of every
/// in-place edit the suites make.
pub fn doc1() -> Address {
    a(&[1, 0, 1, 0, 1])
}

/// Document 2 — principal 1's second draft (private, empty at genesis).
pub fn doc2() -> Address {
    a(&[1, 0, 1, 0, 2])
}

/// Document 3 — principal 1's PUBLISHED edition (an explicit `true` at its
/// mint): the target the version-chain model's refusals key on, and the one
/// owned source the owner may version.
pub fn pdoc() -> Address {
    a(&[1, 0, 1, 0, 3])
}

/// doc1 content element k (length 8), M3's minted shape.
pub fn ca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 1, ordinal])
}

/// pdoc's content element k (length 8).
pub fn pca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 3, 0, 1, ordinal])
}

/// The version member of pdoc on M3's `(d_src, 1)` chain — the owned fork of
/// the published edition — and its length-9 elements.
pub fn vdoc() -> Address {
    a(&[1, 0, 1, 0, 3, 1])
}
pub fn vca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 3, 1, 0, 1, ordinal])
}

pub fn vp(subspace: u32, ordinal: u32) -> VPos {
    VPos {
        subspace: n(subspace),
        ordinal: n(ordinal),
    }
}

pub fn vspan(subspace: u32, ordinal: u32, count: u32) -> Span {
    ordinal_vspan(&vp(subspace, ordinal), &n(count)).expect("test spans name ≥ 1 position")
}

pub fn val(b: &[u8]) -> Val {
    Val::new(b)
}

/// Two of the door's four held types (PUB-2.11, RES-261), as M5 spells them:
/// the set's first, ENROLL's, and its second, RETIRE's — the credential pair,
/// ahead of the registry's BINDING and ENDPOINT.
pub fn enroll_ty() -> Address {
    deposit_class_types()[0].clone()
}
pub fn retire_ty() -> Address {
    deposit_class_types()[1].clone()
}

/// The deposit declaration every declared fixture in the suites carries:
/// ENROLL's type. What these fixtures deposit is prose (`b"z"`, `b"atom"`),
/// which is PUB-2.60's residue — bytes of the depositor's choosing under a
/// declared class type — and the door, which tests the type and cannot test
/// what the bytes are, admits it on the type alone.
pub fn declared() -> Deposit {
    Deposit::Declared(enroll_ty())
}

/// The seeded owner of doc1/doc2/pdoc — the caller every pre-ruling op runs
/// under, so the ω gate is exercised on every path, not skipped.
pub const P1: Caller = Caller::Principal(PrincipalId(1));

/// Genesis with M3 pre-seeded by folding exactly the records its own
/// delegate/create_new_document ops would stage: account [1,0,1] → principal
/// 1 (owns doc1, doc2, pdoc), sibling account [1,0,2] → principal 2,
/// sub-account [1,0,1,1] (delegated under [1,0,1]) → principal 3 with its own
/// document [1,0,1,1,0,1] — the ownership-exactness fixtures. Deterministic,
/// per M2's byte-identical-genesis contract.
///
/// The publication bits: doc1, doc2 and the sub-account's document are
/// PRIVATE drafts — the documents the suites' in-place edits are admitted on
/// (a first mint carrying an explicit `false` is the state M3 produces below
/// the daemon's first-mint door, PUB-8.20 being the daemon's alone) — and
/// pdoc is a PUBLISHED edition. An account's `Allocate` carries no
/// publication state.
pub fn genesis() -> World {
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
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 1, 0, 1]),
            published: false,
        });
    World {
        m3,
        content: ContentStore::default(),
        m5: M5State::genesis(),
    }
}

/// [`genesis`] plus one version MEMBER under each of doc1 and pdoc, each
/// journaled with the bit its DOCUMENT does NOT carry — `[1,0,1,0,1,1]`
/// (a member of the private doc1) stamped `true`, `[1,0,1,0,3,1]` (a member
/// of the published pdoc) stamped `false`. Neither state is one the write
/// path admits any more (PUB-2.7, PUB-2.9); both are reachable by fold, and
/// they are exactly what tells a projected read (PUB-2.15) from a read of the
/// member's own bit.
pub fn genesis_with_members() -> World {
    let world = genesis();
    let m3 = world
        .m3
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 1, 1]),
            published: true,
        })
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 3, 1]),
            published: false,
        });
    World { m3, ..world }
}

pub fn mem_kernel() -> Kernel<World> {
    mem_kernel_of(genesis())
}

pub fn mem_kernel_of(world: World) -> Kernel<World> {
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    };
    Kernel::open(cfg, world).expect("in-memory open")
}

pub fn cfg_fsync(dir: &Path) -> KernelConfig {
    KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 1,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    }
}

/// Unwrap an op's typed rejection (`TxnError::Rejected(E)` — surfaced
/// verbatim, per M2's transact contract).
pub fn rejected<T, E: std::fmt::Debug>(r: Result<T, TxnError<E>>) -> E {
    match r {
        Err(TxnError::Rejected(e)) => e,
        Err(other) => panic!("expected TxnError::Rejected, got {other:?}"),
        Ok(_) => panic!("expected TxnError::Rejected, got Ok"),
    }
}

/// Read the value bytes at content V-ordinal `ord` — point (M5) then
/// value_at (M4), both off ONE snapshot.
pub fn read_v(s: &Snapshot<World>, doc: &Address, ord: u32) -> Vec<u8> {
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

/// Leave doc1 (the draft) holding `a`, `b`, `c` at content ordinals 1..3,
/// and hand back the `Vstream` the caller goes on to drive.
pub fn insert_abc(kernel: &Kernel<World>) -> Vstream<'_, World> {
    let vs = Vstream::new(kernel);
    vs.insert(P1, &doc1(), vp(1, 1), vec![val(b"a"), val(b"b"), val(b"c")], Deposit::Undeclared)
        .expect("insert commits");
    vs
}

/// Leave pdoc (the published edition) holding `a`, `b`, `c` — the ONE way
/// content enters a published document on this surface: a DECLARED deposit
/// at its fresh positions (PUB-2.59, PUB-9.13).
pub fn deposit_abc(kernel: &Kernel<World>) -> Vstream<'_, World> {
    let vs = Vstream::new(kernel);
    vs.insert(P1, &pdoc(), vp(1, 1), vec![val(b"a"), val(b"b"), val(b"c")], declared())
        .expect("a declared deposit at the edition's fresh positions commits");
    vs
}

/// One run of a shot: `width` positions from `start`, windowing `origin`.
pub fn shot_run(origin: &Address, start: &Address, width: u32) -> ShotRun {
    ShotRun {
        origin: origin.clone(),
        run: Run::new(start.clone(), n(width)).expect("a content run"),
    }
}

/// The base a draft was staged from, and how much of it the copy took.
pub fn base(member: &Address, extent: u32) -> Base {
    Base {
        member: member.clone(),
        extent: n(extent),
    }
}

/// A consult over the world it is handed: a published origin is readable to
/// everyone, a private one to its owner `p`. It reads that world and nothing
/// else — `publish` hands it the working world of the shot's own transaction.
pub fn readable_by(p: PrincipalId) -> impl Fn(&World, &Address) -> bool {
    move |world: &World, origin: &Address| {
        let m3 = world.m3();
        m3.published(&skep_arrangement::trunk_of(origin)) || m3.is_effective_owner(p, origin)
    }
}
