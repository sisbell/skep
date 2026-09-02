//! # skep-febe — M10: Operation Surface (FEBE Command Layer)
//!
//! The engine's **front door**: each external FEBE request becomes exactly one
//! call on the owning store/query module, gated on commit (ASN-0134 A7),
//! stamped with its linearization coordinate (`committed_at` on every write,
//! `as_of` on every read — A1/A2/V1), and every failure that reaches it
//! surfaces as a *typed, classified, never-silent* rejection. One thing well:
//! the uniform request lifecycle — *parse → authorize → linearize →
//! commit-gate → marshal → surface* — driven by a static dispatch table
//! ([`Operation::execute`]).
//!
//! M10 owns **no** per-store operation logic (M5/M6/M7/M8), **no** automation
//! (M9 — a parallel surface, not below it), **no** ordering/durability/
//! recovery (M2), and **no** journaled state. Its only authority is
//! *ephemeral connection state* — which principal a session speaks for — plus
//! the best-effort retry de-duplication cache (§6/§7 of the design). It is,
//! concretely, a lifecycle wrapper + dispatch table + client-model adapter:
//! the design resolves that no v1 operation needs cross-family composite
//! orchestration (Conflicts resolved #1), so that capability is latent with
//! zero occupants.
//!
//! Spec traceability: each public item's doc-comment cites the labels it
//! realizes (ASN-0134 A1/A2/A5/A7/V1/V2/G0, and §§ of the M10 design), so a
//! reviewer can walk from code to design without the documents open.
//!
//! A `§n` throughout this crate indexes `_design/module-designs/M10/design.md`
//! §Internal design, whose sections are:
//!
//! 1. Dispatch & the lifecycle entry
//! 2. The read path — M10 owns the snapshot
//! 3. The write path — commit-before-ack falls out of the call order
//! 4. EditLink — the one read-assembled request
//! 5. Rejection surfacing & the disposition hint
//! 6. Session binding & authorization pass-through
//! 7. Idempotency cache
//! 8. Client model — pipelining vs sequential
//! 9. Poisoned-halt & startup
//! 10. Cross-family composite orchestration (latent)
//!
//! A citation naming a section by title instead (§Public interface, §Core data
//! model, §Invariants) indexes that document's top-level headings.
//!
//! ## The two coordinates
//!
//! Every answer carries one `Seq`, and which one it is says how to use it.
//! Both are positions on the single kernel a [`Stores`] impl names, so they
//! are points on one totally ordered, never-regressing log and compare
//! directly:
//!
//! * a write's `at` is the coordinate it COMMITTED at (A1/A7) — the operation
//!   is in the log at that position and at every later one;
//! * a read's `as_of` is the coordinate of the snapshot it ANSWERED from
//!   (A2/V1) — the answer reflects every write committed at or before that
//!   position, and none after it.
//!
//! So a read answer whose `as_of` is at or past a write's `at` reflects that
//! write, and that comparison is the whole protocol. A **sequential** client —
//! one that waits for the acknowledgment before issuing the read — gets it
//! without arithmetic: the write commits before it is acknowledged and the log
//! never regresses, so any snapshot taken afterwards is at or past `at` (G0).
//! A **pipelining** client has requests in flight by construction and gets no
//! such ordering — M10 fixes one linearization point per operation and imposes
//! none between concurrent ones (§8) — so it compares the `as_of` it receives
//! against the `at` it is waiting for, and reissues the read until the
//! comparison holds. [`Operation::log_position`] answers with the same
//! frontier without issuing an operation.
//!
//! ## Boundary — deliberately NOT owned here
//!
//! * per-store operation logic (M5/M6/M7/M8) and automation (M9 ⟂ M10);
//! * ordering, durability, recovery (M2) — the binary calls `Kernel::open`
//!   and handles `OpenError` before constructing [`Operation`];
//! * journaled state — M10 names no concrete `World`/`Record` and contributes
//!   no slice, record, or fold to the engine;
//! * the wire codec byte format, and the request-SIZE limits that travel with
//!   it — [`Codec`] is a seam the transport fills, and its parser is the only
//!   bound on how large a request may be, since M10 measures no field of the
//!   `Op` it is handed ([`Codec::parse`]); the
//!   request↔response correlation (no `ReqId` echo — §8), the `SessionId`
//!   non-forgeability precondition and the authentication mechanism (§6), the
//!   concurrency policy, and reorder/retry buffering (M10 *surfaces*
//!   `Reorder`, it does not reorder);
//! * cross-restart exactly-once — the idempotency cache is an in-memory,
//!   per-`(SessionId, ReqId)` hint, committed-write acks only (§7);
//! * the fine-grained ownership check `ω` — the owning store's, passed through
//!   verbatim (§6); M10 pre-checks only "is there a principal at all".
//!
//! ## Composition
//!
//! M10 is generic over `W` (Engine Composition Contract): it names no concrete
//! `World`/`Record`, reaches upstream state only through the accessor traits
//! ([`FebeWorld`] names all four) via one pinned snapshot per read, and
//! acquires the three transact-driving store drivers per-op from the injected
//! [`Stores`] factory. The `M10 → M4` edge names four types and calls no M4
//! function (design, Conflicts resolved #4): `HasContent` is a [`FebeWorld`]
//! supertrait and `ContentWrite` the record lift `Vstream::insert`'s bound
//! requires, `Val` rides in `Op::Insert`'s payload, and `ContentError` is
//! lowered when M5's insert refuses through `InsertError::Content`.

#![forbid(unsafe_code)]

mod codec;
mod idem;
mod lower;
mod op;
mod operation;
mod reject;
mod response;
mod session;
mod successor;

pub use codec::{Codec, ParseError};
pub use op::{Op, OpKind, ReqId, Request, SuccessorSpec, MAX_REQ_ID_BYTES};
pub use operation::Operation;
// `disposition_of` and `Rejection::classified` are public for the reason the
// disposition is documented as recomputable: a transport that raises one of
// M10's own codes on its own channel asks the table — or builds the whole
// rejection through the constructor that consults it — rather than
// transcribing the row, so the two cannot come to advise the same code
// differently.
pub use reject::{disposition_of, Disposition, FaultSite, RejectCode, Rejection};
pub use response::Response;
pub use session::SessionId;

// Every upstream type named on the request/response path, re-exported so a
// caller of [`Operation::execute`] spells one crate. That is where the line
// falls: what a CALLER must name to build a `Request` or read a `Response` is
// nameable from `skep_febe`; what an ASSEMBLER of the engine must name —
// `Kernel`, `WorldState`, `Namespace`, `Vstream`, `LinkWriter`, the four
// accessor traits — is not, because the binary that implements [`Stores`]
// holds every crate by construction. A re-export claims no ownership: each
// type's owning module stays authoritative for it, exactly as M8 re-exports
// M7's slot numbering.
pub use skep_address::{Address, Nat, Span, SpanSet, Tumbler}; // M1
pub use skep_arrangement::{Run, VPos, VSpec}; // M5
pub use skep_content::Val; // M4
pub use skep_discovery::{Cursor, FourSet, OrphanReport, SupClaim, Window}; // M8
pub use skep_kernel::Seq; // M2
pub use skep_namespace::PrincipalId; // M3
pub use skep_retrieval::{CompareReport, Deletions, Delivery, Operand, Region, Spec, SpecFault}; // M6
// M7, whose slot vocabulary the request model uses directly: `SlotArg` is the
// two-form endset slot (the 2026-08-16 amendment) naming `Op::MakeLink`'s
// three slots and `SuccessorSpec`'s type slot, and `FROM`/`TO`/`TYPE` are the
// numbering `Op::FollowLink`'s and `Op::Project`'s `slot` index is in — so a
// caller spells `FROM` rather than a bare `1` whose meaning lives elsewhere.
pub use skep_links::{Endset, Invalid, Link, SlotArg, View, FROM, TO, TYPE};

use skep_arrangement::{HasM5, Vstream};
use skep_content::HasContent;
use skep_kernel::{Kernel, WorldState};
use skep_links::{HasLinks, LinkWriter};
use skep_namespace::{HasM3, Namespace};

/// The world the front door dispatches over: M2's fold contract plus every
/// upstream accessor, since M10 reaches all four store slices — the widest
/// bound set in the engine, and M10's own slice count is zero (Engine
/// Composition Contract — no state, no record variant, no fold).
///
/// Named for the reason M6 names `M6World` and M7 `LinkWorld`: one word for
/// the seam, so a consumer generic over the same world writes one bound
/// rather than five. Blanket-implemented, so an engine that implements the
/// accessors gets this for free; the record lift each write path needs
/// (`W::Record: From<M3Rec>` and its three siblings) stays on the impl that
/// requires it.
pub trait FebeWorld: WorldState + HasM3 + HasM5 + HasLinks + HasContent {}
impl<W: WorldState + HasM3 + HasM5 + HasLinks + HasContent> FebeWorld for W {}

/// The injected acquisition path for the three transact-driving store-driver
/// handles (§Public interface). The binary/engine builds the one production
/// impl; M10 names only this trait and the published handle *types*, acquiring
/// a driver per-op. Reads, snapshots, `current_seq`, and the latent composite
/// go through [`Stores::kernel`].
///
/// An implementer supplies the kernel and one method. The M3 and M5 drivers
/// follow from the kernel — `Namespace::new` and `Vstream::new` are bound by
/// `W: WorldState` alone, exactly this trait's bound, and each handle holds
/// nothing but the borrow — so they are given here rather than transcribed
/// into every impl. [`Stores::linkstore`] is the one that must be written:
/// `LinkWriter::new` requires `W: HasLinks`, which this trait does not, and it
/// does more than hold a borrow — it takes a snapshot and clones the
/// genesis-sealed `Arc<TypeRegistry>` off it (the as-built constructor takes
/// no registry argument, a benign simplification of the amendment's stated
/// shape).
///
/// PRECONDITION on the implementer: **every accessor names ONE kernel.**
/// [`Stores::kernel`] answers with the same `Kernel<W>` on every call, and
/// [`Stores::linkstore`] is built over that kernel. The signature does not
/// force it — `kernel()` is consulted afresh per request, so an impl that
/// opened a kernel per call would compile — and every coordinate M10 reports
/// rests on it: `Operation::log_position` and every read's `as_of` come from
/// `kernel()`, while the link writes commit through `linkstore()`. Two kernels
/// leave those coordinates describing different logs, each store still
/// committing before it acknowledges and the reported positions no longer
/// meaning what this module promises. The two provided bodies satisfy it by
/// construction; `linkstore` is the one an implementer writes, which is where
/// the obligation lands.
///
/// The design flagged the engine-facing store-driver constructors as a
/// required upstream interface amendment (Conflicts resolved #6); the as-built
/// crates already publish them — `Namespace::new(&Kernel<W>)`,
/// `Vstream::new(&Kernel<W>)`, and `LinkWriter::new(&Kernel<W>)`. The binary —
/// which holds the recovered kernel from M2 recovery — builds a `Stores` impl
/// over them; M10 takes it INJECTED for decoupling/testability (an
/// in-memory-kernel-backed `Stores` exercises the whole lifecycle with no
/// disk/recovery), not because the constructors are unreachable.
pub trait Stores<W: WorldState>: Send + Sync {
    /// M2 — reads/snapshots/`current_seq`/the latent composite `transact`.
    fn kernel(&self) -> &Kernel<W>;
    /// M3 driver — borrows the held kernel for the call.
    fn namespace(&self) -> Namespace<'_, W> {
        Namespace::new(self.kernel())
    }
    /// M5 driver — borrows the held kernel for the call.
    fn vstream(&self) -> Vstream<'_, W> {
        Vstream::new(self.kernel())
    }
    /// M7 driver — borrows the kernel; holds the genesis-immutable registry.
    fn linkstore(&self) -> LinkWriter<'_, W>;
}
