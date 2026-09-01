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
//! ## Boundary — deliberately NOT owned here
//!
//! * per-store operation logic (M5/M6/M7/M8) and automation (M9 ⟂ M10);
//! * ordering, durability, recovery (M2) — the binary calls `Kernel::open`
//!   and handles `OpenError` before constructing [`Operation`];
//! * journaled state — M10 names no concrete `World`/`Record` and contributes
//!   no slice, record, or fold to the engine;
//! * the wire codec byte format ([`Codec`] is a seam the transport fills), the
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
//! (`HasM3`/`HasM5`/`HasLinks`/`HasContent`) via one pinned snapshot per read,
//! and acquires the three transact-driving store drivers per-op from the
//! injected [`Stores`] factory. The `M10 → M4` edge is type-only (design,
//! Conflicts resolved #4): `Val`/`ContentWrite`/`ContentError`/`HasContent`
//! are named solely to satisfy `Vstream::insert`'s public bound.

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
pub use op::{Op, OpKind, ReqId, Request, SuccessorSpec};
pub use operation::Operation;
pub use reject::{Disposition, FaultSite, RejectCode, Rejection};
pub use response::Response;
pub use session::SessionId;
// The two-form endset slot (M7-defined; the 2026-08-16 amendment): names
// `Op::MakeLink`'s three slots and `SuccessorSpec`'s type slot, re-exported
// so the transport spells one crate.
pub use skep_links::SlotArg;

use skep_arrangement::Vstream;
use skep_kernel::{Kernel, WorldState};
use skep_links::LinkWriter;
use skep_namespace::Namespace;

/// The injected acquisition path for the three transact-driving store-driver
/// handles (§Public interface). The binary/engine builds the one production
/// impl; M10 names only this trait and the published handle *types*, acquiring
/// a driver per-op (it never names a store-driver `::new`). Reads, snapshots,
/// `current_seq`, and the latent composite go through [`Stores::kernel`].
///
/// The design flagged the engine-facing store-driver constructors as a
/// required upstream interface amendment (Conflicts resolved #6); the as-built
/// crates already publish them — `Namespace::new(&Kernel<W>)`,
/// `Vstream::new(&Kernel<W>)`, and `LinkWriter::new(&Kernel<W>)` (the as-built
/// `LinkWriter::new` takes no registry argument: it clones the genesis-sealed
/// `Arc<TypeRegistry>` off a snapshot itself, a benign simplification of the
/// amendment's stated shape). The binary — which holds the recovered kernel
/// from M2 recovery — builds a `Stores` impl over them; M10 takes it INJECTED
/// for decoupling/testability (an in-memory-kernel-backed `Stores` exercises
/// the whole lifecycle with no disk/recovery), not because the constructors
/// are unreachable.
pub trait Stores<W: WorldState>: Send + Sync {
    /// M2 — reads/snapshots/`current_seq`/the latent composite `transact`.
    fn kernel(&self) -> &Kernel<W>;
    /// M3 driver — borrows the held kernel for the call.
    fn namespace(&self) -> Namespace<'_, W>;
    /// M5 driver — borrows the held kernel for the call.
    fn vstream(&self) -> Vstream<'_, W>;
    /// M7 driver — borrows the kernel; holds the genesis-immutable registry.
    fn linkstore(&self) -> LinkWriter<'_, W>;
}
