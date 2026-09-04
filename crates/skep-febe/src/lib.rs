//! # skep-febe — M10: Operation Surface (FEBE Command Layer)
//!
//! The engine's **front door**: each external FEBE request becomes exactly one
//! call on the owning store/query module, gated on commit (ASN-0134 A7),
//! stamped with its linearization coordinate (`committed_at` on every write
//! that commits, `as_of` on every read that answers — A1/A2/V1), and every
//! failure that reaches it surfaces as a *typed, classified, never-silent*
//! rejection. One thing well:
//! the uniform request lifecycle — *parse → authorize → linearize →
//! commit-gate → marshal → surface* — driven by a static dispatch table
//! ([`Operation::execute`]).
//!
//! M10 owns **no** per-store operation logic (M5/M6/M7/M8), **no** automation
//! (M9 — a parallel surface, not below it), **no** ordering/durability/
//! recovery (M2), and **no** journaled state. It holds exactly one piece of
//! *authoritative* state, and authoritative only for the uptime: which
//! principal a session speaks for (§6). Everything else it holds is a **hint**
//! that may be lost with no loss of correctness — the best-effort retry memo
//! (§7) and the poison latch (§9). It is, concretely, a lifecycle wrapper +
//! dispatch table + client-model adapter:
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
//! A rejection is the one answer carrying no coordinate — a refused read
//! reports no position, having answered from none — so a client tracking the
//! frontier across a refusal asks [`Operation::log_position`] or reissues.
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
//! * exactly-once, in both of the ways a client can fail to get it — the
//!   idempotency cache is an in-memory, per-`(SessionId, ReqId)` hint holding
//!   committed-write acks only (§7). It answers a SEQUENTIAL client's reissue
//!   of a write whose acknowledgment was lost; it is empty after a restart,
//!   and it offers nothing between concurrent requests, a retry issued while
//!   its original is still in flight finding no entry and executing;
//! * the fine-grained ownership check `ω` — the owning store's, passed through
//!   verbatim (§6); M10 pre-checks only "is there a principal at all", and
//!   only on the write path, a read being served against any `SessionId` and
//!   reaching its store with no principal ([`Operation::execute`]).
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

// Every upstream type or constructor named on the request/response path, plus
// the two budgets a request is held to, re-exported so a caller of
// [`Operation::execute`] spells one crate. That is where the line falls: what
// a CALLER must name to build a `Request` or read a `Response` is nameable
// from `skep_febe`; what an ASSEMBLER of the engine must name — `Kernel`,
// `WorldState`, `Namespace`, `Vstream`, `LinkWriter`, the four accessor
// traits — is not, because the binary that implements [`Stores`] holds every
// crate by construction. A constructor's ERROR type travels with it: a
// `Result` whose failure cannot be named is one a caller can only `unwrap`.
// A re-export claims no ownership: each type's owning module stays
// authoritative for it, exactly as M8 re-exports M7's slot numbering.
//
// M1, with the constructors, because `Address` is a field of thirty-odd `Op`
// variants and `validate` is the only way to make one: `validate`/`T4Error`
// for an address, `Span::new`/`T12Clause` for a span, `Tumbler::new`/
// `EmptySequence` for a tumbler, and `elem_addr`/`ElemPos`/`ElemError` for
// the element addresses `Op::Emit`'s `from` and `Op::Nullify`'s `target`
// take.
pub use skep_address::{
    elem_addr, validate, Address, ElemError, ElemPos, EmptySequence, Nat, Span, SpanSet, T4Error,
    T12Clause, Tumbler,
};
pub use skep_arrangement::{Run, VPos, VSpec}; // M5
pub use skep_content::Val; // M4
// M8, `SlotSpec` included: every field of a `FourSet` is one, so the three
// descriptor ops are unbuildable without it.
pub use skep_discovery::{Cursor, FourSet, OrphanReport, SlotSpec, SupClaim, Window};
pub use skep_kernel::Seq; // M2
pub use skep_namespace::PrincipalId; // M3
// M6, the two enclosed shapes included: `Delivery` and `CompareReport` are
// newtypes over `Vec<DeliveryItem>` and `Vec<CorrPair>`, so reading either
// answer means naming what is inside it.
pub use skep_retrieval::{
    CompareReport, CorrPair, Deletions, Delivery, DeliveryItem, Operand, RegionSpec, Spec, SpanFault,
};
// M7, whose slot vocabulary the request model uses directly: `SlotArg` is the
// two-form endset slot (the 2026-08-16 amendment) naming `Op::MakeLink`'s
// three slots and `SuccessorSpec`'s type slot, and `FROM`/`TO`/`TYPE` are the
// numbering `Op::FollowLink`'s and `Op::Project`'s `slot` index is in — as is
// [`FaultSite`]'s `slot` — so a caller spells `FROM` rather than a bare `1`
// whose meaning lives elsewhere. `enc` rides with `Endset::from_spans`: they
// are the two constructors of one type, one reachable as an inherent method
// and the other only as a free function, and an address-denoting `Op::Emit`
// type or `SlotSpec::Spans` needs the second. `MAX_SLOT_SPANS` is here for
// the reason [`MAX_REQ_ID_BYTES`] is public: they are the two budgets that
// govern what a request may carry, and a caller that checks both before
// sending should not have to spell two crates to do it.
pub use skep_links::{enc, Endset, Invalid, Link, SlotArg, View, FROM, MAX_SLOT_SPANS, TO, TYPE};

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

#[cfg(test)]
mod tests {
    use super::*;

    /// The re-export rule as a check rather than a comment: a request is
    /// assembled through `skep_febe` alone — the M1 constructors and the
    /// failures they answer with, since a `Result` whose error cannot be named
    /// is one a caller can only `unwrap`, and one `Op` per upstream module the
    /// block covers. Nothing here names an upstream crate, so a re-export
    /// dropped from the request half of the block fails to compile.
    #[test]
    fn a_request_is_built_spelling_one_crate() {
        let doc: Result<Tumbler, EmptySequence> = Tumbler::new([1u32, 0, 1, 0, 1].map(Nat::from));
        let doc: Result<Address, T4Error> = validate(doc.expect("nonempty"));
        let doc = doc.expect("T4-valid");

        // `Op::Emit`'s `from` and `Op::Nullify`'s `target` are element
        // addresses, which is the constructor this reaches for.
        let elem: Result<Address, ElemError> = elem_addr(ElemPos {
            doc: doc.clone(),
            subspace: Nat::from(1u32),
            ordinal: Nat::from(1u32),
        });
        assert!(elem.is_ok());

        // A V-span, as every M5/M6/M8 region argument carries.
        let span: Result<Span, T12Clause> = Span::new(
            Tumbler::new([1u32, 1].map(Nat::from)).expect("nonempty"),
            Tumbler::new([0u32, 1].map(Nat::from)).expect("nonempty"),
        );
        assert!(span.is_ok());
        assert_ne!(SpanSet::singleton(span.expect("well formed")), SpanSet::empty());

        // The one refusal a caller meets before any request is assembled.
        let empty: Result<Tumbler, EmptySequence> = Tumbler::new([]);
        assert!(empty.is_err(), "an empty component sequence is no tumbler");

        let span = Span::new(
            Tumbler::new([1u32, 1].map(Nat::from)).expect("nonempty"),
            Tumbler::new([0u32, 1].map(Nat::from)).expect("nonempty"),
        )
        .expect("well formed");
        let at = VPos { subspace: Nat::from(1u32), ordinal: Nat::from(1u32) };
        let vspec = VSpec { source: doc.clone(), span: span.clone() };
        let q = FourSet {
            home: SlotSpec::Spans(enc([&doc])),
            from: SlotSpec::Any,
            to: SlotSpec::Any,
            ty: SlotSpec::Any,
        };
        let cur: Cursor = None;

        // The slot numbering `Op::FollowLink` and `Op::Project` index into,
        // and `FaultSite::slot` reports an EDITLINK successor fault back in.
        const { assert!(FROM < TO && TO < TYPE, "the slot numbering runs FROM, TO, TYPE") };

        // One request per upstream module, so a re-export dropped from any
        // group is a compile error rather than a dependency an external
        // caller silently acquires.
        let ops: Vec<Op> = vec![
            Op::Insert { doc: doc.clone(), at: at.clone(), values: vec![Val::new(vec![1u8])] }, // M4
            Op::Copy { doc: doc.clone(), at, specs: vec![vspec.clone()] },                      // M5
            Op::RetrieveV { specs: vec![Spec { doc: doc.clone(), span: span.clone() }] },       // M6
            Op::Compare {
                rho1: vec![RegionSpec { doc: doc.clone(), spans: vec![span] }],
                rho2: vec![],
            },
            Op::FindLinksFtt { q: q.clone() }, // M8
            Op::WindowFtt { q, cur, n: 1 },
            Op::MakeLink {
                home: doc.clone(),
                from: SlotArg::Resolve(vec![vspec.clone()]), // M7
                to: SlotArg::Addrs(vec![doc.clone()]),
                ty: SlotArg::Resolve(vec![vspec.clone()]),
            },
            Op::Emit { home: doc.clone(), ty: Endset::empty(), from: doc.clone(), to: vec![] },
            Op::InClaims { y: doc.clone(), view: View::Active },
            Op::FollowLink { a: doc.clone(), slot: FROM },
            Op::Project { a: doc.clone(), slot: TYPE, d: doc.clone() },
            Op::Delegate { new_prefix: doc.tumbler().clone(), new_id: PrincipalId(1) }, // M3
            Op::EditLink {
                original: doc.clone(),
                successor: SuccessorSpec {
                    from: vec![vspec],
                    to: vec![],
                    ty: SlotArg::Addrs(vec![doc.clone()]),
                },
                d_s: doc.clone(),
                d_a: doc,
            },
        ];
        assert_eq!(ops.len(), 13, "one request per upstream module, and then some");

        // The two budgets a request is held to — one M10's, one M7's — read
        // off the same crate, since a caller that checks both before sending
        // should not have to spell two.
        const { assert!(MAX_REQ_ID_BYTES > 0 && MAX_SLOT_SPANS > 0) };
    }

    /// The same rule on the answer side. Several response payloads have no
    /// public constructor — they are what a store hands back — so this names
    /// them rather than building them, which is the compile-time check the
    /// rule actually needs. A re-export dropped from the response half of the
    /// block fails here, and its cost is the dependency this crate exists to
    /// spare an external caller.
    #[test]
    fn a_response_payload_is_named_spelling_one_crate() {
        let _: Option<Seq> = None; // M2 — the coordinate on every answer
        let _: Option<Run> = None; // M5 — `Response::Runs`
        let _: Option<Link> = None; // M7 — `Response::LinkValue`
        let _: Option<Invalid> = None; // M7 — `Response::Follow`'s in-band Err
        let _: Option<Window> = None; // M8 — `Response::Page`
        let _: Option<OrphanReport> = None;
        let _: Option<SupClaim> = None; // M8 — `Response::Claims`
        let _: Option<Delivery> = None; // M6 — `Response::Delivery`…
        let _: Option<DeliveryItem> = None; // …and what is inside it
        let _: Option<CompareReport> = None; // M6 — `Response::Compare`…
        let _: Option<CorrPair> = None; // …and what is inside it
        let _: Option<Deletions> = None; // M6 — `Response::Deletions`
        // The two M6 shapes a `FaultSite` carries: M10's own rejection type
        // is unreadable without them.
        let _: Option<Operand> = None;
        let _: Option<SpanFault> = None;
    }
}
