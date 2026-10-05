//! # skep-febe — M10: Operation Surface (FEBE Command Layer)
//!
//! The engine's **front door**: each external FEBE request is dispatched to
//! the store/query module that owns it, gated on commit (ASN-0134 A7),
//! stamped with its linearization coordinate (`committed_at` on every write
//! that commits, `as_of` on every read that answers — A1/A2/V1), and every
//! failure that reaches it surfaces as a *typed, classified, never-silent*
//! rejection. One thing well:
//! the uniform request lifecycle — *parse → authorize → linearize →
//! commit-gate → marshal → surface* — driven by a static dispatch table
//! ([`OperationSurface::execute`]).
//!
//! M10 owns **no** per-store operation logic (M5/M6/M7/M8), **no** automation
//! (M9 — a parallel surface, not below it), **no** ordering/durability/
//! recovery (M2), and **no** journaled state; the one rule it performs on
//! another component's behalf is named below, beside the reads that need it.
//! It holds exactly one piece of *authoritative* state, and authoritative
//! only for the uptime: which principal a session speaks for (§6).
//! Everything else it holds is a **hint** that may be lost with no loss of
//! correctness — the best-effort retry memo (§7).
//! It is, concretely, a lifecycle wrapper + dispatch table + readability
//! door + client-model adapter; the door, the largest of the four, is the one
//! read predicate a request answers through and every rule that predicate
//! decides (`operation/door.rs` lists them). Cross-family COMPOSITE
//! orchestration — a write spanning store families committed as one M2
//! transaction — is latent with zero occupants: the design resolves that no
//! v1 operation needs one (Conflicts resolved #1). A read spanning store
//! families needs no transaction and is answered off the one snapshot the
//! read dispatch pins; M10 composes three, the PUBLICATION READS:
//! [`Op::DocMetadata`] (M3's publication bit, owner and chain with M5's
//! frozen birth extent), [`Op::EditionClaims`] (the world's edition-claim
//! class under the door's home rule) and [`Op::UniversalGrants`] (the grant
//! fold's live universal index narrowed by M3's ω). Each says at its arm what
//! it assembles, and what the three need that no store computes for them is
//! the `publication` card's. That card holds the one rule M10 performs on
//! another component's behalf: the any-principal read's fold-filter
//! RE-DERIVES the grant fold's issuer test as a projection over rows, because
//! the world hands its universal index raw
//! ([`PublicationWorld::universal_grant_index`]).
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
//!   is in the log at that position and at every later one; a write answered
//!   with an incumbent it deduplicated against commits nothing, and its `at`
//!   is the coordinate of the base it found that incumbent in, where the
//!   incumbent already stands ([`Response::AckAddr`]);
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
//! comparison holds. [`OperationSurface::log_position`] answers with the
//! coordinate of the committed head without issuing an operation.
//!
//! A rejection is the one answer carrying no coordinate — a refused read
//! reports no position, having answered from none — so a client tracking the
//! committed head across a refusal asks [`OperationSurface::log_position`] or
//! reissues.
//!
//! ## Boundary — deliberately NOT owned here
//!
//! * per-store operation logic (M5/M6/M7/M8) and automation (M9 ⟂ M10);
//! * ordering, durability, recovery (M2) — the binary calls `Kernel::open`
//!   and handles `OpenError` before constructing [`OperationSurface`];
//! * journaled state — M10 names no concrete `World`/`Record` and contributes
//!   no slice, record, or fold to the engine;
//! * the wire codec byte format, and the request-SIZE limits that travel with
//!   it — [`Codec`] is a seam the transport fills, and its parser is what
//!   bounds how large a request may be, M10 itself measuring almost nothing
//!   ([`Codec::parse`] says exactly what); the request↔response correlation
//!   — no frame M10 marshals carries a correlation id, and the optional
//!   `ReqId` is an idempotency key, never one (§8); the `SessionId`
//!   non-forgeability precondition and the authentication mechanism (§6), the
//!   concurrency policy, and reorder/retry buffering (M10 *surfaces*
//!   `Reorder`, it does not reorder);
//! * exactly-once, in both of the ways a client can fail to get it — the
//!   retry memo is an in-memory, per-`(SessionId, ReqId)` hint holding
//!   committed-write acks only (§7). It answers a SEQUENTIAL client's reissue
//!   of a write whose acknowledgment was lost; it is empty after a restart,
//!   and it offers nothing between concurrent requests, a retry issued while
//!   its original is still in flight finding no entry and executing;
//! * the fine-grained ownership check `ω` — the owning store's, passed through
//!   verbatim (§6); M10 pre-checks only "is there a principal at all", and
//!   only on the write path. A read is served against any `SessionId`, its
//!   principal resolved for the read PREDICATE rather than to gate it, so
//!   reads are masked (by M6 and M8, through that predicate) rather than
//!   gated — a read is never refused for want of a bound session, though the
//!   predicate itself refuses a request that NAMES a document the caller may
//!   not read ([`OperationSurface::execute`] gives the four forms). The one
//!   place M10 ASKS ω without wording it is the write door's source consult
//!   (lane 3.3c, PUB-6.36/6.38): it defers to the store wherever the
//!   destination's own ownership gate would refuse, through the store's own
//!   `Caller::is_owner`, so no source is judged ahead of `not_owner`.
//!
//! ## Composition
//!
//! M10 is generic over `W` (Engine Composition Contract): it names no concrete
//! `World`/`Record`, reaches upstream state only through the accessor traits
//! ([`FebeWorld`] names all four) via one pinned snapshot per read, and
//! acquires the three transact-driving store drivers per-op from the injected
//! [`Stores`] factory. Two capabilities of that world are M10's own seams,
//! and are two because they answer unrelated questions: [`ReadableWorld`],
//! the one read predicate the surface answers through, and
//! [`PublicationWorld`], the two class lookups [`Op::EditionClaims`] and
//! [`Op::UniversalGrants`] ask.
//! The whole of that contract — the world, its two capabilities, the rows the
//! second hands over, and the factory — is written in one module, `world`.
//!
//! The `M10 → M4` edge names four types and calls no M4
//! function (design, Conflicts resolved #4): `HasContent` is a [`FebeWorld`]
//! supertrait and `ContentWrite` the record lift `Vstream::insert`'s bound
//! requires, `Val` rides in `Op::Insert`'s payload, and `ContentError` is
//! lowered when M5's insert or publish refuses through `InsertError::Content`
//! or `PublishError::Content`.

#![forbid(unsafe_code)]

// The modules in dependency order: each names, in code, only modules above
// it, which `tests/it/tidy.rs` checks. The rules that hold across them are in
// the workspace's ARCHITECTURE.md, §The operation surface.

// The parsed request — `Request`, the `Op` enum and its `OpKind` echo — and
// the questions a request answers about its own shape.
mod request;
// The refusal vocabulary — `RejectCode`, `Disposition`, `FaultSite`,
// `Rejection` — and its two per-code policies.
mod reject;
// The answer: `Response`, its payload rows, and `CommittedAck`, the one
// shape the retry memo holds.
mod response;
// The transport's seam: `Codec`, `ParseError`, and the rejection an
// unparseable frame is given.
mod codec;
// Which principal each session speaks for, for one uptime.
mod session;
// The retry memo of committed-write acknowledgments.
mod memo;
// Every upstream store error lowered into a classified `Rejection`.
mod lower;
// EDITLINK's successor, the one request M10 assembles itself.
mod successor;
// What M10 requires of the engine that assembles it: the world it reads and
// the factory it writes through.
mod world;
// What the three publication reads need that no store computes.
mod publication;
// The lifecycle — `OperationSurface`, its sessions, `execute` — with the
// readability door and the two dispatch tables beneath it.
mod operation;

pub use codec::{Codec, ParseError};
pub use operation::{consult_read, OperationSurface, ReadPredicate};
pub use reject::{Disposition, FaultSite, RejectCode, Rejection};
pub use request::{ISpan, ISpanFault, Op, OpKind, ReqId, Request, SuccessorSpec, MAX_REQ_ID_BYTES};
pub use response::{BirthVersion, EditionClaim, IItem, Response, UniversalGrant};
pub use session::SessionId;
// EDITLINK's successor build, for the daemon's composer of its entry frame
// (signed ops): the one function the dispatch and the composer both resolve
// a successor's V-specs through, so the two cannot disagree.
pub use successor::{successor_link, Judgment};
pub use world::{FebeWorld, PublicationWorld, ReadableWorld, Stores, UniversalIndexRow};

// Every upstream type or constructor named on the request/response path, plus
// the two budgets a request is held to, re-exported so a caller of
// [`OperationSurface::execute`] spells one crate. That is where the line
// falls: what a CALLER must name to build a `Request` or read a `Response` is
// nameable from `skep_febe`; what an ASSEMBLER of the engine must name —
// `Kernel`, `WorldState`, `Namespace`, `Vstream`, `LinkWriter`, the four
// accessor traits — is not, because the binary that implements [`Stores`]
// holds every crate by construction. A constructor's ERROR type travels with
// it: a `Result` whose failure cannot be named is one a caller can only
// `unwrap`. A re-export claims no ownership: each type's owning module stays
// authoritative for it, exactly as M8 re-exports M7's slot numbering.
//
// M1, with the constructors, because `Address` is a field of thirty-odd `Op`
// variants and `validate` is the only way to make one: `validate`/`T4Error`
// for an address, `Span::new`/`T12Clause` for a span, `Tumbler::new`/
// `EmptySequence` for a tumbler, and `elem_addr`/`ElemPos`/`ElemError` for
// the element addresses `Op::Emit`'s `from` and `Op::Nullify`'s `target`
// take.
pub use skep_address::{
    elem_addr, validate, Address, ElemError, ElemPos, EmptySequence, Nat, Span, SpanSet, T12Clause,
    T4Error, Tumbler,
};
// M5, the publish shot's three request values included: `Op::Publish` is
// unbuildable without them, and `Run::new`/`RunError` is the one constructor
// of the runs a shot carries. `Deposit` is the two-state DEPOSIT DECLARATION
// `Op::Insert` carries, so an insert is unbuildable without it.
pub use skep_arrangement::{Base, Deposit, Run, RunError, Shot, ShotRun, ShotTerms, VPos, VSpec};
pub use skep_content::Val; // M4
                           // M8, `SlotSpec` included: every field of a `FourSet` is one, so the three
                           // descriptor ops are unbuildable without it.
pub use skep_discovery::{Cursor, FourSet, OrphanReport, SlotSpec, SupClaim, Window};
// M2, `AttestationError` included: `Attestation::new` is the one constructor
// of the value `Request::attest` carries, and its refusal travels with it —
// the rule above — so a caller assembling a signed request spells one crate
// for the tag, the blob, and what it refuses: the two spellings of "no
// signature", and a blob wider than M2's slot holds.
pub use skep_kernel::{Attestation, AttestationError, Seq}; // M2
pub use skep_namespace::PrincipalId; // M3
                                     // M6, the two enclosed shapes included: `Delivery` and `CompareReport` are
                                     // collections of `DeliveryItem` and `CorrPair`, and marshaling either answer
                                     // means naming the element it yields.
pub use skep_retrieval::{
    CompareReport, CorrPair, Deletions, Delivery, DeliveryItem, Operand, RegionSpec, SpanFault,
    Spec,
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
