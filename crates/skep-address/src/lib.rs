//! # skep-address — M1: Address & Span Algebra
//!
//! The pure, stateless value-level calculus of the address space: tumbler
//! identity and total order (ASN-0034: T0–T3), T4 field structure —
//! validation, the node/account/document/element classifier, field and
//! subspace projection, decidable containment (ASN-0045; ASN-0034: T4/T4b,
//! T6, T7) — position arithmetic (`⊕`, `⊖`, `inc`, action-point/`sig`, the
//! ordinal shift; ASN-0034: TA*/TS*/D*), and the interval algebra over spans
//! and span-sets (ASN-0053: WF/SC/S*/N*). Every function is total within its
//! stated preconditions, consults no state, performs no I/O, and leans on
//! nothing below ℕ (`num_bigint::BigUint`).
//!
//! Spec traceability: each public item's doc-comment cites the spec labels it
//! realizes (T0, T4, S3, …), so a reviewer can walk from code to design
//! without the documents open.
//!
//! ## Errors
//!
//! Every rejection type lives beside the one operation that produces it;
//! [`LevelMismatch`], produced across the span and span-set algebra, is the
//! one shared error and keeps its own module. Every public error implements
//! `Display` and [`std::error::Error`], uniformly: the validating
//! deserialization below requires `Display` of [`EmptySequence`], [`T4Error`]
//! and [`T12Clause`], and a caller that boxes any of the others meets the same
//! surface.
//!
//! ## Serde — deserialization is a mint path
//!
//! Every type carrying a standing invariant deserializes **through its own
//! constructor**, never by a bare derive: [`Tumbler`] through
//! [`Tumbler::new`] (T0 nonemptiness), [`Address`] through [`validate`] (T4,
//! with `level` re-derived rather than restored, so a stored level cannot
//! disagree with [`classify`]), [`Span`] through [`Span::new`] (T12). Each
//! pairs that with the serialize shadow its own at-rest shape needs — the
//! bare component sequence, the flat tumbler, the `(start, width)` pair — so
//! the two sides agree and a self-describing format round-trips by
//! construction rather than by coincidence. [`SpanSet`], [`Level`] and
//! [`Class`] derive both sides: none carries a standing invariant, and a
//! span-set's members validate through `Span`'s shadows, so the round trip is
//! inherited. [`CanonicalForm`] carries no serde at all; what a future one
//! would have to re-establish is recorded on the type.
//!
//! ## Boundary — deliberately NOT owned here
//!
//! * the **allocator** — durable monotone frontier, active-allocator set,
//!   journaling, crash recovery (M3): M1 supplies only the pure [`inc`] and
//!   the TA5a gate predicate [`inc_preserves_t4`]; enforcing the gate and
//!   persisting the frontier is M3's obligation;
//! * the **inverse coverage index** ("which spans cover *t*", the spanfilade)
//!   and any scale-up interval index (M7/M8) — M1 hands up span *values*;
//! * the **content↔byte mapping** (M4/M5);
//! * **ownership resolution** — the `ω` longest-prefix owner over the
//!   principal registry (M3): M1 gives only the per-address containment
//!   predicates `ω` is built from.
//!
//! ## Composition
//!
//! M1 is not a store: it has no slice, no record type, no fold, no accessor
//! trait — and no locks, threads, interior mutability, or caches. It is the
//! shared low-level value crate that sits *below* every store (composition
//! contract), so it depends on nothing in the workspace; in particular it
//! carries no edge to `skep-kernel` (M2). M1 holds no persistent state:
//! "authoritative vs hint" collapses to "primary value vs derived value", and
//! every value is immutable — recovery logic exists nowhere in this crate.

mod address;
mod arithmetic;
mod error;
mod span;
mod spanset;
mod tumbler;

pub use address::{
    classify, content_subspace, document_of, is_t4_valid, link_subspace, ordinal, parent,
    same_account, same_document, same_node, under_document, validate, zeros, Address, Class, Level,
    T4Clause, T4Error,
};
pub use arithmetic::{
    action_point, add, checked_inc, displacement, elem_addr, inc, inc_preserves_t4, shift,
    shift_ordinal, sig, sub, AddPrecond, ElemError, ElemPos, GateViolation, SubPrecond,
};
pub use error::LevelMismatch;
pub use span::{
    classify_spans, difference, intersect, merge, split, subtree_of, Span, SpanRel, SplitError,
    T12Clause, WfError,
};
pub use spanset::{
    canonical_key, cover, difference_sets, equiv, hull, intersect_sets, union, CanonicalForm,
    IntoSpans, SpanSet, Spans,
};
pub use tumbler::{is_prefix, Components, EmptySequence, Nat, Pos, Tumbler};
