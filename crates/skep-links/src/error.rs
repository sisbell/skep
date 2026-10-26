//! The typed rejections of M7's write surface, and FOLLOWLINK's ⊥ marker.
//!
//! They cover the write surface (§C/§D) and its staleness family (§7 —
//! [`NotBh4`], [`RetractStaleError`]); FOLLOWLINK's ⊥ marker is
//! [`Invalid`].
//!
//! Variant declaration order is each op's precedence: where an input
//! satisfies several rejections at once, the earlier-declared one speaks.
//! Three hoists put a check ahead of other verdicts. The first overrides
//! that order in [`EditLinkError`], which declares `OriginalNotResident`
//! ahead of the home pair, and the second in [`EmitError`]; the third keeps
//! it, its variant declared first:
//!
//! * the home/ω pair runs ahead of every other in-transaction verdict — each
//!   gate, each dedup short-circuit, and each op's own residence and
//!   well-formedness checks — so an unregistered or unowned home is refused
//!   on hit and miss, whatever else the input violates (Conflicts §8);
//! * [`EmitError::NonAddressDenotingType`], [`EmitError::SupersessionClass`],
//!   [`EmitError::ReplacesClass`] and [`EmitError::SlotTooLarge`] are
//!   pre-transact — in that firing order — so all four outrank every
//!   in-transaction verdict including the home/ω pair;
//! * [`RetractStaleError::NotBh4`] is likewise pre-transact, ahead of the
//!   constituent nullifies' own rejections.

use std::error::Error;
use std::fmt;

use skep_address::Address;
use skep_arrangement::SeatError;
use skep_namespace::MintError;

// Ownership: every op that deposits into a home document's link subspace
// carries a `NotOwner(Address)` rejection — the in-txn ω gate on that home
// (and, for nullify, on the target link's own address) — checked after home
// registration, before every other gate. The payload is the address that
// failed the check (M10 threads it into the rejection's fault site); because
// they carry it, these enums are not `Copy`.

/// MAKELINK rejection (ASN-0120; §C/§2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MakeLinkError {
    /// `home` is not a registered Document (L1a/ML0 P0).
    HomeNotRegistered,
    /// The caller is not `home`'s effective owner (ω, exact account match).
    NotOwner(Address),
    /// A `Resolve` V-spec fails wf.
    ///
    /// Its source is unregistered, or it is not a depth-2 content V-position
    /// with ordinal displacement (`#start = 2 ∧ start₁ = s_C ∧ #width = 2 ∧
    /// width₁ = 0`) — the deliberate depth-2 narrowing of ASN-0120's
    /// `#u_j ≥ 2` (Conflicts §12). `Addrs` slots have no wf step.
    IllFormedSpec,
    /// A span of an I-span slot is no content I-span.
    ///
    /// The I-span form ([`crate::SlotArg::Spans`]) records content I-spans
    /// verbatim, so each span must be one by its own bytes: its start a
    /// content-subspace element position and its width that run's ordinal
    /// displacement, `0…0.n` with `n ≥ 1` — `SlotArg::ill_formed_span`, the
    /// one spelling of the shape, by request arithmetic and no world read.
    /// `slot` is the slot in M7's numbering ([`crate::FROM`], [`crate::TO`],
    /// [`crate::TYPE`]) and `index` the span's position within it. The content
    /// clause is what keeps a span from spelling a type address's unit span —
    /// a credential type's, which would route a deposit around the credential
    /// sequence, the registry's, the `replaces` class — in a form no
    /// classifier of the daemon's reads. Never a registration or occupancy
    /// question of the spans' document: a ghost position is a valid name, as
    /// in the address form.
    NotContentSpan {
        /// The slot the span sits in: [`crate::FROM`], [`crate::TO`] or
        /// [`crate::TYPE`].
        slot: usize,
        /// The span's position within the slot.
        index: usize,
    },
    /// A slot is over one of the two per-slot budgets.
    ///
    /// It holds more than [`crate::MAX_SLOT_SPANS`] spans in whichever form
    /// built it — a `Resolve` slot resolved past the budget, an `Addrs`
    /// list naming more addresses than it, or a `Spans` list carrying more
    /// — or, for a `Resolve` slot, its
    /// specs command more than [`crate::MAX_SLOT_RESOLVE_STEPS`] run-list
    /// steps. One rejection for both, because both are the same answer to
    /// the caller — this slot asks for more than a slot may have — and one
    /// `Display` text, which names both numbers. Why the request that carried
    /// a slot bounds neither is the two constants' own account.
    SlotTooLarge,
    /// The type slot is empty as given (ML6 — `e₃ ≠ ∅`).
    ///
    /// The `Resolve` spec-set resolved to `⟨⟩`, or the `Addrs` name list was
    /// empty.
    EmptyTypeResolution,
    /// The resolved type slot lands in the `[R]` class.
    ///
    /// Retraction writes only through `nullify` (K ≁ R). The hint fold
    /// recognizes a deposit by its type slot's class, never by the surface it
    /// arrived through, so an `[R]`-classed link deposited here would
    /// tombstone every address its `TO` slot denotes; this is the same
    /// sole-writer fence `emit` states.
    RetractionClass,
    /// The resolved type slot lands in the `[K_sup]` class.
    ///
    /// Supersession writes only through `assert_sup`/`editlink`, the two
    /// paths that establish the Df-DISC(ii) schema (resident endpoints,
    /// single denoted addresses, irreflexivity) the walk family reads back as
    /// fact.
    SupersessionClass,
    /// The resolved type slot lands in the `replaces` class.
    ///
    /// That class ([`crate::replaces_type`]; PUB-5.15, RES-309/310) is the
    /// authority successor, whose one writer is
    /// [`crate::LinkWriter::makelink_replacing`], minting it in its record's
    /// own transaction. The grant fold reads a record's `replaces` as the link
    /// deposited at the record's own next address, so a `replaces` link put
    /// there by any other act would name a state for a record whose signed
    /// bytes named none — the sole-writer fence the `[K_sup]` one above
    /// states for its class. Refused whether or not the op carries a member:
    /// a record of this class is itself a `replaces` link.
    ReplacesClass,
    /// M3's mint failed structurally.
    Mint(MintError),
    /// M5's seat step refused (CL-OWN/CL-UNIQ).
    ///
    /// Unreachable for a freshly minted home link, kept typed per the design.
    Seat(SeatError),
}

/// Emit_K rejection (ASN-0086/0126/0128; §D).
///
/// `SupersessionClass` is the `[K_sup]` write fence (Conflicts §10) — the
/// exact parallel of the `[R]` fence, making `assert_sup`/`editlink` the sole
/// `[K_sup]`-writers so every stored claim is schema-conformant, which the
/// walk family leans on. `ReplacesClass` is the `replaces` class's fence,
/// making [`crate::LinkWriter::makelink_replacing`] that class's sole writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmitError {
    /// `home` is not a registered Document (P0).
    ///
    /// Enforced on hit and miss — Conflicts §8.
    HomeNotRegistered,
    /// The caller is not `home`'s effective owner (ω).
    ///
    /// Enforced on hit and miss, like the home check it follows.
    NotOwner(Address),
    /// `ty`'s coverage class is not registered (Managed gate (i)).
    NotRegistered,
    /// `ty ~ [R]` — retraction writes only through `nullify` (K ≁ R).
    ///
    /// Ahead of `ShapeViolation`: an `[R]`-typed emit with a non-conforming
    /// `|G|` satisfies both, and the fence speaks (design's K ≁ R before
    /// Sh-conf).
    RetractionClass,
    /// Span counts violate the registered shape (P3 Sh-conf).
    ///
    /// One `FROM` span always, and no `TO` span under Unary, exactly one
    /// under Binary, any finite number under Multi — each slot's spans counted
    /// as a set, a repeated span once.
    ShapeViolation,
    /// `ty ~ [K_sup]` — a class only `assert_sup` and `editlink` write.
    ///
    /// The fence is Conflicts §10's. Pre-transact.
    SupersessionClass,
    /// `ty ~ replaces` — the authority successor's class, which has one writer.
    ///
    /// That writer is [`crate::LinkWriter::makelink_replacing`] (PUB-5.15,
    /// RES-309/310). Pre-transact, and independent of the registry: the class
    /// is a commons value no registration holds, so without the fence the
    /// Managed gate's `NotRegistered` would refuse it — the fence is what
    /// keeps it refused if a registration ever names it.
    ReplacesClass,
    /// `ty` is not address-denoting.
    ///
    /// Rejected before any class computation (§Core data model totality).
    /// Pre-transact.
    NonAddressDenotingType,
    /// One of the two caller-sized slots is over the per-slot span budget.
    ///
    /// The budget is [`crate::MAX_SLOT_SPANS`] — `to`'s address count or
    /// `ty`'s own span count — as [`crate::emit_tuple`] holds it, which also
    /// says why `ty` is held to it as squarely as `to`. Pre-transact, and so
    /// ahead of `ShapeViolation`.
    SlotTooLarge,
    /// M3's mint failed structurally.
    Mint(MintError),
}

/// Nullify rejection (ASN-0128; §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NullifyError {
    /// `home` (`d_retr`) is not a registered Document (P0).
    HomeNotRegistered,
    /// The caller is not the effective owner (ω) of the address carried.
    ///
    /// That is `home`, or the target link's own address (self-retraction only
    /// — the v1 nullify target policy; owning the retraction's home does not
    /// license retracting someone else's link). `home` is checked first, so a
    /// caller owning neither is told about `home`.
    NotOwner(Address),
    /// P-tgt: `target` is neither a resident link nor this call's `a_emit`.
    ///
    /// `a_emit` is the address this call's own retraction tuple would occupy
    /// — sterilization made unreachable through the surface (DR).
    BadTarget,
    /// M3's mint failed structurally.
    Mint(MintError),
}

/// assert_sup rejection (ASN-0125 Df-DISC; §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssertSupError {
    /// `home` is not a registered Document (P0).
    HomeNotRegistered,
    /// The caller is not `home`'s effective owner (ω).
    NotOwner(Address),
    /// `old` or `new` is not a resident link.
    EndpointNotResident,
    /// `old == new` (Df-DISC(ii) irreflexivity).
    SelfSupersession,
    /// M3's mint failed structurally.
    Mint(MintError),
}

/// editlink rejection (ASN-0125 EDITop/DC; §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditLinkError {
    /// `original` is not a resident link.
    OriginalNotResident,
    /// `d_s` or `d_a` is not a registered Document.
    HomeNotRegistered,
    /// The caller is not the effective owner (ω) of the carried home.
    ///
    /// That home is `d_s` or `d_a`, whichever failed.
    NotOwner(Address),
    /// A successor slot carries more than [`crate::MAX_SLOT_SPANS`] spans.
    ///
    /// That is the budget every caller-shaped slot is held to. Checked ahead
    /// of `IllFormedSuccessor`, because every per-span step below it runs
    /// inside the transact.
    SlotTooLarge,
    /// The supplied successor is ill-formed.
    ///
    /// It has arity ≠ 3 (the deliberate narrowing of EDITop's N ≥ 3 —
    /// Conflicts §11), an empty type slot, or a non-level-uniform span in any
    /// slot (keeps `coverage_class` total for the DC guard, which reads the
    /// type slot, and for the hint fold's dedup key, which reads all three).
    IllFormedSuccessor,
    /// DC: the successor fails the DC guard.
    ///
    /// It is retraction-typed, `replaces`-typed (that class's one writer
    /// being [`crate::LinkWriter::makelink_replacing`] — PUB-5.15, RES-309),
    /// or `[K_sup]`-typed without the Df-DISC(ii) schema (unit-depth
    /// single-addr F/G, resident endpoints, irreflexive).
    DcViolation,
    /// M3's mint failed structurally.
    Mint(MintError),
}

/// The staleness family's served-only-where-declared rejection (§7).
///
/// `ty` is not registered with BH4 (Age), so `stale` does not serve it. A
/// typed refusal, never `Ok(vec![])` — so a caller reading an empty stale
/// set is reading a truthful freshness answer, never "this type does not do
/// staleness".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotBh4;

/// retract_stale rejection (§7).
///
/// It is the pre-transact BH4 fence, or a constituent nullify's own
/// rejection lifted into the batch. Not `Copy`, as `NullifyError` is not:
/// its `NotOwner` carries an `Address`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetractStaleError {
    /// `ty` is not registered with BH4 (Age).
    ///
    /// Rejected before any transaction is opened (served only where declared;
    /// the fence that keeps the batch nullifier off idem⊤ classes).
    NotBh4,
    /// A constituent `nullify` transact rejected.
    ///
    /// Earlier nullifies in the batch stay committed (append-only, no
    /// rollback).
    Nullify(NullifyError),
}

impl From<NullifyError> for RetractStaleError {
    fn from(e: NullifyError) -> Self {
        RetractStaleError::Nullify(e)
    }
}

/// FOLLOWLINK's ⊥: link or slot absent (§E).
///
/// Distinct from `Ok(⟨⟩)` — a valid-but-empty endset — so `⟨⟩ ≠ ⊥` is
/// unforgeable (F7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invalid;

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("followlink: link or slot absent (⊥)")
    }
}
impl Error for Invalid {}

impl fmt::Display for MakeLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MakeLinkError::HomeNotRegistered => {
                f.write_str("makelink: home is not a registered Document (L1a)")
            }
            MakeLinkError::NotOwner(_) => {
                f.write_str("makelink: the caller is not home's effective owner (ω)")
            }
            MakeLinkError::IllFormedSpec => f.write_str(
                "makelink: a V-spec is not a registered-source depth-2 content V-position (wf, Conflicts §12)",
            ),
            MakeLinkError::NotContentSpan { slot, index } => write!(
                f,
                "makelink: span {index} of slot {slot} is not a content I-span (a content-subspace element start and an ordinal width of at least 1)"
            ),
            MakeLinkError::SlotTooLarge => write!(
                f,
                "makelink: a slot carries more than {} spans, or its specs command more than {} resolve steps",
                crate::budget::MAX_SLOT_SPANS,
                crate::budget::MAX_SLOT_RESOLVE_STEPS
            ),
            MakeLinkError::EmptyTypeResolution => {
                f.write_str("makelink: the type slot is empty as given (ML6)")
            }
            MakeLinkError::RetractionClass => {
                f.write_str("makelink: ty ~ [R] — retraction writes only through nullify (K ≁ R)")
            }
            MakeLinkError::SupersessionClass => f.write_str(
                "makelink: ty ~ [K_sup] — supersession writes only through assert_sup/editlink",
            ),
            MakeLinkError::ReplacesClass => f.write_str(
                "makelink: ty ~ replaces — the authority successor writes only through a record's own makelink_replacing",
            ),
            MakeLinkError::Mint(e) => write!(f, "makelink: mint failed: {e}"),
            MakeLinkError::Seat(e) => write!(f, "makelink: seat refused: {e}"),
        }
    }
}
impl Error for MakeLinkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            MakeLinkError::Mint(e) => Some(e),
            MakeLinkError::Seat(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for EmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmitError::HomeNotRegistered => {
                f.write_str("emit: home is not a registered Document (P0)")
            }
            EmitError::NotOwner(_) => {
                f.write_str("emit: the caller is not home's effective owner (ω)")
            }
            EmitError::NotRegistered => f.write_str("emit: ty's coverage class is not registered"),
            EmitError::ShapeViolation => {
                f.write_str("emit: span counts violate the registered shape (P3)")
            }
            EmitError::RetractionClass => {
                f.write_str("emit: ty ~ [R] — retraction writes only through nullify (K ≁ R)")
            }
            EmitError::SupersessionClass => f.write_str(
                "emit: ty ~ [K_sup] — supersession writes only through assert_sup/editlink (Conflicts §10)",
            ),
            EmitError::ReplacesClass => f.write_str(
                "emit: ty ~ replaces — the authority successor writes only through a record's own makelink_replacing",
            ),
            EmitError::NonAddressDenotingType => {
                f.write_str("emit: ty is not address-denoting (rejected before class computation)")
            }
            EmitError::SlotTooLarge => write!(
                f,
                "emit: to or ty carries more than {} spans",
                crate::budget::MAX_SLOT_SPANS
            ),
            EmitError::Mint(e) => write!(f, "emit: mint failed: {e}"),
        }
    }
}
impl Error for EmitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            EmitError::Mint(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for NullifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NullifyError::HomeNotRegistered => {
                f.write_str("nullify: home is not a registered Document (P0)")
            }
            NullifyError::NotOwner(_) => f.write_str(
                "nullify: the caller is not the effective owner (ω) of the home or target link",
            ),
            NullifyError::BadTarget => f.write_str(
                "nullify: target is neither a resident link nor the address this call's own retraction tuple would occupy (P-tgt)",
            ),
            NullifyError::Mint(e) => write!(f, "nullify: mint failed: {e}"),
        }
    }
}
impl Error for NullifyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            NullifyError::Mint(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for AssertSupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssertSupError::HomeNotRegistered => {
                f.write_str("assert_sup: home is not a registered Document (P0)")
            }
            AssertSupError::NotOwner(_) => {
                f.write_str("assert_sup: the caller is not home's effective owner (ω)")
            }
            AssertSupError::EndpointNotResident => {
                f.write_str("assert_sup: old or new is not a resident link")
            }
            AssertSupError::SelfSupersession => {
                f.write_str("assert_sup: old == new (Df-DISC(ii) irreflexivity)")
            }
            AssertSupError::Mint(e) => write!(f, "assert_sup: mint failed: {e}"),
        }
    }
}
impl Error for AssertSupError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            AssertSupError::Mint(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for EditLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EditLinkError::OriginalNotResident => {
                f.write_str("editlink: original is not a resident link")
            }
            EditLinkError::HomeNotRegistered => {
                f.write_str("editlink: d_s or d_a is not a registered Document")
            }
            EditLinkError::NotOwner(_) => {
                f.write_str("editlink: the caller is not the effective owner (ω) of d_s or d_a")
            }
            EditLinkError::SlotTooLarge => write!(
                f,
                "editlink: a successor slot carries more than {} spans",
                crate::budget::MAX_SLOT_SPANS
            ),
            EditLinkError::IllFormedSuccessor => f.write_str(
                "editlink: successor arity ≠ 3, empty type slot, or a non-level-uniform span in some slot (Conflicts §11)",
            ),
            EditLinkError::DcViolation => f.write_str(
                "editlink: DC — retraction- or replaces-typed successor, or schema-non-conforming [K_sup]-typed successor",
            ),
            EditLinkError::Mint(e) => write!(f, "editlink: mint failed: {e}"),
        }
    }
}
impl Error for EditLinkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            EditLinkError::Mint(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for NotBh4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("stale: ty is not registered with BH4 (Age) — served only where declared (§7)")
    }
}
impl Error for NotBh4 {}

impl fmt::Display for RetractStaleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RetractStaleError::NotBh4 => f.write_str(
                "retract_stale: ty is not registered with BH4 (Age) — served only where declared (§7)",
            ),
            RetractStaleError::Nullify(e) => write!(f, "retract_stale: {e}"),
        }
    }
}
impl Error for RetractStaleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RetractStaleError::Nullify(e) => Some(e),
            _ => None,
        }
    }
}
