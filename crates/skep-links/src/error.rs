//! The typed rejections of M7's write surface (§C/§D) and its staleness
//! family (§7 — [`NotBh4`], [`RetractStaleError`]), plus FOLLOWLINK's ⊥
//! marker [`Invalid`].
//!
//! Variant declaration order is each op's PRECEDENCE: where an input
//! satisfies several rejections at once, the earlier-declared one speaks.
//! Three hoists put a check ahead of its declared neighbours, and each is
//! declared where it fires:
//!
//! * the home/ω pair runs ahead of every other in-transaction verdict — each
//!   gate, each dedup short-circuit, and each op's own residence and
//!   well-formedness checks — so an unregistered or unowned home is refused
//!   on hit AND miss, whatever else the input violates (Conflicts §8);
//! * [`EmitError::NonAddressDenotingType`] and
//!   [`EmitError::SupersessionClass`] are pre-transact, so they outrank every
//!   in-transaction verdict including the home/ω pair;
//! * [`RetractStaleError::NotBh4`] is likewise pre-transact, ahead of the
//!   constituent nullifies' own rejections.

use std::error::Error;
use std::fmt;

use skep_address::Address;
use skep_arrangement::SeatError;
use skep_namespace::MintError;

// Ownership (as amended 2026-08-16): every op that deposits into a home
// document's link subspace carries a `NotOwner(Address)` rejection — the
// in-txn ω gate on that home (and, for nullify, on the target link's own
// address) — checked after home registration, before every other gate. The
// payload is the address that failed the check (M10 threads it into the
// rejection's fault site); carrying it costs these enums their `Copy`.

/// MAKELINK rejection (ASN-0120; §C/§2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MakeLinkError {
    /// `home` is not a registered Document (L1a/ML0 P0).
    HomeNotRegistered,
    /// The caller is not `home`'s effective owner (ω, exact account match).
    NotOwner(Address),
    /// A `Resolve` V-spec fails wf: unregistered source, or not a depth-2
    /// content V-position with ordinal displacement (`#start = 2 ∧ start₁ =
    /// s_C ∧ #width = 2 ∧ width₁ = 0`) — the deliberate depth-2 narrowing of
    /// ASN-0120's `#u_j ≥ 2` (Conflicts §12). `Addrs` slots have no wf step.
    IllFormedSpec,
    /// The type slot is empty as given (ML6 — `e₃ ≠ ∅`): the `Resolve`
    /// spec-set resolved to `⟨⟩`, or the `Addrs` name list was empty.
    EmptyTypeResolution,
    /// The resolved type slot lands in the `[R]` class — retraction writes
    /// only through `nullify` (K ≁ R). The hint fold recognizes a deposit by
    /// its type slot's CLASS, never by the surface it arrived through, so an
    /// `[R]`-classed link deposited here would tombstone every address its
    /// TO slot denotes; this is the same sole-writer fence `emit` states.
    RetractionClass,
    /// The resolved type slot lands in the `[K_sup]` class — supersession
    /// writes only through `assert_sup`/`editlink`, the two paths that
    /// establish the Df-DISC(ii) schema (resident endpoints, single denoted
    /// addresses, irreflexivity) the walk family reads back as fact.
    SupersessionClass,
    /// M3's mint failed structurally.
    Mint(MintError),
    /// M5's seat step refused (CL-OWN/CL-UNIQ) — unreachable for a freshly
    /// minted home link, kept typed per the design.
    Seat(SeatError),
}

/// Emit_K rejection (ASN-0086/0126/0128; §D). `SupersessionClass` is the
/// `[K_sup]` write fence (Conflicts §10) — the exact parallel of the `[R]`
/// fence, making `assert_sup`/`editlink` the sole `[K_sup]`-writers so every
/// stored claim is schema-conformant, which the walk family leans on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmitError {
    /// `home` is not a registered Document (P0; enforced on hit AND miss —
    /// Conflicts §8).
    HomeNotRegistered,
    /// The caller is not `home`'s effective owner (ω) — enforced on hit AND
    /// miss, like the home check it follows.
    NotOwner(Address),
    /// `ty`'s coverage class is not registered (Managed gate (i)).
    NotRegistered,
    /// `ty ~ [R]` — retraction writes only through `nullify` (K ≁ R). Ahead
    /// of `ShapeViolation`: an `[R]`-typed emit with a non-conforming `|G|`
    /// satisfies both, and the fence speaks (design's K ≁ R before Sh-conf).
    RetractionClass,
    /// Span counts violate the registered shape (P3 Sh-conf: `|F| = 1`;
    /// Unary `|G| = 0`, Binary `|G| = 1`, Multi finite).
    ShapeViolation,
    /// `ty ~ [K_sup]` — supersession writes only through
    /// `assert_sup`/`editlink` (Conflicts §10). Pre-transact.
    SupersessionClass,
    /// `ty` is not address-denoting — rejected before any class computation
    /// (§Core data model totality). Pre-transact.
    NonAddressDenotingType,
    /// M3's mint failed structurally.
    Mint(MintError),
}

/// Nullify rejection (ASN-0128; §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NullifyError {
    /// `home` (`d_retr`) is not a registered Document (P0).
    HomeNotRegistered,
    /// The caller is not the effective owner (ω) of the address carried:
    /// `home`, or the TARGET link's own address (self-retraction only —
    /// the v1 nullify target policy; owning the retraction's home does not
    /// license retracting someone else's link).
    NotOwner(Address),
    /// P-tgt: `target` is neither a resident link nor this call's own fresh
    /// emitter (sterilization made unreachable through the surface — DR).
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
    /// The caller is not the effective owner (ω) of the carried home —
    /// `d_s` or `d_a`, whichever failed.
    NotOwner(Address),
    /// The supplied successor has arity ≠ 3 (the deliberate narrowing of
    /// EDITop's N ≥ 3 — Conflicts §11), an empty type slot, or a
    /// non-level-uniform span in ANY slot (keeps `coverage_class` total for
    /// the DC guard, which reads the type slot, and for the hint fold's
    /// dedup key, which reads all three).
    IllFormedSuccessor,
    /// DC: the successor is retraction-typed, or `[K_sup]`-typed without the
    /// Df-DISC(ii) schema (unit-depth single-addr F/G, resident endpoints,
    /// irreflexive).
    DcViolation,
    /// M3's mint failed structurally.
    Mint(MintError),
}

/// The staleness family's served-only-where-declared rejection (§7): `ty` is
/// not registered with BH4 (Age), so `stale` does not serve it. A typed
/// refusal, never `Ok(vec![])` — so a caller reading an empty stale set is
/// reading a truthful freshness claim, never "this type does not do
/// staleness".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotBh4;

/// retract_stale rejection (§7): the pre-transact BH4 fence, or a
/// constituent nullify's own rejection lifted into the batch. (`Copy`
/// dropped with `NullifyError`'s — its `NotOwner` carries an `Address`.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetractStaleError {
    /// `ty` is not registered with BH4 (Age) — rejected before any
    /// transaction is opened (served only where declared; the fence that
    /// keeps the batch nullifier off idem⊤ classes).
    NotBh4,
    /// A constituent `nullify` transact rejected; earlier nullifies in the
    /// batch stay committed (append-only, no rollback).
    Nullify(NullifyError),
}

impl From<NullifyError> for RetractStaleError {
    fn from(e: NullifyError) -> Self {
        RetractStaleError::Nullify(e)
    }
}

/// FOLLOWLINK's ⊥: link or slot absent (§E). Distinct from `Ok(⟨⟩)` — a
/// valid-but-empty endset — so `⟨⟩ ≠ ⊥` is unforgeable (F7).
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
            MakeLinkError::EmptyTypeResolution => {
                f.write_str("makelink: the type slot is empty as given (ML6)")
            }
            MakeLinkError::RetractionClass => {
                f.write_str("makelink: ty ~ [R] — retraction writes only through nullify (K ≁ R)")
            }
            MakeLinkError::SupersessionClass => f.write_str(
                "makelink: ty ~ [K_sup] — supersession writes only through assert_sup/editlink",
            ),
            MakeLinkError::Mint(e) => write!(f, "makelink: mint failed: {e}"),
            MakeLinkError::Seat(e) => write!(f, "makelink: seat refused: {e:?}"),
        }
    }
}
impl Error for MakeLinkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            MakeLinkError::Mint(e) => Some(e),
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
            EmitError::NonAddressDenotingType => {
                f.write_str("emit: ty is not address-denoting (rejected before class computation)")
            }
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
                "nullify: target is neither a resident link nor this call's own fresh emitter (P-tgt)",
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
            EditLinkError::IllFormedSuccessor => f.write_str(
                "editlink: successor arity ≠ 3, empty type slot, or a non-level-uniform span in some slot (Conflicts §11)",
            ),
            EditLinkError::DcViolation => f.write_str(
                "editlink: DC — retraction-typed successor, or schema-non-conforming [K_sup]-typed successor",
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
