//! Shared error types (design: "Error types referenced throughout"). The
//! clause enums that belong to one operation live beside it: `T4Clause`/
//! `T4Error` with validation, `T12Clause` with `Span::new`, `ElemError` with
//! `elem_addr`.
//!
//! Serde bound (design preamble): the `try_from` deserialization shadows
//! require `TryFrom::Error: Display`, so `EmptySequence`, `T4Error`, and
//! `T12Clause` must implement `Display`; `WfError` — and, uniformly, every
//! other public error — carries one too, ahead of any serde boundary it might
//! ever back.

use std::error::Error;
use std::fmt;

/// `Tumbler::new` on the empty sequence — T0's carrier is the *nonempty*
/// finite sequences over ℕ (resolves ASN-0045's empty-tumbler question
/// upstream: `[]` is not a tumbler at all, so the classifier never sees it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptySequence;

impl fmt::Display for EmptySequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("empty component sequence (T0 admits only nonempty tumblers)")
    }
}
impl Error for EmptySequence {}

/// `add` (`⊕`) precondition failure: `¬Pos(w) ∨ actionPoint(w) > #a`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddPrecond;

impl fmt::Display for AddPrecond {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("⊕ precondition failed: requires Pos(w) and actionPoint(w) ≤ #a")
    }
}
impl Error for AddPrecond {}

/// `sub` (`⊖`) precondition failure: `a < w` (`⊖` requires `a ≥ w`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubPrecond;

impl fmt::Display for SubPrecond {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("⊖ precondition failed: requires a ≥ w")
    }
}
impl Error for SubPrecond {}

/// `checked_inc`: the TA5a gate refused — `inc_preserves_t4(t, k)` is false.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateViolation;

impl fmt::Display for GateViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TA5a gate violation: inc would not preserve T4-validity")
    }
}
impl Error for GateViolation {}

/// Operands not mutually level-compatible (S6/WF): every endpoint of every
/// operand must share one tumbler length L. Outside level-uniformity the
/// start↔reach interconversion breaks silently, which is what the gate guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LevelMismatch;

impl fmt::Display for LevelMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("operands are not mutually level-compatible (S6/WF)")
    }
}
impl Error for LevelMismatch {}

/// `Span::from_endpoints` rejection (WF: `s < r ∧ #s = #r`). The level clause
/// is checked FIRST (gate-first, design §6): a pair failing both yields
/// `LevelMismatch`, not `NotIncreasing`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfError {
    /// `¬(s < r)` — endpoints not strictly increasing.
    NotIncreasing,
    /// `#s ≠ #r` — endpoints in different length classes.
    LevelMismatch,
}

impl fmt::Display for WfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            WfError::NotIncreasing => "WF failed: endpoints not strictly increasing (s < r)",
            WfError::LevelMismatch => "WF failed: endpoint lengths differ (#s ≠ #r)",
        })
    }
}
impl Error for WfError {}

/// `split` rejection. The level conditions run FIRST (gate-first, design §6):
/// `LevelMismatch` wins when both fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitError {
    /// `¬(start < p < reach)` — the point is not strictly interior.
    NotInterior,
    /// σ not level-uniform (S4) or `#start ≠ #p`.
    LevelMismatch,
}

impl fmt::Display for SplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SplitError::NotInterior => "split failed: point not strictly interior (start < p < reach)",
            SplitError::LevelMismatch => "split failed: level conditions violated (S4/S6)",
        })
    }
}
impl Error for SplitError {}
