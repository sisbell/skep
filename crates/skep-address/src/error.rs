//! The one rejection type produced in more than one place. Every other error
//! lives beside the single operation that produces it: `EmptySequence` with
//! `Tumbler::new`, `T4Clause`/`T4Error` with validation, `AddPrecond`/
//! `SubPrecond`/`GateViolation` with `⊕`/`⊖`/`checked_inc`, `ElemError` with
//! `elem_addr`, `T12Clause`/`WfError` with the span constructors, and
//! `SplitError` with `split`. `LevelMismatch` alone is shared — the span
//! algebra's pairwise gate and the span-set algebra both reject through it —
//! so it alone lives here.

use std::error::Error;
use std::fmt;

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
