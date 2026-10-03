//! M9 contract tests over a real kernel (InMemory), group A — the predicate
//! language: Γ_D-checked typing with `Reg` expansion, the pure evaluator's
//! view/UV semantics and the denotation of every former, and the PD0
//! classifier. Every assertion states a claim the design or interface makes
//! — nothing more.
//!
//! The claims live in this module's children, one concern each: `typing` (the
//! checker), `evaluation` (the evaluator and the reads it makes) and `dynamics`
//! (the classifier).

mod dynamics;
mod evaluation;
mod typing;
