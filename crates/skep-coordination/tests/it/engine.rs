//! M9 contract tests over a real kernel (InMemory), group C — the reactive
//! rule engine: registration validation, the three-leg certification lint,
//! fire/step/quiescence with the two-transaction gap accounted, the
//! rotation's fairness, the draft boundary and the guest-class look,
//! scoping, the divergence backstop, and the armer warning. Every assertion
//! states a claim the design or interface makes — nothing more.
//!
//! The claims live in this module's children, one concern each:
//! `registration` (a rule's validation and its lint), `scheduling` (the peek,
//! the fire, the step and quiescence, scoped or not), `guest_class` (the draft
//! boundary and the guest-class look) and `monitors` (the divergence count and
//! the armer graph).

mod guest_class;
mod monitors;
mod registration;
mod scheduling;
