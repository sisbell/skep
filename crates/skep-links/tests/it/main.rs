//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Nothing but module declarations belongs here.
//!
//! The kernel-backed suites are cut by the section of the surface each
//! exercises — the deposit ops (`writes`), the supersession ops and the graph
//! they build (`supersession`), the typed reads (`reads`) and the §G
//! discovery primitives (`discovery`) — over the carrier-type and registry
//! contracts in `carrier`, with the assembled test world in `common`.

mod attested;
mod carrier;
mod common;
mod discovery;
mod reads;
mod supersession;
mod writes;
