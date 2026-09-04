//! # skep-namespace — M3: Namespace — Allocation, Registry & Ownership
//!
//! The **authoritative permanent name space**: M3 mints every fresh,
//! globally-unique, T4-valid address the system ever uses, records which
//! organizational entities (nodes, accounts, documents) exist, and answers
//! *"is this allocated?"* and *"who owns this?"* by prefix. It is the single
//! minting authority and the single arbiter of the entity/principal sets —
//! it owns **identity, not content**.
//!
//! Two senses, kept apart throughout: the **name space** M3 owns (this
//! module; the [`Namespace`] handle), and a **namespace** — ASN-0040's
//! `(anchor, g)`: one chain, one frontier, one lock (the `Ns`-named
//! internals and the five **chain** `*_lock_key` constructors; the two
//! registry keys — [`M3State::principals_lock_key`] and
//! [`M3State::nodes_lock_key`] — name registries, not namespaces).
//!
//! Two senses of **ghost**, kept apart the same way: B3's *ghost* is an
//! address that IS allocated and has no bytes behind it — a registered-empty
//! document, which [`M3State::is_allocated`] answers true for — while a
//! *ghost tumbler* is one of the reserved type addresses of the ghost region
//! below, which [`M3State::is_allocated`] answers false for, on every board,
//! forever.
//!
//! Four surfaces (§Public interface):
//!
//! * **Frontier allocation** (§A) — pure, composable mints
//!   ([`M3State::mint_content`] / [`M3State::mint_link`] /
//!   [`M3State::mint_version`] / [`M3State::mint_document`]) folded into
//!   M5/M7 composites, each returning the minted address plus the one
//!   [`M3Rec`] the caller stages, with the matching `*_lock_key`
//!   constructor for M2 `transact`'s `keys` \[ASN-0040 B1/B2/B6–B10,
//!   ASN-0123 VD\]. The remaining chain — the account chain, `A_account(N)`
//!   under a node and the sub-account `(A, 1)` under an account — is minted
//!   internally by [`Namespace::delegate`], the only op that allocates one,
//!   and its next value is published as the peek
//!   [`M3State::next_account_prefix`]. Every chain issues `c_{m+1}` and so
//!   opens at ordinal 1 on an empty frontier — except the ghost content
//!   chain, which opens at [`GHOST_POSITIONS`] + 1 (the ghost region
//!   below).
//! * **Entity operations** (§B) — the transact-driving [`Namespace`]
//!   handle: [`Namespace::create_new_document`] \[ASN-0103\],
//!   [`Namespace::delegate`] \[ASN-0042 O15/O17c\],
//!   [`Namespace::register_node`] \[ASN-0047 NodeBaptism\], and
//!   [`Namespace::fork`] \[ASN-0042 O10, account-tier case\].
//! * **Queries** (§C) — pure reads off any M2 snapshot: allocation and
//!   entity membership (exact chain membership, §2), the ω authorization
//!   predicate [`M3State::is_effective_owner`] beside the two projections of
//!   the owner it names ([`M3State::effective_owner`] for the id,
//!   [`M3State::effective_owner_prefix`] for the address it is seated at)
//!   \[ASN-0042 O1–O9\], id→prefix resolution, and the next-form peek
//!   [`M3State::next_account_prefix`] — plus two registry-free address
//!   answers: [`prefix_contains`], which answers where an address SITS and
//!   never who may write it, and [`first_document_address`], the slot an
//!   account's document chain opens at.
//! * **The ghost region** (owner ruling, 2026-08-26) — the first
//!   [`GHOST_POSITIONS`] content positions of [`ghost_home_doc`], spelled by
//!   [`ghost_position`]: five ghost tumblers that are compiled format
//!   constants, which M7's `ReservedAddrs::format` reads to build its
//!   reserved type addresses.
//!   M3 owns the allocation half of the ruling — the allocator skips those
//!   ordinals, so no mint on any board can ever issue one and
//!   [`M3State::is_allocated`] answers false at all five forever — while
//!   what each one MEANS is M7's.
//!
//! Spec traceability: each public item's doc-comment cites the labels it
//! realizes (B\*, O\*, P\*, T\*, V\*, and §§ of the M3 design), so a
//! reviewer can walk from code to design without the documents open.
//!
//! ## Boundary — deliberately NOT owned here
//!
//! * content bytes (M4), arrangements (M5), and link values (M7) — and no
//!   `M(d) = ∅` write at creation: a new document's arrangement is lazy in
//!   M5 (Conflicts §3);
//! * node-address origination — provisioning (NodeBaptism) mints node
//!   addresses outside the docuverse; [`Namespace::register_node`] only
//!   validates (Conflicts §1);
//! * the request lifecycle and session→principal binding (M10), including
//!   exactly-once/idempotency for every retried write — a retried
//!   [`Namespace::create_new_document`] or [`Namespace::fork`] yields a second
//!   empty document, while a retried [`Namespace::delegate`] or
//!   [`Namespace::register_node`] is refused; each op's doc says which, and
//!   how to tell a retry from a lost race;
//! * address algebra (M1 — M3 holds none of its own) and
//!   ordering/durability/recovery (M2 — M3 builds no WAL; it stages
//!   [`M3Rec`]s through `transact` and is recovered by checkpoint-load +
//!   replay, §8);
//! * deletion/revocation — none exists: allocations, nodes, and principals
//!   are permanent (B0/O12), and a frontier gap is unrepresentable (B1). The
//!   one carve-out is the ghost region above, which is compiled format
//!   rather than state: the skipped ordinals are never issued and never
//!   members, on every board.
//!
//! ## Composition
//!
//! Per the Engine Composition Contract, M3 never names the concrete
//! `World`/`Record`: the engine implements [`HasM3`] for its
//! `W: WorldState` (the read accessor), lifts M3's deltas via
//! `impl From<M3Rec> for W::Record` (the write-side mirror), and dispatches
//! its `Record::M3` variant into the fold [`M3State::apply_m3`]. M3's slice
//! is fully serialized — nothing skip-serialized — so it takes M2's default
//! `rebuild_derived`: restored verbatim from the loaded checkpoint, then
//! advanced by replaying the post-checkpoint records.

#![forbid(unsafe_code)]

mod error;
mod ops;
mod state;

pub use error::{CreateDocumentError, DelegateError, MintError, NodeError};
pub use ops::Namespace;
pub use state::{
    first_document_address, ghost_home_doc, ghost_position, prefix_contains, M3Rec, M3State,
    PrincipalId, BOOTSTRAP_PRINCIPAL, GHOST_POSITIONS, MAX_NODE_COMPONENTS,
    MAX_PRINCIPAL_COMPONENTS,
};

/// The engine's **read accessor** for M3's slice (Engine Composition
/// Contract; §Public interface): the engine implements this for its
/// concrete world (`W: WorldState + HasM3`), and M3 — built before `W`
/// exists — codes against it, reaching its slice as `stg.base().m3()` /
/// `stg.working().m3()` inside a composite and `snapshot.world().m3()` for
/// a read. READ side only; its write-side mirror is the engine's
/// `impl From<M3Rec> for W::Record` lift, through which the transact-driving
/// ops stage deltas via `stg.push(rec.into())`.
pub trait HasM3 {
    /// M3's slice of the world state.
    fn m3(&self) -> &M3State;
}
