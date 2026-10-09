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
//! `(p, d)`, spelled `(anchor, g)` here: one chain, one frontier, one lock
//! (the `ns` module and its `Ns`-named items, and the five **chain**
//! `*_lock_key` constructors; the two crate-private registry keys —
//! `M3State::principals_lock_key` and `M3State::nodes_lock_key` — name
//! registries, not namespaces). ASN-0042 says *namespace* a third way, and
//! this module only cites it: a principal's subtree is its namespace, and an
//! account baptized with no principal of its own is an "organizational
//! namespace" — an account allocated without its seat, which M3 never makes.
//!
//! Two senses of **ghost**, kept apart the same way: B3's *ghost* is an
//! address that IS allocated and has no bytes behind it — a registered-empty
//! document, which [`M3State::is_allocated`] answers true for — while a
//! *ghost tumbler* is one of the reserved type addresses of the ghost region
//! below, which [`M3State::is_allocated`] answers false for, on every board,
//! forever.
//!
//! Two senses of **home**, kept apart the same way: an element's *home* is
//! the document it is minted under — [`M3State::mint_content`]`(home)`,
//! [`M3State::mint_link`]`(home)`, [`MintError::HomeNotRegistered`]
//! (P6/C2/L1a) — while PUB's *home* is an account's FIRST document, AUTH's
//! doc 1, born published by default (PUB-1.17). This module says **doc 1**
//! for the second and `home` only for the first: [`first_document_address`]
//! names the slot doc 1 occupies, and [`M3State::has_documents`] whether it
//! is occupied.
//!
//! Two senses of **operator**, kept apart the same way: ASN-0042's *node
//! operator* is the principal seated at a node prefix `[N]` (O14's π_N),
//! whose prefix contains every account under the node — and since
//! [`Namespace::delegate`] seats account-tier prefixes only (Conflicts §7),
//! the one such seat is π₀'s at `[1]`, which this module calls π₀ — while a
//! node's *operator*, by the claim-ceremony convention, is its first
//! delegate, seated at the node's first account `N·0·1`, whose prefix
//! contains its own sub-accounts and none of its siblings. This module says
//! *operator* only for the second.
//!
//! Four surfaces (§Public interface):
//!
//! * **Frontier allocation** (§A) — pure, composable mints
//!   ([`M3State::mint_content`] / [`M3State::mint_link`] /
//!   [`M3State::mint_version`] / [`M3State::mint_document`]) folded into
//!   M5/M7 composites, each returning the minted address plus the one
//!   [`M3Rec`] the caller stages, with the matching `*_lock_key`
//!   constructor for M2 `transact`'s `keys` \[ASN-0040 B1/B2/B6–B10,
//!   ASN-0123 VD\]. The two document-minting mints take the RESOLVED
//!   publication bit the caller resolved and stamp it on the record
//!   \[PUB-8.18\]. The remaining chain — the account chain, `A_account(N)`
//!   under a node and the sub-account `(A, 1)` under an account — is minted
//!   internally by [`Namespace::delegate`], the only op that allocates one,
//!   and its next value is published as the peek
//!   [`M3State::next_account_prefix`]. Every chain issues `c_{m+1}`, so on
//!   an empty frontier its first member lands on the slot it opens at,
//!   ordinal 1 — except on the ghost content chain, whose first member lands
//!   at [`GHOST_POSITIONS`] + 1, past the slots the ghost region reserves
//!   (below). Two of the chains issue elements — a document's content chain
//!   and its link chain — and no third does: the allocator refuses to issue
//!   any other element, so no element in any other subspace is ever minted,
//!   and subspace 3, where type names are spelled, stays unallocated
//!   ([`M3State::is_allocated`]).
//! * **Entity operations** (§B) — the transact-driving [`Namespace`]
//!   handle: [`Namespace::create_new_document`] \[ASN-0103\],
//!   [`Namespace::delegate`] \[ASN-0042 O15/O17c\],
//!   [`Namespace::register_node`] \[ASN-0047 NodeBaptism\], and
//!   [`Namespace::fork`] \[ASN-0042 O10, account-tier case\].
//! * **Queries** (§C) — pure reads off any M2 snapshot: allocation and
//!   entity membership (exact chain membership, §2), the ω authorization
//!   predicate [`M3State::is_effective_owner`] beside the three readers of
//!   the owner it names ([`M3State::effective_owner`] for the id,
//!   [`M3State::effective_owner_prefix`] for the address it is seated at,
//!   [`M3State::effective_owner_pair`] for the whole entry, AUTH-6.37) and
//!   [`M3State::account_seat`], the owner of a registered document or
//!   account, that entry by one lookup at its own account
//!   \[ASN-0042 O1–O9\], id→prefix resolution and the walk of every seat
//!   ([`M3State::principals`]), the four chain-end reads — the next-form
//!   peek [`M3State::next_account_prefix`], the content chain's next
//!   address [`M3State::next_content_address`] (the content-frontier
//!   read's answer, AUTH-6.38), the version chain's latest member
//!   [`M3State::latest_version`], and the emptiness of an account's
//!   document chain [`M3State::has_documents`] — and the publication read
//!   [`M3State::published`] and its enumeration [`M3State::documents`] —
//!   the engine's ONE definition of a document's publication state, the
//!   bit its own allocation record journaled \[PUB-7.8, PUB-7.10; owner
//!   ruling D1\] — plus three registry-free address answers:
//!   [`prefix_contains`], which answers where an address SITS and never
//!   who may write it, and the two slots a chain opens at,
//!   [`first_document_address`] for an account's document chain and
//!   [`first_version_address`] for a document's version chain.
//! * **The ghost region** (owner ruling, 2026-08-26) — the first
//!   [`GHOST_POSITIONS`] content addresses of [`ghost_home_document`],
//!   spelled by [`ghost_position`]: five ghost tumblers that are compiled
//!   format constants, which M7's `ReservedAddrs::format` reads to build its
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
//!   members, on every board;
//! * a publication transition — none exists, in either direction: a
//!   document's publication state is fixed at its mint and journaled on its
//!   own allocation record, and no M3 function changes it (PUB-1.9:
//!   publication is at birth and forever; PUB-1.68). The `publish` op, M5's
//!   publish shot, changes no bit either: it appends a NEW member to a
//!   version chain, born published through [`M3State::mint_version`]. The
//!   three-valued wire flag and the first-mint refusal at the daemon's door
//!   (PUB-8.20) are the daemon's, and the exception set derived over the bit
//!   (PUB-7.5) is the engine's (owner rulings D1/D2).
//!
//! ## Composition
//!
//! Per the Engine Composition Contract, M3 never names the concrete
//! `World`/`Record`: the engine implements [`HasM3`] for its
//! `W: WorldState` (the read accessor), lifts M3's deltas via
//! `impl From<M3Rec> for W::Record` (the write-side mirror), and dispatches
//! the variant that carries an [`M3Rec`] into the fold [`M3State::apply_m3`],
//! the one fold that moves the slice ([`HasM3`] states what its implementor
//! owes). M3's slice is fully serialized — nothing skip-serialized — so it
//! takes M2's default `rebuild_derived`: restored verbatim from the loaded
//! checkpoint, then advanced by replaying the post-checkpoint records.

#![forbid(unsafe_code)]

// The typed rejections of the public surface, each enum in its op's pinned order.
mod error;
// Namespaces — ASN-0040's `(p, d)`, spelled `(anchor, g)` here: the frontier
// and lock key, built only here; the chain-family rule; a chain's slots by
// ordinal; its opening slots.
mod ns;
// The ghost region: the five reserved type addresses M7 reads, and the floor
// that keeps the allocator past them.
mod ghost;
// The journal delta `M3Rec`, its two sealed payloads `Allocation` and
// `Principal`, and the two field doors, and the identity type it names with
// that type's two fixed ids.
mod record;
// M3's slice: `M3State`, genesis and the fold, the frontier arithmetic and
// the two registry caps; beneath it `state/mint.rs` (§A: the lock keys, the
// five mints and the two peeks, each a mint without its record) and
// `state/query.rs` (§C: every other query).
mod state;
// The `Namespace` handle: the four entity operations, each one transaction.
mod ops;

pub use error::{CreateDocumentError, DelegateError, MintError, RegisterNodeError};
pub use ghost::{ghost_home_document, ghost_position, GHOST_POSITIONS};
pub use ns::{first_document_address, first_version_address};
pub use ops::Namespace;
pub use record::{
    Allocation, M3Rec, Principal, PrincipalId, BOOTSTRAP_PRINCIPAL, SYSTEM_PRINCIPAL,
};
pub use state::{
    head_document, prefix_contains, system_account, system_node, M3State, MAX_NODE_COMPONENTS,
    MAX_PRINCIPAL_COMPONENTS,
};

/// The engine's **read accessor** for M3's slice (Engine Composition
/// Contract; §Public interface): the engine implements this for its
/// concrete world (`W: WorldState + HasM3`), and M3 — built before `W`
/// exists — codes against it, reaching its slice inside a composite as
/// `stg.base().m3()` for a gate and `stg.working().m3()` for a mint — the
/// state that mint's record is staged against ([`M3Rec::Allocate`]) — and as
/// `snapshot.world().m3()` for a read. READ side only; its write-side mirror
/// is the engine's `impl From<M3Rec> for W::Record` lift, through which the
/// transact-driving ops stage deltas via `stg.push(rec.into())`.
///
/// IMPLEMENTORS OWE one fact the signature cannot carry: `m3()` is the very
/// slice the world's `WorldState::apply` folds this crate's records into —
/// every [`M3Rec`] the `From<M3Rec>` lift carries, unchanged, through
/// [`M3State::apply_m3`], once per record — and that fold is the only thing
/// that moves it. Every other record's fold carries the slice through
/// unchanged; a checkpoint carries it through this crate's own serde form,
/// neither skipped nor defaulted; and the world's `rebuild_derived` hands it
/// back as it was decoded, M3's share of that rebuild being M2's default, the
/// identity. Three promises rest on it. A mint called on
/// `stg.working().m3()` reads the frontier every record pushed before it
/// advanced, so successive mints in one composite issue distinct addresses
/// and, given the caller's half ([`M3Rec::Allocate`]), no address is issued
/// twice (B8, the single baptismal authority it names). [`Namespace`]'s
/// gates, read off `stg.base().m3()`, judge the state the op commits into.
/// And every answer this crate promises never regresses —
/// [`M3State::is_allocated`]'s `true` (B0), a seat (O12/O13), a document's
/// bit (PUB-1.9), a `Some` from [`M3State::latest_version`],
/// [`M3State::next_account_prefix`] or [`M3State::next_content_address`] —
/// holds from one `snapshot.world().m3()` to the next only because nothing
/// else replaces the slice. An implementor that answered any other
/// `M3State`, or moved this one by any other path, would void all three, and
/// nothing in this crate can check it.
pub trait HasM3 {
    /// M3's slice of the world state.
    fn m3(&self) -> &M3State;
}
