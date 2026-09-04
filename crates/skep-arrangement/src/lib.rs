//! # skep-arrangement — M5: Arrangements & Editing (Vstream)
//!
//! M5 owns every document's **mutable V→I arrangement** (the POOM — a content
//! subspace and a link subspace per document) and the **append-only
//! content-provenance relation R**, and it is the *only* place in the system
//! where destructive change lives (ASN-0047 P3). It provides the
//! editing/versioning operations (INSERT [ASN-0116], DELETE [ASN-0117], COPY
//! [ASN-0118], REARRANGE [ASN-0119/0084], CREATENEWVERSION [ASN-0123]), a
//! semantics-blind link-seating step for M7 (CL-OWN/CL-UNIQ), forward V→I
//! resolution and reverse I→V projection for readers, and the R read surface
//! for provenance queries. Every mutation funnels through one M2 composite,
//! where the J-couplings (J0: content-allocation ⇒ placement; J1★: placement ⇒
//! provenance; J-LV: link placements uncoupled from R) are enforced and each
//! content placement's R-append is co-located with its M-edit, so a reader
//! sees one consistent `(M, R)` root (ASN-0075 atomic root-swap by
//! co-location).
//!
//! The POOM is **authoritative mutable state, not a hint** (ASN-0047 P3): it
//! is the only component that loses information (`ContentRemove`,
//! `ContentReorder`), and it is recovered by replaying the one edit-delta
//! journal ([`M5Rec`]) onto [`M5State::genesis`]. R is authoritative and
//! non-recomputable from the current arrangement (a deleted address keeps its
//! R pair — P2) but, like the POOM, is recovered by replay. v1 has no
//! skip-serialized hints, so [`M5State::rebuild_derived`] is the identity.
//!
//! ## Boundary — deliberately NOT owned here
//!
//! * content bytes (M4) and address minting (M3) — M5 *orchestrates* both at
//!   its composite boundary, owns neither;
//! * link values and link semantics (M7) — M5 seats an opaque,
//!   already-allocated home-link address and never reads M7; interior link
//!   withdrawal is not offered (Conflicts #1);
//! * link-to-link reverse discovery — [`M5State::project`] is content-subspace
//!   only; the link side is M7's BH3;
//! * document registration (M3, eager-lazy split) — a fresh document's
//!   arrangement stays implicit/empty until M5 first touches it;
//! * content/link *queries* (M6/M8) — M5 exposes the read primitives;
//!   RETRIEVEV/SHOWDELETIONS/FINDDOCSCONTAINING are M6's compositions;
//! * ordering, durability, recovery (M2) — M5 stages [`M5Rec`]s through
//!   `transact` and is recovered by checkpoint-load + replay.
//!
//! ## Serialization key
//!
//! M5 contributes **no `Space` lock-key tag of its own**: every M5 mutation
//! serializes under an **M3** lock key for the touched document's allocation
//! domain — content edits under `M3State::content_lock_key(doc)`, VERSION
//! under `version_lock_key`/`document_lock_key`, link seating under M7's held
//! `link_lock_key(doc)` — so a document's arrangement edits and their
//! R-appends are co-serialized under that one key.
//!
//! ## Composition
//!
//! Per the Engine Composition Contract, M5 never names the concrete
//! `World`/`Record`: the engine implements [`HasM5`] for its
//! `W: WorldState` (the read accessor), lifts M5's delta via
//! `impl From<M5Rec> for W::Record` (the write-side mirror), and dispatches
//! its `Record::M5` variant into the fold [`M5State::apply_m5`] — moving the
//! whole record, never destructuring it (the `#[non_exhaustive]` variants
//! forbid foreign destructuring-construction anyway). Write-driving ops are
//! generic over `W` with **per-op trait bounds** (each impl block names
//! exactly the slices its ops read and the records they stage), so a minimal
//! test world can drive `delete`/`rearrange` with `HasM5 + HasM3` and
//! `From<M5Rec>` alone.

#![forbid(unsafe_code)]

mod auth;
mod error;
mod ops;
mod prov;
mod reads;
mod run;
mod runlist;
mod seat;
mod state;
mod vspace;

#[cfg(test)]
pub(crate) mod testutil;

pub use auth::Caller;
pub use error::{CopyError, DeleteError, InsertError, RearrangeError, SeatError, VersionError};
pub use ops::{Vstream, MAX_PLACED_RUNS};
pub use run::Run;
pub use seat::{seat_link, stage_seat_link};
pub use state::{M5Rec, M5State};
pub use vspace::{is_ordinal_vspan, ordinal_vspan, VPos, VSpec};

/// The engine's **read accessor** for M5's slice (Engine Composition
/// Contract): the engine implements this for its concrete world
/// (`W: WorldState + HasM5`), and M5 — built before `W` exists — codes
/// against it, reaching its slice as `stg.working().m5()` inside a composite
/// and `snapshot.world().m5()` for a read. READ side only; its write-side
/// mirror is the engine's `impl From<M5Rec> for W::Record` lift.
pub trait HasM5 {
    /// M5's slice of the world state.
    fn m5(&self) -> &M5State;
}

// Subspace convention (ASN-0047): V-positions are depth-2 tumblers
// [subspace, ordinal] (m = 2, ASN-0036 S8-depth / ASN-0084 scope), and the
// two subspace numerals themselves are M1's — T7 is M1's axiom, so M5 routes
// content from link through `skep_address::content_subspace` /
// `link_subspace` rather than restating the values it compares M3's minted
// element field `[s_C|s_L, k]` against.
