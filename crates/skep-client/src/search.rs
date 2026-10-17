//! The shell's half of search (`client.md` §4e), behind the `search` feature.
//!
//! It is what the design gives the embedder of `skep-search` and the index
//! crate does not hold — "The shell owns three things the crate does not:
//! the index's directory (§4e.4), its feed consumer (§4e.2) and the bridge's
//! one call and one event (§4e.5)". The feature is off by default, as `tls`
//! is, so the default build of this library holds no feed consumer and
//! makes none of its content reads — `client.md` §1.1's "no `/changes` feed
//! consumer" true of it as written — and the shell, skep-shell, turns it on,
//! as §7 has the shell turn `tls` on ("`tls` on in the shell"). Everything
//! here is a library API an embedder calls, and nothing assumes a page or a
//! webview.
//!
//! The parts, each under the design rule it realizes:
//!
//! * [`directory`] — `<data>/index/<chain>/` beside the key store (§4e.4):
//!   [`SearchDir`] under the data directory the shell names, [`BoardDir`]
//!   keyed by `H.1`'s chain, the modes `0700`/`0600` set at creation
//!   (§3.3), the save by `<name>.tmp` written, synced and renamed over the
//!   old, the aside by a rename that never overwrites (`search.md` §5.4),
//!   and the feeder's advisory lock (`search.md` §5.6).
//! * [`consumer`] — the feed consumer, [`Consumer`] (§4e.2): one per board;
//!   it owns the lock, the two indexes and the document index's two parts
//!   under one read-write lock around the engines, polls `/changes` one
//!   read per changed document per poll in parts past the delivery budget
//!   at the class the index takes, keeps each range's `held` as the
//!   `/health` pair read before a draining poll, saves every 64 changed
//!   units or 30 seconds and at close, runs the resume at open (`GET
//!   /chain?at`, the `H.k` re-read, `Resume::judge`), the triggers — widen,
//!   narrow, the person's refresh and forget — and the orphan test; and
//!   [`events`], the `/events` stream as the shell's loop input.
//! * [`places`] — the document index the plane reads (§4e.2; A-255):
//!   addresses, first lines and counts per account, held as the search index
//!   is — a published part and a part per principal (PATTERNS P39) — one
//!   file per part beside its index.
//! * [`state`] — [`State`], the `index` event's ten arms as a typed enum
//!   (§4b.2): positions, units, bytes, ranges, a version — never a UI
//!   string; the words are the UX's.
//! * [`bridge`] — the bridge call (§4e.5): `search(session | guest, query,
//!   opts) → {hits, places, state}` — the query length-bounded before the
//!   crate's grammar sees it, the pair composed by role with the
//!   supplement's header ranges and the honored set, `places` drawn at the
//!   call's class with a standing at the document grain, the crate's flags
//!   forwarded, the state the pair's.
//! * [`jump`] — the jump's landing rule (`search.md` §3.4), a pure function
//!   over the `compare` answer's pairs: `Carried`, `Partial`, `Absent` — and
//!   `Pinned` where the board refused the re-projection on its budgets.
//!
//! What this module does not hold: the engine, the document model, the hit,
//! the grammar, the ranking, the file's layout, the budgets and the ceiling
//! (`skep-search`'s); the box, the results and the jump's face (the UX's);
//! the `skep` command's search; R9c's sidecar; any UI string.

pub mod bridge;
pub mod consumer;
pub mod directory;
pub mod jump;
pub mod places;
pub mod state;

#[cfg(test)]
mod tests;

pub use bridge::{Place, QueryTooLong, SearchAnswer, SearchOpts, SessionRef, Who, QUERY_BOUND};
pub use consumer::{
    events, Consumer, Events, Orphan, Poll, Stop, MAX_DELIVERY_ITEMS, SAVE_EVERY, SAVE_EVERY_UNITS,
};
pub use directory::{BoardDir, SearchDir, LOCK_NAME};
pub use jump::{land, landing_of, Correspondence, Landing};
pub use places::{PlaceRecord, Places, PlacesError};
pub use state::{Lost, Newer, Range, State};
