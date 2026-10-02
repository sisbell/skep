//! The two request-body caps the wire promises (wire.md §Transport), and the
//! change feed's three page bounds (wire.md §The change feed).

use std::num::NonZeroUsize;

/// Request-body cap for the two frame-carrying routes, enforced on the
/// declared `Content-Length` before any body byte is read or allocated.
/// Pre-media value — wire frames are small.
///
/// This bounds the REQUEST, not the allocation it commands, and the ratio
/// between them is what anyone raising it must price. The FLOOR under every
/// JSON-carrying route is `serde_json`'s: the whole `Value` tree is built
/// before any codec cap runs, and a `Value` is order 32 bytes against as
/// little as two wire bytes of dense array, so a body of arbitrary shape
/// buys roughly twenty times its size in transient heap — for a frame the
/// codec is then about to refuse. Above that floor the per-byte write
/// discipline adds the `insert` path's own multiplier, minting one `Val`
/// per input byte, each its own allocation, for roughly forty times the
/// body in live heap; the codec's `MAX_INSERT_VALUES` is what bounds that
/// one. Raising this number alone raises both amplified costs with it.
///
/// It is also the budget of the one frame body the daemon composes out of
/// the STORE rather than out of a request — a shot's entry-frame body
/// (`auth::entry`'s `MAX_SHOT_BODY_BYTES`, parity with this) — so
/// raising it raises what the write-path check reads and verifies per shot.
///
/// REVISIT at the media round: blob upload raises this for its route only,
/// which is the shape [`crate::body_cap`] already has.
pub(crate) const MAX_REQUEST_BODY: usize = 8 * 1024 * 1024;

/// Request-body cap for every route that carries no frame — 16 KiB, ONE
/// constant at EVERY small-body route (rc-1, owner 2026-09-26: "n 8 KiB cap.
/// lets bump ti 16kb limit" → "all small routes"; raised from 8 KiB for the
/// hybrid handshake). `POST /session` carries `{"principal": n}` or the
/// SIGNED body whose `sig` is the hybrid blob in hex — 6,912 B at a loopback
/// origin under tag 1, 7,157 B at the longest DNS-legal origin (the
/// record-cap measurements §4), which the old 8 KiB left a kilobyte's room;
/// a body posted to `/health`, `/changes`, `/dump` or an unknown path is read
/// whole and then never looked at. Those routes have no use for the ceiling
/// above, and offering it to them offers the `Value` tree that rides on it.
pub(crate) const MAX_SMALL_BODY: usize = 16 * 1024;

/// `/changes`'s page size when `limit` is absent — 256 rows.
pub(crate) const DEFAULT_CHANGES_LIMIT: NonZeroUsize =
    NonZeroUsize::new(256).expect("256 is not zero");

/// `/changes`'s page-size ceiling — 4,096 rows; a larger `limit` is refused,
/// not clamped (the never-silent posture applied to paging).
pub(crate) const MAX_CHANGES_LIMIT: usize = 4096;

/// THE PAGE BYTE BUDGET of `/changes` (signed ops, round 7 — bu7-2 = reg-H1;
/// SO-I9; P29): the most bytes one page's entries may marshal to, 2 MiB —
/// 256 rows, the default page, × 8 KiB, the bound on a row the wire admits.
/// A page that would pass it is REFUSED whole, naming the budget and the
/// largest `limit` that fits, never served short (PUB-6.44).
///
/// THE ARITHMETIC. The row count was chosen before rows carried `attest`,
/// and an attested row is dominated by that member: under tag 1 the hybrid
/// blob is 3,373 bytes, 6,746 as hex, with its `alg` token and punctuation
/// under 6,800; the rest of a row — the position and the time (at most
/// twenty digits each), the op's token, the documents (two addresses at
/// most, `nullify`'s two homes, of ordinary depth), the op's own terms (a
/// link address, or two decimal counts), the member names and the
/// punctuation — is a few hundred bytes more, so an attested row of this
/// board's ordinary addresses is under 7.2 KiB and 8 KiB bounds it with
/// room. So the DEFAULT page of attested rows is always served whole, the
/// maximal `limit` over attested rows (~27.6 MB at 4,096 rows) is not, and
/// a reader of a signed feed pages at or below ~300 rows. The budget is
/// measured in the feed's own marshal as rows are rendered
/// (`write_path/feed.rs`), so a row larger than the bound — an address of
/// pathological depth — is refused by the same measure and never served
/// past it.
pub(crate) const MAX_CHANGES_PAGE_BYTES: usize = 256 * 8 * 1024;
