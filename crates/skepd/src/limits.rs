//! The three request-body caps the wire promises (wire.md §Transport), the
//! change feed's three page bounds (wire.md §The change feed), and the blob
//! route's own bounds that are the daemon's — the streaming arm's chunk,
//! its two deadlines and the pruner's cadence (wire.md §Media). The media
//! resource's own numbers — the per-file cap, the fetch pool and its two
//! intervals, the upload pool, the default per-account limit's share and
//! floor, the standing-uploads bound, the logs' compaction trigger and the
//! picture cell's cap — are `skep_media::limits`'s, the daemon taking the
//! four it reads from there.

use std::num::NonZeroUsize;
use std::time::Duration;

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
/// The media round's raise is NOT this constant's: the blob route carries
/// its own cap, [`MAX_BLOB_BYTES`](skep_media::limits::MAX_BLOB_BYTES), on
/// a body that never sits whole in memory — raising this one alone would
/// have bought a buffered body of the cap's size, the amplified costs above
/// with it.
pub(crate) const MAX_REQUEST_BODY: usize = 8 * 1024 * 1024;

/// THE STREAMING ARM's CHUNK — 64 KiB, INTERIM: the one buffer the blob
/// route holds of a body, filled from the socket and handed to the store
/// per read. The arm's whole memory per in-flight upload is this buffer and
/// the hasher's state; a body at the cap costs 1,024 reads of it.
pub(crate) const BLOB_CHUNK: usize = 64 * 1024;

/// THE IDLE BOUND of a blob body (the record's "idle bound the subsystem
/// design pins", clause (5)) — 30 s, INTERIM: the socket's read deadline
/// while a body streams, renewed by any byte and never by silence; a
/// connection whose body stalls past it ends, its upload KEPT (a dropped
/// connection keeps its upload until the expiry).
pub(crate) const BLOB_IDLE_BOUND: Duration = Duration::from_secs(30);

/// THE PRUNER's CADENCE — one hour, INTERIM (D1: a daemon constant for a
/// cadence, as the nonce TTL is): the interval between two passes of the
/// pruner over `blobs/` (`skep-media`'s `pruner.rs`), the first pass running
/// once the cell index's rebuild at open completes. What the interval
/// bounds is how long an expired partial or a lapsed, unreferenced file
/// stands past its expiry — the lease interval is days, so an hour's lag on
/// top of it is nothing a scope reads (the scopes are record-derived and
/// count neither) and a pass over a quiet board costs one directory
/// listing.
pub(crate) const PRUNE_INTERVAL: Duration = Duration::from_secs(3600);

/// THE STANDING LINE's CADENCE — one hour, INTERIM (D1: a daemon constant
/// for a cadence, as the pruner's interval is, and its precedent): the
/// interval of the checkpoint thread's timed wait on the write path's
/// signal (`write_path::CheckpointSignal::wait`), at each tick of which the
/// thread writes ONE `standing:` line re-saying every standing bad state
/// that stands — the write path's halt, the kernel's poison, a stopped feed
/// file, the pruner's dead thread, the floor binding, CLAIMED-PERMISSIVE —
/// and nothing on a healthy board (`operations.md` §1 THE RATES; §1.1 m11).
/// What the interval bounds is how long a standing state goes unsaid past
/// its transition: each is said once at its transition, so a stream rotated
/// past that line holds nothing of it, and an hour is the most a reader of
/// the current stream waits to learn of a state that still stands. A tick
/// on a healthy board costs the six reads — an atomic load or one lock each
/// — and writes nothing.
pub(crate) const STANDING_INTERVAL: Duration = Duration::from_secs(3600);

/// THE TRANSFER BOUND of one blob request — 10 minutes, INTERIM: the
/// deadline on SLOWNESS the idle bound cannot give (a peer pacing one byte
/// per interval renews the idle bound for as long as it cares to, and the
/// transport's own `TRANSFER_DEADLINE` of 30 s would cut an honest body at
/// the cap on a slow link). A body at the cap needs 112 KB/s to pass it; a
/// request cut here leaves its upload standing at the last durable grain,
/// resumable at once — which is what makes a per-request bound safe where a
/// per-file one would not be.
pub(crate) const BLOB_TRANSFER_BOUND: Duration = Duration::from_secs(600);

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
