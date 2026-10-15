//! The bounds the daemon's core reads: the request-body cap of the two
//! frame-carrying routes (wire.md §Transport), the change feed's page byte
//! budget (wire.md §The change feed) and the operator stream's cadences —
//! the standing line's, the feed walk's progress and the hold-down the edge
//! pairs judge their second line by (`operations.md` §1.1 m11, m12, m15).
//!
//! Each is `pub`, the daemon reading the request-body cap and the hold-down
//! from here. The daemon's own bounds — the small-body cap, the feed's two
//! page-size bounds, the blob route's chunk, its two deadlines and the
//! pruner's cadence — are `skepd`'s `limits.rs`; the media resource's own
//! numbers — the per-file cap, the fetch pool and its two intervals, the
//! upload pool, the default per-account limit's share and floor, the
//! standing-uploads bound, the logs' compaction trigger and the picture
//! cell's cap — are `skep_media::limits`'s, each `pub` there for its reader.

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
pub const MAX_REQUEST_BODY: usize = 8 * 1024 * 1024;

/// THE STANDING LINE's CADENCE — one hour, INTERIM (D1: a daemon constant
/// for a cadence, as the pruner's interval is, and its precedent): the
/// interval of the checkpoint thread's timed wait on the write path's
/// signal (`commits::CheckpointSignal::wait`), at each tick of which the
/// thread writes ONE `standing:` line re-saying every standing bad state
/// that stands — the eight, in the line's order: the write path's halt, the
/// kernel's poison, a stopped feed file, the pruner's thread gone, the feed
/// walk's thread gone, the cell index failed, the floor binding,
/// CLAIMED-PERMISSIVE — and nothing on a healthy board (`operations.md` §1
/// THE RATES; §1.1 m11).
/// What the interval bounds is how long a standing state goes unsaid past
/// its transition: each is said once at its transition, so a stream rotated
/// past that line holds nothing of it, and an hour is the most a reader of
/// the current stream waits to learn of a state that still stands. A tick
/// on a healthy board costs the eight reads — an atomic load or one lock
/// each — and writes nothing.
pub const STANDING_INTERVAL: Duration = Duration::from_secs(3600);

/// THE FEED WALK's PROGRESS CADENCE, the boundary half — 1,000 boundaries,
/// INTERIM (D1: a daemon constant for a cadence, as the pruner's interval
/// is): where `commits.log` was lost or torn, the walk that re-covers the
/// uncovered positions runs behind the listener on a thread of its own
/// (`commits/feed.rs`) and says one `progress:` line every so many
/// boundaries it has proved, or every [`FEED_WALK_PROGRESS_INTERVAL`],
/// whichever comes first (`operations.md` §1.1 m15; §3.3 step 2). What the
/// cadence bounds is how long a long walk goes unsaid — a walk's line is
/// what tells it from a hang — against how many lines a walk of the
/// retained window writes: at a thousand boundaries a line, a window of a
/// million positions is a thousand lines over the walk's length, and a
/// boundary costs one whole-world reconstruction, so a thousand of them is
/// seconds at the least.
pub const FEED_WALK_PROGRESS_BOUNDARIES: u64 = 1_000;

/// THE FEED WALK's PROGRESS CADENCE, the time half — ten seconds, INTERIM
/// (D1): the longest a walk goes without a `progress:` line while it walks,
/// where fewer than [`FEED_WALK_PROGRESS_BOUNDARIES`] boundaries fit in it —
/// a large world's boundaries, each a reconstruction of seconds. Ten seconds
/// is well under a supervisor's patience and well over the stream's own
/// cost of a line.
pub const FEED_WALK_PROGRESS_INTERVAL: Duration = Duration::from_secs(10);

/// THE EDGE PAIRS' HOLD-DOWN — 15 s, INTERIM (the register's; D1: a daemon
/// constant for a cadence, as the standing line's and the pruner's are):
/// how long a bound that refused must have stood CLEAR — no refusal — before
/// its next admission says the second line of its edge pair, `landing:`
/// (`operations.md` §1.1 m12; §4 rows 27 and 33; §6's three rows). ONE
/// constant for the eight pairs: the five permit pools — the
/// reconstruction, the class scan, the fetch, the upload and the write —
/// the live-stream budget, the challenge store's live evictions and the
/// workers' `accept`; each judges it through `skep_util::permits`'s
/// [`EdgeTracker`](skep_util::permits::EdgeTracker), the one mechanism. The
/// first line, `failure:`, is said when a request FIRST meets the bound; a
/// refusal inside the hold-down keeps the episode open and restarts it, so
/// an episode is two lines however long it lasts and however often the
/// bound flaps at exactly the load that matters — a permit returns, a
/// request is admitted, the next is refused.
///
/// WHY SECONDS, AND WHY FIFTEEN. The reference figures the pairs stand
/// among: the accept loop's retry pause 10 ms (`listen.rs`'s
/// `ACCEPT_RETRY_PAUSE` — `EMFILE` flaps as fast as connections close and
/// open, so a hold-down of milliseconds would say a pair per flap); a read
/// pool's permit held for one request, at most the transport's
/// `TRANSFER_DEADLINE` of 30 s; an upload's held at most the blob route's
/// `BLOB_TRANSFER_BOUND` (the daemon's `limits.rs`), ten minutes; the
/// `/events` keepalive, 15 s (wire.md §The commit stream); the challenge
/// TTL, 60 s (`auth::session`'s `CHALLENGE_TTL`). Fifteen seconds is long
/// enough that a pool releasing one permit at a time under steady overload
/// says one pair for the overload and not one per permit, and short enough
/// that an operator reading the stream learns the condition cleared within
/// the keepalive's own cadence. The arms the constant's words admit are 5,
/// 15 and 30 s; the owner's figure is 15.
///
/// WHEN THE SECOND LINE COMES. It is judged at the holder's next ADMITTED
/// act — a permit taken, a stream admitted, a mint that evicted no live
/// nonce, an `accept` that succeeded — never by a timer and never at a
/// refusal: a landing says the condition is clear, and only an act the
/// bound admitted shows it so. The ops lanes record §5.3 states the
/// property for the challenge pair and it holds of every pair: on a quiet
/// holder the `landing:` comes at its first admitted act after the
/// hold-down, however late.
pub const EDGE_HOLD_DOWN: Duration = Duration::from_secs(15);

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
/// (`commits/feed.rs`), so a row larger than the bound — an address of
/// pathological depth — is refused by the same measure and never served
/// past it.
pub const MAX_CHANGES_PAGE_BYTES: usize = 256 * 8 * 1024;
