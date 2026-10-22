//! The bounds the daemon's core reads.
//!
//! They are the request-body cap of the two frame-carrying routes (wire.md
//! §Transport), the change feed's page byte budget and its resident window
//! (wire.md §The change feed) and the operator stream's cadences — the
//! standing line's, the feed walk's progress and the hold-down the edge
//! pairs judge their second line by (`operations.md` §1.1 m11, m12, m15).
//!
//! Each is `pub`, the daemon reading three from here: the request-body cap,
//! the hold-down and the standing line's cadence. The daemon's own bounds —
//! the small-body cap, the feed's two page-size bounds, the blob route's
//! chunk, its two deadlines and the pruner's cadence — are `skepd`'s
//! `limits.rs`; the media resource's own numbers — the per-file cap, the
//! fetch pool and its two intervals, the upload pool, the default
//! per-account limit's share and floor, the standing-uploads bound, the
//! logs' compaction trigger and its minimum, and the picture cell's cap —
//! are `skep_media::limits`'s, each `pub` there where another crate reads it
//! and crate-private where none does.

use std::time::Duration;

/// The request-body cap of the two frame-carrying routes, `/op` and `/op-at`.
///
/// It is enforced on the declared `Content-Length`, by the daemon's own
/// transport, before any body byte past those that arrived with the head is
/// read or allocated: a value sized for wire frames, which are small, and
/// not for media.
///
/// It bounds the request, not the allocation the request commands, and the
/// ratio between them is what anyone raising it must price. The floor under
/// every JSON-carrying route is `serde_json`'s: the whole `Value` tree is
/// built before any codec cap runs, and a `Value` is order 32 bytes against
/// as little as two wire bytes of dense array, so a body of arbitrary shape
/// buys roughly twenty times its size in transient heap — for a frame the
/// codec is then about to refuse. Above that floor the per-byte write
/// discipline adds the `insert` path's own multiplier, minting one `Val`
/// per input byte, each its own allocation, for roughly forty times the
/// body in live heap; the codec's `MAX_INSERT_VALUES` is what bounds that
/// one. Raising this number alone raises the first amplified cost with it
/// and leaves the second at what that cap admits.
///
/// Two of the core's bounds are relations to it, and move with it. A shot's
/// entry-frame body (`auth::entry`'s `MAX_SHOT_BODY_BYTES`, parity with
/// this) is the one entry-frame body the daemon composes out of the store
/// rather than out of a request, so raising this raises what the write-path
/// check reads and verifies per shot. The blocked-prefix list's supply file
/// (`auth::blocked`'s `MAX_BLOCKED_SUPPLY_BYTES`) is read whole at every
/// start, and at every reissue with the supply's lock held at the head of
/// routing, so raising this raises how long a reissue can hold every
/// request behind it.
///
/// The blob route's larger bodies are not this constant's: it carries its
/// own cap, [`MAX_BLOB_BYTES`](skep_media::limits::MAX_BLOB_BYTES), on a
/// body the daemon's own transport never holds whole in memory — raising
/// this one in its place would buy a buffered body of that size, the first
/// amplified cost above with it.
pub const MAX_REQUEST_BODY: usize = 8 * 1024 * 1024;

/// The standing line's cadence: one hour, interim (`operations.md`; D1).
///
/// It is a daemon constant for a cadence, as the pruner's interval is, and
/// it has two readers, so moving it moves both. The checkpoint thread's
/// timed wait on the write path's signal (`commits::CheckpointSignal::wait`)
/// ticks at it, and at each tick the thread says one `standing:` line
/// re-saying every standing bad state that stands — the ten, in the line's
/// order: the write path's halt, the kernel's poison, the journal damage a
/// history read met, a stopped feed file, the pruner's thread gone, the feed
/// walk's thread gone, the cell index failed, the floor binding, a
/// deposit's file the store cannot read, `CLAIMED-PERMISSIVE` — and nothing
/// on a healthy board (`operations.md` §1 the rates; §1.1 m11). And
/// `skepd`'s panic hook rates a recurring panic by it: one line per site on
/// its thread per interval while its memory holds the site, the panics
/// between counted on the next.
///
/// What the interval bounds is how long a standing state goes unsaid past
/// its transition: each is said once at its transition, so a stream rotated
/// past that line holds nothing of it, and a reader of the current stream
/// waits up to an hour, plus the work the thread has in hand, to learn of a
/// state that still stands. The tick is answered at the first wait past its
/// deadline that finds no raise pending, so the turn the thread is in when
/// the tick falls due, and each turn a raise pending at a wait calls for,
/// comes first. A tick on a healthy board costs the ten reads — an atomic
/// load or one lock each, save the floor's fresh read of the volume's free
/// space — and writes nothing.
pub const STANDING_INTERVAL: Duration = Duration::from_secs(3600);

/// The feed walk's progress cadence, the boundary half: 1,000, interim (D1).
///
/// It is a daemon constant for a cadence, as the pruner's interval is, and
/// counts boundaries: where `commits.log` was lost or torn, the walk that
/// re-covers the uncovered positions runs behind the listener on a thread of
/// its own (`commits/feed.rs`) — at the open instead, where the OS refuses
/// the thread — and says one `progress:` line as it proves a boundary, once
/// this many are proved or [`FEED_WALK_PROGRESS_INTERVAL`] has passed since
/// its last line or its start, whichever comes first (`operations.md`
/// §1.1 m15; §3.3 step 2). What the cadence bounds is how long a long walk
/// goes unsaid — a walk's line is what tells it from a hang — against how
/// many lines a walk of the retained window says: at a thousand boundaries
/// a line, a window of a million positions is a thousand lines over the
/// walk's length, and a boundary costs one whole-world reconstruction, so a
/// thousand of them is seconds at the least. The open's classification of
/// the bare positions `feed-index.log` lost — a reconstruction a position,
/// before the board serves — says its own `open:` line at the same figures,
/// a position in a boundary's place.
pub const FEED_WALK_PROGRESS_BOUNDARIES: u64 = 1_000;

/// The feed walk's progress cadence, the time half: ten seconds, interim (D1).
///
/// It is how long a walk, while it walks, goes without a `progress:` line
/// before the next boundary it proves says one, where fewer than
/// [`FEED_WALK_PROGRESS_BOUNDARIES`] boundaries fit in it — a large world's
/// boundaries, each a reconstruction of seconds. Ten seconds is well under
/// a supervisor's patience and well over the stream's own cost of a line.
/// The open's classification of the bare positions `feed-index.log` lost
/// reads it too, for its own `open:` line.
pub const FEED_WALK_PROGRESS_INTERVAL: Duration = Duration::from_secs(10);

/// The edge pairs' hold-down: 15 s, interim (the register's; D1).
///
/// It is a daemon constant for a cadence, as the standing line's and the
/// pruner's are, and is how long a bound that refused must have stood
/// clear — no refusal — before its next admission says the second line of
/// its edge pair, `landing:` (`operations.md` §1.1 m12; §4 rows 27 and 33;
/// §6's three rows). One constant for the ten pairs: the five permit
/// pools — the reconstruction, the class scan, the fetch, the upload and
/// the write — the worker pool, the live-stream budget, the live streams'
/// threads, the challenge store's live evictions and the workers' `accept`;
/// each judges it through `skep_util::permits`'s
/// [`EdgeTracker`](skep_util::permits::EdgeTracker), the one mechanism. The
/// first line, `failure:`, is said when a request *first* meets the bound;
/// a refusal inside the hold-down keeps the episode open and restarts it, so
/// an episode is two lines however long it lasts and however often the
/// bound flaps at exactly the load that matters — a permit returns, a
/// request is admitted, the next is refused.
///
/// **Why seconds, and why fifteen.** The reference figures the pairs stand
/// among: the accept loop's retry pause 10 ms (`skepd`'s
/// `ACCEPT_RETRY_PAUSE`, in `server/listen.rs` — `EMFILE` flaps as fast as
/// connections close and open, so a hold-down of milliseconds would say a
/// pair per flap); a read pool's permit held for one request — a
/// reconstruction's or a class scan's while its handler builds the answer,
/// which the transport's `TRANSFER_DEADLINE` of 30 s does not bound, and a
/// fetch's from its whole-file check through its transfer, the transfer
/// alone under the blob route's `BLOB_TRANSFER_BOUND`; an upload's over its
/// body's stream, which that bound (the daemon's `limits.rs`), ten minutes,
/// holds, and over its finish, which it does not; the `/events` keepalive,
/// 15 s (wire.md §The commit stream); the challenge TTL, 60 s
/// (`auth::session`'s `CHALLENGE_TTL`). Fifteen seconds is long enough that
/// a pool releasing one permit at a time under steady overload says one pair
/// for the overload and not one per permit, and short enough that an
/// operator reading the stream learns the condition cleared within the
/// keepalive's own cadence. The figures the constant's words admit are 5, 15
/// and 30 s; it is 15.
///
/// **When the second line comes.** It is judged at the holder's next
/// *admitted* act — a permit taken, a stream admitted, a mint that evicted
/// no live nonce, an `accept` that succeeded, a connection a worker takes
/// with another still free — never by a timer and never at a refusal: a
/// landing says the condition is clear, and only an act the bound admitted
/// shows it so. The ops lanes record §5.3 states the property for the
/// challenge pair and it holds of every pair: on a quiet holder the
/// `landing:` comes at its first admitted act after the hold-down, however
/// late.
pub const EDGE_HOLD_DOWN: Duration = Duration::from_secs(15);

/// The page byte budget of `/changes`: 2 MiB (signed ops; SO-I9; P29).
///
/// It is the most bytes one page's entries and the commas between them may
/// marshal to — 256 rows, the default page, × 8 KiB, the bound a row of
/// ordinary addresses stays under (the arithmetic below). A page that would
/// pass it is refused whole, naming the budget and the largest `limit` that
/// fits, never served short (PUB-6.44).
///
/// **The arithmetic.** The row count is not sized to rows that carry
/// `attest`, and an attested row is dominated by that member: under tag 1
/// the hybrid blob is 3,373 bytes, 6,746 as hex, with its `alg` token and
/// punctuation under 6,800; the rest of a row — the position and the time
/// (at most twenty digits each), the op's token, the documents (two
/// addresses at most, `nullify`'s two homes, of ordinary depth), the op's
/// own terms (a link address, or two decimal counts), the member names and
/// the punctuation — is a few hundred bytes more, so an attested row of
/// this board's ordinary addresses is under 7.2 KiB and 8 KiB bounds it
/// with room. So the *default* page of such rows is always served whole,
/// the maximal `limit` over attested rows (~27.6 MB at 4,096 rows) is not,
/// and a reader of a signed feed pages at or below ~300 rows. The budget is
/// measured in the feed's own marshal as rows are rendered
/// (`commits/feed.rs`), so a row larger than the bound — an address of
/// pathological depth — is counted by the same measure, and a page it
/// carries past the budget is refused, never served.
pub const MAX_CHANGES_PAGE_BYTES: usize = 256 * 8 * 1024;

/// The change feed's resident window: 2,048 positions, interim (D1).
///
/// It is how many of the newest committed positions the daemon holds in
/// memory for the change feed — `commits.log`'s entries and the four derived
/// twins over them — the rest read from the feed's files by position
/// (`commits/feed/window.rs`), so a page's bytes never depend on which side
/// of the window its positions lie. The feed's files are kept whole from
/// genesis (wire.md §The change feed, Retention), so without a window the
/// daemon's memory for the feed would grow with every commit ever made; with
/// it the feed costs the memory of a window's entries, about 200 bytes each,
/// plus one marker slot (~3.4 KB) per attested position inside it. Counted
/// in positions, not in entries: a position is a committed seq, and a commit
/// of several records takes several, so a window holds at most this many
/// entries and usually fewer.
///
/// **Why two thousand and forty-eight.** It is the journal's retained
/// window as the daemon sets it — a checkpoint every 1,024 commits, two
/// kept (`skepd`'s `CHECKPOINT_EVERY_COMMITS` × `RETAINED_CHECKPOINTS`) —
/// which is what the feed held resident before it was kept whole, so the
/// daemon's memory for a board of any age is what it was for a board that
/// had just reclaimed. Every position a live client re-reads after a
/// `/events` tick, and every page the head writer's resume reads, lies
/// inside it on a board at the cadence; a mirror beginning from genesis, or
/// a history pane, reads below it from disk, by one seek and one sequential
/// read per page.
///
/// A test build moves it through `commits::set_feed_resident_window`.
pub const FEED_RESIDENT_WINDOW: u64 = 2 * 1024;
