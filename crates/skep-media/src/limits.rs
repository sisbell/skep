//! The media resource's own numbers (wire.md §Media).
//!
//! They are the per-file cap, the fetch pool and its two intervals, the
//! upload pool, the default per-account limit's share and floor, the
//! standing-uploads bound, the logs' compaction trigger and its minimum, and
//! the picture cell's cap. A number is `pub` where another crate reads it
//! and crate-private where none does. The daemon reads the per-file cap on
//! the blob route's request body, the two pools' counts in its worker
//! minimum, the standing-uploads bound in a refusal's face and the default
//! limit's share and floor in its binary's help; its pruner suite reads the
//! compaction trigger and its minimum. The fetch's two intervals are read
//! through `serve::Progress` alone, and the cell's cap through the one
//! classification. The daemon's own bounds (the request-body caps, the
//! change feed's page bounds, the streaming arm's chunk and its two
//! deadlines, the pruner's cadence) stay the daemon's.

use std::time::Duration;

/// The blob route's cap, 64 MiB: the most bytes one upload may declare.
///
/// It is interim (wire.md §Media), and also the request-body cap of
/// `/blob/upload`'s two body-carrying methods. The per-file cap of the
/// daemon's own, which a venue's limits record may lower and never raise.
/// Sized for v1's images (v1 media stays images only): a camera's raw frame
/// is tens of megabytes, a web picture a few, so 64 MiB holds every picture
/// a board is likely to be handed with room, and no video. What it bounds
/// at the upload is disk and transfer, never memory: the streaming arm
/// (`server/request.rs`'s `BodySource`) holds one `BLOB_CHUNK` (the
/// daemon's) of the body at a time, and the store writes each chunk to the
/// partial as it arrives. A declared `length` past it is refused at the
/// creation with `413 payload_too_large` naming the per-file cap in force —
/// this number, unless a limits record lowers it — before any body byte.
pub const MAX_BLOB_BYTES: u64 = 64 * 1024 * 1024;

/// The fetch pool, 2: the most `GET /blob?i=` answers held whole at once.
///
/// Interim (the media record's Op inventory 3: "every v1 answer therefore
/// reads its whole file before its first byte, and the route admits at most
/// a permit pool of answers at once"; PATTERNS P29). Each answer holds its
/// file in memory from the check to the last byte written (`serve.rs`), so
/// what the route commands is at most [`MAX_BLOB_BYTES`] times this,
/// 128 MiB; a fetch past the pool is refused `503 fetch_busy`, retry-class
/// as `history_busy` is, and faced as pending by a client. Counted into
/// `MIN_WORKERS` beside the reconstruction, class-scan, upload and write
/// pools (`server/listen.rs`), so a caller holding every permit of all five
/// still leaves a worker free. The reconstruction pool's own number, for its
/// reason: two keep a page of figures serviceable without letting a
/// stranger's fetches occupy the worker pool.
pub const MAX_CONCURRENT_FETCHES: usize = 2;

/// The upload pool, 4: the most `/blob/upload` creations and resumes at once.
///
/// Interim (the media record's Op inventory 1: "an upload is admitted at
/// most an upload permit pool at once, counted in `MIN_WORKERS` beside the
/// reconstruction and class-scan pools — the fetch pool's twin — a creation
/// past it refused retry-class"; the register M-I5 (f); PATTERNS P29). What
/// it bounds is worker occupancy and not memory: an admitted stream holds
/// its worker from the permit to its finish — up to `BLOB_TRANSFER_BOUND`,
/// each byte inside `BLOB_IDLE_BOUND` (the daemon's two deadlines) — while
/// its memory is one `BLOB_CHUNK` and a hasher's state, so the fetch pool's
/// 2, a memory figure over whole files, is not this pool's to copy. A
/// board's uploads are its account holders' and v1's media are images
/// alone, so four streams at once are four people on slow links, or one
/// person's batch; a fifth meets `503 upload_busy`, retry-class as
/// `fetch_busy` and `history_busy` are, before any body byte — faced as
/// pending by a client, where without the pool it would meet a daemon that
/// answers nothing. Counted into `MIN_WORKERS` beside the four other pools
/// (`server/listen.rs`), so a caller holding every permit of all five still
/// leaves a worker free; the pool is asked or refused, never told (D9).
pub const MAX_CONCURRENT_UPLOADS: usize = 4;

/// The byte interval of a fetch: 1 MiB, interim.
///
/// It is the most bytes a stream writes between two re-resolutions of its
/// requester and its gate (the media record's Op inventory 3, "at a byte
/// interval the subsystem design pins with the route"; the register M-I2
/// (g)), so a session killed or a grant revoked mid-transfer fetches no
/// draft byte past the interval in flight. Sixteen chunks of the daemon's
/// `BLOB_CHUNK`; the re-check is one `authenticate` and one `retrieve_i` of
/// the span, cheap for a published origin and a guest, the gate's one
/// re-read for a draft's grantee.
pub(crate) const FETCH_RECHECK_BYTES: u64 = 1024 * 1024;

/// The time interval beside it: 5 s, interim.
///
/// It is the record's "or at a time interval pinned beside it, whichever
/// comes first": a reader draining at a trickle holds no interval open past
/// this but for the chunk being written; the re-check runs between chunks,
/// at whichever of the two bounds comes first, judged on the media gate's
/// clock so a suite drives it through the clock seam.
pub(crate) const FETCH_RECHECK_INTERVAL: Duration = Duration::from_secs(5);

/// The default per-account limit's share: one eighth of the volume's capacity.
///
/// It is the divisor applied to the capacity the daemon reads off the
/// volume once at its start (`gate.rs`, `Limits::defaults_for`; `media.md`
/// Op inventory 1, "uploads are open by default, with a default per-account
/// limit in force from start"; the register M-I6 (b): a per-account limit
/// is always in force). D1, a daemon constant; a written limits record
/// overrides the figure whole.
pub const DEFAULT_LIMIT_SHARE: u64 = 8;

/// The default per-account limit's floor: 256 MiB, the least the default is.
///
/// It holds whatever the volume's capacity, and is the whole default on a
/// host that cannot answer its capacity.
pub const DEFAULT_LIMIT_FLOOR_BYTES: u64 = 256 * 1024 * 1024;

/// The standing-uploads bound: 8 per principal, interim.
///
/// It is the most standing uploads one principal holds (`media.md` Op
/// inventory 1, "a principal's standing uploads are bounded in number, a
/// gate constant the subsystem design pins"; PATTERNS P13, P29), counted
/// off its own records at the creation, a creation past it refused before
/// its partial and its record — `507 deposit_refused`, `scope` `standing`,
/// the face naming the end of one of them as the act. What it bounds is
/// what the pending bytes cannot: a creation with no body counts nothing, so
/// without it a principal could hold any number of empty partials, each an
/// inode the floor never reads and a record every open and every pass
/// walks.
pub const MAX_STANDING_UPLOADS: usize = 8;

/// The logs' compaction trigger: 4×, interim.
///
/// The pruner's pass rewrites `uploads.log` or `leases.log` to its current
/// records once its lines number at least [`COMPACTION_MIN_LINES`] and more
/// than this many times those records (`media.md` §The media stores, "the
/// pruner's pass rewrites either store the same way once its log has passed
/// a size trigger, a multiple of its current records the subsystem design
/// pins"; PATTERNS P22) — so between restarts neither log grows past the
/// trigger, or that minimum where it is the larger, plus one pass
/// interval's appends.
pub const COMPACTION_TRIGGER: usize = 4;

/// The compaction's minimum: 1,024 lines, interim.
///
/// A log under it that has not stopped is never rewritten by a pass,
/// whatever its ratio, so a small board's logs are not rewritten per pass
/// for a handful of retirements.
pub const COMPACTION_MIN_LINES: usize = 1024;

/// The cell's cap: 1 KiB, interim (wire.md §Media).
///
/// It is the most bytes the picture cell's parser (`cell.rs`) builds a JSON
/// tree for. A canonical cell is under 140 bytes (the kind's address, 64
/// hex characters of hash, a sixteen-digit count and the member names), so
/// the cap is some eight times the largest cell that can parse; what it
/// bounds is the tree `serde_json` builds before the first schema check for
/// a body that names the kind and is no cell — which the daemon must parse
/// to refuse by name (D13's carve-out) — at the record cap's ratio of close
/// to a hundred times the body (`skep-identity`'s `payload.rs`), under the
/// serialization lock, per value of an insert. The cap is the kind's and
/// every schema's under it: a body past it parses as no cell of any schema,
/// and names a kind only where it opens with that kind's canonical opening.
/// Its own number and not the record grade's 128 KiB: a cell carries no
/// entry array, and a cap sized for one would let a hostile insert command a
/// tree of some twelve megabytes per value for nothing a cell can be.
pub(crate) const MAX_CELL_BYTES: usize = 1024;
