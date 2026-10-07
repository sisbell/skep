//! The media resource's own numbers (wire.md §Media): the per-file cap, the
//! fetch pool and its two intervals, the upload pool, the default
//! per-account limit's share and floor, the standing-uploads bound, the
//! logs' compaction trigger and the picture cell's cap. Four of them the
//! daemon reads too — the per-file cap on the blob route's request body,
//! the two pools' counts in its worker minimum, the standing-uploads bound
//! in a refusal's face — and takes from here; the daemon's own bounds (the
//! request-body caps, the change feed's page bounds, the streaming arm's
//! chunk and its two deadlines, the pruner's cadence) stay the daemon's.

use std::time::Duration;

/// THE BLOB ROUTE's CAP (media lane B; wire.md §Media — INTERIM, the
/// board's sm-Q8): the most bytes one upload may declare, and the
/// request-body cap of `/blob/upload`'s two body-carrying methods — 64 MiB.
/// The per-file cap of the daemon's own, which a venue's limits record may
/// lower and never raise. Sized for v1's images (ms5-V1: v1 media stays
/// images only): a camera's raw frame is tens of megabytes, a web picture a
/// few, so 64 MiB holds every picture a board is likely to be handed with
/// room, and no video. What it bounds is DISK and TRANSFER, never memory:
/// the streaming arm (`server/blob_routes.rs`'s `BodySource`) holds one
/// `BLOB_CHUNK` (the daemon's) of the body at a time, and the store writes
/// each chunk to the partial as it arrives. A declared `length` past it is
/// refused at the creation with `413 payload_too_large` naming this number,
/// before any body byte.
pub const MAX_BLOB_BYTES: u64 = 64 * 1024 * 1024;

/// THE FETCH POOL (the media record's Op inventory 3: "EVERY v1 ANSWER
/// THEREFORE READS ITS WHOLE FILE BEFORE ITS FIRST BYTE, AND THE ROUTE ADMITS
/// AT MOST A PERMIT POOL OF ANSWERS AT ONCE"; PATTERNS P29) — 2, INTERIM
/// (sm-Q8): the most `GET /blob?i=` answers held whole at once. Each holds
/// its file in memory from the check to the last byte written (`serve.rs`),
/// so what the route commands is at most [`MAX_BLOB_BYTES`]
/// times this, 128 MiB; a fetch past the pool is refused `503 fetch_busy`,
/// retry-class as `history_busy` is, and faced PENDING by a client. Counted
/// into `MIN_WORKERS` beside the reconstruction and class-scan pools
/// (`server/listen.rs`), so a caller holding every permit of all three still
/// leaves a worker free. The reconstruction pool's own number, for its
/// reason: two keep a page of figures serviceable without letting a
/// stranger's fetches occupy the worker pool.
pub const MAX_CONCURRENT_FETCHES: usize = 2;

/// THE UPLOAD POOL (the media record's Op inventory 1: "AN UPLOAD IS
/// ADMITTED AT MOST AN UPLOAD PERMIT POOL AT ONCE, counted in `MIN_WORKERS`
/// beside the reconstruction and class-scan pools — the fetch pool's twin
/// — a creation past it refused retry-class"; the register M-I5 (f);
/// PATTERNS P29) — 4, INTERIM (sm-Q8): the most creations and resumes of
/// `/blob/upload` streaming a body at once. What it bounds is WORKER
/// OCCUPANCY and not memory: an admitted stream holds its worker from the
/// permit to its finish — up to `BLOB_TRANSFER_BOUND`, each byte inside
/// `BLOB_IDLE_BOUND` (the daemon's two deadlines) — while its memory is one
/// `BLOB_CHUNK` and a hasher's state, so the fetch pool's 2, a memory figure
/// over whole files, is not this pool's to copy. A board's uploads are its
/// account holders' and v1's media are images alone (ms5-V1), so four
/// streams at once are four people on slow links, or one person's batch; a
/// fifth meets `503 upload_busy`, retry-class as `fetch_busy` and
/// `history_busy` are, before any body byte — faced PENDING by a client,
/// where without the pool it met a daemon that answered nothing. Counted
/// into `MIN_WORKERS` beside the three other pools (`server/listen.rs`), so
/// a caller holding every permit of all four still leaves a worker free;
/// the pool is asked or refused, never told (D9).
pub const MAX_CONCURRENT_UPLOADS: usize = 4;

/// THE BYTE INTERVAL of a fetch (the media record's Op inventory 3, "AT A
/// BYTE INTERVAL THE SUBSYSTEM DESIGN PINS WITH THE ROUTE"; the register
/// M-I2 (g); the ruling s6-E1 (a)) — 1 MiB, INTERIM: the most bytes a
/// stream writes between two re-resolutions of its requester and its gate,
/// so a session killed or a grant revoked mid-transfer fetches no draft
/// byte past the interval in flight. Sixteen chunks of the daemon's
/// `BLOB_CHUNK`; the re-check is one `authenticate` and one `retrieve_i` of
/// the span, cheap for a published origin and a guest, the gate's one
/// re-read for a draft's grantee.
pub const FETCH_RECHECK_BYTES: u64 = 1024 * 1024;

/// THE TIME INTERVAL beside it (the record's "OR AT A TIME INTERVAL PINNED
/// BESIDE IT, WHICHEVER COMES FIRST"; s6-leak-b) — 5 s, INTERIM: a reader
/// draining at a trickle holds no interval open past this; the re-check
/// runs at whichever of the two bounds comes first, judged on the media
/// gate's clock so a suite drives it through the clock seam.
pub const FETCH_RECHECK_INTERVAL: Duration = Duration::from_secs(5);

/// THE DEFAULT PER-ACCOUNT LIMIT's SHARE — one eighth of the volume's
/// capacity (the owner's ruling, "1/8 is fine"; `media.md` Op inventory 1,
/// "UPLOADS ARE OPEN BY DEFAULT, WITH A DEFAULT PER-ACCOUNT LIMIT IN FORCE
/// FROM START"; the register M-I6 (b): a per-account limit is ALWAYS in
/// force): the divisor applied to the capacity the daemon reads off the
/// volume once at its start (`gate.rs`, `Limits::defaults_for`). D1,
/// a daemon constant; a written limits record overrides the figure whole.
pub const DEFAULT_LIMIT_SHARE: u64 = 8;

/// THE DEFAULT PER-ACCOUNT LIMIT's FLOOR — 256 MiB, the least the default
/// is, whatever the volume's capacity (the owner's ruling: "never below 256
/// MiB"); and the whole default on a host that cannot answer its capacity.
pub const DEFAULT_LIMIT_FLOOR_BYTES: u64 = 256 * 1024 * 1024;

/// THE STANDING-UPLOADS BOUND — 8 per principal, INTERIM (sm-Q8;
/// `media.md` Op inventory 1, "A PRINCIPAL's STANDING UPLOADS ARE BOUNDED
/// IN NUMBER, a gate constant the subsystem design pins"; PATTERNS P13,
/// P29): the most standing uploads one principal holds, counted off its own
/// records at the creation, a creation past it refused BEFORE its partial
/// and its record — `507 deposit_refused`, `scope` `standing`, the face
/// naming the end of one of them as the act. What it bounds is what the
/// pending bytes cannot: a creation with no body counts nothing, so without
/// it a principal held any number of empty partials, each an inode the
/// floor never reads and a record every open and every pass walks.
pub const MAX_STANDING_UPLOADS: usize = 8;

/// THE LOGS' COMPACTION TRIGGER — 4×, INTERIM (sm-Q8; `media.md` §The
/// media stores, "the pruner's pass rewrites either store the same way once
/// its log has passed a size trigger, a multiple of its current records the
/// subsystem design pins"; PATTERNS P22): the pruner's pass rewrites
/// `uploads.log` or `leases.log` to its current records once its lines
/// number more than this many times those records — so between restarts
/// neither log grows past the trigger plus one pass interval's appends.
pub const COMPACTION_TRIGGER: usize = 4;

/// THE COMPACTION's MINIMUM — 1,024 lines, INTERIM: a log under it is
/// never rewritten by a pass, whatever its ratio, so a small board's logs
/// are not rewritten per pass for a handful of retirements.
pub const COMPACTION_MIN_LINES: usize = 1024;

/// THE CELL'S CAP (media lane A; wire.md §Media — INTERIM, the board's
/// sm-Q8): the most bytes the picture cell's parser (`cell.rs`) builds
/// a JSON tree for — 1 KiB. A canonical cell is under 140 bytes (the kind's
/// address, 64 hex characters of hash, a sixteen-digit count and the member
/// names), so the cap is some eight times the largest cell that can parse;
/// what it bounds is the tree `serde_json` builds BEFORE the first schema
/// check for a body that NAMES the kind and is no cell — which the daemon
/// must parse to refuse by name (D13's carve-out) — at the record cap's
/// ratio of close to a hundred times the body (`skep-identity`'s
/// `payload.rs`), under the serialization lock, per value of an insert. The
/// cap is the KIND's and every schema's under it: a body past it parses as
/// no cell of any schema and names nothing. Its own number and not the
/// record grade's 128 KiB: a cell carries no entry array, and a cap sized
/// for one would let a hostile insert command a hundred-megabyte tree per
/// value for nothing a cell can be.
pub const MAX_CELL_BYTES: usize = 1024;
