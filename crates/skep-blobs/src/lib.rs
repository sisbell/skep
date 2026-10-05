//! # skep-blobs — the blob store (media lane B)
//!
//! THE FOUR MEDIA STORES UNDER ONE ROOT (`media.md` §The media stores, the
//! set's one home; Op inventory 1, the resumable upload's seven clauses and
//! the lease's crash story; the register M-I5 (a), (c) and M-I6 (c)): the
//! FILES at `<root>/<designation>/<hex>`, the PARTIALS beside them, the
//! UPLOAD RECORDS in `<root>/uploads.log` and the LEASE LOG in
//! `<root>/leases.log`. The daemon hands this crate `blobs/` inside the
//! board's data directory and nothing else of itself: the crate knows a
//! PRINCIPAL only as the opaque string its caller spells it as, compared
//! exactly and never read; it takes NO lock of its caller's — its own keep
//! its records whole and run its finishes one at a time ([`Store`]) — and
//! asks its caller for three exclusions: no second store over its root
//! while one is open ([`Store::open`]); at most one stream of an upload at a
//! time, its acts serialized ([`Store`]); and no [`Store::unlink_blob`] or
//! [`Store::remove_aside`] while a [`Stream::finish`] runs (see there); and
//! it reads NO limits record (it answers pending bytes and the volume's free
//! space; what bounds them is policy, the daemon's). What it promises is the
//! ORDER of its own acts and what each leaves behind on a crash:
//!
//! * THE PUT's ORDER ([`Stream::finish`]): the partial fsynced; where the
//!   name exists, the replaced instance LINKED ASIDE (a second name no hex
//!   spells, so the rename frees nothing); the partial RENAMED onto
//!   `<designation>/<hex>` — REPLACE where the name exists, never a no-op —
//!   that directory fsynced, the root fsynced where no root fsync since the
//!   open has made the designation directory durable, THEN the lease
//!   appended and synced, THEN the upload record retired, THEN the answer —
//!   the aside queued as the finish answers and never sooner, and UNLINKED
//!   AFTER the answer ([`Store::unlink_asides`]), off the request's path, on
//!   whatever thread drains the queue. A crash leaves at worst a file with
//!   no lease (unreferenced, prunable), a retired-by-open record beside a
//!   leased file, or an aside open removes, and never a lease naming bytes
//!   the restart does not hold.
//! * THE PRUNER's READS AND ACTS: the designation directories, the files at
//!   hex names and the asides ([`Store::designation_dirs`],
//!   [`Store::blobs_of`], [`Store::asides_of`]), whether ANY principal holds
//!   a live lease on a file ([`Store::any_live_lease`]), the expired uploads
//!   and their removal ([`Store::expired_uploads`],
//!   [`Store::expire_upload`]), and the unlink of one file or one aside
//!   ([`Store::unlink_blob`], [`Store::remove_aside`]) — each one act, so
//!   the daemon's pass holds its own lock around exactly one.
//! * A BYTE IS RECEIVED ONCE IT IS DURABLE: the partial is fsynced at
//!   [`SYNC_GRAIN`] and at [`Stream::settle`], and the record's offset and
//!   expiry are written after each sync, the expiry re-fixed from the
//!   interval the record took at the upload's creation — so a later limits
//!   record reaches the next upload and never a standing one (clause (3)).
//!   A STREAM IS ONE REQUEST's: [`Store::resume`] answers a [`Stream`], the
//!   partial opened afresh at the record's offset — cutting off whatever an
//!   earlier request left past it — which the request appends through and
//!   ends by [`Stream::settle`] or [`Stream::finish`], or drops; the
//!   partial's file closes with it, so the store holds no file open between
//!   requests.
//! * ONE ANSWER PER PRINCIPAL: an identifier the asking principal's
//!   records do not name is [`BlobError::NoUpload`] whoever minted it (the
//!   upload records answer by principal); a hash the principal holds no
//!   lease on is [`LeaseState::None`] whatever the directory holds; and a
//!   finish answers one shape whether or not the file was already here.
//! * A TORN LINE IS ONLY EVER A LOG's TAIL: an append that fails is cut
//!   back off its log, and a log whose cut fails too — or whose compaction
//!   failed past its rename — takes no further append until a compaction
//!   completes (`jsonl.rs`), so open's tail check never cuts a whole line
//!   and no line lands in a file no open reads. The store compacts only at
//!   its open, so a log stopped while the store serves stays stopped, every
//!   act that writes it answering `Io`, until the next open reads it afresh
//!   ([`Store`]).
//! * OPEN RECONCILES AND COMPACTS: first, nothing at a name it acts on
//!   followed or shared — a symbolic link, a special file, or a second link
//!   to a file the store writes in place failing the open, named
//!   (`blobs.rs`); both logs tail-checked and rewritten to
//!   their current records, a line naming a designation or hex the store's
//!   name check refuses, or an offset past its length, read as no record
//!   (see [`Store`]), so a log restored from elsewhere names no path out of
//!   the root; the partials and the records held to each other both ways,
//!   an orphan partial removed under the designations this build computes
//!   alone — another build's designation directory left to it — and a
//!   partial that cannot be read failing the open rather than reading as
//!   absent (`partials.rs`); every aside removed, a crash's or a failed
//!   finish's (`blobs.rs`); a lease past the horizon dropped.
//! * A CALLER's BUG IS NO REFUSAL: a finish short of the declared length
//!   PANICS, naming the obligation it breaks ([`Stream::finish`]), and so
//!   does a defect of the store's own — a byte received marked past its
//!   record's length (`UploadRecords::mark_received`); [`BlobError`] carries
//!   only answers a caller acts on.
//! * A KEY NAMES THE FUNCTION THAT MADE IT: the store computes one hash,
//!   BLAKE3's, and a creation names it by type — [`HashFunction::Blake3`],
//!   filed under its designation, `blake3` — so no creation can name a
//!   function the store does not compute ([`Store::create_upload`];
//!   `media.md` §The design, item 4).
//!
//! The `test-hooks` feature compiles in the test seam (`store/hooks.rs`):
//! the hazard seam — a hold or an injected failure at a named [`Step`] of
//! the finish — and the three methods only a test calls, `Store::install`,
//! `Stream::written` and `Store::asides_queued`. A build without it carries
//! none of them.

#![forbid(unsafe_code)]

// The store's refusals, `BlobError`.
mod error;
// The files at `<designation>/<hex>`: where one lives, the spellings a
// designation and a hex name must have, the aside name, the listings of the
// designation directories, open's walk holding every entry it acts on to
// what the store makes and its sweep of the asides, the directory fsync
// every install order ends in, and the floor's free-space read.
mod blobs;
// The JSON-lines log both record logs are, `Log`: its tail check at open,
// its append, undone where it fails, and its compaction by the install
// order.
mod jsonl;
// The upload records, `uploads.log`: the records' log, which answers by the
// asking principal and makes every change a record takes, and the one
// expiry rule; beneath it, the identifier (`uploads/id.rs`).
mod uploads;
// The lease log, `leases.log`: the leases, their three states, the horizon.
mod lease;
// The partials, `.upload-<identifier>`: their name, and the walk at open
// that reconciles them with the records; beneath them, the handle a request
// opens on one (`partials/handle.rs`: `Handle`, the bytes written and their
// hash, kept true across a failed write, and `HashFunction`, the function
// that hash is and the designation it files under).
mod partials;
// `Store`, the four opened as one, and `Stream`, an upload open for one
// request: the order of their acts — the resume, the settle, the finish
// and its steps, the pruner's acts, the leases' reads; under
// `test-hooks`, the test seam (`store/hooks.rs`).
mod store;

pub use error::BlobError;
pub use lease::{Lease, LeaseState};
pub use partials::{HashFunction, SYNC_GRAIN};
pub use store::{Finished, Step, Store, Stream};
pub use uploads::{NotAnUploadId, UploadId, UploadRecord, IDENTIFIER_BYTES};

/// What this crate promises without saying so (C-SEND-SYNC, C-GOOD-ERR,
/// C-COMMON-TRAITS). One `Store` is shared by every worker of the daemon,
/// whose own `Daemon: Send + Sync` pin rests on this one; a request's
/// `Stream`, and the store's answers and refusals, cross threads with the
/// requests that carry them. An auto trait is promised by what a type
/// contains, so a private field that is not `Send` would revoke it with no
/// public name changing; this is where that fails to compile instead, under
/// both arms of the test seam — the hold is bounded `Send + Sync` for this
/// reason. And the values a caller keeps — in a set, as a map key — are
/// held to the traits that let it, which a caller cannot add itself.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Store>();
    assert_send_sync::<Stream<'static>>();
    // The refusals, as an error crossing threads in a `Box<dyn Error>`.
    fn crossing<T: std::error::Error + Send + Sync + 'static>() {}
    crossing::<BlobError>();
    crossing::<NotAnUploadId>();
    // The values a caller keeps.
    fn kept<T: Clone + Eq + std::hash::Hash + std::fmt::Debug + Send + Sync>() {}
    kept::<Finished>();
    kept::<HashFunction>();
    kept::<Lease>();
    kept::<LeaseState>();
    kept::<Step>();
    kept::<UploadId>();
    kept::<UploadRecord>();
};
