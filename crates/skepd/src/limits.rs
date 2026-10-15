//! The daemon's own bounds.
//!
//! They are the small-body cap of every route but the frame routes and the
//! blob upload's two body-carrying methods (wire.md §Transport), the change
//! feed's two page-size bounds (wire.md §The change feed) and the blob
//! route's bounds — the streaming arm's chunk, its two deadlines and the
//! pruner's cadence (wire.md §Media).
//!
//! The bounds the core reads are `skep_core::limits`'s — the frame-carrying
//! routes' request-body cap and the edge pairs' hold-down, which this crate
//! takes from there, the standing line's cadence, the feed walk's progress
//! cadence and the feed's page byte budget. The media resource's own
//! numbers — the per-file cap, the fetch pool and its two intervals, the
//! upload pool, the default per-account limit's share and floor, the
//! standing-uploads bound, the logs' compaction trigger and the picture
//! cell's cap — are `skep_media::limits`'s, the daemon taking the ones it
//! reads from there, each `pub` there for that reader.

use std::num::NonZeroUsize;
use std::time::Duration;

/// The streaming arm's chunk: 64 KiB, interim.
///
/// It is the one buffer the blob route holds of a body, filled from the
/// socket over as many reads as that takes and handed to the store one
/// chunk at a time. The arm's whole memory per in-flight upload is this
/// buffer, the body bytes that arrived with the head and the hasher's
/// state; a body at the cap fills it 1,024 times.
pub(crate) const BLOB_CHUNK: usize = 64 * 1024;

/// The idle bound of a blob body: 30 s, interim.
///
/// It is the record's "idle bound the subsystem design pins", clause (5):
/// the socket's read deadline while a body streams, renewed by any byte and
/// never by silence; a connection whose body stalls past it ends, its
/// upload kept (a dropped connection keeps its upload until the expiry).
pub(crate) const BLOB_IDLE_BOUND: Duration = Duration::from_secs(30);

/// The pruner's cadence: one hour, interim.
///
/// It is a daemon constant for a cadence, as the nonce TTL is (D1): the
/// interval between two passes of the pruner over `blobs/` (`skep-media`'s
/// `pruner.rs`), the first pass running once the cell index's rebuild at
/// open completes. What the interval bounds is how long an expired partial
/// or a lapsed, unreferenced file stands past its expiry — the lease
/// interval is days, so an hour's lag on top of it is nothing a scope reads
/// (the scopes are record-derived and count neither) and a pass over a
/// quiet board costs three directory listings.
pub(crate) const PRUNE_INTERVAL: Duration = Duration::from_secs(3600);

/// The transfer bound of one blob request: 10 minutes, interim.
///
/// It is the deadline on *slowness* the idle bound cannot give (a peer
/// pacing one byte per interval renews the idle bound for as long as it
/// cares to, and the transport's own `TRANSFER_DEADLINE` of 30 s would cut
/// an honest body at the cap on a slow link). A body at the cap needs
/// 112 KB/s to pass it; a request cut here leaves its upload standing at
/// the last durable grain, resumable at once — which is what makes a
/// per-request bound safe where a per-file one would not be.
pub(crate) const BLOB_TRANSFER_BOUND: Duration = Duration::from_secs(600);

/// The request-body cap of the small-body routes: 16 KiB.
///
/// It is one constant at every small-body route — every route but the
/// frame routes and the blob upload's two body-carrying methods
/// (`body_cap`). `POST /session` carries `{"principal": n}` or the signed
/// body whose `sig` is the hybrid blob in hex — 6,912 B at a loopback
/// origin under tag 1, 7,157 B at the longest DNS-legal origin (the
/// record-cap measurements §4), which an 8 KiB cap would leave a
/// kilobyte's room; a body posted to `/health`, `/changes`,
/// `/dump` or an unknown path is read whole and then never looked at. Those
/// routes have no use for the frame routes' ceiling
/// (`skep_core::limits::MAX_REQUEST_BODY`), and offering it to them offers
/// the `Value` tree that rides on it.
pub(crate) const MAX_SMALL_BODY: usize = 16 * 1024;

/// `/changes`'s page size when `limit` is absent: 256 rows.
pub(crate) const DEFAULT_CHANGES_LIMIT: NonZeroUsize =
    NonZeroUsize::new(256).expect("256 is not zero");

/// `/changes`'s page-size ceiling: 4,096 rows.
///
/// A larger `limit` is refused, not clamped (the never-silent posture
/// applied to paging).
pub(crate) const MAX_CHANGES_LIMIT: usize = 4096;
