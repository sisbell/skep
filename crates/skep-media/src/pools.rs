//! THE POOLS — the media resource's two permit pools (PATTERNS P29; the
//! register M-I5 (f): PICTURES NEVER STARVE OR STALL THE JOURNAL — bounded by
//! a pool, never a queue): THE FETCH POOL, whose permit a fetch's answer
//! holds from the check of its whole file to its last byte (`serve::fetch`),
//! and its twin THE UPLOAD POOL, whose permit the PUT's creation and resume
//! hold for a body's whole stream (`server/blob_routes.rs`, THE PERMIT). Both
//! are instances of [`skep_util::permits`]'s mechanism, counted into the
//! daemon's worker minimum beside its own reconstruction, class-scan and
//! write pools, and disjoint from those and from each other by the borrow: a
//! [`Permit`] names the pool that issued it. A drained pool REFUSES, never
//! queues (ms5-R), and is asked or refused, never told (D9).
//!
//! Each says its EDGE PAIR (`operations.md` §1.1 m12; §4 row 27) at one door,
//! its admission: an [`EdgeTracker`] told of every refusal and every permit
//! taken, whose edges go out at once through the media gate's classed door, a
//! clone of which the pool holds (`MediaGate::door`) — `the {pool} pool is
//! saturated` at the first refusal of an episode, `the {pool} pool has room
//! again` at the first admission a hold-down past its last refusal, the upload
//! pool's landing alone carrying the episode's refusals; nothing per request,
//! nothing else on a line. The hold-down is the daemon's one constant for
//! every pair, handed in at the open. The two admissions sit side by side
//! because one ruling shapes both: they differ in the pool's word and in the
//! upload landing's count of refusals, and nowhere else.

use std::time::Duration;

use skep_util::permits::{edge_clock_now, EdgeTracker, Permit, Permits, PoolEdgeLine};

use crate::gate::{ClassedDoor, MediaGate};
use crate::limits::{MAX_CONCURRENT_FETCHES, MAX_CONCURRENT_UPLOADS};

/// The word the fetch pool's two lines name it by (`operations.md` §1.1 m12:
/// one word per pool, the same in both lines) — the refusal's own,
/// `fetch_busy`.
const FETCH_POOL: &str = "fetch";

/// The word the upload pool's two lines name it by (`operations.md` §1.1
/// m12: one word per pool, the same in both lines) — the refusal's own,
/// `upload_busy`.
const UPLOAD_POOL: &str = "upload";

/// THE FETCH POOL — the third instance of [`skep_util::permits`]'s mechanism,
/// disjoint from the reconstruction pool and the class-scan pool by the
/// borrow: a [`Permit`] names the pool that issued it, so no fetch spends a
/// slot of either and neither spends one of these. [`MAX_CONCURRENT_FETCHES`]
/// slots, one per answer for its whole life — the file held whole from its
/// check to its last byte written, so the pool is the fetch route's memory
/// bound; a drained pool REFUSES, never queues.
///
/// Its edge pair names it `fetch`: `the fetch pool is saturated`, `the fetch
/// pool has room again` — no count (D9, read loose: a pool saying "full"
/// names no reader).
pub struct FetchPool {
    permits: Permits,
    edge: EdgeTracker,
    door: ClassedDoor,
}

impl FetchPool {
    /// The pool at its count, [`MAX_CONCURRENT_FETCHES`], every slot free —
    /// its edge pair said through `gate`'s door and judged by `hold_down`.
    pub fn new(gate: &MediaGate, hold_down: Duration) -> FetchPool {
        FetchPool {
            permits: Permits::new(MAX_CONCURRENT_FETCHES),
            edge: EdgeTracker::new(hold_down),
            door: gate.door(),
        }
    }

    /// One permit for a whole answer, or `None` right now — `serve::fetch`'s
    /// step 5 — and the pool's edge pair, judged at this one door at the edge
    /// clock's instant and said at the edge: the admission or the refusal is
    /// told to the tracker, and the edge it answers goes out through the
    /// gate's door in the pool's ruled words. The test hook below takes its
    /// permits beside this door and crosses no edge: what a suite holds is the
    /// pool, not a request.
    pub(crate) fn admit(&self) -> Option<Permit<'_>> {
        let permit = self.permits.try_acquire();
        let now = edge_clock_now();
        let edge = match &permit {
            Some(_) => self.edge.admitted(now),
            None => self.edge.refused(now),
        };
        if let Some(edge) = edge {
            self.door.say(edge.class(), PoolEdgeLine::new(FETCH_POOL, edge));
        }
        permit
    }

    /// TEST HOOK, reached through `Daemon::try_hold_fetch_permit`: hold one
    /// permit exactly as an in-flight fetch does.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    #[must_use = "a permit dropped at once holds nothing"]
    pub fn try_hold(&self) -> Option<Permit<'_>> {
        self.permits.try_acquire()
    }
}

/// THE UPLOAD POOL — the fourth instance of [`skep_util::permits`]'s mechanism
/// and the fetch pool's twin ([`FetchPool`]), disjoint from the
/// reconstruction, class-scan and fetch pools by the borrow: a [`Permit`]
/// names the pool that issued it, so no upload spends a slot of theirs and
/// none of them spends one of these. [`MAX_CONCURRENT_UPLOADS`] slots, one
/// per creation or resume of `/blob/upload` for the request's whole life —
/// the body's stream, the finish included (`server/blob_routes.rs`, THE
/// PERMIT; Op inventory 1, "AN UPLOAD IS ADMITTED AT MOST AN UPLOAD PERMIT
/// POOL AT ONCE") — so what the pool bounds is how many workers the family
/// holds at once. A drained pool REFUSES, never queues (ms5-R: nothing of the
/// family waits).
///
/// Its edge pair names it `upload`: `the upload pool is saturated`, and `the
/// upload pool has room again after {n} refusals` — the one line of the
/// eight pairs the ruling lets carry a count, the episode's refusals.
pub struct UploadPool {
    permits: Permits,
    edge: EdgeTracker,
    door: ClassedDoor,
}

impl UploadPool {
    /// The pool at its count, [`MAX_CONCURRENT_UPLOADS`], every slot free —
    /// its edge pair said through `gate`'s door and judged by `hold_down`.
    pub fn new(gate: &MediaGate, hold_down: Duration) -> UploadPool {
        UploadPool {
            permits: Permits::new(MAX_CONCURRENT_UPLOADS),
            edge: EdgeTracker::new(hold_down),
            door: gate.door(),
        }
    }

    /// One permit for a whole request, or `None` right now — never blocks;
    /// and the pool's edge pair, judged at this one door at the edge clock's
    /// instant and said at the edge through the gate's door, the landing
    /// carrying the episode's refusals. The test hook below takes its
    /// permits beside this door and crosses no edge: what a suite holds is
    /// the pool, not a request.
    #[must_use = "a permit dropped at once returns its slot at once: bind it for the request's \
                  whole life"]
    pub fn admit(&self) -> Option<Permit<'_>> {
        let permit = self.permits.try_acquire();
        let now = edge_clock_now();
        let edge = match &permit {
            Some(_) => self.edge.admitted(now),
            None => self.edge.refused(now),
        };
        if let Some(edge) = edge {
            self.door.say(edge.class(), PoolEdgeLine::counted(UPLOAD_POOL, edge));
        }
        permit
    }

    /// TEST HOOK, reached through `Daemon::try_hold_upload_permit`: hold one
    /// permit exactly as an in-flight creation or resume does.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    #[must_use = "a permit dropped at once holds nothing"]
    pub fn try_hold(&self) -> Option<Permit<'_>> {
        self.permits.try_acquire()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::MAX_BLOB_BYTES;

    /// The fetch pool holds exactly [`MAX_CONCURRENT_FETCHES`] permits,
    /// refuses the next rather than queueing, and a released permit reopens
    /// its slot — and its edge pair rides the gate's door: the first refusal
    /// says the failure line through it, in the pool's ruled words, and a
    /// second refusal says nothing more (m12).
    #[test]
    fn the_fetch_pool_admits_the_pools_count_and_refuses_the_next() {
        let dir = tempfile::tempdir().expect("tempdir");
        let media_gate = MediaGate::open(dir.path()).expect("the store opens");
        let pool = FetchPool::new(&media_gate, Duration::from_secs(15));
        let held: Vec<_> =
            (0..MAX_CONCURRENT_FETCHES).map(|_| pool.admit().expect("a permit")).collect();
        assert!(media_gate.lines_said().is_empty(), "admissions with no episode say nothing");
        assert!(pool.admit().is_none(), "a drained pool refuses; it never queues");
        assert!(pool.admit().is_none(), "…and again");
        assert_eq!(
            media_gate.lines_said(),
            ["failure: the fetch pool is saturated"],
            "the first refusal of an episode, once, through the gate's door"
        );
        drop(held);
        assert!(pool.admit().is_some(), "a released permit reopens its slot");
        assert_eq!(media_gate.lines_said().len(), 1, "inside the hold-down: no landing");
        assert_eq!(MAX_CONCURRENT_FETCHES, 2);
        assert_eq!(
            MAX_BLOB_BYTES * MAX_CONCURRENT_FETCHES as u64,
            128 * 1024 * 1024,
            "the memory bound"
        );
    }

    /// The twin, under its own count and word: the upload pool holds exactly
    /// [`MAX_CONCURRENT_UPLOADS`] permits, refuses the next rather than
    /// queueing, and a released permit reopens its slot — its first refusal
    /// saying `upload`'s failure line through the gate's door, once (m12).
    #[test]
    fn the_upload_pool_admits_its_count_and_refuses_the_next() {
        let dir = tempfile::tempdir().expect("tempdir");
        let media_gate = MediaGate::open(dir.path()).expect("the store opens");
        let pool = UploadPool::new(&media_gate, Duration::from_secs(15));
        let held: Vec<_> =
            (0..MAX_CONCURRENT_UPLOADS).map(|_| pool.admit().expect("a permit")).collect();
        assert!(media_gate.lines_said().is_empty(), "admissions with no episode say nothing");
        assert!(pool.admit().is_none(), "a drained pool refuses; it never queues");
        assert!(pool.admit().is_none(), "…and again");
        assert_eq!(
            media_gate.lines_said(),
            ["failure: the upload pool is saturated"],
            "the first refusal of an episode, once, through the gate's door"
        );
        drop(held);
        assert!(pool.admit().is_some(), "a released permit reopens its slot");
        assert_eq!(media_gate.lines_said().len(), 1, "inside the hold-down: no landing");
        assert_eq!(MAX_CONCURRENT_UPLOADS, 4);
    }
}
