//! The class-scan pool (`MAX_CONCURRENT_CLASS_SCANS`, `ClassScans`, `ScanBusy`, `is_class_scan`).

use skep_febe::Op;

use crate::history::{Permit, Permits};

/// Concurrent CLASS SCANS admitted at `/op` at once (wire v7.9; PUB-8.36,
/// PUB-8.37): the link-discovery reads [`is_class_scan`] enumerates, each of
/// which walks the LINK STORE END TO END — M7's `stab` is "a brute scan of
/// `links`" and `match_links` drives its first constraint through it — and
/// pays a span comparison per link whose count the REQUEST sizes, repeatable
/// at will from any unauthenticated peer.
///
/// The reconstruction pool's own number
/// ([`crate::history::MAX_CONCURRENT_RECONSTRUCTIONS`]), for the same reason
/// it is that pool's: two keep directories serviceable without letting a
/// stranger's scans occupy the worker pool. The wire names it as a constant
/// the daemon may raise later — a configuration question, not this bound's,
/// and one the OWNER owes a number for now that the bound covers the region
/// family a board's own reading pane calls on every scroll.
///
/// ONE pool for the board: global across every bounded form, across every
/// type class, and across every session and the guest (a stranger is the
/// case). DISJOINT from the reconstruction pool — a second instance of
/// [`Permits`], never a share of the first — so history panes and mirror
/// bootstraps are never starved by directory scans, nor the reverse.
///
/// The SUM of this and the reconstruction pool must leave a worker free:
/// [`MIN_WORKERS`](super::MIN_WORKERS) holds that relation, and an assertion beside it holds the
/// shipped default to it.
pub(crate) const MAX_CONCURRENT_CLASS_SCANS: usize = 2;

/// The class-scan bound, whole (wire v7.9; PUB-8.36, PUB-8.37): what counts
/// as a class scan ([`is_class_scan`]), how many run at once
/// ([`MAX_CONCURRENT_CLASS_SCANS`]), and the permit that spans one answer.
/// ONE card, as [`crate::history::History`] is for the reconstruction
/// budget, so the shape test and the pool it gates cannot drift apart and a
/// later meter has a whole thing to copy rather than five pieces on
/// [`Daemon`](super::Daemon).
///
/// A second instance of that module's permit mechanism, and disjoint from
/// its pool BY THE BORROW rather than by convention: a [`Permit`] names the
/// pool that issued it, so no signature here can spend a reconstruction
/// slot.
pub(crate) struct ClassScans(Permits);

/// Every class-scan permit is in use. Says nothing about HTTP, as
/// [`crate::history::Unavailable`] does not: the mapping onto the wire is
/// [`refuse_scan_busy`](super::reply::refuse_scan_busy)'s, beside the transport channel's other refusal
/// constructors, and the wire name it maps to is
/// [`TransportError::ScanBusy`](super::reply::TransportError::ScanBusy) — the same condition one layer out, which is
/// why the two share a word and why the type keeps them apart.
#[derive(Debug)]
pub(crate) struct ScanBusy;

impl ClassScans {
    pub(super) fn new() -> ClassScans {
        ClassScans(Permits::new(MAX_CONCURRENT_CLASS_SCANS))
    }

    /// THE CLASS-SCAN ADMISSION (lane 3.7 §2): a class-scan-shaped read
    /// ([`is_class_scan`]) takes one of the [`MAX_CONCURRENT_CLASS_SCANS`]
    /// permits for the WHOLE answer, or is refused at once — a retry-class
    /// refusal, never a queue; any other read is admitted with no permit
    /// (`Ok(None)`).
    ///
    /// Taken BEFORE the read consult and the store call, both of which run
    /// inside M10's `execute`: a refused request has cost the parse and the
    /// session read alone, and an admitted one that M10 then withholds or
    /// rejects — never reaching M7 — still returns its permit by the guard.
    /// The pool is global: the guest and the claimant draw on it alike, and
    /// which class is scanned is not consulted. Whether the request is a
    /// class scan is the one thing decided here; what it answers stays the
    /// stores' — an admitted scan's answer is byte-for-byte the unbounded
    /// one.
    pub(super) fn admit(&self, op: &Op) -> Result<Option<Permit<'_>>, ScanBusy> {
        if !is_class_scan(op) {
            return Ok(None);
        }
        self.0.try_acquire().map(Some).ok_or(ScanBusy)
    }

    /// TEST HOOK, reached through [`Daemon::try_hold_scan_permit`](super::Daemon::try_hold_scan_permit): hold one
    /// permit exactly as an in-flight scan does.
    pub(super) fn try_hold(&self) -> Option<Permit<'_>> {
        self.0.try_acquire()
    }
}

/// THE CLASS-SCAN TEST (wire v7.9; PUB-6.54, PUB-6.56, PUB-8.36; lane 3.7
/// §1) — the one statement of what the pool bounds. As M7 is BUILT that is
/// the OP and never the shape of the query: `LinkState::stab` is "a brute
/// scan of `links` reading each endset's spans — trivially correct, O(n)",
/// and `LinkState::match_links` drives its FIRST constraint through it and
/// narrows the survivors with the rest. So there is no index for a narrow
/// slot to be pinned against, and every read that reaches either primitive
/// walks the whole store however its slots are spelled.
///
/// THE POPULATION, by cost, each citing what it reaches:
///
/// * the FTT family (`find_links_ftt`, `count_ftt`, `window_ftt`) — ONE
///   scan, at `|query spans| × |slot spans|` per link, with the span count
///   and each span's start tumbler the REQUEST's. The all-`"any"` query is
///   `match_links`' unconstrained branch, `scan(view, |_| true)`, one
///   residence lookup per link and NO span comparison, so it is the
///   CHEAPEST member: a query constraining a second slot is that scan plus
///   work, never less;
/// * the region family (`find_links_v`, `count_v`, `window_v`,
///   `retrieve_endsets`) — THREE scans, one `stab` per v1 slot as
///   [M8's cost statement](skep_discovery#cost) counts them, each at up to
///   [`skep_discovery::MAX_IMAGE_RUNS`] query spans per link. That constant
///   caps the image and assigns what it cannot reach — "`#runs(d)` and
///   `|links|` are the WORLD's … they stay with request rate and
///   concurrency, which are M10's" — to this seat;
/// * `delete_orphans` — SIX, three `stab`s over the deleted runs and three
///   over the retained (the same statement), and the dearest read on the
///   surface: it takes no owner gate by design, so every asker reaches it on
///   any registered document;
/// * `in_claims`, `out_claims`, `edition_claims` — ONE each, a `match_links`
///   at a single-span query, behind a residence or registration gate. The
///   query span count is not the request's, but the STORE walk is the same
///   walk, and it is strictly dearer per link than the all-`"any"` query
///   above.
///
/// NOTHING ELSE IS BOUNDED, and each absence is a fact about the read rather
/// than a judgement: `image`, `project` and `discoverable_from` walk no link
/// store — their work is a walk of one document's run-list, or a join of one
/// link's coverage against that document's runs, each held by M8 to a number
/// its cost statement records: the square of
/// [`skep_discovery::MAX_IMAGE_RUNS`] for the walk and for the boolean touch
/// test, and [`skep_discovery::MAX_ANSWER_SPANS`] for the projection, whose
/// join builds the span set it answers with. Each span of an `image` region
/// is held to [`skep_discovery::MAX_IMAGE_RUNS`] ahead of its resolution as
/// well, so no one of them materializes a fragmented document whole;
/// `read_link` and `follow_link` are lookups; the M6 family
/// (`retrieve_v`, `compare`, `show_deletions`, `find_docs_containing`,
/// `show_origin`) and the M3 reads touch no link store at all.
///
/// NOT exhaustive over `Op` (43 variants against 11), so a new READ that
/// walks the link store must be added by hand — `write_meta`'s table, which
/// the compiler does force, reaches writes alone. Nothing about a query is
/// read here: not the class, not the cursor, not the slots, and not whether
/// M8 would answer it off its own descriptor (a `ty` of `"empty"`
/// annihilates before M7 is asked; it is bounded all the same, and its
/// permit is back in the pool a moment later).
pub(super) fn is_class_scan(op: &Op) -> bool {
    matches!(
        op,
        Op::FindLinksFtt { .. }
            | Op::CountFtt { .. }
            | Op::WindowFtt { .. }
            | Op::FindLinksV { .. }
            | Op::CountV { .. }
            | Op::WindowV { .. }
            | Op::RetrieveEndsets { .. }
            | Op::DeleteOrphans { .. }
            | Op::InClaims { .. }
            | Op::OutClaims { .. }
            | Op::EditionClaims { .. }
    )
}
