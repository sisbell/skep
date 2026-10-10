//! The class-scan pool (`MAX_CONCURRENT_CLASS_SCANS`, `ClassScans`, `ScanBusy`, `is_class_scan`).

use skep_febe::Op;
use skep_util::permits::{edge_clock_now, EdgeTracker, Permit, Permits};

use crate::limits::EDGE_HOLD_DOWN;

/// Concurrent CLASS SCANS admitted at `/op` at once (wire v7.9; PUB-8.36,
/// PUB-8.37): the link-discovery reads [`is_class_scan`] enumerates, each of
/// which walks the LINK STORE END TO END — M7's `stab` is "a brute scan of
/// `links`" and `match_links` drives its first constraint through it — or,
/// the lineage pair, the whole supersession class, and pays a span
/// comparison per link whose count the REQUEST sizes, repeatable at will from
/// any unauthenticated peer.
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
pub(super) const MAX_CONCURRENT_CLASS_SCANS: usize = 2;

/// The class-scan bound, whole (wire v7.9; PUB-8.36, PUB-8.37): what counts
/// as a class scan ([`is_class_scan`]), how many run at once
/// ([`MAX_CONCURRENT_CLASS_SCANS`]), and the permit that spans one answer.
/// ONE card, as [`crate::history::History`] is for the reconstruction
/// budget, so the shape test and the pool it gates cannot drift apart and a
/// later meter has a whole thing to copy rather than five pieces on
/// [`Daemon`](super::Daemon).
///
/// A second instance of [`skep_util::permits`]'s mechanism, and disjoint from
/// the reconstruction pool BY THE BORROW rather than by convention: a
/// [`Permit`] names the pool that issued it, so no signature here can spend
/// a reconstruction slot. Beside the pool, its EDGE PAIR (`operations.md`
/// §1.1 m12): an [`EdgeTracker`] the admission tells of every refusal and
/// every permit taken, whose edges the daemon drains ([`ClassScans::edge`])
/// and says through its classed door — `the scan pool is saturated` / `has
/// room again`, once per episode.
pub(super) struct ClassScans {
    permits: Permits,
    edge: EdgeTracker,
}

/// Every class-scan permit is in use. Says nothing about HTTP, as
/// [`crate::history::Unavailable`] does not: the mapping onto the wire is
/// [`refuse_scan_busy`](super::reply::refuse_scan_busy)'s, beside the transport channel's other refusal
/// constructors, and the wire name it maps to is
/// [`TransportError::ScanBusy`](super::reply::TransportError::ScanBusy) — the same condition one layer out, which is
/// why the two share a word and why the type keeps them apart.
#[derive(Debug)]
pub(super) struct ScanBusy;

impl ClassScans {
    pub(super) fn new() -> ClassScans {
        ClassScans {
            permits: Permits::new(MAX_CONCURRENT_CLASS_SCANS),
            edge: EdgeTracker::new(EDGE_HOLD_DOWN),
        }
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
    ///
    /// THE EDGE PAIR's ONE SITE (m12): a class scan's refusal or admission
    /// is told to the tracker at the edge clock's instant and the edge it
    /// answers queued for the daemon's door; a read that takes no permit
    /// crosses none, and neither does the test hook below, which holds the
    /// pool and not a request.
    pub(super) fn admit(&self, op: &Op) -> Result<Option<Permit<'_>>, ScanBusy> {
        if !is_class_scan(op) {
            return Ok(None);
        }
        let permit = self.permits.try_acquire();
        let now = edge_clock_now();
        self.edge.queue(match &permit {
            Some(_) => self.edge.admitted(now),
            None => self.edge.refused(now),
        });
        permit.map(Some).ok_or(ScanBusy)
    }

    /// The pool's edge tracker, for the daemon to drain: the edges the
    /// admission crossed since the last drain, in order.
    pub(super) fn edge(&self) -> &EdgeTracker {
        &self.edge
    }

    /// TEST HOOK, reached through `Daemon::try_hold_scan_permit`: hold one
    /// permit exactly as an in-flight scan does.
    #[cfg(any(test, feature = "test-hooks"))]
    #[must_use = "a permit dropped at once holds nothing"]
    pub(super) fn try_hold(&self) -> Option<Permit<'_>> {
        self.permits.try_acquire()
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
/// * `edition_claims` — ONE, a `match_links` at a single-span query, behind
///   a registration gate. The query span count is not the request's, but the
///   STORE walk is the same walk, and it is strictly dearer per link than the
///   all-`"any"` query above;
/// * `in_claims`, `out_claims` — no store walk: M8 asks M7's typed `observe`
///   of the supersession class, a walk of that class's typed slice behind a
///   residence gate, one coverage test per claim (the same statement). The
///   class is the world's, not the request's — every supersession claim in
///   the docuverse is in it — so the walk is world-sized as the store's is.
///
/// NOTHING ELSE IS BOUNDED, and each absence is a fact about the read rather
/// than a judgement: `image`, `project` and `discoverable_from` walk no link
/// store — their work is a walk of one document's run-list, or a join of one
/// link's coverage against that document's runs, each held by M8 to a number
/// its cost statement records: the square of
/// [`skep_discovery::MAX_IMAGE_RUNS`] for the walk and for the boolean touch
/// test, and [`skep_discovery::MAX_ANSWER_SPANS`] for the projection, whose
/// join builds the span set it answers with. An `image` region's runs are
/// counted as M8 pulls them from M5's lazy resolution and refused at the one
/// past [`skep_discovery::MAX_IMAGE_RUNS`], so no region materializes a
/// fragmented document whole;
/// `read_link` and `follow_link` are lookups; the M6 family
/// (`retrieve_v`, `compare`, `show_deletions`, `find_docs_containing`,
/// `show_origin`) and the M3 reads touch no link store at all.
///
/// NOT exhaustive over `Op` (45 variants against 11 — the first moves with
/// `Op`, whose count the codec suite's op-name table is held to; the second
/// moves only by hand, here), so a new READ that walks the link store must
/// be added by hand — `write_meta`'s table, which the compiler does force,
/// reaches writes alone. Nothing about a query is
/// read here: not the class, not the cursor, not the slots, and not whether
/// M8 would answer it off its own descriptor (a `ty` of `"empty"`
/// annihilates before M7 is asked; it is bounded all the same, and its
/// permit is back in the pool a moment later).
fn is_class_scan(op: &Op) -> bool {
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

#[cfg(test)]
mod tests {
    use skep_febe::Codec;

    use super::*;
    use crate::codec::JsonCodec;

    /// THE CLASS-SCAN TEST, over the OP and not over the query's slots: as
    /// M7 is built every link-discovery read walks the store end to end, or —
    /// the lineage pair — the whole supersession class, so the eleven bounded
    /// ops are bounded whatever their slots hold — a
    /// second constrained slot, an annihilating `"empty"`, a narrow region —
    /// and the reads that walk no link store are bounded by nothing.
    ///
    /// Every row is PARSED through the codec rather than built by hand, so
    /// the test reads the frames a client sends. The two lists are disjoint
    /// and their union is checked against the bounded arm's own count, so an
    /// op moved between the arms without moving here fails the last
    /// assertion rather than passing in silence.
    #[test]
    fn every_link_store_walking_read_is_bounded_whatever_its_slots_hold() {
        /// The bounded arm's size, restated — moving the arm is a visible
        /// decision here, the discipline this crate gives its wire caps.
        const BOUNDED_OPS: usize = 11;

        let parse = |frame: &str| {
            JsonCodec.parse(frame.as_bytes()).unwrap_or_else(|e| panic!("{frame}: {:?}", e.detail)).op
        };
        let ty = r#"[{"start":"1.1.0.1.0.1.0.3.90","width":"0.0.0.0.0.0.0.0.1"}]"#;
        let home = r#"[{"start":"1.0.1.0.1","width":"0.0.0.0.1"}]"#;
        let q = |home: &str, from: &str, to: &str, ty: &str| {
            format!(r#"{{"from":{from},"home":{home},"to":{to},"ty":{ty}}}"#)
        };
        let region = r#"[{"start":"1.1","width":"0.1"}]"#;
        let bounded = [
            // The FTT family, at every slot spelling: the wire's directory
            // shape, the whole store, the annihilated `"empty"`, home-only,
            // and — the cell the slot-keyed predecessor exempted — a SECOND
            // slot constrained, which is that same scan plus a comparison
            // per link and so costs strictly more.
            format!(r#"{{"op":"find_links_ftt","q":{}}}"#, q("\"any\"", "\"any\"", "\"any\"", ty)),
            format!(
                r#"{{"op":"find_links_ftt","q":{}}}"#,
                q("\"any\"", "\"any\"", "\"any\"", "\"any\"")
            ),
            format!(r#"{{"op":"find_links_ftt","q":{}}}"#, q(home, "\"any\"", "\"any\"", ty)),
            format!(r#"{{"op":"count_ftt","q":{}}}"#, q("\"any\"", ty, "\"any\"", ty)),
            format!(
                r#"{{"op":"count_ftt","q":{}}}"#,
                q("\"any\"", "\"any\"", "\"any\"", "\"empty\"")
            ),
            format!(r#"{{"op":"count_ftt","q":{}}}"#, q(home, "\"any\"", "\"any\"", "\"any\"")),
            format!(
                r#"{{"cur":null,"n":16,"op":"window_ftt","q":{}}}"#,
                q("\"any\"", "\"any\"", "\"empty\"", ty)
            ),
            // The region family: THREE scans apiece, one per v1 link slot.
            format!(r#"{{"d":"1.0.1.0.1","op":"find_links_v","region":{region}}}"#),
            format!(r#"{{"d":"1.0.1.0.1","op":"count_v","region":{region}}}"#),
            format!(
                r#"{{"cur":null,"d":"1.0.1.0.1","n":16,"op":"window_v","region":{region}}}"#
            ),
            format!(r#"{{"d":"1.0.1.0.1","op":"retrieve_endsets","region":{region}}}"#),
            // Six scans, and no owner gate: the dearest read on the surface.
            r#"{"d":"1.0.1.0.1","op":"delete_orphans","p":{"subspace":"1","ordinal":"1"},"width":"1"}"#
                .to_string(),
            // A walk of the supersession class apiece, and one store scan at
            // a single-span query.
            r#"{"op":"in_claims","y":"1.0.1.0.1.0.2.1","view":"default"}"#.to_string(),
            r#"{"op":"out_claims","x":"1.0.1.0.1.0.2.1","view":"default"}"#.to_string(),
            r#"{"op":"edition_claims","target":"1.0.1.0.1"}"#.to_string(),
        ];
        let unbounded = [
            // M5's resolve and one `readlink`: no store walk.
            format!(r#"{{"d":"1.0.1.0.1","op":"image","region":{region}}}"#),
            r#"{"a":"1.0.1.0.1.0.2.1","d":"1.0.1.0.1","op":"project","slot":1}"#.to_string(),
            r#"{"a":"1.0.1.0.1.0.2.1","d":"1.0.1.0.1","op":"discoverable_from"}"#.to_string(),
            r#"{"op":"read_link","a":"1.0.1.0.1.0.2.1"}"#.to_string(),
            r#"{"op":"follow_link","a":"1.0.1.0.1.0.2.1","slot":1}"#.to_string(),
            // The M6 and M3 reads touch no link store at all.
            r#"{"op":"retrieve_v","specs":[{"doc":"1.0.1.0.1","span":{"start":"1.1","width":"0.1"}}]}"#
                .to_string(),
            r#"{"op":"show_deletions","d_a":"1.0.1.0.1","d_b":"1.0.1.0.2"}"#.to_string(),
            r#"{"op":"doc_metadata","doc":"1.0.1.0.1"}"#.to_string(),
            r#"{"op":"next_account_prefix","parent":"1"}"#.to_string(),
        ];
        let mut names: std::collections::BTreeSet<&'static str> = std::collections::BTreeSet::new();
        for frame in &bounded {
            let op = parse(frame);
            assert!(is_class_scan(&op), "walks the link store, so it is bounded: {frame}");
            names.insert(crate::codec::op_name(op.kind()));
        }
        for frame in &unbounded {
            assert!(!is_class_scan(&parse(frame)), "walks no link store: {frame}");
        }
        assert_eq!(
            names.len(),
            BOUNDED_OPS,
            "every bounded op is visited, and only those: {names:?}"
        );
    }

    /// The class-scan admission at both ends (wire v7.9): a bounded op takes
    /// one of the [`MAX_CONCURRENT_CLASS_SCANS`] permits and any other read
    /// takes none, a drained pool REFUSES rather than queueing, and a
    /// released permit reopens its slot. The pool is per-op-shape, so an
    /// unbounded read is admitted while it is drained — which is what keeps
    /// the bound off the reads that walk no link store.
    #[test]
    fn the_class_scan_admission_takes_a_permit_only_for_a_bounded_op() {
        let op = |frame: &str| {
            JsonCodec
                .parse(frame.as_bytes())
                .unwrap_or_else(|e| panic!("{frame}: {:?}", e.detail))
                .op
        };
        let bounded =
            op(r#"{"op":"count_ftt","q":{"from":"any","home":"any","to":"any","ty":"any"}}"#);
        let unbounded = op(r#"{"op":"doc_metadata","doc":"1.0.1.0.1"}"#);
        let scans = ClassScans::new();
        assert!(
            scans.admit(&unbounded).expect("an unbounded read is admitted").is_none(),
            "…and spends no permit"
        );
        let held: Vec<_> = (0..MAX_CONCURRENT_CLASS_SCANS)
            .map(|_| {
                scans.admit(&bounded).expect("a permit").expect("a bounded read takes one")
            })
            .collect();
        scans.admit(&bounded).expect_err("a drained pool refuses; it never queues");
        assert!(
            scans.admit(&unbounded).expect("an unbounded read is admitted").is_none(),
            "a drained pool does not reach the reads it does not bound"
        );
        drop(held);
        assert!(
            scans.admit(&bounded).expect("a released permit reopens its slot").is_some(),
            "and the reopened slot is a permit, not an admission with none"
        );
    }
}
