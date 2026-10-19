//! The class-scan pool.
//!
//! The items are `MAX_CONCURRENT_CLASS_SCANS`, `ClassScans`, `ScanBusy` and
//! `is_class_scan`.

use skep_febe::Op;
use skep_util::permits::{edge_clock_now, EdgeTracker, Permit, Permits};

use skep_core::limits::EDGE_HOLD_DOWN;

/// The cap on class scans admitted at `/op` at once (PUB-8.36, PUB-8.37).
///
/// Class scans (wire v7.9) are the link-discovery reads [`is_class_scan`]
/// enumerates, each of which reads the link store at a cost the world sets
/// rather than the request — the whole active slice for an unconstrained
/// descriptor, the whole supersession class for the lineage pair, and every
/// link a region or a class reaches for the reads M7 answers from its
/// coverage index — repeatable at will from any unauthenticated peer.
///
/// The reconstruction pool's own number
/// ([`crate::history::MAX_CONCURRENT_RECONSTRUCTIONS`]), for the same reason
/// it is that pool's: two keep directories serviceable without letting a
/// stranger's scans occupy the worker pool. The wire names it as a constant
/// the daemon may raise later — a configuration question, not this bound's,
/// and one whose number is open, since the bound covers the region family a
/// board's own reading pane calls on every scroll.
///
/// One pool for the board: global across every bounded form, across every
/// type class, and across every session and the guest (a stranger is the
/// case). Disjoint from the reconstruction pool — a second instance of
/// [`Permits`], never a share of the first — so history panes and mirror
/// bootstraps are never starved by directory scans, nor the reverse.
///
/// The sum of this pool and the other four — the reconstruction, fetch,
/// upload and write pools — must leave a worker free:
/// [`MIN_WORKERS`](super::MIN_WORKERS) holds that relation, and an assertion
/// beside it holds the shipped default to it.
pub(super) const MAX_CONCURRENT_CLASS_SCANS: usize = 2;

/// The class-scan bound, whole (wire v7.9; PUB-8.36, PUB-8.37).
///
/// It holds what counts as a class scan ([`is_class_scan`]), how many run
/// at once ([`MAX_CONCURRENT_CLASS_SCANS`]), and the permit that spans one
/// answer. One card, as [`crate::history::History`] is for the
/// reconstruction budget, so the shape test and the pool it gates cannot
/// drift apart and a later meter has a whole thing to copy rather than five
/// pieces on [`Daemon`](super::Daemon).
///
/// A second instance of [`skep_util::permits`]'s mechanism, and disjoint
/// from the reconstruction pool by the borrow rather than by convention: a
/// [`Permit`] names the pool that issued it, so no signature here can spend
/// a reconstruction slot. Beside the pool, its edge pair (`operations.md`
/// §1.1 m12): an [`EdgeTracker`] the admission tells of every refusal and
/// every permit taken, whose edges the daemon drains ([`ClassScans::edge`])
/// and says through its classed door — `the scan pool is saturated` / `has
/// room again`, once per episode.
pub(super) struct ClassScans {
    permits: Permits,
    edge: EdgeTracker,
}

/// The class-scan pool's refusal: every class-scan permit is in use.
///
/// It says nothing about HTTP, as [`crate::history::Unavailable`] does not:
/// the mapping onto the wire is
/// [`refuse_scan_busy`](super::reply::refuse_scan_busy)'s, beside the
/// transport channel's other refusal constructors, and the wire name it maps
/// to is [`TransportError::ScanBusy`](super::reply::TransportError::ScanBusy)
/// — the same condition one layer out, which is why the two share a word and
/// why the type keeps them apart.
#[derive(Debug)]
pub(super) struct ScanBusy;

impl ClassScans {
    pub(super) fn new() -> ClassScans {
        ClassScans {
            permits: Permits::new(MAX_CONCURRENT_CLASS_SCANS),
            edge: EdgeTracker::new(EDGE_HOLD_DOWN),
        }
    }

    /// Admits one read, with a class-scan permit where it is a class scan.
    ///
    /// A class-scan-shaped read ([`is_class_scan`]) takes one of the
    /// [`MAX_CONCURRENT_CLASS_SCANS`] permits for the whole answer; any other
    /// read is admitted with no permit (`Ok(None)`).
    ///
    /// Taken before the read consult and the store call, both of which run
    /// inside M10's `execute`: a refused request has cost the parse and the
    /// session read alone, and an admitted one that M10 then withholds or
    /// rejects — never reaching M7 — still returns its permit by the guard.
    /// The pool is global: the guest and the claimant draw on it alike, and
    /// which class is scanned is not consulted. Whether the request is a
    /// class scan is the one thing decided here; what it answers stays the
    /// stores' — an admitted scan's answer is byte-for-byte the unbounded
    /// one.
    ///
    /// **The edge pair's one site** (m12). A class scan's refusal or
    /// admission is told to the tracker at the edge clock's instant and the
    /// edge it answers queued for the daemon's door; a read that takes no
    /// permit crosses none, and neither does the test hook below, which
    /// holds the pool and not a request.
    ///
    /// # Errors
    ///
    /// [`ScanBusy`] at once where a class-scan-shaped read finds every
    /// permit in use — a retry-class refusal, never a queue.
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

    /// Returns the pool's edge tracker, for the daemon to drain.
    ///
    /// It holds the edges the admission crossed since the last drain, in
    /// order.
    pub(super) fn edge(&self) -> &EdgeTracker {
        &self.edge
    }

    /// Holds one permit exactly as an in-flight scan does.
    ///
    /// **Test hook**, reached through `Daemon::try_hold_scan_permit`.
    #[cfg(any(test, feature = "test-hooks"))]
    #[must_use = "a permit dropped at once holds nothing"]
    pub(super) fn try_hold(&self) -> Option<Permit<'_>> {
        self.permits.try_acquire()
    }
}

/// Returns whether `op` is a class scan, one of the reads the pool bounds.
///
/// It is the class-scan test (wire v7.9; PUB-6.54, PUB-6.56, PUB-8.36) —
/// the one statement of what the pool bounds — and it bounds the op, never
/// the shape of the query. M7 answers `LinkState::stab` from its coverage
/// index, a probe per query span and a step per link it finds, and
/// `LinkState::match_links` answers its first constraint by a `stab` and
/// narrows what that finds with the rest; only its unconstrained form walks
/// the whole store. So a member costs the links its query reaches, or the
/// world's whole slice or class, and the store sets either: a region over a
/// widely linked document, a class every board writes into and the
/// all-`"any"` query are each as large as the world makes them. The
/// membership is the wire's list, held by op whatever each member costs.
///
/// **The population**, each member citing what it reaches:
///
/// * the FTT family (`find_links_ftt`, `count_ftt`, `window_ftt`) — one
///   `match_links`: its smallest constraint answered by a `stab`, and each
///   other tested on every link that finds, at
///   `|query spans| × |slot spans|` apiece, with the span counts and each
///   span's start tumbler the request's. The all-`"any"` and home-only
///   queries are `match_links`' unconstrained branch, a walk of the whole
///   active slice with one residence lookup per link, the one member whose
///   cost is the store's size whatever its query;
/// * the region family (`find_links_v`, `count_v`, `window_v`,
///   `retrieve_endsets`) — three `stab`s, one per v1 slot as
///   [M8's cost statement](skep_discovery#cost) counts them, each at up to
///   [`skep_discovery::MAX_IMAGE_RUNS`] query spans and a step per link the
///   region reaches. That constant caps the image and assigns what it cannot
///   reach — "`#runs(d)` and `|links|` are the WORLD's … they stay with
///   request rate and concurrency, which are M10's" — to this seat;
/// * `delete_orphans` — six `stab`s, three over the deleted runs and three
///   over the retained (the same statement), the most of any read, and it
///   takes no owner gate by design, so every asker reaches it on any
///   registered document;
/// * `edition_claims` — one `match_links` at a single-span `to` range,
///   behind a registration gate: a `stab`, then a type test on every claim
///   the range reaches, so it costs the claims on the target, which its
///   depositors choose;
/// * `in_claims`, `out_claims` — no store walk: M8 asks M7's typed `observe`
///   of the supersession class, a walk of that class's typed slice behind a
///   residence gate, one coverage test per claim (the same statement). The
///   class is the world's, not the request's — every supersession claim in
///   the docuverse is in it — so the walk is world-sized.
///
/// **Nothing else is bounded**, and each absence is a fact about the read
/// rather than a judgement: `image`, `project` and `discoverable_from` walk
/// no link store — their work is a walk of one document's run-list, or a
/// join of one link's coverage against that document's runs, each held by
/// M8 to a number its cost statement records: the square of
/// [`skep_discovery::MAX_IMAGE_RUNS`] for the walk and for the boolean touch
/// test, and [`skep_discovery::MAX_ANSWER_SPANS`] for the projection, whose
/// join builds the span set it answers with. An `image` region's runs are
/// counted as M8 pulls them from M5's lazy resolution and refused at the one
/// past [`skep_discovery::MAX_IMAGE_RUNS`], so no region materializes a
/// fragmented document whole; `read_link` and `follow_link` are lookups;
/// the M6 family (`retrieve_v`, `compare`, `show_deletions`,
/// `find_docs_containing`, `show_origin`) and the M3 reads touch no link
/// store at all.
///
/// **Not exhaustive over `Op`** (46 variants against 11 — the first moves
/// with `Op`, whose count the codec suite's op-name table is held to; the
/// second moves only by hand, here), so a new read that walks the link
/// store must be added by hand — `write_meta`'s table, which the compiler
/// does force, reaches writes alone. Nothing about a query is read here:
/// not the class, not the cursor, not the slots, and not whether M8 would
/// answer it off its own descriptor (a `ty` of `"empty"` annihilates before
/// M7 is asked; it is bounded all the same, and its permit is back in the
/// pool a moment later).
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
    use skep_core::codec::JsonCodec;

    /// Checks the class-scan test over the op and not over the query's slots.
    ///
    /// The eleven bounded ops are the wire's class scans, and the pool bounds
    /// them whatever their slots hold — a second constrained slot, an
    /// annihilating `"empty"`, a narrow region — while the reads that walk no
    /// link store are bounded by nothing.
    ///
    /// Every row is parsed through the codec rather than built by hand, so
    /// the test reads the frames a client sends. The two lists are disjoint,
    /// and the bounded list's distinct ops are checked against the bounded
    /// arm's own count, restated: an op moved between the arms fails its
    /// row's assertion where a list names it, and a new op's bounded row
    /// added without restating the count fails the last assertion.
    #[test]
    fn every_class_scan_is_bounded_whatever_its_slots_hold() {
        /// The bounded arm's size, restated.
        ///
        /// Moving the arm is a visible decision here, the discipline this
        /// crate gives its wire caps.
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
            // and a second slot constrained, which tests each link the first
            // finds.
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
            // The region family: three stabs apiece, one per v1 link slot.
            format!(r#"{{"d":"1.0.1.0.1","op":"find_links_v","region":{region}}}"#),
            format!(r#"{{"d":"1.0.1.0.1","op":"count_v","region":{region}}}"#),
            format!(
                r#"{{"cur":null,"d":"1.0.1.0.1","n":16,"op":"window_v","region":{region}}}"#
            ),
            format!(r#"{{"d":"1.0.1.0.1","op":"retrieve_endsets","region":{region}}}"#),
            // Six stabs, and no owner gate.
            r#"{"d":"1.0.1.0.1","op":"delete_orphans","p":{"subspace":"1","ordinal":"1"},"width":"1"}"#
                .to_string(),
            // A walk of the supersession class apiece, and one `match_links`
            // at a single-span query.
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
            assert!(is_class_scan(&op), "a class scan, so it is bounded: {frame}");
            names.insert(skep_core::codec::op_name(op.kind()));
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

    /// Checks the class-scan admission at both ends (wire v7.9).
    ///
    /// A bounded op takes one of the [`MAX_CONCURRENT_CLASS_SCANS`] permits
    /// and any other read takes none, a drained pool refuses rather than
    /// queueing, and a released permit reopens its slot. The pool is
    /// per-op-shape, so an unbounded read is admitted while it is drained —
    /// which is what keeps the bound off the reads that walk no link store.
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
