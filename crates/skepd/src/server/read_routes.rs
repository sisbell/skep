//! The read endpoints and their parsers.
//!
//! The endpoints are `/op-at`, `/health`, `/chain`, `/changes` and `/dump`.

use std::num::NonZeroUsize;

use serde_json::Value;
use skep_febe::{consult_read, Response};
use skep_identity::HasIdentity;
use skep_kernel::Seq;
use skep_util::json::obj;
use skep_util::notice::Class;

use super::actor::Resolved;
use super::reply::{
    op_answer, refuse, refuse_feed_rebuilding, refuse_over_budget, refuse_reclaimed,
    refuse_unavailable, FeedWalk, Reply,
    TransportError,
};
use super::request::{at_most_once, query_pairs, sole_param};
use super::{Daemon, HistoryDamageLine, JournalDamageSite};
use crate::history::Unavailable;
use skep_core::auth::key_set_of;
use skep_core::codec::{check_keys, key_set_reply, DaemonOp};
use crate::limits::{DEFAULT_CHANGES_LIMIT, MAX_CHANGES_LIMIT};
use skep_core::commits::{ChangesAnswer, ChangesQuery, FeedClass};

impl Daemon {
    /// Answers `POST /op-at`: one read frame as of a committed position.
    ///
    /// The envelope is `{"at": <position>, "frame": {<op>}}`. The frame goes
    /// through the same codec as `/op`; the answer is the same response
    /// document with `as_of` reporting `at`. History is not a place you can
    /// act — a write frame is a transport-level 400 before anything runs; an
    /// unparseable frame gets the same `unparseable` rejection `/op` gives it.
    ///
    /// **The reader is the presented session's** (PUB-8.13). The route
    /// resolved `resolved` against the head, and the read runs as that
    /// principal — the guest when none was presented — never as a guest
    /// regardless of the token. And the read predicate is the head's
    /// (PUB-6.48): one head snapshot is taken here, at admission, and every
    /// consult of this request reads its exception set and grant set — the
    /// doc-argument consult below, and, threaded into the throwaway front
    /// door `history.rs` builds over the reconstructed world, the per-run
    /// masks and the result-set filter. A grant committed after `at`
    /// therefore satisfies a read at `at`.
    ///
    /// **The head-set check comes first** (PUB-6.49). The doc-argument
    /// consult runs before the reconstruction — before the N-world's
    /// registration check, so a document in the head's exception set answers
    /// `withheld` at every `at` to a requester the predicate refuses, never
    /// `doc_not_registered` for a position before its creation; and before
    /// `history_reclaimed` and `history_busy`, so one op has one code, and a
    /// withheld answer occupies no reconstruction permit (PUB-7.11). The
    /// consult is M10's own (`consult_read`) — the list of named documents,
    /// its declaration order (PUB-6.4) and the verdict (PUB-8.4, PUB-8.5:
    /// `withheld`, `reorder`, `site.addr` the document, no detail) — asked
    /// here over the head's predicate rather than restated.
    pub(super) fn post_op_at(&self, resolved: &Resolved, body: &[u8]) -> Reply {
        let (at, frame) = match op_at_envelope(body) {
            Ok(x) => x,
            Err(detail) => return refuse(TransportError::MalformedOpAt, Some(&detail)),
        };
        let parsed = match self.codec.parse_daemon_value(frame) {
            Ok(r) => r,
            Err(e) => return self.op_reply(&self.codec.unparseable(e)),
        };
        match parsed {
            DaemonOp::KeySet { account } => {
                // The same dispatcher as /op's, over the reconstructed World
                // with the identity slice riding in it (AUTH-6.20) — the
                // table as of `at`, folded by the same replay that built the
                // world, in commit order (AUTH-2.95: equal to the live
                // `key_set` when the head was `at`) — under the
                // reconstruction budget like every historical answer. A
                // position whose every base is slice-less over credential
                // deposits is refused whole as `history_reclaimed`
                // (AUTH-2.87), as every read at that position is. Exempt
                // from the predicate (PUB-6.50): it reads only the
                // born-published credential class.
                match self.history.reconstruct(&self.engine, at) {
                    Ok((_permit, world)) => {
                        op_answer(key_set_reply(at, key_set_of(&world, &account)))
                    }
                    Err(e) => self.refuse_history(e),
                }
            }
            DaemonOp::Febe { request: frame, .. } => {
                // The partition is M10's own, asked directly: this daemon
                // holds no second reading of it, and `skep_core::commits`'s
                // `write_meta` records what a drift on the other side costs.
                if !frame.op.is_read() {
                    // The fixed body, exactly: {"error": "write_at_history"}.
                    return refuse(TransportError::WriteAtHistory, None);
                }
                let principal = resolved.principal();
                // One head snapshot per request (PUB-6.39, PUB-6.48), and one
                // reader class over it, so the principal's seat is looked up
                // once for every argument the consult asks about.
                let head = self.engine.kernel().snapshot();
                let reader = head.world().reader_class(principal);
                if let Err(rej) = consult_read(&frame.op, &|doc| reader.readable(doc)) {
                    return self.op_reply(&Response::Rejected(rej));
                }
                match self.history.read_at(&self.engine, at, *frame, principal, &head) {
                    Ok(resp) => self.op_reply(&resp),
                    Err(e) => self.refuse_history(e),
                }
            }
        }
    }

    /// Answers a refused historical read, saying the journal's damage once.
    ///
    /// The reply is [`refuse_unavailable`]'s, the reader's answer unchanged.
    /// Beside it, where the refusal is the journal's damage
    /// ([`Unavailable::journal_damage`]), the first such refusal of this
    /// uptime says [`HistoryDamageLine`] under `Class::Failure` and keeps
    /// the damage's site ([`JournalDamageSite`]) for the standing line, which
    /// re-says it by that site: a history read scans the journal from its
    /// base to its end, so it is the first reader to meet damage in a segment
    /// the write path never reads back — damage the next start's open reads
    /// and may refuse on, which the operator can still mend while the board
    /// serves (RUNBOOK §2). Once per uptime and never per request, and
    /// neither line names a reader (D9). `/op-at`, `/chain?at` and `/dump?at`
    /// answer every refusal through it.
    pub(super) fn refuse_history(&self, e: Unavailable) -> Reply {
        if let Some(damage) = e.journal_damage() {
            if self.history_damage.set(JournalDamageSite(damage).to_string()).is_ok() {
                self.say(Class::Failure, HistoryDamageLine(damage));
            }
        }
        refuse_unavailable(e)
    }

    pub(super) fn get_health(&self) -> Reply {
        // The head position's recorded wall-clock time (wire v6) — null
        // when the head's own record is bare, lies in the region the feed's
        // walk has yet to land, or nothing is recorded at all (a fresh
        // world): transport metadata, never invented, and never an older
        // position's time offered in the head's place.
        //
        // Four independent reads, no lock held ACROSS them — this, the auth
        // object's own head snapshot (whose World carries the key table),
        // the `(log_position, chain_head)` pair at the end, and the `writes`
        // member's two atomic loads beside them — so this answer may
        // straddle one in-flight commit at either seam. A `head_time` correct
        // for the position the sidecar last recorded sits beside a
        // `log_position` one commit newer; and a client polling for the claim
        // flip can see the position advance before `claimant` appears, or
        // read the pre-claim `signed_origins` beside a post-claim position,
        // which costs it one `session_rejected` and a retry. Every one of them
        // corrects itself on the next probe. Taking the serialization lock
        // here would serialize a liveness probe behind every write, which is
        // the worse trade; `CommitsLog::head_time` states what each field is
        // true of.
        //
        // One read does wait: `head_time` takes the change feed's own lock,
        // which the write path's record step holds across a commit's lines —
        // through the attest store's `sync_data` on every attested commit —
        // and the checkpoint thread across the feed's compaction after a
        // landing. A millisecond on a healthy volume; on one that stops
        // answering mid-sync, this probe waits with it, holding its worker,
        // as every `/changes` page does, while a read at the head, which
        // reads no file, still answers. Neither waiter is pooled, so enough
        // of them park every worker; the head's time behind no lock is the
        // change feed's to offer.
        //
        // `log_position` and `chain_head` do not straddle each other: the
        // kernel's root carries the seq and the chain together, and
        // `head_coordinate` reads both off one snapshot — one root load —
        // so the chain served is the chain at the position served, never
        // `current_seq()` and `chain_head()` asked apart with a commit
        // landing between. The value is the kernel's (the marker closing
        // that position's transaction carries it; recovery derives it),
        // rendered as 64 lowercase hex and never recomputed here; a fresh
        // world answers the genesis seed — sixty-four `0`s — never null.
        let head_time =
            self.commits.head_time().map(|t| Value::Number(t.into())).unwrap_or(Value::Null);
        // The auth object (AUTH-6.13), rendered where its state lives — the
        // claimant, the flag and the two origin sets, with the wire's own
        // negative pin stated there too. Read before that pair, which is the
        // direction the straddle above describes.
        let auth = self.auth.auth_object(self.engine.kernel().snapshot().world().identity());
        let (log_position, chain_head) = self.febe.head_coordinate();
        // The `writes` object (wire.md §The other endpoints; `operations.md`
        // op-D10): whether the daemon refuses every write until a restart —
        // the write path's halt (a failed attest line) or the kernel's
        // poison — two atomic loads, so the member and the operator stream's
        // two halt lines agree on one fact; a `true` is terminal for the
        // uptime and so actionable without a race, a `false` one moment's
        // reading.
        let halted = self.commits.halted_at().is_some() || self.engine.kernel().is_poisoned();
        // The media object (wire.md §Media, the upload setting): the upload
        // switch echoed where its state lives (`MediaGate::health_object`),
        // a boundary setting read once by the client before any face that
        // names an upload speaks (P37) — daemon config, never board state,
        // so no snapshot and no straddle. The members ride `obj`, which sorts
        // keys, so the wire's order is alphabetical whatever this list's.
        Reply::json(
            200,
            obj(vec![
                ("auth", auth),
                ("chain_head", Value::String(skep_util::json::hex_string(&chain_head))),
                ("head_time", head_time),
                ("log_position", Value::Number(log_position.0.into())),
                ("media", self.media.health_object()),
                ("ok", Value::Bool(true)),
                ("writes", obj(vec![("halted", Value::Bool(halted))])),
            ]),
        )
    }

    /// Answers `GET /chain?at=N`: the commit chain's value as of position `N`.
    ///
    /// The answer, `{"at": N, "chain": "<64 lowercase hex>"}`, is the value
    /// as of committed position `N`: the kernel's recomputation off its own
    /// journal (`Kernel::chain_at`), under the verification a historical
    /// read runs — every link from the base it selects at or below `N` to
    /// the journal's end, save where `N` is that base's own position, which
    /// answers the base's own chain with the journal unread — and under the
    /// same reconstruction permit, with no world folded and none kept. At the
    /// committed head it is the value `/health` serves as `chain_head` beside
    /// `log_position`; at `0` the genesis seed.
    /// Token-blind and class-invariant like `/health`: a hash over the whole
    /// journal discloses no byte, and `/health` already serves it to
    /// everyone. What a peer holding a saved `(position, chain)` pair — a
    /// `/health` reading, a published head's members — checks against the
    /// board's recomputation rather than the board's stored claim (wire.md
    /// §The other endpoints): a re-chained journal answers the forgery here,
    /// which the saved pair contradicts. The refusals are `/op-at`'s, through
    /// [`Daemon::refuse_history`] — `beyond_head`, `not_a_position`,
    /// `history_reclaimed`, `history_busy`, `history_io`/`history_corrupt`,
    /// `no_journal` — and a malformed or absent `at` is `malformed_at`, the
    /// `/dump` query's own refusal.
    pub(super) fn get_chain(&self, query: Option<&str>) -> Reply {
        let at = match chain_at_param(query) {
            Ok(at) => at,
            Err(detail) => return refuse(TransportError::MalformedAt, Some(&detail)),
        };
        match self.history.chain_at(&self.engine, at) {
            Ok(chain) => Reply::json(
                200,
                obj(vec![
                    ("at", Value::Number(at.0.into())),
                    ("chain", Value::String(skep_util::json::hex_string(&chain))),
                ]),
            ),
            Err(e) => self.refuse_history(e),
        }
    }

    /// Answers `GET /changes`: the delta read.
    ///
    /// The route is `GET /changes?since=N[&limit=K][&under=P][&drafts=true]`
    /// (wire v6; class-gated, wire v7.8), and the answer is the committed
    /// positions in `(N, head]` the presented token's class may see, oldest
    /// first, from the feed. What this route adds over the feed's own paging
    /// is the requester's feed class (PUB-6.40): resolved once, off one head
    /// snapshot — the read predicate at the requester's class, the
    /// requester's own and ancestor accounts and the prefix its descendant
    /// owner accounts lie under (the subtree clause, both ways), its
    /// grant-selected issuers with their covered prefixes, and the live
    /// any-principal set (the universal term, principals alone) — and
    /// threaded down; the feed module resolves nothing itself. An absent or
    /// dead token is the guest (PUB-8.13). Determinism is per class
    /// (PUB-8.26): same `(since, limit, under, drafts)`, same journal, same
    /// head publication and grant state, same class ⇒ byte-equal pages,
    /// across repeats and restarts.
    pub(super) fn get_changes(&self, resolved: &Resolved, query: Option<&str>) -> Reply {
        let changes_query = match changes_params(query) {
            Ok(parsed) => parsed,
            Err(detail) => return refuse(TransportError::MalformedChanges, Some(&detail)),
        };
        // One head snapshot per request (PUB-6.39, PUB-6.40): the predicate
        // every entry is masked by and the class the candidates come from
        // stand on the same committed state.
        let head = self.engine.kernel().snapshot();
        let class = FeedClass::of(head.world(), resolved.principal());
        match self.commits.changes(&class, &changes_query) {
            ChangesAnswer::Reclaimed { floor } => refuse_reclaimed(floor),
            // The page byte budget (SO-I9): refused whole, with the budget
            // and the largest `limit` that fits from this fence.
            ChangesAnswer::OverBudget { budget, fits } => refuse_over_budget(budget, fits),
            // The walk behind the listener (`operations.md` §3.3 step 2):
            // the page's rows would come from the region a lost or torn
            // `commits.log` left uncovered — refused retry-class until the
            // walk lands it, and, where the walk's thread has died, refused
            // with the restart named, since no landing comes this uptime.
            ChangesAnswer::Rebuilding { low, head } => {
                let walk = match self.commits.feed_walk_gone() {
                    Some(_) => FeedWalk::Gone,
                    None => FeedWalk::Walking,
                };
                refuse_feed_rebuilding(low, head, walk)
            }
            ChangesAnswer::Page { entries, last, more } => Reply::json(
                200,
                obj(vec![
                    ("changes", Value::Array(entries)),
                    ("last", Value::Number(last.into())),
                    ("more", Value::Bool(more)),
                ]),
            ),
        }
    }

    /// Answers `GET /dump`: the committed world's dump at the request's class.
    ///
    /// It is the engine's deterministic `WorldDump` of the committed world:
    /// the harness-only walk (`Engine::world_dump`) post-filtered by the read
    /// predicate for the presented session's principal — an absent or dead
    /// token is the guest, whose publication slice renders empty and whose
    /// dump holds no draft's content, arrangement or link. One head snapshot
    /// per request: the world dumped and the predicate it is filtered at
    /// are that snapshot's (PUB-6.39). `GET /dump?at=N` is the dump of the
    /// world as of position `N` (bounded replay) at the head's class — the
    /// N-world's state through the head's exception set and grant set
    /// (PUB-6.48), as `/op-at` reads it. Determinism holds per class
    /// (PUB-8.26): two equal `N`s at one class are byte-equal, and `N` =
    /// head equals the plain dump at that class. Exists only in `observe`
    /// builds.
    #[cfg(feature = "observe")]
    pub(super) fn get_dump(&self, resolved: &Resolved, query: Option<&str>) -> Reply {
        let at = match dump_at_param(query) {
            Ok(x) => x,
            Err(detail) => return refuse(TransportError::MalformedAt, Some(&detail)),
        };
        let principal = resolved.principal();
        let dump = match at {
            None => self.engine.world_dump_visible_to(principal),
            Some(at) => {
                // The head predicate, closed over one head snapshot for this
                // request — the two-world shape `history.rs` states — through
                // one reader class, so the seat is looked up once per dump.
                let head = self.engine.kernel().snapshot();
                let reader = head.world().reader_class(principal);
                match self.history.dump_at(&self.engine, at, |doc| reader.readable(doc)) {
                    Ok(d) => d,
                    Err(e) => return self.refuse_history(e),
                }
            }
        };
        Reply::bodied(200, "text/plain; charset=utf-8", dump.into_string().into_bytes())
    }
}

// ── the change feed (wire v6) ────────────────────────────────────────────

/// Parses the `/changes` query string's parameters into a [`ChangesQuery`].
///
/// They are `since=<position>` (required) plus optional `limit=<1..=4096>`,
/// `under=<address-or-prefix>` (wire v7.8, PUB-7.31) and `drafts=true|false`
/// (the drafts-only narrowing, PUB-7.35).
///
/// # Errors
///
/// A detail naming the fault: an absent or empty query, a pair with no `=`,
/// an unknown or repeated parameter, a `since` that is not a non-negative
/// integer, a `limit` that is not a count in `1..=4096`, an `under` the
/// codec's tumbler grammar refuses, a `drafts` other than `true` or
/// `false`, or a query with no `since`.
fn changes_params(query: Option<&str>) -> Result<ChangesQuery, String> {
    let query = match query {
        None | Some("") => {
            return Err("the required parameter is since=<position>".into());
        }
        Some(query) => query,
    };
    let mut since: Option<u64> = None;
    let mut limit: Option<NonZeroUsize> = None;
    let mut under: Option<skep_address::Tumbler> = None;
    let mut drafts: Option<bool> = None;
    for (k, v) in query_pairs(query)? {
        match k {
            "since" => {
                at_most_once(&since, "parameter", "since")?;
                since = Some(v.parse().map_err(|_| {
                    format!("since: '{v}' is not a position (a non-negative integer)")
                })?);
            }
            "limit" => {
                at_most_once(&limit, "parameter", "limit")?;
                let n: usize = v
                    .parse()
                    .map_err(|_| format!("limit: '{v}' is not a count"))?;
                let n = NonZeroUsize::new(n)
                    .filter(|n| n.get() <= MAX_CHANGES_LIMIT)
                    .ok_or_else(|| format!("limit: must be 1..={MAX_CHANGES_LIMIT}"))?;
                limit = Some(n);
            }
            "under" => {
                at_most_once(&under, "parameter", "under")?;
                // The codec's own door, so a query string's tumbler and a
                // frame's meet one grammar under one budget rather than two
                // that agree today: the depth and digit caps and the
                // dotted-decimal grammar are all `wire_tumbler`'s, applied
                // before any component is converted.
                under = Some(skep_core::codec::wire_tumbler(v).map_err(|e| format!("under: {e}"))?);
            }
            "drafts" => {
                at_most_once(&drafts, "parameter", "drafts")?;
                drafts = Some(match v {
                    "true" => true,
                    "false" => false,
                    other => return Err(format!("drafts: '{other}' is not true or false")),
                });
            }
            other => return Err(format!("unknown parameter '{other}'")),
        }
    }
    let since = since.ok_or_else(|| String::from("the required parameter is since=<position>"))?;
    Ok(ChangesQuery {
        since,
        limit: limit.unwrap_or(DEFAULT_CHANGES_LIMIT),
        under,
        drafts_only: drafts.unwrap_or(false),
    })
}

// ── the history surface (wire v3) ────────────────────────────────────────

/// Parses the `/op-at` envelope into its position and its frame.
///
/// The envelope is strictly `{"at": <non-negative integer>, "frame":
/// <object>}`; it returns the position and the frame, which the codec
/// parses from here. The object-ness check is a decision, not duplicated
/// validation: a non-object `frame` is a malformed envelope (a transport
/// fault), where the same value reaching the codec would be an
/// operation-channel rejection.
///
/// # Errors
///
/// A detail naming the fault: a body that is not JSON or not an object, a
/// member other than `at` and `frame`, an `at` that is missing or not a
/// non-negative integer, a missing `frame`, or a `frame` that is not an
/// object.
fn op_at_envelope(body: &[u8]) -> Result<(Seq, Value), String> {
    let v: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;
    let Value::Object(mut m) = v else {
        return Err("op-at envelope must be a JSON object".into());
    };
    check_keys(&m, &["at", "frame"])?;
    let at = m
        .get("at")
        .and_then(Value::as_u64)
        .ok_or_else(|| String::from("missing or non-integer field 'at'"))?;
    let frame = m.remove("frame").ok_or_else(|| String::from("missing field 'frame'"))?;
    if !frame.is_object() {
        return Err("field 'frame' must be a JSON object (an /op frame)".into());
    }
    Ok((Seq(at), frame))
}

/// Parses the one-parameter `at=<position>` query two routes read.
///
/// The routes are `/dump`, where it is optional, and `/chain`, where it is
/// required: [`sole_param`]'s value as a position.
///
/// # Errors
///
/// [`sole_param`]'s refusals, and a value that is not a non-negative
/// integer.
fn at_param(query: Option<&str>) -> Result<Option<Seq>, String> {
    sole_param(query, "at")?
        .map(|v| {
            v.parse()
                .map(Seq)
                .map_err(|_| format!("at: '{v}' is not a position (a non-negative integer)"))
        })
        .transpose()
}

/// Parses the `/dump` query: nothing, or exactly `at=<decimal position>`.
///
/// # Errors
///
/// [`at_param`]'s.
#[cfg(feature = "observe")]
fn dump_at_param(query: Option<&str>) -> Result<Option<Seq>, String> {
    at_param(query)
}

/// Parses the `/chain` query: exactly `at=<decimal position>`, required.
///
/// The head's own pair is `/health`'s, so a chain read with no position
/// names nothing.
///
/// # Errors
///
/// [`at_param`]'s refusals, and an absent `at`.
fn chain_at_param(query: Option<&str>) -> Result<Seq, String> {
    at_param(query)?
        .ok_or_else(|| String::from("missing parameter 'at'; the one /chain parameter is at=<position>"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks the `/changes` query's accepted forms and its default page size.
    ///
    /// The page size is the one the wire promises when `limit` is absent
    /// (wire.md §The change feed: "default 256, maximum 4096"). The
    /// integration tests drive this parser over the wire, and
    /// `tests/it/changes.rs`'s page-budget test serves the default page of
    /// 256 rows; this test holds the forms and the default at the parser.
    #[test]
    fn the_changes_query_defaults_to_the_documented_page_size() {
        let plain = |q: &str| {
            let p = changes_params(Some(q)).unwrap_or_else(|e| panic!("{q}: {e}"));
            (p.since, p.limit.get(), p.under.map(|t| t.to_string()), p.drafts_only)
        };
        assert_eq!(
            plain("since=0"),
            (0, 256, None, false),
            "an absent limit is the documented default; no narrowing by default"
        );
        assert_eq!(plain("since=7&limit=10"), (7, 10, None, false));
        assert_eq!(
            plain("limit=10&since=7"),
            (7, 10, None, false),
            "parameters are a set, not a sequence"
        );
        assert_eq!(plain("since=0&limit=4096").1, 4096, "the maximum is in range");
        // The two narrowings (wire v7.8): a tumbler prefix, and the flag.
        assert_eq!(
            plain("since=3&under=1.0.2"),
            (3, 256, Some("1.0.2".into()), false),
            "under= names an address or prefix"
        );
        assert_eq!(
            plain("since=3&drafts=true&under=1.0.2.0.4"),
            (3, 256, Some("1.0.2.0.4".into()), true)
        );
        assert!(!plain("since=3&drafts=false").3, "drafts=false is the plain feed");
        for bad in [
            None,
            Some(""),
            Some("limit=2"),
            Some("since=abc"),
            Some("since=0&limit=0"),
            Some("since=0&limit=4097"),
            Some("since=0&since=1"),
            Some("since=0&nope=1"),
            Some("since"),
            Some("since=0&under="),
            Some("since=0&under=1..2"),
            Some("since=0&under=1.x"),
            Some("since=0&under=1&under=2"),
            Some("since=0&drafts=yes"),
            Some("since=0&drafts=1"),
            Some("since=0&drafts=true&drafts=true"),
        ] {
            assert!(changes_params(bad).is_err(), "{bad:?} must be refused");
        }
    }

    /// Checks that the `/dump` query is absent or exactly one position.
    ///
    /// It pins the parser's accepted half, which `tests/it/history.rs` also
    /// drives over the wire beside its refusals.
    #[cfg(feature = "observe")]
    #[test]
    fn the_dump_query_is_absent_or_exactly_one_position() {
        let at = |q| dump_at_param(q).map(|o| o.map(|s| s.0));
        assert_eq!(at(None).expect("no query"), None);
        assert_eq!(at(Some("")).expect("empty query"), None);
        assert_eq!(at(Some("at=9")).expect("a position"), Some(9));
        assert_eq!(at(Some("at=0")).expect("genesis is a position"), Some(0));
        for bad in [Some("at=abc"), Some("at=1&at=2"), Some("position=3"), Some("at")] {
            assert!(dump_at_param(bad).is_err(), "{bad:?} must be refused");
        }
    }
}
