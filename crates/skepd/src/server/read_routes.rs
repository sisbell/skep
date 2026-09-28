//! The read endpoints (`/op-at`, `/health`, `/chain`, `/changes`, `/dump`) and their parsers.

use serde_json::Value;
use skep_febe::{consult_read, Response};
use skep_kernel::Seq;
#[cfg(feature = "observe")]
use skep_namespace::PrincipalId;

use super::actor::Resolved;
use super::reply::{
    at_most_once, op_answer, query_pairs, refuse, refuse_reclaimed, refuse_unavailable, Reply,
    TransportError,
};
use super::Daemon;
use crate::auth::fold::{canonical_identity, key_set_of};
use crate::codec::{check_keys, key_set_reply, obj, DaemonOp};
use crate::write_path::{ChangesAnswer, FeedClass, Query};

/// `/changes` page size when `limit` is absent.
const DEFAULT_CHANGES_LIMIT: usize = 256;

/// `/changes` page-size ceiling; a larger request is refused, not clamped
/// (the never-silent posture applied to paging).
const MAX_CHANGES_LIMIT: usize = 4096;

impl Daemon {
    /// `POST /op-at` — answer one READ frame as of a committed position:
    /// envelope `{"at": <position>, "frame": {<op>}}`. The frame goes through
    /// the same codec as `/op`; the answer is the same response document with
    /// `as_of` reporting `at`. History is not a place you can act — a write
    /// frame is a transport-level 400 before anything runs; an unparseable
    /// frame gets the same `unparseable` rejection `/op` gives it.
    ///
    /// THE READER IS THE PRESENTED SESSION's (PUB-8.13; PUB round 2, lane
    /// 3.3): the route resolved `resolved` against the head, and the read
    /// runs as that principal — the guest when none was presented — never
    /// as a guest regardless of the token. And the read predicate is
    /// the HEAD's (PUB-6.48): ONE head snapshot is taken here, at admission,
    /// and every consult of this request reads its exception set and grant
    /// set — the doc-argument consult below, and, threaded into the throwaway
    /// front door `history.rs` builds over the reconstructed world, the
    /// per-run masks and the result-set filter. A grant committed after `at`
    /// therefore satisfies a read at `at`.
    ///
    /// THE HEAD-SET CHECK COMES FIRST (PUB-6.49): the doc-argument consult
    /// runs BEFORE the reconstruction — before the N-world's registration
    /// check, so a document in the head's exception set answers `withheld` at
    /// EVERY `at` to a requester the predicate refuses, never
    /// `doc_not_registered` for a position before its creation; and before
    /// `history_reclaimed` and `history_busy`, so one op has one code, and a
    /// withheld answer occupies no reconstruction permit (PUB-7.11). The
    /// consult is M10's own (`consult_read`) — the list of named documents,
    /// its declaration order (PUB-6.4) and the verdict (PUB-8.4, PUB-8.5:
    /// `withheld`, `reorder`, `site.addr` the document, no detail) — asked
    /// here over the head's predicate rather than restated.
    pub(super) fn op_at_reply(&self, resolved: &Resolved, body: &[u8]) -> Reply {
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
                // The SAME dispatcher as /op's, over the reconstructed
                // world and its canonical identity rebuild (AUTH-6.20) —
                // under the reconstruction budget like every historical
                // answer. Exempt from the predicate (PUB-6.50): it reads
                // only the born-published credential class.
                match self.history.reconstruct(&self.engine, at) {
                    Ok((_permit, world)) => {
                        let identity = canonical_identity(&world);
                        op_answer(key_set_reply(at, key_set_of(&world, &identity, &account)))
                    }
                    Err(e) => refuse_unavailable(e),
                }
            }
            DaemonOp::Febe { request: frame, .. } => {
                // The partition is M10's own, asked directly: this daemon
                // holds no second reading of it, and `write_path`'s
                // `write_meta` records what a drift on the other side costs.
                if !frame.op.is_read() {
                    // The ruling-fixed body, exactly: {"error": "write_at_history"}.
                    return refuse(TransportError::WriteAtHistory, None);
                }
                let principal = resolved.principal();
                // ONE head snapshot per request (PUB-6.39, PUB-6.48), and ONE
                // reader class over it, so the principal's seat is looked up
                // once for every argument the consult asks about.
                let head = self.engine.kernel().snapshot();
                let reader = head.world().reader_class(principal);
                if let Err(rej) = consult_read(&frame.op, &|doc| reader.readable(doc)) {
                    return self.op_reply(&Response::Rejected(rej));
                }
                match self.history.read_at(&self.engine, at, *frame, principal, &head) {
                    Ok(resp) => self.op_reply(&resp),
                    Err(e) => refuse_unavailable(e),
                }
            }
        }
    }

    pub(super) fn get_health(&self) -> Reply {
        // The head position's recorded wall-clock time (wire v6) — null
        // when the head's own record is bare or nothing is recorded at all
        // (a fresh world): transport metadata, never invented, and never an
        // older position's time offered in the head's place.
        //
        // THREE independent reads under no lock — this, the auth object's
        // own fold snapshot, and the `(log_position, chain_head)` pair at the
        // end — so this answer may straddle one in-flight commit at either
        // seam. A `head_time` correct for the position the sidecar last
        // recorded sits beside a `log_position` one commit newer; and a
        // client polling for the claim flip can see the position advance
        // before `claimant` appears, or read the pre-claim `signed_origins`
        // beside a post-claim position, which costs it one `session_rejected`
        // and a retry. Every one of them corrects itself on the next probe.
        // Taking the write lock here would serialize a liveness probe behind
        // writes, which is the worse trade; `CommitsLog::head_time` states
        // what each field is true of.
        //
        // `log_position` and `chain_head` do NOT straddle each other: the
        // kernel's root carries the seq and the chain together, and
        // `head_coordinate` reads both off ONE snapshot — one root load —
        // so the chain served is the chain AT the position served, never
        // `current_seq()` and `chain_head()` asked apart with a commit
        // landing between. The value is the KERNEL's (the marker closing
        // that position's transaction carries it; recovery derives it),
        // rendered as 64 lowercase hex and never recomputed here; a fresh
        // world answers the genesis seed — sixty-four `0`s — never null.
        let head_time =
            self.writes.head_time().map(|t| Value::Number(t.into())).unwrap_or(Value::Null);
        // The auth object (AUTH-6.13), rendered where its state lives — the
        // claimant, the flag and the two origin sets, with the wire's own
        // negative pin stated there too. Read BEFORE that pair, which is the
        // direction the straddle above describes.
        let auth = self.auth.auth_object();
        let (log_position, chain_head) = self.febe.head_coordinate();
        Reply::json(
            200,
            obj(vec![
                ("auth", auth),
                ("chain_head", Value::String(crate::codec::hex_string(&chain_head))),
                ("head_time", head_time),
                ("log_position", Value::Number(log_position.0.into())),
                ("ok", Value::Bool(true)),
            ]),
        )
    }

    /// `GET /chain?at=N` (the chain's open items, item 7; QUEUE item 10) —
    /// the commit chain's value AS OF committed position `N`, `{"at": N,
    /// "chain": "<64 lowercase hex>"}`: the kernel's RECOMPUTATION off its
    /// own journal (`Kernel::chain_at`), under the verification a historical
    /// read runs — every link from the base it selects below `N` to the
    /// journal's end — and under the same reconstruction permit, with no
    /// world materialized. At the committed head it is the value `/health`
    /// serves as `chain_head` beside `log_position`; at `0` the genesis seed.
    /// Token-blind and class-invariant like `/health`: a hash over the whole
    /// journal discloses no byte, and `/health` already serves it to
    /// everyone. What a peer holding a saved `(position, chain)` pair — a
    /// `/health` reading, a published head's members — checks against the
    /// board's recomputation rather than the board's stored claim (wire.md
    /// §The other endpoints): a re-chained journal answers the forgery here,
    /// which the saved pair contradicts. The refusals are `/op-at`'s through
    /// [`refuse_unavailable`] — `beyond_head`, `not_a_position`,
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
                    ("chain", Value::String(crate::codec::hex_string(&chain))),
                ]),
            ),
            Err(e) => refuse_unavailable(e),
        }
    }

    /// `GET /changes?since=N[&limit=K][&under=P][&drafts=true]` (wire v6;
    /// class-gated since v7.8) — the delta read: the committed positions in
    /// `(N, head]` the presented token's class may see, oldest first, from
    /// the feed. What this route adds over the feed's own paging is the
    /// requester's FEED CLASS (PUB-6.40): resolved ONCE, off ONE head
    /// snapshot — the read predicate at the requester's class, the
    /// requester's own and ancestor accounts and the prefix its descendant
    /// owner accounts lie under (the subtree clause, both ways), its
    /// grant-selected issuers with their covered prefixes, and the live
    /// any-principal set (the universal term, principals alone) — and
    /// threaded down; the feed module resolves nothing itself. An absent
    /// or dead token is the GUEST (PUB-8.13). Determinism is PER CLASS
    /// (PUB-8.26): same `(since, limit, under, drafts)`, same journal,
    /// same head publication and grant state, same class ⇒ byte-equal
    /// pages, across repeats and restarts.
    pub(super) fn get_changes(&self, resolved: &Resolved, query: Option<&str>) -> Reply {
        let query = match changes_params(query) {
            Ok(query) => query,
            Err(detail) => return refuse(TransportError::MalformedChanges, Some(&detail)),
        };
        // ONE head snapshot per request (PUB-6.39, PUB-6.40): the predicate
        // every entry is masked by and the class the candidates come from
        // stand on the same committed state.
        let head = self.engine.kernel().snapshot();
        let class = FeedClass::of(head.world(), resolved.principal());
        match self.writes.changes(&class, &query) {
            ChangesAnswer::Reclaimed { floor } => refuse_reclaimed(floor),
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

    /// `GET /dump` — the engine's deterministic `WorldDump` of the committed
    /// world AT THE REQUEST'S CLASS (PUB round 2, lane 3.4 §4): the
    /// harness-only walk (`Engine::world_dump`) post-filtered by the read
    /// predicate for the presented session's principal — an absent or dead
    /// token is the GUEST, whose publication slice renders EMPTY and whose
    /// dump holds no draft's content, arrangement or link. ONE head snapshot
    /// per request: the world dumped and the predicate it is filtered at
    /// are that snapshot's (PUB-6.39). `GET /dump?at=N` is the dump of the
    /// world as of position `N` (bounded replay) at the HEAD's class — the
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
                // The head predicate, closed over ONE head snapshot for this
                // request — the two-world shape `history.rs` states — through
                // ONE reader class, so the seat is looked up once per dump.
                let head = self.engine.kernel().snapshot();
                let reader = head.world().reader_class(principal);
                match self.history.dump_at(&self.engine, at, |doc| reader.readable(doc)) {
                    Ok(d) => d,
                    Err(e) => return refuse_unavailable(e),
                }
            }
        };
        Reply::bodied(200, "text/plain; charset=utf-8", dump.into_string().into_bytes())
    }

    /// The committed world's dump at `principal`'s class — what `GET /dump`
    /// answers a session bound to `principal` (`None` = the guest), through
    /// the same engine call, so a suite holding the daemon can state the H4
    /// oracle: the wire body equals this post-filter of the harness-only
    /// walk byte for byte. Unbudgeted, like [`Daemon::world_at`]: an
    /// embedder calling this holds the daemon itself.
    ///
    /// The answer's type is re-exported as [`crate::WorldDump`], for the
    /// reason the engine types beside it are: naming it must not oblige a
    /// caller to depend on the engine.
    #[cfg(feature = "observe")]
    pub fn dump_visible_to(&self, principal: Option<PrincipalId>) -> crate::WorldDump {
        self.engine.world_dump_visible_to(principal)
    }
}

// ── the change feed (wire v6) ────────────────────────────────────────────

/// The `/changes` query: `since=<position>` (required) plus optional
/// `limit=<1..=4096>`, `under=<address-or-prefix>` (wire v7.8, PUB-7.31)
/// and `drafts=true|false` (the drafts-only narrowing, PUB-7.35).
fn changes_params(query: Option<&str>) -> Result<Query, String> {
    let query = match query {
        None | Some("") => {
            return Err("the required parameter is since=<position>".into());
        }
        Some(query) => query,
    };
    let mut since: Option<u64> = None;
    let mut limit: Option<usize> = None;
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
                if n == 0 || n > MAX_CHANGES_LIMIT {
                    return Err(format!("limit: must be 1..={MAX_CHANGES_LIMIT}"));
                }
                limit = Some(n);
            }
            "under" => {
                at_most_once(&under, "parameter", "under")?;
                // The codec's own door, so a query string's tumbler and a
                // frame's meet ONE grammar under ONE budget rather than two
                // that agree today: the depth and digit caps and the
                // dotted-decimal grammar are all `wire_tumbler`'s, applied
                // before any component is converted.
                under = Some(crate::codec::wire_tumbler(v).map_err(|e| format!("under: {e}"))?);
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
    Ok(Query {
        since,
        limit: limit.unwrap_or(DEFAULT_CHANGES_LIMIT),
        under,
        drafts_only: drafts.unwrap_or(false),
    })
}

// ── the history surface (wire v3) ────────────────────────────────────────

/// Strictly `{"at": <non-negative integer>, "frame": <object>}`; returns the
/// position and the frame, which the codec parses from here. The
/// object-ness check is a decision, not duplicated validation: a non-object
/// `frame` is a malformed ENVELOPE (a transport fault), where the same
/// value reaching the codec would be an operation-channel rejection.
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

/// The one-parameter `at=<decimal position>` query two routes read —
/// `/dump`, where it is optional, and `/chain`, where it is required —
/// `route` naming the route in the refusal's detail: nothing, or exactly one
/// `at`.
fn at_param(query: Option<&str>, route: &str) -> Result<Option<Seq>, String> {
    let query = match query {
        None | Some("") => return Ok(None),
        Some(query) => query,
    };
    let mut at: Option<Seq> = None;
    for (k, v) in query_pairs(query)? {
        match k {
            "at" => {
                at_most_once(&at, "parameter", "at")?;
                at = Some(Seq(v.parse().map_err(|_| {
                    format!("at: '{v}' is not a position (a non-negative integer)")
                })?));
            }
            other => {
                return Err(format!(
                    "unknown parameter '{other}'; the one {route} parameter is at=<position>"
                ))
            }
        }
    }
    Ok(at)
}

/// The `/dump` query: nothing, or exactly `at=<decimal position>`.
#[cfg(feature = "observe")]
fn dump_at_param(query: Option<&str>) -> Result<Option<Seq>, String> {
    at_param(query, "/dump")
}

/// The `/chain` query: exactly `at=<decimal position>`, REQUIRED — the
/// head's own pair is `/health`'s, so a chain read with no position names
/// nothing.
fn chain_at_param(query: Option<&str>) -> Result<Seq, String> {
    at_param(query, "/chain")?
        .ok_or_else(|| String::from("missing parameter 'at'; the one /chain parameter is at=<position>"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `/changes` query's accepted forms, and the page size the wire
    /// promises when `limit` is absent (wire.md §The change feed: "default
    /// 256, maximum 4096"). Every other test drives this parser through
    /// its refusals; the seeded feeds are four writes long, so a default
    /// silently changed to 4 — or to 4096 — produces an identical wire
    /// answer in all of them.
    #[test]
    fn the_changes_query_defaults_to_the_documented_page_size() {
        let plain = |q: &str| {
            let p = changes_params(Some(q)).unwrap_or_else(|e| panic!("{q}: {e}"));
            (p.since, p.limit, p.under.map(|t| t.to_string()), p.drafts_only)
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
        assert_eq!(plain("since=3&drafts=false").3, false, "drafts=false is the plain feed");
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

    /// The `/dump` query is absent or exactly one position — the accepted
    /// half of the parser `tests/history.rs` exercises only through its
    /// refusals.
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
