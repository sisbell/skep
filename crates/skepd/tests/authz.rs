//! H1 — the authorization matrix (hardening ruling): the ownership round's
//! probes graduated to a standing, table-driven instrument at the WIRE level
//! (every cell goes through `POST /op` — the end-to-end truth).
//!
//! One row per WRITE operation, one column per caller relationship to the
//! row's target resources; each cell is walked and its verdict compared to
//! the table. The full matrix is walked twice — once, then again after a
//! daemon restart with freshly bound sessions — pinning that authorization
//! derives from the persistent registry, never from session state.
//!
//! Finding protocol (H3/H2 discipline): a discovered violation is converted
//! to `#[ignore = "FINDING-n: …"]` with the assertion INTACT and the
//! reproduction in a comment — never weakened.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};

use common::*;
use serde_json::Value;

// ═══════════════════════════════════════════════════════════════════════
// THE CONTRACT TABLE.
//
// Editing a cell is a reviewed AUTHORIZATION CHANGE, never an incidental
// diff: each cell states who may perform that write against a resource
// owned by the `owner` column's principal (wire.md §Identity, v5.1
// ownership ruling 2026-08-16). Sources of truth behind the expectations:
//   * ω exactness — a caller owns a document iff its account is EXACTLY the
//     document's nearest registered account prefix; parent and sub-account
//     own each other's documents in NEITHER direction (skep-arrangement
//     auth.rs; the deliberate fix of green's `tumbleraccounteq`).
//   * `delegate`'s pinned rejection order (M3 §6): a non-ancestor delegator
//     is `not_ancestor` BEFORE authorization; an ancestor that is not
//     ω(new_prefix) is `not_authorized` (the parent-of-owner cell).
//   * `register_node` takes NO principal in the store (provisioning is
//     authentication-gated only) — every bound session may admit a fresh
//     node. Recorded here as a reviewed fact of the local-trust scope.
//   * `version` and `copy`-from-foreign-source are DELIBERATELY ungated
//     (denial-as-fork / transclusion is the medium); an accidental gate on
//     either is a cell mismatch.
//   * `edit_link` of a FOREIGN original with both homes your own is the
//     sanctioned "propose a change" path for links: allowed.
//   * guest (no token) and stale-token (token from a daemon lifetime that
//     has ended) never reach a store: M10's `unauthenticated`, permanent.
// ═══════════════════════════════════════════════════════════════════════

/// Column order — indexes into every row's `expect` array.
const COLS: [&str; 6] =
    ["owner", "sibling", "child-of-owner", "parent-of-owner", "guest", "stale-token"];

const OK: &str = "ok";
const NOT_OWNER: &str = "not_owner";
const UNAUTH: &str = "unauthenticated";

struct Row {
    op: &'static str,
    expect: [&'static str; 6],
}

#[rustfmt::skip]
const MATRIX: &[Row] = &[
    // ── namespace writes ──                owner  sibling         child           parent            guest   stale
    Row { op: "create_new_document",  expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTH, UNAUTH] },
    Row { op: "delegate",             expect: [OK, "not_ancestor", "not_ancestor", "not_authorized", UNAUTH, UNAUTH] },
    Row { op: "register_node",        expect: [OK, OK,             OK,             OK,               UNAUTH, UNAUTH] },
    Row { op: "fork",                 expect: [OK, OK,             OK,             OK,               UNAUTH, UNAUTH] },
    // ── arrangement writes (target: a document owned by `owner`) ──
    Row { op: "insert",               expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTH, UNAUTH] },
    Row { op: "delete",               expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTH, UNAUTH] },
    Row { op: "rearrange",            expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTH, UNAUTH] },
    Row { op: "copy (foreign dest)",  expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTH, UNAUTH] },
    Row { op: "copy (foreign source)",expect: [OK, OK,             OK,             OK,               UNAUTH, UNAUTH] },
    Row { op: "version (foreign src)",expect: [OK, OK,             OK,             OK,               UNAUTH, UNAUTH] },
    // ── link writes (home: a document owned by `owner`) ──
    Row { op: "make_link",            expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTH, UNAUTH] },
    Row { op: "emit",                 expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTH, UNAUTH] },
    Row { op: "assert_sup",           expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTH, UNAUTH] },
    Row { op: "nullify (home)",       expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTH, UNAUTH] },
    Row { op: "nullify (target)",     expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTH, UNAUTH] },
    Row { op: "edit_link (d_s)",      expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTH, UNAUTH] },
    Row { op: "edit_link (d_a)",      expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTH, UNAUTH] },
    Row { op: "edit_link (foreign original)",
                                      expect: [OK, OK,             OK,             OK,               UNAUTH, UNAUTH] },
];

// ── fixture plumbing ─────────────────────────────────────────────────────

/// Principal ids: fixed for the relationships, counter-fresh for delegate
/// cells. P is the parent, X the owner, S the sibling (same parent as X),
/// C the child (sub-delegated under X's account).
const P_PARENT: u64 = 20;
const P_OWNER: u64 = 21;
const P_SIBLING: u64 = 22;
const P_CHILD: u64 = 23;

/// Cross-walk counters: delegate cells consume fresh principal ids, node
/// cells fresh node ordinals, link cells fresh ghost-name ordinals.
struct Counters {
    principal: AtomicU64,
    node: AtomicU64,
    ghost: AtomicU64,
}

impl Counters {
    fn new() -> Counters {
        Counters {
            principal: AtomicU64::new(30),
            node: AtomicU64::new(40),
            ghost: AtomicU64::new(100),
        }
    }
    fn next(c: &AtomicU64) -> u64 {
        c.fetch_add(1, Ordering::Relaxed)
    }
}

/// The persistent fixture — addresses survive restarts; tokens do not.
struct Fx {
    acc_x: String,
    /// One document owned by each caller, indexed like the first four
    /// columns: [owner, sibling, child, parent].
    own_doc: [String; 4],
    insert_doc: String,
    delete_doc: String,
    rearr_doc: String,
    copy_dst: String,
    copy_src: String,
    /// Home of the anchor links and every link-write row.
    link_home: String,
    /// X's document probed as edit_link's foreign d_s / d_a.
    edit_home: String,
    /// Two resident X-owned links: sup endpoints and edit originals.
    /// Never nullified by any cell — the nullify rows mint fresh targets.
    anchor: [String; 2],
}

/// Per-life session tokens, [owner, sibling, child, parent] + bootstrap.
struct Toks {
    by_col: [String; 4],
    x: String,
}

fn open_toks(port: u16) -> Toks {
    Toks {
        by_col: [
            open_session(port, P_OWNER),
            open_session(port, P_SIBLING),
            open_session(port, P_CHILD),
            open_session(port, P_PARENT),
        ],
        x: open_session(port, P_OWNER),
    }
}

fn next_prefix(port: u16, parent: &str) -> String {
    let v = op(port, None, &format!(r#"{{"op":"next_account_prefix","parent":"{parent}"}}"#));
    expect_resp(&v, "maybe_addr")["addr"]
        .as_str()
        .unwrap_or_else(|| panic!("no delegable prefix under {parent}: {v}"))
        .to_string()
}

fn delegate(port: u16, session: &str, parent: &str, id: u64) -> String {
    let prefix = next_prefix(port, parent);
    let v = op(
        port,
        Some(session),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":{id}}}"#),
    );
    acked_addr(&v)
}

fn create_doc(port: u16, session: &str, account: &str) -> String {
    let v =
        op(port, Some(session), &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#));
    acked_addr(&v)
}

fn seed_text(port: u16, session: &str, doc: &str, text: &str) {
    let v = op(
        port,
        Some(session),
        &format!(
            r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"1"}},"values":["{text}"]}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
}

/// A unit-subtree width for an address: `0.….0.1` at its component count.
fn unit_w(addr: &str) -> String {
    let mut comps = vec!["0"; addr.split('.').count() - 1];
    comps.push("1");
    comps.join(".")
}

/// Mint an addrs-form link (empty from/to, fresh ghost type) in `home`.
fn mint_link(port: u16, session: &str, home: &str, n: &Counters) -> String {
    let ghost = format!("{home}.0.3.6.{}", Counters::next(&n.ghost));
    let v = op(
        port,
        Some(session),
        &format!(
            r#"{{"op":"make_link","home":"{home}","from":{{"addrs":[]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{ghost}"]}}}}"#
        ),
    );
    acked_addr(&v)
}

fn build_fixture(port: u16, boot: &str, toks: &Toks, n: &Counters) -> Fx {
    // Relationships: boot → P under node [1]; P → X and S under Ap
    // (siblings); X → C under Ax (sub-delegation).
    let acc_p = delegate(port, boot, "1", P_PARENT);
    let p = &toks.by_col[3];
    let acc_x = delegate(port, p, &acc_p, P_OWNER);
    let acc_s = delegate(port, p, &acc_p, P_SIBLING);
    let x = &toks.x;
    let acc_c = delegate(port, x, &acc_x, P_CHILD);

    let own_doc = [
        create_doc(port, x, &acc_x),
        create_doc(port, &toks.by_col[1], &acc_s),
        create_doc(port, &toks.by_col[2], &acc_c),
        create_doc(port, p, &acc_p),
    ];

    let insert_doc = create_doc(port, x, &acc_x);
    let delete_doc = create_doc(port, x, &acc_x);
    seed_text(port, x, &delete_doc, "abcdefgh");
    let rearr_doc = create_doc(port, x, &acc_x);
    seed_text(port, x, &rearr_doc, "abcdef");
    let copy_dst = create_doc(port, x, &acc_x);
    let copy_src = create_doc(port, x, &acc_x);
    seed_text(port, x, &copy_src, "source");
    let link_home = create_doc(port, x, &acc_x);
    let edit_home = create_doc(port, x, &acc_x);
    let anchor = [mint_link(port, x, &link_home, n), mint_link(port, x, &link_home, n)];

    Fx {
        acc_x,
        own_doc,
        insert_doc,
        delete_doc,
        rearr_doc,
        copy_dst,
        copy_src,
        link_home,
        edit_home,
        anchor,
    }
}

// ── the walk ─────────────────────────────────────────────────────────────

fn verdict(v: &Value) -> String {
    match v["resp"].as_str() {
        Some("ack") | Some("ack_addr") | Some("ack_edit") => OK.to_string(),
        Some("rejected") => v["code"].as_str().unwrap_or("?").to_string(),
        other => format!("resp:{other:?}"),
    }
}

/// One cell: build the row's frame for this caller (minting per-cell fresh
/// resources where the row consumes them), send it, return the verdict.
fn run_cell(
    port: u16,
    fx: &Fx,
    toks: &Toks,
    stale: &str,
    n: &Counters,
    row: &str,
    col: usize,
) -> String {
    // The caller context: a session (or none), and a document the caller
    // owns. Guest and stale cells name X's resources — M10's session gate
    // fires before any store sees the frame.
    let token: Option<&str> = match col {
        0..=3 => Some(toks.by_col[col].as_str()),
        4 => None,
        _ => Some(stale),
    };
    let own_doc: &str = if col <= 3 { &fx.own_doc[col] } else { &fx.own_doc[0] };
    let authed = col <= 3;

    let frame = match row {
        "create_new_document" => {
            format!(r#"{{"op":"create_new_document","account":"{}"}}"#, fx.acc_x)
        }
        "delegate" => {
            let prefix = next_prefix(port, &fx.acc_x);
            let id = Counters::next(&n.principal);
            format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":{id}}}"#)
        }
        "register_node" => {
            format!(r#"{{"op":"register_node","addr":"1.{}"}}"#, Counters::next(&n.node))
        }
        "fork" => r#"{"op":"fork"}"#.to_string(),
        "insert" => format!(
            r#"{{"op":"insert","doc":"{}","at":{{"subspace":"1","ordinal":"1"}},"values":["z"]}}"#,
            fx.insert_doc
        ),
        "delete" => format!(
            r#"{{"op":"delete","doc":"{}","p":{{"subspace":"1","ordinal":"1"}},"width":"1"}}"#,
            fx.delete_doc
        ),
        "rearrange" => format!(
            r#"{{"op":"rearrange","doc":"{}","cuts":[{{"subspace":"1","ordinal":"1"}},{{"subspace":"1","ordinal":"2"}},{{"subspace":"1","ordinal":"3"}}]}}"#,
            fx.rearr_doc
        ),
        "copy (foreign dest)" => format!(
            r#"{{"op":"copy","doc":"{}","at":{{"subspace":"1","ordinal":"1"}},"specs":[{{"source":"{}","span":{{"start":"1.1","width":"0.2"}}}}]}}"#,
            fx.copy_dst, fx.copy_src
        ),
        "copy (foreign source)" => format!(
            r#"{{"op":"copy","doc":"{own_doc}","at":{{"subspace":"1","ordinal":"1"}},"specs":[{{"source":"{}","span":{{"start":"1.1","width":"0.2"}}}}]}}"#,
            fx.copy_src
        ),
        "version (foreign src)" => format!(r#"{{"op":"version","d_src":"{}"}}"#, fx.copy_src),
        "make_link" => {
            let ghost = format!("{}.0.3.6.{}", fx.link_home, Counters::next(&n.ghost));
            format!(
                r#"{{"op":"make_link","home":"{}","from":{{"addrs":[]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{ghost}"]}}}}"#,
                fx.link_home
            )
        }
        // A retired-class unary tuple over a ghost root: the one shipped
        // class the open `emit` surface may write under standard genesis
        // ([K_sup] and [R] are fenced). Same tuple every cell — the owner's
        // walk-2 re-emit dedups to the incumbent ack (idem⊤), still `ok`.
        "emit" => format!(
            r#"{{"op":"emit","home":"{home}","ty":[{{"start":"9.0.9.0.9.0.9.3","width":"0.0.0.0.0.0.0.1"}}],"from":"{home}.0.3.9.1","to":[]}}"#,
            home = fx.link_home
        ),
        "assert_sup" => format!(
            r#"{{"op":"assert_sup","home":"{}","old":"{}","new":"{}"}}"#,
            fx.link_home, fx.anchor[0], fx.anchor[1]
        ),
        "nullify (home)" => {
            // Isolate the HOME check: the target belongs to the caller
            // (minted per cell), so only ω(home) differs across columns.
            let target = if !authed {
                fx.anchor[0].clone() // never reached: unauthenticated first
            } else if col == 0 {
                mint_link(port, &toks.x, &fx.link_home, n)
            } else {
                mint_link(port, token.expect("authed"), own_doc, n)
            };
            format!(r#"{{"op":"nullify","home":"{}","target":"{target}"}}"#, fx.link_home)
        }
        "nullify (target)" => {
            // Isolate the TARGET check: the home is the caller's own; the
            // target is a fresh X-owned link (v1 self-retraction policy).
            let target =
                if authed { mint_link(port, &toks.x, &fx.link_home, n) } else { fx.anchor[0].clone() };
            format!(r#"{{"op":"nullify","home":"{own_doc}","target":"{target}"}}"#)
        }
        "edit_link (d_s)" => {
            let ghost = format!("{}.0.3.6.{}", fx.edit_home, Counters::next(&n.ghost));
            format!(
                r#"{{"op":"edit_link","original":"{}","d_s":"{}","d_a":"{own_doc}","successor":{{"from":[],"to":[],"ty":{{"addrs":["{ghost}"]}}}}}}"#,
                fx.anchor[0], fx.edit_home
            )
        }
        "edit_link (d_a)" => {
            let ghost = format!("{}.0.3.6.{}", fx.edit_home, Counters::next(&n.ghost));
            format!(
                r#"{{"op":"edit_link","original":"{}","d_s":"{own_doc}","d_a":"{}","successor":{{"from":[],"to":[],"ty":{{"addrs":["{ghost}"]}}}}}}"#,
                fx.anchor[0], fx.edit_home
            )
        }
        "edit_link (foreign original)" => {
            let ghost = format!("{}.0.3.6.{}", fx.edit_home, Counters::next(&n.ghost));
            format!(
                r#"{{"op":"edit_link","original":"{}","d_s":"{own_doc}","d_a":"{own_doc}","successor":{{"from":[],"to":[],"ty":{{"addrs":["{ghost}"]}}}}}}"#,
                fx.anchor[1]
            )
        }
        other => panic!("matrix row with no frame builder: {other}"),
    };

    verdict(&op(port, token, &frame))
}

/// Walk every cell; collect mismatches so one report names them all.
fn walk_matrix(port: u16, fx: &Fx, toks: &Toks, stale: &str, n: &Counters, walk: &str) {
    let mut mismatches: Vec<String> = Vec::new();
    let mut cells = 0usize;
    for row in MATRIX {
        for (col, expected) in row.expect.iter().enumerate() {
            let got = run_cell(port, fx, toks, stale, n, row.op, col);
            cells += 1;
            if got != *expected {
                mismatches.push(format!(
                    "  row={:<28} col={:<16} expected={expected} got={got}",
                    row.op, COLS[col]
                ));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "FINDING ({walk}): {} of {cells} authorization cells diverge from the contract table \
         (an intended change here is a reviewed authorization change):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    println!("{walk}: {} rows × {} columns = {cells} cells, all verdicts match", MATRIX.len(), COLS.len());
}

// ── the tests ────────────────────────────────────────────────────────────

/// The matrix, walked twice around a restart. Life 0 exists only to mint a
/// token whose daemon lifetime has ended (the stale column's material);
/// life 1 builds the fixture and walks; life 2 rebinds fresh sessions on
/// the recovered world and re-walks — authorization must derive from the
/// registry, not from session state.
#[test]
fn authorization_matrix_holds_and_survives_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let n = Counters::new();

    // Life 0: mint the first stale token (bound to the future owner id).
    let stale0 = {
        let sd = spawn(dir.path());
        let tok = open_session(sd.port(), P_OWNER);
        sd.shutdown();
        tok
    };

    // Life 1: fixture + first walk.
    let (fx, stale1) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let boot = open_session(port, 0);
        let toks = open_toks(port);
        let fx = build_fixture(port, &boot, &toks, &n);
        walk_matrix(port, &fx, &toks, &stale0, &n, "walk 1");
        let stale1 = toks.x.clone();
        sd.shutdown();
        (fx, stale1)
    };

    // Life 2: recovery, fresh sessions, full re-walk. The stale column now
    // carries life 1's owner token — once the legitimate owner, now dead.
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let toks = open_toks(port);
        walk_matrix(port, &fx, &toks, &stale1, &n, "walk 2 (post-restart)");
        sd.shutdown();
    }
}

/// Session-shaped abuse of the idempotency hint, beyond the matrix: the
/// cache is keyed `(SessionId, ReqId)` and op-kind-matched, so a replayed
/// or guessed id on ANOTHER session must miss — re-execute or reject on its
/// own merits, never replay (or leak) the original ack. And the cache dies
/// with the process: a post-restart retry re-executes (duplicate by
/// design).
#[test]
fn idempotency_confinement_probing_and_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let boot = open_session(port, 0);
    let acc_a = delegate(port, &boot, "1", 1);
    let acc_b = delegate(port, &boot, "1", 2);
    let a1 = open_session(port, 1);
    let a2 = open_session(port, 1); // same principal, DIFFERENT session
    let b = open_session(port, 2);

    // The committed write whose ack the cache holds.
    let frame_a = format!(r#"{{"op":"create_new_document","account":"{acc_a}","id":"k1"}}"#);
    let (st, ack1) = http(port, "POST", "/op", Some(&a1), frame_a.as_bytes());
    assert_eq!(st, 200);
    let addr1 = acked_addr(&json(&ack1));

    // Baseline: the same session replays the identical ack, byte-equal.
    let (_, replay) = http(port, "POST", "/op", Some(&a1), frame_a.as_bytes());
    assert_eq!(ack1, replay, "same-session same-id retry must replay the identical ack");

    // Same principal, different session: MISS — re-executes, minting a
    // fresh document (never A's cached ack).
    let v = op(port, Some(&a2), &frame_a);
    let addr2 = acked_addr(&v);
    assert_ne!(
        addr1, addr2,
        "a same-principal replay on a different session must miss the cache and re-execute"
    );

    // Different principal, same frame + id: MISS — rejected on its own
    // merits (B does not own A's account), never A's ack.
    let v = op(port, Some(&b), &frame_a);
    let rej = expect_resp(&v, "rejected");
    assert_eq!(
        rej["code"].as_str(),
        Some("not_owner"),
        "a foreign-principal replay must be judged on its own merits: {v}"
    );

    // Id probing: B reuses A's id on its OWN frame — a fresh execute (its
    // own document), never a leak of A's cached ack.
    let frame_b = format!(r#"{{"op":"create_new_document","account":"{acc_b}","id":"k1"}}"#);
    let v = op(port, Some(&b), &frame_b);
    let addr_b = acked_addr(&v);
    assert_ne!(addr1, addr_b, "a guessed id must not retrieve another session's ack");

    // An id reused across op-kinds misses: fork under A's create id
    // executes fork, not the cached create.
    let v = op(port, Some(&a1), r#"{"op":"fork","id":"k1"}"#);
    let addr_f = acked_addr(&v);
    assert_ne!(addr1, addr_f, "an id reused across op-kinds must re-execute");

    // Rejections are never memoized: after a rejected write under an id,
    // the same id executes the next (valid) request normally.
    let frame_r = format!(r#"{{"op":"create_new_document","account":"{acc_a}","id":"kr"}}"#);
    expect_resp(&op(port, Some(&b), &frame_r), "rejected");
    let frame_r_own = format!(r#"{{"op":"create_new_document","account":"{acc_b}","id":"kr"}}"#);
    expect_resp(&op(port, Some(&b), &frame_r_own), "ack_addr");

    sd.shutdown();

    // Restart: the cache is process-lifetime. A retry of the original
    // (frame, id) under a fresh session re-executes — a duplicate document,
    // by design (wire.md §Correlation and idempotency).
    let sd = spawn(dir.path());
    let port = sd.port();
    let a_new = open_session(port, 1);
    let v = op(port, Some(&a_new), &frame_a);
    let addr_dup = acked_addr(&v);
    assert_ne!(
        addr1, addr_dup,
        "a post-restart retry must re-execute (the idempotency hint does not survive restart)"
    );
    sd.shutdown();
}
