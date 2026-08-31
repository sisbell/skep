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
//   * RES-26, the public-permanent gate: an account's doc 1 is born
//     published (rule 1's home-mint law), and a BARE owner write homed
//     there refuses `credential_refused signed_session_required` — the
//     publish row's owner cell. ω and M10 stand AHEAD of the gate, so the
//     foreign and guest cells keep their own verdicts. The success half —
//     the same write class from a SIGNED session — is asserted beside each
//     walk (`signed_owner_writes_doc1`): only the claimant's account holds
//     enrolled keys, so it is the account that can sign. Every OTHER row
//     runs against second, private mints, where bare sessions keep their
//     standing (CLAIMED-PERMISSIVE local trust).
// ═══════════════════════════════════════════════════════════════════════

/// Column order — indexes into every row's `expect` array.
const COLS: [&str; 6] =
    ["owner", "sibling", "child-of-owner", "parent-of-owner", "guest", "stale-token"];

const OK: &str = "ok";
const NOT_OWNER: &str = "not_owner";
const UNAUTHENTICATED: &str = "unauthenticated";
/// The RES-26 refusal, `code:detail` (the `auth_wire` convention).
const SIGNED_REQUIRED: &str = "credential_refused:signed_session_required";

struct Row {
    label: &'static str,
    expect: [&'static str; 6],
}

#[rustfmt::skip]
const MATRIX: &[Row] = &[
    // ── namespace writes ──                    owner sibling         child           parent            guest            stale
    Row { label: "create_new_document",   expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTHENTICATED, UNAUTHENTICATED] },
    Row { label: "delegate",              expect: [OK, "not_ancestor", "not_ancestor", "not_authorized", UNAUTHENTICATED, UNAUTHENTICATED] },
    Row { label: "register_node",         expect: [OK, OK,             OK,             OK,               UNAUTHENTICATED, UNAUTHENTICATED] },
    Row { label: "fork",                  expect: [OK, OK,             OK,             OK,               UNAUTHENTICATED, UNAUTHENTICATED] },
    // ── arrangement writes (target: a document owned by `owner`) ──
    Row { label: "insert",                expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTHENTICATED, UNAUTHENTICATED] },
    // ── the publish gate (RES-26): the same insert homed in the owner's
    //    PUBLISHED doc 1 — the one cell where the bare owner is refused ──
    Row { label: "insert (published doc 1)",
                                          expect: [SIGNED_REQUIRED,
                                                       NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTHENTICATED, UNAUTHENTICATED] },
    Row { label: "delete",                expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTHENTICATED, UNAUTHENTICATED] },
    Row { label: "rearrange",             expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTHENTICATED, UNAUTHENTICATED] },
    Row { label: "copy (foreign dest)",   expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTHENTICATED, UNAUTHENTICATED] },
    Row { label: "copy (foreign source)", expect: [OK, OK,             OK,             OK,               UNAUTHENTICATED, UNAUTHENTICATED] },
    Row { label: "version (foreign src)", expect: [OK, OK,             OK,             OK,               UNAUTHENTICATED, UNAUTHENTICATED] },
    // ── link writes (home: a document owned by `owner`) ──
    Row { label: "make_link",             expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTHENTICATED, UNAUTHENTICATED] },
    Row { label: "emit",                  expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTHENTICATED, UNAUTHENTICATED] },
    Row { label: "assert_sup",            expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTHENTICATED, UNAUTHENTICATED] },
    Row { label: "nullify (home)",        expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTHENTICATED, UNAUTHENTICATED] },
    Row { label: "nullify (target)",      expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTHENTICATED, UNAUTHENTICATED] },
    Row { label: "edit_link (d_s)",       expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTHENTICATED, UNAUTHENTICATED] },
    Row { label: "edit_link (d_a)",       expect: [OK, NOT_OWNER,      NOT_OWNER,      NOT_OWNER,        UNAUTHENTICATED, UNAUTHENTICATED] },
    Row { label: "edit_link (foreign original)",
                                          expect: [OK, OK,             OK,             OK,               UNAUTHENTICATED, UNAUTHENTICATED] },
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
struct Fixture {
    /// The owner's account — the one every `create_new_document` and
    /// `delegate` cell aims at, whoever the calling column is.
    owner_account: String,
    /// X's doc 1 — born PUBLISHED (RES-26's home-mint law) and never
    /// written by any cell: the publish row's target.
    pub_doc: String,
    /// One document owned by each caller, indexed like the first four
    /// columns: [owner, sibling, child, parent] — each a SECOND mint,
    /// born private, so the bare columns keep their standing.
    own_doc: [String; 4],
    insert_doc: String,
    delete_doc: String,
    rearrange_doc: String,
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

/// Per-life session tokens: one per matrix column — [owner, sibling,
/// child, parent] — plus a second owner session the fixture is built and
/// extended through. The bootstrap session is not here; it is opened
/// separately, for the one delegation that seats the parent.
struct Tokens {
    by_col: [String; 4],
    owner: String,
}

fn open_tokens(port: u16) -> Tokens {
    Tokens {
        by_col: [
            open_session(port, P_OWNER),
            open_session(port, P_SIBLING),
            open_session(port, P_CHILD),
            open_session(port, P_PARENT),
        ],
        owner: open_session(port, P_OWNER),
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

/// Mint an addrs-form link (empty from/to, fresh ghost type) in `home`.
fn mint_link(port: u16, session: &str, home: &str, counters: &Counters) -> String {
    let ghost = format!("{home}.0.3.6.{}", Counters::next(&counters.ghost));
    let v = op(
        port,
        Some(session),
        &format!(
            r#"{{"op":"make_link","home":"{home}","from":{{"addrs":[]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{ghost}"]}}}}"#
        ),
    );
    acked_addr(&v)
}

fn build_fixture(port: u16, boot: &str, tokens: &Tokens, counters: &Counters) -> Fixture {
    // Relationships: boot → P under node [1]; P → X and S under Ap
    // (siblings); X → C under Ax (sub-delegation).
    let acc_p = delegate(port, boot, "1", P_PARENT);
    let p = &tokens.by_col[3];
    let acc_x = delegate(port, p, &acc_p, P_OWNER);
    let acc_s = delegate(port, p, &acc_p, P_SIBLING);
    let x = &tokens.owner;
    let acc_c = delegate(port, x, &acc_x, P_CHILD);

    // MINT-FIRST (RES-26): each account's first mint is its doc 1, born
    // published under rule 1's home-mint law. X's is kept as the publish
    // row's target; every working document below is a second, private mint.
    let pub_doc = create_doc(port, x, &acc_x);
    create_doc(port, &tokens.by_col[1], &acc_s);
    create_doc(port, &tokens.by_col[2], &acc_c);
    create_doc(port, p, &acc_p);

    let own_doc = [
        create_doc(port, x, &acc_x),
        create_doc(port, &tokens.by_col[1], &acc_s),
        create_doc(port, &tokens.by_col[2], &acc_c),
        create_doc(port, p, &acc_p),
    ];

    let insert_doc = create_doc(port, x, &acc_x);
    let delete_doc = create_doc(port, x, &acc_x);
    seed_text(port, x, &delete_doc, "abcdefgh");
    let rearrange_doc = create_doc(port, x, &acc_x);
    seed_text(port, x, &rearrange_doc, "abcdef");
    let copy_dst = create_doc(port, x, &acc_x);
    let copy_src = create_doc(port, x, &acc_x);
    seed_text(port, x, &copy_src, "source");
    let link_home = create_doc(port, x, &acc_x);
    let edit_home = create_doc(port, x, &acc_x);
    let anchor = [mint_link(port, x, &link_home, counters), mint_link(port, x, &link_home, counters)];

    Fixture {
        owner_account: acc_x,
        pub_doc,
        own_doc,
        insert_doc,
        delete_doc,
        rearrange_doc,
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
        // The daemon-originated family carries its refusal token in
        // `detail`; the cell asserts both (`code:detail`, as `auth_wire`
        // spells it). Store rejections stand on the code alone.
        Some("rejected") => match (v["code"].as_str().unwrap_or("?"), v["detail"].as_str()) {
            ("credential_refused", Some(d)) => format!("credential_refused:{d}"),
            (code, _) => code.to_string(),
        },
        other => format!("resp:{other:?}"),
    }
}

/// One cell: build the row's frame for this caller (minting per-cell fresh
/// resources where the row consumes them), send it, return the verdict.
fn run_cell(
    port: u16,
    fixture: &Fixture,
    tokens: &Tokens,
    stale_token: &str,
    counters: &Counters,
    label: &str,
    col: usize,
) -> String {
    // The caller context: a session (or none), and a document the caller
    // owns. Guest and stale cells name X's resources — M10's session gate
    // fires before any store sees the frame.
    let token: Option<&str> = match col {
        0..=3 => Some(tokens.by_col[col].as_str()),
        4 => None,
        _ => Some(stale_token),
    };
    let own_doc: &str = if col <= 3 { &fixture.own_doc[col] } else { &fixture.own_doc[0] };
    let authed = col <= 3;

    let frame = match label {
        "create_new_document" => {
            format!(r#"{{"op":"create_new_document","account":"{}"}}"#, fixture.owner_account)
        }
        "delegate" => {
            let prefix = next_prefix(port, &fixture.owner_account);
            let id = Counters::next(&counters.principal);
            format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":{id}}}"#)
        }
        "register_node" => {
            format!(r#"{{"op":"register_node","addr":"1.{}"}}"#, Counters::next(&counters.node))
        }
        "fork" => r#"{"op":"fork"}"#.to_string(),
        "insert" => format!(
            r#"{{"op":"insert","doc":"{}","at":{{"subspace":"1","ordinal":"1"}},"values":["z"]}}"#,
            fixture.insert_doc
        ),
        "insert (published doc 1)" => format!(
            r#"{{"op":"insert","doc":"{}","at":{{"subspace":"1","ordinal":"1"}},"values":["z"]}}"#,
            fixture.pub_doc
        ),
        "delete" => format!(
            r#"{{"op":"delete","doc":"{}","p":{{"subspace":"1","ordinal":"1"}},"width":"1"}}"#,
            fixture.delete_doc
        ),
        "rearrange" => format!(
            r#"{{"op":"rearrange","doc":"{}","cuts":[{{"subspace":"1","ordinal":"1"}},{{"subspace":"1","ordinal":"2"}},{{"subspace":"1","ordinal":"3"}}]}}"#,
            fixture.rearrange_doc
        ),
        "copy (foreign dest)" => format!(
            r#"{{"op":"copy","doc":"{}","at":{{"subspace":"1","ordinal":"1"}},"specs":[{{"source":"{}","span":{{"start":"1.1","width":"0.2"}}}}]}}"#,
            fixture.copy_dst, fixture.copy_src
        ),
        "copy (foreign source)" => format!(
            r#"{{"op":"copy","doc":"{own_doc}","at":{{"subspace":"1","ordinal":"1"}},"specs":[{{"source":"{}","span":{{"start":"1.1","width":"0.2"}}}}]}}"#,
            fixture.copy_src
        ),
        "version (foreign src)" => format!(r#"{{"op":"version","d_src":"{}"}}"#, fixture.copy_src),
        "make_link" => {
            let ghost = format!("{}.0.3.6.{}", fixture.link_home, Counters::next(&counters.ghost));
            format!(
                r#"{{"op":"make_link","home":"{}","from":{{"addrs":[]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{ghost}"]}}}}"#,
                fixture.link_home
            )
        }
        // A retired-class unary tuple over a ghost root: the one shipped
        // class the open `emit` surface may write under standard genesis
        // ([K_sup] and [R] are fenced). Same tuple every cell — the owner's
        // walk-2 re-emit dedups to the incumbent ack (idem⊤), still `ok`.
        "emit" => format!(
            r#"{{"op":"emit","home":"{home}","ty":[{{"start":"1.1.0.1.0.1.0.1.3","width":"0.0.0.0.0.0.0.0.1"}}],"from":"{home}.0.3.9.1","to":[]}}"#,
            home = fixture.link_home
        ),
        "assert_sup" => format!(
            r#"{{"op":"assert_sup","home":"{}","old":"{}","new":"{}"}}"#,
            fixture.link_home, fixture.anchor[0], fixture.anchor[1]
        ),
        "nullify (home)" => {
            // Isolate the HOME check: the target belongs to the caller
            // (minted per cell), so only ω(home) differs across columns.
            let target = if !authed {
                fixture.anchor[0].clone() // never reached: unauthenticated first
            } else if col == 0 {
                mint_link(port, &tokens.owner, &fixture.link_home, counters)
            } else {
                mint_link(port, token.expect("authed"), own_doc, counters)
            };
            format!(r#"{{"op":"nullify","home":"{}","target":"{target}"}}"#, fixture.link_home)
        }
        "nullify (target)" => {
            // Isolate the TARGET check: the home is the caller's own; the
            // target is a fresh X-owned link (v1 self-retraction policy).
            let target =
                if authed { mint_link(port, &tokens.owner, &fixture.link_home, counters) } else { fixture.anchor[0].clone() };
            format!(r#"{{"op":"nullify","home":"{own_doc}","target":"{target}"}}"#)
        }
        "edit_link (d_s)" => {
            let ghost = format!("{}.0.3.6.{}", fixture.edit_home, Counters::next(&counters.ghost));
            format!(
                r#"{{"op":"edit_link","original":"{}","d_s":"{}","d_a":"{own_doc}","successor":{{"from":[],"to":[],"ty":{{"addrs":["{ghost}"]}}}}}}"#,
                fixture.anchor[0], fixture.edit_home
            )
        }
        "edit_link (d_a)" => {
            let ghost = format!("{}.0.3.6.{}", fixture.edit_home, Counters::next(&counters.ghost));
            format!(
                r#"{{"op":"edit_link","original":"{}","d_s":"{own_doc}","d_a":"{}","successor":{{"from":[],"to":[],"ty":{{"addrs":["{ghost}"]}}}}}}"#,
                fixture.anchor[0], fixture.edit_home
            )
        }
        "edit_link (foreign original)" => {
            let ghost = format!("{}.0.3.6.{}", fixture.edit_home, Counters::next(&counters.ghost));
            format!(
                r#"{{"op":"edit_link","original":"{}","d_s":"{own_doc}","d_a":"{own_doc}","successor":{{"from":[],"to":[],"ty":{{"addrs":["{ghost}"]}}}}}}"#,
                fixture.anchor[1]
            )
        }
        other => panic!("matrix row with no frame builder: {other}"),
    };

    verdict(&op(port, token, &frame))
}

/// Walk every cell; collect mismatches so one report names them all.
fn walk_matrix(
    port: u16,
    fixture: &Fixture,
    tokens: &Tokens,
    stale_token: &str,
    counters: &Counters,
    walk: &str,
) {
    let mut mismatches: Vec<String> = Vec::new();
    let mut cells = 0usize;
    for row in MATRIX {
        for (col, expected) in row.expect.iter().enumerate() {
            let got = run_cell(port, fixture, tokens, stale_token, counters, row.label, col);
            cells += 1;
            if got != *expected {
                mismatches.push(format!(
                    "  row={:<28} col={:<16} expected={expected} got={got}",
                    row.label, COLS[col]
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

/// The publish row's signed-session arm: the same write class the bare
/// owner cell refuses is ACCEPTED from a signed session. Asserted against
/// the claimant's own published home — the one account with enrolled keys
/// (the matrix principals hold none, which is exactly why their column is
/// the refusal). Walked each life: the enrollment derives from the
/// registry, so a post-restart handshake must still sign in and land.
fn signed_owner_writes_doc1(port: u16, walk: &str) {
    let frame = format!(
        r#"{{"op":"insert","doc":"{OWNER_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":["z"]}}"#
    );
    let bare = open_session(port, OWNER_PRINCIPAL);
    let v = op(port, Some(&bare), &frame);
    assert_eq!(
        verdict(&v),
        SIGNED_REQUIRED,
        "{walk}: the claimant's bare write into its published home: {v}"
    );
    let signed = open_signed_session(port, OWNER_PRINCIPAL, &device_key());
    let v = op(port, Some(&signed), &frame);
    assert_eq!(verdict(&v), OK, "{walk}: the same write, signed, lands: {v}");
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
    let counters = Counters::new();

    // Life 0: mint the first stale token (bound to the future owner id).
    let stale0 = {
        let sd = spawn(dir.path());
        let tok = open_session(sd.port(), P_OWNER);
        sd.shutdown();
        tok
    };

    // Life 1: fixture + first walk, then the publish row's signed arm.
    let (fixture, stale1) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let boot = open_session(port, 0);
        let tokens = open_tokens(port);
        let fixture = build_fixture(port, &boot, &tokens, &counters);
        walk_matrix(port, &fixture, &tokens, &stale0, &counters, "walk 1");
        signed_owner_writes_doc1(port, "walk 1");
        let stale1 = tokens.owner.clone();
        sd.shutdown();
        (fixture, stale1)
    };

    // Life 2: recovery, fresh sessions, full re-walk — the signed arm
    // included, on a handshake freshly bound against the recovered
    // registry. The stale column now carries life 1's owner token — once
    // the legitimate owner, now dead.
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let tokens = open_tokens(port);
        walk_matrix(port, &fixture, &tokens, &stale1, &counters, "walk 2 (post-restart)");
        signed_owner_writes_doc1(port, "walk 2 (post-restart)");
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
fn an_idempotency_id_is_keyed_by_session_and_op_kind_and_dies_with_the_process() {
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
