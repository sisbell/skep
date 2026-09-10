//! The change feed's publication half (wire v7.8; PUB round 2, lane 3.6):
//! `/changes` masked per class with `docs` reduced, the supplement merged
//! from the grant fold, the universal term derived at serve, the `under=`
//! narrowing and the drafts-only form — pinned by THE FEED-CLASS ORACLE
//! (PUB-6.59): for each class, every page equals the position walk over
//! `(since, head]` with `readable()` applied per entry and `docs` reduced,
//! masked entries omitted, `limit`/`last`/`more` over the visible stream
//! (PUB-6.44). The walk is kept HERE, test-side, over the fixture's own
//! statement of what it wrote (the `docs` convention of wire.md §The change
//! feed) with `readable()` read off the wire's own doc-argument row (a
//! `doc_metadata` that answers `withheld` is an unreadable document,
//! PUB-6.1) — never a serving path.
//!
//! The board (PUB-6.59's own list): drafts of THREE accounts in a chain (A,
//! A.1 under A, A.1.1 under A.1 — the subtree clause reads upward), a NAMED
//! grant (A's draft D1 to a stranger B), an ANY-PRINCIPAL grant (A's D2),
//! straddling `nullify` and `edit_link` entries (a draft-homed record
//! against A's public doc 1), and a masked run three draft writes long with
//! a page boundary inside it. The classes: the GUEST, the OWNER (A), the
//! SUBTREE reader (A.1.1), the GRANT-HOLDER (B), and a NON-ENTITLED
//! principal (C).
//!
//! Beside the oracle, the cells of the lane's §7: the guest page never
//! short of `limit` before head; the straddle renderings (PUB-6.46); the
//! universal term appearing on a stranger's page and leaving it on the
//! next page after a revocation, no restart (PUB-7.23); `under=` equal to
//! the oracle's filtered walk and EMPTY for a guest at a draft; the
//! sidecars' recovery (PUB-7.21 — each derived file deleted or torn in
//! turn, every page byte-equal after reopen; every file deleted at once,
//! every class's visible positions unchanged, the bare entries classified
//! from the journal); two daemons over one journal answering byte-equal
//! pages per class (PUB-8.26); and `/events` unchanged across classes on a
//! board with masked commits (PUB-8.14, PUB-6.58's H1 row).

use crate::common;

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use common::*;
use serde_json::Value;

/// One write the fixture made, as the `docs` convention states it.
#[derive(Clone, Debug)]
struct Entry {
    at: u64,
    op: &'static str,
    docs: Vec<String>,
}

/// One reader class: its label, and the token it reads with (`None` = the
/// guest).
struct Class {
    label: &'static str,
    token: Option<String>,
}

/// The board, its sessions, its addresses, and the fixture's own log of
/// every write past the claim ceremony.
struct Board {
    port: u16,
    since0: u64,
    log: Vec<Entry>,
    drafts: BTreeSet<String>,
    // sessions
    a: String,
    a_signed: String,
    a11: String,
    b: String,
    c: String,
    // addresses
    a_acct: String,
    a_doc1: String,
    c_acct: String,
    d1: String,
    d2: String,
    d3: String,
    a1_acct: String,
    g_any: String,
}

fn head(port: u16) -> u64 {
    json(&get(port, "/health").1)["log_position"].as_u64().expect("log_position")
}

fn next_prefix(port: u16, token: &str, parent: &str) -> String {
    let v = op(port, Some(token), &format!(r#"{{"op":"next_account_prefix","parent":"{parent}"}}"#));
    expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string()
}

/// One write, its ack, and the fixture's entry for it: `docs` as named, or
/// the minted address off the ack.
fn write(
    log: &mut Vec<Entry>,
    port: u16,
    token: &str,
    op_name: &'static str,
    frame: &str,
    docs: Option<Vec<String>>,
) -> String {
    let v = op(port, Some(token), frame);
    let at = v["at"].as_u64().unwrap_or_else(|| panic!("{op_name} must commit: {v}"));
    let addr = v["addr"].as_str().map(str::to_string).unwrap_or_default();
    let docs = docs.unwrap_or_else(|| vec![addr.clone()]);
    log.push(Entry { at, op: op_name, docs });
    addr
}

/// A bare mint into `account` by `token`; `None` docs ⇒ the minted address.
fn mint(log: &mut Vec<Entry>, port: u16, token: &str, account: &str) -> String {
    write(
        log,
        port,
        token,
        "create_new_document",
        &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
        None,
    )
}

/// A one-byte insert at content ordinal 1 of `doc` (a prepend, so every
/// ordinal is in bounds whatever the draft holds).
fn insert(log: &mut Vec<Entry>, port: u16, token: &str, doc: &str, text: &str) {
    write(
        log,
        port,
        token,
        "insert",
        &format!(
            r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"1"}},"values":["{text}"]}}"#
        ),
        Some(vec![doc.to_string()]),
    );
}

/// A ghost-typed link in `home` (address-form slots, no resolution).
fn ghost_link(log: &mut Vec<Entry>, port: u16, token: &str, home: &str, n: u64) -> String {
    write(
        log,
        port,
        token,
        "make_link",
        &format!(
            r#"{{"op":"make_link","home":"{home}","from":{{"addrs":[]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{home}.0.3.6.{n}"]}}}}"#
        ),
        Some(vec![home.to_string()]),
    )
}

/// A grant link in `home_doc1` (the issuer's doc 1), from the issuer's
/// signed session: `from` the content prefix (or an earlier grant's own
/// address — a revocation), `to` the grantee, or empty for ANY-PRINCIPAL.
fn grant(
    log: &mut Vec<Entry>,
    port: u16,
    signed: &str,
    home_doc1: &str,
    from: &str,
    grantee: Option<&str>,
) -> String {
    let to = match grantee {
        Some(g) => format!(r#"{{"addrs":["{g}"]}}"#),
        None => r#"{"addrs":[]}"#.to_string(),
    };
    write(
        log,
        port,
        signed,
        "make_link",
        &format!(
            r#"{{"op":"make_link","home":"{home_doc1}","from":{{"addrs":["{from}"]}},"to":{to},"ty":{{"addrs":["{T_GRANT}"]}}}}"#
        ),
        Some(vec![home_doc1.to_string()]),
    )
}

/// THE HIRE (the `common::hire` walk, with its two writes logged): the
/// agent's genesis enrollment into the CLAIMANT's doc 1 — a declared
/// deposit of the enroll atom, then the enroll-typed link — from the
/// claimant's signed session; returns the agent's signed session.
fn hire_logged(
    log: &mut Vec<Entry>,
    port: u16,
    claimant_signed: &str,
    agent_account: &str,
    agent_id: u64,
    key: &ed25519_dalek::SigningKey,
) -> String {
    let ordinal = next_content_ordinal(port, Some(claimant_signed), CLAIMANT_DOC1);
    let atom = write(
        log,
        port,
        claimant_signed,
        "insert",
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{}}}],"deposit":true}}"#,
            enroll_atom(&[key])
        ),
        Some(vec![CLAIMANT_DOC1.to_string()]),
    );
    write(
        log,
        port,
        claimant_signed,
        "make_link",
        &format!(
            r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":["{atom}"]}},"to":{{"addrs":["{agent_account}"]}},"ty":{{"addrs":["{T_ENROLL}"]}}}}"#
        ),
        Some(vec![CLAIMANT_DOC1.to_string()]),
    );
    open_signed_session(port, agent_id, key)
}

/// Build the board on an already-spawned, claimed daemon.
fn build(port: u16) -> Board {
    let since0 = head(port);
    let mut log = Vec::new();
    let mut drafts = BTreeSet::new();
    let boot = open_session(port, 0);
    let claimant_signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    // A — principal 1 at the next top-level prefix; keyed, so it can write
    // into its published doc 1.
    let a_acct = next_prefix(port, &boot, "1");
    assert_eq!(a_acct, "1.0.2", "the ceremony holds 1.0.1; re-pin the fixture");
    write(
        &mut log,
        port,
        &boot,
        "delegate",
        &format!(r#"{{"op":"delegate","new_prefix":"{a_acct}","new_id":1}}"#),
        Some(vec![]),
    );
    let a = open_session(port, 1);
    let a_doc1 = mint(&mut log, port, &a, &a_acct);
    assert_eq!(a_doc1, "1.0.2.0.1");
    let a_signed = hire_logged(&mut log, port, &claimant_signed, &a_acct, 1, &distinct_key(1));
    let d1 = mint(&mut log, port, &a, &a_acct);
    let d2 = mint(&mut log, port, &a, &a_acct);
    let d3 = mint(&mut log, port, &a, &a_acct);
    drafts.extend([d1.clone(), d2.clone(), d3.clone()]);

    // A.1 — principal 2, delegated by A beneath A's account.
    let a1_acct = next_prefix(port, &a, &a_acct);
    assert_eq!(a1_acct, "1.0.2.1", "A's first sub-account");
    write(
        &mut log,
        port,
        &a,
        "delegate",
        &format!(r#"{{"op":"delegate","new_prefix":"{a1_acct}","new_id":2}}"#),
        Some(vec![]),
    );
    let a1 = open_session(port, 2);
    let _a1_doc1 = mint(&mut log, port, &a1, &a1_acct);
    let e1 = mint(&mut log, port, &a1, &a1_acct);
    drafts.insert(e1.clone());

    // A.1.1 — principal 3, delegated by A.1.
    let a11_acct = next_prefix(port, &a1, &a1_acct);
    assert_eq!(a11_acct, "1.0.2.1.1");
    write(
        &mut log,
        port,
        &a1,
        "delegate",
        &format!(r#"{{"op":"delegate","new_prefix":"{a11_acct}","new_id":3}}"#),
        Some(vec![]),
    );
    let a11 = open_session(port, 3);
    let _a11_doc1 = mint(&mut log, port, &a11, &a11_acct);
    let f1 = mint(&mut log, port, &a11, &a11_acct);
    drafts.insert(f1.clone());

    // B — principal 4, a stranger, the grant-holder to be.
    let b_acct = next_prefix(port, &boot, "1");
    assert_eq!(b_acct, "1.0.3");
    write(
        &mut log,
        port,
        &boot,
        "delegate",
        &format!(r#"{{"op":"delegate","new_prefix":"{b_acct}","new_id":4}}"#),
        Some(vec![]),
    );
    let b = open_session(port, 4);
    let _b_doc1 = mint(&mut log, port, &b, &b_acct);
    let g1 = mint(&mut log, port, &b, &b_acct);
    drafts.insert(g1.clone());

    // C — principal 5, a stranger with no grant.
    let c_acct = next_prefix(port, &boot, "1");
    assert_eq!(c_acct, "1.0.4");
    write(
        &mut log,
        port,
        &boot,
        "delegate",
        &format!(r#"{{"op":"delegate","new_prefix":"{c_acct}","new_id":5}}"#),
        Some(vec![]),
    );
    let c = open_session(port, 5);
    let _c_doc1 = mint(&mut log, port, &c, &c_acct);

    // Three public links in A's doc 1 (the straddles' targets).
    let l1 = ghost_link(&mut log, port, &a_signed, &a_doc1, 1);
    let l2 = ghost_link(&mut log, port, &a_signed, &a_doc1, 2);
    let l3 = ghost_link(&mut log, port, &a_signed, &a_doc1, 3);

    // The grants: D1 to B by name; D2 to ANY-PRINCIPAL.
    grant(&mut log, port, &a_signed, &a_doc1, &d1, Some(&b_acct));
    let g_any = grant(&mut log, port, &a_signed, &a_doc1, &d2, None);

    // The draft writes: a masked run of three into D1 (B reads it by
    // grant), two into D2 (every principal, by the universal grant), one
    // into D3 (A's subtree alone), and one apiece into the chain's and the
    // strangers' drafts.
    for t in ["p", "q", "r"] {
        insert(&mut log, port, &a, &d1, t);
    }
    insert(&mut log, port, &a, &d2, "u");
    insert(&mut log, port, &a, &d2, "v");
    insert(&mut log, port, &a, &d3, "w");
    insert(&mut log, port, &a1, &e1, "e");
    insert(&mut log, port, &a11, &f1, "f");
    insert(&mut log, port, &b, &g1, "g");

    // The straddles (PUB-6.46, PUB-6.47): a draft-homed nullify of a public
    // link; the same-home retraction beside it; an edit_link with d_s
    // public and d_a a draft.
    write(
        &mut log,
        port,
        &a_signed,
        "nullify",
        &format!(r#"{{"op":"nullify","home":"{d1}","target":"{l1}"}}"#),
        Some(vec![d1.clone(), a_doc1.clone()]),
    );
    write(
        &mut log,
        port,
        &a_signed,
        "nullify",
        &format!(r#"{{"op":"nullify","home":"{a_doc1}","target":"{l2}"}}"#),
        Some(vec![a_doc1.clone()]),
    );
    write(
        &mut log,
        port,
        &a_signed,
        "edit_link",
        &format!(
            r#"{{"op":"edit_link","original":"{l3}","d_s":"{a_doc1}","d_a":"{d1}","successor":{{"from":[],"to":[],"ty":{{"addrs":["{a_doc1}.0.3.6.9"]}}}}}}"#
        ),
        Some(vec![a_doc1.clone(), d1.clone()]),
    );

    // A tail past the straddles: one more draft write, and a declared
    // deposit into A's published doc 1 (visible to all).
    insert(&mut log, port, &a, &d1, "s");
    let ordinal = next_content_ordinal(port, Some(&a_signed), &a_doc1);
    write(
        &mut log,
        port,
        &a_signed,
        "insert",
        &format!(
            r#"{{"op":"insert","doc":"{a_doc1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":["z"],"deposit":true}}"#
        ),
        Some(vec![a_doc1.clone()]),
    );

    assert!(log.windows(2).all(|w| w[0].at < w[1].at), "the log is position-ordered");
    Board {
        port,
        since0,
        log,
        drafts,
        a,
        a_signed,
        a11,
        b,
        c,
        a_acct,
        a_doc1,
        c_acct,
        d1,
        d2,
        d3,
        a1_acct,
        g_any,
    }
}

impl Board {
    fn classes(&self) -> Vec<Class> {
        vec![
            Class { label: "guest", token: None },
            Class { label: "owner A", token: Some(self.a.clone()) },
            Class { label: "subtree A.1.1", token: Some(self.a11.clone()) },
            Class { label: "grant-holder B", token: Some(self.b.clone()) },
            Class { label: "non-entitled C", token: Some(self.c.clone()) },
        ]
    }
}

/// `readable(class, doc)` off the wire's own doc-argument row (PUB-6.1): a
/// `doc_metadata` answering `withheld` is an unreadable document, and one
/// answering the read is readable. Memoized per (class, doc).
struct Readable<'a> {
    port: u16,
    token: Option<&'a str>,
    memo: HashMap<String, bool>,
}

impl<'a> Readable<'a> {
    fn new(port: u16, token: Option<&'a str>) -> Readable<'a> {
        Readable { port, token, memo: HashMap::new() }
    }

    fn ask(&mut self, doc: &str) -> bool {
        if let Some(&r) = self.memo.get(doc) {
            return r;
        }
        let v = op(self.port, self.token, &format!(r#"{{"op":"doc_metadata","doc":"{doc}"}}"#));
        let r = match v["resp"].as_str() {
            Some("doc_metadata") => true,
            Some("rejected") if v["code"].as_str() == Some("withheld") => false,
            _ => panic!("doc_metadata on {doc}: an existence answer, never anything else: {v}"),
        };
        self.memo.insert(doc.to_string(), r);
        r
    }
}

/// One narrowing of the feed.
#[derive(Clone, Copy, Debug)]
struct Narrowing<'a> {
    under: Option<&'a str>,
    drafts: bool,
}

fn under_prefix(prefix: &str, doc: &str) -> bool {
    doc == prefix || doc.starts_with(&format!("{prefix}."))
}

/// THE ORACLE (PUB-6.59): the position walk over `(since, head]` with
/// `readable()` per entry and `docs` reduced, masked entries omitted, the
/// narrowings' predicates applied to the walk, then `limit`/`last`/`more`
/// over the visible stream. Returns `(entries as (at, op, docs), last, more)`.
fn expected(
    log: &[Entry],
    drafts: &BTreeSet<String>,
    readable: &mut Readable<'_>,
    since: u64,
    limit: usize,
    n: Narrowing<'_>,
) -> (Vec<(u64, String, Vec<String>)>, u64, bool) {
    let mut visible = Vec::new();
    for e in log.iter().filter(|e| e.at > since) {
        let reduced: Vec<String> = e.docs.iter().filter(|d| readable.ask(d)).cloned().collect();
        if !e.docs.is_empty() && reduced.is_empty() {
            continue; // masked
        }
        if let Some(u) = n.under {
            if !reduced.iter().any(|d| under_prefix(u, d)) {
                continue;
            }
        }
        if n.drafts && !reduced.iter().any(|d| drafts.contains(d)) {
            continue;
        }
        visible.push((e.at, e.op.to_string(), reduced));
    }
    let more = visible.len() > limit;
    visible.truncate(limit);
    let last = visible.last().map(|v| v.0).unwrap_or(since);
    (visible, last, more)
}

fn query(since: u64, limit: usize, n: Narrowing<'_>) -> String {
    let mut q = format!("since={since}&limit={limit}");
    if let Some(u) = n.under {
        q.push_str(&format!("&under={u}"));
    }
    if n.drafts {
        q.push_str("&drafts=true");
    }
    q
}

/// The live page, parsed to the oracle's shape.
fn actual(port: u16, token: Option<&str>, q: &str) -> (Vec<(u64, String, Vec<String>)>, u64, bool, Vec<u8>) {
    let (st, body) = http(port, "GET", &format!("/changes?{q}"), token, b"");
    assert_eq!(st, 200, "/changes?{q}: {}", String::from_utf8_lossy(&body));
    let v = json(&body);
    let entries = v["changes"]
        .as_array()
        .expect("changes")
        .iter()
        .map(|e| {
            let docs = e["docs"]
                .as_array()
                .map(|a| a.iter().map(|d| d.as_str().expect("doc").to_string()).collect())
                .unwrap_or_default();
            (e["at"].as_u64().expect("at"), e["op"].as_str().unwrap_or("").to_string(), docs)
        })
        .collect();
    (entries, v["last"].as_u64().expect("last"), v["more"].as_bool().expect("more"), body)
}

/// Every page of every class against the oracle, over the fences, limits
/// and narrowings given.
fn check_oracle(board: &Board, fences: &[u64], limits: &[usize], narrowings: &[Narrowing<'_>]) {
    for class in board.classes() {
        let mut readable = Readable::new(board.port, class.token.as_deref());
        for &since in fences {
            for &limit in limits {
                for &n in narrowings {
                    let q = query(since, limit, n);
                    let (want, want_last, want_more) =
                        expected(&board.log, &board.drafts, &mut readable, since, limit, n);
                    let (got, got_last, got_more, _) = actual(board.port, class.token.as_deref(), &q);
                    assert_eq!(got, want, "[{}] /changes?{q}: the page is the oracle's walk", class.label);
                    assert_eq!(
                        (got_last, got_more),
                        (want_last, want_more),
                        "[{}] /changes?{q}: last/more over the VISIBLE stream",
                        class.label
                    );
                }
            }
        }
    }
}

fn fences(board: &Board) -> Vec<u64> {
    let mut f = vec![board.since0];
    f.extend(board.log.iter().step_by(3).map(|e| e.at));
    let head = board.log.last().expect("writes").at;
    f.push(head - 1);
    f.push(head);
    f.sort_unstable();
    f.dedup();
    f
}

fn narrowings(board: &Board) -> Vec<Narrowing<'_>> {
    vec![
        Narrowing { under: None, drafts: false },
        Narrowing { under: Some(&board.a_acct), drafts: false },
        Narrowing { under: Some(&board.d1), drafts: false },
        Narrowing { under: Some(&board.a1_acct), drafts: false },
        Narrowing { under: Some(CLAIMANT_DOC1), drafts: false },
        Narrowing { under: None, drafts: true },
        Narrowing { under: Some(&board.a_acct), drafts: true },
        Narrowing { under: Some(&board.d1), drafts: true },
        Narrowing { under: Some(&board.d2), drafts: true },
    ]
}

/// The fixture's every entry, so a walk's claims are visible in a failure.
fn ats(entries: &[(u64, String, Vec<String>)]) -> Vec<u64> {
    entries.iter().map(|e| e.0).collect()
}

/// §7 items 1–5: the oracle over five classes, the guest's paging over a
/// masked run, the straddle renderings, the universal term with its
/// revocation, and the `under=` cells.
#[test]
fn every_page_of_every_class_is_the_oracle_s_walk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let mut board = build(port);

    // ── 1. THE ORACLE ──
    check_oracle(&board, &fences(&board), &[1, 3, 256], &narrowings(&board));

    // ── 2. PUB-6.44: the guest's page over the masked run of D1 writes is
    //    never short of `limit` before head, `last` a visible position. ──
    let run_start = board.log.iter().find(|e| e.op == "insert" && e.docs == [board.d1.clone()]).expect("the D1 run").at;
    let (page, last, more, _) = actual(port, None, &query(run_start - 1, 2, Narrowing { under: None, drafts: false }));
    assert_eq!(page.len(), 2, "a guest page of two over the masked run holds two visible entries: {:?}", ats(&page));
    assert!(page.iter().all(|e| e.0 > run_start), "…each past the run's start");
    assert_eq!(last, page[1].0, "and `last` is the second visible position");
    assert!(more, "with more visible entries past it");

    // ── 3. PUB-6.46: the straddles as the guest sees them — three
    //    consecutive entries of the log: the draft-homed nullify of a public
    //    link, the same-home retraction, the edit_link straddle. ──
    let i = board.log.iter().position(|e| e.op == "nullify" && e.docs.len() == 2).expect("the straddle");
    let (n1, n2, el) = (board.log[i].at, board.log[i + 1].at, board.log[i + 2].at);
    assert_eq!((board.log[i + 1].op, board.log[i + 2].op), ("nullify", "edit_link"));
    let (page, ..) = actual(port, None, &query(n1 - 1, 3, Narrowing { under: None, drafts: false }));
    assert_eq!(
        page,
        vec![
            (n1, "nullify".to_string(), vec![board.a_doc1.clone()]),
            (n2, "nullify".to_string(), vec![board.a_doc1.clone()]),
            (el, "edit_link".to_string(), vec![board.a_doc1.clone()]),
        ],
        "a draft-homed retraction of a public link shows as [T]; the same-home one reduces to [T] identically; edit_link straddles to [P]"
    );
    // …and as the owner: whole.
    let (page, ..) = actual(port, Some(&board.a), &query(n1 - 1, 1, Narrowing { under: None, drafts: false }));
    assert_eq!(page[0].2, vec![board.d1.clone(), board.a_doc1.clone()], "the owner sees [D, T], home first");

    // ── 5. `under=`: a guest's page under a draft is EMPTY; B's drafts-only
    //    page under D1 is the oracle's walk over D1 — its run, AND the two
    //    straddles that name D1 beside A's public doc 1 (PUB-7.31: an entry
    //    qualifies when its REDUCED docs name a document under the prefix,
    //    whatever else they name; a straddle homed or landing in D1 is D1's
    //    history as much as an insert is). ──
    let (page, last, more, _) = actual(port, None, &query(board.since0, 256, Narrowing { under: Some(&board.d1), drafts: false }));
    assert!(page.is_empty(), "a guest under a draft: {:?}", ats(&page));
    assert_eq!((last, more), (board.since0, false), "the fence echoed, nothing more");
    {
        let n = Narrowing { under: Some(&board.d1), drafts: true };
        let mut readable_b = Readable::new(port, Some(&board.b));
        let (want, want_last, want_more) =
            expected(&board.log, &board.drafts, &mut readable_b, board.since0, 256, n);
        let (page, last, more, _) = actual(port, Some(&board.b), &query(board.since0, 256, n));
        assert_eq!(
            (&page, last, more),
            (&want, want_last, want_more),
            "B's drafts-only page under D1 is the oracle's walk"
        );
        assert!(
            !page.is_empty() && page.iter().all(|e| e.2.contains(&board.d1)),
            "…every entry of it names D1: {page:?}"
        );
        assert!(
            page.iter().any(|e| e.2 == [board.d1.clone(), board.a_doc1.clone()])
                && page.iter().any(|e| e.2 == [board.a_doc1.clone(), board.d1.clone()]),
            "…the two straddles among them, each naming D1 beside A's public doc 1 in the record's own order: {page:?}"
        );
    }

    // ── 4. THE UNIVERSAL TERM: C, a stranger, sees D2's draft writes by the
    //    any-principal grant — on the plain page and the drafts-only form —
    //    and the guest never does. ──
    let d2_writes: Vec<u64> = board.log.iter().filter(|e| e.docs == [board.d2.clone()]).map(|e| e.at).collect();
    assert!(d2_writes.len() >= 2);
    for drafts in [false, true] {
        let (page, ..) = actual(port, Some(&board.c), &query(board.since0, 256, Narrowing { under: None, drafts }));
        for at in &d2_writes {
            assert!(ats(&page).contains(at), "C sees D2's write at {at} (drafts={drafts}): {:?}", ats(&page));
        }
    }
    let (page, ..) = actual(port, None, &query(board.since0, 256, Narrowing { under: None, drafts: false }));
    assert!(d2_writes.iter().all(|at| !ats(&page).contains(at)), "the guest never merges the universal term");
    // A superseding record revokes it: the NEXT page omits them, no restart
    // (PUB-7.23), and the oracle still holds for every class.
    let g_any = board.g_any.clone();
    let a_signed = board.a_signed.clone();
    let a_doc1 = board.a_doc1.clone();
    grant(&mut board.log, port, &a_signed, &a_doc1, &g_any, None);
    for drafts in [false, true] {
        let (page, ..) = actual(port, Some(&board.c), &query(board.since0, 256, Narrowing { under: None, drafts }));
        assert!(d2_writes.iter().all(|at| !ats(&page).contains(at)), "revoked: D2's writes leave C's page (drafts={drafts}): {:?}", ats(&page));
    }
    let (page, ..) = actual(port, Some(&board.a), &query(board.since0, 256, Narrowing { under: None, drafts: false }));
    assert!(d2_writes.iter().all(|at| ats(&page).contains(at)), "the owner still sees its own draft's writes");
    check_oracle(&board, &fences(&board), &[2, 256], &narrowings(&board));

    // ── 5. A grant at the ISSUER'S ACCOUNT DEPTH (PUB-7.25): the branch
    //    that merges the issuer's draft stream WHOLE, with no per-entry
    //    containment filter, so the MASK alone decides which of its
    //    positions the page carries. It is also the branch a granted union
    //    too large to walk per candidate takes, where the filter stands
    //    aside for the same reason — so the oracle over it is what says
    //    that standing aside moves no page. C, whose universal term was
    //    just revoked, now reads every draft of A's account by name. ──
    let a_acct = board.a_acct.clone();
    let c_acct = board.c_acct.clone();
    grant(&mut board.log, port, &a_signed, &a_doc1, &a_acct, Some(&c_acct));
    let (page, ..) = actual(port, Some(&board.c), &query(board.since0, 256, Narrowing { under: None, drafts: false }));
    assert!(
        d2_writes.iter().all(|at| ats(&page).contains(at)),
        "an account-depth grant reaches every draft under it, the revoked D2 included: {:?}",
        ats(&page)
    );
    check_oracle(&board, &fences(&board), &[2, 256], &narrowings(&board));

    sd.shutdown();
}

/// Every class's pages, for the byte comparisons below: a fresh session per
/// principal (tokens are uptime-scoped; the class is the principal's).
fn pages_per_class(port: u16, since0: u64, prefixes: &[&str]) -> Vec<(String, Vec<u8>)> {
    let sessions: Vec<(&str, Option<String>)> = vec![
        ("guest", None),
        ("A", Some(open_session(port, 1))),
        ("A.1.1", Some(open_session(port, 3))),
        ("B", Some(open_session(port, 4))),
        ("C", Some(open_session(port, 5))),
    ];
    let mut out = Vec::new();
    for (label, token) in &sessions {
        let mut queries = vec![
            format!("since={since0}"),
            format!("since={since0}&limit=2"),
            format!("since={}&limit=3", since0 + 20),
            format!("since={since0}&drafts=true"),
        ];
        for p in prefixes {
            queries.push(format!("since={since0}&under={p}"));
            queries.push(format!("since={since0}&under={p}&drafts=true"));
        }
        for q in queries {
            let (st, body) = http(port, "GET", &format!("/changes?{q}"), token.as_deref(), b"");
            assert_eq!(st, 200, "[{label}] /changes?{q}: {}", String::from_utf8_lossy(&body));
            out.push((format!("[{label}] {q}"), body));
        }
    }
    out
}

const DERIVED_FILES: [&str; 4] = ["feed-index.log", "feed-offsets.log", "feed-masked.log", "feed-streams.log"];

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("case dir");
    for e in std::fs::read_dir(src).expect("fixture dir lists") {
        let e = e.expect("dir entry");
        if e.file_type().expect("file type").is_file() {
            std::fs::copy(e.path(), dst.join(e.file_name())).expect("copy fixture file");
        }
    }
}

/// §7 items 6 and 7: the sidecars' recovery — each derived file deleted,
/// then torn, then all four deleted, then every feed file deleted; every
/// page of every class byte-equal (or, with the testimony gone, the same
/// visible POSITIONS per class, classified from the journal) — and two
/// daemons over one journal answering byte-equal pages per class.
#[test]
fn the_sidecars_recover_and_two_daemons_agree_per_class() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (since0, prefixes, before) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let board = build(port);
        let prefixes = vec![board.a_acct.clone(), board.d1.clone(), board.a1_acct.clone()];
        let ps: Vec<&str> = prefixes.iter().map(String::as_str).collect();
        let before = pages_per_class(port, board.since0, &ps);
        for f in DERIVED_FILES {
            assert!(dir.path().join(f).exists(), "{f} is written beside commits.log");
        }
        sd.shutdown();
        (board.since0, prefixes, before)
    };
    let ps: Vec<&str> = prefixes.iter().map(String::as_str).collect();
    let judge = |port: u16, ctx: &str| {
        let after = pages_per_class(port, since0, &ps);
        for ((label, want), (_, got)) in before.iter().zip(after.iter()) {
            assert_eq!(
                String::from_utf8_lossy(got),
                String::from_utf8_lossy(want),
                "{ctx}: {label} drifted"
            );
        }
    };

    // A clean reopen.
    {
        let sd = spawn(dir.path());
        judge(sd.port(), "clean reopen");
        sd.shutdown();
    }
    // Each derived file deleted in turn — rebuilt whole (PUB-7.21).
    for f in DERIVED_FILES {
        std::fs::remove_file(dir.path().join(f)).expect("delete");
        let sd = spawn(dir.path());
        judge(sd.port(), &format!("{f} deleted"));
        assert!(dir.path().join(f).exists(), "{f} is rebuilt on reopen");
        sd.shutdown();
    }
    // Each derived file's tail torn — re-derived at O(tail).
    for f in DERIVED_FILES {
        let path = dir.path().join(f);
        let len = std::fs::metadata(&path).expect("metadata").len();
        let fh = std::fs::OpenOptions::new().write(true).open(&path).expect("open");
        fh.set_len(len.saturating_sub(37)).expect("tear the tail");
        drop(fh);
        let sd = spawn(dir.path());
        judge(sd.port(), &format!("{f} torn"));
        sd.shutdown();
    }
    // All four at once.
    for f in DERIVED_FILES {
        std::fs::remove_file(dir.path().join(f)).expect("delete");
    }
    {
        let sd = spawn(dir.path());
        judge(sd.port(), "all four derived files deleted");
        sd.shutdown();
    }
    // Two daemons over one journal (PUB-8.26): a copy of the whole data
    // dir, opened beside the original, answers byte-equal pages per class.
    let twin = tempfile::tempdir().expect("tempdir");
    copy_dir(dir.path(), twin.path());
    {
        let sd = spawn(twin.path());
        judge(sd.port(), "a second daemon over a copy of the journal");
        sd.shutdown();
    }
    // Every feed file gone — the testimony too: every position comes back
    // BARE, classified from the journal, so each class's VISIBLE POSITIONS
    // are the ones it saw with the records (PUB-6.45: a lost sidecar never
    // unmasks a draft write — nor hides a public one). The one page shape
    // that does not follow is the plain `under=` narrowing: a published
    // document an arrangement write or a mint touched is not derivable from
    // the journal (no read enumerates them), so such an entry classifies
    // empty and is placed under no prefix — the silent incompleteness of
    // lost testimony (PUB-7.21), never a wrong answer. Drafts and link homes
    // ARE derived, so the drafts-only forms compare exactly.
    for f in DERIVED_FILES.iter().chain(["commits.log"].iter()) {
        std::fs::remove_file(dir.path().join(f)).expect("delete");
    }
    {
        let sd = spawn(dir.path());
        let after = pages_per_class(sd.port(), since0, &ps);
        for ((label, want), (_, got)) in before.iter().zip(after.iter()) {
            if label.contains("under=") && !label.contains("drafts=true") {
                continue;
            }
            let want = json(want);
            let got = json(got);
            let positions = |v: &Value| -> Vec<u64> {
                v["changes"].as_array().expect("changes").iter().map(|e| e["at"].as_u64().expect("at")).collect()
            };
            assert_eq!(positions(&got), positions(&want), "{label}: the visible positions, bare");
            assert_eq!((got["last"].as_u64(), got["more"].as_bool()), (want["last"].as_u64(), want["more"].as_bool()), "{label}: last/more");
            for e in got["changes"].as_array().expect("changes") {
                assert!(
                    e["op"].is_null()
                        && e["docs"].is_null()
                        && e["time"].is_null()
                        && e["key"].is_null(),
                    "{label}: a bare entry answers null in EVERY metadata field, `key` \
                     included — the null is reserved for LOST testimony, where \
                     `\"bare\"` would claim this write was unsigned: {e}"
                );
            }
        }
        sd.shutdown();
    }
}

/// The per-owner draft streams are ASCENDING however their file is
/// ordered. `feed-streams.log` is the one derived file whose replay builds
/// a position LIST by pushing, in the order the lines happen to sit, where
/// the index takes its order from a `BTreeMap` and the bitmap from a
/// `BTreeSet` — so the ordering the feed's fence rests on is the one thing
/// that file cannot itself establish. `at_or_above` is a `partition_point`,
/// which answers an arbitrary index on an unsorted slice: the positions a
/// supplement then yields are not the ones at or above `since`, so a page
/// can carry a position at or below the fence its client just sent.
///
/// The scramble is a REORDER and not a corruption — every line is intact,
/// so nothing is torn, nothing is foreign, and the coverage fence is a
/// maximum and does not move. A file this daemon wrote is in position
/// order; that is a fact about the writer, and this is what says the
/// reader does not depend on it.
#[test]
fn the_draft_streams_replay_ascending_whatever_order_their_file_holds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (since0, prefixes, before) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let board = build(port);
        let prefixes = vec![board.a_acct.clone(), board.d1.clone(), board.a1_acct.clone()];
        let ps: Vec<&str> = prefixes.iter().map(String::as_str).collect();
        let before = pages_per_class(port, board.since0, &ps);
        sd.shutdown();
        (board.since0, prefixes, before)
    };
    let ps: Vec<&str> = prefixes.iter().map(String::as_str).collect();

    let path = dir.path().join("feed-streams.log");
    let text = std::fs::read_to_string(&path).expect("read the streams file");
    let mut lines: Vec<&str> = text.lines().collect();
    assert!(lines.len() > 2, "the fixture must give this file several entries: {lines:?}");
    lines.reverse();
    std::fs::write(&path, format!("{}\n", lines.join("\n"))).expect("scramble the line order");

    let sd = spawn(dir.path());
    let after = pages_per_class(sd.port(), since0, &ps);
    for ((label, want), (_, got)) in before.iter().zip(after.iter()) {
        assert_eq!(
            String::from_utf8_lossy(got),
            String::from_utf8_lossy(want),
            "{label}: a reordered feed-streams.log moved a page"
        );
    }
    sd.shutdown();
}

/// §7 item 8 (PUB-8.14, PUB-6.58's /events row): the position stream is
/// identical across classes on a board with masked commits — a guest and
/// the draft's owner are told the same position for a draft write.
#[test]
fn the_event_stream_is_class_invariant_over_masked_commits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = build(port);

    let mut guest = Sse::connect(port);
    let (mut owner, _) = Sse::connect_with_token(port, &board.a);
    let (mut stranger, _) = Sse::connect_with_token(port, &board.c);
    let h = head(port);
    assert_eq!(guest.expect_commit(), h, "the guest's first event is the head");
    assert_eq!(owner.expect_commit(), h);
    assert_eq!(stranger.expect_commit(), h);

    // A masked commit — a write into A's draft D3, which C and the guest
    // cannot read — moves every stream to the same position.
    let v = op(
        port,
        Some(&board.a),
        &format!(
            r#"{{"op":"insert","doc":"{}","at":{{"subspace":"1","ordinal":"1"}},"values":["x"]}}"#,
            board.d3
        ),
    );
    let at = expect_resp(&v, "ack_addr")["at"].as_u64().expect("at");
    assert_eq!(guest.expect_commit(), at, "the guest is told the masked commit's position");
    assert_eq!(owner.expect_commit(), at);
    assert_eq!(stranger.expect_commit(), at);
    // …while the guest's feed omits the entry and the owner's carries it.
    let (page, ..) = actual(port, None, &query(at - 1, 1, Narrowing { under: None, drafts: false }));
    assert!(page.is_empty(), "masked for the guest: {page:?}");
    let (page, ..) = actual(port, Some(&board.a), &query(at - 1, 1, Narrowing { under: None, drafts: false }));
    assert_eq!(ats(&page), vec![at]);
    // `head_time` moves on the masked commit too (PUB-6.52's residue).
    assert!(!json(&get(port, "/health").1)["head_time"].is_null());

    sd.shutdown();
}
