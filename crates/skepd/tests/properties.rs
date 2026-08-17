//! H4 — property-based op sequences (hardening ruling): random-but-valid
//! plans of FEBE operations against an in-process daemon over a temp store,
//! every op through the wire (`POST /op`), with invariant oracles checked at
//! sampled steps and always at sequence end.
//!
//! The generator draws abstract `P` plan items (small selectors and
//! fractions); the interpreter maps each item onto a CONCRETE valid op
//! against tracked shadow state (pool indices mod current pools, positions
//! mod current lengths), so every dispatched frame is valid by construction
//! and any rejection of a generated op is itself a finding. Ops whose
//! preconditions cannot be met yet degrade deterministically to a fallback
//! insert — a plan is total, which keeps proptest's shrinking meaningful.
//!
//! The oracles:
//!  1. Prefix-replay equivalence — the observe dump captured live at every
//!     k-th committed boundary must be byte-equal to `GET /dump?at=p` at
//!     sequence end (journal + fold + checkpoint + hints in one oracle).
//!  2. Permanence — every boundary's live `retrieve_v` bodies (the content
//!     bytes acked by then, including bytes later deleted) answer
//!     byte-identically via `POST /op-at` at sequence end and after
//!     restart: history never mutates, deletion only edits arrangements.
//!  3. Active ⊆ audit; retraction one-way — every created link stays
//!     `read_link`-resident forever (audit only grows); the per-link
//!     exact-type ftt probe (each generated link is typed by a globally
//!     unique ghost name) answers the link iff it is not nullified, and a
//!     nullified link never reappears.
//!  4. Arrangement consistency — `retrieve_doc_v_span_set`'s content width
//!     equals the shadow's position count (and the link-subspace width the
//!     seated `make_link` count); `retrieve_v` over the full content span
//!     returns exactly the shadow items, granularity intact.
//!  5. Authorization composition — sprinkled FORBIDDEN ops (foreign writes
//!     per the H1 table) reject with the table's code and move nothing:
//!     the log position is unchanged and every other oracle is untouched.
//!  6. Restart equivalence — reopen the same store: recovered head, head
//!     dump, a historical dump, a historical read, and the full doc/link
//!     oracle pass must all agree byte-for-byte with the pre-shutdown run.
//!
//! Budget: 24 sequences of 60–120 ops (`PROPS_EXHAUSTIVE=1` scales to 96 of
//! 120–240), designed to stay under ~90 s total. Failure seeds persist to
//! `proptest-regressions/` — commit them; they are pins.
//!
//! Finding protocol (H3/H2 discipline): a real violation becomes
//! `#[ignore = "FINDING-n: …"]` with the assertion INTACT and the shrunk
//! plan verbatim in the comment (it is the reproduction) — never weakened.

mod common;

use common::*;
use proptest::prelude::*;
use serde_json::{json, Value};

fn exhaustive() -> bool {
    std::env::var_os("PROPS_EXHAUSTIVE").is_some_and(|v| v == "1")
}

fn cases() -> u32 {
    if exhaustive() {
        96
    } else {
        24
    }
}

fn ops_len() -> std::ops::RangeInclusive<usize> {
    if exhaustive() {
        120..=240
    } else {
        60..=120
    }
}

/// Oracle cadence: dumps captured every CADENCE-th committed write, doc and
/// link oracles run every CADENCE-th op (and always at sequence end).
const CADENCE: usize = 10;

// ── the abstract plan ────────────────────────────────────────────────────

/// One planned op: selectors are interpreted modulo the CURRENT pools, so
/// every value is meaningful for every world state (shrink-stable).
#[derive(Clone, Debug)]
enum P {
    Insert { p: u8, d: u8, at: u16, s: u8, atom: bool },
    Delete { p: u8, d: u8, at: u16, w: u8 },
    Copy { p: u8, d: u8, at: u16, sd: u8, f: u16, w: u8 },
    Rearrange { p: u8, d: u8, a: u16, b: u16, c: u16 },
    Version { p: u8, sd: u8 },
    CreateDoc { p: u8 },
    MakeLink { p: u8, d: u8, resolve: bool, cty: bool, f: u16, w: u8 },
    Emit { p: u8, d: u8, root: u8 },
    AssertSup { p: u8, d: u8, x: u8, y: u8 },
    Nullify { p: u8, l: u8 },
    EditLink { p: u8, d: u8, l: u8, resolve: bool },
    IdemRetry,
    Forbidden { p: u8, kind: u8 },
}

fn plan_strategy() -> impl Strategy<Value = Vec<P>> {
    // Grouped (prop_oneof's TupleUnion caps at 10 arms); outer weights are
    // each group's summed inner weights, so the flat distribution is:
    // insert 6, delete 3, copy 3, rearrange 2, version 2, create 1,
    // make_link 4, emit 2, assert_sup 2, nullify 2, edit_link 2,
    // idem-retry 2, forbidden 2.
    let arrangement = prop_oneof![
        6 => (0..3u8, any::<u8>(), any::<u16>(), any::<u8>(), prop::bool::weighted(0.2))
            .prop_map(|(p, d, at, s, atom)| P::Insert { p, d, at, s, atom }),
        3 => (0..3u8, any::<u8>(), any::<u16>(), any::<u8>())
            .prop_map(|(p, d, at, w)| P::Delete { p, d, at, w }),
        3 => (0..3u8, any::<u8>(), any::<u16>(), any::<u8>(), any::<u16>(), any::<u8>())
            .prop_map(|(p, d, at, sd, f, w)| P::Copy { p, d, at, sd, f, w }),
        2 => (0..3u8, any::<u8>(), any::<u16>(), any::<u16>(), any::<u16>())
            .prop_map(|(p, d, a, b, c)| P::Rearrange { p, d, a, b, c }),
        2 => (0..3u8, any::<u8>()).prop_map(|(p, sd)| P::Version { p, sd }),
        1 => (0..3u8).prop_map(|p| P::CreateDoc { p }),
    ];
    let links = prop_oneof![
        4 => (0..3u8, any::<u8>(), any::<bool>(), prop::bool::weighted(0.25), any::<u16>(), any::<u8>())
            .prop_map(|(p, d, resolve, cty, f, w)| P::MakeLink { p, d, resolve, cty, f, w }),
        2 => (0..3u8, any::<u8>(), any::<u8>()).prop_map(|(p, d, root)| P::Emit { p, d, root }),
        2 => (0..3u8, any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(p, d, x, y)| P::AssertSup { p, d, x, y }),
        2 => (0..3u8, any::<u8>()).prop_map(|(p, l)| P::Nullify { p, l }),
        2 => (0..3u8, any::<u8>(), any::<u8>(), any::<bool>())
            .prop_map(|(p, d, l, resolve)| P::EditLink { p, d, l, resolve }),
    ];
    let meta = prop_oneof![
        2 => Just(P::IdemRetry),
        2 => (0..3u8, any::<u8>()).prop_map(|(p, kind)| P::Forbidden { p, kind }),
    ];
    let op = prop_oneof![17 => arrangement, 12 => links, 4 => meta];
    prop::collection::vec(op, ops_len())
}

// ── the shadow world ─────────────────────────────────────────────────────

/// One content position: a single byte (the substrate's text discipline) or
/// one composite value. ASCII-only alphabets keep every per-byte run valid
/// UTF-8, so the expected delivery rendering is exact.
#[derive(Clone)]
enum CItem {
    Byte(u8),
    Atom(Vec<u8>),
}

struct DocSh {
    addr: String,
    content: Vec<CItem>,
    /// Seated link count — `make_link` is the ONE seating write (managed
    /// tuples, retractions, sup claims, and edit successors are unseated).
    seats: u64,
    owner: usize,
}

struct LinkSh {
    addr: String,
    /// The globally unique ghost type name — the exact-ftt probe key.
    /// `None` for a content-resolved type slot (LM content typing): such a
    /// link gets the audit-residence probe only, since its type key is not
    /// a unique name.
    ty: Option<String>,
    home_doc: usize,
    owner: usize,
    nullified: bool,
}

struct Pr {
    token: String,
    account: String,
    docs: Vec<usize>,
    alphabet: &'static [u8],
}

struct World {
    prs: [Pr; 3],
    docs: Vec<DocSh>,
    links: Vec<LinkSh>,
}

struct Memo {
    frame: String,
    token: String,
    body: Vec<u8>,
}

struct Boundary {
    at: u64,
    /// `None` when built without the `observe` feature.
    dump: Option<Vec<u8>>,
    /// (frame, live response body) — replayed via `/op-at` later.
    reads: Vec<(String, Vec<u8>)>,
}

struct Rs {
    port: u16,
    head: u64,
    writes: u64,
    id_seq: u64,
    ghost_seq: u64,
    boundaries: Vec<Boundary>,
    memo: Option<Memo>,
    link_cursor: usize,
    n_writes: usize,
    n_doc_checks: usize,
    n_link_checks: usize,
    n_forbidden: usize,
    n_retries: usize,
}

impl Rs {
    fn next_id(&mut self) -> String {
        self.id_seq += 1;
        format!("w{}", self.id_seq)
    }
    fn next_ghost(&mut self) -> u64 {
        self.ghost_seq += 1;
        self.ghost_seq
    }
}

const ALPHABETS: [&[u8]; 3] = [b"abcdefghij", b"KLMNOPQRST", b"0123456789"];

fn text_bytes(alphabet: &[u8], s: u8) -> Vec<u8> {
    let len = 1 + (s % 3) as usize;
    (0..len).map(|i| alphabet[(s as usize / 3 + i) % alphabet.len()]).collect()
}

/// A unit-subtree width for an address: `0.….0.1` at its component count.
fn unit_w(addr: &str) -> String {
    let mut comps = vec!["0"; addr.split('.').count() - 1];
    comps.push("1");
    comps.join(".")
}

// ── fixture helpers (wire-level, like the other suites) ─────────────────

fn next_prefix(port: u16, parent: &str) -> String {
    let v = op(port, None, &format!(r#"{{"op":"next_account_prefix","parent":"{parent}"}}"#));
    expect_resp(&v, "maybe_addr")["addr"].as_str().expect("delegable prefix").to_string()
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

fn health_pos(port: u16) -> u64 {
    let (st, b) = get(port, "/health");
    assert_eq!(st, 200, "/health failed");
    json(&b)["log_position"].as_u64().expect("log_position")
}

/// The live head dump (`None` without the `observe` feature — the /op-at
/// oracles still run on such a build; the dump oracles go vacuous).
fn live_dump(port: u16) -> Option<Vec<u8>> {
    if cfg!(feature = "observe") {
        let (st, b) = get(port, "/dump");
        assert_eq!(st, 200, "GET /dump failed");
        Some(b)
    } else {
        None
    }
}

fn dump_at(port: u16, at: u64) -> Option<Vec<u8>> {
    if cfg!(feature = "observe") {
        let (st, b) = get(port, &format!("/dump?at={at}"));
        assert_eq!(st, 200, "GET /dump?at={at} failed: {}", String::from_utf8_lossy(&b));
        Some(b)
    } else {
        None
    }
}

/// Setup: bootstrap → principals 1 and 2 under node [1], principal 3
/// sub-delegated under 1's account; one empty document each.
fn setup(port: u16) -> World {
    let boot = open_session(port, 0);
    let acc_a = delegate(port, &boot, "1", 1);
    let acc_b = delegate(port, &boot, "1", 2);
    let ta = open_session(port, 1);
    let tb = open_session(port, 2);
    let acc_c = delegate(port, &ta, &acc_a, 3);
    let tc = open_session(port, 3);
    let mut w = World {
        prs: [
            Pr { token: ta, account: acc_a, docs: Vec::new(), alphabet: ALPHABETS[0] },
            Pr { token: tb, account: acc_b, docs: Vec::new(), alphabet: ALPHABETS[1] },
            Pr { token: tc, account: acc_c, docs: Vec::new(), alphabet: ALPHABETS[2] },
        ],
        docs: Vec::new(),
        links: Vec::new(),
    };
    for pi in 0..3 {
        let addr = create_doc(port, &w.prs[pi].token, &w.prs[pi].account);
        w.docs.push(DocSh { addr, content: Vec::new(), seats: 0, owner: pi });
        w.prs[pi].docs.push(w.docs.len() - 1);
    }
    w
}

// ── execution ────────────────────────────────────────────────────────────

/// Send a valid-by-construction write and require its ack; records the
/// committed head and the idempotent-retry memo.
fn commit(w: &World, rs: &mut Rs, pi: usize, frame: String, i: usize) -> Value {
    let token = w.prs[pi].token.clone();
    let (st, body) = http(rs.port, "POST", "/op", Some(&token), frame.as_bytes());
    assert_eq!(st, 200, "op {i}: transport failed: {}", String::from_utf8_lossy(&body));
    let v = json(&body);
    match v["resp"].as_str() {
        Some("ack") | Some("ack_addr") | Some("ack_edit") => {}
        _ => panic!(
            "FINDING: op {i} was valid-by-construction yet did not ack\n frame: {frame}\n resp:  {v}"
        ),
    }
    let at = v["at"].as_u64().expect("a committed write carries at");
    assert!(at >= rs.head, "op {i}: committed at {at} regressed below head {}", rs.head);
    rs.head = at;
    rs.writes += 1;
    rs.n_writes += 1;
    rs.memo = Some(Memo { frame, token, body });
    v
}

fn own_doc(w: &World, pi: usize, sel: u8) -> usize {
    let pool = &w.prs[pi].docs;
    pool[sel as usize % pool.len()]
}

/// The deterministic degradation target: one byte prepended to the caller's
/// first document. Total, so every plan item executes something.
fn fallback_insert(w: &mut World, rs: &mut Rs, pi: usize, i: usize) {
    let di = w.prs[pi].docs[0];
    let b = w.prs[pi].alphabet[0];
    let id = rs.next_id();
    let frame = format!(
        r#"{{"op":"insert","id":"{id}","doc":"{}","at":{{"subspace":"1","ordinal":"1"}},"values":["{}"]}}"#,
        w.docs[di].addr,
        char::from(b)
    );
    commit(w, rs, pi, frame, i);
    w.docs[di].content.insert(0, CItem::Byte(b));
}

fn step(i: usize, pl: &P, w: &mut World, rs: &mut Rs) {
    match pl {
        P::Insert { p, d, at, s, atom } => {
            let pi = *p as usize % 3;
            let di = own_doc(w, pi, *d);
            let len = w.docs[di].content.len() as u64;
            let pos = 1 + (*at as u64) % (len + 1);
            let bytes = text_bytes(w.prs[pi].alphabet, *s);
            let text = String::from_utf8(bytes.clone()).expect("ascii alphabet");
            let val = if *atom { json!({ "atom": text }) } else { json!(text) };
            let id = rs.next_id();
            let frame = format!(
                r#"{{"op":"insert","id":"{id}","doc":"{}","at":{{"subspace":"1","ordinal":"{pos}"}},"values":[{val}]}}"#,
                w.docs[di].addr
            );
            commit(w, rs, pi, frame, i);
            let at0 = (pos - 1) as usize;
            if *atom {
                w.docs[di].content.insert(at0, CItem::Atom(bytes));
            } else {
                for (k, b) in bytes.iter().enumerate() {
                    w.docs[di].content.insert(at0 + k, CItem::Byte(*b));
                }
            }
        }
        P::Delete { p, d, at, w: wd } => {
            let pi = *p as usize % 3;
            let di = own_doc(w, pi, *d);
            let len = w.docs[di].content.len() as u64;
            if len == 0 {
                return fallback_insert(w, rs, pi, i);
            }
            let pos = 1 + (*at as u64) % len;
            let maxw = (len - pos + 1).min(8);
            let width = 1 + (*wd as u64) % maxw;
            let id = rs.next_id();
            let frame = format!(
                r#"{{"op":"delete","id":"{id}","doc":"{}","p":{{"subspace":"1","ordinal":"{pos}"}},"width":"{width}"}}"#,
                w.docs[di].addr
            );
            commit(w, rs, pi, frame, i);
            let p0 = (pos - 1) as usize;
            w.docs[di].content.drain(p0..p0 + width as usize);
        }
        P::Copy { p, d, at, sd, f, w: wd } => {
            let pi = *p as usize % 3;
            let di = own_doc(w, pi, *d);
            let si = *sd as usize % w.docs.len();
            let srclen = w.docs[si].content.len() as u64;
            if srclen == 0 {
                return fallback_insert(w, rs, pi, i);
            }
            let from = 1 + (*f as u64) % srclen;
            let maxw = (srclen - from + 1).min(6);
            let width = 1 + (*wd as u64) % maxw;
            let dstlen = w.docs[di].content.len() as u64;
            let pos = 1 + (*at as u64) % (dstlen + 1);
            let id = rs.next_id();
            let frame = format!(
                r#"{{"op":"copy","id":"{id}","doc":"{}","at":{{"subspace":"1","ordinal":"{pos}"}},"specs":[{{"source":"{}","span":{{"start":"1.{from}","width":"0.{width}"}}}}]}}"#,
                w.docs[di].addr, w.docs[si].addr
            );
            commit(w, rs, pi, frame, i);
            // Resolution precedes staging (a self-copy sees the pre-edit
            // arrangement), so clone the items first.
            let f0 = (from - 1) as usize;
            let items: Vec<CItem> = w.docs[si].content[f0..f0 + width as usize].to_vec();
            let at0 = (pos - 1) as usize;
            for (k, it) in items.into_iter().enumerate() {
                w.docs[di].content.insert(at0 + k, it);
            }
        }
        P::Rearrange { p, d, a, b, c } => {
            let pi = *p as usize % 3;
            let di = own_doc(w, pi, *d);
            let len = w.docs[di].content.len() as u64;
            if len < 2 {
                return fallback_insert(w, rs, pi, i);
            }
            // Three strictly ascending cuts in [1, len+1]: swap the two
            // adjacent regions [c1,c2) and [c2,c3).
            let c1 = 1 + (*a as u64) % (len - 1);
            let c2 = c1 + 1 + (*b as u64) % (len - c1);
            let c3 = c2 + 1 + (*c as u64) % (len + 1 - c2);
            let id = rs.next_id();
            let frame = format!(
                r#"{{"op":"rearrange","id":"{id}","doc":"{}","cuts":[{{"subspace":"1","ordinal":"{c1}"}},{{"subspace":"1","ordinal":"{c2}"}},{{"subspace":"1","ordinal":"{c3}"}}]}}"#,
                w.docs[di].addr
            );
            commit(w, rs, pi, frame, i);
            // Swapping the adjacent regions [c1,c2) and [c2,c3) is a left
            // rotation of the combined region by |α| (the store's own test:
            // cuts [2,4,6] over a..e tile to a,d,e,b,c).
            let (i1, i2, i3) = ((c1 - 1) as usize, (c2 - 1) as usize, (c3 - 1) as usize);
            w.docs[di].content[i1..i3].rotate_left(i2 - i1);
        }
        P::Version { p, sd } => {
            let pi = *p as usize % 3;
            if w.prs[pi].docs.len() >= 6 {
                return fallback_insert(w, rs, pi, i);
            }
            let si = *sd as usize % w.docs.len();
            let id = rs.next_id();
            let frame =
                format!(r#"{{"op":"version","id":"{id}","d_src":"{}"}}"#, w.docs[si].addr);
            let v = commit(w, rs, pi, frame, i);
            let addr = v["addr"].as_str().expect("version acks the new address").to_string();
            // Content-sharing fork: the content subspace is snapshotted,
            // the link subspace is not.
            let content = w.docs[si].content.clone();
            w.docs.push(DocSh { addr, content, seats: 0, owner: pi });
            let di = w.docs.len() - 1;
            w.prs[pi].docs.push(di);
        }
        P::CreateDoc { p } => {
            let pi = *p as usize % 3;
            if w.prs[pi].docs.len() >= 6 {
                return fallback_insert(w, rs, pi, i);
            }
            let id = rs.next_id();
            let frame = format!(
                r#"{{"op":"create_new_document","id":"{id}","account":"{}"}}"#,
                w.prs[pi].account
            );
            let v = commit(w, rs, pi, frame, i);
            let addr = v["addr"].as_str().expect("create acks the address").to_string();
            w.docs.push(DocSh { addr, content: Vec::new(), seats: 0, owner: pi });
            let di = w.docs.len() - 1;
            w.prs[pi].docs.push(di);
        }
        P::MakeLink { p, d, resolve, cty, f, w: wd } => {
            let pi = *p as usize % 3;
            let di = own_doc(w, pi, *d);
            let home = w.docs[di].addr.clone();
            let len = w.docs[di].content.len() as u64;
            let from = if *resolve && len >= 1 {
                let f1 = 1 + (*f as u64) % len;
                let width = 1 + (*wd as u64) % (len - f1 + 1).min(4);
                format!(r#"[{{"source":"{home}","span":{{"start":"1.{f1}","width":"0.{width}"}}}}]"#)
            } else {
                r#"{"addrs":[]}"#.to_string()
            };
            // The type slot, both wire-v5 forms: a unique ghost NAME
            // (address form — the probe key), or a content RESOLUTION over
            // the home's own first position (never empty — the type floor).
            let (ty_arg, ty_key) = if *cty && len >= 1 {
                (
                    format!(r#"[{{"source":"{home}","span":{{"start":"1.1","width":"0.1"}}}}]"#),
                    None,
                )
            } else {
                let ghost = format!("{home}.0.3.6.{}", rs.next_ghost());
                (format!(r#"{{"addrs":["{ghost}"]}}"#), Some(ghost))
            };
            let id = rs.next_id();
            let frame = format!(
                r#"{{"op":"make_link","id":"{id}","home":"{home}","from":{from},"to":{{"addrs":[]}},"ty":{ty_arg}}}"#
            );
            let v = commit(w, rs, pi, frame, i);
            let addr = v["addr"].as_str().expect("make_link acks the link address").to_string();
            w.links.push(LinkSh { addr, ty: ty_key, home_doc: di, owner: pi, nullified: false });
            w.docs[di].seats += 1; // make_link is the one seating write
        }
        P::Emit { p, d, root } => {
            // A retired-class unary tuple over a ghost root — the one open
            // emit surface under standard genesis. Two roots per home, so
            // re-emits exercise the idem⊤ dedup (incumbent ack, no commit,
            // no seat) — a deliberate world no-op.
            let pi = *p as usize % 3;
            let di = own_doc(w, pi, *d);
            let home = w.docs[di].addr.clone();
            let ghost_root = format!("{home}.0.3.9.{}", 1 + (*root % 2));
            let id = rs.next_id();
            let frame = format!(
                r#"{{"op":"emit","id":"{id}","home":"{home}","ty":[{{"start":"9.0.9.0.9.0.9.3","width":"0.0.0.0.0.0.0.1"}}],"from":"{ghost_root}","to":[]}}"#
            );
            commit(w, rs, pi, frame, i);
        }
        P::AssertSup { p, d, x, y } => {
            let pi = *p as usize % 3;
            if w.links.len() < 2 {
                return fallback_insert(w, rs, pi, i);
            }
            let xi = *x as usize % w.links.len();
            let mut yi = *y as usize % w.links.len();
            if yi == xi {
                yi = (yi + 1) % w.links.len();
            }
            let di = own_doc(w, pi, *d);
            let id = rs.next_id();
            let frame = format!(
                r#"{{"op":"assert_sup","id":"{id}","home":"{}","old":"{}","new":"{}"}}"#,
                w.docs[di].addr, w.links[xi].addr, w.links[yi].addr
            );
            commit(w, rs, pi, frame, i);
        }
        P::Nullify { p, l } => {
            let pi = *p as usize % 3;
            let candidates: Vec<usize> = (0..w.links.len())
                .filter(|&k| w.links[k].owner == pi && !w.links[k].nullified)
                .collect();
            if candidates.is_empty() {
                return fallback_insert(w, rs, pi, i);
            }
            let li = candidates[*l as usize % candidates.len()];
            let home = w.docs[w.links[li].home_doc].addr.clone();
            let id = rs.next_id();
            let frame = format!(
                r#"{{"op":"nullify","id":"{id}","home":"{home}","target":"{}"}}"#,
                w.links[li].addr
            );
            commit(w, rs, pi, frame, i);
            w.links[li].nullified = true;
        }
        P::EditLink { p, d, l, resolve } => {
            let pi = *p as usize % 3;
            if w.links.is_empty() {
                return fallback_insert(w, rs, pi, i);
            }
            let oi = *l as usize % w.links.len();
            let di = own_doc(w, pi, *d);
            let home = w.docs[di].addr.clone();
            let ghost = format!("{home}.0.3.6.{}", rs.next_ghost());
            let from = if *resolve && !w.docs[di].content.is_empty() {
                format!(r#"[{{"source":"{home}","span":{{"start":"1.1","width":"0.1"}}}}]"#)
            } else {
                "[]".to_string()
            };
            let id = rs.next_id();
            let frame = format!(
                r#"{{"op":"edit_link","id":"{id}","original":"{}","d_s":"{home}","d_a":"{home}","successor":{{"from":{from},"to":[],"ty":{{"addrs":["{ghost}"]}}}}}}"#,
                w.links[oi].addr
            );
            let v = commit(w, rs, pi, frame, i);
            let succ = v["successor"].as_str().expect("ack_edit carries successor").to_string();
            // The successor is an ordinary open link in the caller's home
            // (born unseated — no seat count change); the claim is a
            // managed tuple (unseated, not pooled).
            w.links.push(LinkSh {
                addr: succ,
                ty: Some(ghost),
                home_doc: di,
                owner: pi,
                nullified: false,
            });
        }
        P::IdemRetry => {
            // Replay the last committed write's identical frame + id on its
            // own session: the daemon must return the ORIGINAL ack,
            // byte-identical, and change nothing (the shadow is untouched).
            if let Some(m) = &rs.memo {
                let (st, body) = http(rs.port, "POST", "/op", Some(&m.token), m.frame.as_bytes());
                assert_eq!(st, 200, "idempotent retry transport failed");
                assert_eq!(
                    body, m.body,
                    "FINDING: a same-session same-id retry did not replay the identical ack\n frame: {}",
                    m.frame
                );
                rs.n_retries += 1;
            }
        }
        P::Forbidden { p, kind } => {
            forbidden(w, rs, *p as usize % 3, *kind % 6, i);
        }
    }
}

/// Oracle 5 — a foreign write per the H1 table: must reject with the
/// table's code and move nothing (log position unchanged, shadow
/// untouched; the surrounding oracles then prove nothing else moved).
fn forbidden(w: &World, rs: &mut Rs, pi: usize, kind: u8, i: usize) {
    let foreign_doc = w
        .docs
        .iter()
        .find(|d| d.owner != pi)
        .expect("three principals each own a document");
    let foreign_link = w.links.iter().find(|l| l.owner != pi);
    let mine = w.prs[pi].token.as_str();
    let (token, frame, code): (Option<&str>, String, &str) = match kind {
        1 => {
            let acc = &w.prs[(pi + 1) % 3].account;
            (
                Some(mine),
                format!(r#"{{"op":"create_new_document","account":"{acc}"}}"#),
                "not_owner",
            )
        }
        2 if foreign_link.is_some() => {
            let target = &foreign_link.expect("checked").addr;
            let home = &w.docs[w.prs[pi].docs[0]].addr;
            (
                Some(mine),
                format!(r#"{{"op":"nullify","home":"{home}","target":"{target}"}}"#),
                "not_owner",
            )
        }
        3 => (
            Some(mine),
            format!(
                r#"{{"op":"make_link","home":"{home}","from":{{"addrs":[]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{home}.0.3.6.999999"]}}}}"#,
                home = foreign_doc.addr
            ),
            "not_owner",
        ),
        4 => (None, r#"{"op":"fork"}"#.to_string(), "unauthenticated"),
        5 => (
            Some(mine),
            format!(
                r#"{{"op":"delete","doc":"{}","p":{{"subspace":"1","ordinal":"1"}},"width":"1"}}"#,
                foreign_doc.addr
            ),
            "not_owner",
        ),
        // 0, and 2 when no foreign link exists yet.
        _ => (
            Some(mine),
            format!(
                r#"{{"op":"insert","doc":"{}","at":{{"subspace":"1","ordinal":"1"}},"values":["x"]}}"#,
                foreign_doc.addr
            ),
            "not_owner",
        ),
    };
    let before = health_pos(rs.port);
    let v = op(rs.port, token, &frame);
    let rej = expect_resp(&v, "rejected");
    assert_eq!(
        rej["code"].as_str(),
        Some(code),
        "FINDING: op {i}: forbidden write (kind {kind}) rejected with the wrong code\n frame: {frame}\n resp:  {v}"
    );
    let after = health_pos(rs.port);
    assert_eq!(
        before, after,
        "FINDING: op {i}: a rejected write moved the log ({before} → {after})\n frame: {frame}"
    );
    rs.n_forbidden += 1;
}

// ── the oracles ──────────────────────────────────────────────────────────

/// The expected delivery items for a shadow content vector: maximal
/// per-byte runs coalesce into one `content` item; each composite value is
/// its own `atom` item (wire v2 granularity, ASCII ⇒ always UTF-8).
fn render_items(content: &[CItem]) -> Value {
    let mut items: Vec<Value> = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    for it in content {
        match it {
            CItem::Byte(b) => run.push(*b),
            CItem::Atom(bytes) => {
                if !run.is_empty() {
                    items.push(json!({ "content": String::from_utf8(run.clone()).expect("ascii") }));
                    run.clear();
                }
                items.push(json!({ "atom": String::from_utf8(bytes.clone()).expect("ascii") }));
            }
        }
    }
    if !run.is_empty() {
        items.push(json!({ "content": String::from_utf8(run).expect("ascii") }));
    }
    Value::Array(items)
}

/// Oracle 4 for one document: per-subspace extents against the shadow, and
/// the full content read-back, granularity intact.
fn check_doc(w: &World, rs: &mut Rs, di: usize) {
    let d = &w.docs[di];
    let v = op(rs.port, None, &format!(r#"{{"op":"retrieve_doc_v_span_set","doc":"{}"}}"#, d.addr));
    let set = expect_resp(&v, "span_set")["set"].as_array().expect("span set").clone();
    // Extent spans may be doc-qualified (full V-address depth, as the wire's
    // span_set example) or bare depth-2; the subspace is the component after
    // the doc prefix either way, and the position count is the width's final
    // component (extents are ordinal-level).
    let doc_v_prefix = format!("{}.0.", d.addr);
    let (mut content_w, mut link_w) = (0u64, 0u64);
    for sp in &set {
        let start = sp["start"].as_str().expect("span start");
        let width = sp["width"].as_str().expect("span width");
        let local = start.strip_prefix(&doc_v_prefix).unwrap_or(start);
        let subspace: u64 = local
            .split('.')
            .next()
            .expect("component")
            .parse()
            .unwrap_or_else(|_| panic!("unparsable subspace in span start {start}: {v}"));
        let count: u64 = width.rsplit('.').next().expect("component").parse().expect("nat");
        match subspace {
            1 => content_w += count,
            2 => link_w += count,
            other => panic!("FINDING: doc {} reports an unexpected subspace {other}: {v}", d.addr),
        }
    }
    assert_eq!(
        content_w,
        d.content.len() as u64,
        "FINDING: doc {} content width diverges from the shadow: {v}",
        d.addr
    );
    assert_eq!(
        link_w, d.seats,
        "FINDING: doc {} link-subspace width diverges from the seated count: {v}",
        d.addr
    );
    if !d.content.is_empty() {
        let frame = format!(
            r#"{{"op":"retrieve_v","specs":[{{"doc":"{}","span":{{"start":"1.1","width":"0.{}"}}}}]}}"#,
            d.addr,
            d.content.len()
        );
        let v = op(rs.port, None, &frame);
        let items = &expect_resp(&v, "delivery")["items"];
        let want = render_items(&d.content);
        assert_eq!(
            items, &want,
            "FINDING: doc {} content diverges from the shadow\n want: {want}\n got:  {items}",
            d.addr
        );
    }
    rs.n_doc_checks += 1;
}

fn check_all_docs(w: &World, rs: &mut Rs) {
    for di in 0..w.docs.len() {
        check_doc(w, rs, di);
    }
}

/// Oracle 3 for one link: audit-resident forever; for ghost-typed links,
/// the exact-type active probe answers it iff not nullified (and nothing
/// else — the ghost type name is globally unique). Content-typed links get
/// the residence half only.
fn check_link(w: &World, rs: &mut Rs, li: usize) {
    let l = &w.links[li];
    let v = op(rs.port, None, &format!(r#"{{"op":"read_link","a":"{}"}}"#, l.addr));
    assert!(
        !expect_resp(&v, "link_value")["link"].is_null(),
        "FINDING: link {} vanished from the audit store (audit only grows)",
        l.addr
    );
    if let Some(ty) = &l.ty {
        let v = op(
            rs.port,
            None,
            &format!(
                r#"{{"op":"find_links_ftt","q":{{"home":"any","from":"any","to":"any","ty":[{{"start":"{ty}","width":"{}"}}]}}}}"#,
                unit_w(ty)
            ),
        );
        let addrs = expect_resp(&v, "addrs")["addrs"].clone();
        let want = if l.nullified { json!([]) } else { json!([l.addr]) };
        assert_eq!(
            addrs, want,
            "FINDING: link {} (nullified={}) — the exact-type active probe diverges: {v}",
            l.addr, l.nullified
        );
    }
    rs.n_link_checks += 1;
}

/// Sampled: a rotating window of up to 8 links; `all`: every link.
fn check_links(w: &World, rs: &mut Rs, all: bool) {
    if w.links.is_empty() {
        return;
    }
    let count = if all { w.links.len() } else { w.links.len().min(8) };
    for k in 0..count {
        let li = if all { k } else { (rs.link_cursor + k) % w.links.len() };
        check_link(w, rs, li);
    }
    if !all {
        rs.link_cursor = (rs.link_cursor + count) % w.links.len();
    }
}

/// Capture the current committed boundary: the live dump and every
/// non-empty document's live read body (with its frame, for /op-at replay).
fn capture_boundary(w: &World, rs: &mut Rs) {
    if rs.boundaries.last().is_some_and(|b| b.at == rs.head) {
        return;
    }
    let dump = live_dump(rs.port);
    let mut reads = Vec::new();
    for d in &w.docs {
        if d.content.is_empty() {
            continue;
        }
        let frame = format!(
            r#"{{"op":"retrieve_v","specs":[{{"doc":"{}","span":{{"start":"1.1","width":"0.{}"}}}}]}}"#,
            d.addr,
            d.content.len()
        );
        let (st, body) = http(rs.port, "POST", "/op", None, frame.as_bytes());
        assert_eq!(st, 200, "boundary read failed");
        reads.push((frame, body));
    }
    rs.boundaries.push(Boundary { at: rs.head, dump, reads });
}

/// Oracles 1 + 2: every captured boundary must answer byte-identically from
/// history — the dump via `/dump?at`, the reads via `/op-at`.
fn replay_boundaries(rs: &Rs) {
    for b in &rs.boundaries {
        assert_eq!(
            dump_at(rs.port, b.at),
            b.dump,
            "FINDING: /dump?at={} is not byte-equal to the dump captured live there",
            b.at
        );
        for (frame, body) in &b.reads {
            let env = format!(r#"{{"at":{},"frame":{frame}}}"#, b.at);
            let (st, got) = http(rs.port, "POST", "/op-at", None, env.as_bytes());
            assert_eq!(st, 200, "/op-at at={} failed: {}", b.at, String::from_utf8_lossy(&got));
            assert_eq!(
                &got, body,
                "FINDING: historical read at {} diverges from the live body\n frame: {frame}",
                b.at
            );
        }
    }
}

// ── one full case ────────────────────────────────────────────────────────

fn run_case(plan: &[P]) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut srv = Some(spawn(dir.path()));
    let mut rs = Rs {
        port: srv.as_ref().expect("live").port(),
        head: 0,
        writes: 0,
        id_seq: 0,
        ghost_seq: 0,
        boundaries: Vec::new(),
        memo: None,
        link_cursor: 0,
        n_writes: 0,
        n_doc_checks: 0,
        n_link_checks: 0,
        n_forbidden: 0,
        n_retries: 0,
    };
    let mut w = setup(rs.port);
    rs.head = health_pos(rs.port);

    for (i, pl) in plan.iter().enumerate() {
        let writes_before = rs.writes;
        step(i, pl, &mut w, &mut rs);
        if rs.writes > writes_before && rs.writes % CADENCE as u64 == 0 {
            capture_boundary(&w, &mut rs);
        }
        if (i + 1) % CADENCE == 0 {
            check_all_docs(&w, &mut rs);
            check_links(&w, &mut rs, false);
        }
    }

    // Sequence end: the full oracle pass, the final boundary, and the
    // whole-history replay.
    check_all_docs(&w, &mut rs);
    check_links(&w, &mut rs, true);
    capture_boundary(&w, &mut rs);
    replay_boundaries(&rs);

    // Oracle 6 — restart equivalence: reopen the same store; the head, the
    // head dump, a historical dump, a historical read, and the full oracle
    // pass must all agree with the pre-shutdown run.
    let final_dump = live_dump(rs.port);
    let final_head = rs.head;
    srv.take().expect("live daemon").shutdown();
    let sd2 = spawn(dir.path());
    rs.port = sd2.port();
    assert_eq!(
        health_pos(rs.port),
        final_head,
        "FINDING: the recovered head diverges from the last acked position"
    );
    assert_eq!(
        live_dump(rs.port),
        final_dump,
        "FINDING: the recovered head dump is not byte-equal to the pre-shutdown dump"
    );
    if !rs.boundaries.is_empty() {
        let b = &rs.boundaries[rs.boundaries.len() / 2];
        assert_eq!(
            dump_at(rs.port, b.at),
            b.dump,
            "FINDING: /dump?at={} diverges after restart",
            b.at
        );
        if let Some((frame, body)) = b.reads.first() {
            let env = format!(r#"{{"at":{},"frame":{frame}}}"#, b.at);
            let (st, got) = http(rs.port, "POST", "/op-at", None, env.as_bytes());
            assert_eq!(st, 200);
            assert_eq!(
                &got, body,
                "FINDING: historical read at {} diverges after restart\n frame: {frame}",
                b.at
            );
        }
    }
    check_all_docs(&w, &mut rs);
    check_links(&w, &mut rs, true);
    sd2.shutdown();

    println!(
        "props case: {} ops ({} writes, {} retries, {} forbidden), {} boundaries, \
         {} doc checks, {} link checks, head {}",
        plan.len(),
        rs.n_writes,
        rs.n_retries,
        rs.n_forbidden,
        rs.boundaries.len(),
        rs.n_doc_checks,
        rs.n_link_checks,
        final_head
    );
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: cases(),
        // Shrinking re-runs whole cases (~1–2 s each); bound the budget so
        // a failing run still reports its shrunk plan within minutes.
        max_shrink_iters: 200,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn random_valid_op_sequences_hold_the_invariants(plan in plan_strategy()) {
        run_case(&plan);
    }
}
