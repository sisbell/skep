//! H4 — property-based op sequences (hardening ruling): random-but-valid
//! plans of FEBE operations against an in-process daemon over a temp store,
//! every op through the wire (`POST /op`), with invariant oracles checked at
//! sampled steps and always at sequence end.
//!
//! The generator draws abstract `PlanOp` plan items (small selectors and
//! fractions); the interpreter maps each item onto a CONCRETE valid op
//! against tracked shadow state (pool indices mod current pools, positions
//! mod current lengths), so every dispatched frame is valid by construction
//! and any rejection of a generated op is itself a finding. Ops whose
//! preconditions cannot be met yet degrade deterministically to a fallback
//! insert — a plan is total, which keeps proptest's shrinking meaningful.
//!
//! The oracles:
//!  1. Prefix-replay equivalence — the observe dump captured live at every
//!     k-th committed position must be byte-equal to `GET /dump?at=p` at
//!     sequence end (journal + fold + checkpoint + hints in one oracle).
//!  2. Permanence — every captured position's live `retrieve_v` bodies (the content
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
enum PlanOp {
    Insert { p: u8, d: u8, at: u16, s: u8, atom: bool },
    Delete { p: u8, d: u8, at: u16, w: u8 },
    Copy { p: u8, d: u8, at: u16, sd: u8, f: u16, w: u8 },
    Rearrange { p: u8, d: u8, a: u16, b: u16, c: u16 },
    Version { p: u8, sd: u8 },
    CreateDoc { p: u8 },
    MakeLink { p: u8, d: u8, resolve_from: bool, resolve_ty: bool, f: u16, w: u8 },
    Emit { p: u8, d: u8, root: u8 },
    AssertSup { p: u8, d: u8, x: u8, y: u8 },
    Nullify { p: u8, l: u8 },
    EditLink { p: u8, d: u8, l: u8, resolve_from: bool },
    IdemRetry,
    Forbidden { p: u8, kind: u8 },
}

fn plan_strategy() -> impl Strategy<Value = Vec<PlanOp>> {
    // Grouped (prop_oneof's TupleUnion caps at 10 arms); outer weights are
    // each group's summed inner weights, so the flat distribution is:
    // insert 6, delete 3, copy 3, rearrange 2, version 2, create 1,
    // make_link 4, emit 2, assert_sup 2, nullify 2, edit_link 2,
    // idem-retry 2, forbidden 2.
    let arrangement = prop_oneof![
        6 => (0..3u8, any::<u8>(), any::<u16>(), any::<u8>(), prop::bool::weighted(0.2))
            .prop_map(|(p, d, at, s, atom)| PlanOp::Insert { p, d, at, s, atom }),
        3 => (0..3u8, any::<u8>(), any::<u16>(), any::<u8>())
            .prop_map(|(p, d, at, w)| PlanOp::Delete { p, d, at, w }),
        3 => (0..3u8, any::<u8>(), any::<u16>(), any::<u8>(), any::<u16>(), any::<u8>())
            .prop_map(|(p, d, at, sd, f, w)| PlanOp::Copy { p, d, at, sd, f, w }),
        2 => (0..3u8, any::<u8>(), any::<u16>(), any::<u16>(), any::<u16>())
            .prop_map(|(p, d, a, b, c)| PlanOp::Rearrange { p, d, a, b, c }),
        2 => (0..3u8, any::<u8>()).prop_map(|(p, sd)| PlanOp::Version { p, sd }),
        1 => (0..3u8).prop_map(|p| PlanOp::CreateDoc { p }),
    ];
    let links = prop_oneof![
        4 => (0..3u8, any::<u8>(), any::<bool>(), prop::bool::weighted(0.25), any::<u16>(), any::<u8>())
            .prop_map(|(p, d, resolve_from, resolve_ty, f, w)| {
                PlanOp::MakeLink { p, d, resolve_from, resolve_ty, f, w }
            }),
        2 => (0..3u8, any::<u8>(), any::<u8>()).prop_map(|(p, d, root)| PlanOp::Emit { p, d, root }),
        2 => (0..3u8, any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(p, d, x, y)| PlanOp::AssertSup { p, d, x, y }),
        2 => (0..3u8, any::<u8>()).prop_map(|(p, l)| PlanOp::Nullify { p, l }),
        2 => (0..3u8, any::<u8>(), any::<u8>(), any::<bool>())
            .prop_map(|(p, d, l, resolve_from)| PlanOp::EditLink { p, d, l, resolve_from }),
    ];
    let meta = prop_oneof![
        2 => Just(PlanOp::IdemRetry),
        2 => (0..3u8, any::<u8>()).prop_map(|(p, kind)| PlanOp::Forbidden { p, kind }),
    ];
    let op = prop_oneof![17 => arrangement, 12 => links, 4 => meta];
    prop::collection::vec(op, ops_len())
}

// ── the shadow world ─────────────────────────────────────────────────────

/// One content position: a single byte (the substrate's text discipline) or
/// one composite value — always ≥ 2 bytes: a one-byte atom is the same
/// write as its per-byte form (wire.md §Content values), so the shadow
/// records it as a `Byte` and expects it coalesced into a delivery run.
/// ASCII-only alphabets keep every per-byte run valid UTF-8, so the
/// expected delivery rendering is exact.
#[derive(Clone)]
enum ContentItem {
    Byte(u8),
    Atom(Vec<u8>),
}

struct DocShadow {
    addr: String,
    content: Vec<ContentItem>,
    /// Seated link count — `make_link` is the ONE seating write (managed
    /// tuples, retractions, sup claims, and edit successors are unseated).
    seats: u64,
    owner: usize,
}

struct LinkShadow {
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

struct Principal {
    token: String,
    account: String,
    docs: Vec<usize>,
    alphabet: &'static [u8],
}

struct Shadow {
    principals: [Principal; 3],
    docs: Vec<DocShadow>,
    links: Vec<LinkShadow>,
}

struct Memo {
    frame: String,
    token: String,
    body: Vec<u8>,
}

/// One committed POSITION and what the daemon answered there. Every value
/// captured below comes from `/dump?at`, `/op-at` or `/health`, so this
/// file speaks the wire's word throughout — wire.md: "Those numbers are
/// positions" — and never the kernel's `boundary`, which `sidecar.rs`
/// earns by probing the kernel and no test here does.
struct Capture {
    at: u64,
    /// `None` when built without the `observe` feature.
    dump: Option<Vec<u8>>,
    /// (frame, live response body) — replayed via `/op-at` later.
    reads: Vec<(String, Vec<u8>)>,
}

struct RunState {
    port: u16,
    head: u64,
    id_seq: u64,
    ghost_seq: u64,
    captures: Vec<Capture>,
    memo: Option<Memo>,
    link_cursor: usize,
    /// Committed writes so far — the oracle cadence and the report both
    /// read it, so there is exactly one number to keep true.
    n_writes: usize,
    n_doc_checks: usize,
    n_link_checks: usize,
    n_forbidden: usize,
    n_retries: usize,
}

impl RunState {
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
fn setup(port: u16) -> Shadow {
    let boot = open_session(port, 0);
    let acc_a = delegate(port, &boot, "1", 1);
    let acc_b = delegate(port, &boot, "1", 2);
    let ta = open_session(port, 1);
    let tb = open_session(port, 2);
    let acc_c = delegate(port, &ta, &acc_a, 3);
    let tc = open_session(port, 3);
    let mut shadow = Shadow {
        principals: [
            Principal { token: ta, account: acc_a, docs: Vec::new(), alphabet: ALPHABETS[0] },
            Principal { token: tb, account: acc_b, docs: Vec::new(), alphabet: ALPHABETS[1] },
            Principal { token: tc, account: acc_c, docs: Vec::new(), alphabet: ALPHABETS[2] },
        ],
        docs: Vec::new(),
        links: Vec::new(),
    };
    for pi in 0..3 {
        let addr = create_doc(port, &shadow.principals[pi].token, &shadow.principals[pi].account);
        shadow.docs.push(DocShadow { addr, content: Vec::new(), seats: 0, owner: pi });
        shadow.principals[pi].docs.push(shadow.docs.len() - 1);
    }
    shadow
}

// ── execution ────────────────────────────────────────────────────────────

/// Send a valid-by-construction write and require its ack; records the
/// committed head and the idempotent-retry memo.
fn commit(
    shadow: &Shadow,
    state: &mut RunState,
    pi: usize,
    frame: String,
    op_index: usize,
) -> Value {
    let token = shadow.principals[pi].token.clone();
    let (st, body) = http(state.port, "POST", "/op", Some(&token), frame.as_bytes());
    assert_eq!(st, 200, "op {op_index}: transport failed: {}", String::from_utf8_lossy(&body));
    let v = json(&body);
    match v["resp"].as_str() {
        Some("ack") | Some("ack_addr") | Some("ack_edit") => {}
        _ => panic!(
            "FINDING: op {op_index} was valid-by-construction yet did not ack\n frame: {frame}\n resp:  {v}"
        ),
    }
    let at = v["at"].as_u64().expect("a committed write carries at");
    assert!(
        at >= state.head,
        "op {op_index}: committed at {at} regressed below head {}",
        state.head
    );
    state.head = at;
    state.n_writes += 1;
    state.memo = Some(Memo { frame, token, body });
    v
}

fn own_doc(shadow: &Shadow, pi: usize, sel: u8) -> usize {
    let pool = &shadow.principals[pi].docs;
    pool[sel as usize % pool.len()]
}

/// The deterministic degradation target: one byte prepended to the caller's
/// first document. Total, so every plan item executes something.
fn fallback_insert(shadow: &mut Shadow, state: &mut RunState, pi: usize, op_index: usize) {
    let di = shadow.principals[pi].docs[0];
    let b = shadow.principals[pi].alphabet[0];
    let id = state.next_id();
    let frame = format!(
        r#"{{"op":"insert","id":"{id}","doc":"{}","at":{{"subspace":"1","ordinal":"1"}},"values":["{}"]}}"#,
        shadow.docs[di].addr,
        char::from(b)
    );
    commit(shadow, state, pi, frame, op_index);
    shadow.docs[di].content.insert(0, ContentItem::Byte(b));
}

fn step(op_index: usize, planned: &PlanOp, shadow: &mut Shadow, state: &mut RunState) {
    match planned {
        PlanOp::Insert { p, d, at, s, atom } => {
            let pi = *p as usize % 3;
            let di = own_doc(shadow, pi, *d);
            let len = shadow.docs[di].content.len() as u64;
            let pos = 1 + (*at as u64) % (len + 1);
            let bytes = text_bytes(shadow.principals[pi].alphabet, *s);
            let text = String::from_utf8(bytes.clone()).expect("ascii alphabet");
            let val = if *atom { json!({ "atom": text }) } else { json!(text) };
            let id = state.next_id();
            let frame = format!(
                r#"{{"op":"insert","id":"{id}","doc":"{}","at":{{"subspace":"1","ordinal":"{pos}"}},"values":[{val}]}}"#,
                shadow.docs[di].addr
            );
            commit(shadow, state, pi, frame, op_index);
            let at0 = (pos - 1) as usize;
            if *atom && bytes.len() > 1 {
                shadow.docs[di].content.insert(at0, ContentItem::Atom(bytes));
            } else {
                // Per-byte — including a one-byte {"atom"}, which is the
                // same write as its per-byte form (wire.md §Content values)
                // and coalesces into content runs on delivery.
                for (k, b) in bytes.iter().enumerate() {
                    shadow.docs[di].content.insert(at0 + k, ContentItem::Byte(*b));
                }
            }
        }
        PlanOp::Delete { p, d, at, w: wd } => {
            let pi = *p as usize % 3;
            let di = own_doc(shadow, pi, *d);
            let len = shadow.docs[di].content.len() as u64;
            if len == 0 {
                return fallback_insert(shadow, state, pi, op_index);
            }
            let pos = 1 + (*at as u64) % len;
            let maxw = (len - pos + 1).min(8);
            let width = 1 + (*wd as u64) % maxw;
            let id = state.next_id();
            let frame = format!(
                r#"{{"op":"delete","id":"{id}","doc":"{}","p":{{"subspace":"1","ordinal":"{pos}"}},"width":"{width}"}}"#,
                shadow.docs[di].addr
            );
            commit(shadow, state, pi, frame, op_index);
            let p0 = (pos - 1) as usize;
            shadow.docs[di].content.drain(p0..p0 + width as usize);
        }
        PlanOp::Copy { p, d, at, sd, f, w: wd } => {
            let pi = *p as usize % 3;
            let di = own_doc(shadow, pi, *d);
            let si = *sd as usize % shadow.docs.len();
            let srclen = shadow.docs[si].content.len() as u64;
            if srclen == 0 {
                return fallback_insert(shadow, state, pi, op_index);
            }
            let from = 1 + (*f as u64) % srclen;
            let maxw = (srclen - from + 1).min(6);
            let width = 1 + (*wd as u64) % maxw;
            let dstlen = shadow.docs[di].content.len() as u64;
            let pos = 1 + (*at as u64) % (dstlen + 1);
            let id = state.next_id();
            let frame = format!(
                r#"{{"op":"copy","id":"{id}","doc":"{}","at":{{"subspace":"1","ordinal":"{pos}"}},"specs":[{{"source":"{}","span":{{"start":"1.{from}","width":"0.{width}"}}}}]}}"#,
                shadow.docs[di].addr, shadow.docs[si].addr
            );
            commit(shadow, state, pi, frame, op_index);
            // Resolution precedes staging (a self-copy sees the pre-edit
            // arrangement), so clone the items first.
            let f0 = (from - 1) as usize;
            let items: Vec<ContentItem> = shadow.docs[si].content[f0..f0 + width as usize].to_vec();
            let at0 = (pos - 1) as usize;
            for (k, it) in items.into_iter().enumerate() {
                shadow.docs[di].content.insert(at0 + k, it);
            }
        }
        PlanOp::Rearrange { p, d, a, b, c } => {
            let pi = *p as usize % 3;
            let di = own_doc(shadow, pi, *d);
            let len = shadow.docs[di].content.len() as u64;
            if len < 2 {
                return fallback_insert(shadow, state, pi, op_index);
            }
            // Three strictly ascending cuts in [1, len+1]: swap the two
            // adjacent regions [c1,c2) and [c2,c3).
            let c1 = 1 + (*a as u64) % (len - 1);
            let c2 = c1 + 1 + (*b as u64) % (len - c1);
            let c3 = c2 + 1 + (*c as u64) % (len + 1 - c2);
            let id = state.next_id();
            let frame = format!(
                r#"{{"op":"rearrange","id":"{id}","doc":"{}","cuts":[{{"subspace":"1","ordinal":"{c1}"}},{{"subspace":"1","ordinal":"{c2}"}},{{"subspace":"1","ordinal":"{c3}"}}]}}"#,
                shadow.docs[di].addr
            );
            commit(shadow, state, pi, frame, op_index);
            // Swapping the adjacent regions [c1,c2) and [c2,c3) is a left
            // rotation of the combined region by |α| (the store's own test:
            // cuts [2,4,6] over a..e tile to a,d,e,b,c).
            let (i1, i2, i3) = ((c1 - 1) as usize, (c2 - 1) as usize, (c3 - 1) as usize);
            shadow.docs[di].content[i1..i3].rotate_left(i2 - i1);
        }
        PlanOp::Version { p, sd } => {
            let pi = *p as usize % 3;
            if shadow.principals[pi].docs.len() >= 6 {
                return fallback_insert(shadow, state, pi, op_index);
            }
            let si = *sd as usize % shadow.docs.len();
            let id = state.next_id();
            let frame =
                format!(r#"{{"op":"version","id":"{id}","d_src":"{}"}}"#, shadow.docs[si].addr);
            let v = commit(shadow, state, pi, frame, op_index);
            let addr = v["addr"].as_str().expect("version acks the new address").to_string();
            // Content-sharing fork: the content subspace is snapshotted,
            // the link subspace is not.
            let content = shadow.docs[si].content.clone();
            shadow.docs.push(DocShadow { addr, content, seats: 0, owner: pi });
            let di = shadow.docs.len() - 1;
            shadow.principals[pi].docs.push(di);
        }
        PlanOp::CreateDoc { p } => {
            let pi = *p as usize % 3;
            if shadow.principals[pi].docs.len() >= 6 {
                return fallback_insert(shadow, state, pi, op_index);
            }
            let id = state.next_id();
            let frame = format!(
                r#"{{"op":"create_new_document","id":"{id}","account":"{}"}}"#,
                shadow.principals[pi].account
            );
            let v = commit(shadow, state, pi, frame, op_index);
            let addr = v["addr"].as_str().expect("create acks the address").to_string();
            shadow.docs.push(DocShadow { addr, content: Vec::new(), seats: 0, owner: pi });
            let di = shadow.docs.len() - 1;
            shadow.principals[pi].docs.push(di);
        }
        PlanOp::MakeLink { p, d, resolve_from, resolve_ty, f, w: wd } => {
            let pi = *p as usize % 3;
            let di = own_doc(shadow, pi, *d);
            let home = shadow.docs[di].addr.clone();
            let len = shadow.docs[di].content.len() as u64;
            let from = if *resolve_from && len >= 1 {
                let f1 = 1 + (*f as u64) % len;
                let width = 1 + (*wd as u64) % (len - f1 + 1).min(4);
                format!(r#"[{{"source":"{home}","span":{{"start":"1.{f1}","width":"0.{width}"}}}}]"#)
            } else {
                r#"{"addrs":[]}"#.to_string()
            };
            // The type slot, both wire-v5 forms: a unique ghost NAME
            // (address form — the probe key), or a content RESOLUTION over
            // the home's own first position (never empty — the type floor).
            let (ty_arg, ty_key) = if *resolve_ty && len >= 1 {
                (
                    format!(r#"[{{"source":"{home}","span":{{"start":"1.1","width":"0.1"}}}}]"#),
                    None,
                )
            } else {
                let ghost = format!("{home}.0.3.6.{}", state.next_ghost());
                (format!(r#"{{"addrs":["{ghost}"]}}"#), Some(ghost))
            };
            let id = state.next_id();
            let frame = format!(
                r#"{{"op":"make_link","id":"{id}","home":"{home}","from":{from},"to":{{"addrs":[]}},"ty":{ty_arg}}}"#
            );
            let v = commit(shadow, state, pi, frame, op_index);
            let addr = v["addr"].as_str().expect("make_link acks the link address").to_string();
            shadow.links.push(LinkShadow { addr, ty: ty_key, home_doc: di, owner: pi, nullified: false });
            shadow.docs[di].seats += 1; // make_link is the one seating write
        }
        PlanOp::Emit { p, d, root } => {
            // A retired-class unary tuple over a ghost root — the one open
            // emit surface under standard genesis. Two roots per home, so
            // re-emits exercise the idem⊤ dedup (incumbent ack, no commit,
            // no seat) — a deliberate world no-op.
            let pi = *p as usize % 3;
            let di = own_doc(shadow, pi, *d);
            let home = shadow.docs[di].addr.clone();
            let ghost_root = format!("{home}.0.3.9.{}", 1 + (*root % 2));
            let id = state.next_id();
            let frame = format!(
                r#"{{"op":"emit","id":"{id}","home":"{home}","ty":[{{"start":"9.0.9.0.9.0.9.3","width":"0.0.0.0.0.0.0.1"}}],"from":"{ghost_root}","to":[]}}"#
            );
            commit(shadow, state, pi, frame, op_index);
        }
        PlanOp::AssertSup { p, d, x, y } => {
            let pi = *p as usize % 3;
            if shadow.links.len() < 2 {
                return fallback_insert(shadow, state, pi, op_index);
            }
            let xi = *x as usize % shadow.links.len();
            let mut yi = *y as usize % shadow.links.len();
            if yi == xi {
                yi = (yi + 1) % shadow.links.len();
            }
            let di = own_doc(shadow, pi, *d);
            let id = state.next_id();
            let frame = format!(
                r#"{{"op":"assert_sup","id":"{id}","home":"{}","old":"{}","new":"{}"}}"#,
                shadow.docs[di].addr, shadow.links[xi].addr, shadow.links[yi].addr
            );
            commit(shadow, state, pi, frame, op_index);
        }
        PlanOp::Nullify { p, l } => {
            let pi = *p as usize % 3;
            let candidates: Vec<usize> = (0..shadow.links.len())
                .filter(|&k| shadow.links[k].owner == pi && !shadow.links[k].nullified)
                .collect();
            if candidates.is_empty() {
                return fallback_insert(shadow, state, pi, op_index);
            }
            let li = candidates[*l as usize % candidates.len()];
            let home = shadow.docs[shadow.links[li].home_doc].addr.clone();
            let id = state.next_id();
            let frame = format!(
                r#"{{"op":"nullify","id":"{id}","home":"{home}","target":"{}"}}"#,
                shadow.links[li].addr
            );
            commit(shadow, state, pi, frame, op_index);
            shadow.links[li].nullified = true;
        }
        PlanOp::EditLink { p, d, l, resolve_from } => {
            let pi = *p as usize % 3;
            if shadow.links.is_empty() {
                return fallback_insert(shadow, state, pi, op_index);
            }
            let oi = *l as usize % shadow.links.len();
            let di = own_doc(shadow, pi, *d);
            let home = shadow.docs[di].addr.clone();
            let ghost = format!("{home}.0.3.6.{}", state.next_ghost());
            let from = if *resolve_from && !shadow.docs[di].content.is_empty() {
                format!(r#"[{{"source":"{home}","span":{{"start":"1.1","width":"0.1"}}}}]"#)
            } else {
                "[]".to_string()
            };
            let id = state.next_id();
            let frame = format!(
                r#"{{"op":"edit_link","id":"{id}","original":"{}","d_s":"{home}","d_a":"{home}","successor":{{"from":{from},"to":[],"ty":{{"addrs":["{ghost}"]}}}}}}"#,
                shadow.links[oi].addr
            );
            let v = commit(shadow, state, pi, frame, op_index);
            let succ = v["successor"].as_str().expect("ack_edit carries successor").to_string();
            // The successor is an ordinary open link in the caller's home
            // (born unseated — no seat count change); the claim is a
            // managed tuple (unseated, not pooled).
            shadow.links.push(LinkShadow {
                addr: succ,
                ty: Some(ghost),
                home_doc: di,
                owner: pi,
                nullified: false,
            });
        }
        PlanOp::IdemRetry => {
            // Replay the last committed write's identical frame + id on its
            // own session: the daemon must return the ORIGINAL ack,
            // byte-identical, and change nothing (the shadow is untouched).
            if let Some(m) = &state.memo {
                let (st, body) = http(state.port, "POST", "/op", Some(&m.token), m.frame.as_bytes());
                assert_eq!(st, 200, "idempotent retry transport failed");
                assert_eq!(
                    body, m.body,
                    "FINDING: a same-session same-id retry did not replay the identical ack\n frame: {}",
                    m.frame
                );
                state.n_retries += 1;
            }
        }
        PlanOp::Forbidden { p, kind } => {
            forbidden(shadow, state, *p as usize % 3, *kind % 6, op_index);
        }
    }
}

/// Oracle 5 — a foreign write per the H1 table: must reject with the
/// table's code and move nothing (log position unchanged, shadow
/// untouched; the surrounding oracles then prove nothing else moved).
fn forbidden(shadow: &Shadow, state: &mut RunState, pi: usize, kind: u8, op_index: usize) {
    let foreign_doc = shadow
        .docs
        .iter()
        .find(|d| d.owner != pi)
        .expect("three principals each own a document");
    let foreign_link = shadow.links.iter().find(|l| l.owner != pi);
    let mine = shadow.principals[pi].token.as_str();
    let (token, frame, code): (Option<&str>, String, &str) = match kind {
        1 => {
            let acc = &shadow.principals[(pi + 1) % 3].account;
            (
                Some(mine),
                format!(r#"{{"op":"create_new_document","account":"{acc}"}}"#),
                "not_owner",
            )
        }
        2 if foreign_link.is_some() => {
            let target = &foreign_link.expect("checked").addr;
            let home = &shadow.docs[shadow.principals[pi].docs[0]].addr;
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
    let before = health_pos(state.port);
    let v = op(state.port, token, &frame);
    let rej = expect_resp(&v, "rejected");
    assert_eq!(
        rej["code"].as_str(),
        Some(code),
        "FINDING: op {op_index}: forbidden write (kind {kind}) rejected with the wrong code\n frame: {frame}\n resp:  {v}"
    );
    let after = health_pos(state.port);
    assert_eq!(
        before, after,
        "FINDING: op {op_index}: a rejected write moved the log ({before} → {after})\n frame: {frame}"
    );
    state.n_forbidden += 1;
}

// ── the oracles ──────────────────────────────────────────────────────────

/// The expected delivery items for a shadow content vector: maximal
/// per-byte runs coalesce into one `content` item; each composite value is
/// its own `atom` item (wire v2 granularity, ASCII ⇒ always UTF-8).
fn render_items(content: &[ContentItem]) -> Value {
    let mut items: Vec<Value> = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    for it in content {
        match it {
            ContentItem::Byte(b) => run.push(*b),
            ContentItem::Atom(bytes) => {
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
fn check_doc(shadow: &Shadow, state: &mut RunState, di: usize) {
    let d = &shadow.docs[di];
    let v = op(state.port, None, &format!(r#"{{"op":"retrieve_doc_v_span_set","doc":"{}"}}"#, d.addr));
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
        let v = op(state.port, None, &frame);
        let items = &expect_resp(&v, "delivery")["items"];
        let want = render_items(&d.content);
        assert_eq!(
            items, &want,
            "FINDING: doc {} content diverges from the shadow\n want: {want}\n got:  {items}",
            d.addr
        );
    }
    state.n_doc_checks += 1;
}

fn check_all_docs(shadow: &Shadow, state: &mut RunState) {
    for di in 0..shadow.docs.len() {
        check_doc(shadow, state, di);
    }
}

/// Oracle 3 for one link: audit-resident forever; for ghost-typed links,
/// the exact-type active probe answers it iff not nullified (and nothing
/// else — the ghost type name is globally unique). Content-typed links get
/// the residence half only.
fn check_link(shadow: &Shadow, state: &mut RunState, li: usize) {
    let l = &shadow.links[li];
    let v = op(state.port, None, &format!(r#"{{"op":"read_link","a":"{}"}}"#, l.addr));
    assert!(
        !expect_resp(&v, "link_value")["link"].is_null(),
        "FINDING: link {} vanished from the audit store (audit only grows)",
        l.addr
    );
    if let Some(ty) = &l.ty {
        let v = op(
            state.port,
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
    state.n_link_checks += 1;
}

/// Which links one pass checks: the rotating window the per-cadence sample
/// walks, or every link — the sequence-end and post-restart passes, where a
/// narrowed scope would weaken the oracle in silence.
#[derive(Clone, Copy)]
enum LinkScope {
    Sample,
    All,
}

/// One link-oracle pass: a rotating window of up to 8 links under
/// [`LinkScope::Sample`], every link under [`LinkScope::All`].
fn check_links(shadow: &Shadow, state: &mut RunState, scope: LinkScope) {
    if shadow.links.is_empty() {
        return;
    }
    let count = match scope {
        LinkScope::All => shadow.links.len(),
        LinkScope::Sample => shadow.links.len().min(8),
    };
    for k in 0..count {
        let li = match scope {
            LinkScope::All => k,
            LinkScope::Sample => (state.link_cursor + k) % shadow.links.len(),
        };
        check_link(shadow, state, li);
    }
    if matches!(scope, LinkScope::Sample) {
        state.link_cursor = (state.link_cursor + count) % shadow.links.len();
    }
}

/// Capture the current committed position: the live dump and every
/// non-empty document's live read body (with its frame, for /op-at replay).
fn capture_position(shadow: &Shadow, state: &mut RunState) {
    if state.captures.last().is_some_and(|c| c.at == state.head) {
        return;
    }
    let dump = live_dump(state.port);
    let mut reads = Vec::new();
    for d in &shadow.docs {
        if d.content.is_empty() {
            continue;
        }
        let frame = format!(
            r#"{{"op":"retrieve_v","specs":[{{"doc":"{}","span":{{"start":"1.1","width":"0.{}"}}}}]}}"#,
            d.addr,
            d.content.len()
        );
        let (st, body) = http(state.port, "POST", "/op", None, frame.as_bytes());
        assert_eq!(st, 200, "the captured position's read failed");
        reads.push((frame, body));
    }
    state.captures.push(Capture { at: state.head, dump, reads });
}

/// Oracles 1 + 2: every captured position must answer byte-identically from
/// history — the dump via `/dump?at`, the reads via `/op-at`.
fn replay_captures(state: &RunState) {
    for c in &state.captures {
        assert_eq!(
            dump_at(state.port, c.at),
            c.dump,
            "FINDING: /dump?at={} is not byte-equal to the dump captured live there",
            c.at
        );
        for (frame, body) in &c.reads {
            let env = format!(r#"{{"at":{},"frame":{frame}}}"#, c.at);
            let (st, got) = http(state.port, "POST", "/op-at", None, env.as_bytes());
            assert_eq!(st, 200, "/op-at at={} failed: {}", c.at, String::from_utf8_lossy(&got));
            assert_eq!(
                &got, body,
                "FINDING: historical read at {} diverges from the live body\n frame: {frame}",
                c.at
            );
        }
    }
}

// ── one full case ────────────────────────────────────────────────────────

fn run_case(plan: &[PlanOp]) {
    let dir = tempfile::tempdir().expect("tempdir");
    let srv = spawn(dir.path());
    let mut state = RunState {
        port: srv.port(),
        head: 0,
        id_seq: 0,
        ghost_seq: 0,
        captures: Vec::new(),
        memo: None,
        link_cursor: 0,
        n_writes: 0,
        n_doc_checks: 0,
        n_link_checks: 0,
        n_forbidden: 0,
        n_retries: 0,
    };
    let mut shadow = setup(state.port);
    state.head = health_pos(state.port);

    for (op_index, planned) in plan.iter().enumerate() {
        let writes_before = state.n_writes;
        step(op_index, planned, &mut shadow, &mut state);
        if state.n_writes > writes_before && state.n_writes % CADENCE == 0 {
            capture_position(&shadow, &mut state);
        }
        if (op_index + 1) % CADENCE == 0 {
            check_all_docs(&shadow, &mut state);
            check_links(&shadow, &mut state, LinkScope::Sample);
        }
    }

    // Sequence end: the full oracle pass, the final position, and the
    // whole-history replay.
    check_all_docs(&shadow, &mut state);
    check_links(&shadow, &mut state, LinkScope::All);
    capture_position(&shadow, &mut state);
    replay_captures(&state);

    // Oracle 6 — restart equivalence: reopen the same store; the head, the
    // head dump, a historical dump, a historical read, and the full oracle
    // pass must all agree with the pre-shutdown run.
    let final_dump = live_dump(state.port);
    let final_head = state.head;
    srv.shutdown();
    let sd2 = spawn(dir.path());
    state.port = sd2.port();
    assert_eq!(
        health_pos(state.port),
        final_head,
        "FINDING: the recovered head diverges from the last acked position"
    );
    assert_eq!(
        live_dump(state.port),
        final_dump,
        "FINDING: the recovered head dump is not byte-equal to the pre-shutdown dump"
    );
    if !state.captures.is_empty() {
        let c = &state.captures[state.captures.len() / 2];
        assert_eq!(
            dump_at(state.port, c.at),
            c.dump,
            "FINDING: /dump?at={} diverges after restart",
            c.at
        );
        if let Some((frame, body)) = c.reads.first() {
            let env = format!(r#"{{"at":{},"frame":{frame}}}"#, c.at);
            let (st, got) = http(state.port, "POST", "/op-at", None, env.as_bytes());
            assert_eq!(st, 200);
            assert_eq!(
                &got, body,
                "FINDING: historical read at {} diverges after restart\n frame: {frame}",
                c.at
            );
        }
    }
    check_all_docs(&shadow, &mut state);
    check_links(&shadow, &mut state, LinkScope::All);
    sd2.shutdown();

    println!(
        "props case: {} ops ({} writes, {} retries, {} forbidden), {} captured positions, \
         {} doc checks, {} link checks, head {}",
        plan.len(),
        state.n_writes,
        state.n_retries,
        state.n_forbidden,
        state.captures.len(),
        state.n_doc_checks,
        state.n_link_checks,
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
