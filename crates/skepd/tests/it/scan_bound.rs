//! THE CLASS-SCAN BOUND over the wire (PUB round 2, lane 3.7; PUB-8.36,
//! PUB-8.37; the home-index record's D3 and D4; skep #651): `/op` bounds the
//! link-discovery reads by two pools. The CLASS pool admits at most two
//! class scans at once — the four-sets whose SHAPE is world-sized: `ty`
//! alone, nothing at all, or a `home` at an account or the node — and the
//! PER-DOCUMENT pool admits at most two region reads of one document at once
//! — the region family and `delete_orphans`, keyed by the `d` their frame
//! names — inside a ceiling of six across every document. Every other link
//! read takes no permit. The surplus is refused with `503 scan_busy` — a
//! class scan and a read past the ceiling at once, a region read whose
//! document holds its width once a bounded wait for one of its permits ends
//! (D3 (b)) — the body naming the op and, in `detail`, the bound that
//! refused — one fixed sentence each. A concurrency bound, never a rate
//! statement; the pools the board's, for every class, session and the guest;
//! disjoint from the reconstruction pool and from each other; never a change
//! to an answer.
//!
//! In `history.rs`'s permit-test form (`op_at_reconstruction_is_permit_bounded`):
//! a real link read over a test-sized world finishes in microseconds, so
//! true concurrency cannot be raced from the wire — the permits are pinned
//! through the daemon's doc(hidden) test hooks (holding one is exactly what
//! an in-flight read holds) and the counter accounting is asserted beside
//! the wire's busy answer.
//!
//! The fixture is `read_surface.rs`'s claimed board (PUBLISHED-BORN doc 1
//! holding the ceremony's credential links), plus one private draft of the
//! claimant's and one grant to a stranger deposited from the claimant's
//! signed session — so PUB-6.54's grant-coverage directory, `{ty: T_grant,
//! home/from/to: any}`, is the class scan under test, and it answers exactly
//! the one grant to every class (grants are born published in doc 1).

use crate::common;

use common::*;
use serde_json::Value;
use skep_address::{validate, Address, Nat, Tumbler};

/// The claimed board with one draft and one grant.
struct Board {
    /// The claimant's bare session — the OWNER class.
    owner: String,
    /// A private draft of the claimant's, holding "d" at ordinal 1.
    draft: String,
    /// A stranger's session — the grantee, a bound principal.
    b: String,
    /// The grant link's address, in the claimant's published doc 1.
    grant: String,
}

fn seed(port: u16) -> Board {
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = acked_addr(&op(
        port,
        Some(&owner),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    ));
    expect_resp(
        &op(
            port,
            Some(&owner),
            &format!(
                r#"{{"op":"insert","doc":"{draft}","at":{{"subspace":"1","ordinal":"1"}},"values":["d"]}}"#
            ),
        ),
        "ack_addr",
    );
    // A stranger under node 1, delegated from the bootstrap principal.
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let b_account =
        expect_resp(&v, "maybe_addr")["addr"].as_str().expect("a delegable prefix").to_string();
    expect_resp(
        &op(
            port,
            Some(&boot),
            &format!(r#"{{"op":"delegate","new_prefix":"{b_account}","new_id":905}}"#),
        ),
        "ack_addr",
    );
    let b = open_session(port, 905);
    // The grant: the draft to B, from the claimant's SIGNED session into its
    // published doc 1 (the shared helper, lane 3.3c).
    let grant = deposit_grant(port, &signed, CLAIMANT_DOC1, &draft, Some(&b_account));
    Board { owner, draft, b, grant }
}

/// The wildcard slot, as the wire spells it.
const ANY: &str = r#""any""#;

/// The refusal's `detail`, one fixed sentence per bound — the three §Link
/// discovery reads quotes: the class pool's, a document's width's and the
/// ceiling's.
const CLASS_BUSY: &str = "all class-scan permits are in use; retry shortly";
const DOCUMENT_BUSY: &str = "all region-read permits of this document are in use; retry shortly";
const CEILING_BUSY: &str =
    "all region-read permits across every document are in use; retry shortly";

/// The per-document pool's waiting slots, as §Link discovery reads spells
/// them (**`MAX_REGION_READ_WAITERS` = 2**): the daemon's crate-private
/// constant, held to that page by the scan module's own unit test. A
/// waiting slot is no permit a hook can take — it is a region read's worker
/// parked for its bounded wait — so the minimum's drain counts it in by
/// figure.
const REGION_READ_WAITERS: usize = 2;

/// The unit span at `addr` — `enc([addr])`'s shape: `start` the address,
/// `width` one at its own depth — as a one-span slot array.
fn unit_span(addr: &str) -> String {
    let depth = addr.split('.').count();
    let width = format!("{}1", "0.".repeat(depth - 1));
    format!(r#"[{{"start":"{addr}","width":"{width}"}}]"#)
}

/// `addr` as the daemon's own address type, for the per-document pool's
/// hook, which is keyed as the pool is.
fn address(addr: &str) -> Address {
    let comps = addr.split('.').map(|c| Nat::from(c.parse::<u64>().expect("a component")));
    validate(Tumbler::new(comps).expect("nonempty")).expect("a valid address")
}

/// A `find_links_ftt` frame over the four slots as given (each already
/// JSON: `ANY`, `"empty"`, or a span array).
fn find_links_ftt(home: &str, from: &str, to: &str, ty: &str) -> String {
    format!(r#"{{"op":"find_links_ftt","q":{{"from":{from},"home":{home},"to":{to},"ty":{ty}}}}}"#)
}

/// The `ty`-only census form.
fn count_ftt(ty: &str) -> String {
    count_ftt_slots(ANY, ANY, ANY, ty)
}

/// A `count_ftt` frame over the four slots as given — the census twin of
/// [`find_links_ftt`], so the home-only and second-slot spellings can be
/// probed on the counting form too.
fn count_ftt_slots(home: &str, from: &str, to: &str, ty: &str) -> String {
    format!(r#"{{"op":"count_ftt","q":{{"from":{from},"home":{home},"to":{to},"ty":{ty}}}}}"#)
}

/// The `ty`-only windowed form, from the start.
fn window_ftt(ty: &str) -> String {
    format!(
        r#"{{"cur":null,"n":16,"op":"window_ftt","q":{{"from":"any","home":"any","to":"any","ty":{ty}}}}}"#
    )
}

/// The region-keyed discovery read over content ordinal 1 of `doc` — the
/// homes touching the region at the three v1 slots, their readable links —
/// a region read, so it draws on `doc`'s per-document pool.
fn find_links_v(doc: &str) -> String {
    format!(r#"{{"d":"{doc}","op":"find_links_v","region":[{{"start":"1.1","width":"0.1"}}]}}"#)
}

/// The region-keyed census over content ordinal 1 of `doc`.
fn count_v(doc: &str) -> String {
    format!(r#"{{"d":"{doc}","op":"count_v","region":[{{"start":"1.1","width":"0.1"}}]}}"#)
}

/// The region-keyed window over content ordinal 1 of `doc`, from the start.
fn window_v(doc: &str) -> String {
    format!(
        r#"{{"cur":null,"d":"{doc}","n":16,"op":"window_v","region":[{{"start":"1.1","width":"0.1"}}]}}"#
    )
}

/// The region-keyed count by home over content ordinal 1 of `doc`, a budget
/// of sixty-four and no home excepted — a region read, keyed by `doc`.
fn count_v_by_home(doc: &str) -> String {
    format!(
        r#"{{"d":"{doc}","except":[],"n":64,"op":"count_v_by_home","region":[{{"start":"1.1","width":"0.1"}}]}}"#
    )
}

/// The region-keyed retracted-links read over content ordinal 1 of `doc`,
/// from the start — a region read, keyed by `doc`, whatever its view.
fn find_links_v_history(doc: &str) -> String {
    format!(
        r#"{{"cur":null,"d":"{doc}","n":16,"op":"find_links_v_history","region":[{{"start":"1.1","width":"0.1"}}]}}"#
    )
}

/// The region-keyed endset read over content ordinal 1 of `doc`.
fn retrieve_endsets(doc: &str) -> String {
    format!(
        r#"{{"d":"{doc}","op":"retrieve_endsets","region":[{{"start":"1.1","width":"0.1"}}]}}"#
    )
}

/// The orphan PREVIEW of deleting `doc`'s first content position — the
/// deleted and the retained runs' homes in one walk, and no owner gate (M8
/// answers alike for every asker) — a region read, keyed by `doc`.
fn delete_orphans(doc: &str) -> String {
    format!(
        r#"{{"d":"{doc}","op":"delete_orphans","p":{{"subspace":"1","ordinal":"1"}},"width":"1"}}"#
    )
}

/// The supersession claims naming `link` as their `old` endpoint.
fn in_claims(link: &str) -> String {
    format!(r#"{{"op":"in_claims","view":"default","y":"{link}"}}"#)
}

/// The supersession claims naming `link` as their `new` endpoint.
fn out_claims(link: &str) -> String {
    format!(r#"{{"op":"out_claims","view":"default","x":"{link}"}}"#)
}

/// The edition claims on `doc`.
fn edition_claims(doc: &str) -> String {
    format!(r#"{{"op":"edition_claims","target":"{doc}"}}"#)
}

/// The pointwise V→I image over `doc` — M5's `resolve` alone, so it walks no
/// link store and takes no permit. The near neighbour of [`find_links_v`],
/// and the row that keeps the bound from reading as "every discovery read".
fn image(doc: &str) -> String {
    format!(r#"{{"d":"{doc}","op":"image","region":[{{"start":"1.1","width":"0.1"}}]}}"#)
}

/// PUB-6.54's directory: the grants class, no other slot constrained.
fn grant_directory() -> String {
    find_links_ftt(ANY, ANY, ANY, &unit_span(T_GRANT))
}

/// One `/op` exchange as `token` (`None` = the guest): the status and the
/// body, whatever the status — `common::op` insists on 200.
fn post(port: u16, token: Option<&str>, frame: &str) -> (u16, Value) {
    let (st, body) = http(port, "POST", "/op", token, frame.as_bytes());
    (st, json(&body))
}

fn head_of(port: u16) -> u64 {
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200);
    json(&body)["log_position"].as_u64().expect("log_position")
}

fn addrs_of(v: &Value) -> Vec<String> {
    expect_resp(v, "addrs")["addrs"]
        .as_array()
        .expect("addrs")
        .iter()
        .map(|a| a.as_str().expect("an address").to_string())
        .collect()
}

/// The documented refusal: `503`, `error: scan_busy`, the `op` named, the
/// `detail` the sentence of the bound that refused, and a TRANSPORT body —
/// no `resp`, no `code` — exactly as `history_busy` is a transport refusal.
fn assert_scan_busy(st: u16, v: &Value, op: &str, detail: &str) {
    assert_eq!(st, 503, "a saturated pool answers 503: {v}");
    assert_eq!(v["error"].as_str(), Some("scan_busy"), "{v}");
    assert_eq!(v["op"].as_str(), Some(op), "the refusal names the op it refused: {v}");
    assert_eq!(v["detail"].as_str(), Some(detail), "the detail names the bound that refused: {v}");
    assert!(v.get("resp").is_none(), "a transport refusal is not an operation response: {v}");
    assert!(v.get("code").is_none(), "no Op ran, so there is no rejection code: {v}");
}

/// A served answer: `200`, and no rejection.
fn assert_serves(st: u16, v: &Value, what: &str) {
    assert_eq!(st, 200, "{what}: {v}");
    assert_ne!(v["resp"].as_str(), Some("rejected"), "{what}: {v}");
}

/// The pool a probe draws on, if any.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Pool {
    /// The class pool: a class-scan SHAPE.
    Class,
    /// The per-document pool: a region read, keyed by its `d`.
    Document,
    /// No permit at all.
    None,
}

/// §1 the SHAPE TEST and §2 BOUND together, observed from the wire: with
/// both CLASS permits held, a frame is refused `scan_busy` iff its four-set
/// is a class-scan shape — `ty`-only, all-`any`, a `home` at the claimant's
/// ACCOUNT, alone or beside `ty` — and with doc 1's two REGION permits held,
/// iff it is a region read of doc 1, the `detail` the held pool's own
/// sentence either way. A `home` at a DOCUMENT, alone or beside `ty`, two
/// link slots, the lineage pair, `edition_claims`, `image` and `read_link`
/// take no permit and serve under either hold. Every probe serves with both
/// pools free, before and after.
#[test]
fn every_class_scan_takes_a_scan_permit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = seed(port);
    let grant_class = unit_span(T_GRANT);
    let doc1 = unit_span(CLAIMANT_DOC1);
    let account = unit_span(CLAIMANT_ACCOUNT);

    // (op name, frame, the pool it draws on)
    let probes: Vec<(&str, String, Pool)> = vec![
        ("find_links_ftt", find_links_ftt(ANY, ANY, ANY, &grant_class), Pool::Class),
        // A `home` at a DOCUMENT beside `ty`: the home slot drives, and it
        // names one chain — the cell the op-keyed predecessor refused.
        ("find_links_ftt", find_links_ftt(&doc1, ANY, ANY, &grant_class), Pool::None),
        ("find_links_ftt", find_links_ftt(ANY, ANY, ANY, ANY), Pool::Class),
        // A four-set constraining `home` ALONE: at a document, that home's
        // key range and nothing else; at the ACCOUNT, every home under it —
        // the account's whole population, one seek and one test apiece.
        ("find_links_ftt", find_links_ftt(&doc1, ANY, ANY, ANY), Pool::None),
        ("find_links_ftt", find_links_ftt(&account, ANY, ANY, ANY), Pool::Class),
        // `ty` beside an ACCOUNT `home`: the home slot still drives, so the
        // walk is the account's every home with `ty` tested per link of each
        // — it costs the `home`-only walk and a test besides, so it takes the
        // class permit the `home`-only form takes.
        ("find_links_ftt", find_links_ftt(&account, ANY, ANY, &grant_class), Pool::Class),
        // Two link slots: the one naming fewer homes drives off the
        // directory, the request's spans sizing the walk.
        ("find_links_ftt", find_links_ftt(ANY, &doc1, ANY, &grant_class), Pool::None),
        ("count_ftt", count_ftt(&grant_class), Pool::Class),
        ("count_ftt", count_ftt_slots(ANY, &doc1, ANY, &grant_class), Pool::None),
        ("window_ftt", window_ftt(&grant_class), Pool::Class),
        // The region family and the preview: keyed by their `d`.
        ("find_links_v", find_links_v(CLAIMANT_DOC1), Pool::Document),
        ("count_v", count_v(CLAIMANT_DOC1), Pool::Document),
        ("window_v", window_v(CLAIMANT_DOC1), Pool::Document),
        ("count_v_by_home", count_v_by_home(CLAIMANT_DOC1), Pool::Document),
        ("find_links_v_history", find_links_v_history(CLAIMANT_DOC1), Pool::Document),
        ("retrieve_endsets", retrieve_endsets(CLAIMANT_DOC1), Pool::Document),
        ("delete_orphans", delete_orphans(CLAIMANT_DOC1), Pool::Document),
        // The lineage pair and the edition claims answer off the index at the
        // key's own span: no walk of a class, no permit.
        ("in_claims", in_claims(&board.grant), Pool::None),
        ("out_claims", out_claims(&board.grant), Pool::None),
        ("edition_claims", edition_claims(CLAIMANT_DOC1), Pool::None),
        // …and the reads that walk no link store, which is what keeps the
        // bound from reading as "every discovery read": M5's resolve, and a
        // lookup.
        ("image", image(CLAIMANT_DOC1), Pool::None),
        ("read_link", format!(r#"{{"a":"{}","op":"read_link"}}"#, board.grant), Pool::None),
    ];
    let serves = |what: &str| {
        for (name, frame, _) in &probes {
            let (st, v) = post(port, None, frame);
            assert_serves(st, &v, &format!("{name} serves {what}"));
        }
    };
    let under = |held: Pool, what: &str| {
        let detail = match held {
            Pool::Class => CLASS_BUSY,
            Pool::Document => DOCUMENT_BUSY,
            Pool::None => unreachable!("a hold is of one of the two pools"),
        };
        for (name, frame, pool) in &probes {
            let (st, v) = post(port, None, frame);
            if *pool == held {
                assert_scan_busy(st, &v, name, detail);
            } else {
                assert_serves(st, &v, &format!("{name} draws on no {held:?} permit, {what}"));
            }
        }
    };
    serves("with both pools free");

    // The class pool's accounting, directly: 2 acquires succeed, the 3rd
    // fails — and the class scans alone are refused.
    let daemon = sd.daemon();
    let p1 = daemon.try_hold_scan_permit().expect("scan permit 1 of 2");
    let p2 = daemon.try_hold_scan_permit().expect("scan permit 2 of 2");
    assert!(daemon.try_hold_scan_permit().is_none(), "the class pool is exactly 2");
    under(Pool::Class, "with every class permit held");
    drop(p1);
    drop(p2);
    serves("once the class permits are released");

    // Doc 1's width, directly: 2 acquires succeed, the 3rd fails — and the
    // region reads of doc 1 alone are refused.
    let d = address(CLAIMANT_DOC1);
    let r1 = daemon.try_hold_region_permit(&d).expect("region permit 1 of 2 for doc 1");
    let r2 = daemon.try_hold_region_permit(&d).expect("region permit 2 of 2 for doc 1");
    assert!(daemon.try_hold_region_permit(&d).is_none(), "a document's width is exactly 2");
    under(Pool::Document, "with doc 1's region permits held");
    drop(r1);
    drop(r2);
    serves("once the region permits are released");
    sd.shutdown();
}

/// §2 BOUND: two class permits held → a third class scan answers `503
/// scan_busy` with the op named — N+1 at once, none queuing; a `ty` query
/// with a DOCUMENT `home` beside it is admitted and answers the grant, as is
/// one with a link slot beside `ty`, and a `home`-only four-set at the
/// ACCOUNT is refused, the home slot driving every home under it; `/op-at`
/// still answers (disjoint pools); and, conversely, every reconstruction
/// permit held → a live scan still answers while `/op-at` is the one
/// refused. A wire call returns its permit: the slot is reusable afterwards.
#[test]
fn a_third_class_scan_is_refused_and_the_two_pools_are_disjoint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = seed(port);
    let scan = grant_directory();
    let narrowed = find_links_ftt(&unit_span(CLAIMANT_DOC1), ANY, ANY, &unit_span(T_GRANT));
    // Two link slots: the grant's own FROM — the draft it shares — beside
    // its class, so the directory drives and the answer is the grant.
    let two_slots = find_links_ftt(ANY, &unit_span(&board.draft), ANY, &unit_span(T_GRANT));
    let account_homed = find_links_ftt(&unit_span(CLAIMANT_ACCOUNT), ANY, ANY, ANY);
    let head = head_of(port);
    let at_head = format!(r#"{{"at":{head},"frame":{scan}}}"#);
    let expect = vec![board.grant.clone()];
    // The two-link-slot query's answer with the pool free — what the same
    // frame must answer under the hold, the bound altering no answer.
    let (st, two_slots_free) = post(port, None, &two_slots);
    assert_serves(st, &two_slots_free, "a two-link-slot query with the pool free");

    let daemon = sd.daemon();
    let p1 = daemon.try_hold_scan_permit().expect("scan permit 1 of 2");
    let p2 = daemon.try_hold_scan_permit().expect("scan permit 2 of 2");
    assert!(daemon.try_hold_scan_permit().is_none(), "the class-scan pool is exactly 2");

    // N+1 concurrent class scans while both slots are held: every one is
    // answered 503 scan_busy at once — none queues behind another.
    let answers: Vec<(u16, Vec<u8>)> = std::thread::scope(|s| {
        let handles: Vec<_> =
            (0..3).map(|_| s.spawn(|| http(port, "POST", "/op", None, scan.as_bytes()))).collect();
        handles.into_iter().map(|jh| jh.join().expect("scan caller thread")).collect()
    });
    for (st, body) in &answers {
        assert_scan_busy(*st, &json(body), "find_links_ftt", CLASS_BUSY);
        // The documented bytes, exactly (canonical key order).
        assert_eq!(
            String::from_utf8_lossy(body),
            r#"{"detail":"all class-scan permits are in use; retry shortly","error":"scan_busy","op":"find_links_ftt"}"#
        );
    }

    // A DOCUMENT `home` beside `ty` is admitted with every class permit held
    // — the cell the op-keyed bound refused: the home slot drives, and a
    // document's home names one key range, the grant's, so the read costs
    // that chain and nothing the board sets. The wire's sentence holds of
    // the build: a second slot constrained is no class scan.
    let (st, v) = post(port, None, &narrowed);
    assert_serves(st, &v, "a document-homed `ty` query takes no class permit");
    assert_eq!(addrs_of(&v), expect, "and answers the grant, byte for byte the unbounded answer");
    let (st, v) = post(port, None, &two_slots);
    assert_serves(st, &v, "a two-link-slot query takes no class permit");
    assert_eq!(v, two_slots_free, "the directory drives, and the answer is the unbounded one");
    assert_eq!(addrs_of(&v), expect, "the grant, whose FROM is the draft");
    // …while a `home`-only four-set at the ACCOUNT is refused: the home slot
    // drives every home under the account, the account's whole population.
    let (st, v) = post(port, None, &account_homed);
    assert_scan_busy(st, &v, "find_links_ftt", CLASS_BUSY);

    // DISJOINT: with every scan permit held, `/op-at` — a reconstruction —
    // still answers the same frame, and so does `/dump?at`.
    let (st, body) = http(port, "POST", "/op-at", None, at_head.as_bytes());
    assert_eq!(st, 200, "a historical scan spends no scan permit: {}", String::from_utf8_lossy(&body));
    assert_eq!(addrs_of(&json(&body)), expect);
    #[cfg(feature = "observe")]
    {
        let (st, _body) = get(port, &format!("/dump?at={head}"));
        assert_eq!(st, 200, "/dump?at rides the reconstruction pool alone");
    }

    // Releasing one slot restores service, and the wire call returns its
    // permit: the slot is reusable afterwards.
    drop(p1);
    let (st, v) = post(port, None, &scan);
    assert_eq!(st, 200, "{v}");
    assert_eq!(addrs_of(&v), expect);
    let p3 = daemon.try_hold_scan_permit().expect("the wire call released its permit");
    assert!(daemon.try_hold_scan_permit().is_none(), "still exactly one slot came back");
    drop(p2);
    drop(p3);

    // Conversely: every reconstruction permit held → a live class scan still
    // answers, and `/op-at` is the one refused — with ITS code.
    let mut held = Vec::new();
    while let Some(p) = daemon.try_hold_reconstruction_permit() {
        held.push(p);
    }
    assert!(!held.is_empty(), "the daemon has a reconstruction budget to exhaust");
    let (st, v) = post(port, None, &scan);
    assert_eq!(st, 200, "a class scan spends no reconstruction permit: {v}");
    assert_eq!(addrs_of(&v), expect);
    let (st, body) = http(port, "POST", "/op-at", None, at_head.as_bytes());
    assert_eq!(st, 503, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["error"].as_str(), Some("history_busy"), "the other pool's own code");
    drop(held);

    sd.shutdown();
}

/// §2 THE PER-DOCUMENT POOL (D3, D4; skep #651): doc 1's two region permits
/// held → every region read of doc 1 — `find_links_v`, `count_v`,
/// `window_v`, `count_v_by_home`, `retrieve_endsets`, `delete_orphans` — answers `503
/// scan_busy` with the op named and the width's sentence in `detail`, while
/// a region read of the claimant's DRAFT is admitted and answers (one page's
/// readers contend among themselves) and the grant directory is admitted
/// (the class pool is disjoint). Six held across three documents → a read of
/// a fourth is refused by the ceiling, its `detail` the ceiling's sentence,
/// and admitted again as soon as one of the six is returned; a wire call
/// returns its permit; with every region permit held the class pool is
/// whole, and with every class permit held a region read is admitted.
#[test]
fn a_documents_region_reads_contend_only_among_themselves() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = seed(port);
    let daemon = sd.daemon();
    let doc1 = address(CLAIMANT_DOC1);
    let draft = address(&board.draft);
    let expect = vec![board.grant.clone()];
    // The draft's region read with every pool free — doc 1's links reach
    // the draft's first position, the grant's coverage among them — which is
    // what the same frame must answer under every hold below.
    let (st, draft_free) = post(port, Some(&board.owner), &find_links_v(&board.draft));
    assert_serves(st, &draft_free, "the draft's region read with every pool free");
    assert!(addrs_of(&draft_free).contains(&board.grant), "the grant covers the draft: {draft_free}");

    // Doc 1's width, as two in-flight reads of it hold it.
    let r1 = daemon.try_hold_region_permit(&doc1).expect("doc 1's region permit 1 of 2");
    let r2 = daemon.try_hold_region_permit(&doc1).expect("doc 1's region permit 2 of 2");
    assert!(daemon.try_hold_region_permit(&doc1).is_none(), "a document's width is exactly 2");

    // Every region read of doc 1 is refused once its bounded wait for one of
    // doc 1's permits ends, none queuing past it: the permits stay held.
    for (name, frame) in [
        ("find_links_v", find_links_v(CLAIMANT_DOC1)),
        ("count_v", count_v(CLAIMANT_DOC1)),
        ("window_v", window_v(CLAIMANT_DOC1)),
        ("count_v_by_home", count_v_by_home(CLAIMANT_DOC1)),
        ("retrieve_endsets", retrieve_endsets(CLAIMANT_DOC1)),
        ("delete_orphans", delete_orphans(CLAIMANT_DOC1)),
    ] {
        let (st, v) = post(port, None, &frame);
        assert_scan_busy(st, &v, name, DOCUMENT_BUSY);
    }
    // The documented bytes of a width's refusal, exactly (canonical key
    // order): it is the page that is busy, and the detail says so.
    let (_, body) = http(port, "POST", "/op", None, find_links_v(CLAIMANT_DOC1).as_bytes());
    assert_eq!(
        String::from_utf8_lossy(&body),
        format!(r#"{{"detail":"{DOCUMENT_BUSY}","error":"scan_busy","op":"find_links_v"}}"#)
    );
    // …while the draft — another page, read by the one reader who may —
    // is admitted and answers: its readers never meet doc 1's.
    let (st, v) = post(port, Some(&board.owner), &find_links_v(&board.draft));
    assert_serves(st, &v, "a region read of another document is admitted");
    assert_eq!(v, draft_free, "and answers what it answers unbounded");
    // …and the class pool is untouched: the grant directory answers.
    let (st, v) = post(port, None, &grant_directory());
    assert_serves(st, &v, "a class scan spends no region permit");
    assert_eq!(addrs_of(&v), expect);

    // THE CEILING: six across three documents — the two further documents
    // need not exist, the key is the frame's `d` — and the draft, a fourth,
    // is refused though it holds none of its own two.
    let x = address("1.0.1.0.7");
    let y = address("1.0.1.0.8");
    let x1 = daemon.try_hold_region_permit(&x).expect("X's region permit 1 of 2");
    let x2 = daemon.try_hold_region_permit(&x).expect("X's region permit 2 of 2");
    let y1 = daemon.try_hold_region_permit(&y).expect("Y's region permit 1 of 2");
    let y2 = daemon.try_hold_region_permit(&y).expect("Y's region permit 2 of 2");
    assert!(daemon.try_hold_region_permit(&draft).is_none(), "the ceiling is exactly 6");
    let (st, v) = post(port, Some(&board.owner), &find_links_v(&board.draft));
    assert_scan_busy(st, &v, "find_links_v", CEILING_BUSY);
    // The documented bytes of the ceiling's refusal, exactly: the draft holds
    // none of its own two, so it is the board that is busy, and the detail
    // says so.
    let (st, body) =
        http(port, "POST", "/op", Some(&board.owner), count_v(&board.draft).as_bytes());
    assert_scan_busy(st, &json(&body), "count_v", CEILING_BUSY);
    assert_eq!(
        String::from_utf8_lossy(&body),
        format!(r#"{{"detail":"{CEILING_BUSY}","error":"scan_busy","op":"count_v"}}"#)
    );
    // Disjoint, the other way: every region permit held, the class pool is
    // whole — both class permits can be taken, and the directory answers.
    let c1 = daemon.try_hold_scan_permit().expect("class permit 1 of 2 with every region permit held");
    let c2 = daemon.try_hold_scan_permit().expect("class permit 2 of 2 with every region permit held");
    drop(c1);
    drop(c2);
    let (st, v) = post(port, None, &grant_directory());
    assert_serves(st, &v, "a class scan with every region permit held");
    assert_eq!(addrs_of(&v), expect);

    // One of the six returned: the draft's read is admitted, answers, and
    // returns its permit — the slot is reusable afterwards.
    drop(x1);
    let (st, v) = post(port, Some(&board.owner), &find_links_v(&board.draft));
    assert_serves(st, &v, "a region read fits the slot the ceiling got back");
    assert_eq!(v, draft_free, "and answers what it answers unbounded");
    let x3 = daemon.try_hold_region_permit(&x).expect("the wire call released its ceiling slot");
    assert!(daemon.try_hold_region_permit(&draft).is_none(), "and exactly one slot came back");

    // Conversely: every class permit held, a region read is admitted.
    drop((x2, x3, y1, y2));
    let c1 = daemon.try_hold_scan_permit().expect("class permit 1 of 2");
    let c2 = daemon.try_hold_scan_permit().expect("class permit 2 of 2");
    let (st, v) = post(port, Some(&board.owner), &find_links_v(&board.draft));
    assert_serves(st, &v, "a region read spends no class permit");
    let (st, v) = post(port, None, &grant_directory());
    assert_scan_busy(st, &v, "find_links_ftt", CLASS_BUSY);
    drop((c1, c2));

    // Doc 1's width returned: its reads serve again.
    drop((r1, r2));
    for frame in [find_links_v(CLAIMANT_DOC1), delete_orphans(CLAIMANT_DOC1)] {
        let (st, v) = post(port, None, &frame);
        assert_serves(st, &v, "a region read of doc 1 once its permits are released");
    }
    sd.shutdown();
}

/// §2 RELEASE: a scan the read predicate filters to EMPTY — the guest
/// scanning a class whose every home is a draft (an empty `addrs`, never
/// `withheld`: no document argument is named) — returns its permit, as
/// does one M8 annihilates before M7 is asked (`ty: "empty"`); after each
/// answer the pool is full again.
#[test]
fn a_scan_filtered_to_empty_returns_its_permit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = seed(port);

    // A link homed in the private draft whose TYPE is the draft's own
    // content: the class it founds has no member homed anywhere a guest can
    // read. FROM reaches the published doc 1 (readable to the owner, so the
    // source gate passes); TO and TYPE reach the draft's own ordinal 1.
    let pos1 = |doc: &str| {
        format!(r#"[{{"source":"{doc}","span":{{"start":"1.1","width":"0.1"}}}}]"#)
    };
    let link = acked_addr(&op(
        port,
        Some(&board.owner),
        &format!(
            r#"{{"op":"make_link","home":"{home}","from":{from},"to":{to},"ty":{ty}}}"#,
            home = board.draft,
            from = pos1(CLAIMANT_DOC1),
            to = pos1(&board.draft),
            ty = pos1(&board.draft),
        ),
    ));
    // The class: the draft's I-address at content ordinal 1 (its first mint).
    let class = unit_span(&format!("{}.0.1.1", board.draft));
    let scan = find_links_ftt(ANY, ANY, ANY, &class);

    // The owner's scan holds the link; the guest's is EMPTY — dropped at
    // link-home identity (PUB-6.13), never withheld.
    let (st, v) = post(port, Some(&board.owner), &scan);
    assert_eq!(st, 200, "{v}");
    assert_eq!(addrs_of(&v), vec![link.clone()], "the owner reads the draft-homed class");
    let (st, v) = post(port, None, &scan);
    assert_eq!(st, 200, "{v}");
    assert_eq!(
        expect_resp(&v, "addrs")["addrs"],
        Value::Array(vec![]),
        "the guest's scan is filtered to empty, not withheld: {v}"
    );

    // …and the pool is full again: both permits are back.
    let daemon = sd.daemon();
    let full_again = |what: &str| {
        let a = daemon.try_hold_scan_permit().unwrap_or_else(|| panic!("{what}: permit 1 of 2 back"));
        let b = daemon.try_hold_scan_permit().unwrap_or_else(|| panic!("{what}: permit 2 of 2 back"));
        assert!(daemon.try_hold_scan_permit().is_none(), "{what}: the pool is exactly full again");
        drop(a);
        drop(b);
    };
    full_again("after the filtered-to-empty answer");

    // The annihilated form: class-scan-shaped, answered off its own slots
    // before M7 is asked, its permit back a moment later.
    let (st, v) = post(port, None, &find_links_ftt(ANY, ANY, ANY, r#""empty""#));
    assert_eq!(st, 200, "{v}");
    assert_eq!(expect_resp(&v, "addrs")["addrs"], Value::Array(vec![]), "{v}");
    let (st, v) = post(port, None, &count_ftt(r#""empty""#));
    assert_eq!(st, 200, "{v}");
    assert_eq!(expect_resp(&v, "count")["n"].as_u64(), Some(0), "{v}");
    full_again("after the annihilated answers");

    sd.shutdown();
}

/// §4 BYTES: a class scan's answer under the bound equals the answer the
/// same frame gives unbounded — with a slot held, with none held, and on
/// the path that takes no scan permit at all (`/op-at` at the head) — byte
/// for byte. The directory itself (PUB-6.54) answers exactly the grant.
#[test]
fn an_admitted_scan_answers_byte_for_byte_the_unbounded_answer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = seed(port);
    let scan = grant_directory();

    // Nothing held: the grant-coverage directory is the one grant.
    let (st, free) = http(port, "POST", "/op", None, scan.as_bytes());
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&free));
    assert_eq!(addrs_of(&json(&free)), vec![board.grant.clone()]);

    // One slot held: the same bytes — the bound admits or refuses, and never
    // alters an answer.
    let daemon = sd.daemon();
    let held = daemon.try_hold_scan_permit().expect("one slot held");
    let (st, under) = http(port, "POST", "/op", None, scan.as_bytes());
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&under));
    assert_eq!(
        under,
        free,
        "the bound altered an answer:\n free  {}\n under {}",
        String::from_utf8_lossy(&free),
        String::from_utf8_lossy(&under)
    );
    drop(held);

    // The path that takes no scan permit — `/op-at` at the head — answers
    // the same bytes: the oracle cell, per class.
    let head = head_of(port);
    let env = format!(r#"{{"at":{head},"frame":{scan}}}"#);
    for token in [None, Some(board.owner.as_str())] {
        let (st, live) = http(port, "POST", "/op", token, scan.as_bytes());
        assert_eq!(st, 200);
        let (st, hist) = http(port, "POST", "/op-at", token, env.as_bytes());
        assert_eq!(st, 200, "{}", String::from_utf8_lossy(&hist));
        assert_eq!(
            live,
            hist,
            "the bounded live scan and the unbounded historical one differ:\n live {}\n hist {}",
            String::from_utf8_lossy(&live),
            String::from_utf8_lossy(&hist)
        );
    }

    // Two bounded scans in a row: byte-identical (the permit leaves no mark).
    let (_, again) = http(port, "POST", "/op", None, scan.as_bytes());
    assert_eq!(again, free);

    sd.shutdown();
}

/// §5 CLASS-INVARIANT: the guest, the claimant and a stranger draw on the
/// ONE pool — with the pool free every class is answered the directory
/// alike, with it full every class is refused alike (no per-principal
/// quota, no exemption for the owner), and a slot one class frees is a slot
/// any class may take.
#[test]
fn the_guest_and_the_claimant_draw_on_one_pool() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = seed(port);
    let scan = grant_directory();
    let expect = vec![board.grant.clone()];
    let classes: Vec<(&str, Option<&str>)> = vec![
        ("the guest", None),
        ("the claimant", Some(board.owner.as_str())),
        ("a stranger", Some(board.b.as_str())),
    ];

    for (who, token) in &classes {
        let (st, v) = post(port, *token, &scan);
        assert_eq!(st, 200, "{who}: {v}");
        assert_eq!(addrs_of(&v), expect, "{who} reads the born-published grant class");
    }

    let daemon = sd.daemon();
    let p1 = daemon.try_hold_scan_permit().expect("scan permit 1 of 2");
    let p2 = daemon.try_hold_scan_permit().expect("scan permit 2 of 2");
    for (who, token) in &classes {
        let (st, v) = post(port, *token, &scan);
        assert_scan_busy(st, &v, "find_links_ftt", CLASS_BUSY);
        assert_eq!(
            v["detail"].as_str(),
            Some(CLASS_BUSY),
            "{who}: the one detail rides every class's refusal: {v}"
        );
    }

    // One slot freed: the claimant's scan takes it and returns it; the
    // guest's then takes the same slot — one pool, whoever asks.
    drop(p1);
    let (st, v) = post(port, Some(&board.owner), &scan);
    assert_eq!(st, 200, "the claimant's scan fits the freed slot: {v}");
    assert_eq!(addrs_of(&v), expect);
    let (st, v) = post(port, None, &scan);
    assert_eq!(st, 200, "the guest's scan fits the same slot once returned: {v}");
    assert_eq!(addrs_of(&v), expect);
    let p3 = daemon.try_hold_scan_permit().expect("the slot is back after both");
    let (st, v) = post(port, Some(&board.b), &scan);
    assert_scan_busy(st, &v, "find_links_ftt", CLASS_BUSY);
    drop(p2);
    drop(p3);

    sd.shutdown();
}

/// [`skepd::MIN_WORKERS`] is the caller's half of the obligation [`serve`]
/// states and deliberately does not re-check: leave a worker free of the
/// six permit pools, or a caller INSIDE every bound occupies the whole pool
/// and the daemon answers nothing — `/health` and `/session` included —
/// with every structure inside it healthy (M-I5 (f): the upload pool
/// counted in the same budget as the three before it; `operations.md` §4
/// rows 25, 27: the write pool counted in after it; the home-index record's
/// D4: the per-document pool counted in by its ceiling; its D3 (b): and by
/// its waiting slots, each a region read's worker parked for its bounded
/// wait).
///
/// Named HERE, from outside the library, because that is the whole of what
/// the constant buys: the six pools' counts are crate-private, so before it
/// an embedder was handed a relation over quantities it could not name,
/// evaluate, or watch for change. This test fails to COMPILE if the export
/// is dropped, which is the check the obligation needs.
///
/// The count is then spent as a real `workers` argument and every pool is
/// drained through the daemon's hooks — the permits held together, with the
/// waiting slots no hook can take ([`REGION_READ_WAITERS`]), exactly one
/// short of the minimum, which pins the derivation from outside; the
/// per-document pool drained to its ceiling, two permits each of three
/// documents, the fourth document then refused — so the minimum is pinned
/// as a count `serve` accepts and serves at. What it does not pin is worker
/// OCCUPANCY: as this file's own header says, a scan over a test-sized world
/// finishes in microseconds, and a held permit holds no worker — which is
/// why the pooled-permit relation is a compile-time assertion beside the
/// constant rather than a test here, and why the two occupancy tests hold
/// real upload streams
/// (`blob_routes::trickling_uploads_fill_the_pool_and_never_the_daemon`) and
/// park real writes on the guard (`write_pool.rs`) instead.
#[test]
fn the_minimum_worker_count_is_evaluable_and_serves_with_every_pool_drained() {
    const {
        assert!(
            skepd::MIN_WORKERS > 1,
            "the minimum leaves a worker free of the pools, so it exceeds serve's own floor"
        )
    };
    const {
        assert!(
            skepd::DEFAULT_WORKERS >= skepd::MIN_WORKERS,
            "the shipped default satisfies the obligation it documents"
        )
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let daemon = skepd::Daemon::open(dir.path()).expect("genesis open");
    let sd = skepd::serve(daemon, 0, skepd::MIN_WORKERS).expect("serve at the minimum count");
    let port = sd.port();

    // Every pool drained — the state the obligation is about.
    let mut held: Vec<skepd::Permit<'_>> = Vec::new();
    while let Some(p) = sd.daemon().try_hold_scan_permit() {
        held.push(p);
    }
    while let Some(p) = sd.daemon().try_hold_reconstruction_permit() {
        held.push(p);
    }
    while let Some(p) = sd.daemon().try_hold_fetch_permit() {
        held.push(p);
    }
    while let Some(p) = sd.daemon().try_hold_upload_permit() {
        held.push(p);
    }
    while let Some(p) = sd.daemon().try_hold_write_permit() {
        held.push(p);
    }
    // The per-document pool, to its ceiling: a document's width is two, so
    // three documents drain six, and a fourth is refused by the ceiling.
    let documents = ["1.0.1.0.1", "1.0.1.0.2", "1.0.1.0.3"].map(address);
    let mut region_held = Vec::new();
    for d in &documents {
        while let Some(p) = sd.daemon().try_hold_region_permit(d) {
            region_held.push(p);
        }
    }
    assert!(
        sd.daemon().try_hold_region_permit(&address("1.0.1.0.4")).is_none(),
        "the ceiling is drained: a fourth document finds no slot"
    );
    assert_eq!(
        held.len() + region_held.len() + REGION_READ_WAITERS,
        skepd::MIN_WORKERS - 1,
        "the six pools' permits and the per-document pool's waiting slots together are one \
         short of the minimum"
    );

    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "the liveness probe answers: {}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["ok"].as_bool(), Some(true));

    drop(held);
    drop(region_held);
    sd.shutdown();
}
