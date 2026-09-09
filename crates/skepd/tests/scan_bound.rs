//! THE CLASS-SCAN BOUND over the wire (PUB round 2, lane 3.7; PUB-8.36,
//! PUB-8.37): `/op` admits at most two LINK-STORE-WALKING reads at once —
//! the FTT family, the region family, `delete_orphans` and the three claims
//! reads, which as M7 is built each scan the whole store however their slots
//! are spelled — and refuses the surplus at once with `503 scan_busy`, the
//! body naming the op. A concurrency bound, never a rate statement; one
//! global pool for every class, session and the guest; disjoint from the
//! reconstruction pool; never a change to an answer.
//!
//! In `history.rs`'s permit-test form (`op_at_reconstruction_is_permit_bounded`):
//! a real class scan over a test-sized world finishes in microseconds, so
//! true concurrency cannot be raced from the wire — the permits are pinned
//! through the daemon's doc(hidden) test hook (holding one is exactly what
//! an in-flight scan holds) and the counter accounting is asserted beside
//! the wire's busy answer.
//!
//! The fixture is `read_surface.rs`'s claimed board (PUBLISHED-BORN doc 1
//! holding the ceremony's credential links), plus one private draft of the
//! claimant's and one grant to a stranger deposited from the claimant's
//! signed session — so PUB-6.54's grant-coverage directory, `{ty: T_grant,
//! home/from/to: any}`, is the class scan under test, and it answers exactly
//! the one grant to every class (grants are born published in doc 1).

mod common;

use common::*;
use serde_json::Value;

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

/// The unit span at `addr` — `enc([addr])`'s shape: `start` the address,
/// `width` one at its own depth — as a one-span slot array.
fn unit_span(addr: &str) -> String {
    let depth = addr.split('.').count();
    let width = format!("{}1", "0.".repeat(depth - 1));
    format!(r#"[{{"start":"{addr}","width":"{width}"}}]"#)
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

/// The region-keyed discovery read over content ordinal 1 of `doc` — THREE
/// whole-store scans, one per v1 link slot, so it is bounded too.
fn find_links_v(doc: &str) -> String {
    format!(r#"{{"d":"{doc}","op":"find_links_v","region":[{{"start":"1.1","width":"0.1"}}]}}"#)
}

/// The region-keyed census over content ordinal 1 of `doc`.
fn count_v(doc: &str) -> String {
    format!(r#"{{"d":"{doc}","op":"count_v","region":[{{"start":"1.1","width":"0.1"}}]}}"#)
}

/// The region-keyed endset read over content ordinal 1 of `doc`.
fn retrieve_endsets(doc: &str) -> String {
    format!(
        r#"{{"d":"{doc}","op":"retrieve_endsets","region":[{{"start":"1.1","width":"0.1"}}]}}"#
    )
}

/// The orphan PREVIEW of deleting `doc`'s first content position — six
/// whole-store scans, and no owner gate (M8 answers alike for every asker).
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

/// The documented refusal: `503`, `error: scan_busy`, the `op` named, and a
/// TRANSPORT body — no `resp`, no `code` — exactly as `history_busy` is a
/// transport refusal.
fn assert_scan_busy(st: u16, v: &Value, op: &str) {
    assert_eq!(st, 503, "a saturated scan pool answers 503 at once: {v}");
    assert_eq!(v["error"].as_str(), Some("scan_busy"), "{v}");
    assert_eq!(v["op"].as_str(), Some(op), "the refusal names the op it refused: {v}");
    assert!(v.get("resp").is_none(), "a transport refusal is not an operation response: {v}");
    assert!(v.get("code").is_none(), "no Op ran, so there is no rejection code: {v}");
}

/// §1 the OP TEST and §2 BOUND together, observed from the wire: with both
/// permits held, a frame is refused `scan_busy` iff its op walks the link
/// store. Every FTT spelling is — `ty`-only, all-`any`, `home`-only, and a
/// SECOND slot constrained, which the slot-keyed predecessor exempted though
/// it is that same scan plus a comparison per link — and so is the region
/// family, `delete_orphans` and the claims pair. `image`, the pointwise
/// near-neighbour of `find_links_v`, and `read_link` are not, and serve as if
/// nothing were held. Every probe serves with the pool free, before and after.
#[test]
fn every_link_store_walking_read_takes_a_scan_permit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = seed(port);
    let grant_class = unit_span(T_GRANT);
    let doc1 = unit_span(CLAIMANT_DOC1);

    // (op name, frame, walks the link store?)
    let probes: Vec<(&str, String, bool)> = vec![
        ("find_links_ftt", find_links_ftt(ANY, ANY, ANY, &grant_class), true),
        // A SECOND slot constrained: `ty` narrows the candidate set to one
        // class only if something indexes it, and nothing does — M7's `stab`
        // is a brute scan of `links` — so this is the row above plus a span
        // comparison per link, and strictly dearer.
        ("find_links_ftt", find_links_ftt(&doc1, ANY, ANY, &grant_class), true),
        ("find_links_ftt", find_links_ftt(ANY, ANY, ANY, ANY), true),
        // A four-set constraining `home` ALONE: `home` is not a link slot, so
        // M7 is handed no constraint and takes the whole active slice — the
        // all-`any` candidate set, plus a residence test per link.
        ("find_links_ftt", find_links_ftt(&doc1, ANY, ANY, ANY), true),
        ("count_ftt", count_ftt(&grant_class), true),
        ("count_ftt", count_ftt_slots(ANY, &doc1, ANY, &grant_class), true),
        ("window_ftt", window_ftt(&grant_class), true),
        // The region family: THREE scans apiece (`stab_runs_by_slot` stabs
        // `from`, `to` and `ty` separately), at up to `MAX_IMAGE_RUNS` query
        // spans per link.
        ("find_links_v", find_links_v(CLAIMANT_DOC1), true),
        ("count_v", count_v(CLAIMANT_DOC1), true),
        ("retrieve_endsets", retrieve_endsets(CLAIMANT_DOC1), true),
        // Six scans, and no owner gate: every asker reaches it.
        ("delete_orphans", delete_orphans(CLAIMANT_DOC1), true),
        // One scan apiece, at a single-span query, behind a residence gate.
        ("in_claims", in_claims(&board.grant), true),
        ("out_claims", out_claims(&board.grant), true),
        // …and the reads that walk no link store, which is what keeps the
        // bound from reading as "every discovery read": M5's resolve, and a
        // lookup.
        ("image", image(CLAIMANT_DOC1), false),
        ("read_link", format!(r#"{{"a":"{}","op":"read_link"}}"#, board.grant), false),
    ];
    let serves = |what: &str| {
        for (name, frame, _) in &probes {
            let (st, v) = post(port, None, frame);
            assert_eq!(st, 200, "{name} serves {what}: {v}");
            assert_ne!(v["resp"].as_str(), Some("rejected"), "{name} {what}: {v}");
        }
    };
    serves("with the pool free");

    // The accounting, directly: 2 acquires succeed, the 3rd fails.
    let daemon = sd.daemon();
    let p1 = daemon.try_hold_scan_permit().expect("scan permit 1 of 2");
    let p2 = daemon.try_hold_scan_permit().expect("scan permit 2 of 2");
    assert!(daemon.try_hold_scan_permit().is_none(), "the class-scan pool is exactly 2");

    for (name, frame, class_scan) in &probes {
        let (st, v) = post(port, None, frame);
        if *class_scan {
            assert_scan_busy(st, &v, name);
        } else {
            assert_eq!(st, 200, "{name} walks no link store and takes no permit: {v}");
            assert_ne!(v["resp"].as_str(), Some("rejected"), "{name}: {v}");
        }
    }

    drop(p1);
    drop(p2);
    serves("once the permits are released");
    sd.shutdown();
}

/// §2 BOUND: two permits held → a third scan answers `503 scan_busy` with
/// the op named — N+1 at once, none queuing; a `ty`+`home` query is refused
/// too, being the same scan plus a comparison per link; `/op-at` still
/// answers (disjoint pools); and, conversely, every reconstruction permit
/// held → a live scan still answers while `/op-at` is the one refused. A
/// wire call returns its permit: the slot is reusable afterwards.
#[test]
fn a_third_class_scan_is_refused_and_the_two_pools_are_disjoint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let board = seed(port);
    let scan = grant_directory();
    let narrowed = find_links_ftt(&unit_span(CLAIMANT_DOC1), ANY, ANY, &unit_span(T_GRANT));
    let head = head_of(port);
    let at_head = format!(r#"{{"at":{head},"frame":{scan}}}"#);
    let expect = vec![board.grant.clone()];

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
        assert_scan_busy(*st, &json(body), "find_links_ftt");
        // The documented bytes, exactly (canonical key order).
        assert_eq!(
            String::from_utf8_lossy(body),
            r#"{"detail":"all class-scan permits are in use; retry shortly","error":"scan_busy","op":"find_links_ftt"}"#
        );
    }

    // A second slot constrained is refused TOO, and this is the cell the
    // slot-keyed predecessor exempted: `home` beside `ty` is the `ty` scan
    // plus a residence test per survivor, so it costs strictly more and used
    // to take no permit at all. Nothing narrows it, M7 owning no index for a
    // slot to be pinned against.
    let (st, v) = post(port, None, &narrowed);
    assert_scan_busy(st, &v, "find_links_ftt");

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
        assert_scan_busy(st, &v, "find_links_ftt");
        assert!(v.get("detail").is_some(), "{who}: the detail rides every refusal: {v}");
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
    assert_scan_busy(st, &v, "find_links_ftt");
    drop(p2);
    drop(p3);

    sd.shutdown();
}
