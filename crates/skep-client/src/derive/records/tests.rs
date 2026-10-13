use std::sync::Arc;

use serde_json::json;
use skep_identity::{canonical_record, SIG_ALGS};
use skep_signature::HybridSigner;

use super::*;
use crate::board::fake::{self, Fake};

const LINK: &str = "1.0.1.0.1.0.2.7";

/// A board's history over the committed positions `committed`, the
/// genesis at 0 beside them, its retention floor at `floor`, a link
/// committed at `p`: `/op-at` answers as the wire does — `410
/// history_reclaimed` below the floor, `400 not_a_position` naming the
/// nearest position under a gap, and otherwise the discovery, holding
/// the link from `p` on.
fn history(committed: Vec<u64>, floor: Option<u64>, p: u64) -> Arc<Fake> {
    Fake::new(move |req| {
        assert_eq!(req.path, "/op-at", "the bisection reads history alone");
        let at = serde_json::from_slice::<Value>(&req.body).unwrap()["at"].as_u64().unwrap();
        if floor.is_some_and(|f| at < f) {
            return fake::json(410, json!({"error": "history_reclaimed", "floor": floor}));
        }
        if at == 0 || committed.contains(&at) {
            let addrs: Vec<&str> = if at >= p { vec![LINK] } else { Vec::new() };
            return fake::json(200, json!({"addrs": addrs, "as_of": at, "resp": "addrs"}));
        }
        let nearest = committed.iter().copied().filter(|c| *c <= at).max().unwrap_or(0);
        fake::json(400, json!({"error": "not_a_position", "nearest": nearest}))
    })
}

/// THE BISECTION (AUTH-5.68) as a law over generated histories — every
/// gapless history to 20 positions and two with gaps, every position the
/// link commits at, every retention floor or none: the answer is the
/// LEAST position at which the discovery returns the link where that lies
/// above the floor, and NONE where it lies at or below it — an answer,
/// never an exit, and no position asserted (§9 item 50) — in at most
/// 2·⌈log₂ head⌉ + 3 reads.
#[test]
fn the_bisection_finds_the_least_position_and_asserts_none_below_the_floor() {
    let mut histories: Vec<Vec<u64>> = (1..=20).map(|head| (1..=head).collect()).collect();
    histories.push(vec![1, 4, 5, 9, 12]);
    histories.push(vec![2, 3, 7, 8, 15, 16]);
    let frame = frames::find_links_ftt(T_ENROLL, "1.0.1");
    let mut cases = 0;
    for committed in histories {
        let head = *committed.last().unwrap();
        let bound = 2 * u64::from(head.next_power_of_two().trailing_zeros()) + 3;
        for &p in &committed {
            for floor in std::iter::once(None).chain(committed.iter().copied().map(Some)) {
                let fake = history(committed.clone(), floor, p);
                let found = position_of(&fake::board(&fake), &frame, LINK, head).expect("an answer, never an exit");
                let expected = match floor {
                    Some(f) if p <= f => (None, Some(f)),
                    _ => (Some(p), floor),
                };
                assert_eq!(found, expected, "{committed:?}, the link at {p}, the floor at {floor:?}");
                let reads = fake.sent.lock().unwrap().len() as u64;
                assert!(reads <= bound, "{reads} reads past {bound}: {committed:?}, the link at {p}, the floor at {floor:?}");
                cases += 1;
            }
        }
    }
    assert!(cases > 3000, "the family holds {cases} cases");
}

/// Below the retention floor neither a record's position nor its hand is
/// derivable, and the read ASSERTS NEITHER (§9 item 50), reading neither
/// the feed nor the set to try: an unsigned record read position-free,
/// and a signed one whose base is unreadable and which no key of this
/// store verifies, each answer `Unreadable`.
#[test]
fn below_the_floor_no_hand_is_asserted_and_no_read_is_made() {
    let board = fake::board(&Fake::unread());
    let key = |b: u8| HybridSigner::public_key(&crate::sign::signer_from_seed(&[b; 32])).clone();
    let own = [(Fingerprint::of(&key(4)), key(4))];
    let term = Some(BoardTerm { log_position: 12, chain: [7; 32] });
    let unsigned = enrollment("1.0.1.0.1.0.2.1", vec![Enrollment::new(key(1), true, Some("paper".into())).unwrap()]);
    let mut signed = enrollment("1.0.1.0.1.0.2.2", vec![Enrollment::new(key(2), false, Some("phone".into())).unwrap()]);
    // A hybrid blob of a row's width, which no key of this store verifies.
    signed.sig = Some("ab".repeat(SIG_ALGS[0].sig_len()));
    for record in [unsigned, signed] {
        let hand = hand_of(&board, &record, term, &own, None).expect("no read, so no fault");
        assert!(matches!(hand, Hand::Unreadable(_)), "{}: {hand:?}", record.link);
    }
}

/// A `sig` of no row's width — the classical 64 bytes, here — is no hybrid
/// blob (skep-identity's `HybridBlob::parse_hex`), so no key could verify
/// it: its hand is `NoKeyVerifies`, answered before the set as of its base
/// is read, where a blob of a row's width would read that set to try.
#[test]
fn a_sig_of_no_rows_width_is_verified_by_no_key_and_reads_nothing() {
    let board = fake::board(&Fake::unread());
    let key = |b: u8| HybridSigner::public_key(&crate::sign::signer_from_seed(&[b; 32])).clone();
    let own = [(Fingerprint::of(&key(4)), key(4))];
    let term = Some(BoardTerm { log_position: 12, chain: [7; 32] });
    let mut classical = enrollment("1.0.1.0.1.0.2.2", vec![Enrollment::new(key(2), false, None).unwrap()]);
    classical.sig = Some("ab".repeat(64));
    let hand = hand_of(&board, &classical, term, &own, Some(19)).expect("no read, so no fault");
    assert_eq!(hand, Hand::NoKeyVerifies);
}

#[test]
fn addresses_order_by_component() {
    let mut v = vec!["1.0.1.0.1.0.2.10".to_string(), "1.0.1.0.1.0.2.2".to_string()];
    v.sort_by_cached_key(|a| components(a));
    assert_eq!(v, ["1.0.1.0.1.0.2.2", "1.0.1.0.1.0.2.10"]);
}

/// An enrollment record of `entries` at `link`.
fn enrollment(link: &str, entries: Vec<Enrollment>) -> Record {
    let sigless = canonical_record(&entries, None);
    Record {
        kind: Kind::Enroll,
        link: link.into(),
        home: "1.0.1.0.1".into(),
        home_account: "1.0.1".into(),
        subject: "1.0.1".into(),
        atom: format!("{link}.1"),
        bytes: sigless.clone().into_bytes(),
        sigless,
        sig: None,
        enrolled: entries,
        retired: Vec::new(),
        position: None,
        base: None,
        hand: Hand::Bare,
        anchor_grade: false,
    }
}

/// AUTH-5.69 — a key's label is the one on the record that FIRST enrolled
/// it, and `None` — never an empty string — where that record carried
/// none, whatever a later record names it.
#[test]
fn a_label_is_the_first_enrolling_records_and_none_where_it_carried_none() {
    let key = |b: u8| HybridSigner::public_key(&crate::sign::signer_from_seed(&[b; 32])).clone();
    let (labelled, bare) = (key(1), key(2));
    let records = Records {
        account: "1.0.1".into(),
        records: vec![
            enrollment("1.0.1.0.1.0.2.1", vec![Enrollment::new(labelled.clone(), true, Some("paper".into())).unwrap(), Enrollment::new(bare.clone(), false, None).unwrap()]),
            enrollment("1.0.1.0.1.0.2.2", vec![Enrollment::new(bare.clone(), false, Some("named later".into())).unwrap()]),
        ],
        head: 9,
        floor: None,
        claim_entry: None,
        claimed: false,
    };
    assert_eq!(records.label_of(&Fingerprint::of(&labelled)).as_deref(), Some("paper"));
    assert_eq!(records.enrollment_of(&Fingerprint::of(&bare)).map(|r| r.link.as_str()), Some("1.0.1.0.1.0.2.1"), "the record that FIRST enrolled it");
    assert!(records.enrollment_of(&Fingerprint::of(&key(3))).is_none());
    assert_eq!(records.label_of(&Fingerprint::of(&bare)), None);
    assert_eq!(records.label_of_hand(&Hand::Key(Fingerprint::of(&bare))), None);
    assert_eq!(records.label_of(&Fingerprint::of(&key(3))), None, "a key no record enrolled");
}

/// THE BISECTION's bound holds whatever the board answers: a board that
/// names the head as `nearest` at every position below it — a `nearest`
/// above the position asked, which the wire never answers — is bisected
/// all the same, its `nearest` taken only within the half asked, in the
/// law's 2·⌈log₂ head⌉ + 3 reads; the fake refuses to answer past 200.
#[test]
fn a_board_whose_nearest_does_not_descend_is_bisected_in_its_bound() {
    const HEAD: u64 = 1000;
    let asked = std::sync::atomic::AtomicUsize::new(0);
    let fake = Fake::new(move |req| {
        assert!(asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 200, "the bisection spun past 200 reads");
        let at = serde_json::from_slice::<Value>(&req.body).unwrap()["at"].as_u64().unwrap();
        if at == HEAD {
            return fake::json(200, json!({"addrs": [LINK], "as_of": at, "resp": "addrs"}));
        }
        fake::json(400, json!({"error": "not_a_position", "nearest": HEAD}))
    });
    let frame = frames::find_links_ftt(T_ENROLL, "1.0.1");
    assert_eq!(position_of(&fake::board(&fake), &frame, LINK, HEAD).expect("an answer"), (Some(HEAD), None));
    let bound = 2 * u64::from(HEAD.next_power_of_two().trailing_zeros()) + 3;
    assert!(fake.sent.lock().unwrap().len() as u64 <= bound, "{} reads past {bound}", fake.sent.lock().unwrap().len());
}

/// The head's probe takes a `nearest` only at or below the head it asked of:
/// a board answering the head with a `nearest` past it — which the wire never
/// answers — leaves the link at no position this read asserts, and the
/// positions above the head are never bisected.
#[test]
fn a_nearest_past_the_head_asked_asserts_no_position() {
    const HEAD: u64 = 1000;
    let fake = Fake::new(|req| {
        let at = serde_json::from_slice::<Value>(&req.body).unwrap()["at"].as_u64().unwrap();
        match at {
            HEAD => fake::json(400, json!({"error": "not_a_position", "nearest": 5000})),
            at if at >= 2000 => fake::json(200, json!({"addrs": [LINK], "as_of": at, "resp": "addrs"})),
            _ => fake::json(200, json!({"addrs": [], "as_of": at, "resp": "addrs"})),
        }
    });
    let frame = frames::find_links_ftt(T_ENROLL, "1.0.1");
    assert_eq!(position_of(&fake::board(&fake), &frame, LINK, HEAD).expect("an answer"), (None, None));
    assert_eq!(fake.log(), ["POST /op-at find_links_ftt", "POST /op-at find_links_ftt"], "the lowest position's probe and the head's");
}

/// A retention floor at the top of the range — past the head the board
/// answered for — leaves no position to bisect: the read answers none below
/// the floor and overflows nothing.
#[test]
fn a_floor_at_the_top_of_the_range_overflows_nothing() {
    let fake = Fake::new(|req| {
        let at = serde_json::from_slice::<Value>(&req.body).unwrap()["at"].as_u64().unwrap();
        match at {
            0 => fake::json(410, json!({"error": "history_reclaimed", "floor": u64::MAX})),
            u64::MAX => fake::json(200, json!({"addrs": [], "as_of": at, "resp": "addrs"})),
            _ => fake::json(200, json!({"addrs": [LINK], "as_of": at, "resp": "addrs"})),
        }
    });
    let frame = frames::find_links_ftt(T_ENROLL, "1.0.1");
    assert_eq!(position_of(&fake::board(&fake), &frame, LINK, 20).expect("an answer"), (None, Some(u64::MAX)));
}

/// The set as of a base is read upward from ω's prefix only where that
/// prefix lies within the namespace's depth: a deeper one is unreadable,
/// with no read made.
#[test]
fn a_home_account_deeper_than_the_namespace_reads_no_set() {
    let deep = format!("1.0.1{}", ".1".repeat(crate::address::MAX_PRINCIPAL_COMPONENTS));
    assert_eq!(set_opening_at(&fake::board(&Fake::unread()), &deep, 9).expect("no read, so no fault"), None);
}
