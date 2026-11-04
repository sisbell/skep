use std::sync::Arc;

use serde_json::json;

use super::*;
use crate::board::fake::{self, Fake};
use crate::board::HEAD_MEMBER_1;

/// The issuer `1.0.1`, whose doc 1 is `1.0.1.0.1`; its link subspace mints
/// `1.0.1.0.1.0.2.k`.
const ISSUER: &str = "1.0.1";
const HOME: &str = "1.0.1.0.1";
const DOC: &str = "1.0.1.0.5";
const OTHER_DOC: &str = "1.0.1.0.6";
const GRANTEE: &str = "1.0.7";

fn a(text: &str) -> Address {
    parse_address(text).expect("an address")
}

/// The k-th record of the issuer's doc 1.
fn at(k: u64) -> Address {
    a(&format!("{HOME}.0.2.{k}"))
}

fn record(k: u64, from: &str, to: &[&str]) -> LinkRecord {
    LinkRecord { at: at(k), from: vec![a(from)], to: to.iter().map(|t| a(t)).collect() }
}

fn grantee() -> Grantee {
    Grantee::Account(a(GRANTEE))
}

fn fold(records: &[LinkRecord], replaces: &[(Address, Address)]) -> Ledger {
    Ledger::fold(&a(ISSUER), records, replaces)
}

/// The frames (wire.md §Links (writes)): a grant is an address-form
/// `make_link` homed in the issuer's doc 1, `from` the prefix, `to` the
/// grantee, `ty` the grants class, `replaces` present only where named and
/// inside the signed body where it is; the privash is the ONE frame with an
/// empty `to`; a revocation's `from` is the grant's own address and its `to`
/// the grant's grantee, with no `replaces`.
#[test]
fn the_grant_frame_names_its_slots_and_the_privash_alone_leaves_to_empty() {
    let (frame, body) = grant_frame(&a(HOME), &a(DOC), &grantee(), None);
    assert_eq!(frame["op"], json!("make_link"));
    assert_eq!(frame["home"], json!(HOME));
    assert_eq!(frame["from"], json!({"addrs": [DOC]}));
    assert_eq!(frame["to"], json!({"addrs": [GRANTEE]}));
    assert_eq!(frame["ty"], json!({"addrs": [T_GRANT]}));
    assert!(frame.get("replaces").is_none(), "the EMPTY state is the member's absence: {frame}");
    let revocation = at(2);
    let (again, body_replacing) = grant_frame(&a(HOME), &a(DOC), &grantee(), Some(&revocation));
    assert_eq!(again["replaces"], json!(revocation.to_string()));
    assert_ne!(body.as_bytes(), body_replacing.as_bytes(), "the signed body carries the `replaces` row");
    assert!(body_replacing.as_bytes().starts_with(body.as_bytes().strip_suffix(&[0, 0, 0, 0]).expect("the EMPTY replaces group, be32(0)")), "the three slots, then the `replaces` row");
    assert_eq!((body.op(), body_replacing.op()), ("make_link", "make_link"));
    let (privash, _) = grant_frame(&a(HOME), &a(DOC), &Grantee::Privashed, None);
    assert_eq!(privash["to"], json!({"addrs": []}), "the ANY-PRINCIPAL grant: an empty `to` (PUB-5.8)");
    assert_eq!(privash["from"], json!({"addrs": [DOC]}));
    let grant = Grant { at: at(1), issuer: a(ISSUER), prefix: a(DOC), grantee: grantee(), replaces: None };
    let (revoke, _) = revocation_frame(&a(HOME), &grant);
    assert_eq!(revoke["from"], json!({"addrs": [at(1).to_string()]}), "a revocation's `from` names the grant (PUB-5.13)");
    assert_eq!(revoke["to"], json!({"addrs": [GRANTEE]}));
    assert_eq!(revoke["ty"], json!({"addrs": [T_GRANT]}));
    assert!(revoke.get("replaces").is_none());
    let privashed = Grant { grantee: Grantee::Privashed, ..grant };
    assert_eq!(revocation_frame(&a(HOME), &privashed).0["to"], json!({"addrs": []}));
}

/// THE THREE `replaces` CASES (PUB-5.15 (iv)): an empty key — no record —
/// takes a grant with no `replaces`; a key whose latest record is a
/// revocation takes a re-share naming it; a key with a live grant takes
/// nothing, the state naming the grant that stands.
#[test]
fn the_key_state_is_empty_then_live_then_the_revocation_then_live_again() {
    let empty = fold(&[], &[]);
    assert_eq!(empty.key_state(&a(DOC), &grantee()), KeyState::Empty);
    let g1 = record(1, DOC, &[GRANTEE]);
    let one = fold(std::slice::from_ref(&g1), &[]);
    let KeyState::Live(live) = one.key_state(&a(DOC), &grantee()) else { panic!("{one:?}") };
    assert_eq!((live.at.clone(), live.prefix.clone(), live.grantee.clone(), live.replaces.clone()), (at(1), a(DOC), grantee(), None));
    assert_eq!(live.issuer, a(ISSUER));
    assert_eq!(one.key_state(&a(OTHER_DOC), &grantee()), KeyState::Empty, "another prefix is another key");
    assert_eq!(one.key_state(&a(DOC), &Grantee::Privashed), KeyState::Empty, "the privash is another key");
    let r1 = record(2, &at(1).to_string(), &[GRANTEE]);
    let revoked = fold(&[g1.clone(), r1.clone()], &[]);
    assert_eq!(revoked.key_state(&a(DOC), &grantee()), KeyState::Revoked(Revocation { at: at(2), revokes: at(1), issuer: a(ISSUER) }));
    assert_eq!(revoked.grants[0].1, GrantState::Revoked { by: at(2) });
    let g2 = record(3, DOC, &[GRANTEE]);
    let again = fold(&[g1, r1, g2], &[(at(3), at(2))]);
    let KeyState::Live(live) = again.key_state(&a(DOC), &grantee()) else { panic!("{again:?}") };
    assert_eq!((live.at, live.replaces), (at(3), Some(at(2))), "the re-share names the revocation it follows");
    assert_eq!(again.grants.iter().map(|(g, s)| (g.at.clone(), s.clone())).collect::<Vec<_>>(), vec![(at(1), GrantState::Revoked { by: at(2) }), (at(3), GrantState::Live)]);
    assert_eq!(again.grant(&at(3)).map(|(g, _)| g.prefix.clone()), Some(a(DOC)));
    assert_eq!(again.grant(&at(2)), None, "a revocation is no grant");
}

/// THE PAIRING, and what the wire says opens nothing (wire.md §The read
/// predicate): a revocation of a revocation lifts nothing and revokes
/// nothing; the second revocation of one grant is nothing, the first
/// standing; a duplicate of a live grant is inert; a re-share naming a
/// revocation a later one has passed is inert, and one naming the latest is
/// live; a share replayed after its revocation — no `replaces` — is inert; a
/// record whose `to` names two addresses, whose `from` is a node, or whose
/// `from` names a link in another doc 1 is of neither kind.
#[test]
fn the_pairing_ignores_what_the_wire_says_opens_nothing() {
    let stranger_link = "1.0.2.0.1.0.2.1";
    let records = vec![
        record(1, DOC, &[GRANTEE]),              // G1
        record(2, &at(1).to_string(), &[GRANTEE]), // R1 revokes G1
        record(3, &at(2).to_string(), &[GRANTEE]), // a revocation of a revocation: nothing
        record(4, &at(1).to_string(), &[GRANTEE]), // a second revocation of G1: nothing
        record(5, DOC, &[GRANTEE]),              // G2, replaces R1: live
        record(6, DOC, &[GRANTEE]),              // a duplicate while G2 lives: inert
        record(7, &at(5).to_string(), &[]),        // R2 revokes G2, its `to` empty
        record(8, DOC, &[GRANTEE]),              // G3, replaces R1, which R2 has passed: inert
        record(9, DOC, &[GRANTEE]),              // a replay after R2, no `replaces`: inert
        record(10, DOC, &[GRANTEE]),             // G4, replaces R2: live
        record(11, DOC, &[GRANTEE, "1.0.8"]),    // two grantees: neither kind
        record(12, "1", &[GRANTEE]),             // a node prefix: neither kind
        record(13, stranger_link, &[GRANTEE]),   // names a link in another doc 1: neither kind
        record(14, OTHER_DOC, &[]),              // a privash of another document: live
    ];
    let replaces = vec![(at(5), at(2)), (at(8), at(2)), (at(10), at(7))];
    let ledger = fold(&records, &replaces);
    let states: Vec<(u64, GrantState)> = ledger.grants.iter().map(|(g, s)| (g.at.to_string().rsplit('.').next().unwrap().parse().unwrap(), s.clone())).collect();
    assert_eq!(
        states,
        vec![
            (1, GrantState::Revoked { by: at(2) }),
            (5, GrantState::Revoked { by: at(7) }),
            (6, GrantState::Inert),
            (8, GrantState::Inert),
            (9, GrantState::Inert),
            (10, GrantState::Live),
            (14, GrantState::Live),
        ]
    );
    let KeyState::Live(live) = ledger.key_state(&a(DOC), &grantee()) else { panic!() };
    assert_eq!((live.at, live.replaces), (at(10), Some(at(7))));
    let KeyState::Live(privashed) = ledger.key_state(&a(OTHER_DOC), &Grantee::Privashed) else { panic!() };
    assert_eq!((privashed.at, privashed.grantee), (at(14), Grantee::Privashed));
    // The order is the address order, whatever order the records arrive in.
    let mut shuffled = records.clone();
    shuffled.reverse();
    assert_eq!(fold(&shuffled, &replaces), ledger, "the fold is order-blind");
}

/// AUTH-5.87's layout read back: an account at or under some account's
/// first sub-user `X.1` is in `X`'s agent space; a person's account, a
/// top-level account and a second sub-user are in none.
#[test]
fn agent_space_of_places_an_agent_under_its_owners_first_sub_user() {
    assert_eq!(agent_space_of(&a("1.0.1.1.1")), Some(a("1.0.1")));
    assert_eq!(agent_space_of(&a("1.0.1.1.2.1")), Some(a("1.0.1")), "a spawned agent beneath an agent");
    assert_eq!(agent_space_of(&a("1.0.1.1")), Some(a("1.0.1")), "the space itself");
    assert_eq!(agent_space_of(&a("1.0.1.2.1.3")), Some(a("1.0.1.2")), "a sub-account's own agent space");
    assert_eq!(agent_space_of(&a("1.0.1.2")), None);
    assert_eq!(agent_space_of(&a("1.0.1")), None);
    assert_eq!(agent_space_of(&a("1.0.7")), None);
}

/// Each refusal names the act that would help, and the grantee spells as a
/// face does.
#[test]
fn a_refusal_names_the_act_and_a_grantee_spells_itself() {
    assert_eq!(grantee().text(), GRANTEE);
    assert_eq!(Grantee::Privashed.text(), "privashed");
    assert_eq!(Grantee::Privashed.account(), None);
    let standing = Grant { at: at(1), issuer: a(ISSUER), prefix: a(DOC), grantee: grantee(), replaces: None };
    let text = Refusal::AlreadyShared(Box::new(standing)).to_string();
    assert!(text.contains("already shared with 1.0.7") && text.contains("revoke that grant") && text.contains("nothing was written"), "{text}");
    let text = Refusal::NotADocument(a(ISSUER)).to_string();
    assert!(text.contains("privashing a whole account is not available") && text.contains("PUB-5.108"), "{text}");
    let text = Refusal::NotOwner { prefix: a(DOC), owner: Some(a("1.0.2")) }.to_string();
    assert!(text.contains("not yours to share — it is 1.0.2's") && text.contains("PUB-5.3"), "{text}");
    let text = Refusal::NotYours { grant: at(1), issuer: Some(a(ISSUER)) }.to_string();
    assert!(text.contains("only the issuer revokes a share"), "{text}");
    assert!(Refusal::NotStanding(at(6)).to_string().contains("revoke the grant that stands for its key"));
}

const TOKEN: &str = "9f3a6c21d4b8e07a5c1b2d4e6f708192";

/// Returns a board over the issuer's ledger.
///
/// The issuer's doc 1 holds one live grant at `at(1)`, `DOC` shared with
/// `GRANTEE`; `DOC` is the issuer's draft; `H.1` serves its record where
/// `head` holds; `/health` names `claimant`; every `make_link` is answered
/// `link`.
fn ledger_board(head: bool, claimant: Option<&'static str>, link: Value) -> Arc<Fake> {
    Fake::new(move |req| {
        if req.path == "/health" {
            return fake::json(200, json!({"auth": {"claimant": claimant, "local_trust": false, "origins": [], "signed_origins": []}, "log_position": 9}));
        }
        let frame = fake::frame(req);
        let record = json!({"type": "skep-head", "position": 1, "chain": "00".repeat(32)}).to_string();
        let items = if head { json!([{"atom": record}]) } else { json!([]) };
        let answer = match frame["op"].as_str().unwrap_or("?") {
            "retrieve_v" if frame["specs"][0]["doc"] == HEAD_MEMBER_1 => json!({"resp": "delivery", "as_of": 9, "items": items}),
            "doc_metadata" => json!({"resp": "doc_metadata", "as_of": 9, "doc": DOC, "published": false, "owner": ISSUER}),
            "find_links_ftt" if frame["q"]["ty"][0]["start"] == T_GRANT => json!({"resp": "addrs", "as_of": 9, "addrs": [at(1).to_string()]}),
            "find_links_ftt" => json!({"resp": "addrs", "as_of": 9, "addrs": []}),
            "read_link" => json!({"resp": "link_value", "as_of": 9, "link": {"slots": [[{"start": DOC, "width": "0.1"}], [{"start": GRANTEE, "width": "0.1"}], [{"start": T_GRANT, "width": "0.1"}]]}}),
            "make_link" => link.clone(),
            op => panic!("the share sent an op this board does not answer: {op}"),
        };
        fake::json(200, answer)
    })
}

/// Returns the grant-class links a board was sent, in order.
fn links(fake: &Fake) -> Vec<Value> {
    fake.sent.lock().unwrap().iter().map(|(_, req)| fake::frame(req)).filter(|f| f["op"] == "make_link").collect()
}

/// A CLAIMED BOARD WHOSE HEAD IS OWED IS SENT NO GRANT-CLASS LINK (SP-14):
/// where `H.1` serves no record and `/health` names a claimant, `privash`
/// and `revoke` each halt naming `H.1` after their reads and before the
/// write — no `make_link` sent, and never as this library's fault; the
/// same board with no claimant takes each link without an `attest`; and
/// the board's own `attestation_invalid:board_unavailable` is faced as the
/// head it owes, never as this library's frame.
#[test]
fn a_claimed_board_serving_no_head_record_sends_no_grant_and_an_unclaimed_one_sends_it_unsigned() {
    let token = Token::parse(TOKEN).expect("a token");
    let signer = crate::sign::signer_from_seed(&[42; 32]);
    let issuer = Issuer { token: &token, account: ISSUER, signer: &signer };
    let acked = json!({"resp": "ack_addr", "addr": at(2).to_string(), "at": 10});
    let owed = ledger_board(false, Some(ISSUER), acked.clone());
    let board = fake::board(&owed);
    for (what, answer) in [("the grant", privash(&board, &issuer, &a(DOC)).map(|_| ())), ("the revocation", revoke(&board, &issuer, &at(1)).map(|_| ()))] {
        let Err(Refusal::Halt(Halt::Halt(face))) = &answer else { panic!("{what}: {answer:?}") };
        assert!(face.state.contains("H.1") && face.state.contains(what), "{face}");
        assert!(face.cause.contains(&format!("names {ISSUER} its claimant")) && face.act.contains("nothing was written"), "{face}");
        assert!(!face.act.contains("fault in this library"), "{face}");
    }
    assert!(links(&owed).is_empty(), "no grant-class link: {:?}", owed.log());
    // No one the board's claimant: each link sent, unsigned.
    let unclaimed = ledger_board(false, None, acked);
    let board = fake::board(&unclaimed);
    assert_eq!(privash(&board, &issuer, &a(DOC)).map(|g| g.at), Ok(at(2)));
    assert_eq!(revoke(&board, &issuer, &at(1)).map(|r| r.at), Ok(at(2)));
    let sent = links(&unclaimed);
    assert_eq!(sent.len(), 2, "{:?}", unclaimed.log());
    assert!(sent.iter().all(|f| f.get("attest").is_none()), "unsigned where no one claimed the board: {sent:?}");
    // The head owed past the read: the board's own refusal, faced as such.
    let unavailable = json!({"resp": "rejected", "code": "credential_refused", "detail": "attestation_invalid:board_unavailable", "disposition": "reorder", "op": "make_link"});
    let raced = ledger_board(true, Some(ISSUER), unavailable);
    let board = fake::board(&raced);
    let answer = privash(&board, &issuer, &a(DOC));
    let Err(Refusal::Halt(Halt::Halt(face))) = &answer else { panic!("{answer:?}") };
    assert!(face.state.contains("H.1") && face.cause.contains("attestation_invalid:board_unavailable"), "{face}");
    assert!(face.act.contains("retry once the board has written its head") && !face.act.contains("fault in this library"), "{face}");
    assert!(links(&raced)[0]["attest"]["sig"].is_string(), "the premise: the link went signed: {:?}", raced.log());
}
