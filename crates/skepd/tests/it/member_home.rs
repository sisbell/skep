//! A version member homes links, proved end to end through the daemon: a
//! link whose `home` is a published version member — `E.2` — is admitted
//! from a signed session and refused from a bare one by the publish-class
//! gate (PUB-2.15, the member read as its document), lands in THE MEMBER's
//! own link subspace `E.2.0.2.n` in order of arrival (CL-OWN; LM 4/28–4/31),
//! is found by its CONTENT at every version sharing the bytes (PUB-2.51;
//! conformance decision 15's refraction — a reader meets it by identity,
//! never by a copy), satisfies a home slot naming the member alone or naming
//! the document (skep-discovery's coverage claim, carried to the daemon), and
//! is gone everywhere once retracted (R16). wire.md §Links (writes) states
//! the member as a home; §Link discovery reads the home slot; §The publish
//! shot and head-float the float a bare address takes; §The change feed that
//! a link write's row names its home.
//!
//! The store, the index and the gate each admit the member in their own
//! tests (`skep-links`, `skep-discovery`'s `descriptor.rs`, `auth_wire`'s
//! `gates.rs`); nothing had driven the ceremony through the daemon. This
//! suite proves and fixes nothing: a case red against the daemon as built is
//! kept, ignored with the verdict met, and reported.
//!
//! THE BOARD, one per test (`spawn`, CLAIMED-PERMISSIVE; the claimant
//! `1.0.1`, a signed session S and a bare session B). `E` is the claimant's
//! second document, a published edition whose own arrangement holds a
//! passage P; shot 1 re-supplies P by reference → `E.1`; shot 2, off `E.1`,
//! re-supplies P by reference and re-mints a staged passage Q → `E.2`
//! holding P then Q — P's bytes ONE identity at `E`, `E.1` and `E.2`; a
//! daughter staged off `E.1` once `E.2` exists → `E.1.1`; a third shot, on
//! the boards whose case names it, re-supplies Q by reference → `E.3`
//! holding none of P, the bare `E` floating to it there and to `E.2`
//! everywhere else; and `F`, a private draft of the claimant's, transcludes
//! P from `E` by `copy`.
//! Every endset is a V-spec on a MEMBER address: the store resolves it
//! against the member's own arrangement, which `image` answers too
//! (PUB-2.50), so the slot the test signer composes is the slot stored.

use crate::common;

use common::*;
use serde_json::{json, Value};

/// The citation type, a seeded commons type (`3.13`): the one type every
/// link here carries, named in the address form.
const T_CITATION: &str = "1.1.0.1.0.1.0.3.13";

/// The two passages, per-byte.
const P: &str = "the quick brown fox jumps over the lazy dog";
const Q: &str = "and the dish ran away with the spoon";
const P_LEN: u64 = P.len() as u64;
const Q_LEN: u64 = Q.len() as u64;

/// The empty address-form slot.
const NONE: &str = r#"{"addrs":[]}"#;

/// The claim ceremony's two links in the claimant's doc 1 — the genesis
/// deposit, whose TO names the account `1.0.1`, and the claim, whose FROM
/// does. An address-form slot naming an account is the unit span over it,
/// which covers every content address beneath, so `find_links_v` over any
/// region of the claimant's own documents answers the two ahead of the
/// region's own links: the floor every content read of this account has.
const CEREMONY_LINKS: [&str; 2] = ["1.0.1.0.1.0.2.1", "1.0.1.0.1.0.2.2"];

/// The ceremony's floor, then `links`, in the order `find_links_v` answers.
fn floor_and(links: &[&str]) -> Vec<String> {
    CEREMONY_LINKS.iter().chain(links).map(|a| a.to_string()).collect()
}

/// The claimant's document `E`, its first two trunk members, and the private
/// draft `F` that transcludes P.
struct Chain {
    e: String,
    e1: String,
    e2: String,
    f: String,
}

/// P's one I-run under `E`'s own content chain — what every arrangement that
/// holds P images, and what a V-spec over P resolves to.
fn p_run(e: &str) -> (String, u64) {
    (format!("{e}.0.1.1"), P_LEN)
}

/// Q's one I-run, `E`'s own chain past P.
fn q_run(e: &str) -> (String, u64) {
    (format!("{e}.0.1.{}", P_LEN + 1), Q_LEN)
}

/// P's I-span as a stored slot spells it: the run's start, the count in the
/// width's last component.
fn p_slot(e: &str) -> Value {
    json!([{"start": format!("{e}.0.1.1"), "width": format!("0.0.0.0.0.0.0.{P_LEN}")}])
}

/// A citation link homed in `home` FROM `from` TO `to`, each slot JSON.
fn citation(home: &str, from: &str, to: &str) -> String {
    link_frame(home, from, to, &addrs_slot(&[T_CITATION]))
}

/// The board's chain: `E` holding P, `E.1` and `E.2`, and `F`.
fn chain(port: u16, signed: &str, bare: &str) -> Chain {
    let e = edition_with(port, signed, P);
    assert_eq!(e, "1.0.1.0.2", "the claimant's second document");
    assert_eq!(image_runs(port, None, &e, 1, P_LEN), vec![p_run(&e)]);
    // Shot 1, the birth version: E's own runs by reference.
    let e1 = shot(port, signed, &e, Some((&e, P_LEN)), None, &shot_runs(port, None, &e, 1, P_LEN));
    assert_eq!(e1, format!("{e}.1"));
    // Q staged in a draft; shot 2 off E.1: P by reference, Q re-minted under
    // E's own content chain.
    let d_q = draft_with(port, bare, Q);
    assert_eq!(d_q, "1.0.1.0.3");
    let mut runs = shot_runs(port, None, &e1, 1, P_LEN);
    runs.push(run(&d_q, &format!("{d_q}.0.1.1"), Q_LEN));
    let e2 = shot(port, signed, &e, Some((&e1, P_LEN)), Some(&d_q), &runs);
    assert_eq!(e2, format!("{e}.2"));
    assert_eq!(content_extent(port, None, &e2), P_LEN + Q_LEN);
    assert_eq!(text_of(port, None, &e2, 1, P_LEN), P);
    assert_eq!(text_of(port, None, &e2, P_LEN + 1, Q_LEN), Q);
    // P's bytes are ONE identity at E.1, at E.2 and at the bare E, which
    // floats to E.2 (PUB-2.49); Q's are E's own chain past P.
    for d in [e1.as_str(), e2.as_str(), e.as_str()] {
        assert_eq!(image_runs(port, None, d, 1, P_LEN), vec![p_run(&e)], "P at {d}");
    }
    assert_eq!(image_runs(port, None, &e2, P_LEN + 1, Q_LEN), vec![q_run(&e)]);
    // F transcludes P from E: `copy` reads the address named — E's own
    // arrangement, which holds P (§The publish shot and head-float).
    let f = owner_draft(port, bare);
    assert_eq!(f, "1.0.1.0.4");
    expect_resp(&copy_span(port, bare, &f, 1, &e, 1, P_LEN), "ack");
    assert_eq!(image_runs(port, Some(bare), &f, 1, P_LEN), vec![p_run(&e)], "F holds P's identity");
    Chain { e, e1, e2, f }
}

/// A shot staged off `E.1` once `E.2` exists: `E.1`'s daughter `E.1.1`, in
/// the nested form (PUB-2.55), holding P by reference.
fn daughter(port: u16, signed: &str, c: &Chain) -> String {
    let runs = shot_runs(port, None, &c.e1, 1, P_LEN);
    let d = shot(port, signed, &c.e, Some((&c.e1, P_LEN)), None, &runs);
    assert_eq!(d, format!("{}.1", c.e1));
    assert_eq!(image_runs(port, None, &d, 1, P_LEN), vec![p_run(&c.e)]);
    d
}

/// A third trunk shot, off `E.2`, re-supplying Q alone: `E.3`, holding none
/// of P — and the bare `E` floats to it.
fn third_member(port: u16, signed: &str, c: &Chain) -> String {
    let runs = shot_runs(port, None, &c.e2, P_LEN + 1, Q_LEN);
    let e3 = shot(port, signed, &c.e, Some((&c.e2, P_LEN + Q_LEN)), None, &runs);
    assert_eq!(e3, format!("{}.3", c.e));
    assert_eq!(content_extent(port, None, &e3), Q_LEN);
    assert_eq!(text_of(port, None, &e3, 1, Q_LEN), Q);
    assert_eq!(image_runs(port, None, &e3, 1, Q_LEN), vec![q_run(&c.e)]);
    assert_eq!(content_extent(port, None, &c.e), Q_LEN, "the bare address floats to E.3");
    e3
}

/// The change-feed entries past `since`, as `token` (`None` = the guest).
fn changes_since(port: u16, token: Option<&str>, since: u64) -> Vec<Value> {
    let (st, body) = http(port, "GET", &format!("/changes?since={since}"), token, b"");
    assert_eq!(st, 200, "/changes: {}", String::from_utf8_lossy(&body));
    json(&body)["changes"].as_array().expect("changes").clone()
}

/// M1 — PUB-2.15 at the link write (wire.md §Links (writes), ownership): S's
/// `make_link` homed in `E.2`, its endsets P as V-specs on `E.2` and on
/// `E.1`, attested, is acked with an address; B's same frame meets the
/// publish-class gate — `signed_session_required`, the member read as its
/// published document — and commits nothing; and a `home` naming the
/// never-minted member `E.9` is `home_not_registered`, registration ahead of
/// everything (PUB-6.37).
#[test]
fn a_link_homed_in_a_member_is_admitted_signed_refused_bare_and_registered_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let Chain { e, e1, e2, .. } = chain(port, &signed, &bare);
    let frame = citation(&e2, &vspec(&e2, 1, P_LEN), &vspec(&e1, 1, P_LEN));

    let before = head_position(port);
    assert_eq!(verdict(&op(port, Some(&bare), &frame)), GATED, "the bare session's write");
    assert_eq!(head_position(port), before, "a refused write commits nothing");
    let v = op(port, Some(&signed), &frame);
    assert_eq!(verdict(&v), "ok", "{v}");
    assert_eq!(acked_addr(&v), format!("{e2}.0.2.1"));
    let never = format!("{e}.9");
    let v = op(port, Some(&signed), &citation(&never, &vspec(&e2, 1, P_LEN), &vspec(&e1, 1, P_LEN)));
    assert_eq!(verdict(&v), "home_not_registered", "{v}");
    sd.shutdown();
}

/// M2 — CL-OWN at the seat (`stage_seat_link`): the acked address is the
/// member's own link subspace at ordinal 1, `E.2.0.2.1`; a second link homed
/// in `E.2` is `E.2.0.2.2`; a link homed in `E` is `E.0.2.1` — `E`'s own
/// count, untouched by the member's; `read_link` answers the slots as stored,
/// FROM and TO the one I-span P resolved to; and `E.2`'s CONTENT arrangement
/// is unchanged by the link (PUB-2.66), its own `{home: [E.2]}` the links and
/// `E.1`'s none.
#[test]
fn the_link_lands_in_the_members_own_subspace_and_the_members_content_does_not_grow() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let Chain { e, e1, e2, .. } = chain(port, &signed, &bare);
    let extent_before = content_extent(port, None, &e2);
    let image_before = image_runs(port, None, &e2, 1, P_LEN + Q_LEN);

    let l1 = acked_addr(&op(port, Some(&signed), &citation(&e2, &vspec(&e2, 1, P_LEN), &vspec(&e1, 1, P_LEN))));
    assert_eq!(l1, format!("{e2}.0.2.1"), "the member's own link subspace, ordinal 1");
    let l2 = acked_addr(&op(
        port,
        Some(&signed),
        &citation(&e2, &vspec(&e2, 1, P_LEN), &vspec(&e2, P_LEN + 1, Q_LEN)),
    ));
    assert_eq!(l2, format!("{e2}.0.2.2"), "the member's second");
    let l_e = acked_addr(&op(
        port,
        Some(&signed),
        &citation(&e, &vspec(&e1, 1, P_LEN), &vspec(&e2, P_LEN + 1, Q_LEN)),
    ));
    assert_eq!(l_e, format!("{e}.0.2.1"), "E's own count, untouched by the member's");

    let link = read_link(port, None, &l1);
    assert_eq!(
        link["slots"],
        json!([p_slot(&e), p_slot(&e), [{"start": T_CITATION, "width": "0.0.0.0.0.0.0.0.1"}]]),
        "the slots as stored: {link}"
    );
    assert_eq!(content_extent(port, None, &e2), extent_before, "the content arrangement does not grow");
    assert_eq!(image_runs(port, None, &e2, 1, P_LEN + Q_LEN), image_before);
    assert_eq!(find_links_ftt_home(port, None, &e2), vec![l1, l2]);
    assert_eq!(find_links_ftt_home(port, None, &e1), Vec::<String>::new(), "E.1's subspace holds none");
    sd.shutdown();
}

/// M3 — PUB-2.51; decision 15's refraction: a link homed in `E.2` on P is
/// found by `find_links_v` over P's region at `E.1`, at `E.2`, at the bare
/// `E` (head-float, §The publish shot and head-float) and at `F`, the
/// transclusion — by the shared content addresses, nothing copied; the
/// census agrees; Q's region at `E.2` answers none; and the guest asking at
/// the draft `F` is `withheld`.
#[test]
fn the_link_is_found_by_identity_at_every_version_sharing_the_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let Chain { e, e1, e2, f } = chain(port, &signed, &bare);
    let l1 = acked_addr(&op(port, Some(&signed), &citation(&e2, &vspec(&e2, 1, P_LEN), &vspec(&e1, 1, P_LEN))));
    assert_eq!(l1, format!("{e2}.0.2.1"));

    for d in [e1.as_str(), e2.as_str(), e.as_str()] {
        assert_eq!(find_links_v(port, None, d, 1, P_LEN), floor_and(&[&l1]), "P's region at {d}");
        assert_eq!(count_v(port, None, d, 1, P_LEN), 3, "the census at {d}");
    }
    assert_eq!(find_links_v(port, Some(&bare), &f, 1, P_LEN), floor_and(&[&l1]), "the transclusion");
    assert_eq!(count_v(port, Some(&bare), &f, 1, P_LEN), 3);
    assert_eq!(find_links_v(port, None, &e2, P_LEN + 1, Q_LEN), floor_and(&[]), "Q's region");
    assert_withheld(&op(port, None, &find_links_frame(&f, 1, P_LEN)), &f);
    sd.shutdown();
}

/// M4 — absent where the bytes are absent: a third shot re-supplying Q alone
/// mints `E.3`, and `find_links_v` over its whole content answers none of
/// P's link — nor does the bare `E`, floated to it; a link homed in `E.2`
/// whose FROM is Q's V-spec IS found at `E.3` and NOT at `E.1`.
#[test]
fn a_link_is_absent_where_its_bytes_are_absent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let c = chain(port, &signed, &bare);
    let Chain { e, e1, e2, .. } = &c;
    let l_p = acked_addr(&op(port, Some(&signed), &citation(e2, &vspec(e2, 1, P_LEN), &vspec(e1, 1, P_LEN))));
    assert_eq!(l_p, format!("{e2}.0.2.1"));

    let e3 = third_member(port, &signed, &c);
    assert_eq!(find_links_v(port, None, &e3, 1, Q_LEN), floor_and(&[]), "E.3 holds none of P");
    assert_eq!(find_links_v(port, None, e, 1, Q_LEN), floor_and(&[]), "the bare E floats to E.3");

    let l_q = acked_addr(&op(port, Some(&signed), &citation(e2, &vspec(e2, P_LEN + 1, Q_LEN), NONE)));
    assert_eq!(l_q, format!("{e2}.0.2.2"));
    assert_eq!(find_links_v(port, None, &e3, 1, Q_LEN), floor_and(&[&l_q]), "Q's link at E.3");
    assert_eq!(find_links_v(port, None, e, 1, Q_LEN), floor_and(&[&l_q]), "and at the floated E");
    assert_eq!(find_links_v(port, None, e1, 1, P_LEN), floor_and(&[&l_p]), "not at E.1");
    assert_eq!(find_links_v(port, None, e2, 1, P_LEN + Q_LEN), floor_and(&[&l_p, &l_q]), "both at E.2");
    sd.shutdown();
}

/// M5 — the home slot (skep-discovery's claim, at the daemon): with a link
/// homed in each of `E`, `E.1`, `E.1.1`, `E.2` and `E.3`, `{home: [E.2]}`
/// answers `E.2`'s link alone; `{home: [E]}` all five together; `{home:
/// [E.1]}` `E.1`'s and its daughter's and none of `E.2`'s; `count_ftt`
/// agrees with each; and a GUEST gets the same answers (§The read predicate:
/// published homes answer anyone).
#[test]
fn the_home_slot_names_the_member_alone_or_the_document_for_any_reader() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let c = chain(port, &signed, &bare);
    let e11 = daughter(port, &signed, &c);
    let e3 = third_member(port, &signed, &c);
    let Chain { e, e1, e2, .. } = &c;
    let homed = |home: &str, from: &str| {
        acked_addr(&op(port, Some(&signed), &citation(home, from, NONE)))
    };
    let l_e2 = homed(e2, &vspec(e2, 1, P_LEN));
    let l_e1 = homed(e1, &vspec(e1, 1, P_LEN));
    let l_e = homed(e, &vspec(e1, 1, P_LEN));
    let l_e3 = homed(&e3, &vspec(&e3, 1, Q_LEN));
    let l_e11 = homed(&e11, &vspec(&e11, 1, P_LEN));
    assert_eq!(l_e2, format!("{e2}.0.2.1"));
    assert_eq!(l_e1, format!("{e1}.0.2.1"));
    assert_eq!(l_e, format!("{e}.0.2.1"));
    assert_eq!(l_e3, format!("{e3}.0.2.1"));
    assert_eq!(l_e11, format!("{e11}.0.2.1"));

    for token in [Some(signed.as_str()), None] {
        let who = if token.is_some() { "the signed session" } else { "the guest" };
        assert_eq!(find_links_ftt_home(port, token, e2), vec![l_e2.clone()], "{who}: E.2's alone");
        assert_eq!(count_ftt_home(port, token, e2), 1, "{who}");
        assert_eq!(
            find_links_ftt_home(port, token, e),
            vec![l_e.clone(), l_e1.clone(), l_e11.clone(), l_e2.clone(), l_e3.clone()],
            "{who}: the document's span admits every member's"
        );
        assert_eq!(count_ftt_home(port, token, e), 5, "{who}");
        assert_eq!(
            find_links_ftt_home(port, token, e1),
            vec![l_e1.clone(), l_e11.clone()],
            "{who}: E.1's and its daughter's, none of E.2's"
        );
        assert_eq!(count_ftt_home(port, token, e1), 2, "{who}");
        assert_eq!(find_links_ftt_home(port, token, &e3), vec![l_e3.clone()], "{who}: E.3's alone");
        assert_eq!(find_links_ftt_home(port, token, &e11), vec![l_e11.clone()], "{who}: the daughter's alone");
    }
    sd.shutdown();
}

/// M6 — the ceremony's form: a private link L homed in `F` on P's bytes; S's
/// `edit_link {original: L, d_s: E.2, d_a: F}` with the successor's endsets
/// V-specs on `E.2`, attested over the pair's row (`d_s` then `d_a`), is
/// `ack_edit` — the successor under the member, the claim under `F`; B's
/// same edit is gated (`d_s` published); the successor is found by content
/// at `E.1` on P, by the guest too, where L is the owner's alone; `in_claims`
/// and `out_claims` show the claim to S and no row to the guest (§The read
/// predicate: only rows whose home you may read).
#[test]
fn the_ceremonys_edit_link_homes_the_successor_in_the_member_and_the_claim_in_the_draft() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let Chain { e1, e2, f, .. } = chain(port, &signed, &bare);
    let l = acked_addr(&op(port, Some(&bare), &citation(&f, &vspec(&f, 1, P_LEN), NONE)));
    assert_eq!(l, format!("{f}.0.2.1"), "the private link, F's own");
    let frame = format!(
        r#"{{"op":"edit_link","original":"{l}","d_s":"{e2}","d_a":"{f}","successor":{{"from":{},"to":{},"ty":{}}}}}"#,
        vspec(&e2, 1, P_LEN),
        vspec(&e2, P_LEN + 1, Q_LEN),
        addrs_slot(&[T_CITATION])
    );

    let before = head_position(port);
    assert_eq!(verdict(&op(port, Some(&bare), &frame)), GATED, "the bare edit: d_s is published");
    assert_eq!(head_position(port), before);
    let v = op(port, Some(&signed), &frame);
    let ack = expect_resp(&v, "ack_edit");
    let successor = ack["successor"].as_str().expect("successor").to_string();
    let claim = ack["claim"].as_str().expect("claim").to_string();
    assert_eq!(successor, format!("{e2}.0.2.1"), "the successor under the member");
    assert_eq!(claim, format!("{f}.0.2.2"), "the claim under F");

    assert_eq!(find_links_v(port, None, &e1, 1, P_LEN), floor_and(&[&successor]), "the guest at E.1 on P");
    assert_eq!(
        find_links_v(port, Some(&signed), &e1, 1, P_LEN),
        floor_and(&[&successor, &l]),
        "the owner at E.1 on P: the successor and L, F's own"
    );
    let rows = op(port, Some(&signed), &format!(r#"{{"op":"in_claims","view":"active","y":"{l}"}}"#));
    assert_eq!(
        expect_resp(&rows, "claims")["claims"],
        json!([{"active": true, "claim": claim, "home": f, "new": successor, "old": l}]),
        "{rows}"
    );
    assert_eq!(claims_out(port, Some(&signed), &successor, "active"), vec![claim.clone()]);
    assert_eq!(claims_in(port, None, &l, "active"), Vec::<String>::new(), "the guest: no row");
    assert_eq!(claims_out(port, None, &successor, "active"), Vec::<String>::new(), "the guest: no row");
    sd.shutdown();
}

/// M7 — the daughter is a home: S's `make_link` homed in `E.1.1` lands at
/// `E.1.1.0.2.1`, admitted by `{home: [E]}` and by `{home: [E.1]}` and not by
/// `{home: [E.2]}`, and found by content at every member holding P.
#[test]
fn the_daughter_is_a_home_under_its_base_and_its_document() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let c = chain(port, &signed, &bare);
    let e11 = daughter(port, &signed, &c);
    let Chain { e, e1, e2, .. } = &c;
    let l = acked_addr(&op(port, Some(&signed), &citation(&e11, &vspec(&e11, 1, P_LEN), &vspec(e1, 1, P_LEN))));
    assert_eq!(l, format!("{e11}.0.2.1"), "the daughter's own link subspace");

    assert_eq!(find_links_ftt_home(port, None, e), vec![l.clone()], "under the document");
    assert_eq!(find_links_ftt_home(port, None, e1), vec![l.clone()], "under its base");
    assert_eq!(find_links_ftt_home(port, None, e2), Vec::<String>::new(), "not under E.2");
    assert_eq!(find_links_ftt_home(port, None, &e11), vec![l.clone()], "its own");
    for d in [e11.as_str(), e1.as_str(), e2.as_str(), e.as_str()] {
        assert_eq!(find_links_v(port, None, d, 1, P_LEN), floor_and(&[&l]), "by content at {d}");
    }
    sd.shutdown();
}

/// M8 — retraction is global (R16; wire.md `nullify`): S's `nullify {home:
/// E.2, target: E.2.0.2.1}`, attested, is acked with the retraction's
/// address — the member's next; afterwards `find_links_v` at `E.1`, `E.2`,
/// `E` and `F`, and `{home: [E.2]}`, answer the link no more; B's `nullify`
/// of it, before and after, is `signed_session_required` — the gate reads
/// the record's home and the target's.
#[test]
fn a_retraction_homed_in_the_member_removes_the_link_everywhere() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let Chain { e, e1, e2, f } = chain(port, &signed, &bare);
    let l1 = acked_addr(&op(port, Some(&signed), &citation(&e2, &vspec(&e2, 1, P_LEN), &vspec(&e1, 1, P_LEN))));
    assert_eq!(l1, format!("{e2}.0.2.1"));
    for d in [e1.as_str(), e2.as_str(), e.as_str()] {
        assert_eq!(find_links_v(port, None, d, 1, P_LEN), floor_and(&[&l1]), "before: at {d}");
    }

    let before = head_position(port);
    assert_eq!(verdict(&op(port, Some(&bare), &nullify_frame(&e2, &l1))), GATED, "the bare retraction");
    assert_eq!(head_position(port), before);
    let v = op(port, Some(&signed), &nullify_frame(&e2, &l1));
    assert_eq!(verdict(&v), "ok", "{v}");
    let retraction = acked_addr(&v);
    assert_eq!(retraction, format!("{e2}.0.2.2"), "the retraction, the member's next link");

    for d in [e1.as_str(), e2.as_str(), e.as_str()] {
        assert_eq!(find_links_v(port, None, d, 1, P_LEN), floor_and(&[]), "after: at {d}");
    }
    assert_eq!(find_links_v(port, Some(&bare), &f, 1, P_LEN), floor_and(&[]), "after: at F");
    let homed = find_links_ftt_home(port, None, &e2);
    assert!(!homed.contains(&l1), "the retracted link is gone from its home's answer: {homed:?}");
    assert_eq!(homed, vec![retraction.clone()], "the member's active links: the retraction record alone");
    assert_eq!(count_ftt_home(port, None, &e2), 1);
    assert_eq!(read_link(port, None, &l1)["slots"].as_array().map(Vec::len), Some(3), "the value stands, retracted");
    assert_eq!(verdict(&op(port, Some(&bare), &nullify_frame(&e2, &l1))), GATED, "the bare re-retraction");
    sd.shutdown();
}

/// M9 — the feed names the member (§The change feed: a link write names its
/// home): the `/changes` row for M1's write carries `op: "make_link"`,
/// `docs: [E.2]`, `link` the acked address, `at` the ack's own position, the
/// request's `attest` and no `key` — the same row to the guest, `E.2` being
/// published — and the position reads back: `read_link` at it through
/// `/op-at` answers the link, and at the position before it nothing.
#[test]
fn the_feed_row_of_a_member_homed_link_names_the_member() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let Chain { e1, e2, .. } = chain(port, &signed, &bare);

    let before = head_position(port);
    let v = op(port, Some(&signed), &citation(&e2, &vspec(&e2, 1, P_LEN), &vspec(&e1, 1, P_LEN)));
    let l1 = acked_addr(&v);
    let at = acked_at(&v);
    assert!(at > before, "the write advanced the head");
    for token in [Some(signed.as_str()), None] {
        let rows = changes_since(port, token, before);
        assert_eq!(rows.len(), 1, "one write, one row: {rows:?}");
        let row = &rows[0];
        assert_eq!(row["at"].as_u64(), Some(at), "{row}");
        assert_eq!(row["op"].as_str(), Some("make_link"), "{row}");
        assert_eq!(row["docs"], json!([e2]), "the row names the member as the home: {row}");
        assert_eq!(row["link"].as_str(), Some(l1.as_str()), "{row}");
        assert!(row.get("attest").is_some_and(|a| a["sig"].is_string()), "a signed row carries its attest: {row}");
        assert!(row.get("key").is_none(), "and no key: {row}");
    }
    let then = op_at_ok(port, None, at, &read_link_frame(&l1));
    assert_eq!(expect_resp(&then, "link_value")["link"]["slots"].as_array().map(Vec::len), Some(3), "{then}");
    let earlier = op_at_ok(port, None, before, &read_link_frame(&l1));
    assert!(expect_resp(&earlier, "link_value")["link"].is_null(), "{earlier}");
    sd.shutdown();
}

/// M10 — the member homes the publication's own `links` (the link-sets
/// design §5.7; lane S3): a third shot off `E.2` re-supplying P and Q by
/// reference, carrying one `links` entry homed in the tag `member` with
/// `from` P by the member-position form, mints `E.3` and the copy as
/// `E.3`'s first link in ONE commit — its slots P's I-span under `E`, the
/// empty TO and the citation type, as the two-step `make_link` stores them —
/// found by identity at `E.1`, `E.2`, `E.3`, the bare `E` and the
/// transclusion `F`, absent over Q's region, in `E.3`'s subspace and no
/// other member's; the row names `E.3` first.
#[test]
fn the_publication_s_links_entry_lands_in_the_members_own_subspace_and_is_found_by_identity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let Chain { e, e1, e2, f } = chain(port, &signed, &bare);
    let head = json(&get(port, "/health").1)["log_position"].as_u64().expect("log_position");
    let mut frame: Value = serde_json::from_str(&publish_frame(&e, Some((&e2, P_LEN + Q_LEN)), None, &shot_runs(port, None, &e2, 1, P_LEN + Q_LEN))).expect("a frame");
    frame["links"] = json!([{"home": "member", "from": {"member": [{"ordinal": "1", "width": P_LEN.to_string()}]}, "to": {"addrs": []}, "ty": {"addrs": [T_CITATION]}}]);
    let e3 = acked_addr(&op(port, Some(&signed), &frame.to_string()));
    assert_eq!(e3, format!("{e}.3"));
    let copy = format!("{e3}.0.2.1");
    let link = read_link(port, None, &copy);
    assert_eq!(
        link["slots"],
        json!([p_slot(&e), [], [{"start": T_CITATION, "width": "0.0.0.0.0.0.0.0.1"}]]),
        "the slots as stored: P's identity, the TO empty, the type: {link}"
    );
    for d in [e1.as_str(), e2.as_str(), e3.as_str(), e.as_str()] {
        assert_eq!(find_links_v(port, None, d, 1, P_LEN), floor_and(&[&copy]), "P's region at {d}");
        assert_eq!(count_v(port, None, d, 1, P_LEN), 3, "the census at {d}");
    }
    assert_eq!(find_links_v(port, Some(&bare), &f, 1, P_LEN), floor_and(&[&copy]), "the transclusion");
    assert_eq!(find_links_v(port, None, &e3, P_LEN + 1, Q_LEN), floor_and(&[]), "Q's region");
    assert_eq!(find_links_ftt_home(port, None, &e3), vec![copy.clone()], "E.3's own subspace");
    assert_eq!(find_links_ftt_home(port, None, &e2), Vec::<String>::new(), "E.2's holds none");
    let rows = changes_since(port, None, head);
    assert_eq!(rows.len(), 1, "one commit: {rows:?}");
    assert_eq!(rows[0]["docs"], json!([e3]), "the member first — and alone, the copy homed in it: {}", rows[0]);
    sd.shutdown();
}
