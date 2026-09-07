//! THE READ-SURFACE SWEEP over the wire (PUB round 2, lane 3.3): the read
//! predicate `readable(doc, principal) = published ∨ subtree ∨ grant`
//! (PUB-1.31), the doc-argument consult (PUB-6.12), the grant clause and its
//! ANY-PRINCIPAL form (PUB-5.8), and the serving bound (PUB-8.43). The daemon
//! builds the predicate off one head snapshot; M10 answers every read through
//! it. Reader classes: GUEST (no token), SUBTREE (the owner), GRANT-HOLDER (a
//! stranger the owner granted), NON-ENTITLED (a stranger without a grant).

mod common;

use common::*;
use serde_json::Value;

/// A stranger account under node 1, delegated from the bootstrap principal,
/// with its own session. Returns `(account, session)`.
fn stranger(port: u16, id: u64) -> (String, String) {
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let account =
        expect_resp(&v, "maybe_addr")["addr"].as_str().expect("a delegable prefix").to_string();
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{account}","new_id":{id}}}"#),
    );
    expect_resp(&v, "ack_addr");
    (account.clone(), open_session(port, id))
}

/// A private draft under the claimant's account, holding `text` from ordinal 1.
fn private_draft(port: u16, owner: &str, text: &str) -> String {
    let d = acked_addr(&op(
        port,
        Some(owner),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    ));
    expect_resp(
        &op(
            port,
            Some(owner),
            &format!(
                r#"{{"op":"insert","doc":"{d}","at":{{"subspace":"1","ordinal":"1"}},"values":["{text}"]}}"#
            ),
        ),
        "ack_addr",
    );
    d
}

// The grant is deposited through `common::deposit_grant` — the shared helper
// (lane 3.3c) — into the claimant's published doc 1 from the SIGNED session.

/// Read ordinal 1 of `doc` as `token` (None = guest).
fn read1(port: u16, token: Option<&str>, doc: &str) -> Value {
    op(
        port,
        token,
        &format!(
            r#"{{"op":"retrieve_v","specs":[{{"doc":"{doc}","span":{{"start":"1.1","width":"0.1"}}}}]}}"#
        ),
    )
}

/// Assert a WITHHELD rejection (PUB-8.4/8.5): code `withheld`, disposition
/// `reorder`, `site.addr` the document, no `detail`.
fn assert_withheld(v: &Value, doc: &str) {
    let rej = expect_resp(v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("withheld"), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("reorder"), "{v}");
    assert_eq!(rej["site"]["addr"].as_str(), Some(doc), "the withheld document: {v}");
    assert!(rej.get("detail").is_none(), "withheld carries no detail: {v}");
}

/// Assert a one-character delivery of `text`.
fn assert_delivers(v: &Value, text: &str) {
    let items = expect_resp(v, "delivery")["items"].as_array().expect("items");
    let got: String = items.iter().filter_map(|i| i["content"].as_str()).collect();
    assert_eq!(got, text, "delivered content: {v}");
}

/// H1 — the four reader classes against a private draft: the doc-argument
/// consult masks the guest and the non-entitled stranger with WITHHELD, the
/// owner reads by the subtree clause, and the grantee reads once granted.
#[test]
fn pub_8_43_the_read_surface_serves_the_four_reader_classes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL); // a bare owner session
    let draft = private_draft(port, &owner, "secret");
    let (b_account, b) = stranger(port, 901);

    // SUBTREE — the owner reads its own private draft.
    assert_delivers(&read1(port, Some(&owner), &draft), "s");
    // GUEST — no token: masked (published alone, PUB-5.5).
    assert_withheld(&read1(port, None, &draft), &draft);
    // NON-ENTITLED — a stranger, no grant: masked.
    assert_withheld(&read1(port, Some(&b), &draft), &draft);

    // Grant the draft to B, then B reads it — GRANT-HOLDER.
    deposit_grant(port, &signed, CLAIMANT_DOC1, &draft, Some(&b_account));
    assert_delivers(&read1(port, Some(&b), &draft), "s");
    // The guest is STILL masked — a grant is to a principal, not the guest.
    assert_withheld(&read1(port, None, &draft), &draft);
    // A different stranger is still non-entitled (grantee is PRINCIPAL-EXACT).
    let (_c_account, c) = stranger(port, 902);
    assert_withheld(&read1(port, Some(&c), &draft), &draft);

    sd.shutdown();
}

/// H1 — the ANY-PRINCIPAL grant (empty `to`, PUB-5.8): every bound principal
/// reads, the guest still does not.
#[test]
fn an_any_principal_grant_opens_a_draft_to_every_principal_but_not_the_guest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = private_draft(port, &owner, "open");
    let (_b_account, b) = stranger(port, 903);

    assert_withheld(&read1(port, Some(&b), &draft), &draft); // before
    deposit_grant(port, &signed, CLAIMANT_DOC1, &draft, None); // ANY-PRINCIPAL
    assert_delivers(&read1(port, Some(&b), &draft), "o"); // any principal reads
    assert_withheld(&read1(port, None, &draft), &draft); // the guest still does not
    sd.shutdown();
}

/// The serving bound (PUB-8.43): the read surface serves the predicate over
/// the wire — the subtree clause, the read-surface sweep (a masked read is a
/// `withheld` rejection, not a leak), and PUB-8.2's routed write refusals
/// (`published_target`) are all reachable. The interval is CLOSED for those
/// three; PUB-8.46's audit-view lookup is its remaining item (stated in
/// wire.md's changelog).
#[test]
fn pub_8_43_serving_bound_is_closed_for_the_three() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);

    // The subtree clause and the read-surface sweep — served over the wire.
    let draft = private_draft(port, &owner, "z");
    assert_delivers(&read1(port, Some(&owner), &draft), "z");
    assert_withheld(&read1(port, None, &draft), &draft);

    // PUB-8.2's routed write refusal is on the wire: an undeclared insert into
    // the published home is `published_target` (the version-chain refusals'
    // permanent class), not a read-surface answer — the two surfaces are
    // distinct and both present.
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"9"}},"values":["q"]}}"#
        ),
    );
    assert_eq!(
        expect_resp(&v, "rejected")["code"].as_str(),
        Some("published_target"),
        "the routed write refusal is present: {v}"
    );
    sd.shutdown();
}

/// A link homed in `home` that reaches into BOTH documents (the V-spec form —
/// each endset records the resolved position's I-address):
///
/// * FROM and a content-resolved TYPE record content ordinal 1 of `from_doc`,
///   so the link is found over `from_doc`'s region. The FROM endset collapses
///   with the ceremony enroll link's identical FROM under RETRIEVEENDSETS'
///   identity-withholding, so it is the TYPE pair — which no ceremony link
///   carries — that surfaces uniquely for the owner (PUB-6.17).
/// * TO records content ordinal 1 of `home`, so the link is DISCOVERABLE from
///   its own home (an endpoint reaching into the home's arrangement, not the
///   mere fact of being seated there).
fn link_from_ordinal_1(port: u16, token: &str, home: &str, from_doc: &str) -> String {
    let pos1 = |doc: &str| format!(r#"[{{"source":"{doc}","span":{{"start":"1.1","width":"0.1"}}}}]"#);
    acked_addr(&op(
        port,
        Some(token),
        &format!(
            r#"{{"op":"make_link","home":"{home}","from":{},"to":{},"ty":{}}}"#,
            pos1(from_doc),
            pos1(home),
            pos1(from_doc)
        ),
    ))
}

/// The `d`/`region` fields naming content ordinal 1 of `doc`.
fn region1(doc: &str) -> String {
    format!(r#""d":"{doc}","region":[{{"start":"1.1","width":"0.1"}}]"#)
}

fn addrs_of(v: &Value) -> Vec<String> {
    expect_resp(v, "addrs")["addrs"]
        .as_array()
        .expect("addrs")
        .iter()
        .map(|a| a.as_str().expect("an address").to_string())
        .collect()
}

/// H1 — the RESULT-SET row (PUB-6.13), LINK-ADDRESS ABSENCE (PUB-6.6) and the
/// DUAL ROW (PUB-6.8), on one link: homed in the owner's private draft, its
/// FROM/TYPE reaching the published doc 1's ceremony atom and its TO reaching
/// the draft's own content. Over doc 1 — readable to all — the guest's
/// discovery answers drop the row and the owner's hold it; by address the
/// link is ⊥ to the guest, exactly a never-deposited address; and where a
/// read carries both a document and a link (`d`, then the link), the document
/// is consulted first.
#[test]
fn a_draft_homed_link_is_dropped_from_the_guest_s_result_sets_and_absent_by_address() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = private_draft(port, &owner, "d");
    let link = link_from_ordinal_1(port, &owner, &draft, CLAIMANT_DOC1);

    // RESULT SET (PUB-6.13): dropped for the guest, present for the owner,
    // and exactly that one row differs — the ceremony's own links (homed in
    // doc 1, published) answer both classes.
    let find = |token: Option<&str>| -> Vec<String> {
        addrs_of(&op(port, token, &format!(r#"{{"op":"find_links_v",{}}}"#, region1(CLAIMANT_DOC1))))
    };
    let (guest, mine) = (find(None), find(Some(&owner)));
    assert!(!guest.contains(&link), "the guest's result set drops the draft-homed link: {guest:?}");
    assert!(mine.contains(&link), "the owner's result set holds it: {mine:?}");
    assert_eq!(mine.len(), guest.len() + 1, "exactly the one row differs");
    // The census counts the filtered set…
    let count = |token: Option<&str>| -> u64 {
        let v = op(port, token, &format!(r#"{{"op":"count_v",{}}}"#, region1(CLAIMANT_DOC1)));
        expect_resp(&v, "count")["n"].as_u64().expect("n")
    };
    assert_eq!(count(Some(&owner)), count(None) + 1, "count_v counts the filtered set");
    // …the page turns over it…
    let batch = |token: Option<&str>| -> Vec<String> {
        let v = op(
            port,
            token,
            &format!(r#"{{"op":"window_v","cur":null,"n":16,{}}}"#, region1(CLAIMANT_DOC1)),
        );
        expect_resp(&v, "page")["window"]["batch"]
            .as_array()
            .expect("batch")
            .iter()
            .map(|a| a.as_str().expect("an address").to_string())
            .collect()
    };
    assert!(!batch(None).contains(&link), "window_v pages the filtered set");
    assert!(batch(Some(&owner)).contains(&link));
    // …and the dropped row's endset fragments go with it.
    let endsets = |token: Option<&str>| -> usize {
        let v = op(port, token, &format!(r#"{{"op":"retrieve_endsets",{}}}"#, region1(CLAIMANT_DOC1)));
        expect_resp(&v, "endsets")["pairs"].as_array().expect("pairs").len()
    };
    assert_eq!(endsets(Some(&owner)), endsets(None) + 1, "retrieve_endsets answers the filtered rows");

    // LINK-ADDRESS ABSENCE (PUB-6.6): ⊥ to the guest, as a never-deposited
    // address — `link: null`, `{"err":"invalid"}` (never ⟨⟩), `false`.
    let v = op(port, None, &format!(r#"{{"op":"read_link","a":"{link}"}}"#));
    assert!(expect_resp(&v, "link_value")["link"].is_null(), "absent to the guest: {v}");
    let v = op(port, Some(&owner), &format!(r#"{{"op":"read_link","a":"{link}"}}"#));
    assert!(!expect_resp(&v, "link_value")["link"].is_null(), "present to the owner: {v}");
    let v = op(port, None, &format!(r#"{{"op":"follow_link","a":"{link}","slot":1}}"#));
    assert_eq!(
        expect_resp(&v, "follow")["result"],
        serde_json::json!({"err": "invalid"}),
        "⊥ to the guest, never the empty answer: {v}"
    );
    let v = op(port, Some(&owner), &format!(r#"{{"op":"follow_link","a":"{link}","slot":1}}"#));
    assert!(expect_resp(&v, "follow")["result"].get("ok").is_some(), "the owner follows it: {v}");
    let v = op(
        port,
        None,
        &format!(r#"{{"op":"discoverable_from","a":"{link}","d":"{CLAIMANT_DOC1}"}}"#),
    );
    assert_eq!(expect_resp(&v, "bool")["val"], serde_json::json!(false), "absent ⟹ not discoverable: {v}");
    let v = op(port, None, &format!(r#"{{"op":"project","a":"{link}","slot":1,"d":"{CLAIMANT_DOC1}"}}"#));
    assert_eq!(
        expect_resp(&v, "rejected")["code"].as_str(),
        Some("not_a_link"),
        "absent ⟹ the answer a non-link gets: {v}"
    );
    let v = op(port, Some(&owner), &format!(r#"{{"op":"project","a":"{link}","slot":1,"d":"{CLAIMANT_DOC1}"}}"#));
    expect_resp(&v, "span_set");

    // THE DUAL ROW (PUB-6.8): `d` is consulted FIRST — a draft `d` answers
    // `withheld` naming it, ahead of the link's own absence; the owner gets
    // the answer.
    let v = op(port, None, &format!(r#"{{"op":"discoverable_from","a":"{link}","d":"{draft}"}}"#));
    assert_withheld(&v, &draft);
    let v = op(port, Some(&owner), &format!(r#"{{"op":"discoverable_from","a":"{link}","d":"{draft}"}}"#));
    assert_eq!(
        expect_resp(&v, "bool")["val"],
        serde_json::json!(true),
        "its TO endpoint reaches its home's content, so the owner discovers it: {v}"
    );
    let v = op(port, None, &format!(r#"{{"op":"project","a":"{link}","slot":1,"d":"{draft}"}}"#));
    assert_withheld(&v, &draft);

    sd.shutdown();
}

/// H1 — REGISTRATION FIRST (PUB-7.5, PUB-6.12): an UNREGISTERED address is
/// fail-open at the predicate and answers the store's own
/// `doc_not_registered` to every class — a withheld answer is only ever a
/// registered private document, so absence is never masked as privacy.
#[test]
fn an_unregistered_document_answers_doc_not_registered_to_every_class() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (_b_account, b) = stranger(port, 904);
    let ghost = format!("{CLAIMANT_ACCOUNT}.0.77");
    for token in [None, Some(owner.as_str()), Some(b.as_str())] {
        let v = read1(port, token, &ghost);
        let rej = expect_resp(&v, "rejected");
        assert_eq!(rej["code"].as_str(), Some("doc_not_registered"), "never withheld: {v}");
        assert_eq!(rej["disposition"].as_str(), Some("reorder"), "{v}");
    }
    sd.shutdown();
}

/// H1 — the ORACLE cell: `/op-at` at the head is byte-identical to `/op` for
/// the same frame under the same session — the owner's delivery and the
/// guest's `withheld` alike (the predicate is the head's on both surfaces).
#[test]
fn a_historical_read_at_the_head_byte_equals_the_live_read_per_class() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = private_draft(port, &owner, "h");
    let frame = format!(
        r#"{{"op":"retrieve_v","specs":[{{"doc":"{draft}","span":{{"start":"1.1","width":"0.1"}}}}]}}"#
    );
    let head = json(&get(port, "/health").1)["log_position"].as_u64().expect("log_position");
    let env = format!(r#"{{"at":{head},"frame":{frame}}}"#);
    for token in [Some(owner.as_str()), None] {
        let (st, live) = http(port, "POST", "/op", token, frame.as_bytes());
        assert_eq!(st, 200);
        let (st, hist) = http(port, "POST", "/op-at", token, env.as_bytes());
        assert_eq!(st, 200);
        assert_eq!(
            live,
            hist,
            "the head answers both surfaces alike:\n live {}\n hist {}",
            String::from_utf8_lossy(&live),
            String::from_utf8_lossy(&hist)
        );
        match token {
            Some(_) => assert_delivers(&json(&live), "h"),
            None => assert_withheld(&json(&live), &draft),
        }
    }
    sd.shutdown();
}

/// H1 — the DELIVERY's withheld arm (wire.md §Response shapes, v7.4): a
/// published member that WINDOWS the owner's private draft (a run whose
/// origin is the draft, not the staging draft) delivers, to the guest, the
/// `withheld` item at each masked run's own position — two non-contiguous
/// runs from one origin are two items, never one of the summed width — and
/// the extents are not shrunk. The owner reads the bytes.
#[test]
fn a_windowed_draft_run_is_a_withheld_item_at_its_own_position() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = private_draft(port, &owner, "abcde"); // I-positions {draft}.0.1.1 ..= .5

    // The birth member of doc 1's chain: two NON-CONTIGUOUS windows of the
    // draft — positions 1–2 and 4–5 — and nothing else. No `draft` field:
    // the draft is an "other document", windowed by reference, not the
    // staging draft re-minted as doc 1's own identity.
    let shot = format!(
        r#"{{"op":"publish","doc":"{CLAIMANT_DOC1}","runs":[{{"origin":"{draft}","i_start":"{draft}.0.1.1","width":"2"}},{{"origin":"{draft}","i_start":"{draft}.0.1.4","width":"2"}}]}}"#
    );
    let member = acked_addr(&op(port, Some(&signed), &shot));

    let read4 = |token: Option<&str>, doc: &str| -> Value {
        op(
            port,
            token,
            &format!(
                r#"{{"op":"retrieve_v","specs":[{{"doc":"{doc}","span":{{"start":"1.1","width":"0.4"}}}}]}}"#
            ),
        )
    };
    let masked = serde_json::json!([
        {"withheld": {"origin": draft, "width": "2"}},
        {"withheld": {"origin": draft, "width": "2"}}
    ]);
    // The guest: two withheld items at their own positions — by the member's
    // address and by the bare address that floats to it.
    for doc in [member.as_str(), CLAIMANT_DOC1] {
        let v = read4(None, doc);
        assert_eq!(expect_resp(&v, "delivery")["items"], masked, "per-run masking of {doc}: {v}");
    }
    // The owner: the bytes.
    let v = read4(Some(&owner), &member);
    let text: String = expect_resp(&v, "delivery")["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|i| i["content"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(text, "abde");
    // Extents are the arrangement's, unshrunk, for every class.
    for token in [None, Some(owner.as_str())] {
        let v = op(port, token, &format!(r#"{{"op":"retrieve_doc_v_span_set","doc":"{member}"}}"#));
        let set = expect_resp(&v, "span_set")["set"].as_array().expect("set").clone();
        let content = set.iter().find(|s| s["start"].as_str() == Some("1.1")).expect("a content span");
        assert_eq!(content["width"].as_str(), Some("0.4"), "unshrunk: {v}");
    }
    sd.shutdown();
}
