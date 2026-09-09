//! §3 OF THE LANE-4 BRIEF — LANE 3.3's H1 RESIDUE: (a) the WITHHELD ARM at
//! position — `/op-at` reads against the HEAD's sets (PUB-6.48), so a
//! published member that windows a draft delivers the withheld item at every
//! position the draft is reconstructed at, to the outside principal and the
//! guest alike; (b) the RESULT-SET HOME FILTER (PUB-6.13) — every discovery
//! result set the wire lists drops a draft-homed member for a reader OUTSIDE
//! the owner's subtree, one cell per read. TESTS ONLY; a red is a finding.
//!
//! COVERED-BY: the draft ITSELF at every position (`withheld` ahead of the
//! N-world's registration check and of the history refusals, PUB-6.49) —
//! `history.rs`; the guest's drop over `find_links_v`/`count_v`/`window_v`/
//! `retrieve_endsets` — `read_surface.rs`; the guest's class scan filtered to
//! empty — `scan_bound.rs`; `edition_claims`' home filter for a stranger —
//! `publication_reads.rs`.

mod common;

use common::*;
use serde_json::{json, Value};

/// The per-byte text of a historical delivery.
fn text_in(v: &Value) -> String {
    expect_resp(v, "delivery")["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|i| i["content"].as_str().unwrap_or(""))
        .collect()
}

/// H1 residue (a) — the withheld arm at position: a member of doc 1 windows
/// the owner's draft at two non-contiguous runs; at the member's own
/// position, at a later one, and through the bare address, `/op-at` delivers
/// TWO withheld items to the guest and to two strangers; before the member
/// existed the head-set check passes (the member is published at the head)
/// and the N-world's registration check answers; and a grant committed
/// AFTER every position opens the same positions to its grantee alone.
#[test]
fn h1_a_op_at_delivers_the_withheld_arm_at_every_position_to_the_outsider_and_the_guest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);

    let d = owner_draft(port, &owner);
    let at_i = acked_at(&insert_text(port, &owner, &d, 1, "abcde"));
    let v = op(
        port,
        Some(&signed),
        &publish_frame(CLAIMANT_DOC1, None, None, &[run(&d, &format!("{d}.0.1.1"), 2), run(&d, &format!("{d}.0.1.4"), 2)]),
    );
    let (m, at_m) = (acked_addr(&v), acked_at(&v));
    let at_x = acked_at(&insert_text(port, &owner, &d, 6, "f"));
    let b = seat_stranger(port, 901);
    let c = seat_stranger(port, 902);
    let masked = json!([withheld_item(&d, 2), withheld_item(&d, 2)]);
    let frame = retrieve_frame(&m, 1, 4);
    let bare_frame = retrieve_frame(CLAIMANT_DOC1, 1, 4);

    for token in [None, Some(b.session.as_str()), Some(c.session.as_str())] {
        for at in [at_m, at_x] {
            let v = op_at_ok(port, token, at, &frame);
            assert_eq!(expect_resp(&v, "delivery")["items"], masked, "H1 (a): the withheld arm at position {at}: {v}");
            assert_eq!(v["as_of"].as_u64(), Some(at), "stamped with the position it is of: {v}");
            let v = op_at_ok(port, token, at, &bare_frame);
            assert_eq!(expect_resp(&v, "delivery")["items"], masked, "…and through the bare address at {at}: {v}");
        }
        // Before the member existed: the N-world's own registration answer.
        let v = op_at_ok(port, token, at_i, &frame);
        assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("doc_not_registered"), "{v}");
        // The draft itself, at the member's position: the rejection.
        assert_withheld(&op_at_ok(port, token, at_m, &read1_frame(&d)), &d);
    }

    // A grant to B, committed after every position above.
    let v = typed_link(port, &signed, CLAIMANT_DOC1, &[d.as_str()], &[b.account.as_str()], T_GRANT);
    let at_g = acked_at(&v);
    assert!(at_g > at_x);
    for at in [at_m, at_x, at_g] {
        assert_eq!(text_in(&op_at_ok(port, Some(&b.session), at, &frame)), "abde", "the grantee reads at {at} through the head's grant");
        assert_eq!(expect_resp(&op_at_ok(port, None, at, &frame), "delivery")["items"], masked, "the guest never does");
        assert_eq!(expect_resp(&op_at_ok(port, Some(&c.session), at, &frame), "delivery")["items"], masked, "nor the ungranted stranger");
    }
    sd.shutdown();
}

/// H1 residue (b) — the result-set home filter for a reader OUTSIDE the
/// subtree (PUB-6.13, PUB-6.17, PUB-6.19): a link homed in the owner's draft
/// reaching doc 1's content, a ghost class with one member in the draft and
/// one in doc 1, a draft that copies doc 1's atom, and claims homed in the
/// draft and in doc 1 — every discovery read drops the draft-homed row for a
/// stranger, keeps the published-homed one, and the owner reads both. The
/// claim KEY is a filter value, never a consulted address (PUB-6.12).
#[test]
fn h1_b_every_discovery_result_set_drops_a_draft_homed_member_for_a_reader_outside_the_subtree() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let d = draft_with(port, &owner, "d");

    // L: homed in the draft; FROM and TYPE resolve doc 1's ordinal 1, TO the
    // draft's own ordinal 1 (read_surface's shape: its TYPE pair surfaces
    // uniquely in retrieve_endsets).
    let l = acked_addr(&op(port, Some(&owner), &link_frame(&d, &vspec(CLAIMANT_DOC1, 1, 1), &vspec(&d, 1, 1), &vspec(CLAIMANT_DOC1, 1, 1))));
    // The ghost class G: one member homed in the draft, one in doc 1.
    let g = format!("{CLAIMANT_DOC1}.0.3.6.55");
    let g_slot = addrs_slot(&[g.as_str()]);
    let l2 = acked_addr(&op(port, Some(&owner), &link_frame(&d, r#"{"addrs":[]}"#, r#"{"addrs":[]}"#, &g_slot)));
    let p = acked_addr(&op(port, Some(&signed), &link_frame(CLAIMANT_DOC1, r#"{"addrs":[]}"#, r#"{"addrs":[]}"#, &g_slot)));
    // The draft copies doc 1's atom: a container of its identity.
    expect_resp(&copy_span(port, &owner, &d, 2, CLAIMANT_DOC1, 1, 1), "ack");
    // Three public links and the claims over them: C1 in the draft, C2 and
    // C3 in doc 1 (C3's `old` is the draft-homed L — the straddle, legal).
    let la = ghost_link(port, &signed, CLAIMANT_DOC1, 1);
    let lb = ghost_link(port, &signed, CLAIMANT_DOC1, 2);
    let lc = ghost_link(port, &signed, CLAIMANT_DOC1, 3);
    let c1 = acked_addr(&op(port, Some(&owner), &assert_sup_frame(&d, &la, &lb)));
    let c2 = acked_addr(&op(port, Some(&signed), &assert_sup_frame(CLAIMANT_DOC1, &la, &lc)));
    let c3 = acked_addr(&op(port, Some(&signed), &assert_sup_frame(CLAIMANT_DOC1, &l, &lc)));
    let s = seat_stranger(port, 903);
    let mine = Some(owner.as_str());
    let theirs = Some(s.session.as_str());

    // 1–4: the region family over doc 1's ordinal 1.
    let (a, b) = (find_links_v(port, mine, CLAIMANT_DOC1, 1, 1), find_links_v(port, theirs, CLAIMANT_DOC1, 1, 1));
    assert!(a.contains(&l) && !b.contains(&l), "find_links_v drops the draft-homed link: {a:?} vs {b:?}");
    assert_eq!(a.len(), b.len() + 1, "…and exactly that row");
    assert!(b.iter().all(|x| a.contains(x)));
    assert_eq!(count_v(port, mine, CLAIMANT_DOC1, 1, 1), count_v(port, theirs, CLAIMANT_DOC1, 1, 1) + 1, "count_v counts the filtered set");
    let (a, b) = (window_v(port, mine, CLAIMANT_DOC1, 1, 1), window_v(port, theirs, CLAIMANT_DOC1, 1, 1));
    assert!(a.contains(&l) && !b.contains(&l), "window_v pages the filtered set: {a:?} vs {b:?}");
    assert_eq!(endset_pairs(port, mine, CLAIMANT_DOC1, 1, 1).len(), endset_pairs(port, theirs, CLAIMANT_DOC1, 1, 1).len() + 1, "retrieve_endsets answers the filtered rows");

    // 5–7: the four-set family over the ghost class — dropped, not emptied.
    let (a, b) = (addrs_of(&op(port, mine, &class_scan("find_links_ftt", &g))), addrs_of(&op(port, theirs, &class_scan("find_links_ftt", &g))));
    assert!(a.contains(&l2) && a.contains(&p), "the owner's scan holds both members: {a:?}");
    assert_eq!(b, vec![p.clone()], "find_links_ftt keeps the published-homed member alone");
    let n = |token: Option<&str>| expect_resp(&op(port, token, &class_scan("count_ftt", &g)), "count")["n"].as_u64().expect("n");
    assert_eq!((n(mine), n(theirs)), (2, 1), "count_ftt counts the filtered set");
    let (a, b) = (batch_of(&op(port, mine, &class_scan("window_ftt", &g))), batch_of(&op(port, theirs, &class_scan("window_ftt", &g))));
    assert!(a.contains(&l2) && a.contains(&p), "{a:?}");
    assert_eq!(b, vec![p.clone()], "window_ftt pages the filtered set");

    // 8: the containers of doc 1's atom.
    let (a, b) = (find_docs_containing(port, mine, CLAIMANT_DOC1, 1, 1), find_docs_containing(port, theirs, CLAIMANT_DOC1, 1, 1));
    assert!(a.contains(&d) && !b.contains(&d), "find_docs_containing drops the draft container: {a:?} vs {b:?}");
    assert!(b.iter().all(|x| a.contains(x)));

    // 9: the orphans a delete of doc 1's ordinal 1 would leave.
    let (a, b) = (orphans_of(port, mine, CLAIMANT_DOC1, 1, 1), orphans_of(port, theirs, CLAIMANT_DOC1, 1, 1));
    assert!(a.contains(&l) && !b.contains(&l), "delete_orphans drops the draft-homed link: {a:?} vs {b:?}");
    assert!(b.iter().all(|x| a.contains(x)));

    // 10–11: lineage, filtered by the CLAIM's home.
    let (a, b) = (claims_in(port, mine, &la, "active"), claims_in(port, theirs, &la, "active"));
    assert!(a.contains(&c1) && a.contains(&c2), "{a:?}");
    assert_eq!(b, vec![c2.clone()], "in_claims keeps the doc-1-homed claim alone");
    assert_eq!(claims_out(port, mine, &lb, "active"), vec![c1.clone()]);
    assert_eq!(claims_out(port, theirs, &lb, "active"), Vec::<String>::new(), "out_claims drops the draft-homed claim");
    let b = claims_out(port, theirs, &lc, "active");
    assert!(b.contains(&c2) && b.contains(&c3), "…and answers the doc-1-homed ones: {b:?}");

    // 12: the claim KEY is a filter value (PUB-6.12): L, absent to the
    // stranger by address, still keys the public claim naming it.
    assert!(read_link(port, theirs, &l).is_null(), "the draft-homed link is absent by address");
    assert_eq!(claims_in(port, theirs, &l, "active"), vec![c3.clone()], "in_claims over an unreadable key answers, never withheld");

    // The guest, one cell: the same drop.
    assert!(!find_links_v(port, None, CLAIMANT_DOC1, 1, 1).contains(&l));
    sd.shutdown();
}
