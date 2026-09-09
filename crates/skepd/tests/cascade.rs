//! §4 OF THE LANE-4 BRIEF — THE CASCADE COVERAGE of ruling 20's fifteen
//! `pub-2.9-private-versionless` goldens (`conformance/adjudication/
//! decisions.md`, owner 2026-09-08: "add it"). Each golden diverges at its
//! `create_version` (or `open_document` conflict-copy) op because udanax
//! versions a PRIVATE draft and skep refuses (PUB-2.9); every later op is the
//! refusal's cascade and no longer differentially tested. Here each golden's
//! post-refusal behaviour is re-expressed on a PUBLISHED-BORN source in
//! skep's own terms — the publish shot (`publish`, PUB-2.33) where the golden
//! versioned and edited, `version` where it versioned and read, the same
//! reads and links after it — asserting what the SPEC promises of a version
//! chain (`02-versions.clean.md`), never what udanax answered. One test per
//! golden, named for it. Nothing in `conformance/` moves.
//!
//! The fixture: a claimed board; the claimant's editions are explicit
//! `published:true` mints from its signed session, their text a declared
//! deposit (PUB-2.59, the one insert a published document admits); its
//! drafts are flagless later mints, edited in place; every shot is staged in
//! a draft and shot from the signed session.
//!
//! Tally: RECOVERED 15 · NO-SPEC-PROMISE 0 · FINDING 0 (see the report).
//! udanax's duplicate answer in `version_with_links` (`find_links` on the
//! source answering the one link twice) is udanax's and is not asserted.

mod common;

use std::collections::BTreeSet;

use common::*;

/// A chain `levels` deep off `base_text`, an edit at every level (PUB-2.33's
/// shot, each staged off the previous member and re-supplying its runs plus
/// a draft's suffix): the edition and its members `E.1 ..= E.(levels+1)`,
/// member 0 the birth version holding the base text alone.
fn depth_chain(port: u16, signed: &str, owner: &str, base_text: &str, levels: usize, suffix: impl Fn(usize) -> String) -> (String, Vec<String>) {
    let e = edition_with(port, signed, base_text);
    let mut extent = base_text.len() as u64;
    let mut members = vec![shot(port, signed, &e, None, None, &shot_runs(port, None, &e, 1, extent))];
    for k in 1..=levels {
        let text = suffix(k);
        let d = draft_with(port, owner, &text);
        let prev = members.last().expect("a member").clone();
        let mut runs = shot_runs(port, None, &prev, 1, extent);
        runs.push(run(&d, &format!("{d}.0.1.1"), text.len() as u64));
        let m = shot(port, signed, &e, Some((&prev, extent)), Some(&d), &runs);
        extent += text.len() as u64;
        assert_eq!(content_extent(port, None, &m), extent, "level {k}'s extent");
        members.push(m);
    }
    (e, members)
}

/// allocation_independence/version_insert_allocation_independence — a
/// deposit after a version continues the document's ONE I-space (PUB-2.12,
/// PUB-2.52: one prefix down the chain), the chain's members allocate
/// densely under their anchor (PUB-2.6), each deposit lands in the head
/// member (PUB-2.66) and a pinned member never grows (PUB-2.65).
#[test]
fn cascade_version_insert_allocation_independence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    let e = published_edition(port, &signed);
    assert_eq!(deposit_text(port, &signed, &e, 1, "AAA"), format!("{e}.0.1.1"));
    let m1 = acked_addr(&version_of(port, &signed, &e, None));
    assert_eq!(m1, format!("{e}.1"), "the document-level chain opens at member 1");
    assert_eq!(deposit_text(port, &signed, &e, 4, "BBB"), format!("{e}.0.1.4"), "VERSION did not move the element chain: one I-space (PUB-2.52)");
    assert_eq!(content_extent(port, None, &m1), 6, "the deposit landed in the head member (PUB-2.66)");
    let m2 = acked_addr(&version_of(port, &signed, &e, None));
    assert_eq!(m2, format!("{e}.2"), "INSERT did not move the document chain: dense under its anchor (PUB-2.6)");
    assert_eq!(deposit_text(port, &signed, &e, 7, "CCC"), format!("{e}.0.1.7"));
    assert_eq!(text_of(port, None, &e, 1, 9), "AAABBBCCC");
    assert_eq!(expand_runs(&image_runs(port, None, &e, 1, 9)), i_range(&e, 1, 9), "the head's image is the one I-space, contiguous");
    assert_eq!(content_extent(port, None, &m1), 6, "a pinned member never grows (PUB-2.65)");
    assert_eq!(content_extent(port, None, &m2), 9);
    sd.shutdown();
}

/// allocation_independence/version_link_allocation_independence — links homed
/// in the document land in ITS link subspace, one prefix down the chain,
/// whatever members exist (PUB-2.12), the document chain unmoved by them.
#[test]
fn cascade_version_link_allocation_independence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let e = edition_with(port, &signed, "ABCDEF");
    let link = |n: u64| -> String {
        acked_addr(&op(port, Some(&signed), &link_frame(&e, &vspec(&e, 1, 1), r#"{"addrs":[]}"#, &ghost_ty(&e, n))))
    };

    let l1 = link(1);
    assert_eq!(l1, format!("{e}.0.2.1"));
    assert_eq!(acked_addr(&version_of(port, &signed, &e, None)), format!("{e}.1"));
    let l2 = link(2);
    assert_eq!(l2, format!("{e}.0.2.2"), "VERSION did not move the link chain (PUB-2.12)");
    assert_eq!(acked_addr(&version_of(port, &signed, &e, None)), format!("{e}.2"), "MAKELINK did not move the document chain");
    let l3 = link(3);
    assert_eq!(l3, format!("{e}.0.2.3"));
    let found = find_links_v(port, None, &e, 1, 1);
    for l in [&l1, &l2, &l3] {
        assert!(found.contains(l), "the link {l} is found from the head, version-proof (PUB-2.51): {found:?}");
    }
    sd.shutdown();
}

/// compare_fanout/fanout_version_and_copy_routes — a destination holding the
/// same content by a version route and a direct route compares whole against
/// the original and against the version, and the version against the
/// original: content identity is shared by copy-on-write (PUB-2.51).
#[test]
fn cascade_fanout_version_and_copy_routes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let source = edition_with(port, &signed, "MNOPQRST");
    let version = acked_addr(&version_of(port, &signed, &source, None));
    let dest = owner_draft(port, &owner);
    expect_resp(&copy_span(port, &owner, &dest, 1, &version, 1, 4), "ack"); // MNOP from the version
    expect_resp(&copy_span(port, &owner, &dest, 5, &source, 1, 4), "ack"); // MNOP from the original
    assert_eq!(text_of(port, Some(&owner), &dest, 1, 8), "MNOPMNOP");

    let both_routes: BTreeSet<(u64, u64)> = [(1, 1), (2, 2), (3, 3), (4, 4), (5, 1), (6, 2), (7, 3), (8, 4)].into_iter().collect();
    assert_eq!(compare_positions(port, Some(&owner), &dest, 8, &source, 8), both_routes, "both routes vs the original");
    assert_eq!(compare_positions(port, Some(&owner), &dest, 8, &version, 8), both_routes, "both routes vs the version");
    assert_eq!(compare_positions(port, None, &version, 8, &source, 8), shared_prefix(8), "the version vs the original, whole");
    sd.shutdown();
}

/// content/insert_vspace_mapping — a middle insert on a published document is
/// a shot; the pinned version before it keeps its V→I mapping and the new
/// member's shows the shift: content after the insertion point keeps its
/// identity at shifted positions, the inserted text is fresh identity
/// (PUB-2.40, PUB-2.51).
#[test]
fn cascade_insert_vspace_mapping() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let e = edition_with(port, &signed, "ABCDE");
    let at = |doc: &str, k: u64| text_of(port, None, doc, k, 1);
    let before: Vec<String> = (1..=5).map(|k| at(&e, k)).collect();
    assert_eq!(before, ["A", "B", "C", "D", "E"]);

    let version_before = acked_addr(&version_of(port, &signed, &e, None));
    let d = draft_with(port, &owner, "XY");
    let runs = [run(&e, &format!("{e}.0.1.1"), 2), run(&d, &format!("{d}.0.1.1"), 2), run(&e, &format!("{e}.0.1.3"), 3)];
    let after = shot(port, &signed, &e, Some((&version_before, 5)), Some(&d), &runs);
    assert_eq!(after, format!("{e}.2"));
    assert_eq!(content_extent(port, None, &e), 7);
    assert_eq!(text_of(port, None, &e, 1, 7), "ABXYCDE");
    let now: Vec<String> = (1..=7).map(|k| at(&e, k)).collect();
    assert_eq!(now, ["A", "B", "X", "Y", "C", "D", "E"], "how the V-addresses shifted");
    let identity: BTreeSet<(u64, u64)> = [(1, 1), (2, 2), (3, 5), (4, 6), (5, 7)].into_iter().collect();
    assert_eq!(compare_positions(port, None, &version_before, 5, &after, 7), identity, "I-space identity preserved across the shift");
    assert_eq!(compare_positions(port, None, &version_before, 5, &e, 7), identity, "…and the bare address floats to the member (PUB-2.49)");
    sd.shutdown();
}

/// depth_scale/depth_version_chain_4 — a chain four deep with an edit at
/// every level: each member's text, its address dense under the anchor
/// (PUB-2.6), and the pairwise compares — level 4 vs level 0 shares the base,
/// each level shares its predecessor whole (PUB-2.29, PUB-2.51).
#[test]
fn cascade_depth_version_chain_4() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (e, levels) = depth_chain(port, &signed, &owner, "Base text.", 4, |k| format!(" v{k}."));
    let mut text = String::from("Base text.");
    for (k, member) in levels.iter().enumerate() {
        assert_eq!(*member, format!("{e}.{}", k + 1), "level {k}'s address");
        if k > 0 {
            text.push_str(&format!(" v{k}."));
        }
        assert_eq!(text_of(port, None, member, 1, text.len() as u64), text, "level {k}");
    }
    assert_eq!(compare_positions(port, None, &levels[4], 26, &levels[0], 10), shared_prefix(10), "level 4 vs level 0");
    assert_eq!(compare_positions(port, None, &levels[4], 26, &levels[3], 22), shared_prefix(22), "level 4 vs level 3");
    assert_eq!(compare_positions(port, None, &levels[2], 18, &levels[1], 14), shared_prefix(14), "level 2 vs level 1");
    sd.shutdown();
}

/// depth_scale/depth_version_chain_7 — the same, seven deep.
#[test]
fn cascade_depth_version_chain_7() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (e, levels) = depth_chain(port, &signed, &owner, "0123456789", 7, |k| format!(".{k}"));
    let mut text = String::from("0123456789");
    for (k, member) in levels.iter().enumerate() {
        assert_eq!(*member, format!("{e}.{}", k + 1), "level {k}'s address");
        if k > 0 {
            text.push_str(&format!(".{k}"));
        }
        assert_eq!(text_of(port, None, member, 1, text.len() as u64), text, "level {k}");
    }
    assert_eq!(compare_positions(port, None, &levels[7], 24, &levels[0], 10), shared_prefix(10), "level 7 vs level 0");
    assert_eq!(compare_positions(port, None, &levels[7], 24, &levels[6], 22), shared_prefix(22), "level 7 vs level 6");
    sd.shutdown();
}

/// documents/conflict_copy — the "conflict copy" of a document in hand: on a
/// PUBLISHED document it is the chain's next member, sharing the content
/// (PUB-2.17); the private working copy is the POOL sibling, a document and
/// never a chain member (PUB-2.20, PUB-2.21, PUB-2.30).
#[test]
fn cascade_conflict_copy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let text = "Shared document content";
    let e = edition_with(port, &signed, text);

    let member = acked_addr(&version_of(port, &signed, &e, None));
    assert_eq!(member, format!("{e}.1"));
    assert_eq!(text_of(port, None, &member, 1, 23), text, "the member shares the content");

    let sibling = acked_addr(&op(port, Some(&owner), &create_frame(CLAIMANT_ACCOUNT, Some(false))));
    expect_resp(&copy_span(port, &owner, &sibling, 1, &e, 1, 23), "ack");
    assert_eq!(text_of(port, Some(&owner), &sibling, 1, 23), text, "the pool sibling holds the content by identity");
    assert_eq!(image_runs(port, Some(&owner), &sibling, 1, 23), vec![(format!("{e}.0.1.1"), 23)]);
    assert!(!sibling.starts_with(&format!("{e}.")), "a document, never a chain member: {sibling}");
    let v = doc_metadata(port, Some(&owner), &sibling);
    assert_eq!(expect_resp(&v, "doc_metadata")["published"].as_bool(), Some(false), "…and private: {v}");
    sd.shutdown();
}

/// edgecases/version_immediately — a version of an EMPTY published document
/// exists, empty; content deposited into it lands in it — the head member —
/// and the bare address floats to it (PUB-2.49, PUB-2.66).
#[test]
fn cascade_version_immediately() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let e = published_edition(port, &signed);
    let member = acked_addr(&version_of(port, &signed, &e, None));
    assert_eq!(member, format!("{e}.1"));
    assert_eq!(content_extent(port, None, &member), 0, "born empty");
    deposit_text(port, &signed, &member, 1, "Content in version");
    assert_eq!(text_of(port, None, &member, 1, 18), "Content in version");
    assert_eq!(text_of(port, None, &e, 1, 18), "Content in version", "the bare address floats to the head member");
    sd.shutdown();
}

/// interactions/transitive_link_discovery — A transcludes B, B is a version
/// of C, a link is filed on C: content identity is shared down the chain and
/// across the transclusion, so the link is found from C, from B and from A
/// (PUB-2.51: links onto content are version-proof).
#[test]
fn cascade_transitive_link_discovery() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let c_doc = edition_with(port, &signed, "Original content in C");
    let b_doc = acked_addr(&version_of(port, &signed, &c_doc, None));
    let a_doc = draft_with(port, &owner, "A prefix: ");
    expect_resp(&copy_span(port, &owner, &a_doc, 11, &b_doc, 1, 21), "ack");
    assert_eq!(text_of(port, Some(&owner), &a_doc, 1, 31), "A prefix: Original content in C");
    // The link on C's "content" (ordinals 10..16).
    let link = acked_addr(&op(port, Some(&signed), &link_frame(&c_doc, &vspec(&c_doc, 10, 7), r#"{"addrs":[]}"#, &ghost_ty(&c_doc, 1))));

    assert!(find_links_v(port, None, &c_doc, 10, 7).contains(&link), "C finds its link");
    assert!(find_links_v(port, None, &b_doc, 10, 7).contains(&link), "B, a version of C, finds it");
    assert!(find_links_v(port, Some(&owner), &a_doc, 20, 7).contains(&link), "A, transcluding B, finds it transitively");
    sd.shutdown();
}

/// interactions/version_add_link_check_original — a link filed on a
/// VERSION's content is discoverable from the original: the members share
/// identity, and links onto content are version-proof (PUB-2.51, PUB-2.52).
/// The link is homed in the document (its one link subspace, one prefix
/// down the chain, PUB-2.12) and its FROM resolves through the version.
#[test]
fn cascade_version_add_link_check_original() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let e = edition_with(port, &signed, "Shared content here");
    let original = acked_addr(&version_of(port, &signed, &e, None));
    let version = acked_addr(&version_of(port, &signed, &e, None));
    assert_eq!(original, format!("{e}.1"));
    assert_eq!(version, format!("{e}.2"));
    // The link on the VERSION's "content" (ordinals 8..14).
    let link = acked_addr(&op(port, Some(&signed), &link_frame(&e, &vspec(&version, 8, 7), r#"{"addrs":[]}"#, &ghost_ty(&e, 1))));
    assert!(!read_link(port, None, &link).is_null());

    assert!(find_links_v(port, None, &version, 8, 7).contains(&link), "the version finds its own link");
    assert!(find_links_v(port, None, &original, 8, 7).contains(&link), "the original finds the link added to the version (shared identity)");
    assert!(find_links_v(port, None, &e, 8, 7).contains(&link), "…and the bare address, floating to the head");
    sd.shutdown();
}

/// interactions/version_transcluded_linked_content — a source with a link,
/// a document transcluding the linked text, published as an edition (the
/// birth shot), then advanced with a suffix (the next shot): a window keeps
/// its origin's identity across every member (PUB-2.40), so the link is
/// found from the source, from the edition and from its advance.
#[test]
fn cascade_version_transcluded_linked_content() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let source = edition_with(port, &signed, "Source with linked text here");
    // The link on "linked" (ordinals 13..18).
    let link = acked_addr(&op(port, Some(&signed), &link_frame(&source, &vspec(&source, 13, 6), r#"{"addrs":[]}"#, &ghost_ty(&source, 1))));
    let d = draft_with(port, &owner, "Doc prefix: ");
    expect_resp(&copy_span(port, &owner, &d, 13, &source, 13, 11), "ack"); // "linked text"
    assert_eq!(text_of(port, Some(&owner), &d, 1, 23), "Doc prefix: linked text");

    let e = published_edition(port, &signed);
    let doc = shot(port, &signed, &e, None, Some(&d), &shot_runs(port, Some(&owner), &d, 1, 23));
    assert_eq!(doc, format!("{e}.1"));
    assert_eq!(text_of(port, None, &doc, 1, 23), "Doc prefix: linked text");
    let d2 = draft_with(port, &owner, " (version suffix)");
    let mut runs = shot_runs(port, None, &doc, 1, 23);
    runs.push(run(&d2, &format!("{d2}.0.1.1"), 17));
    let version = shot(port, &signed, &e, Some((&doc, 23)), Some(&d2), &runs);
    assert_eq!(version, format!("{e}.2"));
    assert_eq!(text_of(port, None, &version, 1, 40), "Doc prefix: linked text (version suffix)");
    assert_eq!(text_of(port, None, &source, 1, 28), "Source with linked text here", "the source is untouched");

    assert!(find_links_v(port, None, &source, 13, 6).contains(&link), "the source finds its link");
    assert!(find_links_v(port, None, &doc, 13, 6).contains(&link), "the edition finds it through the window (PUB-2.40)");
    assert!(find_links_v(port, None, &version, 13, 6).contains(&link), "…and so does its advance");
    sd.shutdown();
}

/// multisession/ms_version_race — two sessions of one account version one
/// document back to back, each edits its own version, and the cross-compares
/// hold: the members allocate in commit order (PUB-2.6); an edit staged off a
/// PINNED member lands as that member's DAUGHTER (PUB-2.37, PUB-2.39,
/// PUB-2.55); the original and every pinned member are unchanged (PUB-2.50);
/// each daughter shares its base whole (PUB-2.51).
#[test]
fn cascade_ms_version_race() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let a = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let b = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let e = edition_with(port, &a, "Root content here.");

    let a1 = acked_addr(&version_of(port, &a, &e, None));
    let b1 = acked_addr(&version_of(port, &b, &e, None));
    let a2 = acked_addr(&version_of(port, &a, &e, None));
    assert_eq!(a1, format!("{e}.1"), "the members allocate in commit order (PUB-2.6)");
    assert_eq!(b1, format!("{e}.2"));
    assert_eq!(a2, format!("{e}.3"));

    // A edits its version, B edits its own: each staged off a pinned member.
    let da = draft_with(port, &owner, " A1.");
    let mut runs = shot_runs(port, None, &a1, 1, 18);
    runs.push(run(&da, &format!("{da}.0.1.1"), 4));
    let a1_edit = shot(port, &a, &e, Some((&a1, 18)), Some(&da), &runs);
    assert_eq!(a1_edit, format!("{a1}.1"), "staged off a pinned member, the shot lands as its daughter (PUB-2.55)");
    let db = draft_with(port, &owner, " B1.");
    let mut runs = shot_runs(port, None, &b1, 1, 18);
    runs.push(run(&db, &format!("{db}.0.1.1"), 4));
    let b1_edit = shot(port, &b, &e, Some((&b1, 18)), Some(&db), &runs);
    assert_eq!(b1_edit, format!("{b1}.1"));

    assert_eq!(text_of(port, None, &a1_edit, 1, 22), "Root content here. A1.");
    assert_eq!(text_of(port, None, &b1_edit, 1, 22), "Root content here. B1.");
    assert_eq!(text_of(port, None, &e, 1, 18), "Root content here.", "the original, unchanged (the trunk head)");
    assert_eq!(content_extent(port, None, &e), 18);
    assert_eq!(content_extent(port, None, &a1), 18, "a pinned member never grows");
    assert_eq!(compare_positions(port, None, &a1_edit, 22, &a1, 18), shared_prefix(18), "A's edit vs its base");
    assert_eq!(compare_positions(port, None, &b1_edit, 22, &a1_edit, 22), shared_prefix(18), "B's edit vs A's");
    sd.shutdown();
}

/// versions/version_address_allocation — a version is the document's CHILD,
/// versions of one document allocate monotonically under it, a version of a
/// different document under that one, and a version of a version nests
/// again (PUB-2.6, PUB-2.17, PUB-2.55).
#[test]
fn cascade_version_address_allocation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let doc1 = published_edition(port, &signed);
    let doc2 = published_edition(port, &signed);
    let version1 = acked_addr(&version_of(port, &signed, &doc1, None));
    assert_eq!(version1, format!("{doc1}.1"), "a child of the document, never a sibling under the account");
    assert_eq!(acked_addr(&version_of(port, &signed, &doc1, None)), format!("{doc1}.2"), "monotone under the anchor");
    assert_eq!(acked_addr(&version_of(port, &signed, &doc2, None)), format!("{doc2}.1"), "a version of a different document");
    assert_eq!(acked_addr(&version_of(port, &signed, &version1, None)), format!("{version1}.1"), "a version of a version, the same mechanism (PUB-2.55)");
    sd.shutdown();
}

/// versions/version_preserves_transclusion — the published edition of a draft
/// that transcludes a source keeps the transcluded content's identity: its
/// runs from the source stay WINDOWS answering their origin (PUB-2.40), and
/// `compare` against the source finds them.
#[test]
fn cascade_version_preserves_transclusion() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let source = edition_with(port, &signed, "Shared transcluded content");
    let d = draft_with(port, &owner, "Prefix: ");
    expect_resp(&copy_span(port, &owner, &d, 9, &source, 1, 6), "ack"); // "Shared"
    let e = published_edition(port, &signed);
    let version = shot(port, &signed, &e, None, Some(&d), &shot_runs(port, Some(&owner), &d, 1, 14));
    assert_eq!(version, format!("{e}.1"));
    assert_eq!(text_of(port, None, &version, 1, 14), "Prefix: Shared");
    assert_eq!(image_runs(port, None, &version, 9, 6), vec![(format!("{source}.0.1.1"), 6)], "the window keeps its origin's identity");
    let shared: BTreeSet<(u64, u64)> = (0..6).map(|k| (9 + k, 1 + k)).collect();
    assert_eq!(compare_positions(port, None, &version, 14, &source, 26), shared, "the version shares the transcluded content with the source");
    sd.shutdown();
}

/// versions/version_with_links — a document with a link, then versioned:
/// the link is discovered from the version by content identity, and from
/// the source as before (PUB-2.51).
#[test]
fn cascade_version_with_links() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let source = edition_with(port, &signed, "Click here for info");
    let target = edition_with(port, &signed, "Information content");
    // The link from "here" (ordinals 7..10) to the target's content.
    let link = acked_addr(&op(port, Some(&signed), &link_frame(&source, &vspec(&source, 7, 4), &vspec(&target, 1, 19), &ghost_ty(&source, 1))));
    let version = acked_addr(&version_of(port, &signed, &source, None));
    assert_eq!(version, format!("{source}.1"));
    assert!(find_links_v(port, None, &version, 7, 4).contains(&link), "the version discovers the link by content identity");
    assert!(find_links_v(port, None, &source, 7, 4).contains(&link), "…and the source still does");
    sd.shutdown();
}
