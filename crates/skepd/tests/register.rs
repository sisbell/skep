//! §1 OF THE CONFORMANCE PACK — THE REGISTER AS TESTS (PUB round 2, lane 4):
//! the eleven invariants' Test lines and lettered clauses, one named test per
//! cell the daemon can show and no golden or standing suite already pins.
//! TESTS ONLY: a red here is a SPEC-VS-CODE FINDING, left `#[ignore]`d with
//! its assertion INTACT and its cell named — never a fix. Every test names its
//! cell (`I3.c`, `I10.b`) in its name and its doc comment, so coverage is
//! countable.
//!
//! COVERED-BY, recorded rather than duplicated: I1.b (the four in-place edits
//! refuse `published_target`) and I1.c (PUB-2.7 / PUB-2.9, every session
//! class) — `version_chain.rs`, `auth_wire.rs`; I1's build bound (PUB-8.43) —
//! `read_surface.rs`; I2.b's grain (two non-contiguous masked runs, two items)
//! — `read_surface.rs`; I2.c (the H1 matrix) — `read_surface.rs`,
//! `source_gate.rs`, `publication_reads.rs`, `dedup_class.rs`,
//! `feed_class.rs`, `h1_residue.rs`; I2.d's mirror image (a guest dump holds
//! no draft section, content line or slice entry) — `publication_reads.rs`;
//! I3.a's four refusal cells — `auth_wire.rs`, `nullify_class.rs`,
//! `version_chain.rs`; I3.b (the flagless first mint honored, the home born
//! published) — `auth_wire.rs`; I3 (scope: a bare owner's marker and
//! designation admitted into its draft journal) — `nullify_class.rs`; I4.c's
//! `nullify` refusals and `key_set`'s set — `nullify_class.rs`,
//! `auth_wire.rs`; I5.c (own-source `version` appends the chain, cross-owner
//! mints in the caller's account) and I5.e (the proposer's own `nullify`, the
//! owner's `not_owner`) — `version_chain.rs`, `source_gate.rs`,
//! `ownership.rs`; I6.a's carried deposit — `publish.rs`; I7's idempotency
//! memo and the post-restart re-execute (PUB-8.31) — `authz.rs`; I7.e's
//! `mint_home_first` ahead of the first write — `auth_wire.rs`; I10.a's single
//! op and I10.e's two-key genesis — `auth_wire.rs`; I11.d's honest claim —
//! every `spawn`.
//!
//! UNOBSERVABLE at the daemon: I3.d (no rule-registration surface; the fire's
//! guest class is the engine's `fires.rs`); I4.a/b for every class but the
//! grant (the client's admission derivations); I4.e (the label's difference-set
//! walk); I5.a/b/d, I6.b–e, I7.a–d/f, I8 and I9 whole (ceremony copy, faces
//! and client resumes — the daemon carries codes, never faces); I11.a–c (the
//! rail is the attendant's); I3.b's first-mint-with-content form (the wire
//! mints empty).

mod common;

use common::*;
use serde_json::{json, Value};

/// The record text of an enroll atom, back out of its delivery item.
fn atom_text(items: &Value) -> String {
    items.as_array().expect("items")[0]["atom"].as_str().expect("the atom's text").to_string()
}

// ═══════════════════════════════════════════════════════════════════════
// I1 — Publication is at birth and forever (PUB-1.9)
// ═══════════════════════════════════════════════════════════════════════

/// I1.a — `published(D)` at every N equals its birth state (the H1 `/op-at`
/// cells, PUB-6.48): a draft and an edition, read at every position from
/// their births to the head, answer their birth state; a member answers its
/// document's (PUB-2.15); the wire carries no transition op in either
/// direction; and the exception set only GROWS across positions (PUB-8.26).
#[test]
fn i1_a_publication_is_fixed_at_birth_at_every_position_and_the_exception_set_only_grows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);

    // A publish op MUST NOT exist, in either direction (PUB-1.9): the wire
    // has no transition to carry, so such a frame never becomes an op.
    for frame in [
        r#"{"op":"publish_document","doc":"1.0.1.0.1"}"#,
        r#"{"op":"unpublish","doc":"1.0.1.0.1"}"#,
        r#"{"op":"set_published","doc":"1.0.1.0.1","published":true}"#,
    ] {
        let v = op(port, Some(&signed), frame);
        assert_eq!(expect_resp(&v, "rejected")["op"].as_str(), Some("unparseable"), "{v}");
    }

    let at0 = head_position(port);
    let v = op(port, Some(&owner), &create_frame(CLAIMANT_ACCOUNT, None));
    let (draft, at_draft) = (acked_addr(&v), acked_at(&v));
    let v = op(port, Some(&signed), &create_frame(CLAIMANT_ACCOUNT, Some(true)));
    let (edition, at_edition) = (acked_addr(&v), acked_at(&v));
    let at_write = acked_at(&insert_text(port, &owner, &draft, 1, "d"));
    let at_deposit = acked_at(&op(port, Some(&signed), &insert_frame(&edition, 1, "e", true)));
    let v = version_of(port, &signed, &edition, None);
    let (member, at_member) = (acked_addr(&v), acked_at(&v));
    let at_link = acked_at(&op(port, Some(&owner), &link_frame(&draft, r#"{"addrs":[]}"#, r#"{"addrs":[]}"#, &ghost_ty(&draft, 1))));
    let runs = shot_runs(port, None, &member, 1, 1);
    let at_shot = acked_at(&op(port, Some(&signed), &publish_frame(&edition, Some((&member, 1)), None, &runs)));
    let head = head_position(port);
    let positions = [at_draft, at_edition, at_write, at_deposit, at_member, at_link, at_shot, head];

    for &at in &positions {
        if at >= at_draft {
            let v = op_at_ok(port, Some(&owner), at, &doc_metadata_frame(&draft));
            assert_eq!(
                expect_resp(&v, "doc_metadata")["published"].as_bool(),
                Some(false),
                "I1.a: the draft at {at} answers its birth state: {v}"
            );
        }
        if at >= at_edition {
            for token in [None, Some(owner.as_str())] {
                let v = op_at_ok(port, token, at, &doc_metadata_frame(&edition));
                assert_eq!(
                    expect_resp(&v, "doc_metadata")["published"].as_bool(),
                    Some(true),
                    "I1.a: the edition at {at} answers its birth state: {v}"
                );
            }
        }
        if at >= at_member {
            let v = op_at_ok(port, None, at, &doc_metadata_frame(&member));
            let meta = expect_resp(&v, "doc_metadata");
            assert_eq!(meta["doc"].as_str(), Some(edition.as_str()), "a member answers its DOCUMENT (PUB-2.15): {v}");
            assert_eq!(meta["published"].as_bool(), Some(true), "{v}");
        }
    }
    // …and live, after every write above: no op transitioned either.
    let live = doc_metadata(port, Some(&owner), &draft);
    assert_eq!(expect_resp(&live, "doc_metadata")["published"].as_bool(), Some(false));
    let live = doc_metadata(port, None, &edition);
    assert_eq!(expect_resp(&live, "doc_metadata")["published"].as_bool(), Some(true));

    // The exception set only grows (PUB-8.26): the owner's publication
    // slice at each position contains the slice at every earlier one.
    #[cfg(feature = "observe")]
    {
        let mut previous: Vec<String> = publication_slice(&dump_text(port, Some(&owner), Some(at0)));
        for &at in &positions {
            let slice = publication_slice(&dump_text(port, Some(&owner), Some(at)));
            assert!(
                previous.iter().all(|d| slice.contains(d)),
                "I1.a: the exception set shrank between positions: {previous:?} then {slice:?} at {at}"
            );
            previous = slice;
        }
        assert!(previous.contains(&draft), "the owner's slice lists its draft at the head: {previous:?}");
        assert!(!previous.contains(&edition) && !previous.contains(&member), "no published document is in it: {previous:?}");
    }
    let _ = at0;
    sd.shutdown();
}

/// I1.d — a version address names its state forever (PUB-2.50): for a
/// non-head member, `image(v)` at any later position equals `image(v)` at
/// its mint — after the trunk advanced, after a deposit into the head, after
/// a daughter landed off it — and its extent never moves; the bare address
/// floats to the trunk head and only to it (PUB-2.53), a daughter floating
/// nothing; a member projects to its document (PUB-2.15).
#[test]
fn i1_d_a_pinned_member_s_image_at_any_later_position_equals_its_image_at_mint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);

    let e = edition_with(port, &signed, "abc");
    let v = version_of(port, &signed, &e, None);
    let (m1, at_m1) = (acked_addr(&v), acked_at(&v));
    assert_eq!(m1, format!("{e}.1"));
    let mint_image = image_runs(port, None, &m1, 1, 3);
    assert_eq!(expand_runs(&mint_image), i_range(&e, 1, 3));

    // The trunk advances past m1: a shot staged off it re-supplying its runs
    // plus a draft's text.
    let d = draft_with(port, &owner, "d");
    let mut runs = shot_runs(port, None, &m1, 1, 3);
    runs.push(run(&d, &format!("{d}.0.1.1"), 1));
    let v = op(port, Some(&signed), &publish_frame(&e, Some((&m1, 3)), Some(&d), &runs));
    let (m2, at_m2) = (acked_addr(&v), acked_at(&v));
    assert_eq!(m2, format!("{e}.2"));
    // A deposit into the chain — it lands in the head m2 (PUB-2.66).
    let at_z = acked_at(&op(port, Some(&signed), &insert_frame(&e, 5, "z", true)));
    // A daughter off the pinned m1 (PUB-2.55).
    let d2 = draft_with(port, &owner, "q");
    let mut runs2 = shot_runs(port, None, &m1, 1, 3);
    runs2.push(run(&d2, &format!("{d2}.0.1.1"), 1));
    let v = op(port, Some(&signed), &publish_frame(&e, Some((&m1, 3)), Some(&d2), &runs2));
    let (daughter, at_daughter) = (acked_addr(&v), acked_at(&v));
    assert_eq!(daughter, format!("{m1}.1"), "the daughter's address nests under its base (PUB-2.55)");

    for at in [at_m1, at_m2, at_z, at_daughter, head_position(port)] {
        let v = op_at_ok(port, None, at, &image_frame(&m1, 1, 3));
        assert_eq!(runs_in(&v), mint_image, "I1.d: image(m1) at {at} is its image at mint: {v}");
        let v = op_at_ok(port, None, at, &spanset_frame(&m1));
        let width = expect_resp(&v, "span_set")["set"][0]["width"].as_str();
        assert_eq!(width, Some("0.3"), "I1.d: a pinned member's extent never moves: {v}");
    }
    assert_eq!(image_runs(port, None, &m1, 1, 3), mint_image, "…and live");
    assert_eq!(content_extent(port, None, &e), 5, "the bare address floats to the trunk head");
    assert_eq!(content_extent(port, None, &m2), 5);
    assert_eq!(content_extent(port, None, &daughter), 4, "a daughter never floats anything (PUB-2.53)");
    let v = doc_metadata(port, None, &daughter);
    assert_eq!(expect_resp(&v, "doc_metadata")["doc"].as_str(), Some(e.as_str()), "a member projects to its document (PUB-2.15): {v}");
    sd.shutdown();
}

/// I1.e — a credential-class deposit into a published doc 1 whose head is
/// member k and whose member k−1 is pinned: the atom's `insert`, the
/// read-back-and-verify, then the `make_link` naming the verified address
/// (PUB-2.63). NEITHER refusal reads on it (PUB-2.59); it appends to the HEAD
/// member's arrangement alone, and the pinned member never grows (PUB-2.65,
/// PUB-2.66).
#[test]
fn i1_e_a_credential_deposit_appends_to_the_head_alone_and_a_pinned_member_never_grows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    let m1 = acked_addr(&version_of(port, &signed, CLAIMANT_DOC1, None)); // k−1
    let m2 = acked_addr(&version_of(port, &signed, CLAIMANT_DOC1, None)); // k, the head
    assert_eq!(m1, format!("{CLAIMANT_DOC1}.1"));
    assert_eq!(m2, format!("{CLAIMANT_DOC1}.2"));
    let pinned_image = image_runs(port, None, &m1, 1, 1);
    assert_eq!(content_extent(port, None, &m1), 1);

    // The pair: the atom at the head's next free ordinal, read back and
    // verified, then the enroll link naming it.
    let ordinal = next_content_ordinal(port, Some(&signed), CLAIMANT_DOC1);
    let record = enroll_atom(&[&distinct_key(41)]);
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{record}}}],"deposit":true}}"#
        ),
    );
    let atom = acked_addr(&v);
    assert_eq!(json_atom(&atom_text(&delivery(port, None, CLAIMANT_DOC1, ordinal, 1))), record, "read back and verified");
    let v = typed_link(port, &signed, CLAIMANT_DOC1, &[atom.as_str()], &[CLAIMANT_ACCOUNT], T_ENROLL);
    expect_resp(&v, "ack_addr");

    assert_eq!(content_extent(port, None, &m2), 2, "the head member's arrangement grew (PUB-2.66)");
    assert_eq!(content_extent(port, None, CLAIMANT_DOC1), 2, "…and the bare address floats to it");
    assert_eq!(content_extent(port, None, &m1), 1, "a pinned member's arrangement never grows (PUB-2.65)");
    assert_eq!(image_runs(port, None, &m1, 1, 1), pinned_image, "image on member k−1 unchanged");
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#));
    assert_eq!(v["enrolled"].as_array().map(Vec::len), Some(3), "the deposit was honored: {v}");
    sd.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════
// I2 — The boundary law (PUB-1.49)
// ═══════════════════════════════════════════════════════════════════════

/// I2.a — references cross the boundary freely: a public link whose endset
/// names a draft's I-space is read whole by a guest; the draft's EXISTENCE is
/// visible (a `withheld` that a never-minted neighbour does not get) and its
/// OWNER derives by tumbler arithmetic (PUB-1.14, PUB-8.9); an address-form
/// slot naming an I-position inside the draft is ungated for a stranger
/// (PUB-6.24).
#[test]
fn i2_a_a_reference_into_a_draft_is_public_and_the_draft_s_existence_and_owner_are_visible() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let d = draft_with(port, &owner, "ab");
    let inside = format!("{d}.0.1.1");

    let plink = acked_addr(&op(
        port,
        Some(&signed),
        &link_frame(CLAIMANT_DOC1, r#"{"addrs":[]}"#, &vspec(&d, 1, 2), &ghost_ty(CLAIMANT_DOC1, 71)),
    ));
    // The reference, to a guest: whole, and its endset names D's I-space.
    assert!(!read_link(port, None, &plink).is_null(), "the public link is read whole");
    let v = op(port, None, &format!(r#"{{"op":"follow_link","a":"{plink}","slot":2}}"#));
    assert_eq!(expect_resp(&v, "follow")["result"]["ok"][0]["start"].as_str(), Some(inside.as_str()), "{v}");
    // The target bytes never come back; existence is the one observable.
    assert_withheld(&op(port, None, &read1_frame(&d)), &d);
    assert_withheld(&doc_metadata(port, None, &d), &d);
    let never = format!("{CLAIMANT_ACCOUNT}.0.99");
    let v = doc_metadata(port, None, &never);
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("doc_not_registered"), "an unminted neighbour is not withheld: {v}");
    // The owner by arithmetic: the account prefix, whose principal the
    // registry read names.
    assert!(d.starts_with(&format!("{CLAIMANT_ACCOUNT}.0.")), "{d}");
    let v = op(port, None, &format!(r#"{{"op":"principal_prefix","principal":{CLAIMANT_PRINCIPAL}}}"#));
    assert_eq!(expect_resp(&v, "maybe_addr")["addr"].as_str(), Some(CLAIMANT_ACCOUNT));
    // Address-form slots stay ungated: a stranger names the I-position.
    let s = seat_stranger(port, 901);
    let s_draft = create_doc(port, &s.session, &s.account);
    let l = acked_addr(&op(port, Some(&s.session), &link_frame(&s_draft, r#"{"addrs":[]}"#, &addrs_slot(&[&inside]), &ghost_ty(&s_draft, 1))));
    assert_eq!(read_link(port, Some(&s.session), &l)["slots"][1][0]["start"].as_str(), Some(inside.as_str()));
    sd.shutdown();
}

/// I2.b — delivery per origin, per run, and the lapse: a grantee reads the
/// draft-origin runs of a published member through its grant; once the
/// issuer's superseding record lands, delivery is withdrawn AT ONCE, wherever
/// the runs sit (PUB-1.66, PUB-7.23) — each masked run its own withheld item
/// (PUB-1.57).
#[test]
fn i2_b_revoking_the_origin_s_grant_withdraws_delivery_at_once_wherever_the_runs_sit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let d = draft_with(port, &owner, "abcde");
    let b = seat_stranger(port, 911);
    let member = shot(
        port,
        &signed,
        CLAIMANT_DOC1,
        None,
        None,
        &[run(&d, &format!("{d}.0.1.1"), 2), run(&d, &format!("{d}.0.1.4"), 2)],
    );
    let masked = json!([withheld_item(&d, 2), withheld_item(&d, 2)]);
    assert_eq!(delivery(port, Some(&b.session), &member, 1, 4), masked, "before the grant");

    let grant = deposit_grant(port, &signed, CLAIMANT_DOC1, &d, Some(&b.account));
    assert_eq!(text_of(port, Some(&b.session), &member, 1, 4), "abde", "granted: the runs deliver");
    assert_eq!(text_of(port, Some(&b.session), &d, 1, 5), "abcde");

    // Revocation by supersession from the same home (PUB-5.13).
    expect_resp(&typed_link(port, &signed, CLAIMANT_DOC1, &[grant.as_str()], &[b.account.as_str()], T_GRANT), "ack_addr");
    assert_eq!(delivery(port, Some(&b.session), &member, 1, 4), masked, "I2.b: delivery withdrawn at once");
    assert_withheld(&op(port, Some(&b.session), &read1_frame(&d)), &d);
    assert_eq!(delivery(port, None, &member, 1, 4), masked, "the guest, all along");
    sd.shutdown();
}

/// I2.d — a born-published fork of D carries D's I-addresses publicly and
/// never its bytes (PUB-1.16, PUB-1.58): the grantee's `version(D,
/// published: true)` mints in ITS account, and a non-entitled reader — and
/// the guest — get withheld items at the fork's positions, its `image` and
/// `show_origin` naming D's I-space whole, while the grantee reads the bytes.
#[test]
fn i2_d_a_born_published_fork_carries_the_draft_s_addresses_publicly_and_never_its_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let d = draft_with(port, &owner, "abcde");
    let b = seat_stranger(port, 921);
    let b_signed = hire(port, &signed, CLAIMANT_DOC1, &b.account, 921, &distinct_key(21));
    deposit_grant(port, &signed, CLAIMANT_DOC1, &d, Some(&b.account));

    let fork = acked_addr(&version_of(port, &b_signed, &d, Some(true)));
    assert!(fork.starts_with(&format!("{}.0.", b.account)), "the fork is the grantee's own document: {fork}");
    let c = seat_stranger(port, 922);
    for token in [None, Some(c.session.as_str())] {
        let v = doc_metadata(port, token, &fork);
        assert_eq!(expect_resp(&v, "doc_metadata")["published"].as_bool(), Some(true), "born published: {v}");
        assert_eq!(delivery(port, token, &fork, 1, 5), json!([withheld_item(&d, 5)]), "I2.d: D's bytes never come back");
        assert_eq!(image_runs(port, token, &fork, 1, 5), vec![(format!("{d}.0.1.1"), 5)], "…but its I-ranges do");
        assert_eq!(origins_of(port, token, &fork, 1, 5), vec![d.clone()], "…and its owner's document");
        assert_withheld(&op(port, token, &read1_frame(&d)), &d);
    }
    assert_eq!(text_of(port, Some(&b_signed), &fork, 1, 5), "abcde", "the entitled reader reads through the fork");
    sd.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════
// I3 — Irreversibility earns a possession check (PUB-6.33)
// ═══════════════════════════════════════════════════════════════════════

/// The guest-readable projection behind `/dump`: the dump less its identity
/// section (a draft's registration is visible, PUB-1.14), beside the reads a
/// guest takes of the published home — each less its `as_of` stamp, which
/// names the head and moves with every commit.
fn guest_projection(port: u16, public_link: &str) -> (Option<String>, Vec<Value>) {
    #[cfg(feature = "observe")]
    let dump = Some(without_namespace_section(&dump_text(port, None, None)));
    #[cfg(not(feature = "observe"))]
    let dump = None;
    let reads = [
        retrieve_frame(CLAIMANT_DOC1, 1, 1),
        spanset_frame(CLAIMANT_DOC1),
        find_links_frame(CLAIMANT_DOC1, 1, 1),
        read_link_frame(public_link),
        doc_metadata_frame(CLAIMANT_DOC1),
    ]
    .iter()
    .map(|f| {
        let mut v = op(port, None, f);
        v.as_object_mut().expect("an answer is an object").remove("as_of");
        v
    })
    .collect();
    (dump, reads)
}

/// I3.a — the Test line's stream property, deterministic: for a stream of
/// BARE ops on a claimed board — draft mints and draft-homed writes admitted,
/// every published-landing act refused `signed_session_required` — the guest
/// projection is unchanged; and the one exemption, a content-empty doc-1
/// birth (I3.b, PUB-6.43), is what a bare delegate-then-mint leaves.
#[test]
fn i3_a_a_bare_op_stream_leaves_the_guest_projection_unchanged_but_for_content_empty_home_births() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let pub_l = ghost_link(port, &signed, CLAIMANT_DOC1, 31);
    let s = seat_stranger(port, 931);
    let before = guest_projection(port, &pub_l);

    // Admitted bare: drafts and draft-homed writes.
    let j = owner_draft(port, &owner);
    expect_resp(&insert_text(port, &owner, &j, 1, "jj"), "ack_addr");
    expect_resp(&copy_span(port, &owner, &j, 3, CLAIMANT_DOC1, 1, 1), "ack");
    let jl = ghost_link(port, &owner, &j, 1);
    expect_resp(&op(port, Some(&owner), &nullify_frame(&j, &jl)), "ack_addr");
    let s_draft = create_doc(port, &s.session, &s.account);
    expect_resp(&insert_text(port, &s.session, &s_draft, 1, "ss"), "ack_addr");
    // Refused bare: every act that lands in the published world.
    let before_refusals = head_position(port);
    let ordinal = next_content_ordinal(port, None, CLAIMANT_DOC1);
    for (what, frame) in [
        ("a write homed in the published doc 1", insert_frame(CLAIMANT_DOC1, ordinal, "x", true)),
        ("a flagless version of a published source", version_frame(CLAIMANT_DOC1, None)),
        ("a mint resolving published", create_frame(CLAIMANT_ACCOUNT, Some(true))),
        ("a published fork", fork_frame(Some(true))),
        ("the shot", publish_frame(CLAIMANT_DOC1, None, None, &[])),
        ("a draft-homed retraction of a public link", nullify_frame(&j, &pub_l)),
        ("a rail record", typed_link_frame(CLAIMANT_DOC1, &[s.account.as_str()], &[CLAIMANT_DOC1], T_RAIL_CLASS)),
        ("a grant", typed_link_frame(CLAIMANT_DOC1, &[j.as_str()], &[s.account.as_str()], T_GRANT)),
        ("an emit into the published home", emit_frame(CLAIMANT_DOC1)),
    ] {
        assert_eq!(verdict(&op(port, Some(&owner), &frame)), GATED, "I3.a: {what}");
    }
    assert_eq!(head_position(port), before_refusals, "the refusals commit nothing");

    let after = guest_projection(port, &pub_l);
    assert_eq!(after.1, before.1, "I3.a: the guest's reads of the published world are unchanged");
    assert_eq!(after.0, before.0, "I3.a: the guest's dump (its identity section aside) is unchanged");

    // The exemption: a bare delegate-then-first-mint chain leaves a
    // content-empty published home and nothing else.
    let (acct, sess) = bootstrap_delegate(port, 932);
    let home = create_doc(port, &sess, &acct);
    let v = doc_metadata(port, None, &home);
    assert_eq!(expect_resp(&v, "doc_metadata")["published"].as_bool(), Some(true), "born published: {v}");
    assert_eq!(content_extent(port, None, &home), 0, "…and content-empty");
    sd.shutdown();
}

/// I3.a, the lineage half: a draft-homed supersession claim over two PUBLIC
/// links is a draft write a bare session may make, and it stays OUT of the
/// guest projection — `in_claims` drops it (PUB-6.22, the claim's home
/// filters), and the guest's dump is unchanged by it (PUB-6.60, PUB-8.26).
#[test]
fn i3_a_a_draft_homed_supersession_claim_over_public_links_stays_out_of_the_guest_projection() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let l1 = ghost_link(port, &signed, CLAIMANT_DOC1, 41);
    let l2 = ghost_link(port, &signed, CLAIMANT_DOC1, 42);
    let j = owner_draft(port, &owner);
    let before = guest_projection(port, &l1);

    let claim = acked_addr(&op(port, Some(&owner), &assert_sup_frame(&j, &l1, &l2)));
    assert!(claim.starts_with(&format!("{j}.0.2.")), "a draft write: {claim}");
    assert_eq!(claims_in(port, None, &l1, "active"), Vec::<String>::new(), "the read surface drops the claim (PUB-6.22)");
    assert_eq!(claims_in(port, Some(&owner), &l1, "active"), vec![claim.clone()], "…and the owner reads it");

    let after = guest_projection(port, &l1);
    assert_eq!(after.1, before.1);
    assert_eq!(after.0, before.0, "I3.a: a draft-homed claim leaves no trace in the guest's dump");
    sd.shutdown();
}

/// I3.c — the gate keys on the EFFECT's home: a retraction lands at its
/// target, so a record homed in draft D against public link L in published T
/// takes `published(document_of(target))` from a bare session (PUB-6.43's
/// `nullify` row, PUB-6.34), and the signed session lands it.
#[test]
fn i3_c_a_draft_homed_nullify_of_a_public_link_takes_the_gate_on_the_target_s_home() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let j = owner_draft(port, &owner);
    let l = ghost_link(port, &signed, CLAIMANT_DOC1, 41);
    let scan = class_scan("find_links_ftt", &format!("{CLAIMANT_DOC1}.0.3.6.41"));
    assert_eq!(addrs_of(&op(port, None, &scan)), vec![l.clone()], "the public link is active");

    let before = head_position(port);
    assert_eq!(verdict(&op(port, Some(&owner), &nullify_frame(&j, &l))), GATED, "I3.c: bare, the target's home decides");
    assert_eq!(head_position(port), before, "nothing committed");
    let retraction = acked_addr(&op(port, Some(&signed), &nullify_frame(&j, &l)));
    assert!(retraction.starts_with(&format!("{j}.0.2.")), "the record is filed in the draft: {retraction}");
    assert_eq!(addrs_of(&op(port, None, &scan)), Vec::<String>::new(), "…and the retraction landed at its target");
    sd.shutdown();
}

/// I3.c — `edit_link` names two documents and takes NO target-home OR: each
/// of its two deposits takes `published(home)` on ITS OWN home (PUB-6.43).
/// The successor's home: a bare owner's `edit_link` with `d_s` the published
/// doc 1 and `d_a` a draft is refused; signed, it lands both deposits.
#[test]
fn i3_c_edit_link_takes_the_gate_on_the_successor_s_own_home() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let j = owner_draft(port, &owner);
    let l = ghost_link(port, &signed, CLAIMANT_DOC1, 51);

    let frame = edit_link_frame(&l, CLAIMANT_DOC1, &j, "[]", &ghost_ty(CLAIMANT_DOC1, 52));
    let before = head_position(port);
    assert_eq!(verdict(&op(port, Some(&owner), &frame)), GATED, "I3.c: the successor lands in the published doc 1");
    assert_eq!(head_position(port), before);
    let v = op(port, Some(&signed), &frame);
    let ack = expect_resp(&v, "ack_edit");
    assert!(ack["successor"].as_str().expect("successor").starts_with(&format!("{CLAIMANT_DOC1}.0.2.")), "{v}");
    assert!(ack["claim"].as_str().expect("claim").starts_with(&format!("{j}.0.2.")), "{v}");
    sd.shutdown();
}

/// I3.c — the CLAIM's own home: a bare owner's `edit_link` with `d_s` a draft
/// and `d_a` the published doc 1 deposits its supersession claim into the
/// published world, so it takes `published(d_a)` and is refused
/// `signed_session_required` (PUB-6.43: "each of its two deposits — the
/// successor link and the supersession claim — takes the `published(home)`
/// row on ITS OWN home"; PUB-6.34: nothing public may be written bare).
#[test]
fn i3_c_edit_link_takes_the_gate_on_the_claim_s_own_home() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let j = owner_draft(port, &owner);
    let l = ghost_link(port, &signed, CLAIMANT_DOC1, 61);

    let frame = edit_link_frame(&l, &j, CLAIMANT_DOC1, "[]", &ghost_ty(&j, 62));
    let before = head_position(port);
    let v = op(port, Some(&owner), &frame);
    assert_eq!(verdict(&v), GATED, "I3.c: the claim lands in the published doc 1, so the bare edit takes the gate: {v}");
    assert_eq!(head_position(port), before, "a refused edit commits nothing");
    let v = op(port, Some(&signed), &frame);
    expect_resp(&v, "ack_edit");
    sd.shutdown();
}

/// I3.e — the domain is stated over every op, the ungated ones named and
/// conceded (PUB-6.34): a bare `delegate` from principal 0 mints an account;
/// a bare `register_node` admits a node; the new account's bare first mint is
/// the content-empty home; and a bare `delegate` beneath one's own account is
/// the never-keyed residue (PUB-1.42) — each admitted, none published-landing.
#[test]
fn i3_e_delegate_and_register_node_stand_outside_the_gate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (acct, sess) = bootstrap_delegate(port, 941);
    assert!(acct.starts_with("1.0."), "a top-level account: {acct}");
    expect_resp(&op(port, Some(&sess), r#"{"op":"register_node","addr":"1.9"}"#), "ack_addr");
    let home = create_doc(port, &sess, &acct);
    assert_eq!(home, format!("{acct}.0.1"));
    let (nested, _) = delegate_under(port, &owner, CLAIMANT_ACCOUNT, 942);
    assert!(nested.starts_with(&format!("{CLAIMANT_ACCOUNT}.")), "beneath the owner's account: {nested}");
    sd.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════
// I4 — One authority (PUB-5.19)
// ═══════════════════════════════════════════════════════════════════════

/// I4.a / I4.b, at the grant class — the one authority class the daemon's
/// fold reads: a grant is admitted ONLY from the issuer's own PUBLISHED doc 1
/// (residence + ω, PUB-5.17). The owner's grant in a second published
/// document of theirs, a stranger's grant-typed record naming the owner's
/// draft, a delegate's record under the owner's prefix, and the owner's
/// grant homed in a DRAFT each open nothing — containment never suffices, a
/// draft-homed authority record authorizes nothing — and the doc-1 grant does.
#[test]
fn i4_a_b_a_grant_admits_only_from_the_issuer_s_own_published_doc_1() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let d = draft_with(port, &owner, "s");
    let b = seat_stranger(port, 951); // the would-be grantee
    let s = seat_stranger(port, 952);
    let s_signed = hire(port, &signed, CLAIMANT_DOC1, &s.account, 952, &distinct_key(52));
    let c = seat_sub_account(port, &owner, 953);
    let c_signed = hire(port, &signed, CLAIMANT_DOC1, &c.account, 953, &distinct_key(53));
    let edition = published_edition(port, &signed);
    let journal = owner_draft(port, &owner);

    let cells: [(&str, &str, &str); 4] = [
        ("I4.a: the owner's grant homed in a second published document of theirs", signed.as_str(), edition.as_str()),
        ("I4.a: a stranger's grant-typed record naming the owner's draft", s_signed.as_str(), s.doc1.as_str()),
        ("I4.a: a delegate's record under the owner's prefix", c_signed.as_str(), c.doc1.as_str()),
        ("I4.b: the owner's grant homed in a DRAFT", owner.as_str(), journal.as_str()),
    ];
    for (what, session, home) in cells {
        let v = typed_link(port, session, home, &[d.as_str()], &[b.account.as_str()], T_GRANT);
        assert_eq!(v["resp"].as_str(), Some("ack_addr"), "{what}: the record is mintable: {v}");
        assert_withheld(&op(port, Some(&b.session), &read1_frame(&d)), &d);
        let msg = format!("{what}: inert to the fold");
        assert_eq!(verdict(&op(port, Some(&b.session), &read1_frame(&d))), "withheld", "{msg}");
    }
    // Residence and ω together: the grant in the issuer's own doc 1 admits.
    deposit_grant(port, &signed, CLAIMANT_DOC1, &d, Some(&b.account));
    assert_eq!(text_of(port, Some(&b.session), &d, 1, 1), "s", "the doc-1 grant is honored");
    sd.shutdown();
}

/// I4.c / I4.d — supersession from the same home is the only revocation and
/// retraction never a second path: a deposited supersession claim over the
/// grant (`assert_sup`, `edit_link`) is lineage display and no fold input
/// (PUB-5.13); the grant class is ADDITIVE — a document-rung grant beside an
/// account-rung one each stand on their own (PUB-7.3, PUB-5.8); a revoked
/// grant's record is permanent and the class scan is a superset, never a
/// face (PUB-5.21); the `nullify` of a grant is refused (`nullify_class.rs`).
#[test]
fn i4_c_d_supersession_from_the_same_home_is_the_only_revocation_and_grants_are_additive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let d = draft_with(port, &owner, "s");
    let b = seat_stranger(port, 961);
    let reads = |what: &str| {
        assert_eq!(text_of(port, Some(&b.session), &d, 1, 1), "s", "{what}: B reads the draft");
    };
    let withheld = |what: &str| {
        let v = op(port, Some(&b.session), &read1_frame(&d));
        assert_eq!(verdict(&v), "withheld", "{what}: B is withheld");
    };

    let g_doc = deposit_grant(port, &signed, CLAIMANT_DOC1, &d, Some(&b.account));
    reads("the document-rung grant");
    // Deposited claims over the grant record: display, never a fold input.
    let other = ghost_link(port, &signed, CLAIMANT_DOC1, 71);
    expect_resp(&op(port, Some(&signed), &assert_sup_frame(CLAIMANT_DOC1, &g_doc, &other)), "ack_addr");
    reads("I4.c: after an assert_sup claim naming the grant");
    expect_resp(&op(port, Some(&signed), &edit_link_frame(&g_doc, CLAIMANT_DOC1, CLAIMANT_DOC1, "[]", &ghost_ty(CLAIMANT_DOC1, 72))), "ack_edit");
    reads("I4.c: after an edit_link claim naming the grant");
    // ADDITIVE: the account-rung grant beside it; revoking the document-rung
    // one leaves the account-rung standing.
    let g_acct = deposit_grant(port, &signed, CLAIMANT_DOC1, CLAIMANT_ACCOUNT, Some(&b.account));
    reads("the account-rung grant beside it");
    expect_resp(&typed_link(port, &signed, CLAIMANT_DOC1, &[g_doc.as_str()], &[b.account.as_str()], T_GRANT), "ack_addr");
    reads("I4.c: the document-rung grant revoked, the account-rung one stands on its own");
    let revocation = acked_addr(&typed_link(port, &signed, CLAIMANT_DOC1, &[g_acct.as_str()], &[b.account.as_str()], T_GRANT));
    withheld("I4.c: both revoked by the class's own superseding records");
    // The scan is a superset and never a face (PUB-5.21): every record,
    // revoked grants and revocations alike, is permanent and listed.
    let listed = addrs_of(&op(port, None, &class_scan("find_links_ftt", T_GRANT)));
    for record in [&g_doc, &g_acct, &revocation] {
        assert!(listed.contains(record), "I4.d: the class scan lists the permanent record {record}: {listed:?}");
    }
    // …and a later grant admits again: the fold reads the admitted state.
    deposit_grant(port, &signed, CLAIMANT_DOC1, &d, Some(&b.account));
    reads("a fresh grant after the revocations");
    sd.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════
// I6 — Nothing is accepted or published sight-unseen (PUB-3.43)
// ═══════════════════════════════════════════════════════════════════════

/// I6.a — the shot composes from the rendered runs the client supplies and
/// reads no draft's arrangement at commit (PUB-8.1, PUB-2.33): the staging
/// draft moved between the render and the shot, and the member reflects the
/// render.
#[test]
fn i6_a_the_shot_composes_from_the_rendered_runs_never_the_draft_s_arrangement_at_commit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let e = edition_with(port, &signed, "abc");
    // The staging draft: the head by reference, then "xy" — rendered.
    let d = owner_draft(port, &owner);
    expect_resp(&copy_span(port, &owner, &d, 1, &e, 1, 3), "ack");
    expect_resp(&insert_text(port, &owner, &d, 4, "xy"), "ack_addr");
    let render = shot_runs(port, Some(&owner), &d, 1, 5);
    assert_eq!(text_of(port, Some(&owner), &d, 1, 5), "abcxy");
    // The draft moves after the sight.
    expect_resp(&op(port, Some(&owner), &delete_frame(&d, 1, 1)), "ack");
    expect_resp(&insert_text(port, &owner, &d, 1, "Q"), "ack_addr");
    assert_eq!(text_of(port, Some(&owner), &d, 1, 5), "Qbcxy", "the draft as it stands at commit");

    let member = shot(port, &signed, &e, Some((&e, 3)), Some(&d), &render);
    assert_eq!(member, format!("{e}.1"));
    assert_eq!(text_of(port, None, &member, 1, 5), "abcxy", "I6.a: the member is the render, not the draft at commit");
    assert_eq!(text_of(port, Some(&owner), &d, 1, 5), "Qbcxy", "the draft is what it was");
    sd.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════
// I10 — The claim admits no stranger (PUB-6.35)
// ═══════════════════════════════════════════════════════════════════════

/// I10.a — until a board is claimed it admits nothing but the ceremony: the
/// pre-claim op catalogue, from a seated account's bare session, is refused
/// `claim_first`; the guest is `unauthenticated` ahead of it; MINT-FIRST
/// (slot 2) stands ahead of the admission gate; reads stand; and the
/// ceremony's own shapes stay admitted.
#[test]
fn i10_a_the_pre_claim_catalogue_is_refused_claim_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    let (_, empty) = bootstrap_delegate(port, 501);
    assert_eq!(verdict(&op(port, Some(&empty), &fork_frame(None))), "credential_refused:mint_home_first", "slot 2 ahead of slot 4");
    let a = seat_stranger(port, 502);
    let probe = format!("{}.0.2.9", a.doc1);
    let under_a = next_prefix_under(port, Some(&a.session), &a.account);
    let cases: Vec<(&str, String)> = vec![
        ("fork", fork_frame(None)),
        ("version", version_frame(&a.doc1, None)),
        ("create_new_document into a non-empty account", create_frame(&a.account, None)),
        ("delete", delete_frame(&a.doc1, 1, 1)),
        ("rearrange", rearrange_frame(&a.doc1, [1, 2, 3])),
        ("copy", copy_frame(&a.doc1, 1, &a.doc1, 1, 1)),
        ("publish", publish_frame(&a.doc1, None, None, &[])),
        ("make_link", link_frame(&a.doc1, r#"{"addrs":[]}"#, r#"{"addrs":[]}"#, &ghost_ty(&a.doc1, 1))),
        ("emit", emit_frame(&a.doc1)),
        ("nullify", nullify_frame(&a.doc1, &probe)),
        ("assert_sup", assert_sup_frame(&a.doc1, &probe, &probe)),
        ("edit_link", edit_link_frame(&probe, &a.doc1, &a.doc1, "[]", &ghost_ty(&a.doc1, 2))),
        ("delegate by a principal other than 0", format!(r#"{{"op":"delegate","new_prefix":"{under_a}","new_id":503}}"#)),
        ("register_node", r#"{"op":"register_node","addr":"1.9"}"#.to_string()),
    ];
    for (what, frame) in &cases {
        let v = op(port, Some(&a.session), frame);
        assert_eq!(verdict(&v), "credential_refused:claim_first", "I10.a: {what}: {v}");
        assert_eq!(v["disposition"].as_str(), Some("permanent"), "{what}");
    }
    assert_eq!(verdict(&op(port, None, &fork_frame(None))), "unauthenticated", "the guest, ahead of the gate");
    expect_resp(&op(port, Some(&a.session), &spanset_frame(&a.doc1)), "span_set");
    expect_resp(&op(port, None, r#"{"op":"next_account_prefix","parent":"1"}"#), "maybe_addr");
    // The ceremony's own shapes: another empty account's home mint and the
    // record atom's insert into the caller's own doc 1.
    let (acct2, sess2) = bootstrap_delegate(port, 504);
    let home2 = create_doc(port, &sess2, &acct2);
    let v = op(
        port,
        Some(&sess2),
        &format!(
            r#"{{"op":"insert","doc":"{home2}","at":{{"subspace":"1","ordinal":"1"}},"values":[{{"atom":{}}}],"deposit":true}}"#,
            enroll_atom(&[&distinct_key(4)])
        ),
    );
    expect_resp(&v, "ack_addr");
    assert!(!claimed(port));
    sd.shutdown();
}

/// I10.b — the claim REFUSES over residue (PUB-6.63): where a second hand's
/// partial (steps 1–4) stands above the genesis floor, the operator's own
/// claim is refused, naming the one cure — re-genesis — and the board stays
/// claimable by nobody.
#[test]
fn i10_b_the_claim_refuses_over_a_second_hand_s_residue() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_configured(dir.path(), true);
    let port = sd.port();
    let stranger = seed_partial(port, 601, &[(&distinct_key(61), false)]);
    assert_eq!(stranger.account, "1.0.1", "a second hand's partial holds the first top-level slot");
    let operator = seed_partial(port, 602, &[(&anchor_key(), true), (&device_key(), false)]);
    assert_eq!(operator.account, "1.0.2");
    let signed = open_signed_session(port, 602, &device_key());

    let v = op(port, Some(&signed), &claim_frame(&operator.doc1, &operator.account));
    assert_eq!(v["resp"].as_str(), Some("rejected"), "I10.b: the claim refuses over pre-claim residue — two top-level principals above the genesis floor: {v}");
    assert!(!claimed(port), "…and the board stays unclaimed, its one cure re-genesis");
    sd.shutdown();
}

/// I10.c — the latch: a partial's genesis latches its key set, a further
/// enrollment into it pre-claim answers `claim_first` (bare and signed
/// alike, AUTH-3.82/3.83), and a BARE claim over the keyed partial claims an
/// empty world under the MINTER's keys — the race, no new outcome
/// (PUB-6.63): the minter's key opens the signed arm, an unenrolled key does
/// not.
#[test]
fn i10_c_a_partial_s_key_set_is_latched_and_a_bare_claim_over_it_is_the_race() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_configured(dir.path(), true);
    let port = sd.port();
    let minter = distinct_key(11);
    let a = seed_partial(port, 611, &[(&minter, false)]);
    let a_signed = open_signed_session(port, 611, &minter);

    // A further enrollment into the partial: the atom lands (the ceremony's
    // insert shape) and its deposit answers `claim_first`, whoever presents.
    let v = op(
        port,
        Some(&a.session),
        &format!(
            r#"{{"op":"insert","doc":"{}","at":{{"subspace":"1","ordinal":"2"}},"values":[{{"atom":{}}}],"deposit":true}}"#,
            a.doc1,
            enroll_atom(&[&distinct_key(12)])
        ),
    );
    let atom = acked_addr(&v);
    for token in [&a.session, &a_signed] {
        let v = typed_link(port, token, &a.doc1, &[atom.as_str()], &[a.account.as_str()], T_ENROLL);
        assert_eq!(verdict(&v), "credential_refused:claim_first", "I10.c: the latch: {v}");
    }
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{}"}}"#, a.account));
    assert_eq!(v["enrolled"].as_array().map(Vec::len), Some(1), "one key, the genesis's: {v}");

    // The race: a bare claim over the keyed partial lands, the world claimed
    // under the minter's keys.
    expect_resp(&op(port, Some(&a.session), &claim_frame(&a.doc1, &a.account)), "ack_addr");
    assert!(claimed(port));
    assert_eq!(json(&get(port, "/health").1)["auth"]["claimant"].as_str(), Some(a.account.as_str()));
    let _minter_session = open_signed_session(port, 611, &minter);
    let (st, body) = http(port, "GET", "/challenge?principal=611", None, b"");
    assert_eq!(st, 200);
    let nonce = json(&body)["nonce"].as_str().expect("nonce").to_string();
    let origin = format!("http://127.0.0.1:{port}");
    let sig = sign_session(&distinct_key(12), &origin, &nonce, 611);
    let body = format!("{{\"principal\":611,\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"sig\":\"{sig}\"}}");
    let (st, _) = http(port, "POST", "/session", None, body.as_bytes());
    assert_eq!(st, 401, "no second hand's key ever joined the partial");
    sd.shutdown();
}

/// I10.d — the refused-claim shape is readable off the frontier: a stranger
/// at an exposed port runs the ceremony's admitted `delegate` and stops, and
/// `next_account_prefix` — principal-free, exempt (PUB-6.50, PUB-6.52) —
/// discloses the residue to any hand.
#[test]
fn i10_d_the_frontier_read_discloses_pre_claim_residue() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    assert_eq!(next_prefix_under(port, None, "1"), "1.0.1", "an empty top-level space");
    let (residue, _) = bootstrap_delegate(port, 701);
    assert_eq!(residue, "1.0.1");
    assert_eq!(next_prefix_under(port, None, "1"), "1.0.2", "I10.d: the frontier moved by the stranger's delegate");
    assert!(!claimed(port));
    sd.shutdown();
}

/// I10.e — the honest ceremony always completes: a THREE-key notebook
/// genesis is admitted, its signed claim lands with the count above the floor
/// standing at one, and every key of the set signs.
#[test]
fn i10_e_a_three_key_genesis_is_admitted_and_the_honest_claim_lands_at_count_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_configured(dir.path(), true);
    let port = sd.port();
    let (k1, k2) = (distinct_key(21), distinct_key(22));
    let a = seed_partial(port, 621, &[(&anchor_key(), true), (&k1, false), (&k2, false)]);
    let signed = open_signed_session(port, 621, &k2);
    expect_resp(&op(port, Some(&signed), &claim_frame(&a.doc1, &a.account)), "ack_addr");
    assert!(claimed(port));
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{}"}}"#, a.account));
    assert_eq!(v["enrolled"].as_array().map(Vec::len), Some(3), "{v}");
    assert_eq!(next_prefix_under(port, None, "1"), "1.0.2", "one principal above the floor");
    let _ = open_signed_session(port, 621, &k1);
    let _ = open_signed_session(port, 621, &anchor_key());
    sd.shutdown();
}

// ═══════════════════════════════════════════════════════════════════════
// I11 — No guard strands a ruled flow (PUB-5.75)
// ═══════════════════════════════════════════════════════════════════════

/// I11.d — the one named exception: the operator's LOST-STATE retry that
/// re-runs `delegate` is refused at the claim (PUB-6.35, PUB-6.63), its
/// residue being its own abandoned partial, at the accepted cost of
/// re-genesis.
#[test]
fn i11_d_the_operator_s_lost_state_retry_is_refused_at_the_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_configured(dir.path(), true);
    let port = sd.port();
    let abandoned = seed_partial(port, 801, &[(&distinct_key(81), false)]);
    assert_eq!(abandoned.account, "1.0.1");
    let retry = seed_partial(port, 802, &[(&anchor_key(), true), (&device_key(), false)]);
    let signed = open_signed_session(port, 802, &device_key());
    let v = op(port, Some(&signed), &claim_frame(&retry.doc1, &retry.account));
    assert_eq!(v["resp"].as_str(), Some("rejected"), "I11.d: the lost-state retry is refused at the claim: {v}");
    assert!(!claimed(port));
    sd.shutdown();
}
