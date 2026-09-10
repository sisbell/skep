//! H1 — THE WRITE SIDE'S CONSULT over the wire (PUB round 2, lane 3.3c):
//! the source gate on the writes that READ a document before they write —
//! `copy`'s specs, `version`'s `d_src`, the RESOLVE-form slots of `make_link`
//! and `edit_link` (PUB-6.23, PUB-6.24) — and the link-address rule on the
//! links a write validates by address (`edit_link.original`,
//! `assert_sup.old`/`new`, PUB-6.6), both at M10's door, pre-dispatch
//! (PUB-6.38), behind the destination's ownership (PUB-6.36 slot 1) and ahead
//! of any read of the source. Beside them: the origin-side readers a public
//! link into a draft answers WHOLE through (PUB-6.14, PUB-6.15, PUB-6.22),
//! and the hire ceremony the suites grant through (AUTH-5.58).
//!
//! The writer classes are lane 3.3's reader classes, as writers: the OWNER
//! (the claimant), SUBTREE (a sub-account the owner delegates), GRANT-HOLDER
//! (a stranger the owner granted), NON-ENTITLED (a stranger without a grant),
//! and the GUEST — who, on a WRITE, is `unauthenticated` at slot 0 ahead of
//! every consult and so never reaches one (PUB-6.36's write side presupposes
//! a bound principal; the read side's `withheld` guest cell has no write
//! twin).

use crate::common;

use common::*;
use serde_json::{json, Value};

/// A writer other than the owner: its account, its BARE session, its doc 1
/// (the MINT-FIRST home, born published) and a second, PRIVATE mint — the
/// destination of every write below.
struct Writer {
    account: String,
    session: String,
    doc1: String,
    draft: String,
}

fn create_doc(port: u16, session: &str, account: &str) -> String {
    acked_addr(&op(
        port,
        Some(session),
        &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
    ))
}

fn delegated(port: u16, by: &str, parent: &str, id: u64) -> Writer {
    let v = op(port, Some(by), &format!(r#"{{"op":"next_account_prefix","parent":"{parent}"}}"#));
    let account =
        expect_resp(&v, "maybe_addr")["addr"].as_str().expect("a delegable prefix").to_string();
    expect_resp(
        &op(port, Some(by), &format!(r#"{{"op":"delegate","new_prefix":"{account}","new_id":{id}}}"#)),
        "ack_addr",
    );
    let session = open_session(port, id);
    let doc1 = create_doc(port, &session, &account);
    let draft = create_doc(port, &session, &account);
    Writer { account, session, doc1, draft }
}

/// A STRANGER under node 1, delegated from the bootstrap principal — the
/// NON-ENTITLED writer, or the GRANT-HOLDER once the owner grants.
fn stranger(port: u16, id: u64) -> Writer {
    let boot = open_session(port, 0);
    delegated(port, &boot, "1", id)
}

/// A SUB-ACCOUNT the owner delegates beneath the claimant's account — a
/// SUBTREE reader of every draft of the owner's (PUB-1.4, PUB-1.32).
fn sub_account(port: u16, owner: &str, id: u64) -> Writer {
    delegated(port, owner, CLAIMANT_ACCOUNT, id)
}

fn insert_text(port: u16, session: &str, doc: &str, ordinal: u64, text: &str) -> Value {
    op(
        port,
        Some(session),
        &format!(
            r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":["{text}"]}}"#
        ),
    )
}

/// A private draft of the OWNER's under the claimant's account, holding
/// `text` from ordinal 1 — the SOURCE every cell below reads.
fn owner_draft(port: u16, owner: &str, text: &str) -> String {
    let d = create_doc(port, owner, CLAIMANT_ACCOUNT);
    expect_resp(&insert_text(port, owner, &d, 1, text), "ack_addr");
    d
}

/// An address-form link homed in `home` under a fresh ghost type
/// `{home}.0.3.6.{ordinal}`, from `session`.
fn ghost_link(port: u16, session: &str, home: &str, ordinal: u64) -> String {
    acked_addr(&op(
        port,
        Some(session),
        &format!(
            r#"{{"op":"make_link","home":"{home}","from":{{"addrs":[]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{home}.0.3.6.{ordinal}"]}}}}"#
        ),
    ))
}

/// `copy` into `doc` at content ordinal `at`, each spec `(source, from, width)`.
fn copy_frame(doc: &str, at: u64, specs: &[(&str, u64, u64)]) -> String {
    let specs: Vec<String> = specs
        .iter()
        .map(|(source, from, width)| {
            format!(r#"{{"source":"{source}","span":{{"start":"1.{from}","width":"0.{width}"}}}}"#)
        })
        .collect();
    format!(
        r#"{{"op":"copy","doc":"{doc}","at":{{"subspace":"1","ordinal":"{at}"}},"specs":[{}]}}"#,
        specs.join(",")
    )
}

fn version_frame(d_src: &str) -> String {
    format!(r#"{{"op":"version","d_src":"{d_src}"}}"#)
}

/// `make_link` homed in `home` whose `to` RESOLVES content ordinal 1 of
/// `source`; `ty` a ghost under `home`.
fn make_link_resolving(home: &str, source: &str, ghost: u64) -> String {
    format!(
        r#"{{"op":"make_link","home":"{home}","from":{{"addrs":[]}},"to":[{{"source":"{source}","span":{{"start":"1.1","width":"0.1"}}}}],"ty":{{"addrs":["{home}.0.3.6.{ghost}"]}}}}"#
    )
}

/// The same link with its `to` in ADDRESS FORM naming `to_addr` — no
/// resolution, no read.
fn make_link_naming(home: &str, to_addr: &str, ghost: u64) -> String {
    format!(
        r#"{{"op":"make_link","home":"{home}","from":{{"addrs":[]}},"to":{{"addrs":["{to_addr}"]}},"ty":{{"addrs":["{home}.0.3.6.{ghost}"]}}}}"#
    )
}

/// `edit_link` of `original`, both homes `d`, the successor's `to` resolving
/// content ordinal 1 of `to_source` where given, its `ty` a ghost under `d`.
fn edit_link_frame(original: &str, d: &str, to_source: Option<&str>, ghost: u64) -> String {
    let to = match to_source {
        Some(s) => format!(r#"[{{"source":"{s}","span":{{"start":"1.1","width":"0.1"}}}}]"#),
        None => "[]".to_string(),
    };
    format!(
        r#"{{"op":"edit_link","original":"{original}","d_s":"{d}","d_a":"{d}","successor":{{"from":[],"to":{to},"ty":{{"addrs":["{d}.0.3.6.{ghost}"]}}}}}}"#
    )
}

fn assert_sup_frame(home: &str, old: &str, new: &str) -> String {
    format!(r#"{{"op":"assert_sup","home":"{home}","old":"{old}","new":"{new}"}}"#)
}

fn read1_frame(doc: &str) -> String {
    format!(
        r#"{{"op":"retrieve_v","specs":[{{"doc":"{doc}","span":{{"start":"1.1","width":"0.1"}}}}]}}"#
    )
}

/// A rejection's verdict: the code, or `credential_refused:<token>` for the
/// daemon-originated family (the `auth_wire` convention).
fn code(v: &Value) -> String {
    let rej = expect_resp(v, "rejected");
    match (rej["code"].as_str().unwrap_or("?"), rej["detail"].as_str()) {
        ("credential_refused", Some(d)) => format!("credential_refused:{d}"),
        (c, _) => c.to_string(),
    }
}

/// PUB-8.4/8.5: `withheld`, `reorder`, `site.addr` the document, no `detail`.
fn assert_withheld(v: &Value, doc: &str) {
    let rej = expect_resp(v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("withheld"), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("reorder"), "{v}");
    assert_eq!(rej["site"]["addr"].as_str(), Some(doc), "the withheld source: {v}");
    assert!(rej.get("detail").is_none(), "withheld carries no detail: {v}");
}

/// PUB-6.36 slot 1: `not_owner`, the destination in `site.addr`.
fn assert_not_owner(v: &Value, dest: &str) {
    assert_eq!(code(v), "not_owner", "{v}");
    assert_eq!(v["site"]["addr"].as_str(), Some(dest), "the destination that failed ω: {v}");
}

/// The op's own never-deposited answer for a link named by address
/// (PUB-6.6): `code`, `reorder`, no site, no detail — nothing that says a
/// draft-homed link exists.
fn assert_absent(v: &Value, expected: &str) {
    let rej = expect_resp(v, "rejected");
    assert_eq!(rej["code"].as_str(), Some(expected), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("reorder"), "{v}");
    assert!(rej.get("site").is_none() || rej["site"].is_null(), "an absence answer localizes nothing: {v}");
    assert!(rej.get("detail").is_none(), "{v}");
}

/// H1 cell 1 — `copy` from a private source × class: the OWNER and the
/// SUBTREE reader land; the NON-ENTITLED stranger is `withheld` naming the
/// source, and with two specs the SECOND — declaration order (PUB-6.4); the
/// GRANT-HOLDER is withheld until granted and lands after. The GUEST is
/// `unauthenticated` at slot 0. And slot 1 ahead of slot 6: the stranger
/// copying that same source INTO the owner's document is `not_owner`, never
/// told whether it may read there.
#[test]
fn copy_from_a_private_source_is_withheld_to_the_non_entitled_and_lands_for_the_entitled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let src = owner_draft(port, &owner, "secret");
    let sub = sub_account(port, &owner, 911);
    let b = stranger(port, 912);
    let c = stranger(port, 913);

    let src_run: (&str, u64, u64) = (src.as_str(), 1, 2);
    // OWNER, into a second draft of its own.
    let dst = create_doc(port, &owner, CLAIMANT_ACCOUNT);
    expect_resp(&op(port, Some(&owner), &copy_frame(&dst, 1, &[src_run])), "ack");
    // SUBTREE: reads the owner's draft by containment, so the copy lands.
    expect_resp(&op(port, Some(&sub.session), &copy_frame(&sub.draft, 1, &[src_run])), "ack");
    // NON-ENTITLED: withheld, the source named, nothing placed.
    assert_withheld(&op(port, Some(&c.session), &copy_frame(&c.draft, 1, &[src_run])), &src);
    // Two specs, the SECOND unreadable: `site.addr` is the second.
    expect_resp(&insert_text(port, &c.session, &c.draft, 1, "own"), "ack_addr");
    assert_withheld(
        &op(
            port,
            Some(&c.session),
            &copy_frame(&c.draft, 4, &[(c.draft.as_str(), 1, 1), (src.as_str(), 1, 1)]),
        ),
        &src,
    );
    // …and the refusal placed nothing: the stranger's draft still holds "own".
    let v = op(port, Some(&c.session), &format!(r#"{{"op":"retrieve_doc_v_span_set","doc":"{}"}}"#, c.draft));
    assert_eq!(expect_resp(&v, "span_set")["set"][0]["width"].as_str(), Some("0.3"), "{v}");
    // Slot 1 first: the same source into the OWNER's document is `not_owner`.
    assert_not_owner(&op(port, Some(&c.session), &copy_frame(&dst, 1, &[(src.as_str(), 1, 1)])), &dst);
    // GRANT-HOLDER: withheld before the grant, landing after it.
    assert_withheld(&op(port, Some(&b.session), &copy_frame(&b.draft, 1, &[src_run])), &src);
    deposit_grant(port, &signed, CLAIMANT_DOC1, &src, Some(&b.account));
    expect_resp(&op(port, Some(&b.session), &copy_frame(&b.draft, 1, &[src_run])), "ack");
    // GUEST: no session — refused at slot 0, ahead of every consult.
    assert_eq!(code(&op(port, None, &copy_frame(&c.draft, 1, &[src_run]))), "unauthenticated");

    sd.shutdown();
}

/// H1 cell 2 — `version` of a private source × class: SUBTREE forks it, the
/// NON-ENTITLED stranger is `withheld`, the GRANT-HOLDER forks once granted;
/// the OWNER's own is the store's `private_source_versionless` (PUB-2.9 —
/// the owner reads its draft, so the consult passes and slot 5 speaks). The
/// flagless INHERIT arm on a PUBLISHED source: from a BARE session the
/// publish gate answers `signed_session_required` FIRST (slot 4 ahead of 6;
/// a published source is readable, so `withheld` is unreachable there), from
/// a SIGNED non-entitled session the fork lands; on a PRIVATE source the gate
/// is silent and the consult answers, signed or bare.
#[test]
fn version_of_a_private_source_is_withheld_and_the_inherit_arm_takes_the_publish_gate_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let src = owner_draft(port, &owner, "v");
    let sub = sub_account(port, &owner, 921);
    let b = stranger(port, 922);
    let c = stranger(port, 923);

    expect_resp(&op(port, Some(&sub.session), &version_frame(&src)), "ack_addr");
    assert_withheld(&op(port, Some(&c.session), &version_frame(&src)), &src);
    assert_withheld(&op(port, Some(&b.session), &version_frame(&src)), &src);
    deposit_grant(port, &signed, CLAIMANT_DOC1, &src, Some(&b.account));
    let fork = acked_addr(&op(port, Some(&b.session), &version_frame(&src)));
    assert!(fork.starts_with(&format!("{}.0.", b.account)), "a private copy in the forker's account: {fork}");
    assert_eq!(code(&op(port, Some(&owner), &version_frame(&src))), "private_source_versionless");

    // The INHERIT arm on a PUBLISHED source, bare: slot 4 speaks.
    assert_eq!(
        code(&op(port, Some(&c.session), &version_frame(CLAIMANT_DOC1))),
        "credential_refused:signed_session_required"
    );
    // …signed and non-entitled: the fork lands, born published by inheritance,
    // in the stranger's own account.
    let c_signed = hire(port, &signed, CLAIMANT_DOC1, &c.account, 923, &distinct_key(23));
    let fork = acked_addr(&op(port, Some(&c_signed), &version_frame(CLAIMANT_DOC1)));
    assert!(fork.starts_with(&format!("{}.0.", c.account)), "{fork}");
    // …and on the PRIVATE source the gate is silent: the consult answers the
    // signed stranger exactly as it answered the bare one.
    assert_withheld(&op(port, Some(&c_signed), &version_frame(&src)), &src);

    sd.shutdown();
}

/// H1 cell 3 — `make_link` with a RESOLVE-form slot into a private source ×
/// class: withheld for the NON-ENTITLED stranger and the not-yet-granted
/// GRANT-HOLDER, landing for the OWNER, the SUBTREE reader and the granted
/// holder; the SAME slot in ADDRESS FORM lands for EVERY class, the name
/// recorded verbatim (PUB-6.24: ungated). Slot 1 first: the stranger's link
/// INTO the owner's draft is `not_owner`.
#[test]
fn a_make_link_resolve_slot_into_a_private_source_is_withheld_and_the_address_form_is_ungated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let src = owner_draft(port, &owner, "ab");
    let sub = sub_account(port, &owner, 931);
    let b = stranger(port, 932);
    let c = stranger(port, 933);

    expect_resp(&op(port, Some(&owner), &make_link_resolving(&src, &src, 1)), "ack_addr");
    expect_resp(&op(port, Some(&sub.session), &make_link_resolving(&sub.draft, &src, 1)), "ack_addr");
    assert_withheld(&op(port, Some(&c.session), &make_link_resolving(&c.draft, &src, 1)), &src);
    assert_withheld(&op(port, Some(&b.session), &make_link_resolving(&b.draft, &src, 1)), &src);
    deposit_grant(port, &signed, CLAIMANT_DOC1, &src, Some(&b.account));
    expect_resp(&op(port, Some(&b.session), &make_link_resolving(&b.draft, &src, 1)), "ack_addr");
    // Slot 1 first.
    assert_not_owner(&op(port, Some(&c.session), &make_link_resolving(&src, &src, 3)), &src);

    // The ADDRESS FORM names an I-position INSIDE the draft, unresolved, for
    // every class — the non-entitled stranger included.
    let inside = format!("{src}.0.1.1");
    for (session, home) in [
        (&owner, &src),
        (&sub.session, &sub.draft),
        (&b.session, &b.draft),
        (&c.session, &c.draft),
    ] {
        let link = acked_addr(&op(port, Some(session), &make_link_naming(home, &inside, 2)));
        let v = op(port, Some(session), &format!(r#"{{"op":"read_link","a":"{link}"}}"#));
        assert_eq!(
            expect_resp(&v, "link_value")["link"]["slots"][1][0]["start"].as_str(),
            Some(inside.as_str()),
            "the name verbatim: {v}"
        );
    }

    sd.shutdown();
}

/// H1 cell 4 — the link-address rule on writes (PUB-6.6): `edit_link` of an
/// original homed in a private document answers the op's own
/// `original_not_resident` to the NON-ENTITLED stranger — never `withheld`,
/// never `not_owner` — with the link-address argument speaking ahead of an
/// unreadable successor source (declaration order); a READABLE original with
/// a resolve-form successor spec into the private source is `withheld`
/// naming the source; `assert_sup.old`/`new` homed there answer
/// `endpoint_not_resident`. Slot 1 first: the same edit with the OWNER's
/// draft as its home is `not_owner`. The GRANT-HOLDER and the OWNER land
/// both writes.
#[test]
fn edit_link_and_assert_sup_answer_absence_for_links_homed_in_a_private_document() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let src = owner_draft(port, &owner, "ab");
    let l1 = ghost_link(port, &owner, &src, 1);
    let l2 = ghost_link(port, &owner, &src, 2);
    // A PUBLIC link — homed in the published doc 1, readable to every class.
    let public_l = ghost_link(port, &signed, CLAIMANT_DOC1, 41);
    let b = stranger(port, 942);
    let c = stranger(port, 943);

    // NON-ENTITLED: the original's home is unreadable — the never-deposited
    // answer, reorder, nothing localized.
    assert_absent(&op(port, Some(&c.session), &edit_link_frame(&l1, &c.draft, None, 1)), "original_not_resident");
    // Both the original and the successor's source unreadable: the
    // link-address argument is declared first and speaks.
    assert_absent(
        &op(port, Some(&c.session), &edit_link_frame(&l1, &c.draft, Some(&src), 2)),
        "original_not_resident",
    );
    // A readable original, an unreadable successor source: withheld, naming it.
    assert_withheld(&op(port, Some(&c.session), &edit_link_frame(&public_l, &c.draft, Some(&src), 3)), &src);
    // The supersession claim over endpoints homed in the private document.
    assert_absent(&op(port, Some(&c.session), &assert_sup_frame(&c.draft, &l1, &l2)), "endpoint_not_resident");
    assert_absent(&op(port, Some(&c.session), &assert_sup_frame(&c.draft, &public_l, &l2)), "endpoint_not_resident");
    // Slot 1 first: the owner's draft as the home is `not_owner`, never absence.
    assert_not_owner(&op(port, Some(&c.session), &edit_link_frame(&l1, &src, Some(&src), 4)), &src);
    assert_not_owner(&op(port, Some(&c.session), &assert_sup_frame(&src, &l1, &l2)), &src);

    // GRANT-HOLDER: granted, the link is visible and both writes land.
    deposit_grant(port, &signed, CLAIMANT_DOC1, &src, Some(&b.account));
    expect_resp(&op(port, Some(&b.session), &edit_link_frame(&l1, &b.draft, Some(&src), 1)), "ack_edit");
    expect_resp(&op(port, Some(&b.session), &assert_sup_frame(&b.draft, &l1, &l2)), "ack_addr");
    // OWNER: both land in the draft.
    expect_resp(&op(port, Some(&owner), &edit_link_frame(&l1, &src, Some(&src), 5)), "ack_edit");
    expect_resp(&op(port, Some(&owner), &assert_sup_frame(&src, &l1, &l2)), "ack_addr");

    sd.shutdown();
}

/// H1 cell 4, the SUBTREE axis — the cell the property suite surfaced (H4,
/// `properties.rs`, whose chain world names an ancestor's link from a
/// descendant and the reverse in every run): the link-address rule on writes
/// runs the subtree clause DOWNWARD only (PUB-1.32), so a SUB-ACCOUNT's
/// `assert_sup` and `edit_link` over links homed in its ANCESTOR's draft
/// land, while the ancestor's over links homed in the sub-account's draft
/// answer `endpoint_not_resident` / `original_not_resident` — the
/// never-deposited address's answer, even to the principal that delegated
/// the account, and on a mixed pair as on a wholly unreadable one.
#[test]
fn a_sub_account_names_its_ancestor_s_links_and_the_ancestor_cannot_name_the_sub_account_s() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let src = owner_draft(port, &owner, "ab");
    let up1 = ghost_link(port, &owner, &src, 1);
    let up2 = ghost_link(port, &owner, &src, 2);
    let sub = sub_account(port, &owner, 991);
    let down1 = ghost_link(port, &sub.session, &sub.draft, 1);
    let down2 = ghost_link(port, &sub.session, &sub.draft, 2);

    // Downward: the sub-account reads the owner's draft, so its writes over
    // the links homed there land in its own draft.
    expect_resp(&op(port, Some(&sub.session), &assert_sup_frame(&sub.draft, &up1, &up2)), "ack_addr");
    expect_resp(&op(port, Some(&sub.session), &edit_link_frame(&up1, &sub.draft, None, 3)), "ack_edit");
    // Never upward: the owner does not read the sub-account's draft, so the
    // links homed there are absent to it — its own delegation notwithstanding.
    assert_absent(&op(port, Some(&owner), &assert_sup_frame(&src, &down1, &down2)), "endpoint_not_resident");
    assert_absent(&op(port, Some(&owner), &assert_sup_frame(&src, &up1, &down2)), "endpoint_not_resident");
    assert_absent(&op(port, Some(&owner), &edit_link_frame(&down1, &src, None, 3)), "original_not_resident");

    sd.shutdown();
}

/// H1 cell 5 — REGISTRATION FIRST (PUB-6.37): an UNREGISTERED source is
/// fail-open at the predicate and answers the store's own
/// `source_not_registered` — `copy`'s and `version`'s from the store,
/// `edit_link`'s from M10's own successor guard — never `withheld`: a
/// withheld answer is only ever a registered private document.
#[test]
fn an_unregistered_source_answers_source_not_registered_never_withheld() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let public_l = ghost_link(port, &signed, CLAIMANT_DOC1, 51);
    let c = stranger(port, 953);
    let never = format!("{CLAIMANT_ACCOUNT}.0.99");

    for frame in [
        copy_frame(&c.draft, 1, &[(never.as_str(), 1, 1)]),
        version_frame(&never),
        edit_link_frame(&public_l, &c.draft, Some(&never), 1),
    ] {
        let v = op(port, Some(&c.session), &frame);
        assert_eq!(code(&v), "source_not_registered", "never withheld: {v}");
        assert_eq!(v["disposition"].as_str(), Some("reorder"), "{v}");
    }

    sd.shutdown();
}

/// H1 cell 6 — the public-link-into-a-draft cell (PUB-6.14, PUB-6.15,
/// PUB-6.22; PUB-1.13, PUB-1.14, PUB-1.55): the owner writes a link in a
/// PUBLIC home whose `to` resolves into the owner's draft, and a published
/// member of doc 1 windows the same runs. To a stranger and to the guest the
/// link is read WHOLE, `follow_link` answers the endset VERBATIM naming the
/// draft's own I-space, `retrieve_v` over the windowed region delivers the
/// `withheld` item at its position, `image` on the public member returns the
/// run whole, and `project`/`discoverable_from` on the READABLE home answer
/// whole — while a link homed IN the draft stays absent to them by address
/// (PUB-6.6, built in lane 3.3), and the draft itself withheld.
#[test]
fn a_public_link_into_a_draft_is_visible_whole_and_the_draft_s_bytes_are_withheld_per_origin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = owner_draft(port, &owner, "abcde");
    let i_start = format!("{draft}.0.1.1");

    // The published member WINDOWING the draft's positions 1–2 (the shot).
    let member = acked_addr(&op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"publish","doc":"{CLAIMANT_DOC1}","runs":[{{"origin":"{draft}","i_start":"{i_start}","width":"2"}}]}}"#
        ),
    ));
    // The PUBLIC link: homed in doc 1, its `to` RESOLVING into the draft —
    // the owner reads its draft, so the consult admits it.
    let plink = acked_addr(&op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":[]}},"to":[{{"source":"{draft}","span":{{"start":"1.1","width":"0.2"}}}}],"ty":{{"addrs":["{CLAIMANT_DOC1}.0.3.6.61"]}}}}"#
        ),
    ));
    // …and a link homed IN the draft, the absence half's subject.
    let dlink = ghost_link(port, &owner, &draft, 1);
    let c = stranger(port, 963);

    for token in [None, Some(c.session.as_str())] {
        // read_link: whole, three slots.
        let v = op(port, token, &format!(r#"{{"op":"read_link","a":"{plink}"}}"#));
        let link = &expect_resp(&v, "link_value")["link"];
        assert_eq!(link["slots"].as_array().map(Vec::len), Some(3), "the link whole: {v}");
        // follow_link, slot 2: the endset VERBATIM — the draft's own I-space.
        let v = op(port, token, &format!(r#"{{"op":"follow_link","a":"{plink}","slot":2}}"#));
        let ok = expect_resp(&v, "follow")["result"]["ok"].as_array().expect("ok spans").clone();
        assert_eq!(ok.len(), 1, "{v}");
        assert_eq!(ok[0]["start"].as_str(), Some(i_start.as_str()), "the draft's I-address, verbatim: {v}");
        assert!(ok[0]["width"].as_str().is_some_and(|w| w.ends_with(".2")), "two positions: {v}");
        // retrieve_v over the member's window: the withheld item at its position.
        let v = op(
            port,
            token,
            &format!(
                r#"{{"op":"retrieve_v","specs":[{{"doc":"{member}","span":{{"start":"1.1","width":"0.2"}}}}]}}"#
            ),
        );
        assert_eq!(
            expect_resp(&v, "delivery")["items"],
            json!([{"withheld": {"origin": draft, "width": "2"}}]),
            "{v}"
        );
        // image on the public member: the run WHOLE, its i_start in the draft's I-space.
        let v = op(port, token, &format!(r#"{{"op":"image","d":"{member}","region":[{{"start":"1.1","width":"0.2"}}]}}"#));
        assert_eq!(expect_resp(&v, "runs")["runs"], json!([{"i_start": i_start, "width": "2"}]), "{v}");
        // project and discoverable_from on the READABLE home: answered whole.
        let v = op(port, token, &format!(r#"{{"op":"project","a":"{plink}","slot":2,"d":"{member}"}}"#));
        assert!(!expect_resp(&v, "span_set")["set"].as_array().expect("set").is_empty(), "{v}");
        let v = op(port, token, &format!(r#"{{"op":"discoverable_from","a":"{plink}","d":"{member}"}}"#));
        assert_eq!(expect_resp(&v, "bool")["val"], json!(true), "{v}");

        // The absence half: a link homed IN the draft, by address.
        let v = op(port, token, &format!(r#"{{"op":"project","a":"{dlink}","slot":1,"d":"{member}"}}"#));
        assert_eq!(code(&v), "not_a_link", "{v}");
        let v = op(port, token, &format!(r#"{{"op":"discoverable_from","a":"{dlink}","d":"{member}"}}"#));
        assert_eq!(expect_resp(&v, "bool")["val"], json!(false), "{v}");
        // And the draft itself, by address: withheld (the doc-argument row).
        assert_withheld(&op(port, token, &read1_frame(&draft)), &draft);
    }
    // The owner reads the bytes through the window.
    let v = op(
        port,
        Some(&owner),
        &format!(r#"{{"op":"retrieve_v","specs":[{{"doc":"{member}","span":{{"start":"1.1","width":"0.2"}}}}]}}"#),
    );
    assert_eq!(expect_resp(&v, "delivery")["items"], json!([{"content": "ab"}]), "{v}");

    sd.shutdown();
}

/// H1 cell 7 — the HIRE helper's own test (AUTH-5.58, AUTH-2.62, AUTH-2.70):
/// a delegated, keyless principal's bare grant into its own published doc 1
/// meets `signed_session_required` (RES-26 — what lane 3.3's round 2 met);
/// the claimant keys it into the claimant's doc 1 — its genesis registry —
/// and its SIGNED session then deposits the grant, after which the grantee
/// reads and the guest still does not (PUB-5.109).
#[test]
fn a_hired_principal_s_signed_session_deposits_a_grant_and_a_stranger_reads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let a = stranger(port, 971);
    expect_resp(&insert_text(port, &a.session, &a.draft, 1, "hi"), "ack_addr");
    let b = stranger(port, 972);

    assert_withheld(&op(port, Some(&b.session), &read1_frame(&a.draft)), &a.draft);
    // Bare, the grant is refused at the publish gate: a doc 1 is published.
    let bare_grant = format!(
        r#"{{"op":"make_link","home":"{}","from":{{"addrs":["{}"]}},"to":{{"addrs":["{}"]}},"ty":{{"addrs":["{T_GRANT}"]}}}}"#,
        a.doc1, a.draft, b.account
    );
    assert_eq!(code(&op(port, Some(&a.session), &bare_grant)), "credential_refused:signed_session_required");

    // THE HIRE: A is bootstrap-delegated, so its genesis registry is the
    // claimant's doc 1 (AUTH-2.62); the claimant's signed session keys it.
    let a_signed = hire(port, &signed, CLAIMANT_DOC1, &a.account, 971, &distinct_key(71));
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{}"}}"#, a.account));
    assert_eq!(v["enrolled"].as_array().map(Vec::len), Some(1), "the hire's one device key: {v}");

    // A's signed session grants B the draft from A's OWN doc 1; B reads.
    deposit_grant(port, &a_signed, &a.doc1, &a.draft, Some(&b.account));
    let v = op(port, Some(&b.session), &read1_frame(&a.draft));
    assert_eq!(expect_resp(&v, "delivery")["items"], json!([{"content": "h"}]), "{v}");
    // The guest, and a third stranger (the grantee is principal-exact), still do not.
    assert_withheld(&op(port, None, &read1_frame(&a.draft)), &a.draft);
    let d = stranger(port, 973);
    assert_withheld(&op(port, Some(&d.session), &read1_frame(&a.draft)), &a.draft);

    sd.shutdown();
}

/// THE CELL WHERE SLOT 5 AND SLOT 6 BOTH APPLY, pinned AS BUILT and reported
/// (lane 3.3c §1): a `copy` from a source the caller may not read INTO a
/// PUBLISHED destination the caller owns. PUB-6.36 orders the model's
/// refusals (slot 5 — here `published_target`, PUB-2.11) AHEAD of the
/// per-source consult (slot 6); as built, the consult is PRE-DISPATCH at
/// M10's door (PUB-6.38) and `published_target` is the STORE's, inside its
/// transaction (owner ruling D2b), so the DOOR pre-evaluates the in-place
/// refusal for `copy` and answers `published_target` ahead of the consult
/// (PUB-6.36 slot 5 before slot 6; lane 4.2). The store's own answer is
/// pinned beside it over a READABLE source, so the two halves of the cell
/// are both visible. The versionless sibling never meets
/// the consult: `private_source_versionless` fires only on a source the
/// caller OWNS and so reads.
#[test]
fn a_copy_from_an_unreadable_source_into_a_published_destination_answers_published_target_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let src = owner_draft(port, &owner, "s");
    let a = stranger(port, 981);
    expect_resp(&insert_text(port, &a.session, &a.draft, 1, "x"), "ack_addr");
    let a_signed = hire(port, &signed, CLAIMANT_DOC1, &a.account, 981, &distinct_key(81));

    // A readable source: slot 5, the store's own in-place refusal.
    assert_eq!(
        code(&op(port, Some(&a_signed), &copy_frame(&a.doc1, 1, &[(a.draft.as_str(), 1, 1)]))),
        "published_target"
    );
    // An unreadable source: slot 5 still speaks first — the door answers
    // the model's refusal before it would consult the source (PUB-6.36).
    assert_eq!(
        code(&op(port, Some(&a_signed), &copy_frame(&a.doc1, 1, &[(src.as_str(), 1, 1)]))),
        "published_target"
    );

    sd.shutdown();
}
