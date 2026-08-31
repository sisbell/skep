//! The ownership gate through the wire (the 2026-08-16 ruling): a sibling
//! principal's insert into a foreign document comes back as the `not_owner`
//! rejection with `site.addr` naming the document — end to end over a real
//! socket. The gate itself is store-owned and store-tested; what this file
//! asserts is the TRANSPORT: the session principal reaches the store, and
//! the typed rejection (code, disposition, site) survives marshaling.

mod common;

use common::*;

#[test]
fn sibling_insert_rejects_not_owner_with_the_document_in_site_addr() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    // Two SIBLING principals, each delegated directly under node [1] by the
    // bootstrap session (not one under the other — exactness is the store
    // suite's job; the sibling probe is the wire's).
    let boot = open_session(port, 0);
    let delegate = |id: u64| {
        let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
        let prefix =
            expect_resp(&v, "maybe_addr")["addr"].as_str().expect("delegable prefix").to_string();
        let v = op(
            port,
            Some(&boot),
            &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":{id}}}"#),
        );
        acked_addr(&v)
    };
    let account1 = delegate(1);
    let _account2 = delegate(2);
    let s1 = open_session(port, 1);
    let s2 = open_session(port, 2);

    // MINT-FIRST (RES-26): an account's first document is its doc 1, born
    // published, where a bare owner write is gated by design — the probe
    // document is a second, private mint.
    let v = op(
        port,
        Some(&s1),
        &format!(r#"{{"op":"create_new_document","account":"{account1}"}}"#),
    );
    expect_resp(&v, "ack_addr");

    // Principal 1's document, with content.
    let v = op(
        port,
        Some(&s1),
        &format!(r#"{{"op":"create_new_document","account":"{account1}"}}"#),
    );
    let doc = acked_addr(&v);
    let insert_frame = format!(
        r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"1"}},"values":["mine"]}}"#
    );
    expect_resp(&op(port, Some(&s1), &insert_frame), "ack_addr");

    // The sibling's identical frame: rejected `not_owner`, permanent, with
    // site.addr naming the document that failed the ω check.
    let append = format!(
        r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"5"}},"values":["theirs"]}}"#
    );
    let v = op(port, Some(&s2), &append);
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["op"].as_str(), Some("insert"));
    assert_eq!(rej["code"].as_str(), Some("not_owner"));
    assert_eq!(rej["disposition"].as_str(), Some("permanent"));
    assert_eq!(
        rej["site"]["addr"].as_str(),
        Some(doc.as_str()),
        "site.addr must name the document that failed the check: {v}"
    );

    // The owner's own append still lands, and the content is untouched by
    // the rejected write.
    expect_resp(&op(port, Some(&s1), &append), "ack_addr");
    let v = op(
        port,
        None,
        &format!(
            r#"{{"op":"retrieve_v","specs":[{{"doc":"{doc}","span":{{"start":"1.1","width":"0.10"}}}}]}}"#
        ),
    );
    let text: String = expect_resp(&v, "delivery")["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|i| i["content"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(text, "minetheirs", "only the owner's writes reached the document");

    sd.shutdown();
}

#[test]
fn foreign_nullify_target_rejects_not_owner_naming_the_link() {
    // The v1 nullify target policy over the wire: owning the retraction's
    // home does not license retracting someone else's link — the rejection
    // names the TARGET in site.addr.
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let boot = open_session(port, 0);
    let delegate = |id: u64| {
        let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
        let prefix =
            expect_resp(&v, "maybe_addr")["addr"].as_str().expect("delegable prefix").to_string();
        let v = op(
            port,
            Some(&boot),
            &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":{id}}}"#),
        );
        acked_addr(&v)
    };
    let account1 = delegate(1);
    let account2 = delegate(2);
    let s1 = open_session(port, 1);
    let s2 = open_session(port, 2);

    // MINT-FIRST (RES-26): each account's doc 1 is born published, so the
    // working documents below are second, private mints.
    let v = op(
        port,
        Some(&s1),
        &format!(r#"{{"op":"create_new_document","account":"{account1}"}}"#),
    );
    expect_resp(&v, "ack_addr");
    let v = op(
        port,
        Some(&s2),
        &format!(r#"{{"op":"create_new_document","account":"{account2}"}}"#),
    );
    expect_resp(&v, "ack_addr");

    // Principal 1's document holds a link (ghost-name typed, no content
    // needed); principal 2 owns a home of its own.
    let v = op(
        port,
        Some(&s1),
        &format!(r#"{{"op":"create_new_document","account":"{account1}"}}"#),
    );
    let doc1 = acked_addr(&v);
    let v = op(
        port,
        Some(&s2),
        &format!(r#"{{"op":"create_new_document","account":"{account2}"}}"#),
    );
    let doc2 = acked_addr(&v);
    let v = op(
        port,
        Some(&s1),
        &format!(
            r#"{{"op":"make_link","home":"{doc1}","from":{{"addrs":[]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{doc1}.0.3.1"]}}}}"#
        ),
    );
    let link = acked_addr(&v);

    // Principal 2, from its OWN home, aims at principal 1's link.
    let v = op(
        port,
        Some(&s2),
        &format!(r#"{{"op":"nullify","home":"{doc2}","target":"{link}"}}"#),
    );
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("not_owner"));
    assert_eq!(
        rej["site"]["addr"].as_str(),
        Some(link.as_str()),
        "site.addr must name the target link: {v}"
    );

    // The link is still active: the owner's discovery view is unchanged.
    let v = op(port, None, &format!(r#"{{"op":"read_link","a":"{link}"}}"#));
    assert!(
        !expect_resp(&v, "link_value")["link"].is_null(),
        "the foreign retraction must not have landed"
    );
    // And the owner's own retraction still works.
    let v = op(
        port,
        Some(&s1),
        &format!(r#"{{"op":"nullify","home":"{doc1}","target":"{link}"}}"#),
    );
    expect_resp(&v, "ack_addr");

    sd.shutdown();
}
