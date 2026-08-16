//! Restart: run writes, shut the daemon down, reopen the SAME data dir, and
//! prove the world came back — byte-identical read bodies (the `as_of`
//! included, since recovery restores the log position), dump equality under
//! `observe`, and the documented session reset (stale tokens miss).

mod common;

use common::*;

#[test]
fn world_survives_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");

    let doc: String;
    let stale_token: String;
    let retrieve_frame: String;
    let spanset_frame: String;
    let before_retrieve: Vec<u8>;
    let before_spanset: Vec<u8>;
    #[cfg(feature = "observe")]
    let before_dump: Vec<u8>;

    // ── first life: genesis, writes, capture read-backs ──
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let boot = open_session(port, 0);
        let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
        let prefix =
            expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
        let v = op(
            port,
            Some(&boot),
            &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
        );
        let account = acked_addr(&v);
        let s1 = open_session(port, 1);
        stale_token = s1.clone();

        let v = op(
            port,
            Some(&s1),
            &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
        );
        doc = acked_addr(&v);
        // Per-byte writes: "durable" fills positions 1..=7, so the append
        // lands at ordinal 8 — twelve positions of "durable text" in all.
        for (ord, text) in [(1, "durable"), (8, " text")] {
            let v = op(
                port,
                Some(&s1),
                &format!(
                    r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{ord}"}},"values":["{text}"]}}"#
                ),
            );
            expect_resp(&v, "ack_addr");
        }

        retrieve_frame = format!(
            r#"{{"op":"retrieve_v","specs":[{{"doc":"{doc}","span":{{"start":"1.1","width":"0.12"}}}}]}}"#
        );
        spanset_frame = format!(r#"{{"op":"retrieve_doc_v_span_set","doc":"{doc}"}}"#);
        let (st, body) = http(port, "POST", "/op", None, retrieve_frame.as_bytes());
        assert_eq!(st, 200);
        before_retrieve = body;
        let (st, body) = http(port, "POST", "/op", None, spanset_frame.as_bytes());
        assert_eq!(st, 200);
        before_spanset = body;
        #[cfg(feature = "observe")]
        {
            let (st, body) = get(port, "/dump");
            assert_eq!(st, 200);
            before_dump = body;
        }

        // Joins the workers and drops the kernel — the journal-directory
        // lock releases here, which is what makes the reopen legal.
        sd.shutdown();
    }

    // ── second life: recovery on the same directory ──
    {
        let sd = spawn(dir.path());
        let port = sd.port();

        // The recovered world answers the same reads with byte-identical
        // bodies — as_of included (recovery restores the log position).
        let (st, after_retrieve) = http(port, "POST", "/op", None, retrieve_frame.as_bytes());
        assert_eq!(st, 200);
        assert_eq!(
            before_retrieve,
            after_retrieve,
            "retrieve_v drifted across restart:\n before {}\n after  {}",
            String::from_utf8_lossy(&before_retrieve),
            String::from_utf8_lossy(&after_retrieve),
        );
        let (st, after_spanset) = http(port, "POST", "/op", None, spanset_frame.as_bytes());
        assert_eq!(st, 200);
        assert_eq!(before_spanset, after_spanset, "doc_v_span_set drifted across restart");

        #[cfg(feature = "observe")]
        {
            let (st, after_dump) = get(port, "/dump");
            assert_eq!(st, 200);
            assert_eq!(
                before_dump, after_dump,
                "the recovered world's dump must be byte-equal to the pre-shutdown dump"
            );
        }

        // Sessions are process-lifetime: the old token is dead, so a write
        // under it is the guest path — M10's Unauthenticated, not a 4xx.
        let v = op(
            port,
            Some(&stale_token),
            &format!(
                r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"13"}},"values":["x"]}}"#
            ),
        );
        assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("unauthenticated"));

        // Re-authenticating works and the world accepts new writes.
        let s1 = open_session(port, 1);
        let v = op(
            port,
            Some(&s1),
            &format!(
                r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"13"}},"values":["!"]}}"#
            ),
        );
        expect_resp(&v, "ack_addr");

        sd.shutdown();
    }
}
