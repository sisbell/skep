use super::*;

/// A program with no help, for the codes alone.
const PROGRAM: Program = Program { name: "skep", help: "" };

/// Every stop answers §2.3's code from the one renderer: a usage refusal
/// 2, a halt the code its family carries, a store refusal faced as a
/// halt, and a DATA write stdout refused a halt, 3.
#[test]
fn every_stop_finishes_with_its_exit_code() {
    assert_eq!(finish(PROGRAM, Ok(())), 0);
    assert_eq!(finish(PROGRAM, Err(Usage("a command is required".into()).into())), 2);
    assert_eq!(finish(PROGRAM, Err(Halt::face("state", "cause", "act").into())), 3);
    let refused = skep_client::Refused {
        status: 200,
        code: "credential_refused".into(),
        detail: None,
        op: None,
        body: serde_json::Value::Null,
    };
    assert_eq!(finish(PROGRAM, Err(Halt::Refused(refused).into())), 1);
    assert_eq!(
        finish(PROGRAM, Err(Halt::Dial(skep_client::DialError::Connect("refused".into())).into())),
        4
    );
    assert_eq!(finish(PROGRAM, Err(StoreError::NotFound { select: "zz".into() }.into())), 3);
    assert_eq!(finish(PROGRAM, Err(data_refused(io::ErrorKind::BrokenPipe.into()).into())), 3);
}

/// Every transport halt carries an act, by where its exchange broke —
/// nothing sent before the request was written, the read-back after it,
/// the opening daemon and this client's bounds at a timeout — and a
/// retry-class refusal the retry; `index_failed`'s 503, a `rejected`
/// document and a face carry none beside their own.
#[test]
fn a_transport_halt_and_a_busy_board_name_their_act() {
    let act =
        |d: DialError| act_beside(&Halt::Dial(d)).expect("every transport halt carries an act");
    for unsent in [DialError::Connect("refused".into()), DialError::Resolve("no addresses".into())]
    {
        let a = act(unsent);
        assert!(
            a.starts_with("nothing was sent") && a.contains("or SKEP_BOARD where no flag is given"),
            "{a}"
        );
    }
    for broke in [
        DialError::Io("read".into()),
        DialError::Truncated { declared: 9, got: 3 },
        DialError::Tls("record".into()),
        DialError::Response("not http".into()),
        DialError::TooLarge { cap: 9 },
    ] {
        let a = act(broke);
        assert!(a.contains("read back"), "{a}");
    }
    let a = act(DialError::Timeout("read".into()));
    assert!(
        a.contains("still opening its journal")
            && a.contains("RUNBOOK.md §3, step 5")
            && a.contains(&format!(
                "{} s for a connection and {} s on a read",
                CONNECT_TIMEOUT.as_secs(),
                IO_TIMEOUT.as_secs()
            ))
            && a.contains("reading back first"),
        "{a}"
    );
    assert!(act(DialError::NotHeld("https".into())).contains("`tls`"));
    assert!(act(DialError::Request("target".into())).starts_with("nothing was sent"));
    let refused = |status: u16, code: &str| {
        Halt::Refused(skep_client::Refused {
            status,
            code: code.into(),
            detail: None,
            op: None,
            body: serde_json::Value::Null,
        })
    };
    for busy in ["write_busy", "scan_busy", "history_busy", "feed_rebuilding"] {
        assert!(
            act_beside(&refused(503, busy))
                .is_some_and(|a| a.contains("took nothing of this request")),
            "{busy}"
        );
    }
    assert_eq!(act_beside(&refused(503, "index_failed")), None, "the one 503 no retry clears");
    assert_eq!(act_beside(&refused(200, "credential_refused")), None);
    assert_eq!(act_beside(&Halt::face("state", "cause", "act")), None, "a face names its own act");
}

/// A write refused for the board's own state names the act that clears
/// it: `poisoned` the restart, room BEFORE it where the volume is full;
/// `durability` the room alone, no restart owed — each a rejected
/// document's code (HTTP 200), and no other code at 200 an act.
#[test]
fn a_halted_board_and_a_full_volume_name_their_act() {
    let rejected = |code: &str| {
        Halt::Refused(skep_client::Refused {
            status: 200,
            code: code.into(),
            detail: None,
            op: Some("delegate".into()),
            body: serde_json::Value::Null,
        })
    };
    let poisoned = act_beside(&rejected("poisoned")).expect("poisoned names its act");
    assert!(
        poisoned.contains("until its daemon restarts")
            && poisoned.contains("make room BEFORE the restart")
            && poisoned.contains("RUNBOOK.md §1, steps 4 and 5"),
        "{poisoned}"
    );
    let durability = act_beside(&rejected("durability")).expect("durability names its act");
    assert!(
        durability.starts_with("the write did nothing")
            && durability.contains("no restart owed")
            && durability.contains("never by deleting, moving or truncating a file"),
        "{durability}"
    );
    assert_eq!(act_beside(&rejected("credential_refused")), None);
    assert_eq!(act_beside(&rejected("not_owner")), None);
}

/// A DATA line carries no control a board chose: each C0 control — a
/// clipboard write's escape and bell, a carriage return, the line break
/// that would forge a second line — shown as its code point; and a
/// canonical record whose label holds a tab, DEL and a bidi control
/// passes byte for byte, its encoder having escaped the tab and left the
/// other two standing (AUTH-2.130 clause 3).
#[test]
fn a_data_line_renders_every_c0_control_and_passes_a_record_whole() {
    assert_eq!(
        c0_inert("claimed by 1.0.1\x1b]52;c;cHduZWQ=\x07\r\naccount 1.0.9"),
        "claimed by 1.0.1<U+001B>]52;c;cHduZWQ=<U+0007><U+000D><U+000A>account 1.0.9"
    );
    let key =
        skep_client::sheet::KeyFile::new(skep_client::sheet::Seed::new([7; 32]), false, None, None)
            .public;
    let record = skep_identity::encode_enroll(&[skep_identity::Enrollment::new(
        key,
        false,
        Some("a\tb\u{7f}c\u{202e}d".into()),
    )
    .unwrap()]);
    assert!(
        record.contains('\u{7f}') && record.contains('\u{202e}') && !record.contains('\t'),
        "{record}"
    );
    assert!(matches!(c0_inert(&record), Cow::Borrowed(text) if text == record));
}

/// A third party's text a line echoes is clipped to [`CLIPPED_CHARS`]
/// characters — counted in chars, so a cut never splits one — an
/// ellipsis marking the cut; text at or under the bound stands whole.
#[test]
fn a_third_partys_text_is_clipped_to_its_bound_in_chars() {
    assert_eq!(clipped("1.0.1"), "1.0.1");
    let at = "é".repeat(CLIPPED_CHARS);
    assert_eq!(clipped(&at), at, "at the bound, whole");
    assert_eq!(clipped(&format!("{at}é")), format!("{at}…"), "past it, cut at a character");
    assert_eq!(clipped(&"a".repeat(100_000)).chars().count(), CLIPPED_CHARS + 1);
}

/// A key is named by its fingerprint and its label, `(none)` where it has
/// none, the label rendered inert.
#[test]
fn a_key_is_named_by_its_fingerprint_and_its_label() {
    let file = |label: Option<&str>| {
        let file = skep_client::sheet::KeyFile::new(
            skep_client::sheet::Seed::new([7; 32]),
            false,
            label.map(|l| skep_client::sheet::Label::new(l).unwrap()),
            None,
        );
        KeyFacts {
            fingerprint: file.fingerprint,
            public: file.public.clone(),
            anchor: false,
            label: label.map(str::to_string),
            path: "/s/keys/k.key".into(),
        }
    };
    let phone = file(Some("phone\u{202e}"));
    assert_eq!(key_named(&phone), format!("{} (label phone<U+202E>)", phone.fingerprint));
    let bare = file(None);
    assert_eq!(key_named(&bare), format!("{} (label (none))", bare.fingerprint));
}
