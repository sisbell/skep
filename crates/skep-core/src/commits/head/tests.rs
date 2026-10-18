use super::*;

/// The schema's ONE card, both directions: a record renders in the
/// schema's order with no whitespace and reads back as itself, `base`
/// and `prev` present or absent. The two hashes of a `base` are distinct
/// bytes, so a transposed pair cannot pass; and a record another format
/// wrote is not this build's head.
#[test]
fn a_head_record_renders_in_schema_order_and_reads_back_as_itself() {
    let hex = |b: u8| hex_string(&[b; 32]);
    let full = HeadRecord {
        position: 7,
        chain: [0xab; 32],
        base: Some(CheckpointBase { seq: 4, chain: [0x01; 32], body_hash: [0x02; 32] }),
        prev: Some(CommittedPair { position: 3, chain: [0xcd; 32] }),
    };
    let bytes = full.to_bytes();
    assert_eq!(
        String::from_utf8(bytes.clone()).expect("utf-8"),
        format!(
            "{{\"type\":\"skep-head\",\"format\":\"{FORMAT_STAMP}\",\"position\":7,\
             \"chain\":\"{}\",\"base\":{{\"seq\":4,\"chain\":\"{}\",\"body_hash\":\"{}\"}},\
             \"prev\":{{\"position\":3,\"chain\":\"{}\"}}}}",
            hex(0xab),
            hex(0x01),
            hex(0x02),
            hex(0xcd),
        ),
    );
    assert_eq!(HeadRecord::parse(&bytes), Some(full));
    let first = HeadRecord { position: 1, chain: [0x0f; 32], base: None, prev: None };
    let first_bytes = first.to_bytes();
    assert_eq!(HeadRecord::parse(&first_bytes), Some(first), "the first head: base and prev null");
    let first_text = String::from_utf8(first_bytes).expect("utf-8");
    let foreign = first_text.replace(FORMAT_STAMP, "SKJ3");
    assert_eq!(HeadRecord::parse(foreign.as_bytes()), None, "a head another format wrote");
    let other_type = first_text.replace(RECORD_TYPE, "skep-tail");
    assert_eq!(HeadRecord::parse(other_type.as_bytes()), None, "a record of another type");
    // The reader admits EXACTLY what the writer emits: `hex_string` writes
    // lowercase and no sign, so another spelling of the same bytes — one a
    // radix parse would fold back to them — is not this build's record.
    let chain = hex(0x0f);
    for respelled in [chain.to_uppercase(), format!("+f{}", &chain[2..])] {
        let text = first_text.replace(&chain, &respelled);
        assert_eq!(HeadRecord::parse(text.as_bytes()), None, "a respelled hash: {respelled}");
    }
}

/// The clock seam holds EVERY reading — `u64::MAX`, the far-future value
/// a test reaching for "the hour has certainly passed" writes first,
/// included — and an unset clock reads the wall clock. A reading the seam
/// accepted and then answered with the wall clock instead would leave a
/// time-bound test passing or failing with the bound never consulted.
#[test]
fn the_clock_seam_holds_every_reading_and_an_unset_clock_reads_the_wall_clock() {
    let clock = Clock::new();
    assert!(
        clock.now_millis().abs_diff(wall_clock_millis()) < 60_000,
        "an unset clock reads the wall clock"
    );
    for fixed in [0, TIME_BOUND_MILLIS, u64::MAX] {
        clock.set_millis(fixed);
        assert_eq!(clock.now_millis(), fixed, "a fixed reading holds, whatever its value");
    }
}

/// RESUME FROM THE FEED, over every case the module doc names. The COUNT
/// is the entries whose testimony is not `"system"` — a session's and a
/// BARE entry's, its testimony lost, alike. The HOUR's origin is the time
/// of the LAST `"system"` entry — the head's publish, or a later attempt's
/// orphaned insert; with none, the FIRST entry above the position carrying
/// a time — a witness no earlier than the head, so the hour fires no
/// sooner than it is owed; with nothing timed, `None`, which the writer
/// reads as open-time. The restart suites drive the first case and the
/// lost sidecar's third; the second — every restart of a board that has
/// written no head, whose whole feed lies above position 0 — is reached by
/// none of them.
#[test]
fn the_resume_counts_every_non_system_entry_and_times_the_last_system_one() {
    let recorded = |key: &str, time: u64| CommitMeta::Recorded {
        op: "insert".to_string(),
        docs: Vec::new(),
        time,
        key: Some(key.to_string()),
        signed: None,
        terms: None,
    };
    let system = |time| recorded(SYSTEM_TESTIMONY, time);
    let session = |time| recorded("bare", time);

    let r = resume_cadence(&[
        (5, system(100)),
        (6, system(110)),
        (7, session(200)),
        (8, system(120)),
        (9, CommitMeta::bare()),
    ]);
    assert_eq!(r.commits_since_head, 2, "the session's commit and the bare entry count");
    assert_eq!(r.last_head_millis, Some(120), "the LAST system entry's time, not the first");

    let r = resume_cadence(&[(5, CommitMeta::bare()), (6, session(300)), (7, session(400))]);
    assert_eq!(r.commits_since_head, 3);
    assert_eq!(r.last_head_millis, Some(300), "no system entry: the EARLIEST timed witness");

    let r = resume_cadence(&[(5, CommitMeta::bare()), (6, CommitMeta::bare())]);
    assert_eq!((r.commits_since_head, r.last_head_millis), (2, None), "nothing timed: open-time");
    let r = resume_cadence(&[]);
    assert_eq!((r.commits_since_head, r.last_head_millis), (0, None), "nothing above the head");
}

/// ROW 40's WORDS at fixed addresses: the draft minted, the address the
/// frontier pins, the cause, and that the head goes on with the draft it
/// minted.
#[test]
fn the_misminted_drafts_line_names_both_addresses_and_that_the_head_goes_on() {
    let minted = Tumbler::new([1u32, 1, 0, 1, 0, 4].into_iter().map(Nat::from))
        .ok()
        .and_then(|t| validate(t).ok())
        .expect("1.1.0.1.0.4 is T4-valid");
    assert_eq!(
        DraftMintedElsewhere { minted: &minted, expected: &staging_draft_address() }.to_string(),
        "head writer: the staging draft minted at 1.1.0.1.0.4, not at 1.1.0.1.0.3 — another \
         writer minted under the system account; the head goes on with the draft it minted"
    );
}

/// ROW 38's TWO LINES at fixed inputs — the refusal with its position, the
/// commit it was met at and the cause, the clearing with the landed
/// position, the attempts refused, the first refused position and how long
/// the refusals stood — and THE CAUSE's RENDERING as the wire renders a
/// rejection: the code as the wire spells it (`durability`, never
/// `Durability`), the detail where one is threaded, the code alone where
/// none is (a `publish` refused `base_superseded`, lowered through M10's
/// table), and the operator's words for a full volume ahead of the OS's
/// text. No rendering carries a variant name or a brace — the `Debug`
/// tells — and the door keeps each under its class word.
#[test]
fn row_38s_lines_render_the_ruled_words_and_the_cause_as_the_wire_renders_a_rejection() {
    use skep_arrangement::{InsertError, PublishError};
    use skep_kernel::TxnError;

    let cause = "durability: the test seam's refusal";
    let refused = |first| HeadRefusedLine { position: 24, act: "insert", cause, first }.to_string();
    assert_eq!(
        refused(false),
        "head writer: the head at position 24 was refused at its insert (durability: the test \
         seam's refusal); no head written this cycle"
    );
    assert_eq!(
        refused(true),
        "head writer: the head at position 24 was refused at its insert (durability: the test \
         seam's refusal); no head written this cycle; no head stands yet, so a claimed board \
         refuses every attested write attestation_invalid:board_unavailable until one lands — \
         tried again at every write's turn",
        "no head standing: the board term's absence and when it is retried"
    );
    assert_eq!(
        RefusalsClearedLine { landed: 31, attempts: 7, since: 24, elapsed_ms: 1_830 }.to_string(),
        "head writer: a head landed at position 31; 7 refused attempts since position 24, over \
         1830 ms, are cleared"
    );
    let mut seam = Rejection::classified(OpKind::Insert, RejectCode::Durability, None);
    seam.detail = Some(SEAM_REFUSAL_DETAIL.to_string());
    assert_eq!(render_cause(&seam), "durability: the test seam's refusal");
    let superseded = lower_txn(OpKind::Publish, TxnError::Rejected(PublishError::BaseSuperseded));
    assert_eq!(render_cause(&superseded), "base_superseded", "no detail: the code alone");
    let full = lower_txn::<InsertError>(
        OpKind::Insert,
        TxnError::Durability(io::Error::new(
            io::ErrorKind::StorageFull,
            "No space left on device (os error 28)",
        )),
    );
    assert_eq!(
        render_cause(&full),
        "durability: the volume is full (No space left on device (os error 28))",
        "a full volume: the operator's words, then the OS's"
    );
    let other = lower_txn::<InsertError>(
        OpKind::Insert,
        TxnError::Durability(io::Error::other("the OS refused entropy")),
    );
    assert_eq!(render_cause(&other), "durability: the OS refused entropy");
    for cause in [&seam, &superseded, &full, &other].map(render_cause) {
        assert!(
            !cause.contains("::") && !cause.contains("Error") && !cause.contains(['{', '}']),
            "a Debug tell in the cause: {cause}"
        );
    }
    let lines = Lines::new();
    let cause = render_cause(&seam);
    let act = op_name(OpKind::Publish);
    lines.say(Class::Failure, HeadRefusedLine { position: 24, act, cause: &cause, first: false });
    let cleared = RefusalsClearedLine { landed: 31, attempts: 1, since: 24, elapsed_ms: 4 };
    lines.say(Class::Landing, cleared);
    assert_eq!(
        lines.said().lock().as_slice(),
        [
            "failure: head writer: the head at position 24 was refused at its publish \
             (durability: the test seam's refusal); no head written this cycle",
            "landing: head writer: a head landed at position 31; 1 refused attempts since \
             position 24, over 4 ms, are cleared",
        ],
        "the class word ahead of each, the commit named as the wire names its op"
    );
}
