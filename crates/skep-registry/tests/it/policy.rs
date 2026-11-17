//! The door's policy document at this parser (`tests/vectors/policy.json`):
//! every vector meets the answer the set pins — a policy, with the hand its
//! reader answers, or the refusal's cause — and the document's rules a hand
//! states once: each term parsed as the value it spells, `vouches` only
//! with n-vouches, the member order, no `sig`, the approval's hand as the
//! reader honors it, and a malformed document refused whole. The set's
//! readers are the registration suite's.

use skep_address::{validate, Address, Nat, Tumbler};
use skep_registry::{
    encode_policy, parse_policy, Admission, AdmissionPolicy, ApprovalHand, Digits, Member,
    ParseRefusal, MAX_REGISTRY_RECORD_BYTES, POLICY_TYPE,
};

use crate::registration::{vector_bytes, vector_file};

fn address(s: &str) -> Address {
    let comps = s.split('.').map(|c| c.parse::<Nat>().expect("a component"));
    validate(Tumbler::new(comps).expect("nonempty")).expect("T4-valid")
}

fn digits(s: &str) -> Digits {
    Digits::new(s).expect("decimal digits")
}

/// The registry's own door, as REG-1.86 shows it: open, approved by its
/// unattended console.
fn the_registrys_door() -> AdmissionPolicy {
    AdmissionPolicy {
        admission: Admission::Open,
        approval: "auto".into(),
        intake: vec![address("1.0.1.4")],
        intake_rate: digits("60"),
        intake_window: digits("3600"),
        intake_per_device: digits("3"),
        collection_interval: digits("1209600"),
        stale_request_interval: digits("2592000"),
        transcription_interval: digits("3600"),
        contact: "registrar@registry.example".into(),
        sponsors: None,
        grounds: vec!["No machine-rate sponsoring.".into(), "One registration a board.".into()],
    }
}

/// The hand a vector names for its reader: `officer`, `unattended`, or
/// null — no approval.
fn hand_named(vector: &serde_json::Value) -> Option<ApprovalHand> {
    match vector["approval_hand"].as_str() {
        Some("officer") => Some(ApprovalHand::Officer),
        Some("unattended") => Some(ApprovalHand::Unattended),
        Some(other) => panic!("{}: an unknown hand {other}", vector["name"]),
        None => None,
    }
}

/// REG-1.86, REG-4.131 — EVERY VECTOR, under its own name: an admitted
/// document is its own canonical encoding and answers the hand the set
/// pins; a refused one names its cause, and no part of it is read — a
/// malformed document is refused whole.
#[test]
fn the_vector_set_meets_one_answer_at_this_parser() {
    let set = vector_file("policy.json");
    let vectors = set["vectors"].as_array().expect("vectors");
    let (mut admitted, mut refused) = (0, 0);
    let mut names = std::collections::BTreeSet::new();
    for vector in vectors {
        let name = vector["name"].as_str().expect("a name");
        assert!(names.insert(name), "{name}: the set names two vectors so");
        let bytes = vector_bytes(vector);
        let answer = vector["parse"].as_str().expect("the parse's answer");
        let parsed = std::panic::catch_unwind(|| parse_policy(&bytes))
            .unwrap_or_else(|_| panic!("{name}: the parse panicked"));
        match (answer, parsed) {
            ("ok", Ok(policy)) => {
                assert!(encode_policy(&policy).as_bytes() == bytes, "{name}: its own encoding");
                assert_eq!(policy.approval_hand(), hand_named(vector), "{name}: the hand");
                admitted += 1;
            }
            ("ok", Err(refusal)) => panic!("{name}: the set admits it, the parser refuses {refusal}"),
            (_, Err(refusal)) => {
                assert_eq!(refusal.token(), answer, "{name}");
                refused += 1;
            }
            (_, Ok(policy)) => {
                panic!("{name}: the set refuses it ({answer}), the parser admits {policy:?}")
            }
        }
    }
    assert!(admitted >= 12 && refused >= 40, "{admitted} admitted, {refused} refused");
    for required in [
        "open_auto",
        "open_officer",
        "invitation_only_auto_fails_closed",
        "n_vouches_officer",
        "n_vouches_auto_fails_closed",
        "a_third_approval_value_opens_no_approval",
        "members_in_another_order",
        "with_a_sig_member",
        "vouches_with_open",
        "vouches_with_invitation_only",
        "n_vouches_without_vouches",
        "with_sponsors_at_depth",
        "spaced",
        "empty",
        "at_the_cap",
        "one_byte_past_the_cap",
        "past_the_cap_ahead_of_every_other_stage",
    ] {
        assert!(vectors.iter().any(|v| v["name"] == required), "the set names {required}");
    }
}

/// REG-1.86's policy row, shown once — the registry's own door in its one
/// canonical form: `type` first, then the members in the document's order,
/// each term parsed as the value it spells; and the same spaced is refused.
#[test]
fn the_spec_example_has_one_canonical_form() {
    let text = concat!(
        r#"{"type":"admission-policy","admission":"open","approval":"auto","intake":["1.0.1.4"],"#,
        r#""intake_rate":"60","intake_window":"3600","intake_per_device":"3","#,
        r#""collection_interval":"1209600","stale_request_interval":"2592000","#,
        r#""transcription_interval":"3600","contact":"registrar@registry.example","#,
        r#""grounds":["No machine-rate sponsoring.","One registration a board."]}"#
    );
    let policy = the_registrys_door();
    assert_eq!(POLICY_TYPE, "admission-policy");
    assert_eq!(encode_policy(&policy), text);
    assert_eq!(parse_policy(text.as_bytes()), Ok(policy.clone()));
    assert_eq!(policy.intake, [address("1.0.1.4")]);
    assert_eq!(policy.collection_interval.value(), Some(1_209_600));
    assert_eq!(policy.grounds.len(), 2, "a clause is cited by its position in this list");
    let spaced = text.replace("\":\"", "\": \"");
    assert_eq!(parse_policy(spaced.as_bytes()), Err(ParseRefusal::NotCanonical));
    // A document, not a deposit: no `sig` member.
    let signed = format!("{},\"sig\":\"c0ffee\"}}", &text[..text.len() - 1]);
    assert_eq!(parse_policy(signed.as_bytes()), Err(ParseRefusal::UnknownMember));
}

/// THE CAP IS 16 KiB, AHEAD OF EVERY OTHER STAGE: a policy document of
/// exactly 16,384 bytes parses, and one byte more is refused `past_cap` —
/// the registry records' own cap, held here as every body but a request is
/// held to it. The refusal stands ahead of the text, the value, the number
/// scan, the `type`, the member set and the canonical compare: bytes past
/// the cap that would fault at each of those answer the cap, where the same
/// fault inside the cap answers its own cause. And the empty document, which
/// a door's policy document holds between its creation and its first words,
/// is no policy.
#[test]
fn a_document_of_sixteen_kibibytes_parses_and_one_byte_more_is_refused_at_the_cap() {
    assert_eq!(MAX_REGISTRY_RECORD_BYTES, 16_384);
    let filled = |len: usize| {
        let mut policy = the_registrys_door();
        policy.contact = String::new();
        let room = len - encode_policy(&policy).len();
        policy.contact = "x".repeat(room);
        policy
    };
    let at_cap = filled(MAX_REGISTRY_RECORD_BYTES);
    let text = encode_policy(&at_cap);
    assert_eq!(text.len(), 16_384);
    assert_eq!(parse_policy(text.as_bytes()), Ok(at_cap), "a document at the cap parses");
    let one_past = encode_policy(&filled(MAX_REGISTRY_RECORD_BYTES + 1));
    assert_eq!(one_past.len(), 16_385, "the encoder measures nothing");
    assert_eq!(parse_policy(one_past.as_bytes()), Err(ParseRefusal::PastCap), "one byte past it");

    // Each later stage's fault, inside the cap and past it.
    let pad = |body: &str, len: usize| -> Vec<u8> {
        let mut bytes = body.as_bytes().to_vec();
        bytes.resize(len, b' ');
        bytes
    };
    let whole = encode_policy(&the_registrys_door());
    let staged: [(Vec<u8>, ParseRefusal); 6] = [
        (vec![0xff], ParseRefusal::NotUtf8),
        (b"{".to_vec(), ParseRefusal::NotJson),
        (b"[]".to_vec(), ParseRefusal::NotAnObject),
        (br#"{"type":"admission-policy","admission":7}"#.to_vec(), ParseRefusal::Number),
        (br#"{"type":"policy"}"#.to_vec(), ParseRefusal::WrongType),
        (whole.replace("\":\"", "\": \"").into_bytes(), ParseRefusal::NotCanonical),
    ];
    for (bytes, cause) in staged {
        assert_eq!(parse_policy(&bytes), Err(cause.clone()), "inside the cap: {cause}");
        let mut past = bytes.clone();
        past.resize(MAX_REGISTRY_RECORD_BYTES + 1, if cause == ParseRefusal::NotUtf8 { 0xff } else { b' ' });
        assert_eq!(parse_policy(&past), Err(ParseRefusal::PastCap), "past the cap, ahead of {cause}");
    }
    assert_eq!(parse_policy(&pad("", MAX_REGISTRY_RECORD_BYTES)), Err(ParseRefusal::NotJson), "blank bytes at the cap are read, and are no JSON");
    assert_eq!(parse_policy(b""), Err(ParseRefusal::NotJson), "an empty document is no policy");
}

/// REG-4.185 — `vouches` IS A MEMBER ONLY WITH `"n-vouches"`, and always
/// with it: the N rides the mode, between `admission` and `approval`;
/// beside either other mode the member is one the document does not name,
/// and an n-vouches document without it lacks a required member.
#[test]
fn vouches_is_admitted_only_with_n_vouches() {
    let document = |admission: &str, vouches: Option<&str>| {
        let vouches = vouches.map(|n| format!(r#""vouches":"{n}","#)).unwrap_or_default();
        format!(
            r#"{{"type":"admission-policy","admission":"{admission}",{vouches}"approval":"officer","intake":[],"intake_rate":"1","intake_window":"1","intake_per_device":"1","collection_interval":"1","stale_request_interval":"1","transcription_interval":"1","contact":"","grounds":[]}}"#
        )
    };
    let parse = |text: String| parse_policy(text.as_bytes());
    let n_vouches = parse(document("n-vouches", Some("3"))).expect("n-vouches with its N");
    assert_eq!(n_vouches.admission, Admission::NVouches(digits("3")));
    assert_eq!(n_vouches.admission.as_str(), "n-vouches");
    assert_eq!(
        parse(document("n-vouches", None)),
        Err(ParseRefusal::MissingMember(Member::Vouches))
    );
    assert_eq!(parse(document("n-vouches", Some("x"))), Err(ParseRefusal::NotDigits(Member::Vouches)));
    for mode in ["open", "invitation-only"] {
        assert!(parse(document(mode, None)).is_ok(), "{mode} without vouches");
        assert_eq!(
            parse(document(mode, Some("3"))),
            Err(ParseRefusal::UnknownMember),
            "{mode} with vouches"
        );
    }
    assert_eq!(
        parse(document("closed", None)),
        Err(ParseRefusal::UnknownValue(Member::Admission))
    );
}

/// REG-4.108 — THE APPROVAL's HAND, AS ITS READER HONORS IT: the parser
/// admits `"officer"` and `"auto"` with any admission; a document naming
/// `"auto"` under `"open"` answers the unattended hand, under any other
/// mode it fails closed to the officer's; `"officer"` is the officer's
/// under every mode; and a value the parser does not know opens no
/// approval — the document parses, and its reader finds no hand.
#[test]
fn the_approval_hand_is_auto_only_where_admission_is_open() {
    let modes = [Admission::InvitationOnly, Admission::NVouches(digits("2")), Admission::Open];
    for admission in modes {
        let open = admission == Admission::Open;
        for (approval, hand) in [
            ("officer", Some(ApprovalHand::Officer)),
            ("auto", Some(if open { ApprovalHand::Unattended } else { ApprovalHand::Officer })),
            ("steward", None),
            ("Auto", None),
            ("", None),
            ("auto ", None),
        ] {
            let policy = AdmissionPolicy {
                admission: admission.clone(),
                approval: approval.into(),
                ..the_registrys_door()
            };
            assert_eq!(policy.approval_hand(), hand, "{approval:?} under {admission:?}");
            let read = parse_policy(encode_policy(&policy).as_bytes())
                .unwrap_or_else(|r| panic!("{approval:?} under {admission:?}: refused {r}"));
            assert_eq!(read.approval_hand(), hand, "the hand read off the parsed document");
        }
    }
}

/// THE ENCODER's LAW, and `sponsors` AT ITS POSITION: every policy a caller
/// builds — any mode, any strings, any intake homes and grounds, with a
/// `sponsors` string or none — is the document its encoding spells; a root
/// document carries no `sponsors` and is never refused for lacking it; and
/// each required member's absence is that member's own refusal.
#[test]
fn every_policy_a_caller_builds_is_a_document() {
    let root = the_registrys_door();
    assert_eq!(root.sponsors, None);
    assert!(!encode_policy(&root).contains("sponsors"), "a root document carries none");
    assert_eq!(parse_policy(encode_policy(&root).as_bytes()), Ok(root.clone()));
    let at_depth = AdmissionPolicy {
        admission: Admission::NVouches(digits("002")),
        approval: "officer".into(),
        intake: vec![],
        contact: "a \"quoted\" line\n\u{1}é€".into(),
        sponsors: Some("members and subnodes".into()),
        grounds: vec![String::new(), "§ 1\t\\".into()],
        ..root.clone()
    };
    let text = encode_policy(&at_depth);
    let sponsors_at = text.find(r#""sponsors":"#).expect("sponsors is written");
    assert!(
        text.find(r#""contact":"#).expect("contact") < sponsors_at
            && sponsors_at < text.find(r#""grounds":"#).expect("grounds"),
        "sponsors stands between contact and grounds"
    );
    assert_eq!(parse_policy(text.as_bytes()), Ok(at_depth));
    let whole = encode_policy(&root);
    for member in [
        Member::Admission,
        Member::Approval,
        Member::Intake,
        Member::IntakeRate,
        Member::IntakeWindow,
        Member::IntakePerDevice,
        Member::CollectionInterval,
        Member::StaleRequestInterval,
        Member::TranscriptionInterval,
        Member::Contact,
        Member::Grounds,
    ] {
        let value: serde_json::Value = serde_json::from_str(&whole).expect("JSON");
        let name = ParseRefusal::MissingMember(member).token();
        let name = name.strip_prefix("missing_member:").expect("a member's name");
        let without: Vec<String> = value
            .as_object()
            .expect("an object")
            .iter()
            .filter(|(k, _)| *k != name)
            .map(|(k, v)| format!("{}:{v}", serde_json::Value::from(k.as_str())))
            .collect();
        // serde_json's map is sorted, so the members are re-ordered: the
        // missing member is named ahead of the canonical compare.
        let text = format!("{{{}}}", without.join(","));
        assert_eq!(
            parse_policy(text.as_bytes()),
            Err(ParseRefusal::MissingMember(member)),
            "without {name}"
        );
    }
}
