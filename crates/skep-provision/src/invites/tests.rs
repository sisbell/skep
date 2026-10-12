//! T9 — THE INVITE FILE: a mint writes one `issued` line and answers the
//! code its claim address carries; `--code` is used verbatim; a lookup
//! before and after the spend answers issued, then spent; a spent or an
//! unknown code is not issued; the file is rewritten whole — a failure
//! between the write and the rename leaves it as it was — and a line of
//! another shape survives. (A failed flow leaving the line issued, a post
//! refused on a spent or unknown code, and the code in no log line are the
//! flow's suite's and the binary's.)

use std::fs;

use super::*;
use crate::scratch::Scratch;

fn state(dir: &Scratch) -> StateDir {
    StateDir::open(&dir.path().join("state")).expect("the state directory")
}

fn alice() -> Name {
    Name::parse(b"alice").expect("a name")
}

/// T9: `invite --address` WRITES ONE `issued` LINE — a fresh code, 128 bits
/// as hex — and its claim address carries the code.
#[test]
fn a_mint_writes_one_issued_line_and_the_claim_address_carries_its_code() {
    let dir = Scratch::new();
    let state = state(&dir);
    let code = mint(&state, "person@example.com", None).expect("minted");
    assert_eq!(code.len(), 32);
    assert!(code_ok(&code));
    let text = fs::read_to_string(state.file(INVITES)).expect("the file");
    assert_eq!(text, format!("{code} person@example.com issued {}\n", today()));
    assert_eq!(claim_address("skep.host", &code), format!("https://skep.host/claim?invite={code}"));
    assert!(state.file(INVITES_LOCK).exists(), "the lock file stands beside it");
}

/// T9: `--code` IS USED VERBATIM — a document's address in a random
/// string's place — and the file then holds it whole.
#[test]
fn a_given_code_is_used_verbatim() {
    let dir = Scratch::new();
    let state = state(&dir);
    assert_eq!(mint(&state, "person@example.com", Some("1.1.0.1.0.3")).expect("minted"), "1.1.0.1.0.3");
    let invite = lookup(&state, "1.1.0.1.0.3").expect("read").expect("held");
    assert_eq!(invite.address, "person@example.com");
    assert!(invite.issued());
    assert!(lookup(&state, "1.1.0.1.0").expect("read").is_none(), "compared whole, never by prefix");
}

/// The mint's refusals: an address out of the rule, a code out of the
/// alphabet, a code the file already holds — the file untouched.
#[test]
fn a_mint_refuses_a_bad_address_a_bad_code_and_a_duplicate() {
    let dir = Scratch::new();
    let state = state(&dir);
    assert!(matches!(mint(&state, "not an address", None), Err(MintRefused::Address)));
    let long = "x".repeat(MAX_CODE_BYTES + 1);
    for bad in ["has space", "a&b", "a/b", "", long.as_str()] {
        assert!(matches!(mint(&state, "person@example.com", Some(bad)), Err(MintRefused::Code)), "{bad:?}");
    }
    mint(&state, "person@example.com", Some("abc")).expect("minted");
    assert!(matches!(mint(&state, "other@example.com", Some("abc")), Err(MintRefused::Duplicate)));
    assert_eq!(read_all(&state).expect("read").len(), 1);
}

/// T9: A LOOKUP BEFORE AND AFTER THE SPEND answers issued, then spent by
/// the board; a second spend and an unknown code's find nothing issued.
#[test]
fn a_code_answers_issued_then_spent() {
    let dir = Scratch::new();
    let state = state(&dir);
    let code = mint(&state, "person@example.com", None).expect("minted");
    let other = mint(&state, "other@example.com", None).expect("minted");
    assert!(lookup(&state, &code).expect("read").expect("held").issued());
    assert!(spend(&state, &code, &alice()).expect("spent"));
    let spent = lookup(&state, &code).expect("read").expect("held");
    assert_eq!(spent.state, InviteState::Spent { name: "alice".into(), date: today() });
    assert!(!spent.issued());
    assert!(!spend(&state, &code, &alice()).expect("read"), "spent once");
    assert!(!spend(&state, "unknown", &alice()).expect("read"), "an unknown code");
    assert!(lookup(&state, "unknown").expect("read").is_none());
    assert!(lookup(&state, &other).expect("read").expect("held").issued(), "the other invite untouched");
    let text = fs::read_to_string(state.file(INVITES)).expect("the file");
    assert_eq!(text.lines().next(), Some(format!("{code} person@example.com spent alice {}", today()).as_str()));
}

/// T9: THE FILE IS REWRITTEN WHOLE — a failure between the write and the
/// rename leaves the file exactly as it was, no temp file, the code still
/// issued.
#[test]
fn a_failure_before_the_rename_leaves_the_file_as_it_was() {
    let dir = Scratch::new();
    let state = state(&dir);
    let code = mint(&state, "person@example.com", None).expect("minted");
    let before = fs::read(state.file(INVITES)).expect("the file");
    let failed = spend_with(&state, &code, &alice(), &|| Err(io::Error::other("a failure between the write and the rename")));
    assert!(failed.is_err());
    assert_eq!(fs::read(state.file(INVITES)).expect("the file"), before);
    assert!(!crate::signups::temp_of(&state.file(INVITES)).exists());
    assert!(lookup(&state, &code).expect("read").expect("held").issued());
}

/// A line of another shape — a hand edit's — is passed over by the lookup
/// and kept as it stands by every rewrite.
#[test]
fn a_hand_edited_line_survives_a_rewrite() {
    let dir = Scratch::new();
    let state = state(&dir);
    fs::write(state.file(INVITES), "# the owner's note\n").expect("a hand edit");
    let code = mint(&state, "person@example.com", None).expect("minted");
    spend(&state, &code, &alice()).expect("spent");
    let text = fs::read_to_string(state.file(INVITES)).expect("the file");
    assert!(text.starts_with("# the owner's note\n"), "{text}");
    assert_eq!(read_all(&state).expect("read").len(), 1);
}

/// An invite's `Debug` carries neither its code nor its address.
#[test]
fn an_invites_debug_carries_neither_code_nor_address() {
    let invite = Invite { code: "secretcode".into(), address: "person@example.com".into(), state: InviteState::Issued { date: "2026-10-12".into() } };
    let shown = format!("{invite:?}");
    assert!(!shown.contains("secretcode") && !shown.contains("person@"), "{shown}");
}
