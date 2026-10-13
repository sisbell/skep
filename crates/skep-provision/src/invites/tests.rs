//! T9 — THE INVITE FILE: a mint writes one `issued` line and answers its
//! code; `--code` is used verbatim; the code's alphabet, at every byte, and
//! its value admitting exactly the codes the alphabet does; a duplicate
//! refused, and a file that cannot be reached refused as its own failure,
//! each an error saying which; a lookup before and after the spend answers
//! issued, then spent; a spent or an unknown code is not issued; the file is
//! rewritten whole — a failure between the write and the rename leaves it as
//! it was — and a line of another shape survives; and changes made at once,
//! mints beside spends, lose none of each other under the lock file. (The
//! invite link the code rides is the pages' suite's; a failed flow leaving
//! the line issued, a post refused on a spent or unknown code, and the code
//! in no log line are the flow's suite's and the binary's.)

use std::fs;

use super::*;
use crate::scratch::Scratch;

fn state_dir(dir: &Scratch) -> StateDir {
    StateDir::open(&dir.path().join("state")).expect("the state directory")
}

fn alice() -> Name {
    Name::parse(b"alice").expect("a name")
}

fn address(text: &str) -> MailAddress {
    MailAddress::parse(text).expect("an address")
}

fn invite_code(text: &str) -> InviteCode {
    InviteCode::parse(text).expect("a code")
}

/// T9: `invite --address` WRITES ONE `issued` LINE — a fresh code, 128 bits
/// as hex, in the alphabet — and answers the code.
#[test]
fn a_mint_writes_one_issued_line() {
    let dir = Scratch::new();
    let state_dir = state_dir(&dir);
    let before = today();
    let code = mint(&state_dir, &address("person@example.com"), None).expect("minted");
    let after = today();
    assert_eq!(code.as_str().len(), 32);
    assert!(code_ok(code.as_str()));
    let text = fs::read_to_string(state_dir.file(INVITES)).expect("the file");
    assert!([&before, &after].into_iter().any(|day| text == format!("{} person@example.com issued {day}\n", code.as_str())), "{text:?}, not dated {before} or {after}");
    assert!(state_dir.file(INVITES_LOCK).exists(), "the lock file stands beside it");
}

/// T9: `--code` IS USED VERBATIM — a document's address in a random
/// string's place — and the file then holds it whole.
#[test]
fn a_given_code_is_used_verbatim() {
    let dir = Scratch::new();
    let state_dir = state_dir(&dir);
    assert_eq!(mint(&state_dir, &address("person@example.com"), Some(invite_code("1.1.0.1.0.3"))).expect("minted").as_str(), "1.1.0.1.0.3");
    let invite = lookup(&state_dir, &invite_code("1.1.0.1.0.3")).expect("read").expect("held");
    assert_eq!(invite.address, "person@example.com");
    assert!(invite.issued());
    assert!(lookup(&state_dir, &invite_code("1.1.0.1.0")).expect("read").is_none(), "compared whole, never by prefix");
}

/// THE CODE's ALPHABET: a space, `&`, `/`, the empty code and one byte past
/// [`MAX_CODE_BYTES`] are outside it; a document's address, every
/// unreserved character and a code at the bound are inside — and
/// [`InviteCode::parse`], the value's one door, admits exactly the codes the
/// alphabet does, keeping each as given, its `Debug` showing none of it.
#[test]
fn a_code_is_1_to_128_unreserved_characters_and_parse_admits_just_those() {
    let long = "x".repeat(MAX_CODE_BYTES + 1);
    for bad in ["has space", "a&b", "a/b", "", long.as_str()] {
        assert!(!code_ok(bad), "{bad:?}");
        assert!(InviteCode::parse(bad).is_none(), "{bad:?}");
    }
    let longest = "x".repeat(MAX_CODE_BYTES);
    for good in ["abc", "1.1.0.1.0.3", "A-z_0.9~", longest.as_str()] {
        assert!(code_ok(good), "{good:?}");
        assert_eq!(InviteCode::parse(good).as_ref().map(InviteCode::as_str), Some(good));
    }
    assert_eq!(format!("{:?}", invite_code("secretcode")), "InviteCode(…)");
}

/// THE CODE's ALPHABET AT EVERY BYTE: `a`, one character, `a` is a code iff
/// the character is a letter, a digit, `-`, `.`, `_` or `~` — the URL's
/// unreserved characters, each riding the invite link as it is — and
/// refused for every other: `+`, which the link would carry as a space, `%`,
/// which opens an escape, `#`, which ends the query, and `&`, `=`, a space,
/// a control character and every character past ASCII.
#[test]
fn every_character_but_the_unreserved_is_out_of_the_alphabet() {
    for b in 0..=255u8 {
        let code = format!("a{}a", char::from(b));
        let unreserved = b.is_ascii_alphanumeric() || b"-._~".contains(&b);
        assert_eq!(code_ok(&code), unreserved, "{b:#04x}");
        assert_eq!(InviteCode::parse(&code).is_some(), unreserved, "{b:#04x}");
    }
}

/// The mint's refusal: a code the file already holds mints nothing, and the
/// file keeps its one invite.
#[test]
fn a_mint_refuses_a_duplicate() {
    let dir = Scratch::new();
    let state_dir = state_dir(&dir);
    mint(&state_dir, &address("person@example.com"), Some(invite_code("abc"))).expect("minted");
    let refused = mint(&state_dir, &address("other@example.com"), Some(invite_code("abc"))).expect_err("a duplicate");
    assert!(matches!(refused, MintRefused::Duplicate), "{refused:?}");
    let said: &dyn std::error::Error = &refused;
    assert_eq!(said.to_string(), "the invite file already holds that code");
    assert_eq!(read_invites(&state_dir).expect("read").len(), 1);
}

/// A FILE THAT CANNOT BE REACHED refuses the mint as the file's own failure
/// — the lock, the read or the rewrite reaching the refusal through `?` —
/// never as a duplicate.
#[test]
fn a_mint_over_a_directory_gone_is_the_files_failure() {
    let dir = Scratch::new();
    let state_dir = state_dir(&dir);
    fs::remove_dir(dir.path().join("state")).expect("the state directory removed");
    let refused = mint(&state_dir, &address("person@example.com"), None).expect_err("no directory to write in");
    assert!(matches!(refused, MintRefused::Io(_)), "{refused:?}");
    assert!(refused.to_string().starts_with("the invite file: "), "{refused}");
}

/// T9: A LOOKUP BEFORE AND AFTER THE SPEND answers issued, then spent by
/// the board; a second spend and an unknown code's find nothing issued.
#[test]
fn a_code_answers_issued_then_spent() {
    let dir = Scratch::new();
    let state_dir = state_dir(&dir);
    let code = mint(&state_dir, &address("person@example.com"), None).expect("minted");
    let other = mint(&state_dir, &address("other@example.com"), None).expect("minted");
    assert!(lookup(&state_dir, &code).expect("read").expect("held").issued());
    let before = today();
    assert!(spend(&state_dir, &code, &alice()).expect("spent"));
    let after = today();
    let spent = lookup(&state_dir, &code).expect("read").expect("held");
    assert!(matches!(&spent.state, InviteState::Spent { name, date } if name == "alice" && (*date == before || *date == after)), "{:?}, not dated {before} or {after}", spent.state);
    assert!(!spent.issued());
    assert!(!spend(&state_dir, &code, &alice()).expect("read"), "spent once");
    assert!(!spend(&state_dir, &invite_code("unknown"), &alice()).expect("read"), "an unknown code");
    assert!(lookup(&state_dir, &invite_code("unknown")).expect("read").is_none());
    assert!(lookup(&state_dir, &other).expect("read").expect("held").issued(), "the other invite untouched");
    let text = fs::read_to_string(state_dir.file(INVITES)).expect("the file");
    let first = text.lines().next().expect("a line");
    assert!([&before, &after].into_iter().any(|day| first == format!("{} person@example.com spent alice {day}", code.as_str())), "{first:?}, not dated {before} or {after}");
}

/// T9: THE FILE IS REWRITTEN WHOLE — a failure between the write and the
/// rename leaves the file exactly as it was, no temp file, the code still
/// issued.
#[test]
fn a_failure_before_the_rename_leaves_the_file_as_it_was() {
    let dir = Scratch::new();
    let state_dir = state_dir(&dir);
    let code = mint(&state_dir, &address("person@example.com"), None).expect("minted");
    let before = fs::read(state_dir.file(INVITES)).expect("the file");
    let failed = spend_with(&state_dir, &code, &alice(), &|| Err(io::Error::other("a failure between the write and the rename")));
    assert!(failed.is_err());
    assert_eq!(fs::read(state_dir.file(INVITES)).expect("the file"), before);
    assert!(!crate::whole::temp_of(&state_dir.file(INVITES)).exists());
    assert!(lookup(&state_dir, &code).expect("read").expect("held").issued());
}

/// A line of another shape — a hand edit's — is passed over by the lookup
/// and kept as it stands by every rewrite.
#[test]
fn a_hand_edited_line_survives_a_rewrite() {
    let dir = Scratch::new();
    let state_dir = state_dir(&dir);
    fs::write(state_dir.file(INVITES), "# the owner's note\n").expect("a hand edit");
    let code = mint(&state_dir, &address("person@example.com"), None).expect("minted");
    spend(&state_dir, &code, &alice()).expect("spent");
    let text = fs::read_to_string(state_dir.file(INVITES)).expect("the file");
    assert!(text.starts_with("# the owner's note\n"), "{text}");
    assert_eq!(read_invites(&state_dir).expect("read").len(), 1);
}

/// THE LOCK FILE KEEPS EVERY CHANGE: mints and spends made at once — the
/// owner's `invite` beside the service's spend, here threads, each its own
/// open of the lock file as each process makes one — every one lands and
/// none is lost to another's rewrite: every code minted held issued, every
/// spend written.
#[test]
fn changes_made_at_once_lose_none_of_each_other() {
    let dir = Scratch::new();
    let state_dir = state_dir(&dir);
    let spent: Vec<InviteCode> = (0..4).map(|_| mint(&state_dir, &address("person@example.com"), None).expect("minted")).collect();
    let minted: Vec<InviteCode> = std::thread::scope(|s| {
        let minters: Vec<_> = (0..4).map(|_| s.spawn(|| (0..4).map(|_| mint(&state_dir, &address("other@example.com"), None).expect("minted")).collect::<Vec<_>>())).collect();
        for code in &spent {
            let state_dir = &state_dir;
            s.spawn(move || assert!(spend(state_dir, code, &alice()).expect("spent"), "a spend found its code no longer issued"));
        }
        minters.into_iter().flat_map(|minter| minter.join().expect("a minter")).collect()
    });
    assert_eq!(read_invites(&state_dir).expect("read").len(), 4 + 16, "an invite lost to another's rewrite");
    for code in &minted {
        assert!(lookup(&state_dir, code).expect("read").expect("held").issued(), "a mint lost to another's rewrite");
    }
    for code in &spent {
        assert!(!lookup(&state_dir, code).expect("read").expect("held").issued(), "a spend lost to another's rewrite");
    }
}

/// An invite's `Debug` carries neither its code nor its address.
#[test]
fn an_invites_debug_carries_neither_code_nor_address() {
    let invite = Invite { code: "secretcode".into(), address: "person@example.com".into(), state: InviteState::Issued { date: "2026-10-12".into() } };
    let shown = format!("{invite:?}");
    assert!(!shown.contains("secretcode") && !shown.contains("person@"), "{shown}");
}
