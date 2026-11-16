//! The paste door (`client.md` §2.2 `enroll`; AUTH-5.32).
//!
//! It takes an enrollment record carried in from the device that generated
//! it — its bytes read as UTF-8 text, `parse_enroll` and nothing else
//! (AUTH-2.130; a mangled paste caught at the door, AUTH-5.57 step 3's
//! echo-back), an anchor-flagged entry refused where the door enrolls
//! device keys alone (AUTH-3.20/3.22; AUTH-1.26), and the comparison beat,
//! a consent moment (AUTH-4.59; R48). `enroll`, `rotate --payload` and
//! `handoff`'s second invocation take a paste through it, and so does
//! `hire`, whose paste is an agent's working key (AUTH-5.58 steps 1 and 4).
//!
//! **The hire's own tests.** At the hire the paste is not committed: its one
//! entry is re-emitted into a record the owner composes (AUTH RES-211). So
//! the door tests what the comparison alone does not — an anchor-flagged
//! entry refused for the hire's own reason (an agent's anchors are the
//! owner's pair, never fetched: `refuse_anchor_flagged_at_hire`), exactly
//! one device-flagged entry (`the_one_device_entry`: the consent types one
//! fingerprint's group, and a second would latch at the genesis unseen), and a label that
//! is not empty (`labelled`: the byline a flag on another machine chose is
//! committed permanently by the owner's hand) — and its comparison beat
//! says the hire's own consequence (`compare_hire_payload`), where the
//! device hop's "co-holder … `skep retire`" would be false.

use skep_identity::{parse_enroll, Enrollment, Fingerprint};

use super::say;
use crate::halt::Halt;
use crate::person::{Confirmation, Consent, Person};
use crate::sheet::{group_hex, render_inert};

/// Returns the pasted bytes as the record's text.
///
/// The text is UTF-8, every trailing CR and LF stripped (the canonical
/// encoding has no `\n`, RES-98).
///
/// # Errors
///
/// Bytes that are not UTF-8 halt.
pub fn payload_text(payload: &[u8]) -> Result<String, Halt> {
    let text = std::str::from_utf8(payload).map_err(|_| Halt::face("the payload is not UTF-8", "a canonical record is UTF-8 text (AUTH-2.130)", "re-take the payload from the device that generated it; never edit it here"))?;
    Ok(text.trim_end_matches(['\n', '\r']).to_string())
}

/// Runs `parse_enroll` on the paste.
///
/// # Errors
///
/// A paste `parse_enroll` refuses halts, the malformed face naming where.
pub fn parse_payload(text: &str) -> Result<Vec<Enrollment>, Halt> {
    parse_enroll(text.as_bytes()).map_err(|e| {
        Halt::face(
            "the payload is not a canonical enrollment record",
            format!("`parse_enroll` refused it: {e} — malformed_payload (AUTH-2.130 admits the canonical encoding and nothing else)"),
            "re-take the payload from the device that generated it (`skep keygen --payload`); never edit it here (AUTH-5.57 step 3's echo-back)",
        )
    })
}

/// Refuses an anchor-flagged entry at a paste that enrolls device keys.
///
/// It is the device doors' test — `enroll` and `rotate --payload`, each of
/// which writes a post-genesis enrollment — and its face names their walks.
/// The hire's test is [`refuse_anchor_flagged_at_hire`].
///
/// # Errors
///
/// An anchor-flagged entry halts, naming the walks that exist — never
/// stripped and re-flagged (AUTH-1.26 fixes the flag for the fingerprint's
/// life).
pub fn refuse_anchor_flagged(entries: &[Enrollment], door: &str) -> Result<(), Halt> {
    if let Some(e) = entries.iter().find(|e| e.anchor) {
        return Err(Halt::face(
            format!("the payload carries an ANCHOR-flagged entry ({}) and `{door}` enrolls device keys alone", Fingerprint::of(&e.key)),
            "a post-genesis anchor enrollment needs a session an anchor established (AUTH-3.20/3.22) and is a walk of its own; the flag is fixed for the fingerprint's life (AUTH-1.26), so it is never stripped here",
            "the walks that exist: `skep recover --anchor-lost` where a paper was lost (the loss arm), and the anchor REPLACEMENT rotation, LATER with the attendant campaign; a device is added with `skep keygen --payload`'s one device-flagged key",
        ));
    }
    Ok(())
}

/// Refuses an anchor-flagged entry at the hire (AUTH-5.58 step 4).
///
/// The flag is tested and not merely carried: a genesis is exempt from the
/// anchor gate (AUTH-3.21), so an anchor-flagged entry in the agent side's
/// bytes would ride into the genesis and latch there (AUTH-2.100), the
/// agent's own host then holding an anchor of its own account — the
/// placement AUTH-5.62 forbids — which no act from below retires.
///
/// # Errors
///
/// An anchor-flagged entry halts, never stripped and re-flagged
/// (AUTH-1.26).
pub fn refuse_anchor_flagged_at_hire(entries: &[Enrollment]) -> Result<(), Halt> {
    if let Some(e) = entries.iter().find(|e| e.anchor) {
        return Err(Halt::face(
            format!("the payload carries an ANCHOR-flagged entry ({}) and a hire takes the agent's one working key alone", Fingerprint::of(&e.key)),
            "an agent account's anchors are the OWNER'S OWN custody pair, made by this command and never fetched (AUTH-5.58 step 4; \
             AUTH-5.62: never on the agent's host) — committed, an anchor-flagged entry from the agent's side would latch in the \
             genesis (AUTH-2.100), which no anchor gate judges (AUTH-3.21), and the agent's host would hold an anchor of its own \
             account for good; the flag is fixed for the fingerprint's life (AUTH-1.26), so it is never stripped here",
            "re-take the record from the agent's host: `skep keygen --payload` there prints its one device-flagged working key",
        ));
    }
    Ok(())
}

/// Returns the payload's one device-flagged entry (AUTH RES-211's count).
///
/// AUTH-5.58 step 4: the payload carries exactly one device-flagged entry,
/// refused otherwise — with [`refuse_anchor_flagged_at_hire`] ahead of it,
/// one entry and no other. No other test of the step counts: `keys` is an
/// array of one entry or more (AUTH-2.128), so a second device-flagged
/// entry passes the flag, the label and the fingerprints alike and would
/// latch at the genesis (AUTH-2.100), a second working key in the agent's
/// set from birth, while the consent types one fingerprint's group. The
/// count binds the payload and the genesis and never the set's later life:
/// a second working key the agent enrolls for itself afterwards is its own
/// act.
///
/// # Errors
///
/// A payload whose device-flagged entries are not exactly one halts, ahead
/// of the consent.
pub fn the_one_device_entry(entries: &[Enrollment]) -> Result<&Enrollment, Halt> {
    let mut device = entries.iter().filter(|e| !e.anchor);
    match (device.next(), device.next()) {
        (Some(one), None) => Ok(one),
        _ => {
            let count = entries.iter().filter(|e| !e.anchor).count();
            let listed: Vec<String> = entries.iter().map(|e| format!("{} anchor={}", Fingerprint::of(&e.key), e.anchor)).collect();
            Err(Halt::face(
                format!("the payload carries {count} device-flagged entries, and a hire takes EXACTLY ONE: the agent's one working key"),
                format!(
                    "AUTH-5.58 step 4 (AUTH RES-211): every entry of the record committed latches in the genesis (AUTH-2.100), so a \
                     second would be a second working key in this agent's set from its birth, which the comparison never showed you \
                     — the one group you type is one fingerprint's; the entries:\n  {}",
                    listed.join("\n  ")
                ),
                "re-take the record from the agent's host that generated it (`skep keygen --payload` prints one entry); never edit \
                 it here — a second working key, where the agent needs one, is the agent's own act after the hire",
            ))
        }
    }
}

/// Returns the entry's label, refusing an entry that carries none.
///
/// AUTH-5.58 step 4; AUTH-5.42: an empty label is faced and never
/// committed. `skep keygen --label ""` is no label (AUTH-5.67), the genesis
/// would latch the empty byline permanently (AUTH-2.100), and every later
/// rotation carries the label forward verbatim, so this is the one moment
/// it can be put right.
///
/// # Errors
///
/// An entry with no label halts.
pub fn labelled(entry: &Enrollment) -> Result<&str, Halt> {
    entry.label().ok_or_else(|| {
        Halt::face(
            format!("the payload's key {} carries NO label, and a hire never commits an empty byline", Fingerprint::of(&entry.key)),
            "AUTH-5.58 step 4; AUTH-5.42: the label is the public, permanent, uncorrectable byline on every write this agent's key \
             makes, and the genesis fixes it (AUTH-2.100) — an empty one would stand beside every other agent's forever, and every \
             later rotation carries it forward",
            "have the record recomposed under the name you intend: `skep keygen --label <name> --payload` on the agent's host, a \
             fresh key under that label, then run `skep hire` again with it",
        )
    })
}

/// The device hop's consequence of a substituted payload (AUTH-5.32).
///
/// It is true where the paste is enrolled into a set its holder keeps
/// acting from — `enroll`, `rotate --payload`, `handoff` — and false at the
/// hire, whose own is [`compare_hire_payload`]'s.
const HOP_CONSEQUENCE: &str = "a substituted payload enrolled here is a permanent co-holder of this account, evictable only by `skep retire`.";

/// Runs the comparison beat (AUTH-5.32; AUTH-4.59; R48).
///
/// Each fingerprint is re-derived from the bytes read and shown R42-grouped
/// beside its label rendered inert with AUTH-5.42's permanence line, one
/// line says what the parse proves, then the consent: the person compares
/// against the generating device's display and types the first group.
/// `false` on `no`, `n` or an empty answer, and after three answers that
/// are not the group.
///
/// # Errors
///
/// An abandoned comparison halts.
///
/// # Panics
///
/// Panics where `entries` is empty; [`parse_payload`]'s entries never are.
pub fn compare_payload(person: &mut dyn Person, entries: &[Enrollment], door: &str) -> Result<bool, Halt> {
    let question = format!("`{door}`: does the fingerprint match the generating device's display? type its first 8 hex to confirm, or `no`");
    compare(person, entries, HOP_CONSEQUENCE, &question)
}

/// Runs the comparison beat at the hire (AUTH-5.58 step 4; AUTH RES-211).
///
/// It is the owner's own act, standing where the payload's self-signature
/// is not owed: the fingerprint re-derived from the bytes read, shown flat
/// and grouped beside the label with AUTH-5.42's permanence line, compared
/// against the one the generating host displays, its first group typed as
/// the consent. What a substituted payload costs is said in the hire's own
/// terms, by arm: on the anchored arm one roster act, on the anchorless arm
/// an account dead at birth or live under another party's keys
/// (AUTH-5.65). The wrong-label act is said beside it: refusing the payload
/// here is the only moment a label that is not the one intended can be put
/// right. `false` on `no`, `n` or an empty answer, and after three answers
/// that are not the group.
///
/// # Errors
///
/// An abandoned comparison halts.
pub fn compare_hire_payload(person: &mut dyn Person, entry: &Enrollment, anchorless: bool) -> Result<bool, Halt> {
    let consequence = if anchorless {
        "a substituted payload committed here is another party's key at the head of this agent's account from its birth, with no \
         custody pair behind it: the account is dead at birth where nobody holds that key, and where somebody does it is a LIVE \
         principal under their keys inside your own prefix, which no act of yours reaches (AUTH-5.62 (iii); AUTH-5.65) — what is \
         left is the disavowal and the report, beside a fresh hire."
    } else {
        "a substituted payload committed here is another party's key at the head of this agent's account from its birth: the agent's \
         own first handshake then fails its pre-check (AUTH-5.65), and what is left is one act under the custody pair — the stop, \
         `skep recover` with a sheet — and a fresh hire."
    };
    say(
        person,
        "AUTH-5.58 step 4",
        "this is the one moment in this agent's life with a person present: the label below was chosen by a flag on the agent's host \
         and is about to be committed by YOUR hand, permanently. Where it is not the name you intend, answer `no`, have the record \
         recomposed under the intended label on that host, and run this again — nothing is committed yet, and no later act corrects \
         it: every rotation carries the label forward, and a changed label at a later re-key reads as a sign of compromise.",
    );
    let question = "`skep hire`: does the fingerprint match the one the agent's host displays (`skep keygen --payload` prints it there)? type its first 8 hex to confirm, or `no`";
    compare(person, std::slice::from_ref(entry), consequence, question)
}

/// Runs the comparison beat over `entries` for one door.
///
/// `consequence` is what a substituted payload costs at that door, and
/// `question` the consent's text.
///
/// # Errors
///
/// An abandoned comparison halts.
///
/// # Panics
///
/// Panics where `entries` is empty.
fn compare(person: &mut dyn Person, entries: &[Enrollment], consequence: &str, question: &str) -> Result<bool, Halt> {
    for e in entries {
        let fp = Fingerprint::of(&e.key);
        say(
            person,
            "AUTH-5.32",
            format!(
                "key to enroll — fingerprint re-derived from the bytes read:\n  {}\n  {}\n  label: {} — {}\n  anchor: {}",
                fp,
                group_hex(&fp.to_hex()).replace('\n', "\n  "),
                e.label().map(render_inert).unwrap_or_else(|| "(none)".into()),
                "this label is PUBLIC, PERMANENT and UNCORRECTABLE, the byline on every write this key makes; it was typed on the generating device and the hand that commits it here never typed it (AUTH-5.42)",
                e.anchor
            ),
        );
    }
    say(
        person,
        "R48",
        format!(
            "what the parse PROVES: that these bytes parsed as a canonical record — and nothing about who composed them. Compare the fingerprint above against the one the generating device displays, over the channel the payload came by, BEFORE anything depends on it (AUTH-5.39's discipline over a pubkey): {consequence}"
        ),
    );
    let expected = Fingerprint::of(&entries[0].key).to_hex()[..8].to_string();
    for _ in 0..3 {
        let typed = person
            .confirm_typed(Consent(Confirmation {
                text: question.to_string(),
                expected: expected.clone(),
            }))
            .map_err(|_| Halt::face("the comparison was abandoned", "nothing was written", "re-run when ready"))?;
        let typed = typed.trim().to_ascii_lowercase();
        if typed == expected {
            return Ok(true);
        }
        if typed.is_empty() || typed == "no" || typed == "n" {
            return Ok(false);
        }
        say(person, "AUTH-5.39", format!("`{typed}` is not the first group of the fingerprint shown ({expected}…); compare again and type that group, or `no`"));
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::person::scripted::{Script, Scripted};

    /// The comparison beat's consent (AUTH-5.32; AUTH-4.59; R48).
    ///
    /// The fingerprint's first R42 group, in either case and whatever
    /// whitespace rides it, consents at once; `no` or nothing declines at
    /// once; and a row near the group — a hex short, a hex long — never
    /// consents: it is asked again, three times, then declined.
    #[test]
    fn the_comparison_consents_to_the_first_group_and_nothing_near_it() {
        let key = crate::sign::signer_from_seed(&[14; 32]).public_key().clone();
        let group = Fingerprint::of(&key).to_hex()[..8].to_string();
        let entries = [Enrollment::new(key, false, Some("phone".into())).unwrap()];
        let compare = |answers: Vec<Script>| {
            let mut person = Scripted::new(answers);
            let consented = compare_payload(&mut person, &entries, "skep enroll").expect("answered");
            let asked = person.transcript.iter().filter(|l| l.starts_with("CONSENT confirm")).count();
            let reasked = person.transcript.iter().filter(|l| l.contains("is not the first group of the fingerprint shown")).count();
            (consented, asked, reasked)
        };
        assert_eq!(compare(vec![Script::Typed(format!("  {} \n", group.to_ascii_uppercase()))]), (true, 1, 0));
        assert_eq!(compare(vec![Script::Typed(String::new())]), (false, 1, 0));
        assert_eq!(compare(vec![Script::Confirm(false)]), (false, 1, 0));
        for near in [group[..7].to_string(), format!("{group}0")] {
            assert_eq!(compare(vec![Script::Typed(near.clone()); 3]), (false, 3, 3), "`{near}` consented");
        }
    }

    fn entry(seed: u8, anchor: bool, label: Option<&str>) -> Enrollment {
        let key = crate::sign::signer_from_seed(&[seed; 32]).public_key().clone();
        Enrollment::new(key, anchor, label.map(str::to_string)).unwrap()
    }

    /// The hire's three tests over the paste (AUTH-5.58 step 4; RES-211).
    ///
    /// Each is its own: the flag test refuses an anchor-flagged entry beside
    /// one device-flagged one, which the count passes; the count refuses a
    /// second device-flagged entry, and none, which the flag test passes;
    /// and the label test refuses an entry with no label, which both pass.
    #[test]
    fn the_hires_flag_count_and_label_tests_are_each_their_own() {
        let (device, second, anchor) = (entry(31, false, Some("scribe")), entry(32, false, Some("scribe two")), entry(33, true, Some("sheet")));
        let state = |r: Result<(), Halt>| match r {
            Err(Halt::Halt(face)) => face.state,
            other => panic!("a halt's face: {other:?}"),
        };
        // One device entry and one anchor-flagged: the flag test alone refuses.
        let mixed = [device.clone(), anchor.clone()];
        assert!(state(refuse_anchor_flagged_at_hire(&mixed)).contains("carries an ANCHOR-flagged entry"));
        assert_eq!(the_one_device_entry(&mixed).map(|e| Fingerprint::of(&e.key)), Ok(Fingerprint::of(&device.key)), "the count alone passes it");
        // Two device entries: the count alone refuses.
        let two = [device.clone(), second];
        assert_eq!(refuse_anchor_flagged_at_hire(&two), Ok(()));
        assert!(state(the_one_device_entry(&two).map(|_| ())).contains("carries 2 device-flagged entries"));
        assert!(state(the_one_device_entry(std::slice::from_ref(&anchor)).map(|_| ())).contains("carries 0 device-flagged entries"));
        // One device entry, unlabelled: the label test alone refuses.
        let bare = [entry(34, false, None)];
        assert_eq!(refuse_anchor_flagged_at_hire(&bare), Ok(()));
        let one = the_one_device_entry(&bare).expect("one device entry");
        assert!(state(labelled(one).map(|_| ())).contains("carries NO label"));
        assert_eq!(labelled(&device), Ok("scribe"));
    }

    /// The hire's comparison says the hire's own consequence, by arm.
    ///
    /// The device hop's "co-holder … `skep retire`" is false of an agent's
    /// first key record and is never said there; the consent is the first
    /// group, as at every paste.
    #[test]
    fn the_hires_comparison_says_its_own_consequence_and_never_the_hops() {
        let device = entry(35, false, Some("scribe"));
        let group = Fingerprint::of(&device.key).to_hex()[..8].to_string();
        for (anchorless, own) in [(false, "one act under the custody pair"), (true, "with no custody pair behind it")] {
            let mut person = Scripted::new(vec![Script::Confirm(true)]);
            assert_eq!(compare_hire_payload(&mut person, &device, anchorless), Ok(true));
            assert!(person.said(own) && person.said("label: scribe") && person.said("AUTH-5.42"), "{}", person.transcript.join("\n"));
            assert!(!person.said("co-holder") && !person.said("skep retire"), "{}", person.transcript.join("\n"));
        }
        let mut person = Scripted::new(vec![Script::Typed(group[..7].to_string()); 3]);
        assert_eq!(compare_hire_payload(&mut person, &device, false), Ok(false), "a group near the fingerprint's never consents");
        let mut hop = Scripted::new(vec![Script::Confirm(true)]);
        assert_eq!(compare_payload(&mut hop, std::slice::from_ref(&device), "skep enroll"), Ok(true));
        assert!(hop.said("a permanent co-holder of this account, evictable only by `skep retire`"), "the hop's own consequence stands at its door");
    }
}
