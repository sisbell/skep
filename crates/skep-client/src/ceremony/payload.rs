//! THE PASTE DOOR (`client.md` §2.2 `enroll`; AUTH-5.32): an enrollment
//! record carried in from the device that generated it — its bytes read as
//! UTF-8 text, `parse_enroll` and nothing else (AUTH-2.130; a mangled paste
//! caught at the door, AUTH-5.57 step 3's echo-back), an ANCHOR-flagged
//! entry refused where the door enrolls device keys alone (AUTH-3.20/3.22;
//! AUTH-1.26), and THE COMPARISON BEAT, a CONSENT moment (AUTH-4.59; R48;
//! cs6-1). `enroll`, `rotate --payload` and `handoff`'s second invocation
//! take a paste through it.

use skep_identity::{parse_enroll, Enrollment, Fingerprint};

use super::say;
use crate::halt::Halt;
use crate::person::{Confirmation, Consent, Person};
use crate::sheet::{group_hex, render_inert};

/// The pasted bytes as the record's TEXT: UTF-8, the trailing newline
/// stripped (the canonical encoding has no `\n`, RES-98).
pub fn payload_text(payload: &[u8]) -> Result<String, Halt> {
    let text = std::str::from_utf8(payload).map_err(|_| Halt::face("the payload is not UTF-8", "a canonical record is UTF-8 text (AUTH-2.130)", "re-take the payload from the device that generated it; never edit it here"))?;
    Ok(text.trim_end_matches(['\n', '\r']).to_string())
}

/// `parse_enroll` on the paste, the malformed face naming where.
pub fn parse_payload(text: &str) -> Result<Vec<Enrollment>, Halt> {
    parse_enroll(text.as_bytes()).map_err(|e| {
        Halt::face(
            "the payload is not a canonical enrollment record",
            format!("`parse_enroll` refused it: {e} — malformed_payload (AUTH-2.130 admits the canonical encoding and nothing else)"),
            "re-take the payload from the device that generated it (`skep keygen --payload`); never edit it here (AUTH-5.57 step 3's echo-back)",
        )
    })
}

/// An ANCHOR-FLAGGED entry is REFUSED AT THE PASTE, naming the walks that
/// exist — never stripped and re-flagged (AUTH-1.26 fixes the flag for the
/// fingerprint's life).
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

/// THE COMPARISON BEAT (AUTH-5.32; AUTH-4.59; R48): each fingerprint
/// re-derived from the bytes read and shown R42-grouped beside its label
/// rendered inert with AUTH-5.42's permanence line, ONE line saying what the
/// parse proves, then the CONSENT: the person compares against the
/// generating device's display and types the first group. `false` on `no`.
pub fn compare_payload(person: &mut dyn Person, entries: &[Enrollment], door: &str) -> Result<bool, Halt> {
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
        "what the parse PROVES: that these bytes parsed as a canonical record — and nothing about who composed them. Compare the fingerprint above against the one the generating device displays, over the channel the payload came by, BEFORE anything depends on it (AUTH-5.39's discipline over a pubkey): a substituted payload enrolled here is a permanent co-holder of this account, evictable only by `skep retire`.",
    );
    let expected = Fingerprint::of(&entries[0].key).to_hex()[..8].to_string();
    for _ in 0..3 {
        let typed = person
            .confirm_typed(Consent(Confirmation {
                text: format!("`{door}`: does the fingerprint match the generating device's display? type its first 8 hex to confirm, or `no`"),
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

    /// THE COMPARISON BEAT's consent (AUTH-5.32; AUTH-4.59; R48): the
    /// fingerprint's first R42 group, in either case and whatever whitespace
    /// rides it, consents at once; `no` or nothing declines at once; and a
    /// row NEAR the group — a hex short, a hex long — never consents: it is
    /// asked again, three times, then declined.
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
}
