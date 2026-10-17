//! The one retirement preview, `preview(removed)`.
//!
//! `client.md` §1.1's `ceremony` row; §5.1 "the retirement preview": it runs
//! at every site that retires — `retire`, `recover` R4 (once per retirement
//! and per stolen round) and its containment act at an agent's account, the
//! loss arm at L5's failure arm and at L6, and `rotate` T1. It holds
//! AUTH-5.46's ordinary arm's four clauses (the commit kills that key's live
//! sessions, AUTH-4.63; the retirement is a permanent public record; I4
//! bars the fingerprint forever, AUTH-2.98; the device returns only as a
//! fresh keypair under a new byline, AUTH-5.42, AUTH-5.69); the reach's two
//! halves over the gesture's own enumeration (every account the gesture
//! will not close and every account this client cannot open — the act where
//! one exists, the state where none does; AUTH-5.46 as RES-142 states it;
//! AUTH-5.59's head); the rows labelled from the admitted read (AUTH-5.69),
//! rendered inert (AUTH-5.2); the last-device line forked on the set's
//! anchor flags (§4a.4 — the no-anchor arm unwritable, `would_empty`, taking
//! no confirmation) at every site but a rotation's, whose retire-old follows
//! its replacement's enrollment (AUTH-5.59 steps 1 and 4); the last-anchor
//! line with RES-177's downgrade, armed; and the typed answer through
//! `Person::confirm_typed`, never a flag — no `--yes` exists, because "the
//! wrong row is the mistake stress produces". The library takes the
//! fingerprints to retire as input and never chooses one (§4a.4;
//! §9 item 33).

use skep_identity::Fingerprint;

use super::say;
use crate::board::KeySet;
use crate::ceremony::enumerate::Closure;
use crate::derive::records::Records;
use crate::halt::Halt;
use crate::person::{Confirmation, Consent, Person};
use crate::sheet::{group_hex, render_inert};

/// One row of the preview: a fingerprint to retire, labelled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub fingerprint: Fingerprint,
    pub anchor: bool,
    pub label: Option<String>,
    /// This store holds the key.
    pub held: bool,
    /// The key opened the session the retirement runs under.
    ///
    /// The commit ends this session.
    pub session_key: bool,
    /// Enrolled after this walk began (the stolen arm's round).
    pub enrolled_since: bool,
}

impl Row {
    /// Returns a row over the set, the records and what this store holds.
    pub fn of(fp: &Fingerprint, set: &KeySet, records: Option<&Records>, held: &[Fingerprint], session_key: Option<&Fingerprint>, since: bool) -> Row {
        Row {
            fingerprint: *fp,
            anchor: set.enrolled(fp).is_some_and(|e| e.anchor),
            label: records.and_then(|r| r.label_of(fp)),
            held: held.contains(fp),
            session_key: session_key == Some(fp),
            enrolled_since: since,
        }
    }

    fn render(&self) -> String {
        let label = self.label.as_deref().map(render_inert).unwrap_or_else(|| "(no label recorded)".into());
        let mut out = format!("{}\n    {}\n    label: {label}", self.fingerprint, group_hex(&self.fingerprint.to_hex()).replace('\n', "\n    "));
        if self.anchor {
            out.push_str("\n    an ANCHOR");
        }
        if self.held {
            out.push_str("\n    this store holds this key");
        }
        if self.session_key {
            out.push_str("\n    this key opened the session this retirement runs under");
        }
        if self.enrolled_since {
            out.push_str("\n    ENROLLED AFTER THIS WALK BEGAN — a hand enrolling at machine rate");
        }
        out
    }
}

/// The site the preview runs at — what each adds (§1.1's `ceremony` row).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewSite {
    Retire,
    RecoverDevice,
    RecoverStolen,
    LossArm,
    Rotate,
}

/// The preview's inputs.
pub struct Preview<'a> {
    /// The account whose set the retirement names (the set account).
    pub account: &'a str,
    pub set: &'a KeySet,
    pub rows: &'a [Row],
    /// The head invariant's enumeration for the retired key.
    ///
    /// It is the closure AUTH-5.59's head defines, and the reach is stated
    /// over it.
    pub closure: &'a Closure,
    /// This store's own keys, for the reach's act.
    pub held: &'a [Fingerprint],
    pub site: PreviewSite,
    /// The board is the person's own (a notebook) — the volume copy exists.
    pub own_board: bool,
}

/// The answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Previewed {
    /// The typed answer named the row.
    Confirmed,
    /// `no` — or `n`, nothing, or three answers that are not the row.
    Declined,
    /// The write is unreachable (`would_empty`): no confirmation was taken.
    Unwritable,
}

/// Runs the preview.
///
/// # Errors
///
/// An abandoned confirmation halts.
///
/// # Panics
///
/// Panics where `p.rows` is empty and the walk reaches the typed answer;
/// every site names the row it retires.
pub fn preview(person: &mut dyn Person, p: &Preview<'_>) -> Result<Previewed, Halt> {
    let removed: Vec<Fingerprint> = p.rows.iter().map(|r| r.fingerprint).collect();
    say(person, "AUTH-5.46", format!("RETIREMENT PREVIEW at {} — the row(s) this act retires:\n  {}", p.account, p.rows.iter().map(Row::render).collect::<Vec<_>>().join("\n  ")));
    // The four clauses (AUTH-5.46's ordinary arm).
    let own_session = p.rows.iter().any(|r| r.session_key);
    say(
        person,
        "AUTH-5.46 (1)",
        format!(
            "(1) the commit KILLS that key's live sessions at the commit (AUTH-4.63): the device holding it sees `closed` on its next request{}",
            if own_session { " — this session included: the commit ends it, and no close is sent" } else { "" }
        ),
    );
    say(person, "AUTH-5.46 (2)", "(2) the retirement is a PERMANENT PUBLIC RECORD in this account's doc 1");
    say(person, "AUTH-5.46 (3)", "(3) I4 bars this fingerprint from ever re-entering this set (AUTH-2.98): no act on this key changes it");
    say(person, "AUTH-5.46 (4)", "(4) that device returns only as a FRESH keypair under a NEW permanent byline (AUTH-5.42, AUTH-5.69)");
    // The reach's two halves over the gesture's own enumeration.
    let others: Vec<&crate::ceremony::enumerate::Admitted> = p.closure.accounts.iter().filter(|a| a.account != p.account).collect();
    if others.is_empty() {
        say(person, "AUTH-5.46 (reach)", format!("THE REACH: the board names no other set of yours holding this key — the enumeration from {} admitted {} account(s) and this gesture closes every one it names", p.account, p.closure.accounts.len()));
    } else {
        for a in others {
            let opens = a.set.enrolled.iter().any(|e| p.held.contains(&e.fingerprint));
            if opens {
                say(
                    person,
                    "AUTH-5.46 (reach)",
                    format!(
                        "THE REACH: this gesture will NOT close {} — the key stands in that set too (its genesis in the doc 1 of {}), and sets are per account (AUTH-2.98); the act exists: a key of this store opens it, so retire the key THERE from a session as that account (AUTH-2.69, AUTH-3.20)",
                        a.account, a.genesis_home
                    ),
                );
            } else {
                say(
                    person,
                    "AUTH-5.46 (reach)",
                    format!(
                        "THE REACH: this gesture will NOT close {} and this client CANNOT open it — the account is another party's, handed away at a genesis in the doc 1 of {} (AUTH-5.90 clause 1); its succession, recovery and total-loss end are theirs (AUTH-5.62 (ii)) — never a retry, never 'busy'; nothing is reported closed that is not closed",
                        a.account, a.genesis_home
                    ),
                );
            }
        }
    }
    // The last-device line, forked on the anchor flags of the set named.
    let remaining_devices = p.set.enrolled.iter().filter(|e| !e.anchor && !removed.contains(&e.fingerprint)).count();
    let anchors_remaining = p.set.enrolled.iter().filter(|e| e.anchor && !removed.contains(&e.fingerprint)).count();
    let anchors_total = p.set.enrolled.iter().filter(|e| e.anchor).count();
    if anchors_total > 0 && anchors_remaining == 0 && p.rows.iter().any(|r| r.anchor) {
        // The last-anchor arm (AUTH-5.46; RES-177's downgrade) — armed,
        // unreachable in these walks.
        say(
            person,
            "AUTH-5.46 (last anchor)",
            "this retires your LAST ANCHOR — no anchor can ever be enrolled on this account again (AUTH-3.20/3.22); AND THE DOWNGRADE: every subdivision this account opens by reference — those it holds now and any it delegates later, their drafts with them — becomes takeable at a handoff genesis by any device key of this set alone, an act only an anchor session could perform while an anchor stood (AUTH-3.21; RES-177); no later act restores the grade",
        );
    }
    // A rotation's retire-old never leaves the set keyless: T2 enrolls the
    // replacement before T4 retires the old key in the same session
    // (AUTH-5.59 steps 1 and 4), so the fork is no rotation's.
    if p.site != PreviewSite::Rotate && remaining_devices == 0 && p.rows.iter().any(|r| !r.anchor) {
        if anchors_remaining > 0 {
            say(
                person,
                "AUTH-5.46 (last device)",
                format!(
                    "THE LAST DEVICE KEY: after this write the set at {} is worth {anchors_remaining} anchor(s) and NO device key — you are keyless at this board until a paper import: the act that follows is `skep keygen` then `skep recover` with a kept anchor; where the papers went with the ladder's top rung (AUTH-5.16's DESTROYED arm) the three acts are: enroll a second device NOW while a key still signs (`skep keygen --payload` there, `skep enroll` here, `skep bind` there); copy this board's volume off the machine; succeed while this account can still sign the handoff — no command in this version performs the third",
                    p.account
                ),
            );
        } else {
            // No anchor: the write is unreachable (`would_empty`) and no
            // confirmation is taken (§4a.4).
            say(
                person,
                "AUTH-5.46 (unwritable)",
                format!(
                    "THIS RETIREMENT CANNOT BE WRITTEN AT ALL: the set at {} holds no anchor and this is its only device key, so the board answers `would_empty` and nothing was ever writable. The permanent state is AUTH-5.16's SECOND arm — no anchor stands, so `skep recover` is unavailable on this account forever — and AUTH-5.62 (ii)'s anchorless end. The acts that DO exist while this key still signs: AUTH-5.32's hop from this very session (`skep keygen --payload` on the second device, `skep enroll` here, `skep bind` there){}",
                    p.account,
                    if p.own_board { "; and the volume copy of this board, which is your own" } else { "" }
                ),
            );
            return Ok(Previewed::Unwritable);
        }
    }
    match p.site {
        PreviewSite::RecoverStolen => say(person, "AUTH-5.64 (residual)", "on the STOLEN arm this preview repeats per retirement and per round: `key_set` is re-read after each commit, and a hand enrolling at machine rate can survive the rounds — TERMINATION IS NOT GUARANTEED; what the loop buys is that this act cannot END with that hand's key enrolled unseen"),
        PreviewSite::Rotate => say(person, "AUTH-5.59 step 4", "this is the rotation's retire-old: THE LAST WRITE the old key's session can make; the commit ends that session atomically and the next act is a sign-in with the new key"),
        _ => {}
    }
    // The typed answer: the row's first R42 group, or `no`; a wrong row is
    // re-asked (AUTH-5.46: "the wrong row is the mistake stress produces").
    let expected = removed[0].to_hex()[..8].to_string();
    for _ in 0..3 {
        let typed = person
            .confirm_typed(Consent(Confirmation {
                text: format!("CONFIRM THE RETIREMENT of {} at {} — type the first 8 hex of the fingerprint to retire, or `no`", removed[0], p.account),
                expected: expected.clone(),
            }))
            .map_err(|_| Halt::face("the confirmation was abandoned", "nothing was written", "re-run when ready"))?;
        let typed = typed.trim().to_ascii_lowercase();
        if typed == expected {
            return Ok(Previewed::Confirmed);
        }
        if typed.is_empty() || typed == "no" || typed == "n" {
            return Ok(Previewed::Declined);
        }
        say(person, "AUTH-5.46", format!("`{typed}` is not the row this act names ({expected}…); type that row's first 8 hex, or `no`"));
    }
    Ok(Previewed::Declined)
}

/// Returns the decline, faced: nothing written, the walk resumes by reading.
pub fn declined(what: &str) -> Halt {
    Halt::face(
        format!("the {what} was declined at the preview: nothing was written"),
        "the typed answer was `no`",
        "re-run when ready; every state of this walk resumes by reading the board (P4)",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::EnrolledKey;
    use crate::ceremony::enumerate::Admitted;
    use crate::person::scripted::{Script, Scripted};
    use crate::sign::signer_from_seed;

    /// Builds a one-device-key, anchorless set and previews retiring its key.
    ///
    /// The set is one account's; the preview runs at `site`.
    ///
    /// # Panics
    ///
    /// Panics where the preview halts.
    fn lone_key_preview(site: PreviewSite) -> (Previewed, Scripted) {
        let key = signer_from_seed(&[12; 32]).public_key().clone();
        let fp = Fingerprint::of(&key);
        let set = KeySet { enrolled: vec![EnrolledKey { fingerprint: fp, key, anchor: false }], ..KeySet::default() };
        let closure = Closure { accounts: vec![Admitted { account: "1.0.1".into(), set: set.clone(), genesis_home: "1.0.1.0.1".into() }], reads: 1 };
        let rows = [Row::of(&fp, &set, None, &[fp], Some(&fp), false)];
        let mut person = Scripted::new(vec![Script::Confirm(true)]);
        let answer = preview(&mut person, &Preview { account: "1.0.1", set: &set, rows: &rows, closure: &closure, held: &[fp], site, own_board: true }).expect("the preview");
        (answer, person)
    }

    /// The last-device fork is no rotation's.
    ///
    /// Retiring an anchorless account's only device key is unwritable at
    /// `retire` and takes no confirmation, while a rotation's retire-old —
    /// its replacement enrolled at T2 first — reads the set it names and asks
    /// for the row.
    #[test]
    fn the_last_device_fork_is_no_rotations() {
        let (answer, person) = lone_key_preview(PreviewSite::Retire);
        assert_eq!(answer, Previewed::Unwritable);
        assert!(person.said("THIS RETIREMENT CANNOT BE WRITTEN AT ALL") && !person.said("CONSENT confirm"), "{}", person.transcript.join("\n"));
        let (answer, person) = lone_key_preview(PreviewSite::Rotate);
        assert_eq!(answer, Previewed::Confirmed);
        assert!(!person.said("CANNOT BE WRITTEN") && !person.said("THE LAST DEVICE KEY"), "{}", person.transcript.join("\n"));
        assert!(person.said("AUTH-5.59 step 4") && person.said("CONSENT confirm"), "{}", person.transcript.join("\n"));
    }

    /// The typed answer is the row's first R42 group and nothing near it.
    ///
    /// AUTH-5.46: "the wrong row is the mistake stress produces". The group,
    /// in either case and whatever whitespace rides it, confirms at once;
    /// `no` or nothing declines at once; and a row near the group — a hex
    /// short, a hex long — never confirms: it is asked again, three times,
    /// then declined.
    #[test]
    fn the_typed_answer_is_the_rows_first_group_and_nothing_near_it() {
        let (anchor, device) = (signer_from_seed(&[13; 32]).public_key().clone(), signer_from_seed(&[12; 32]).public_key().clone());
        let (anchor_fp, fp) = (Fingerprint::of(&anchor), Fingerprint::of(&device));
        let set = KeySet {
            enrolled: vec![EnrolledKey { fingerprint: anchor_fp, key: anchor, anchor: true }, EnrolledKey { fingerprint: fp, key: device, anchor: false }],
            ..KeySet::default()
        };
        let closure = Closure { accounts: vec![Admitted { account: "1.0.1".into(), set: set.clone(), genesis_home: "1.0.1.0.1".into() }], reads: 1 };
        let rows = [Row::of(&fp, &set, None, &[fp], Some(&fp), false)];
        let group = fp.to_hex()[..8].to_string();
        let answer = |answers: Vec<Script>| {
            let mut person = Scripted::new(answers);
            let previewed = preview(&mut person, &Preview { account: "1.0.1", set: &set, rows: &rows, closure: &closure, held: &[fp], site: PreviewSite::Retire, own_board: true });
            let reasked = person.transcript.iter().filter(|l| l.contains("is not the row this act names")).count();
            (previewed.expect("answered"), reasked)
        };
        assert_eq!(answer(vec![Script::Typed(format!(" {}\n", group.to_ascii_uppercase()))]), (Previewed::Confirmed, 0));
        assert_eq!(answer(vec![Script::Typed(String::new())]), (Previewed::Declined, 0));
        assert_eq!(answer(vec![Script::Confirm(false)]), (Previewed::Declined, 0));
        for near in [group[..7].to_string(), format!("{group}0")] {
            assert_eq!(answer(vec![Script::Typed(near.clone()); 3]), (Previewed::Declined, 3), "`{near}` confirmed");
        }
    }
}
