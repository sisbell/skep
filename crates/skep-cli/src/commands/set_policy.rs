//! `skep set-policy`, the twenty-fifth command: a door's policy published
//! (REG-4.131; REG-4.139).
//!
//! A registry's door keeps its admission policy in one published document,
//! well-known document 5 of the door account, and publishing its next
//! version is the revision. `skep set-policy <file>` is that act, the
//! library's (`skep_client::ceremony::policy::set_policy`): the document is
//! created where it is missing, and the file is published as its next
//! version — the first policy and every later change alike.
//!
//! `<file>` is the policy as every reader parses it: one JSON object in its
//! canonical form, at most 16 KiB. It is read and judged first, ahead of
//! the door and of any socket, so a file that would stand as no policy —
//! too long, or one the shared parser refuses, a trailing newline among its
//! causes — is refused naming its cause and nothing is written: a door
//! whose standing version does not parse is shut.
//!
//! A person door: the officer is told what the version says — the admission
//! mode, the approval's hand, the intake homes, the intervals and the
//! grounds — and that a published version is permanent and public, and
//! types `publish`. Where the version standing already holds exactly the
//! file's bytes nothing is published and no confirmation is asked, so a run
//! that was cut after its publication is answered by the next.
//!
//! The session is the door account's own: the principal the board seats at
//! its claimant where `--principal` is omitted, under the selected signing
//! key, content-scoped and closed on every exit. Stdout carries `policy
//! <version address>`; stderr what was done. A line with no file is a usage
//! refusal, exit 2.

use std::fs::File;
use std::io::Read;

use skep_client::board::Scope;
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::ceremony::policy::{check_policy, policy_document, read_policy, set_policy as publish, MAX_POLICY_BYTES};
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::halt::Halt;
use skep_client::person::{Confirmation, Consent, Person};
use skep_client::sheet::render_inert;
use skep_client::store::{KeySelector, KeyStore, Purpose};
use skep_registry::{AdmissionPolicy, ApprovalHand};

use super::{board_of, data, key_named, registrar_principal, require_terminal, select_key, store_of, talk, Door, Stop};
use crate::args::{CommandLine, Usage};
use crate::terminal::Terminal;

/// The word an officer types to publish a policy version.
const CONFIRMATION: &str = "publish";

pub fn set_policy(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    let store = store_of(c)?;
    let given = c.principal()?;
    let key_file = c.key_file()?;
    let Some(path) = c.operand() else {
        return Err(Usage("a file is required: `skep set-policy <file>`, the door's policy as one canonical JSON object".into()).into());
    };
    // The file, read to one byte past the cap and judged before the door
    // and before any socket: a file that would stand as no policy is never
    // published (REG-4.139).
    let mut text = Vec::new();
    File::open(path).and_then(|file| file.take(MAX_POLICY_BYTES as u64 + 1).read_to_end(&mut text)).map_err(|e| {
        Halt::face(format!("the policy file {path} could not be read: {e}"), "a mis-pathed file is a halt naming the path, never a fallback", "check the path; nothing was written")
    })?;
    let policy = check_policy(&text)?;
    require_terminal(Door { form: "set-policy", moments: "the policy's statement and its typed confirmation" })?;
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let principal = registrar_principal(&board, given)?;
    let key = select_key(key_file.as_deref(), &store, &board, principal, Purpose::Sign)?;
    let signer = store.signer(&KeySelector::Path(&key.path))?;
    let session = handshake(&board, Scope::Content, &*signer, principal, Site::Console)?;
    talk(format!("acting as principal {principal} at account {} with key {}", session.account(), key_named(&key)));
    let outcome = (|| -> Result<(), Stop> {
        // What stands, read first: a version that already holds the file
        // is answered, and no confirmation is asked for nothing.
        let chain = read_policy(&board, Some(session.token()), session.account())?;
        let unchanged = chain.versions.last().is_some_and(|head| head.text.as_deref() == Some(text.as_slice()));
        if !unchanged {
            let next = format!("{}.{}", policy_document(session.account()), chain.versions.len() + 1);
            statement(&policy, &next, chain.created);
            let mut person = Terminal;
            let typed = person
                .confirm_typed(Consent(Confirmation { text: format!("publish this policy as {next}? type `{CONFIRMATION}` to publish it; or `no`"), expected: CONFIRMATION.to_string() }))
                .map_err(|_| Halt::face("the policy was not published: the confirmation was abandoned", "no answer was typed", "nothing was written; run it again to answer"))?;
            if !typed.trim().eq_ignore_ascii_case(CONFIRMATION) {
                return Err(Halt::face("the policy was not published: the confirmation was declined", format!("the typed answer was not `{CONFIRMATION}`"), "nothing was written").into());
            }
        }
        let set = publish(&board, &session, &*signer, &text)?;
        if set.created {
            talk(format!("the door's policy document {} is created: published, and found by its number (REG-4.131)", set.document));
        }
        if set.published {
            talk(format!(
                "the policy is published as {}, the version every act from here cites; an act already taken cites the version it stood on, which stays readable at its own address (REG-4.134)",
                set.version
            ));
        } else {
            talk(format!("the version standing, {}, already holds this file: nothing was published", set.version));
        }
        data(format!("policy {}", set.version))?;
        Ok(())
    })();
    // The session is closed on every exit; a close the board refuses speaks
    // only where the run itself passed.
    match session.close() {
        Ok(_) => outcome,
        Err(h) => {
            outcome?;
            Err(h.into())
        }
    }
}

/// Says what the version to publish states, ahead of its confirmation.
fn statement(policy: &AdmissionPolicy, next: &str, created: bool) {
    let hand = match policy.approval_hand() {
        Some(ApprovalHand::Officer) => "an officer approves each request by hand".to_string(),
        Some(ApprovalHand::Unattended) => "the unattended hand approves what passes the approval's check (`skep approve --auto`), and an officer may".to_string(),
        None => format!("NO APPROVAL can be written under it: `approval` is `{}`, which names no hand", render_inert(&policy.approval)),
    };
    let intake: Vec<String> = policy.intake.iter().map(ToString::to_string).collect();
    talk(format!(
        "[REG-4.131] this publishes the door's policy as {next}{}: `{}` admission; {hand}; requests are read from {}; a registration is collected within {} seconds; \
         {} ground{} a denial can cite; out-of-band contact `{}`. A published version is PERMANENT and PUBLIC: every reader — an applicant, a guest — reads it, \
         and what is published next binds the acts taken after it, never the ones already taken.",
        if created { "" } else { ", creating the door's policy document first" },
        policy.admission.as_str(),
        if intake.is_empty() { "NO home: `intake` names none, so no request is admitted".to_string() } else { intake.join(", ") },
        policy.collection_interval.as_str(),
        policy.grounds.len(),
        if policy.grounds.len() == 1 { "" } else { "s" },
        render_inert(&policy.contact)
    ));
}
