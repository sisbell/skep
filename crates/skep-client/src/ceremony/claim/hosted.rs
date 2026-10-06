//! THE HOSTED ARM (`client.md` §4.5; AUTH-5.55 step 8): the claim made by a
//! hosting flow for a customer whose device composed the payload — the
//! canonical record inserted VERBATIM as the genesis, every session bare,
//! nothing generated, nothing asked, no `Person` call anywhere — and its
//! reply, DATA for the hosting flow's message. `claim` re-exports what it
//! answers.

use skep_identity::Fingerprint;

use super::foreign_claimant;
use crate::address::doc_1_of;
use crate::board::{acked_addr, frames, Answer, Board, Opened, Rejection, SessionBody, Token, T_CLAIM};
use crate::ceremony::deposit::{deposit, Deposit, DepositKind, DepositOutcome};
use crate::ceremony::first_session::document_present;
use crate::halt::Halt;

/// THE HOSTED ARM's reply (§4.5 H6): DATA for the hosting flow's message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedReply {
    pub claimant: String,
    pub account: String,
    pub principal: u64,
    pub origin: String,
    /// The operator's log lines — TALK.
    pub log: Vec<String>,
    /// Whether the payload carried no anchor-flagged entry (AUTH-5.16's
    /// second arm, for the reply's own sentence).
    pub anchorless: bool,
}

/// What the hosted arm answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostedOutcome {
    Claimed(HostedReply),
    /// Idempotent: already claimed, exit 0.
    AlreadyClaimed { claimant: String },
}

/// THE HOSTED ARM, H0–H6: every session bare, nothing generated, nothing
/// asked; the payload the customer's canonical record, inserted verbatim.
pub fn hosted(board: &Board, payload: &[u8], principal: u64) -> Result<HostedOutcome, Halt> {
    let mut log = Vec::new();
    // H0
    let health = board.health()?;
    if let Some(c) = health.claimant() {
        return Ok(HostedOutcome::AlreadyClaimed { claimant: c.to_string() });
    }
    let local_trust = health.local_trust();
    if local_trust {
        log.push("warning: this daemon runs with local trust ON, so the flip will be into CLAIMED-PERMISSIVE: any party reaching its loopback — every process in the container's namespace, this sidecar included — reads every draft this customer writes, writes drafts as them, and mints permanent dead accounts under their prefix, with `key: \"bare\"` testimony and no key anywhere in it (AUTH-4.52; AUTH-4.57 pin (i) is the image's obligation)".into());
    }
    let loopback: Vec<&str> = health.origins().into_iter().filter(|o| crate::origin::Origin::parse(o).is_some_and(|x| x.names_loopback_host() && !x.is_https())).collect();
    let configured: Vec<&str> = health.origins().into_iter().filter(|o| !loopback.contains(o)).collect();
    if configured.is_empty() {
        log.push("warning: this board is configured with no origin — once claimed its signed set is EMPTY and every signed session will be refused until the daemon is relaunched with `--origin` (wire.md §The claim ceremony and credentials)".into());
    }
    // H1
    match board.next_account_prefix("1")?.as_deref() {
        Some("1.0.1") => {}
        other => {
            return Err(Halt::face(
                format!("this board carries pre-claim residue (next_account_prefix answers {})", other.unwrap_or("null")),
                "the claim would refuse `claim_residue`; the image's cure is a fresh data directory",
                "start the daemon on a fresh data directory and run the hosted claim again",
            ))
        }
    }
    // H2: the payload parsed, canonical only; a preview-kind entry refused
    // here, ahead of H3's every frame (P13).
    let text = std::str::from_utf8(payload).map_err(|_| payload_face("not UTF-8"))?.trim_end_matches(['\n', '\r']).to_string();
    let entries = skep_identity::parse_enroll(text.as_bytes()).map_err(|e| payload_face(&e.to_string()))?;
    for e in &entries {
        let fp = Fingerprint::of(&e.key);
        if e.key.alg() != skep_identity::ALG_MLDSA65_ED25519 {
            return Err(Halt::face(
                format!("the payload names a PREVIEW-kind key: {} ({})", fp, e.key.alg()),
                "refused by this client as a preview kind; the board's own setting not consulted — a hosted board is a served board, which enrolls the production kind alone",
                "the customer re-takes the payload from a client generating the production kind (`mldsa65-ed25519`)",
            ));
        }
        log.push(format!("payload entry: {fp} anchor={} label={}", e.anchor, e.label().map(crate::sheet::render_inert).unwrap_or_else(|| "(none)".into())));
    }
    let anchorless = !entries.iter().any(|e| e.anchor);
    if anchorless {
        log.push("this payload carries no anchor-flagged entry: the account it founds is ANCHORLESS PERMANENTLY — no anchor act on it is ever possible, `skep recover` is unavailable forever, the only remaining path being the enroll hop from another signed-in device; a captured token is the account (AUTH-5.16's second arm; AUTH-5.62; AUTH-4.53)".into());
    }
    // H3: bare 0 → delegate; bare N → the mint.
    let account = "1.0.1".to_string();
    let boot = hosted_bare(board, 0)?;
    let v = match board.op(Some(&boot), &frames::delegate(&account, principal, Some("hosted.delegate")))? {
        Answer::Closed => return Err(Halt::face("the bootstrap session ended", "closed", "re-run")),
        Answer::Document(v) => v,
    };
    if acked_addr(&v).is_none() {
        let r = Rejection::of(&v).map(|r| r.token()).unwrap_or_else(|| v.to_string());
        return Err(Halt::face(format!("the delegate was refused: {r}"), "H3", "re-run the hosted claim on a fresh data directory"));
    }
    let owner = hosted_bare(board, principal)?;
    let home = doc_1_of(&account);
    if !document_present(board, &home)? {
        let v = match board.op(Some(&owner), &frames::create_home(&account, Some("hosted.mint")))? {
            Answer::Closed => return Err(Halt::face("the owner's bare session ended", "closed", "re-run")),
            Answer::Document(v) => v,
        };
        if acked_addr(&v).is_none() {
            let r = Rejection::of(&v).map(|r| r.token()).unwrap_or_else(|| v.to_string());
            return Err(Halt::face(format!("the home mint was refused: {r}"), "H3", "re-run the hosted claim"));
        }
    }
    // H4: the record VERBATIM, declared, from N's bare session.
    let outcome = deposit(
        board,
        &owner,
        &Deposit { home: &home, subject: &account, kind: DepositKind::EnrollVerbatim(text.clone()), hand: None, id: "hosted.genesis" },
    )?;
    if let DepositOutcome::Committed { reason } = outcome {
        log.push(format!("the genesis stands: {reason}"));
    }
    // H5: the claim from N's BARE session (testimony `key: "bare"`).
    let v = match board.op(Some(&owner), &frames::make_link(&home, &[&account], &[], T_CLAIM, Some("hosted.claim")))? {
        Answer::Closed => return Err(Halt::face("the owner's bare session ended at the claim", "closed", "re-run; H6 reads /health.auth.claimant for the answer")),
        Answer::Document(v) => v,
    };
    if acked_addr(&v).is_none() {
        if let Some(r) = Rejection::of(&v) {
            match r.detail.as_deref().unwrap_or("") {
                "already_claimed" => {}
                "claim_residue" => return Err(Halt::face("this board carries pre-claim residue", "claim_residue at the claim", "a fresh data directory")),
                _ => return Err(r.refused(&v)),
            }
        }
    }
    // H6: the ANSWER off /health.auth.claimant, never "the claim failed".
    let after = board.health()?;
    let claimant = after.claimant().map(str::to_string);
    match claimant {
        Some(c) if c == account => {}
        Some(c) => return Err(foreign_claimant(&c)),
        None => return Err(Halt::face("the board is still unclaimed after the claim", "the claim link was acked and /health shows no claimant", "re-run; this is a board fault")),
    }
    // THE CLOSE IS CONDITIONED ON H0's OWN READ: under local_trust the bare
    // sessions survive the flip and are closed here; under false they died.
    if local_trust {
        let _ = board.session_close(&boot);
        let _ = board.session_close(&owner);
    }
    Ok(HostedOutcome::Claimed(HostedReply { claimant: account.clone(), account, principal, origin: board.dialed.as_str().to_string(), log, anchorless }))
}

fn payload_face(why: &str) -> Halt {
    Halt::face(
        "the payload is not a canonical enrollment record",
        format!("`parse_enroll` admits the canonical encoding and nothing else (AUTH-2.130): {why}"),
        "the customer re-takes the payload from the device that generated it (`skep keygen --payload` or `--anchors`); nothing was written",
    )
}

fn hosted_bare(board: &Board, principal: u64) -> Result<Token, Halt> {
    match board.session_open(SessionBody::Bare { principal })? {
        Opened::Token(t) => Ok(t),
        Opened::Rejected => Err(Halt::face(
            format!("the bare bind as principal {principal} was refused"),
            "a Remote peer — the sidecar is not in the daemon's network namespace — or a claimed board",
            "run the sidecar with `--network container:<daemon>`",
        )),
        Opened::Blocked { record } => Err(Halt::Blocked(crate::halt::Blocked { record, named_by: board.dialed.as_str().to_string(), ground: None })),
    }
}
