//! THE ANCHOR IMPORT STEP (`client.md` §4a.2 R1; §4a.3) — never a command:
//! ONE anchor, from a FILE (`--anchor <path>` — a path INSIDE the store
//! refused ahead of the kept-or-placed question, §3.4; KEPT-OR-PLACED asked
//! when the ceremony opens, the destroy-at-end stated, AUTH-5.54 step 3's
//! file arm), from PAPER (the 64 hex typed, then a fingerprint PREFIX of at
//! least one R42 group, §9 item 35; AUTH-5.41), or NEITHER — "I hold
//! neither" an ANSWER, the no-artifact face (AUTH-5.16's first arm with its
//! DESTROYED / FINDABLE fork and the three acts that exist elsewhere, forked
//! by cell). FINGERPRINT FIRST (AUTH-5.39): re-derived from the seed and
//! compared against the artifact's — the typed arm's fingerprint prefix off
//! the print, the file arm's `KeyFile::parse`, which refuses a file whose
//! members do not re-derive from its seed — then against the set R0's walk
//! reached (the RETIRED-SHEET face from the admitted read — the position
//! and the retiring hand's label, AUTH-5.22, AUTH-5.77, neither asserted
//! below the retention floor; a device key's material; the WRONG SHEET,
//! AUTH-5.25 (iii)), then the client-local sign/verify against the `key`
//! `key_set` publishes (AUTH-5.54 step 5's pattern). AUTH-5.22's facts —
//! the file's `account`, `principal` and `origin` — are compared BEFORE any
//! `/challenge`, a disagreement a halt naming both. R1's TWO QUESTIONS: WHOSE
//! ACCOUNT THIS IS (asked ONCE per walk at R1's head, on every arm; the
//! address is NOT the key) and, where the set holds a second enrolled
//! anchor, whether the OTHER PAPER is still held (AUTH-5.47's urgency, `skep
//! recover --anchor-lost` named). The SEED's lifetime is §4a.3's: the caller
//! holds the anchor to the last record signed with it, and the anchor's end —
//! its close or its drop — takes the seed with it.

use std::path::{Path, PathBuf};

use skep_identity::{Fingerprint, PublicKey};
use skep_signature::HybridSigner;

use super::say;
use crate::board::{Board, KeySet};
use crate::ceremony::backup::local_verify;
use crate::ceremony::reads::A4Cell;
use crate::derive::records::{Hand, Records};
use crate::derive::KeyDiagnosis;
use crate::halt::Halt;
use crate::person::{HandedPath, Import, Imported, KeptOrPlaced, Person, Public, Question, Secret};
use crate::sheet::{render_inert, typed_prefix_matches, KeyFile, Seed};
use crate::sign::Signer;
use crate::store::FileStore;

/// R1's head question: whose account this is — the person's OWN, or an
/// AGENT's whose custody sheet the owner holds (AUTH-5.62). A thing the
/// person at the keyboard knows and no read answers (RES-45's discipline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Whose {
    Own,
    Agent,
}

/// The imported anchor: the signer (the SEED, held to §4a.3's bound), its
/// fingerprint and label, and the kept-or-placed answer for its file — and
/// THE OWNER OF ITS OWN END. The anchor is dropped when the ceremony it was
/// imported FOR ends (AUTH-5.54 step 3), and every exit ends that ceremony:
/// [`ImportedAnchor::dispose`] is the close that tells the person, and an
/// anchor dropped without it — every halt a walk takes after the import —
/// still destroys a PLACED copy on the drop, best effort, so the person who
/// answered "placed" never leaves with a findable paper on the ladder's worst
/// rung (AUTH-5.40). The seed goes with the anchor.
pub struct ImportedAnchor {
    pub signer: HybridSigner,
    pub fingerprint: Fingerprint,
    pub label: Option<String>,
    /// The file, where the artifact was one.
    pub file: Option<PathBuf>,
    /// Kept (retained) or placed (destroyed at the close); `Kept` on paper.
    pub kept_or_placed: KeptOrPlaced,
    /// The close ran: the drop destroys nothing.
    ended: bool,
}

impl ImportedAnchor {
    /// AUTH-5.54 step 3's mirror at the close: the PLACED copy destroyed, the
    /// KEPT artifact retained — each said.
    pub fn dispose(mut self, person: &mut dyn Person) {
        self.ended = true;
        match (&self.file, self.kept_or_placed) {
            (Some(path), KeptOrPlaced::Placed) => {
                let gone = std::fs::remove_file(path).is_ok();
                say(person, "AUTH-5.54 step 3", format!("the placed copy {} is {}", path.display(), if gone { "destroyed" } else { "already gone" }));
            }
            (Some(path), KeptOrPlaced::Kept) => say(person, "AUTH-5.54 step 3", format!("the kept artifact {} is retained", path.display())),
            (None, _) => say(person, "AUTH-5.54 step 3", "the paper stays the kept artifact; nothing of the seed remains in this client"),
        }
    }
}

impl Drop for ImportedAnchor {
    fn drop(&mut self) {
        if let (false, Some(path), KeptOrPlaced::Placed) = (self.ended, &self.file, self.kept_or_placed) {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl std::fmt::Debug for ImportedAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ImportedAnchor({}, {:?})", self.fingerprint, self.kept_or_placed)
    }
}

/// The import's answer.
pub enum ImportOutcome {
    Anchor(Box<ImportedAnchor>),
    /// "I hold neither" — an ANSWER and never an error (AUTH-5.16's
    /// no-artifact arm; `client.md` §4a.2 R1); the caller faces it —
    /// [`no_artifact_face`] at the recovery's arms, its own face at the
    /// handoff.
    Neither,
}

/// What the artifact handed in yields, its fingerprint already checked
/// against the artifact's own: the signer (the SEED, held to §4a.3's bound),
/// its label, its file where it was one, and the kept-or-placed answer for
/// that file (`Kept` on paper).
struct Handed {
    signer: HybridSigner,
    label: Option<String>,
    file: Option<PathBuf>,
    kept_or_placed: KeptOrPlaced,
}

/// What the import is checked against.
pub struct ImportContext<'a> {
    pub board: &'a Board,
    pub store: &'a FileStore,
    /// The account named (`principal_prefix(n)`) and its principal.
    pub account: &'a str,
    pub principal: u64,
    /// The set the walk reached and its account.
    pub set_account: &'a str,
    pub set: &'a KeySet,
    pub records: &'a Records,
    /// This store's own keys (for the hand's chrome).
    pub own: &'a [(Fingerprint, PublicKey)],
    /// `--anchor <path>`.
    pub anchor_path: Option<&'a Path>,
    pub whose: Whose,
    pub cell: &'a A4Cell,
}

fn abandoned() -> Halt {
    Halt::face("the import was abandoned", "the person left at the import", "re-run when ready; nothing was written")
}

/// WHOSE ACCOUNT THIS IS, asked once at R1's head (§4a.2 R1; §2.2's head).
pub fn whose_account(person: &mut dyn Person, account: &str, principal: u64) -> Result<Whose, Halt> {
    say(
        person,
        "AUTH-5.64",
        format!(
            "WHOSE ACCOUNT IS {account} (principal {principal})? This walk is a person's OWN-account recovery and never an agent's burn: an owner holding an AGENT's custody sheet can point it at the agent's account, where it would enroll THIS store's device key into the agent's set permanently and retire the agent's working key. The address is not the key — the question is yours to answer."
        ),
    );
    let own = person
        .yes_no(Public(Question { text: "is this account your OWN (yes), or an AGENT's whose custody sheet you hold (no)?".into() }))
        .map_err(|_| abandoned())?;
    Ok(if own { Whose::Own } else { Whose::Agent })
}

/// The file's three facts (AUTH-5.38) against `--board`, n and
/// `principal_prefix(n)` (AUTH-5.22): a disagreement a halt naming both,
/// never silently preferred or ignored.
fn compare_facts(file: &KeyFile, cx: &ImportContext<'_>) -> Result<(), Halt> {
    let mut faults = Vec::new();
    if let Some(a) = &file.account {
        if a != cx.account {
            faults.push(format!("the artifact names account {a}; `principal_prefix({})` answers {}", cx.principal, cx.account));
        }
    }
    if let Some(p) = file.principal {
        if p != cx.principal {
            faults.push(format!("the artifact names principal {p}; this walk was given {}", cx.principal));
        }
    }
    if let Some(o) = &file.origin {
        if o != cx.board.dialed() {
            faults.push(format!("the artifact names origin {o}; this walk dials {}", cx.board.dialed()));
        }
    }
    if faults.is_empty() {
        return Ok(());
    }
    Err(Halt::face(
        "the artifact's facts disagree with the board and principal named",
        format!("AUTH-5.22: the address/principal read is made off the artifact before any `/challenge`, and it disagrees:\n  {}", faults.join("\n  ")),
        "name the board and principal the artifact carries, or hand in the artifact of this account — no nonce was spent",
    ))
}

/// THE RETIRED-SHEET FACE (AUTH-5.22 as RES-114 cut it; AUTH-5.77's reads):
/// the position and the retiring hand's label where readable, neither
/// asserted below the floor; the act off the anchor flags.
fn retired_sheet(cx: &ImportContext<'_>, fp: &Fingerprint) -> Halt {
    let label = cx.records.label_of(fp).map(|l| render_inert(&l)).unwrap_or_else(|| "(no label recorded)".into());
    let cause = match cx.records.retirement_of(fp) {
        Some(rec) => match (&rec.hand, rec.position) {
            (Hand::Key(hand), Some(at)) => {
                let hand_label = cx.records.label_of(hand).map(|l| render_inert(&l)).unwrap_or_default();
                let whose = if cx.own.iter().any(|(f, _)| f == hand) { "this store's own key (AUTH-5.28)" } else { "ANOTHER hand (AUTH-5.77)" };
                format!("retired at position {at} by {hand} {hand_label} — {whose}")
            }
            (Hand::Bare, Some(at)) => format!("retired at position {at} by a bare session"),
            _ => "this paper's key stands RETIRED; who wrote the retirement, and when, was not readable at this board (below its retention floor, or the record unfetchable) — no hand is asserted".into(),
        },
        None => "this paper's key stands RETIRED; the retirement record was not found at this board — no hand and no position is asserted".into(),
    };
    let other_anchor = cx.set.enrolled.iter().any(|e| e.anchor && e.fingerprint != *fp);
    let every_other = !cx.set.enrolled.iter().any(|e| cx.own.iter().any(|(f, _)| *f == e.fingerprint));
    let act = if other_anchor {
        "import your other paper anchor and try again (AUTH-5.16's first arm)".to_string()
    } else if every_other {
        "every key the set still lists is another's: AUTH-5.77's LIMIT — no key you hold opens this account".to_string()
    } else {
        "no anchor of this account stands enrolled beside it: no anchor act on this account is possible from a paper".to_string()
    };
    Halt::face(
        format!("a sheet whose key stands RETIRED opens nothing, ever (AUTH-2.98): {fp} ({label})"),
        cause,
        act,
    )
}

/// THE NO-ARTIFACT FACE (AUTH-5.16's FIRST arm at its neither-paper branch;
/// `client.md` §4a.2 R1): the state, then the DESTROYED / FINDABLE fork and
/// the three acts that exist elsewhere, forked by cell; the AGENT form on
/// "an agent's"; the import's own abandonment where the person leaves at the
/// fork.
pub fn no_artifact_face(person: &mut dyn Person, cx: &ImportContext<'_>) -> Halt {
    let anchors: Vec<String> = cx.set.enrolled.iter().filter(|e| e.anchor).map(|e| format!("{} ({})", e.fingerprint, cx.records.label_of(&e.fingerprint).map(|l| render_inert(&l)).unwrap_or_default())).collect();
    if cx.whose == Whose::Agent {
        return Halt::face(
            format!("both custody sheets of the agent at {} are unheld", cx.set_account),
            format!(
                "AUTH-5.16's AGENT form: the two papers are the OWNER's custody pair (AUTH-5.62) and there is no person working on under them — the AGENT keeps working under its working key and the OWNER has lost R39's one roster act; the anchors still enrolled: {}",
                anchors.join(", ")
            ),
            "the acts that exist are AUTH-5.64's anchorless arm's, none on this account: a fresh hire on a clean host, the old account named as permanent LIVE residue, then the disavowal and the report; the roster act and its fetch channel land with the attendant campaign — this client does not perform them",
        );
    }
    say(
        person,
        "AUTH-5.16",
        format!(
            "NO ARTIFACT: both papers are gone. Loss is not retirement (AUTH-5.47), so both anchors stand ENROLLED ({}) — what the set holds is senior credentials nobody holds, and nothing clears it from below: retiring one anchor and enrolling a replacement each need an anchor session (AUTH-3.20/3.22), and the only hand that could open one is a finder's.",
            anchors.join(", ")
        ),
    );
    let Ok(destroyed) = person.yes_no(Public(Question { text: "were the papers DESTROYED (yes), or might they be FINDABLE — lost where someone could find them (no)?".into() })) else {
        return abandoned();
    };
    if !destroyed {
        return Halt::face(
            "the papers may be FINDABLE: until they are destroyed whoever finds one outranks every device session permanently (AUTH-5.47)",
            "AUTH-5.16's FINDABLE branch",
            "abandon this account and succeed to a fresh one (AUTH-5.72) — no act on this account clears a findable paper",
        );
    }
    let succession = match cx.cell {
        A4Cell::HandoffRecipient { giver } => format!(
            "succeed on this board while this account can still sign the handoff — at a handed-off subdivision the same-board succession is TWO ACTS OF THE GIVER's ({giver}: a `delegate` of a fresh sibling and its genesis) and no act of yours (AUTH-5.72); your act is to ask for them while this account can still sign — no command performs them"
        ),
        _ => "succeed on this board while this account can still sign the handoff — at the bootstrap tier there is no handoff door (AUTH-5.90's last clause), so what is named is the OPS and not a command: a `delegate` from 0 and the claimant's genesis into the claimant's own doc 1 (AUTH-5.10), no ceremony walking them (AUTH-5.73) — this client does not perform them".to_string(),
    };
    Halt::face(
        "the papers were DESTROYED: you work on normally under senior credentials nobody will ever hold — said at the last moment any of the three acts below is cheap, this device key still signing and every act dying with it",
        "AUTH-5.16's DESTROYED branch; AUTH-5.72's boundary line: the successor is a FRESH SIBLING and never a delegate, so the subtree clause reaches nothing the predecessor held — its PUBLISHED documents fork, every DRAFT it holds freezes permanently, every GRANT it issued stands forever (a revocation needs a session nobody will open), and the one exception running the other way is a surviving ANCHORED agent's custody pile, a full read of the predecessor's drafts and a republish path",
        format!(
            "(1) ENROLL A SECOND DEVICE NOW — `skep keygen --payload` there, `skep enroll` here, `skep bind` there; (2) on a notebook COPY THE VOLUME off this machine (AUTH-5.44's line; AUTH-5.60 step 1); (3) {succession}"
        ),
    )
}

/// THE IMPORT.
pub fn import_anchor(person: &mut dyn Person, cx: &ImportContext<'_>) -> Result<ImportOutcome, Halt> {
    // The file arm by flag, else the prompt's three answers.
    let handed = match cx.anchor_path {
        Some(path) => import_file(person, cx, path)?,
        None => loop {
            let answer = person
                .import(Secret(Import {
                    prompt: format!(
                        "IMPORT ONE ANCHOR of account {} (principal {}) at {}: the kept FILE, or the 64 hex typed from the PRINT and then its fingerprint's first group (at least 8 hex), or `neither` where both papers are gone",
                        cx.account, cx.principal, cx.board.dialed()
                    ),
                }))
                .map_err(|_| abandoned())?;
            match answer {
                Imported::Neither => return Ok(ImportOutcome::Neither),
                Imported::File(path) => break import_file(person, cx, &path)?,
                Imported::Typed { seed_hex, fingerprint_prefix } => {
                    let Some(seed) = Seed::from_hex(seed_hex.trim()) else {
                        say(person, "AUTH-5.41", "that is not 64 hex — type the seed from the print again");
                        continue;
                    };
                    let signer = crate::sign::signer_from_seed(seed.bytes());
                    let fp = Signer::fingerprint(&signer);
                    if !typed_prefix_matches(&fingerprint_prefix, &fp) {
                        // AUTH-5.39: "this is not the key on this paper — re-scan".
                        say(person, "AUTH-5.39", "this is not the key on this paper — re-scan: the fingerprint on the print does not match the key the typed seed derives");
                        continue;
                    }
                    // The typed path carries no facts: the three it will use
                    // are shown and confirmed against the paper (AUTH-5.22).
                    let ok = person
                        .yes_no(Public(Question {
                            text: format!("the paper should name account {}, principal {} and origin {} — does it?", cx.account, cx.principal, cx.board.dialed()),
                        }))
                        .map_err(|_| abandoned())?;
                    if !ok {
                        return Err(Halt::face(
                            "the paper's facts disagree with the board and principal named",
                            "AUTH-5.22: a mistyped principal is faced at import, before any signature — no nonce was spent",
                            "name the board and principal the paper carries",
                        ));
                    }
                    break Handed { label: cx.records.label_of(&fp), signer, file: None, kept_or_placed: KeptOrPlaced::Kept };
                }
            }
        },
    };
    let Handed { signer, label, file, kept_or_placed } = handed;
    let fp = Signer::fingerprint(&signer);
    // Then against the set R0's walk reached.
    match KeyDiagnosis::of(cx.set, &fp) {
        KeyDiagnosis::Retired { .. } => return Err(retired_sheet(cx, &fp)),
        KeyDiagnosis::Enrolled { anchor: false } => {
            return Err(Halt::face(
                format!("{fp} is a DEVICE key's material, not an anchor's"),
                "`key_set` lists this fingerprint enrolled with `anchor: false`; the walk needs a paper (AUTH-3.20)",
                "hand in an anchor of this account",
            ))
        }
        KeyDiagnosis::Neither => {
            return Err(Halt::face(
                format!("THE WRONG SHEET: this account's records do not list this key ({fp})"),
                format!(
                    "AUTH-5.25 (iii): `key_set` at {} holds it in neither list — another account's or another board's paper; this walk is at {} (principal {}) on {}",
                    cx.set_account, cx.account, cx.principal, cx.board.dialed()
                ),
                "hand in the paper of THIS account, or name the board and principal that paper carries",
            ))
        }
        KeyDiagnosis::Enrolled { anchor: true } => {}
    }
    // The client-local sign/verify against the key `key_set` publishes.
    let published = &cx.set.enrolled(&fp).expect("the diagnosis above found it enrolled").key;
    if published != Signer::public_key(&signer) || !local_verify(&signer) {
        return Err(Halt::face(
            "this paper's key does not sign as the key the board publishes",
            "AUTH-5.54 step 5's client-local sign-and-verify failed against `key_set`'s `key` for this fingerprint",
            "this is not the key this paper names — re-scan",
        ));
    }
    say(person, "AUTH-5.39", format!("anchor {} ({}) imported: fingerprint first, then the set, then the local verify — all pass", fp, label.as_deref().map(render_inert).unwrap_or_else(|| "(no label)".into())));
    // The OTHER PAPER, where the set holds a second enrolled anchor.
    let others: Vec<String> = cx.set.enrolled.iter().filter(|e| e.anchor && e.fingerprint != fp).map(|e| format!("{} ({})", e.fingerprint, cx.records.label_of(&e.fingerprint).map(|l| render_inert(&l)).unwrap_or_default())).collect();
    if !others.is_empty() {
        let held = person
            .yes_no(Public(Question { text: format!("the set holds another enrolled anchor — {} — is that paper still held?", others.join(", ")) }))
            .map_err(|_| abandoned())?;
        if !held {
            say(
                person,
                "AUTH-5.47",
                "LOSS IS NOT RETIREMENT: until it is retired the lost paper OUTRANKS EVERY DEVICE SESSION PERMANENTLY, and one paper now stands between this account and the both-lost state. The act is `skep recover --anchor-lost` — the only recovery from a single anchor's loss this design has — run it next. The device recovery goes on either way.",
            );
        }
    }
    Ok(ImportOutcome::Anchor(Box::new(ImportedAnchor { fingerprint: fp, label, file, kept_or_placed, signer, ended: false })))
}

/// The FILE arm: the path inside the store refused ahead of the question;
/// the destroy-at-end stated; KEPT-OR-PLACED asked (SECRET); the file
/// parsed, its `anchor` member true; AUTH-5.22's facts compared.
fn import_file(person: &mut dyn Person, cx: &ImportContext<'_>, path: &Path) -> Result<Handed, Halt> {
    if cx.store.contains_path(path) {
        return Err(Halt::face(
            format!("{} lies inside the key store", path.display()),
            "no path under the store ever holds an anchor's seed (§3.4; AUTH-5.54 step 3): the store is the device key's place",
            "move the anchor file out of the store, then re-run",
        ));
    }
    say(
        person,
        "AUTH-5.54 step 3",
        format!(
            "the file at {} is imported for this ceremony alone: an imported anchor is dropped when the ceremony it was imported FOR ends — a PLACED copy is DESTROYED at the close, a KEPT artifact retained; kept-or-placed is not a filesystem-readable property of a path, so it is yours to answer",
            path.display()
        ),
    );
    let kept_or_placed = person
        .kept_or_placed(Secret(HandedPath { path: path.to_path_buf(), text: "is this the KEPT artifact (retained), or a PLACED copy (destroyed when this ceremony ends)?".into() }))
        .map_err(|_| abandoned())?;
    let bytes = std::fs::read(path).map_err(|e| {
        Halt::face(format!("the anchor file {} is missing, unreadable or mis-pathed: {e}", path.display()), "AUTH-5.67: HALT AND SURFACE naming the path, never a fallback", "check the path")
    })?;
    let file = KeyFile::parse(&bytes).map_err(|e| Halt::face(format!("the anchor file {} is refused: {e}", path.display()), "the file's own contents decide this (§3.2)", "hand in the anchor file the backup moment wrote"))?;
    if !file.anchor {
        return Err(Halt::face(
            format!("{} is a device key's file, not an anchor's", path.display()),
            "its `anchor` member is false; the walk needs a paper",
            "hand in an anchor file (`anchor-<label>-<fp>.skep-key`)",
        ));
    }
    compare_facts(&file, cx)?;
    say(person, "AUTH-5.38", format!("the artifact: anchor {} label {}", file.fingerprint, file.label.as_deref().map(render_inert).unwrap_or_else(|| "(none)".into())));
    Ok(Handed { signer: file.signer(), label: file.label.clone(), file: Some(path.to_path_buf()), kept_or_placed })
}
