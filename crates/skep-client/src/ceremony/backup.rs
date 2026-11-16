//! The backup moment in AUTH-5.54's pinned order (`client.md` §4.2).
//!
//! The backup's default is the file form and paper is opt-in by flag: only
//! the paper path prints the seed and asks for the re-type from the paper.
//! The moment is the three statements at the head (AUTH-5.54 (a)–(c)), the
//! two anchor boxes with their per-run defaults and the domain test at the
//! box (AUTH-5.42; AUTH-1.24), generate (step 1), export (step 2) — each
//! anchor to its own destination, `O_EXCL` `0600` at its final name (the
//! media may lack links), never under the store (§3.4), the ladder words
//! at the path said BEFORE the write, so a run killed inside it leaves a
//! file the words already named (AUTH-5.40; §4.2), and the one-place
//! sentence where both land in one place — the sheet besides under
//! `--paper`, the drop (step 3), the dismissal on the paper path
//! (§4.2 step 6), the re-import over a channel whose absence breaks it
//! (step 4: the file read back from the path it wrote, or the 64 hex typed
//! from the print), fingerprint first then the client-local sign-and-verify
//! (step 5; AUTH-5.39), AUTH-5.41 where both exist, the keep-the-papers
//! line keyed per site (AUTH-5.44; §4.2 step 10) — and only then the
//! caller's genesis (step 6). At the hire the pair is an agent's custody
//! pair, the owner's to keep (`Venue::Hire`; AUTH-5.58 step 3; AUTH-5.62),
//! and the material the re-import read is handed to the walk, which opens
//! the agent's first session with it and drops it when that session's one
//! act ends (`backup_moment_holding`; AUTH-5.58 step 5). A file-path
//! read-back that fails re-runs from
//! step 1 under a fresh pair, every file of the pair destroyed (§4.1 S3) —
//! each removal's answer read, a file the volume refuses to unlink said
//! standing by its path, never "destroyed", as every removal of an anchor
//! file is (AUTH-5.40: a seed on media is a findable paper until it is
//! gone). AUTH-5.41's offer to destroy the file asks by the anchor's letter
//! and its label rendered inert, never by the file's path, which is said
//! just before it under that rule: a question carries no rule an embedder
//! could keep it native by, and an anchor file's path is native (§4b.3).
//! Steps 1–3 alone — the generate, the export and the drop — are
//! `export_pair`, and statement (b) alone is `two_places`: the loss arm
//! cites the order with those two and inherits nothing else (§4a.6 L3).

use std::path::{Path, PathBuf};

use skep_identity::{Fingerprint, PublicKey};
use skep_signature::HybridSigner;
use skep_util::file;

use super::say;
use crate::halt::Halt;
use crate::person::{Abandoned, Destination, LabelBox, Person, Public, Question, Retype, Retyped, Secret, Sheet};
use crate::sheet::{read_key_file, typed_prefix_matches, Facts, KeyFile, Label, Seed};
use crate::sign::{fresh_bytes, Signer};
use crate::store::FileStore;

/// The venue the moment runs at — the copy is keyed by it (P7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Venue {
    /// `claim`'s S3: host and owner one party.
    ///
    /// The artifact carries the three facts (AUTH-5.38) and the
    /// keep-the-papers line takes the notebook form.
    Notebook { facts: Facts },
    /// `keygen --anchors`: someone else's board.
    ///
    /// Statement (a) carries the operator sentence unconditionally
    /// (AUTH-5.43's create-org sibling), the artifact lacks the address, the
    /// principal and the origin, and the line is AUTH-5.44's create-org arm.
    DoorSide,
    /// `accept`'s beat (`client.md` §4c.1): the recipient's own facts.
    ///
    /// The artifact carries the address, the principal and the origin
    /// (AUTH-5.38; AUTH RES-162) — statement (a) carrying the recipient's
    /// beat's own operator sentence per A4 cell, rendered once (`operator`;
    /// AUTH RES-156), the anchor boxes' consequence keyed to this door (the
    /// label rides the genesis into the giver's doc 1, AUTH-5.42), the line
    /// AUTH-5.44's handoff form verbatim, the org-door artifact line dropped.
    Handoff { facts: Facts, operator: String },
    /// `hire`'s step 3 (AUTH-5.58): an agent's custody pair, the owner's.
    ///
    /// The artifact carries the agent's address, its principal and the
    /// origin (AUTH-5.38), knowable because the hire's `delegate` stands
    /// ahead of the moment; the two boxes are the sheets' only source for
    /// their labels, their copy naming what the field must tell apart — this
    /// agent's sheets from every other agent's, and at a re-hire from the
    /// account it replaces (`replaces`; AUTH-5.58 step 3) — and the line is
    /// AUTH-5.44's hire form, in the owner's own facts.
    Hire { facts: Facts, replaces: Option<Replaced> },
}

/// The account a re-hire replaces, as the hire's label boxes name it.
///
/// AUTH-5.58 step 3: a re-hire is named distinguishably from the account it
/// replaces, and no mechanism can close this — labels are uncorrectable and
/// never an identity — so the door copy does: the boxes show the
/// predecessor's own labels and say the new ones must read apart from them.
/// Nothing refuses a label that matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replaced {
    /// The predecessor's account.
    pub account: String,
    /// The labels its first key record carries, as the board serves them.
    ///
    /// They are its sheets' and its working key's; each is rendered inert
    /// where it is shown.
    pub labels: Vec<String>,
}

/// The moment's inputs.
#[derive(Debug, Clone)]
pub struct BackupOptions {
    /// `--anchor-label`, up to two; a box asks where one is absent.
    pub labels: Vec<Label>,
    /// `--anchor-out`, one destination per anchor (0, 1 or 2 given).
    ///
    /// The destination is asked for where absent — no default (§6).
    pub destinations: Vec<PathBuf>,
    /// `--paper`: the sheet printed besides, and the re-type asked.
    pub paper: bool,
    /// The store, whose paths are refused as destinations (§3.4).
    pub store: Option<PathBuf>,
    /// The machine's host name, for the per-run default.
    pub host_name: String,
    /// The date, for the per-run default.
    pub date: String,
}

/// One exported anchor's public facts — never the seed, which was dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorArtifact {
    /// The anchor's public key.
    pub public: PublicKey,
    /// The anchor's fingerprint.
    pub fingerprint: Fingerprint,
    /// The label the anchor's box fixed.
    pub label: Label,
    /// The file, where it stands (destroyed under AUTH-5.41's offer: `None`).
    pub file: Option<PathBuf>,
    /// The print, under `--paper`.
    ///
    /// `None` on the file form, which prints nothing.
    pub print: Option<Print>,
}

/// What a printed anchor's re-type made of its print (AUTH-5.41).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Print {
    /// The print passed its re-type — the kept artifact is the print.
    Verified,
    /// The print was not verified — labelled so.
    ///
    /// The file stays the verified artifact.
    Unverified,
}

/// The moment's outcome: two anchors, public facts alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupOutcome {
    /// The two anchors, public facts alone.
    pub anchors: Vec<AnchorArtifact>,
    /// Both files landed in one place — (b)'s file-venue words were said.
    pub one_place: bool,
}

fn abandoned(e: Abandoned) -> Halt {
    Halt::face(
        format!("{e}"),
        "the backup moment was abandoned before its genesis write",
        "see the walk's own abandonment exit: the artifacts already made open nothing and are destroyed or kept plainly marked dead",
    )
}

/// Says the three statements at the head (AUTH-5.54 (a)–(c)).
///
/// They are keyed to the path this run takes and to the venue.
fn statements(person: &mut dyn Person, venue: &Venue, paper: bool) {
    let operator = match venue {
        Venue::Notebook { .. } => String::new(),
        Venue::DoorSide => " — on the board you are joining another party runs the daemon: it can read what you write there before you publish it and withhold or delay it; anything it writes in your name carries no signature of yours, and the app you install shows it as unsigned; it never learns your keys and can never act as you anywhere else; on that board it can still retire your keys and continue as you, which every copy that checks signatures will show was not you; your way back is a fresh account, and the board is portable (AUTH-5.43's create-org sibling; AUTH-4.54)".to_string(),
        Venue::Handoff { operator, .. } => format!(" — {operator}"),
        Venue::Hire { facts, .. } => format!(
            " — at this hire the account is your AGENT's, {}: these two sheets are its senior credential, whoever holds one \
             outranks the agent's own key, and you hold no other key of it (AUTH-5.62)",
            facts.account
        ),
    };
    say(
        person,
        "AUTH-5.54 (a)",
        format!(
            "(a) THIS KEY SET IS THIS IDENTITY AND THERE IS NO RESET: no one holds a re-key power over this account and nothing \
             in the protocol restores it to a person who holds none of its keys — there is no reset to ask an operator, host, \
             officer or registrar for, the rules giving none of them a channel{operator}."
        ),
    );
    two_places(person, paper);
    say(
        person,
        "AUTH-5.54 (c)",
        "(c) DESTROYED IS NOT LOST: 'lost' means FINDABLE until the paper is destroyed; whoever holds a paper outranks every \
         device session permanently and no act from below ever clears it. The ladder runs destroyed, then media you control, \
         then a print in a place you control, then an exported file that syncs, rides a backup or sits on a shared machine — the \
         worst rung. The top rung is a REDUNDANT copy's alone: destroying the last artifact you hold is the same act as losing \
         both, and no act on this account clears it.",
    );
}

/// Says statement (b) (AUTH-5.54 (b)), keyed to the path the run takes.
///
/// It is said at the moment's head, and alone by the loss arm before each
/// pair it exports (§4a.6 L3): a person who has just lost an anchor is one
/// artifact from AUTH-5.16's both-unheld state, which is the exact loss (b)
/// is about.
pub(crate) fn two_places(person: &mut dyn Person, paper: bool) {
    let b = if paper {
        "(b) PRINT TWO, KEEP THEM APART: the pair is two papers so that one place that burns, floods or is searched cannot take \
         both — two papers, kept in two places ONCE THIS IS FINISHED; you will need both here in a moment."
    } else {
        "(b) TWO FILES, TWO PLACES YOU CONTROL: the pair is two files so that one place that burns, floods or is searched cannot \
         take both — two files, in two places you control ONCE THIS IS FINISHED; you will need both here in a moment."
    };
    say(person, "AUTH-5.54 (b)", b);
}

/// Asks the anchor box (AUTH-5.42's anchor copy).
///
/// The box names the sheet, never where you keep it; a default derived per
/// run — the machine's host name, the date, a per-run token (§4.2 step 2);
/// the domain test at the box, re-asked on a refusal.
///
/// # Errors
///
/// An abandoned box halts.
fn anchor_box(person: &mut dyn Person, venue: &Venue, which: &str, default: String) -> Result<Label, Halt> {
    let consequence = match venue {
        Venue::Notebook { .. } => "at this notebook the name is readable by anything on the machine (AUTH-5.85's reader clause)",
        Venue::DoorSide => "at the door this payload serves the name rides onto a public thread, approved or DENIED, forever",
        Venue::Handoff { .. } => "at this door the name rides the genesis record into the GIVER's own doc 1, on a board you may not be able to read, under a byline you can never correct (AUTH-5.42)",
        Venue::Hire { .. } => "at this door the name rides the genesis record into the home document of the space for your agents, where it sits beside every OTHER agent's sheets forever, uncorrectable and never an identity — and the account it names never goes away: name it so this agent's sheets read apart from every other agent's (AUTH-5.58 step 3)",
    };
    let mut statements = vec![
        "This names the SHEET and never where you keep it — the one human-navigable field on an otherwise machine-facing paper, so you can tell the two sheets apart.".to_string(),
        "It is public forever and uncorrectable: fixing a typo costs a keypair.".to_string(),
        "This is not the device's name and not your own: the display name is a separate, changeable label collected elsewhere.".to_string(),
        consequence.to_string(),
    ];
    if let Venue::Hire { replaces: Some(replaced), .. } = venue {
        statements.push(replaced_line(replaced));
    }
    loop {
        let text = person
            .label(Public(LabelBox { title: format!("name anchor {which}"), statements: statements.clone(), default: Some(default.clone()) }))
            .map_err(abandoned)?;
        match Label::new(&text) {
            Ok(label) => return Ok(label),
            Err(fault) => say(person, "AUTH-1.24", format!("that name is refused at the box: {fault}; name the sheet again")),
        }
    }
}

/// Returns the re-hire's line at a label box (AUTH-5.58 step 3).
///
/// It shows the labels the account being replaced carries, each rendered
/// inert, and says the new name must read apart from them. It is door copy
/// and no test: nothing refuses a name that matches.
fn replaced_line(replaced: &Replaced) -> String {
    let labels = if replaced.labels.is_empty() {
        "no label this board serves".to_string()
    } else {
        replaced.labels.iter().map(|l| format!("`{}`", crate::sheet::render_inert(l))).collect::<Vec<_>>().join(", ")
    };
    format!(
        "This hire REPLACES {}, whose sheets and key carry {labels}: that account never goes away, so name this sheet to read apart \
         from them — a pile of sheets under names that read alike leaves the address and the principal as the only tell, and \
         nothing here refuses a name that matches.",
        replaced.account
    )
}

/// Returns AUTH-5.44's keep-the-papers line in its hire form.
///
/// The line is in the owner's own facts — the sheets are an agent's custody
/// and not the owner's way back into anything of their own — and names what
/// the sheets substitute for: the agent's working key, the one artifact with
/// no backup (AUTH-5.62), a copy of whose file is a second copy of the
/// agent's identity (AUTH-5.40's ladder). `noun` is `sheets` ahead of the
/// export, and after it what the run exported; `account` the agent's
/// address, once the hire's `delegate` has named it.
///
/// AUTH-5.44's string names a third act the sheets alone open, reading the
/// agent's drafts. It is not said: the owner's account contains the
/// agent's, so the owner reads those drafts by the rule from their own
/// session, on both arms (AUTH-5.62 (iv); PUB-1.32). And where the string
/// says the sheets re-key the agent, the line says which of the pair's acts
/// this client performs: the stop, and a fresh hire in the re-key's place.
pub(crate) fn hire_keep_line(noun: &str, account: Option<&str>) -> String {
    let agent = match account {
        Some(account) => format!("this agent ({account})"),
        None => "this agent".to_string(),
    };
    format!(
        "keep both {noun} — they are the only way to open a session as {agent}, and so the only way to re-key it or retire its \
         keys; lose both and no act of yours ever reaches this account again, while the agent keeps working. This agent's own key is \
         UNBACKED BY DESIGN — no ceremony here backs it up and no copy of it is a custody artifact: if it is lost, these {noun} are \
         what re-key this agent. A copy of the agent's key file — its host's backup, a restored image — is a SECOND COPY OF THIS \
         AGENT'S IDENTITY, on the ladder's worst rung: the agent host's backups are credential material (AUTH-5.40). In this version \
         the act a sheet performs is the STOP — `skep recover --anchor <sheet>` at the agent's principal, answered \"an agent's\": \
         its working keys retired, nothing enrolled (AUTH-5.64) — and its replacement is a fresh hire, `skep hire --replaces <its \
         address>`; a fresh key on this same account is not yet a command."
    )
}

/// Returns the ladder words at the file's path (AUTH-5.40).
///
/// They are keyed to the path the run takes: ending at "move it to media
/// you control" on the file-only path, the print clause under `--paper`
/// alone (RES-62 item 7). They are said BEFORE the write (§4.2): the
/// export writes at its final name, since its media may lack links, so a
/// run killed inside the write leaves a part of a file there — and these
/// words have named it, for the person to check against.
fn ladder_words(path: &Path, paper: bool) -> String {
    let tail = if paper { ", or destroy it and keep the print" } else { "" };
    format!(
        "anchor file written: {} — written as these words are said, so a run killed inside the write leaves a part of a file at \
         this name, which no restore takes for an anchor; an exported file that syncs, rides into a backup, or sits on a shared \
         machine IS a FINDABLE PAPER, the ladder's worst rung, so move it to media you control{tail}",
        path.display()
    )
}

/// Destroys the anchor file at `path`, saying what the removal did.
///
/// A file that went, or none that stood, is destroyed; a removal the
/// volume refuses — a permission, a read-only medium — leaves the file
/// standing, and says so at once naming the path, never "destroyed": a
/// seed on media is a findable paper until it is gone (AUTH-5.40). `what`
/// names the file's standing in the words ("the anchor file", "the file").
/// Answers whether the file is gone.
fn destroy(person: &mut dyn Person, what: &str, path: &Path, rule: &'static str) -> bool {
    match file::remove(path) {
        Ok(_) => {
            say(person, rule, format!("{what} {} is destroyed", path.display()));
            true
        }
        Err(e) => {
            say(
                person,
                "AUTH-5.40",
                format!("{what} {} could not be destroyed ({e}) and STILL STANDS — a findable paper until you remove it yourself", path.display()),
            );
            false
        }
    }
}

/// Returns the destination for anchor `which`: the flag's, or asked.
///
/// The ask is a secret moment; a path inside the store is refused (§3.4;
/// §6), and an asked one is asked again.
///
/// # Errors
///
/// The flag's path inside the store is refused, and an abandoned ask
/// halts.
fn destination(person: &mut dyn Person, opts: &BackupOptions, which: usize) -> Result<PathBuf, Halt> {
    let inside = |p: &Path| opts.store.as_ref().is_some_and(|s| FileStore::open(s).contains_path(p));
    if let Some(given) = opts.destinations.get(which) {
        if inside(given) {
            return Err(Halt::face(
                format!("{} lies inside the key store", given.display()),
                "no path under the store ever holds an anchor's seed (§3.4; AUTH-5.54 step 3): the store is the device key's \
                 place and the ladder's worst rung for a paper",
                "name a directory outside the store with `--anchor-out`, once per anchor",
            ));
        }
        return Ok(given.clone());
    }
    loop {
        let path = person
            .destination(Secret(Destination {
                prompt: format!(
                    "where should anchor {} be written? a DIRECTORY you control — no default is offered, and the working directory of \
                     a `--rm` container is discarded at exit",
                    if which == 0 { "a" } else { "b" }
                ),
                which,
            }))
            .map_err(abandoned)?;
        if inside(&path) {
            say(person, "§3.4", "that path lies inside the key store, where no anchor ever rests; name another");
            continue;
        }
        return Ok(path);
    }
}

/// Returns an anchor's file name (§6).
///
/// The name is `anchor-<label slug>-<8 hex of fingerprint>.skep-key`.
///
/// # Panics
///
/// Panics if the fingerprint's hex runs under 8 digits; it runs to 64, so
/// the slice never fails.
pub fn anchor_file_name(label: &Label, fp: &Fingerprint) -> String {
    format!("anchor-{}-{}.skep-key", label.slug(), &fp.to_hex()[..8])
}

/// Runs the moment.
///
/// The material its re-import reads is dropped as each anchor is verified,
/// before the moment returns.
///
/// # Errors
///
/// An abandoned box, destination, sheet, re-type or offer halts; so do a
/// destination inside the store, a directory that cannot be made, a file
/// that cannot be written, and a typed seed that derives the key but does
/// not sign; and three runs in a row whose read-back fails halt the moment.
pub fn backup_moment(person: &mut dyn Person, venue: &Venue, opts: &BackupOptions) -> Result<BackupOutcome, Halt> {
    moment(person, venue, opts, false).map(|(outcome, _)| outcome)
}

/// Runs the moment, keeping the material its re-import read of anchor a.
///
/// AUTH-5.58 step 5: the hire's custody-anchor session "rides the material
/// step 3's backup moment re-imported (AUTH-5.54 step 4), the hire being
/// the ceremony that import was for" — never a fresh import, which would
/// send the owner back to two sheets filed apart minutes earlier. The
/// signer answered is anchor a's as the re-import read it — the file read
/// back from the path it was written to, or under `--paper` the 64 hex
/// typed from the print — verified as the moment verifies it. The caller
/// holds it to the end of the ceremony it was read for and drops it there,
/// with the session it opens (AUTH-5.54 step 3's mirror); anchor b's is
/// dropped inside the moment, as every other venue's are.
///
/// # Errors
///
/// [`backup_moment`]'s.
///
/// # Panics
///
/// Panics if the moment answers no material for an anchor it verified;
/// every verified anchor's signer is held to the end of its run, so the
/// `expect` never fires.
pub fn backup_moment_holding(person: &mut dyn Person, venue: &Venue, opts: &BackupOptions) -> Result<(BackupOutcome, HybridSigner), Halt> {
    moment(person, venue, opts, true).map(|(outcome, held)| (outcome, held.expect("anchor a's re-imported material is held where the caller asks for it")))
}

/// Runs the moment, answering anchor a's re-imported material under `hold`.
///
/// # Errors
///
/// [`backup_moment`]'s.
fn moment(person: &mut dyn Person, venue: &Venue, opts: &BackupOptions, hold: bool) -> Result<(BackupOutcome, Option<HybridSigner>), Halt> {
    // Step 1 (the head): the three statements, before any generation.
    statements(person, venue, opts.paper);
    // Step 2: the two boxes, between the statements and the export.
    let token = crate::hex::encode(&fresh_bytes(2));
    let mut labels: Vec<Label> = Vec::new();
    for (i, which) in ["a", "b"].iter().enumerate() {
        let label = match opts.labels.get(i) {
            Some(l) => {
                // The box's statements render whenever a label is fixed, flag
                // or prompt alike (§2.2 `keygen`): at the flag its first two,
                // in one line.
                say(person, "AUTH-5.42", format!("anchor {which} is named `{}`: this names the SHEET and never where you keep it; public forever and uncorrectable", crate::sheet::render_inert(l.as_str())));
                l.clone()
            }
            None => anchor_box(person, venue, which, format!("{}-{}-{token}-{which}", opts.host_name, opts.date))?,
        };
        labels.push(label);
    }
    let facts = match venue {
        Venue::Notebook { facts } | Venue::Handoff { facts, .. } | Venue::Hire { facts, .. } => Some(facts),
        Venue::DoorSide => None,
    };
    for attempt in 0..3 {
        match run_once(person, venue, opts, &labels, facts, attempt, hold)? {
            Some(outcome) => return Ok(outcome),
            None => say(person, "§4.1 S3", "the moment re-runs from step 1 under a fresh pair"),
        }
    }
    // The command that re-runs the moment is its venue's: the claim, the
    // door-side form, the recipient's beat.
    let rerun = match venue {
        Venue::Notebook { .. } => "`skep claim`",
        Venue::DoorSide => "`skep keygen --anchors`",
        Venue::Handoff { .. } => "`skep accept`",
        Venue::Hire { .. } => "`skep hire`",
    };
    Err(Halt::face(
        "the backup moment could not complete",
        "three runs in a row failed their read-back",
        format!("check the destination media and re-run {rerun}; every artifact written names no live pair and opens nothing"),
    ))
}

/// Runs AUTH-5.54 steps 1–3 for one pair — §4.2's steps 3–6.
///
/// The steps: generate the pair, each seed born in its file's own zeroing
/// value; export each anchor to its own destination, the ladder words at
/// its path and the one-place sentence where both land in one place; the
/// sheets under `--paper`; the drop; the paper path's dismissal. It answers
/// the artifacts, each file standing and read back by nothing yet — a
/// print, under `--paper`, unverified. The re-import is the caller's: the
/// moment's own read-back, or the loss arm's [`reimport_anchor`] after its
/// enroll, which cites this order and inherits nothing else of the moment
/// (§4a.6 L3). `opts.labels`, `host_name` and `date` are the boxes' and
/// unread here: `labels` names the pair.
///
/// # Errors
///
/// An abandoned destination or sheet halts, as do a destination inside the
/// store, a directory that cannot be made and a file that cannot be
/// written.
pub(crate) fn export_pair(person: &mut dyn Person, opts: &BackupOptions, labels: &[Label], facts: Option<&Facts>) -> Result<BackupOutcome, Halt> {
    // Step 3: generate the pair, each seed born in its file's own zeroing
    // value — no copy of it outlives step 5's drop.
    let files: Vec<KeyFile> = labels.iter().map(|l| KeyFile::new(Seed::fresh(), true, Some(l.clone()), facts)).collect();
    let publics: Vec<(PublicKey, Fingerprint)> = files.iter().map(|f| (f.public.clone(), f.fingerprint)).collect();
    // Step 4: export — the file, each to its own destination, its path said
    // BEFORE the write (§4.2): the file is written at its final name, and a
    // run killed inside the write leaves a part of a file the words named.
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut dirs: Vec<PathBuf> = Vec::new();
    for (i, file) in files.iter().enumerate() {
        let dir = destination(person, opts, i)?;
        std::fs::create_dir_all(&dir).map_err(|e| Halt::face_at(&dir, "the anchor's destination cannot be made", e.to_string(), "name a directory you control"))?;
        let path = dir.join(anchor_file_name(&labels[i], &file.fingerprint));
        say(person, "AUTH-5.40", ladder_words(&path, opts.paper));
        FileStore::write_once(&path, file.to_json().as_bytes()).map_err(|e| {
            Halt::face_at(&path, "the anchor file could not be written", e.to_string(), "name a directory you control, writable and not a `--rm` container's own filesystem")
        })?;
        let canon = std::fs::canonicalize(&dir).unwrap_or(dir.clone());
        if i == 1 && dirs.iter().any(|d| *d == canon) {
            say(
                person,
                "AUTH-5.54 (b)",
                "both anchors are in this one place, which is the one thing (b) asks you to avoid; move one to media you control before you leave this machine",
            );
        }
        dirs.push(canon);
        paths.push(path);
    }
    let one_place = dirs.len() == 2 && dirs[0] == dirs[1];
    // Under `--paper`: the sheets printed — the seed's only screen appearance.
    if opts.paper {
        for file in &files {
            person.sheet(Secret(Sheet { fields: file.sheet() })).map_err(abandoned)?;
        }
    }
    // Step 5: drop — the seeds zeroed, the signers released, before anything
    // is read back.
    drop(files);
    // Step 6: dismiss, the paper path alone.
    if opts.paper {
        person.dismiss();
    }
    let anchors = paths
        .into_iter()
        .zip(publics)
        .zip(labels)
        .map(|((path, (public, fingerprint)), label)| AnchorArtifact {
            public,
            fingerprint,
            label: label.clone(),
            file: Some(path),
            print: opts.paper.then_some(Print::Unverified),
        })
        .collect();
    Ok(BackupOutcome { anchors, one_place })
}

/// Runs §4.2's steps 3–10 for one pair.
///
/// The steps are [`export_pair`], then the re-import, the offer and the
/// per-site line; `None` where the file path's read-back failed — every
/// file the pair wrote destroyed, each removal said, one the volume
/// refuses said standing — and the moment re-runs. Under `hold` the
/// material the re-import read of anchor a is answered beside the outcome;
/// otherwise each anchor's is dropped as it is verified.
///
/// # Errors
///
/// [`export_pair`]'s halts; an abandoned re-type or offer; and a typed seed
/// that derives the key but does not sign.
///
/// # Panics
///
/// Panics if an exported anchor has no file; [`export_pair`] gives each one
/// a file, so the `expect` never fires.
#[allow(clippy::too_many_arguments)]
fn run_once(
    person: &mut dyn Person,
    venue: &Venue,
    opts: &BackupOptions,
    labels: &[Label],
    facts: Option<&Facts>,
    attempt: usize,
    hold: bool,
) -> Result<Option<(BackupOutcome, Option<HybridSigner>)>, Halt> {
    let BackupOutcome { anchors: exported, one_place } = export_pair(person, opts, labels, facts)?;
    // Steps 7–9: re-import, fingerprint first, the client-local verify.
    let mut anchors = Vec::new();
    let mut held: Option<HybridSigner> = None;
    for (i, mut artifact) in exported.iter().cloned().enumerate() {
        let path = artifact.file.clone().expect("an exported anchor's file stands");
        // The material the re-import reads: the print's where it passed its
        // re-type, else the file's. Anchor a's is kept under `hold`; every
        // other is dropped as soon as it is verified, ahead of the offer.
        let mut material: Option<HybridSigner> = None;
        if opts.paper {
            material = retype_from_print(person, &artifact.label, i, &artifact.fingerprint)?;
            artifact.print = Some(if material.is_some() { Print::Verified } else { Print::Unverified });
        }
        if artifact.print != Some(Print::Verified) {
            // The file read back from the path it wrote — the disk channel.
            material = read_back_from_file(&path, &artifact.public, &artifact.fingerprint);
            if material.is_none() {
                say(person, "§4.1 S3", format!("the anchor file {} did not read back as the key it names (never a verified artifact): the pair's files are destroyed next, each said, and the moment re-runs (attempt {})", path.display(), attempt + 1));
                // Each file's removal read and said: the pair opens nothing,
                // and a file the volume keeps is a findable paper.
                for written in exported.iter().filter_map(|a| a.file.as_ref()) {
                    destroy(person, "the anchor file", written, "§4.1 S3");
                }
                return Ok(None);
            }
        }
        if hold && i == 0 {
            held = material;
        } else {
            drop(material);
        }
        // Step 9: AUTH-5.41 where both exist and the print passed — offer to
        // destroy the file, never the act unasked; the removal's answer read,
        // a file the volume keeps said standing and kept as the artifact. The
        // question names the anchor by its letter, since two boxes may fix
        // one label, and by its label rendered inert, as its sheet prints it.
        // A question carries no rule an embedder could route it by, so it
        // names no path: the file's is said just before it under AUTH-5.41,
        // a native rule (§4b.3: an anchor file's path is the shell's own
        // window's).
        if artifact.print == Some(Print::Verified) {
            let anchor = format!("anchor {} (`{}`)", if i == 0 { "a" } else { "b" }, crate::sheet::render_inert(artifact.label.as_str()));
            say(person, "AUTH-5.41", format!("{anchor}: its file is {} — the file the next question offers to destroy", path.display()));
            let destroy_it = person
                .yes_no(Public(Question { text: format!("the print of {anchor} passed its re-type and is the KEPT artifact; destroy its file and keep the print? (AUTH-5.40)") }))
                .map_err(abandoned)?;
            if destroy_it && destroy(person, "the file", &path, "AUTH-5.41") {
                artifact.file = None;
            }
        }
        if artifact.print == Some(Print::Unverified) {
            say(person, "AUTH-5.41", format!("anchor {}: the print is UNVERIFIED and the file {} is the verified artifact; a verified artifact is never destroyed in favor of an unverified one", artifact.label, path.display()));
        }
        anchors.push(artifact);
    }
    // Step 10: the keep-the-papers line, keyed per site (AUTH-5.44).
    let noun = if opts.paper { "papers" } else { "anchor files" };
    match venue {
        Venue::Notebook { facts } => say(
            person,
            "AUTH-5.44 (notebook)",
            format!(
                "keep the {noun} apart — they are the way back into account {} on this board if you lose this device's key, \
                 through `skep recover` from a wiped profile or a restored volume; AND copy this board's \
                 data directory off this machine: a restored volume meets a keyless person unless the papers were kept, and \
                 the papers open nothing on a fresh install — with no copy of this board's volume, a fresh install is a fresh \
                 board. A copy of the board carries its credential records AS OF THE COPY: a restore predating a retirement \
                 brings that key back live, and any retirement made after the copy must be re-run on the restored board.",
                facts.account
            ),
        ),
        Venue::DoorSide => say(
            person,
            "AUTH-5.44 (create-org)",
            format!(
                "keep the {noun} — if you lose every device you have signed in on, they are the only way back in, and your anchors \
                 go on the record at admission either way: lose both and no anchor act on this account is ever possible again. \
                 These sheets carry your key and its fingerprint — not your account's address, its principal number or the \
                 board's origin, which do not exist yet. Those arrive in the reply to your request, and that reply is where \
                 they live permanently: keep it with the papers."
            ),
        ),
        // The handoff form, verbatim (AUTH-5.44; `client.md` §4c.1): the
        // recipient's own facts, the only site where the papers' holder is not
        // the party running the door — beside the operator sentence
        // statement (a) carried, never against it (AUTH RES-156).
        Venue::Handoff { facts, .. } => say(
            person,
            "AUTH-5.44 (handoff)",
            format!(
                "keep the papers — they are the way back into {} if you lose the device you sign in on, and the rules give nobody \
                 a channel to re-key this account for you: not the person who gave it to you, not an operator, host, officer or \
                 registrar (AUTH-5.54 (a)); lose both and no anchor act on this account is ever possible again.",
                facts.account
            ),
        ),
        // The hire form, in the owner's own facts (AUTH-5.44): the sheets are
        // an agent's custody, and what they substitute for is named.
        Venue::Hire { facts, .. } => say(person, "AUTH-5.44 (hire)", hire_keep_line(noun, Some(&facts.account))),
    }
    Ok(Some((BackupOutcome { anchors, one_place }, held)))
}

/// Asks the paper re-type for anchor `i` (AUTH-5.41: "the 64 hex typed once").
///
/// Fingerprint first (AUTH-5.39) — a wrong re-type says "re-scan" and asks
/// again; `Some(signer)` where the print passed, `None` where the person
/// declined.
///
/// # Errors
///
/// An abandoned re-type halts, and a typed seed that derives the right key
/// and still does not sign is this client's fault.
fn retype_from_print(person: &mut dyn Person, label: &Label, i: usize, fp: &Fingerprint) -> Result<Option<HybridSigner>, Halt> {
    loop {
        let typed = person
            .retype(Secret(Retype {
                prompt: format!("type the 64 hex of the SEED from the sheet for anchor {} (`{}`), then the first 8 hex of its fingerprint", if i == 0 { "a" } else { "b" }, label),
            }))
            .map_err(abandoned)?;
        match typed {
            Retyped::Declined => return Ok(None),
            Retyped::Typed { seed_hex, fingerprint_prefix } => {
                if let Some(signer) = Seed::from_hex(seed_hex.trim()).map(|seed| crate::sign::signer_from_seed(seed.bytes())) {
                    if Signer::fingerprint(&signer) == *fp && typed_prefix_matches(&fingerprint_prefix, fp) {
                        if !local_verify(&signer) {
                            return Err(Halt::face("the typed seed derives the right key and still does not sign", "the client-local sign-and-verify failed", "this is this client's fault"));
                        }
                        return Ok(Some(signer));
                    }
                }
                say(person, "AUTH-5.39", "this is not the key on this paper — re-scan");
            }
        }
    }
}

/// Reads the file back from the path it was written to.
///
/// It is the disk channel AUTH-5.41 names as the pinned order's own —
/// fingerprint first, then the client-local sign-and-verify; `None` where
/// it does not read back as the key it names.
fn read_back_from_file(path: &Path, public: &PublicKey, fp: &Fingerprint) -> Option<HybridSigner> {
    let file = KeyFile::parse(&read_key_file(path).ok()?).ok()?;
    if file.fingerprint != *fp || file.public != *public {
        return None;
    }
    let signer = file.signer();
    local_verify(&signer).then_some(signer)
}

/// Re-imports one exported anchor from its own artifact.
///
/// AUTH-5.54 step 4, "over a channel whose absence breaks it"; AUTH-5.59
/// step 3 cites it: under `paper` the 64 hex typed from the print (a
/// declined re-type falls to the file), else the file read back from the
/// path it was written to; fingerprint first (AUTH-5.39), then the
/// client-local sign/verify. `None` is step 3's failure arm — an enrolled
/// anchor whose private half exists nowhere — which the caller faces as
/// that rule says.
///
/// # Errors
///
/// An abandoned re-type halts, and a typed seed that derives the right key
/// and still does not sign is this client's fault.
pub fn reimport_anchor(person: &mut dyn Person, artifact: &AnchorArtifact, paper: bool, i: usize) -> Result<Option<HybridSigner>, Halt> {
    if paper {
        if let Some(signer) = retype_from_print(person, &artifact.label, i, &artifact.fingerprint)? {
            return Ok(Some(signer));
        }
    }
    let Some(path) = &artifact.file else { return Ok(None) };
    Ok(read_back_from_file(path, &artifact.public, &artifact.fingerprint))
}

/// Returns whether `signer` signs and verifies — step 5's client-local check.
///
/// It is checked against the pubkey about to be enrolled — no daemon
/// machinery.
pub fn local_verify(signer: &HybridSigner) -> bool {
    let msg = b"skep backup moment: client-local verify";
    let blob = HybridSigner::sign(signer, msg);
    skep_signature::verify(Signer::tag(signer), HybridSigner::public_key(signer), msg, &blob).is_ok()
}
