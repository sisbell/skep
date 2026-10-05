//! THE BACKUP MOMENT in AUTH-5.54's pinned order (`client.md` §4.2; RULED,
//! owner 2026-09-09: "THE BACKUP'S DEFAULT IS THE FILE FORM … PAPER IS OPT-IN
//! by flag, and only the paper path prints the seed and asks for the re-type
//! from the paper"): the three statements at the HEAD (AUTH-5.54 (a)–(c)),
//! the two anchor boxes with their per-run defaults and the domain test at
//! the box (AUTH-5.42; AUTH-1.24), generate (step 1), EXPORT (step 2) — each
//! anchor to its own destination, `O_EXCL` `0600`, never under the store
//! (§3.4), the ladder words at the path (AUTH-5.40) and the one-place
//! sentence where both land in one place — the sheet besides under `--paper`,
//! the DROP (step 3), the DISMISSAL on the paper path (§4.2 step 6), the
//! RE-IMPORT over a channel whose ABSENCE breaks it (step 4: the file read
//! back from the path it wrote, or the 64 hex typed from the print),
//! fingerprint FIRST then the client-local sign-and-verify (step 5;
//! AUTH-5.39), AUTH-5.41 where both exist, the keep-the-papers line KEYED
//! PER SITE (AUTH-5.44; §4.2 step 10) — and ONLY THEN the caller's genesis
//! (step 6). A file-path read-back that fails RE-RUNS FROM STEP 1 under a
//! fresh pair, the bad file destroyed (§4.1 S3).

use std::path::{Path, PathBuf};

use skep_identity::{Fingerprint, PublicKey};
use skep_signature::HybridSigner;

use crate::halt::Halt;
use crate::person::{Abandoned, Destination, LabelBox, Person, Public, Question, Retype, Retyped, Secret, Sheet, Statement};
use crate::sheet::{Facts, KeyFile, Seed};
use crate::sign::{fresh_bytes, fresh_seed, Signer};
use crate::store::{FileStore, Label};

/// The venue the moment runs at — the copy is keyed by it (P7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Venue {
    /// `claim`'s S3: host and owner one party; the artifact carries the
    /// three facts (AUTH-5.38) and the keep-the-papers line takes the
    /// NOTEBOOK form.
    Notebook { facts: Facts },
    /// `keygen --anchors`: someone else's board — statement (a) carries the
    /// operator sentence unconditionally (AUTH-5.43's create-org sibling),
    /// the artifact lacks the address, the principal AND the origin, and
    /// the line is AUTH-5.44's create-org arm.
    DoorSide,
    /// `accept`'s beat (`client.md` §4c.1): the RECIPIENT's own facts —
    /// the artifact carries the address, the principal and the origin
    /// (AUTH-5.38; AUTH RES-162) — statement (a) carrying THE RECIPIENT'S
    /// BEAT'S OWN operator sentence per A4 cell, rendered ONCE (`operator`;
    /// AUTH RES-156), the anchor boxes' consequence keyed to this door (the
    /// label rides the genesis into the GIVER's doc 1, AUTH-5.42), the line
    /// AUTH-5.44's HANDOFF form verbatim, the org-door artifact line DROPPED.
    Handoff { facts: Facts, operator: String },
    /// `recover --anchor-lost`'s L3 (`client.md` §4a.6): AUTH-5.54 steps 1–3
    /// CITED, not inherited — the statements NOT re-rendered save (b) in its
    /// file-venue form, the boxes answered at L1 (given as `labels`), the
    /// export and the DROP, and NO read-back here: L5 re-imports each anchor
    /// from its artifact after L4's enroll ([`reimport_anchor`]).
    LossArm { facts: Facts },
}

/// The moment's inputs.
#[derive(Debug, Clone)]
pub struct BackupOptions {
    /// `--anchor-label`, up to two; a box asks where one is absent.
    pub labels: Vec<Label>,
    /// `--anchor-out`, ONE DESTINATION PER ANCHOR (0, 1 or 2 given); the
    /// destination is asked for where absent — NO default (§6).
    pub destinations: Vec<PathBuf>,
    /// `--paper`: the sheet printed besides, and the re-type asked.
    pub paper: bool,
    /// The store, whose paths are refused as destinations (§3.4).
    pub store: Option<PathBuf>,
    /// The machine's host name and the date, for the per-run default.
    pub host: String,
    pub date: String,
}

/// One exported anchor's PUBLIC facts — never the seed, which was dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorArtifact {
    pub public: PublicKey,
    pub fingerprint: Fingerprint,
    pub label: Label,
    /// The file, where it stands (destroyed under AUTH-5.41's offer: `None`).
    pub file: Option<PathBuf>,
    /// The print passed its re-type — the KEPT artifact is the print.
    pub print_verified: bool,
    /// A print exists (under `--paper`) and was NOT verified — labelled so.
    pub print_unverified: bool,
}

/// The moment's outcome: two anchors, public facts alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupOutcome {
    pub anchors: Vec<AnchorArtifact>,
    /// Both files landed in one place — (b)'s file-venue words were said.
    pub one_place: bool,
}

fn say(person: &mut dyn Person, rule: &'static str, text: impl Into<String>) {
    person.say(Public(Statement { rule, text: text.into() }));
}

fn abandoned(e: Abandoned) -> Halt {
    Halt::face(
        format!("{e}"),
        "the backup moment was abandoned before its genesis write",
        "see the walk's own abandonment exit: the artifacts already made open nothing and are destroyed or kept plainly marked dead",
    )
}

/// The three statements at the head (AUTH-5.54 (a)–(c)), keyed to the path
/// this run takes and to the venue.
fn statements(person: &mut dyn Person, venue: &Venue, paper: bool) {
    let operator = match venue {
        Venue::Notebook { .. } | Venue::LossArm { .. } => String::new(),
        Venue::DoorSide => " — on the board you are joining another party runs the daemon: it can read what you write there before you publish it and withhold or delay it; anything it writes in your name carries no signature of yours, and the app you install shows it as unsigned; it never learns your keys and can never act as you anywhere else; on that board it can still retire your keys and continue as you, which every copy that checks signatures will show was not you; your way back is a fresh account, and the board is portable (AUTH-5.43's create-org sibling; AUTH-4.54)".to_string(),
        Venue::Handoff { operator, .. } => format!(" — {operator}"),
    };
    // The LOSS arm re-renders statement (b) ALONE (§4a.6 L3): this person
    // has just lost an anchor and is one artifact from AUTH-5.16's
    // both-unheld state, which is the exact loss (b) is about.
    if !matches!(venue, Venue::LossArm { .. }) {
        say(
            person,
            "AUTH-5.54 (a)",
            format!(
                "(a) THIS KEY SET IS THIS IDENTITY AND THERE IS NO RESET: no one holds a re-key power over this account and nothing \
                 in the protocol restores it to a person who holds none of its keys — there is no reset to ask an operator, host, \
                 officer or registrar for, the rules giving none of them a channel{operator}."
            ),
        );
    }
    let b = if paper {
        "(b) PRINT TWO, KEEP THEM APART: the pair is two papers so that one place that burns, floods or is searched cannot take \
         both — two papers, kept in two places ONCE THIS IS FINISHED; you will need both here in a moment."
    } else {
        "(b) TWO FILES, TWO PLACES YOU CONTROL: the pair is two files so that one place that burns, floods or is searched cannot \
         take both — two files, in two places you control ONCE THIS IS FINISHED; you will need both here in a moment."
    };
    say(person, "AUTH-5.54 (b)", b);
    if matches!(venue, Venue::LossArm { .. }) {
        return;
    }
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

/// The anchor box (AUTH-5.42's anchor copy): names the SHEET, never where
/// you keep it; a default DERIVED PER RUN — host, date, a per-run token
/// (§4.2 step 2); the domain test at the box, re-asked on a refusal.
fn anchor_box(person: &mut dyn Person, venue: &Venue, which: &str, default: String) -> Result<Label, Halt> {
    let consequence = match venue {
        Venue::Notebook { .. } | Venue::LossArm { .. } => "at this notebook the name is readable by anything on the machine (AUTH-5.85's reader clause)",
        Venue::DoorSide => "at the door this payload serves the name rides onto a public thread, approved or DENIED, forever",
        Venue::Handoff { .. } => "at this door the name rides the genesis record into the GIVER's own doc 1, on a board you may not be able to read, under a byline you can never correct (AUTH-5.42)",
    };
    let statements = vec![
        "This names the SHEET and never where you keep it — the one human-navigable field on an otherwise machine-facing paper, so you can tell the two sheets apart.".to_string(),
        "It is public forever and uncorrectable: fixing a typo costs a keypair.".to_string(),
        "This is not the device's name and not your own: the display name is a separate, changeable label collected elsewhere.".to_string(),
        consequence.to_string(),
    ];
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

/// The ladder words at the file's path (AUTH-5.40), venue-keyed: ending at
/// "move it to media you control" on the file-only path, the print clause
/// under `--paper` alone (RES-62 item 7).
fn ladder_words(path: &Path, paper: bool) -> String {
    let tail = if paper { ", or destroy it and keep the print" } else { "" };
    format!(
        "anchor file written: {} — an exported file that syncs, rides into a backup, or sits on a shared machine IS a FINDABLE \
         PAPER, the ladder's worst rung, so move it to media you control{tail}",
        path.display()
    )
}

/// The destination for anchor `which`: the flag's, or asked (SECRET), a path
/// inside the store refused (§3.4; §6).
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

/// The file name: `anchor-<label slug>-<8 hex of fingerprint>.skep-key` (§6).
pub fn anchor_file_name(label: &Label, fp: &Fingerprint) -> String {
    format!("anchor-{}-{}.skep-key", label.slug(), &fp.to_hex()[..8])
}

/// THE MOMENT.
pub fn backup_moment(person: &mut dyn Person, venue: &Venue, opts: &BackupOptions) -> Result<BackupOutcome, Halt> {
    // Step 1 (the head): the three statements, before any generation.
    statements(person, venue, opts.paper);
    // Step 2: the two boxes, between the statements and the export.
    let token = crate::hex::encode(&fresh_bytes(2));
    let mut labels: Vec<Label> = Vec::new();
    for (i, which) in ["a", "b"].iter().enumerate() {
        let label = match opts.labels.get(i) {
            Some(l) => {
                // The box's statements render whenever a label is fixed, flag or
                // prompt alike (§2.2 `keygen`).
                say(person, "AUTH-5.42", format!("anchor {which} is named `{}`: this names the SHEET and never where you keep it; public forever and uncorrectable", crate::sheet::render_inert(l.as_str())));
                l.clone()
            }
            None => anchor_box(person, venue, which, format!("{}-{}-{token}-{which}", opts.host, opts.date))?,
        };
        labels.push(label);
    }
    let facts = match venue {
        Venue::Notebook { facts } | Venue::Handoff { facts, .. } | Venue::LossArm { facts } => Some(facts),
        Venue::DoorSide => None,
    };
    for attempt in 0..3 {
        match run_once(person, venue, opts, &labels, facts, attempt)? {
            Some(outcome) => return Ok(outcome),
            None => say(person, "§4.1 S3", "the moment re-runs from step 1 under a fresh pair"),
        }
    }
    Err(Halt::face(
        "the backup moment could not complete",
        "three runs in a row failed their read-back",
        "check the destination media and re-run `skep claim`; every artifact written names no live pair and opens nothing",
    ))
}

/// Steps 3–10 for one pair; `None` where the file path's read-back failed
/// and the moment re-runs.
fn run_once(person: &mut dyn Person, venue: &Venue, opts: &BackupOptions, labels: &[Label], facts: Option<&Facts>, attempt: usize) -> Result<Option<BackupOutcome>, Halt> {
    // Step 3: generate the pair.
    let seeds: Vec<[u8; 32]> = (0..2).map(|_| fresh_seed()).collect();
    let mut files: Vec<KeyFile> = seeds.iter().zip(labels).map(|(s, l)| KeyFile::new(Seed::new(*s), true, Some(l.as_str().to_string()), facts)).collect();
    let publics: Vec<(PublicKey, Fingerprint)> = files.iter().map(|f| (f.public.clone(), f.fingerprint)).collect();
    // Step 4: EXPORT — the file, each to its own destination.
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut dirs: Vec<PathBuf> = Vec::new();
    for (i, file) in files.iter().enumerate() {
        let dir = destination(person, opts, i)?;
        std::fs::create_dir_all(&dir).map_err(|e| Halt::face(format!("the destination {} cannot be made", dir.display()), e.to_string(), "name a directory you control"))?;
        let path = dir.join(anchor_file_name(&labels[i], &file.fingerprint));
        FileStore::write_once(&path, file.to_json().as_bytes()).map_err(|e| {
            Halt::face(format!("the anchor file {} could not be written", path.display()), e.to_string(), "name a directory you control, writable and not a `--rm` container's own filesystem")
        })?;
        say(person, "AUTH-5.40", ladder_words(&path, opts.paper));
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
    // Step 5: DROP — the seeds zeroed, the signers released, before anything
    // is read back.
    drop(std::mem::take(&mut files));
    // Step 6: DISMISS, the paper path alone.
    if opts.paper {
        person.dismiss();
    }
    // THE LOSS ARM stops at the DROP: the re-import is L5's, run from each
    // artifact AFTER L4's enroll with a probe handshake (AUTH-5.59 step 3),
    // so the artifacts are answered now, read back by nothing yet.
    if matches!(venue, Venue::LossArm { .. }) {
        let anchors = paths
            .iter()
            .enumerate()
            .map(|(i, path)| AnchorArtifact {
                public: publics[i].0.clone(),
                fingerprint: publics[i].1,
                label: labels[i].clone(),
                file: Some(path.clone()),
                print_verified: false,
                print_unverified: opts.paper,
            })
            .collect();
        return Ok(Some(BackupOutcome { anchors, one_place }));
    }
    // Steps 7–9: RE-IMPORT, fingerprint first, the client-local verify.
    let mut anchors = Vec::new();
    for (i, path) in paths.iter().enumerate() {
        let (public, fp) = &publics[i];
        let mut print_verified = false;
        let mut print_unverified = false;
        let mut from_file = true;
        if opts.paper {
            match retype_from_print(person, &labels[i], i, fp)? {
                Some(_) => {
                    print_verified = true;
                    from_file = false;
                }
                None => print_unverified = true,
            }
        }
        if from_file {
            // The file read back from the path it wrote — the disk channel.
            if read_back_from_file(path, public, fp).is_none() {
                say(person, "§4.1 S3", format!("the anchor file {} did not read back as the key it names; it is destroyed (never a verified artifact) and the moment re-runs (attempt {})", path.display(), attempt + 1));
                for p in &paths {
                    let _ = std::fs::remove_file(p);
                }
                return Ok(None);
            }
        }
        // Step 9: AUTH-5.41 where BOTH exist and the print passed — offer to
        // destroy the file, never the act unasked.
        let mut file = Some(path.clone());
        if print_verified {
            let destroy = person
                .yes_no(Public(Question { text: format!("the print of anchor {} passed its re-type and is the KEPT artifact; destroy the file {} and keep the print? (AUTH-5.40)", labels[i], path.display()) }))
                .map_err(abandoned)?;
            if destroy {
                let _ = std::fs::remove_file(path);
                file = None;
            }
        }
        if print_unverified {
            say(person, "AUTH-5.41", format!("anchor {}: the print is UNVERIFIED and the file {} is the verified artifact; a verified artifact is never destroyed in favor of an unverified one", labels[i], path.display()));
        }
        anchors.push(AnchorArtifact { public: public.clone(), fingerprint: *fp, label: labels[i].clone(), file, print_verified, print_unverified });
    }
    // Step 10: the keep-the-papers line, KEYED PER SITE (AUTH-5.44).
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
        // THE HANDOFF FORM, verbatim (AUTH-5.44; `client.md` §4c.1): the
        // RECIPIENT's own facts, the only site where the papers' holder is not
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
        Venue::LossArm { .. } => {}
    }
    Ok(Some(BackupOutcome { anchors, one_place }))
}

/// The paper re-type for anchor `i` (AUTH-5.41: "the 64 hex typed once"),
/// fingerprint FIRST (AUTH-5.39) — a wrong re-type says "re-scan" and asks
/// again; `Some(signer)` where the print passed, `None` where the person
/// declined.
pub fn retype_from_print(person: &mut dyn Person, label: &Label, i: usize, fp: &Fingerprint) -> Result<Option<HybridSigner>, Halt> {
    loop {
        let typed = person
            .retype(Secret(Retype {
                prompt: format!("type the 64 hex of the SEED from the sheet for anchor {} (`{}`), then the first 8 hex of its fingerprint", if i == 0 { "a" } else { "b" }, label),
            }))
            .map_err(abandoned)?;
        match typed {
            Retyped::Declined => return Ok(None),
            Retyped::Typed { seed_hex, fingerprint_prefix } => {
                let seed = crate::hex::decode32(seed_hex.trim());
                let signer = seed.map(|s| crate::sign::signer_from_seed(&s));
                let derived = signer.as_ref().map(Signer::fingerprint);
                let prefix_ok = fingerprint_prefix.len() >= 8 && fp.to_hex().starts_with(fingerprint_prefix.trim());
                if derived == Some(*fp) && prefix_ok {
                    let signer = signer.expect("derived");
                    if !local_verify(&signer) {
                        return Err(Halt::face("the typed seed derives the right key and still does not sign", "the client-local sign-and-verify failed", "this is this client's fault"));
                    }
                    return Ok(Some(signer));
                }
                say(person, "AUTH-5.39", "this is not the key on this paper — re-scan");
            }
        }
    }
}

/// The file read back from the path it was written to — the disk channel
/// AUTH-5.41 names as the pinned order's own — fingerprint first, then the
/// client-local sign-and-verify; `None` where it does not read back as the
/// key it names.
pub fn read_back_from_file(path: &Path, public: &PublicKey, fp: &Fingerprint) -> Option<HybridSigner> {
    let file = KeyFile::parse(&std::fs::read(path).ok()?).ok()?;
    if file.fingerprint != *fp || file.public != *public {
        return None;
    }
    let signer = file.signer();
    local_verify(&signer).then_some(signer)
}

/// THE RE-IMPORT of one exported anchor from ITS artifact (AUTH-5.54 step
/// 4, "over a channel whose ABSENCE breaks it"; AUTH-5.59 step 3 cites it):
/// under `paper` the 64 hex typed from the print (a declined re-type falls
/// to the file), else the file read back from the path it was written to;
/// fingerprint FIRST (AUTH-5.39), then the client-local sign/verify. `None`
/// is step 3's FAILURE ARM — an enrolled anchor whose private half exists
/// nowhere — which the caller faces as that rule says.
pub fn reimport_anchor(person: &mut dyn Person, artifact: &AnchorArtifact, paper: bool, i: usize) -> Result<Option<HybridSigner>, Halt> {
    if paper {
        if let Some(signer) = retype_from_print(person, &artifact.label, i, &artifact.fingerprint)? {
            return Ok(Some(signer));
        }
    }
    let Some(path) = &artifact.file else { return Ok(None) };
    Ok(read_back_from_file(path, &artifact.public, &artifact.fingerprint))
}

/// Step 5's client-local check: sign and verify against the pubkey about
/// to be enrolled — no daemon machinery.
pub fn local_verify(signer: &HybridSigner) -> bool {
    let msg = b"skep backup moment: client-local verify";
    let blob = HybridSigner::sign(signer, msg);
    skep_signature::verify(Signer::tag(signer), HybridSigner::public_key(signer), msg, &blob).is_ok()
}
