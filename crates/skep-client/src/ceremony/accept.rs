//! `accept` — THE RECIPIENT's beat (`client.md` §4c.1; AUTH-5.90; AUTH
//! RES-162): `--board` and `--account` REQUIRED (a run missing either asks,
//! generating nothing); THE READS FIRST — `/health` (the pair, the mode,
//! the A4 cell; at a served board the beat ASKS hosted-host or the giver's
//! own org, RES-45), `key_set` at `--account` MUST BE EMPTY (non-empty ⇒
//! halt: already handed away, the act the GIVER's — which makes a re-run
//! safe), `effective_owner(account)` with `prefix == account` THE
//! ALLOCATION TEST (unequal ⇒ halt: beat (a) still owed), AUTH-5.21's walk
//! upward whose terminus is ⟨giver⟩, `key_set` at `inc(--account, 1)`
//! (string (xi) where taken, (viii) where not), the ⟨m⟩ count by the cone,
//! the block clause's cell off `claimant`; then string (vi) ahead of
//! generation, `keygen --anchors`' walk with THIS DOOR's copy —
//! `Venue::Handoff` (the operator sentence per A4 cell rendered ONCE,
//! AUTH-5.44's HANDOFF form, AUTH-5.42's consequence keyed to this door, the
//! org-door artifact line DROPPED, the abandonment disposition);
//! `--no-anchors` the DECLINE's site (AUTH-5.62's sentence; AUTH-5.90's
//! decline clause; the cost its CONFIRMATION by a typed answer; no pair,
//! no backup moment); the ACCEPTANCE string (v) per cell with its shares
//! and block clauses; the ACCOUNT-CREATION sentence in the future tense
//! (AUTH-5.87); AUTH-5.85's statement scoped by the board's venue; THE
//! REPLY string (vii) on its arm with `skep bind` and what skipping it
//! costs (AUTH-5.90 (iii)); the three-key (or one-key) canonical record for
//! the giver; `--reprint` re-composing the record from the artifacts'
//! PUBLIC members alone. A PERSON DOOR; `--reprint` is not.

use std::path::{Path, PathBuf};

use skep_identity::{encode_enroll, Enrollment, Fingerprint};

use crate::board::{Board, KeySetAnswer};
use crate::ceremony::backup::{backup_moment, AnchorArtifact, BackupOptions, Venue};
use crate::ceremony::claim::store_halt;
use crate::ceremony::enumerate::by_reference_cone;
use crate::ceremony::reads::A4Cell;
use crate::derive::{first_child, parent_account, principal_of, walk_to_set, Mode};
use crate::halt::Halt;
use crate::person::{Confirmation, Consent, LabelBox, Person, Public, Question, Statement};
use crate::sheet::{render_inert, Facts, KeyFile};
use crate::store::{Binding, FileStore, KeySelector, KeyStore, Label, Purpose};

/// The beat's inputs.
#[derive(Debug, Clone)]
pub struct AcceptOptions {
    pub account: String,
    pub label: Option<String>,
    pub anchor_out: Vec<PathBuf>,
    pub paper: bool,
    pub no_anchors: bool,
    /// At a served board: the host is a HOSTED host (`Some(true)`), the
    /// giver's own org (`Some(false)`), or asked (`None`).
    pub hosted: Option<bool>,
    pub host: String,
    pub date: String,
}

/// What the beat made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    /// The canonical record for the giver.
    pub record: String,
    pub facts: Facts,
    pub device: Fingerprint,
    pub anchors: Vec<AnchorArtifact>,
    pub declined_pair: bool,
}

fn say(person: &mut dyn Person, rule: &'static str, text: impl Into<String>) {
    person.say(Public(Statement { rule, text: text.into() }));
}

fn abandoned() -> Halt {
    Halt::face("the beat was abandoned", "the person left", "re-run when ready; nothing was generated")
}

/// The operator sentence per A4 cell, in the recipient's own facts (string
/// (v)'s close; AUTH-5.43; AUTH RES-156).
fn operator_sentence(cell: &A4Cell, giver: &str, hosted: bool) -> String {
    match cell {
        A4Cell::Served if hosted => format!("Whoever runs this board can read what you write here before you publish it, and can withhold or delay it; anything they write in your name carries no signature of yours, and the app you install shows it as unsigned; on this board they can still retire your keys and continue as you, which every copy that checks signatures will show was not you; your way back is a fresh account. {giver} cannot: the rules give them no way to retire your keys here."),
        A4Cell::Served => format!("{giver}'s org runs this board: on it they can read what you write before you publish it, and withhold or delay it; anything they write in your name carries no signature of yours, and the app you install shows it as unsigned; they can still retire your keys and continue as you here, which every copy that checks signatures will show was not you; your way back is a fresh account. The rules give them no channel to; the daemon they run does."),
        _ => format!("{giver} runs this board: on it they can read what you write before you publish it, and withhold or delay it; anything they write in your name carries no signature of yours, and the app you install shows it as unsigned; they can still retire your keys and continue as you here, which every copy that checks signatures will show was not you; your way back is a fresh account. The rules give them no channel to; the daemon they run does."),
    }
}

/// The device-name box's statements at this door (AUTH-5.42).
fn device_box() -> Vec<String> {
    vec![
        "This name is permanent and cannot be edited: fixing a typo costs a keypair.".into(),
        "It is a byline: this name appears beside every write you make with this key, forever.".into(),
        "It holds the DEVICE's name — never your own and never your organisation's.".into(),
        "At this door the name rides the genesis record into the GIVER's own doc 1, on a board you may not be able to read, under a byline you can never correct.".into(),
    ]
}

/// THE BEAT.
pub fn accept(board: &Board, store: &FileStore, person: &mut dyn Person, opts: &AcceptOptions) -> Result<Accepted, Halt> {
    let account = opts.account.trim().to_string();
    if account.is_empty() || parent_account(&account).is_none() {
        return Err(Halt::face(
            format!("`{account}` is not a subdivision's address"),
            "AUTH RES-162: the giver's beat (a) is complete before the recipient's key generation, and the giver hands the recipient the ADDRESS over the channel the keys come back on; a top-level address is no handoff's",
            "ask the giver for the address and pass it as `--account <address>`",
        ));
    }
    // THE READS FIRST.
    let health = board.health()?;
    let mode = Mode::of(&health);
    if mode == Mode::Unclaimed {
        return Err(Halt::face("this board is unclaimed", "no account of a giver's exists here", "ask the giver which board the account is on"));
    }
    let seat = principal_of(board, &account)?;
    let Some(seat) = seat else {
        let above = board.effective_owner(&account)?.map(|o| format!("{} (principal {})", o.prefix, o.principal)).unwrap_or_else(|| "nothing".into());
        return Err(Halt::face(
            format!("{account} is not yet delegated: the giver's beat (a) is still owed"),
            format!("`effective_owner({account})` answers the seat above — {above} — and not this address (AUTH-6.37's allocation test); unfaced, this beat would print the giver's principal on your sheets as this account's own and mint a key set for an account that does not exist"),
            "the act is the GIVER's: `skep handoff --account <address>` without `--payload`; re-run `skep accept` once they hand you the address",
        ));
    };
    let own_set = match board.key_set(&account)? {
        KeySetAnswer::Set(s) => s,
        KeySetAnswer::NotAnAccount => Default::default(),
    };
    if !own_set.enrolled.is_empty() {
        return Err(Halt::face(
            format!("{account} already holds a key set: it has already been handed away"),
            "a NON-EMPTY `key_set` is exactly the signal that the account has been handed away (AUTH-6.19); a second run at a seeded address generates nothing",
            "the act is the GIVER's — ask them; this beat is safe to re-run",
        ));
    }
    let walk = walk_to_set(board, &account)?;
    if walk.terminus_empty() {
        return Err(Halt::face(format!("no key set opens {account} or anything above it"), "the walk from the address reached no set", "ask the giver which board the account is on"));
    }
    let giver = walk.set_account.clone();
    let cell = A4Cell::of(board, &health, &giver, &walk);
    let hosted = match (&cell, opts.hosted) {
        (A4Cell::Served, Some(h)) => h,
        (A4Cell::Served, None) => person.yes_no(Public(Question { text: "this is a SERVED board, and no read tells a HOSTED host from the giver's own org: is the party running it a hosting provider (yes), or the giver's own org (no)?".into() })).map_err(|_| abandoned())?,
        _ => false,
    };
    let first_space = first_child(&account);
    let first_space_taken = matches!(board.key_set(&first_space)?, KeySetAnswer::Set(s) if !s.enrolled.is_empty());
    let cone = by_reference_cone(board, person, std::slice::from_ref(&account))?;
    let m = cone.nodes.iter().filter(|c| c.seeded).count();
    let giver_is_member = health.claimant() != Some(giver.as_str());
    // String (vi) ahead of generation.
    say(person, "AUTH-5.90 (vi)", "(vi) Make a new key and two anchor sheets FOR THIS ACCOUNT. Do not reuse a key that opens another account of yours: keys are per account, so retiring it there does not retire it here.");
    // The device key into the store.
    let label = match &opts.label {
        Some(text) => {
            let l = Label::new(text).map_err(|f| Halt::face(format!("the label is refused at the box: {f}"), "AUTH-1.24's domain", "pass a label inside the domain"))?;
            for s in device_box() {
                say(person, "AUTH-5.42", s);
            }
            l
        }
        None => loop {
            let text = person.label(Public(LabelBox { title: "name this device".into(), statements: device_box(), default: None })).map_err(|_| abandoned())?;
            match Label::new(&text) {
                Ok(l) => break l,
                Err(fault) => say(person, "AUTH-1.24", format!("that name is refused at the box: {fault}; name the device again")),
            }
        },
    };
    let id = store.generate(Some(label.clone())).map_err(store_halt)?;
    let device = store.load(&store.key_path(&id.0)).map_err(store_halt)?;
    say(person, "§3a", format!("key file written: {} — the seed rests in this file and the filesystem's modes are its whole protection (0600 under 0700); your anchors are what its loss recovers from", store.key_path(&id.0).display()));
    let facts = Facts { account: account.clone(), principal: seat, origin: board.dialed.clone() };
    let operator = operator_sentence(&cell, &giver, hosted);
    // The pair, or the DECLINE at its site.
    let (anchors, declined_pair) = if opts.no_anchors {
        say(
            person,
            "AUTH-5.62",
            format!(
                "THE DECLINE (`--no-anchors`): a set born with no anchor can never gain one — a post-genesis anchor-flagged enrollment needs an ANCHOR SESSION in every mode (AUTH-3.20/3.22) — so AUTH-5.16's 'permanently impossible on this account' is this account's standing state from its genesis, and the loss of the one device key is AUTH-5.62 (ii)'s ANCHORLESS END at an account inside the giver's prefix that no party can act at, no retirement reaches and no report can end. WHAT ONLY AN ANCHOR SESSION COULD DO HERE AND WHAT A DEVICE KEY ALONE CAN DO AFTER: every subdivision this account comes to open by reference — the agents' home at {first_space}, every topic delegated after, their drafts with them — is takeable at a handoff genesis by this one device key alone, or by any copy of it; a copied device key then seizes what a paper would have held (AUTH-5.89's SEIZED class), and no later act restores the grade."
            ),
        );
        let typed = person.confirm_typed(Consent(Confirmation { text: "CONFIRM THE DECLINE of the anchor pair — type `decline` to accept these costs, or `no`".into(), expected: "decline".into() })).map_err(|_| abandoned())?;
        if typed.trim() != "decline" {
            return Err(Halt::face("the decline was not confirmed", "the device key was generated and no pair; nothing was handed out", "re-run without `--no-anchors` to take the pair, or confirm the decline"));
        }
        (Vec::new(), true)
    } else {
        let out = backup_moment(
            person,
            &Venue::Handoff { facts: facts.clone(), operator: operator.clone() },
            &BackupOptions { labels: Vec::new(), destinations: opts.anchor_out.clone(), paper: opts.paper, store: Some(store.root().to_path_buf()), host: opts.host.clone(), date: opts.date.clone() },
        )
        .map_err(|h| {
            Halt::face(
                format!("{h} — the beat stops before the payload"),
                format!("a run abandoned between the export and the reply leaves anchor artifacts that name {account} and open nothing — the set is still empty and the payload never went out: destroy them, or keep them plainly marked dead, never filed beside a live pair (their per-run token tells them apart)"),
                "re-run this beat; a seeded address stops it before anything is generated",
            )
        })?;
        (out.anchors, false)
    };
    // THE ACCEPTANCE, string (v) per cell, with the shares and block clauses.
    say(person, "AUTH-5.90 (v)", format!("(v) What you write here can be read by {giver} and by everyone above them, forever — and by whoever any account above this one is later given to, which nothing here tells you. This account cannot move. {operator} Anything this account already shared stays shared until you withdraw it — whoever it was shared with reads what you write here until then; this account's home page lists those shares."));
    if giver_is_member {
        say(person, "AUTH-5.90 (v) block", format!("If {giver}'s account is ever blocked on this board, this account is blocked with it: it sits under theirs."));
    }
    if m > 0 {
        say(person, "AUTH-5.90 (x)", format!("(x) {m} of the spaces under {account} were given away before it came to you. Whoever holds their keys reads everything you write here, forever, and nothing of yours removes them — and from this write you read everything they write there."));
    }
    if first_space_taken {
        say(person, "AUTH-5.90 (xi)", "(xi) This account's first space is already taken; your agents will have no home here.");
    } else {
        say(person, "AUTH-5.90 (viii)", format!("(viii) Your agents' home will be {first_space}; giving that account away gives your agents' home away."));
        say(person, "AUTH-5.87", "creating your account will also create a space for your agents beneath it, and its home — reserved by your own hand at `skep bind`");
    }
    // AUTH-5.85's statement, scoped by the board's VENUE.
    let notebook = board.dialed.names_loopback_host() && health.origins().iter().all(|o| crate::origin::Origin::parse(o).is_some_and(|x| x.names_loopback_host()));
    if notebook {
        say(person, "AUTH-5.85", format!("every edit to this page, including what you later remove, is kept — this notebook's history is permanent, and it is local: no mirror holds it and this board can never be made public; the records this page holds (your keys, the grants you issue) stand as records of their own, so removing the text one names does not remove it: the record stays in force, and the version you removed it from remains readable{}", if health.local_trust() { "; and local means the machine this board runs on: while local trust is on, anything running on it can bare-bind as you here — writing as you, and reading every draft you have already written, with no mint at all" } else { "" }));
    } else {
        say(person, "AUTH-5.85", "every edit to this page, including what you later remove, is public history — and the records this page holds (your keys, the grants you issue) stand as records of their own, so removing the text one names does not remove it: the record stays in force, and the version you removed it from remains readable");
    }
    // THE REPLY, string (vii) per arm, with `skep bind` and what skipping it costs.
    let keep = if declined_pair { "Keep this somewhere you control" } else { "Keep this with your papers" };
    say(
        person,
        "AUTH-5.90 (vii)",
        format!(
            "(vii) the giver will return: \"{keep}: {account}, principal {seat}, {}. Nothing else on this board tells you which account is yours.\" — land it with `skep bind --board {} --dir <store> --account {account} --principal {seat}{}`, which runs this account's FIRST SIGNED SESSION in its pinned order: the doc-1 mint, then the setup act. Until it runs this account has NO DOC 1: the first note written here becomes a DRAFT doc 1 and answers `unpublished` at every later credential act with no clearing act, and every credential write homes its atom in a document the board does not hold — the papers just printed reaching a recovery, a rotation and an enrollment that all land there (AUTH-5.90 (iii)).",
            board.dialed,
            board.dialed,
            if declined_pair { String::new() } else { " --anchor <a> --anchor <b>".into() }
        ),
    );
    // The record for the giver: the anchors, then the device key.
    let mut entries: Vec<Enrollment> = anchors.iter().map(|a| Enrollment::new(a.public.clone(), true, Some(a.label.as_str().to_string())).expect("a label the box admitted")).collect();
    entries.push(Enrollment::new(device.public.clone(), false, Some(label.as_str().to_string())).expect("a label the box admitted"));
    let record = encode_enroll(&entries);
    say(person, "AUTH-4.59", "hand the record (on stdout) to the giver over the channel the address came by; they compare the fingerprint with you before anything depends on it — the outstanding act is their genesis and their reply, then `skep bind` here (`skep accept --reprint` re-prints this record from the artifacts)");
    Ok(Accepted { record, facts, device: device.fingerprint, anchors, declined_pair })
}

/// `--reprint [--anchor <path>]…`: the record re-composed from the
/// artifacts' PUBLIC members alone — `public`, `fingerprint`, `anchor`,
/// `label` — no seed loaded past the parse's own re-derivation, nothing
/// written; the device key from `key` or the store's lone UNBOUND device
/// key. A `--paper` file destroyed under AUTH-5.41's offer halts: the act is
/// a re-run under a fresh pair.
pub fn reprint(store: &FileStore, key: Option<&Path>, anchors: &[PathBuf], board: Option<&crate::origin::Origin>) -> Result<String, Halt> {
    let mut entries = Vec::new();
    for path in anchors {
        if !path.is_file() {
            return Err(Halt::face(
                format!("no artifact remains at {}", path.display()),
                "a `--paper` file destroyed under AUTH-5.41's offer composes nothing: the record needs the anchor FILES, which by rule never enter the store",
                "re-run `skep accept` under a fresh pair, the dead one disposed of as the abandonment exit says",
            ));
        }
        let file = store.select(&KeySelector::Path(path), Purpose::Read).map_err(store_halt)?.file;
        if !file.anchor {
            return Err(Halt::face(format!("{} is a device key's file", path.display()), "`--anchor` names an anchor file", "pass the anchor files the beat wrote"));
        }
        entries.push(Enrollment::new(file.public.clone(), true, file.label.clone()).expect("a stored label"));
    }
    let device: KeyFile = match key {
        Some(path) => store.select(&KeySelector::Path(path), Purpose::Read).map_err(store_halt)?.file,
        None => {
            let bound: Vec<Fingerprint> = store
                .all_bindings()
                .map_err(store_halt)?
                .into_iter()
                .filter_map(|b| match b {
                    Binding::Enrollment { origin, fingerprint, .. } if board.is_none_or(|o| *o == origin) => Some(fingerprint),
                    _ => None,
                })
                .collect();
            let keys = store.list().map_err(store_halt)?;
            let unbound: Vec<_> = keys.iter().filter(|k| !k.anchor && !bound.contains(&k.fingerprint)).collect();
            match unbound.as_slice() {
                [one] => store.load(&one.path).map_err(store_halt)?,
                [] => return Err(Halt::face("no unbound device key stands in this store", "the beat's device key is bound at no board until `skep bind` lands the reply", "name the key with `--key <path>`")),
                many => {
                    return Err(Halt::face(
                        "more than one unbound device key stands in this store",
                        many.iter().map(|k| format!("{} {}", k.fingerprint, k.label.as_deref().map(render_inert).unwrap_or_default())).collect::<Vec<_>>().join("\n  "),
                        "name the key with `--key <path>`; never a pick",
                    ))
                }
            }
        }
    };
    entries.push(Enrollment::new(device.public.clone(), false, device.label.clone()).expect("a stored label"));
    Ok(encode_enroll(&entries))
}
