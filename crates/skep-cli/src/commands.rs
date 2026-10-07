//! THE THIRTEEN COMMANDS, each exactly as `client.md` §2.2 writes it — one
//! function per command, every walk a library call, stdout DATA and stderr
//! TALK (§2.4), §2.3's exit codes. A halt is one block on stderr: the
//! state, its cause, the one act (AUTH-5.66; AUTH-5.67's key-file cell
//! naming the path and the state). THE PERSON DOORS — `claim`'s notebook
//! arm, `keygen --anchors`, `enroll`'s comparison, `recover`, `retire`,
//! `rotate`, `handoff` with `--payload`, `accept` without `--reprint` —
//! refuse without a controlling terminal through the CLI's `Person` (§2.4:
//! the CLI's check, never the walk's).

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use skep_client::board::{Board, KeySetAnswer, Scope, Token};
use skep_client::ceremony::accept::{self as accept_walk, AcceptOptions};
use skep_client::ceremony::backup::{backup_moment, BackupOptions, Venue};
use skep_client::ceremony::claim::{self, ClaimOutcome, HostedOutcome, NotebookOptions};
use skep_client::ceremony::enroll::{self as enroll_walk, EnrollOptions};
use skep_client::ceremony::handoff::{self as handoff_walk, HandoffOptions, HandoffOutcome};
use skep_client::ceremony::recover::{self as recover_walk, RecoverOptions};
use skep_client::ceremony::retire::{self as retire_walk, RetireEnd, RetireOptions};
use skep_client::ceremony::rotate::{self as rotate_walk, RotateOptions};
use skep_client::person::{Person, Public, Question};
use skep_client::ceremony::first_session::{first_session, FirstSessionReads};
use skep_client::ceremony::handshake::{handshake, key_face, Site};
use skep_client::derive::records::{compare_whole_set, credential_records, Difference, Held};
use skep_client::derive::{origin_arm, precheck, principal_of, walk_to_set, Mode};
use skep_client::dial::{plaintext_non_loopback_warning, PlainHttp};
use skep_client::halt::Halt;
use skep_client::sheet::{group_hex, render_inert, Label};
use skep_client::store::{arm4_face, Binding, FileStore, KeyFacts, KeySelector, KeyStore, Purpose, StoreError};
use skep_identity::{encode_enroll, Enrollment, Fingerprint};

use crate::args::{Command, Usage};
use crate::terminal::{has_terminal, Terminal};

/// DATA, to stdout.
fn data(line: impl AsRef<str>) {
    println!("{}", line.as_ref());
}

/// TALK, to stderr.
fn talk(line: impl AsRef<str>) {
    eprintln!("{}", line.as_ref());
}

/// A halt rendered as its one block, its exit code answered.
fn halt(h: Halt) -> i32 {
    talk(format!("skep: {h}"));
    h.exit_code()
}

fn usage(u: Usage) -> i32 {
    talk(format!("skep: {}\n\n{}", u.0, crate::usage()));
    2
}

/// The missing-TTY face (§2.4; §2.3's exit 3).
fn no_terminal(door: &str) -> i32 {
    talk(format!(
        "skep: `{door}` is a person door and requires a controlling terminal — it reads its prompts from the terminal and refuses \
         without one, so a wrapper over stderr and stdin cannot satisfy the backup moment with no paper and no person. A script \
         that must drive this walk drives the library's scripted Person in-process."
    ));
    3
}

fn board_of(c: &Command) -> Result<Board, Usage> {
    let origin = c.board()?;
    Ok(Board::new(origin, PlainHttp::new()))
}

fn store_of(c: &Command) -> Result<FileStore, Usage> {
    Ok(FileStore::open(c.dir()?))
}

/// The machine's host name and today's date — the anchor boxes' per-run
/// default (§4.2 step 2).
fn host_name_and_date() -> (String, String) {
    let host_name = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string()))
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "this-machine".to_string());
    let host_name = host_name.split('.').next().unwrap_or("this-machine").to_lowercase();
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    (host_name, civil_date(secs))
}

/// `yyyy-mm-dd` from unix seconds (Howard Hinnant's civil-from-days).
fn civil_date(secs: u64) -> String {
    let z = (secs / 86400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// AUTH-5.42's statements, rendered whenever a label is fixed — prompt or
/// flag alike (§2.2 `keygen`), keyed to the venue.
fn device_box_statements(door_side: bool) -> Vec<String> {
    let venue = if door_side {
        "it rides onto a public thread, approved or denied; and not every write under this byline is yours — the party that operates the board you join can write as you there, visibly and permanently, which every copy that checks signatures will show was not you"
    } else {
        "at this notebook it is readable by anything on the machine"
    };
    vec![
        "This name is permanent and cannot be edited: fixing a typo costs a keypair.".to_string(),
        "It is a byline: this name appears beside every write you make with this key, forever.".to_string(),
        "It holds the DEVICE's name — never your own and never your organisation's; a display name is a separate, changeable label.".to_string(),
        venue.to_string(),
    ]
}

/// The key file's custody line beside its path (§3a, RULED; §9 items 4, 5,
/// 38: the ladder alone until the store-location spike answers).
fn custody_line(path: &Path) -> String {
    format!(
        "key file written: {} — the seed rests in this file and the filesystem's modes are its whole protection (0600 under 0700): a \
         same-user process reads it and a disk image carries it; your anchors, where the account this key joins holds them, are what \
         its loss recovers from (`skep recover`); an account founded from this key's own one-key record holds none, and there the one \
         way back is the enroll hop from another signed-in device",
        path.display()
    )
}

/// `keygen --payload`'s one line of outstanding-act text (AUTH-5.32: the
/// generating client holds the pending state), conditioned on the walk.
fn outstanding_act_line() -> &'static str {
    "this key is not enrolled anywhere yet. Where it ADDS a device: take this payload to a device already signed in, run `skep enroll` \
     there, and bring its three facts back to `skep bind` here. Where it REPLACES a machine: `skep rotate --payload` there instead, then \
     `skep bind` here. Where no board has been claimed from this store at all: `skep claim`. Where this key was made for a handoff at \
     `skep accept`: the outstanding act is the giver's genesis and their reply, then `skep bind`."
}

// ── keygen ──────────────────────────────────────────────────────────────

pub fn keygen(c: &Command) -> i32 {
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    let anchors = c.switch("--anchors");
    if anchors && !has_terminal() {
        return no_terminal("keygen --anchors");
    }
    let mut person = Terminal::new();
    // The device-name box: `--label`, or asked; the statements whenever a
    // label is fixed; the domain test at the box (P13).
    let label = match c.value("--label", None) {
        Some(text) => match Label::new(&text) {
            Ok(l) => {
                for s in device_box_statements(anchors) {
                    talk(format!("[AUTH-5.42] {s}"));
                }
                l
            }
            Err(fault) => return halt(Halt::face(format!("the label is refused at the box: {fault}"), "AUTH-1.24's domain: non-empty, no line break, at most 128 bytes of UTF-8", "pass a label inside the domain")),
        },
        None => {
            use skep_client::person::{LabelBox, Person, Public};
            loop {
                let text = match person.label(Public(LabelBox { title: "name this device".into(), statements: device_box_statements(anchors), default: None })) {
                    Ok(t) => t,
                    Err(_) => return halt(Halt::face("no device name was given", "the box was abandoned", "run `skep keygen --label <name>`, or answer the box")),
                };
                match Label::new(&text) {
                    Ok(l) => break l,
                    Err(fault) => talk(format!("[AUTH-1.24] that name is refused at the box: {fault}")),
                }
            }
        }
    };
    let id = match store.generate(Some(label.clone())) {
        Ok(id) => id,
        Err(e) => return halt(e.into()),
    };
    let path = store.key_path(&id.0);
    let key = match store.select(&KeySelector::Path(&path), Purpose::Read) {
        Ok(k) => k,
        Err(e) => return halt(e.into()),
    };
    talk(custody_line(&path));
    let mut entries = Vec::new();
    if anchors {
        // THE DOOR-SIDE FORM (AUTH-5.57 step 2): the backup moment for an
        // anchor pair with no board, statement (a) carrying the operator
        // sentence unconditionally; then the three-key payload for the
        // hosted signup.
        let labels: Vec<Label> = match c.all("--anchor-label").iter().map(|l| Label::new(l)).collect::<Result<Vec<_>, _>>() {
            Ok(ls) => ls,
            Err(fault) => return halt(Halt::face(format!("an anchor label is refused at the box: {fault}"), "AUTH-1.24's domain", "pass labels inside the domain")),
        };
        let (host_name, date) = host_name_and_date();
        let opts = BackupOptions {
            labels,
            destinations: c.all("--anchor-out").into_iter().map(PathBuf::from).collect(),
            paper: c.switch("--paper"),
            store: Some(store.root().to_path_buf()),
            host_name,
            date,
        };
        let outcome = match backup_moment(&mut person, &Venue::DoorSide, &opts) {
            Ok(o) => o,
            Err(h) => {
                talk("this form delegates nothing and leaves no board state behind: any anchor file written names no account and opens nothing, ever — destroy it, or keep it plainly marked dead and never beside a live pair");
                return halt(h);
            }
        };
        for a in &outcome.anchors {
            entries.push(Enrollment::new(a.public.clone(), true, Some(a.label.as_str().to_string())).expect("a label the box admitted"));
        }
    }
    entries.push(Enrollment::new(key.public.clone(), false, Some(label.as_str().to_string())).expect("a label the box admitted"));
    if c.switch("--payload") || anchors {
        // The record FIRST (§2.2): one canonical JSON object.
        data(encode_enroll(&entries));
        if anchors {
            talk("this three-key payload serves ONE door, the hosted signup — never the enroll hop, whose `skep enroll` refuses every anchor-flagged entry at the paste");
        } else {
            talk(outstanding_act_line());
        }
    }
    // The fingerprint LAST, flat and grouped — never the bare public key.
    data(key.fingerprint.to_hex());
    data(group_hex(&key.fingerprint.to_hex()));
    0
}

// ── claim ───────────────────────────────────────────────────────────────

/// A payload argument: a file, or `-` for stdin.
fn read_payload(arg: &str) -> Result<Vec<u8>, Halt> {
    if arg == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf).map_err(|e| Halt::face("the payload could not be read from stdin", e.to_string(), "pipe the payload in"))?;
        return Ok(buf);
    }
    std::fs::read(arg).map_err(|e| Halt::face(format!("the payload file {arg} could not be read: {e}"), "AUTH-5.67: a mis-pathed file is a halt naming the path, never a fallback", "check the path"))
}

pub fn claim(c: &Command) -> i32 {
    let board = match board_of(c) {
        Ok(b) => b,
        Err(u) => return usage(u),
    };
    let principal = match c.principal() {
        Ok(p) => p,
        Err(u) => return usage(u),
    };
    if let Some(payload_arg) = c.value("--hosted", None) {
        // THE HOSTED ARM (§4.5): no --dir, no person, nothing generated.
        let payload = match read_payload(&payload_arg) {
            Ok(p) => p,
            Err(h) => return halt(h),
        };
        return match claim::hosted(&board, &payload, principal.unwrap_or(1)) {
            Err(h) => halt(h),
            Ok(HostedOutcome::AlreadyClaimed { claimant }) => {
                data(format!("claimed by {claimant}"));
                0
            }
            Ok(HostedOutcome::Claimed(reply)) => {
                for l in &reply.log {
                    talk(l);
                }
                // THE REPLY, DATA on stdout (§4.5 H6).
                data(format!("claimant {}", reply.claimant));
                facts(&reply.facts);
                data(format!(
                    "first act: from the device that generated the payload run `skep verify --board {} --principal {} --payload <the record it printed>` \
                     (or `--anchor <a> --anchor <b>`): the genesis record compared entry for entry, fingerprint and anchor flag, against what that \
                     device composed — it confirms the keys on the board, and it cannot tell you the board will open a session for you",
                    reply.facts.origin, reply.facts.principal
                ));
                data("second act: in your first signed session the setup act runs — `skep claim --board <origin> --dir <store>` from that device performs it: creating your account also creates a space for your agents beneath it, and its home");
                if reply.anchorless {
                    data("this account holds no anchor: no anchor act on it is ever possible, and the enroll hop from another signed-in device is its one recovery");
                }
                0
            }
        };
    }
    // THE NOTEBOOK ARM: a person door.
    if !has_terminal() {
        return no_terminal("claim");
    }
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let (host_name, date) = host_name_and_date();
    let opts = NotebookOptions {
        principal,
        display_name: c.value("--name", None),
        anchor_out: c.all("--anchor-out").into_iter().map(PathBuf::from).collect(),
        paper: c.switch("--paper"),
        host_name,
        date,
    };
    let mut person = Terminal::new();
    match claim::notebook(&board, &store, &mut person, &opts) {
        Err(h) => halt(h),
        Ok(ClaimOutcome::Stranger { claimant }) => {
            data(format!("claimed by {claimant}; no key in this store is bound to it — `skep verify` tells you whether one is enrolled"));
            0
        }
        Ok(ClaimOutcome::Ours(done)) => {
            for w in &done.warnings {
                talk(w);
            }
            talk(format!("this board is yours — account {}, principal {}, key {}", done.account, done.principal, done.fingerprint));
            data(format!("account {}", done.account));
            data(format!("principal {}", done.principal));
            data(format!("origin {}", board.dialed()));
            if let Some(space) = &done.agent_space {
                data(format!("agent space {space}"));
            }
            0
        }
    }
}

// ── session ─────────────────────────────────────────────────────────────

/// The store's key for this board and principal (§3.5's lookup, `--key`
/// first), its public facts — its signer is the store's (`KeyStore::signer`)
/// — the arm-4 face forked on the claimant.
fn select_key(c: &Command, store: &FileStore, board: &Board, principal: Option<u64>) -> Result<KeyFacts, Halt> {
    let sel = match c.key() {
        Some(path) => store.select(&KeySelector::Path(&path), Purpose::Sign),
        None => store.select(&KeySelector::Board { origin: board.dialed(), principal }, Purpose::Sign),
    };
    match sel {
        Ok(key) => Ok(key),
        Err(StoreError::NoSelection { keys }) => Err(arm4_face(store, &keys, Mode::of(&board.health()?))),
        Err(e) => Err(e.into()),
    }
}

/// The principal: the flag, else the board's one binding in the store.
fn principal_or_bound(c: &Command, store: &FileStore, board: &Board) -> Result<u64, Halt> {
    if let Ok(Some(p)) = c.principal() {
        return Ok(p);
    }
    let ps = store.principals_at(board.dialed())?;
    match ps.as_slice() {
        [one] => Ok(*one),
        [] => Err(Halt::face("no principal", "--principal (or SKEP_PRINCIPAL) is absent and the store holds no binding for this board", "pass --principal")),
        _ => Err(Halt::face("no principal", "--principal is absent and the store holds bindings for several principals at this board", "pass --principal")),
    }
}

pub fn session(c: &Command) -> i32 {
    let board = match board_of(c) {
        Ok(b) => b,
        Err(u) => return usage(u),
    };
    if let Some(close) = c.value("--close", None) {
        // THE TOKEN IS NEVER AN ARGV VALUE (§2.2; AUTH-4.53; §9 item 29).
        if close != "-" {
            return usage(Usage("--close takes `-` and reads the token from stdin (or SKEP_SESSION); a token given as a flag value is refused — a command line is world-readable and outlives the run in shell history".into()));
        }
        let mut text = String::new();
        let token = match std::env::var("SKEP_SESSION").ok().filter(|t| !t.is_empty()) {
            Some(t) => t,
            None => {
                if io::stdin().read_to_string(&mut text).is_err() {
                    return usage(Usage("the token could not be read from stdin".into()));
                }
                text
            }
        };
        let Some(token) = Token::parse(&token) else { return usage(Usage("the token read is not a session token (32 lowercase hex)".into())) };
        return match board.session_close(&token) {
            Err(h) => halt(h),
            Ok(answer) => {
                if answer.already_dead {
                    talk("the token was already dead (the death signal rode the 204): a restart, a retirement, a block, a genesis at the account, or an earlier close ended it");
                }
                0
            }
        };
    }
    // The plaintext non-loopback WARNING, ahead of everything a signed
    // session needs (AUTH-4.53; §9 item 23: a warning, never a refusal).
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    let principal = match principal_or_bound(c, &store, &board) {
        Ok(p) => p,
        Err(h) => return halt(h),
    };
    let key = match select_key(c, &store, &board, Some(principal)) {
        Ok(k) => k,
        Err(h) => return halt(h),
    };
    let signer = match store.signer(&KeySelector::Path(&key.path)) {
        Ok(s) => s,
        Err(e) => return halt(e.into()),
    };
    // CONTENT scope only (§9 item 45; RES-63); the token handed out LIVE.
    let session = match handshake(&board, Scope::Content, &*signer, principal, Site::Session) {
        Ok(s) => s,
        Err(h) => return halt(h),
    };
    talk("the token reads, holds its draft visibility and writes content; a credential act under it answers content_session. It is live until `skep session --close -`, the key's retirement, or a daemon restart (AUTH-4.53: a captured token is this principal's content capability for that long)");
    data(session.into_token().as_str());
    0
}

// ── fingerprint ─────────────────────────────────────────────────────────

pub fn fingerprint(c: &Command) -> i32 {
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    let bindings = store.all_bindings().unwrap_or_default();
    let keys: Vec<KeyFacts> = if let Some(path) = c.key() {
        match store.select(&KeySelector::Path(&path), Purpose::Read) {
            Ok(k) => vec![k],
            Err(e) => return halt(e.into()),
        }
    } else if let Some(select) = c.value("--select", None) {
        match store.select(&KeySelector::select(&select), Purpose::Read) {
            Ok(k) => vec![k],
            Err(StoreError::Ambiguous { keys }) => {
                let list: Vec<String> = keys.iter().map(|k| format!("{} {}", k.fingerprint, k.label.as_deref().map(render_inert).unwrap_or_default())).collect();
                return halt(Halt::face(format!("`{select}` matches more than one key"), format!("neither a fingerprint prefix nor a label is unique by rule (AUTH-5.3):\n  {}", list.join("\n  ")), "give a longer prefix; never a pick"));
            }
            Err(StoreError::NotFound { select }) => return halt(Halt::face(format!("no key in the store matches `{select}`"), "the store's keys are listed by `skep fingerprint --dir`", "check the selector")),
            Err(e) => return halt(e.into()),
        }
    } else {
        match store.list() {
            Ok(keys) => keys,
            Err(e) => return halt(e.into()),
        }
    };
    let any_binding = bindings.iter().any(|b| matches!(b, Binding::Enrollment { .. }));
    let mut json_rows = Vec::new();
    for key in &keys {
        let fp = key.fingerprint;
        let bound: Vec<String> = bindings
            .iter()
            .filter_map(|b| match b {
                Binding::Enrollment { origin, principal, account, fingerprint } if *fingerprint == fp => Some(format!("{origin} principal {principal} account {account}")),
                _ => None,
            })
            .collect();
        let unbound = bound.is_empty();
        if c.switch("--json") {
            json_rows.push(serde_json::json!({
                "alg": key.public.alg(),
                "fingerprint": fp.to_hex(),
                "label": key.label,
                "anchor": key.anchor,
                "path": key.path.display().to_string(),
                "bindings": bound,
                "unbound": unbound,
                "payload": c.switch("--payload").then(|| encode_enroll(&[Enrollment::new(key.public.clone(), key.anchor, key.label.clone()).expect("a stored label is in the domain")])),
            }));
            continue;
        }
        data(format!("{} {}", key.public.alg(), key.public.to_hex()));
        data(fp.to_hex());
        data(group_hex(&fp.to_hex()));
        data(format!("label {}", key.label.as_deref().map(render_inert).unwrap_or_else(|| "(none)".into())));
        if key.anchor {
            data("ANCHOR — a paper's file, never a device key");
        }
        for b in &bound {
            data(format!("bound {b}"));
        }
        if unbound {
            // THE PENDING STATE (AUTH-5.32), the durable half of `keygen
            // --payload`'s line, conditioned on the walk.
            data(if any_binding {
                "UNBOUND — this key is enrolled at no board this store knows: `skep fingerprint --select <fp> --payload` re-prints its payload; `skep enroll` on a device already signed in (or `skep rotate --payload` there where this key REPLACES a machine), then `skep bind` here; where this key was made at `skep accept`, the outstanding act is the giver's genesis and their reply, then `skep bind`"
            } else {
                "UNBOUND — no board has been claimed from this store: the act is `skep claim`; or, for a board another device is signed in on, `skep enroll` there with this key's payload and `skep bind` here"
            });
        }
        if c.switch("--payload") {
            data(encode_enroll(&[Enrollment::new(key.public.clone(), key.anchor, key.label.clone()).expect("a stored label is in the domain")]));
        }
    }
    if c.switch("--json") {
        data(serde_json::Value::Array(json_rows).to_string());
    }
    0
}

// ── verify ──────────────────────────────────────────────────────────────

/// What this device HOLDS for the whole-set compare: the payload's entries
/// (at `verify`, where `--payload` is the RECORD this device printed; at
/// `bind` it is the REPLY and never read here), and the anchor files'
/// public members beside the store's device key.
fn held_set(c: &Command, store: &FileStore, device: Option<&KeyFacts>, payload_is_record: bool) -> Result<Option<Vec<Held>>, Halt> {
    let mut held = Vec::new();
    let mut any = false;
    if let Some(arg) = c.value("--payload", None).filter(|_| payload_is_record) {
        any = true;
        let bytes = read_payload(&arg)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| Halt::face("the payload is not UTF-8", "a canonical record is UTF-8 text", "re-take the payload"))?.trim();
        let entries = skep_identity::parse_enroll(text.as_bytes()).map_err(|e| Halt::face("the payload is not a canonical enrollment record", e.to_string(), "re-take it from the device that printed it"))?;
        for e in entries {
            held.push(Held { fingerprint: Fingerprint::of(&e.key), anchor: e.anchor, label: e.label().map(str::to_string) });
        }
    }
    let anchors = c.all("--anchor");
    if !anchors.is_empty() {
        any = true;
        for path in anchors {
            // The file's PUBLIC facts and nothing else — the lookup hands out
            // no seed; no session, nothing written.
            let artifact = store.select(&KeySelector::Path(Path::new(&path)), Purpose::Read)?;
            held.push(Held { fingerprint: artifact.fingerprint, anchor: artifact.anchor, label: artifact.label.clone() });
        }
        if let Some(d) = device {
            held.push(Held { fingerprint: d.fingerprint, anchor: false, label: d.label.clone() });
        }
    }
    Ok(any.then_some(held))
}

fn difference_lines(diffs: &[Difference]) -> Vec<String> {
    diffs
        .iter()
        .map(|d| match d {
            Difference::Added { fingerprint, anchor, label } => format!(
                "a key you did not send stands in the genesis: {fingerprint} anchor={anchor} label={} — {}",
                label.as_deref().map(render_inert).unwrap_or_else(|| "(none)".into()),
                if *anchor { "an anchor planted: the remedy is your OWN anchor where the flags survived (AUTH-4.56), and the state is PERMANENT where they did not" } else { "a device key planted: retire it from this device's own session (`skep retire --fingerprint <prefix>`)" }
            ),
            Difference::Missing { fingerprint, anchor, label } => format!(
                "a key you sent is missing from the genesis: {fingerprint} anchor={anchor} label={}",
                label.as_deref().map(render_inert).unwrap_or_else(|| "(none)".into())
            ),
            Difference::FlagFlipped { fingerprint, held_anchor, genesis_anchor } => {
                format!("the anchor flag is flipped on {fingerprint}: you sent anchor={held_anchor}, the genesis holds anchor={genesis_anchor}")
            }
        })
        .collect()
}

pub fn verify(c: &Command) -> i32 {
    let board = match board_of(c) {
        Ok(b) => b,
        Err(u) => return usage(u),
    };
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    let json = c.switch("--json");
    let mut checks: Vec<&str> = Vec::new();
    // (1) THE ORIGIN ARM.
    let health = match board.health() {
        Ok(h) => h,
        Err(h) => return halt(h),
    };
    if let Err(h) = origin_arm(board.signed(), &health) {
        return halt(h);
    }
    checks.push("origin");
    // (2) THE KEY ARM: `principal_prefix(n)`, then `key_set` at the set the
    // walk reaches, against the selected key.
    let principal = match principal_or_bound(c, &store, &board) {
        Ok(p) => p,
        Err(h) => return halt(h),
    };
    let key = match c.key() {
        Some(path) => match store.select(&KeySelector::Path(&path), Purpose::Read) {
            Ok(k) => k,
            Err(e) => return halt(e.into()),
        },
        None => match select_key(c, &store, &board, Some(principal)) {
            Ok(k) => k,
            Err(h) => return halt(h),
        },
    };
    let pre = match precheck(&board, principal, &key.fingerprint) {
        Ok(p) => p,
        Err(h) => return halt(h),
    };
    checks.push("key_set");
    let own = [(key.fingerprint, key.public.clone())];
    if let Err(h) = key_face(&board, &pre.walk, &key.fingerprint, &own, Site::Session) {
        return halt(h);
    }
    // THE WHOLE-SET COMPARE, where the person holds what this device
    // composed (AUTH-4.58's detection; P25).
    let mut later_lines = Vec::new();
    let held = match held_set(c, &store, Some(&key), true) {
        Ok(h) => h,
        Err(h) => return halt(h),
    };
    if let Some(held) = held {
        checks.push("payload");
        let records = match credential_records(&board, &pre.walk.set_account, &own) {
            Ok(r) => r,
            Err(h) => return halt(h),
        };
        match compare_whole_set(&records, &pre.walk.set, &held) {
            None => return halt(Halt::face("the account has no genesis record to compare against", "the admitted read found no enrollment record naming the account", "this is a board fault, or the account is not the one the facts name")),
            Some(whole) => {
                if !whole.differences.is_empty() {
                    let lines = difference_lines(&whole.differences);
                    return halt(Halt::face(
                        format!("this account is NOT yours to keep as it stands (AUTH-5.53): the genesis record of {} differs from what you hold", pre.walk.set_account),
                        lines.join("\n  "),
                        "the acts by cell: a planted DEVICE key is retired from this device's own session; a planted ANCHOR only under an anchor of your own that survived; the state is PERMANENT where the flags did not — or decline the account",
                    ));
                }
                for l in &whole.later {
                    later_lines.push(format!("later act: {} anchor={} label={}", l.fingerprint, l.anchor, l.label.as_deref().map(render_inert).unwrap_or_else(|| "(none)".into())));
                }
            }
        }
    } else {
        talk("the key arm is the one-key read — this key's membership and never the set's: pass --payload or --anchor to compare the genesis record whole");
    }
    for l in &later_lines {
        talk(l);
    }
    talk("a block is invisible to both reads: a verify that passes can still meet 403 prefix_blocked at the next handshake");
    if json {
        data(serde_json::json!({
            "checks": checks,
            "account": pre.account,
            "set_account": pre.walk.set_account,
            "fingerprint": key.fingerprint.to_hex(),
            "state": "enrolled",
            "mode": pre.mode.name(),
            "limit": "a block is invisible to these reads",
        })
        .to_string());
    } else {
        data(format!("account {}", pre.account));
        if pre.walk.by_reference() {
            data(format!("opens by reference against {}", pre.walk.set_account));
        }
    }
    0
}

// ── health ──────────────────────────────────────────────────────────────

pub fn health(c: &Command) -> i32 {
    let board = match board_of(c) {
        Ok(b) => b,
        Err(u) => return usage(u),
    };
    let health = match board.health() {
        Ok(h) => h,
        Err(h) => return halt(h),
    };
    // The body VERBATIM — one JSON document already; the CLI never adds a
    // `mode` field (AUTH-5.86's negative pin).
    let mut out = io::stdout().lock();
    let _ = out.write_all(&health.raw);
    if !health.raw.ends_with(b"\n") {
        let _ = out.write_all(b"\n");
    }
    let _ = out.flush();
    let mode = Mode::of(&health);
    talk(format!("mode {} (claimant {}, local_trust {}) — derived from the pair, no mode field (AUTH-5.86)", mode.name(), health.claimant().unwrap_or("null"), health.local_trust()));
    talk(format!("bare arm (origins): [{}]", health.origins().join(", ")));
    talk(format!("signed arm (signed_origins): [{}]", health.signed_origins().join(", ")));
    0
}

// ── bind ────────────────────────────────────────────────────────────────

/// The three facts, from `--account`/`--principal`/`--board`, or `--payload`
/// in the form `enroll` prints them (`account …`, `principal …`, `origin …`
/// lines), or a paste read from stdin line by line.
fn facts_of(c: &Command, board: &Board) -> Result<(String, u64), Halt> {
    let mut account = c.value("--account", None);
    let mut principal = c.principal().map_err(|u| Halt::face("the principal is malformed", u.0, "pass --principal <n>"))?;
    if let Some(arg) = c.value("--payload", None) {
        let bytes = read_payload(&arg)?;
        let text = String::from_utf8_lossy(&bytes).to_string();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some("account"), Some(a)) => account = Some(a.to_string()),
                (Some("principal"), Some(p)) => principal = p.parse().ok(),
                (Some("origin"), Some(o)) => {
                    if o != board.dialed().as_str() {
                        return Err(Halt::face(format!("the reply names origin {o} and this command dials {}", board.dialed()), "the reply came from another board", "dial the board the reply names"));
                    }
                }
                _ => {}
            }
        }
    }
    let account = match account {
        Some(a) => a,
        None => {
            let mut line = String::new();
            eprint!("account address (from the enrolling device's reply): ");
            let _ = io::stderr().flush();
            io::stdin().read_line(&mut line).map_err(|e| Halt::face("the account could not be read", e.to_string(), "pass --account"))?;
            line.trim().to_string()
        }
    };
    let principal = principal.ok_or_else(|| Halt::face("no principal", "--principal (or SKEP_PRINCIPAL), or a `principal` line in the reply, is required", "pass --principal <n>"))?;
    if account.is_empty() || !skep_client::address::is_address_text(&account) {
        return Err(Halt::face(format!("`{account}` is not an account address"), "an address is dotted decimal", "pass --account <address>"));
    }
    Ok((account, principal))
}

pub fn bind(c: &Command) -> i32 {
    let board = match board_of(c) {
        Ok(b) => b,
        Err(u) => return usage(u),
    };
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    let (account, principal) = match facts_of(c, &board) {
        Ok(f) => f,
        Err(h) => return halt(h),
    };
    // The facts CONFIRMED against the board before anything is written:
    // the origin arm; the principal by the ADDRESS-KEYED read (AUTH-6.37);
    // `principal_prefix(n)` against the pasted account; the key-set compare.
    let health = match board.health() {
        Ok(h) => h,
        Err(h) => return halt(h),
    };
    if let Err(h) = origin_arm(board.signed(), &health) {
        return halt(h);
    }
    match principal_of(&board, &account) {
        Ok(Some(p)) if p == principal => {}
        Ok(other) => {
            return halt(Halt::face(
                format!("the pasted principal {principal} is not the principal seated at {account}"),
                format!("`effective_owner({account})` where `prefix == {account}` answers {} — the reply came from another board or another principal, which is exactly what an out-of-band channel gets wrong", other.map(|p| p.to_string()).unwrap_or_else(|| "no seat".into())),
                "re-take the three facts from the enrolling device",
            ))
        }
        Err(h) => return halt(h),
    }
    match board.principal_prefix(principal) {
        Ok(Some(a)) if a == account => {}
        Ok(other) => {
            return halt(Halt::face(
                format!("the pasted account {account} is not `principal_prefix({principal})`"),
                format!("the board answers {} for that principal", other.unwrap_or_else(|| "null".into())),
                "re-take the three facts from the enrolling device",
            ))
        }
        Err(h) => return halt(h),
    }
    let key = match select_key(c, &store, &board, Some(principal)) {
        Ok(k) => k,
        Err(h) => return halt(h),
    };
    let walk = match walk_to_set(&board, &account) {
        Ok(w) => w,
        Err(h) => return halt(h),
    };
    let own = [(key.fingerprint, key.public.clone())];
    if let Err(h) = key_face(&board, &walk, &key.fingerprint, &own, Site::Tail) {
        return halt(h);
    }
    // At a HANDOFF LANDING the set is compared WHOLE, ahead of
    // `first_session` and any session (AUTH-4.58's detection).
    let records_for_compare = match held_set(c, &store, Some(&key), false) {
        Ok(h) => h,
        Err(h) => return halt(h),
    };
    if let Some(held) = records_for_compare {
        let records = match credential_records(&board, &walk.set_account, &own) {
            Ok(r) => r,
            Err(h) => return halt(h),
        };
        match compare_whole_set(&records, &walk.set, &held) {
            Some(whole) if !whole.differences.is_empty() => {
                return halt(Halt::face(
                    format!("this account is NOT yours to keep as it stands (AUTH-5.53): the genesis record of {account} differs from what you hold"),
                    difference_lines(&whole.differences).join("\n  "),
                    "the extra key is one the giver's hand can act with, whatever was said at `skep accept`; a planted device key is retired from this device's own session, a planted anchor only under an anchor of your own that survived",
                ))
            }
            Some(whole) => {
                for l in &whole.later {
                    talk(format!("later act: {} anchor={} label={}", l.fingerprint, l.anchor, l.label.as_deref().map(render_inert).unwrap_or_else(|| "(none)".into())));
                }
            }
            None => return halt(Halt::face("the account has no genesis record to compare against", "the admitted read found none", "this is a board fault")),
        }
    }
    // THE TWO ARMS, selected by `first_session`'s own reads (§2.2).
    let reads = match FirstSessionReads::take(&board, &account, &key.fingerprint, Some(&store)) {
        Ok(r) => r,
        Err(h) => return halt(h),
    };
    let mut agent_space = None;
    if reads.anything_owed() {
        if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
            talk(w);
        }
        let signer = match store.signer(&KeySelector::Path(&key.path)) {
            Ok(s) => s,
            Err(e) => return halt(e.into()),
        };
        let session = match handshake(&board, Scope::Content, &*signer, principal, Site::Tail) {
            Ok(s) => s,
            Err(h) => return halt(h),
        };
        let done = first_session(&board, &reads, &session, &*signer, Some(&store));
        let _ = session.close();
        match done {
            Err(h) => return halt(h),
            Ok(done) => {
                for w in &done.warnings {
                    talk(w);
                }
                if done.minted_home {
                    talk(format!("the home {} is minted — the empty profile home, born published (AUTH-5.90 (iii); AUTH-5.52)", reads.home));
                }
                if done.setup_stopped_seeded {
                    talk(format!("{} already holds a set of its own: the setup act stops and no agents' home is created (AUTH-5.90 (iii)'s permanent fact)", reads.agent_space));
                } else if let Some(d) = done.setup_skipped {
                    talk(format!("the setup act was not sent: this key stands {d} in the set that opens {}", reads.agent_space));
                } else if done.agent_space_principal.is_some() {
                    agent_space = Some(reads.agent_space.clone());
                }
            }
        }
    } else {
        talk("nothing is owed at this account's first signed session: no session is opened and no record is written");
    }
    let line = Binding::Enrollment { origin: board.dialed().clone(), principal, account: account.clone(), fingerprint: key.fingerprint };
    if let Err(w) = store.bind(&line) {
        talk(w.to_string());
    }
    data(format!("account {account}"));
    data(format!("principal {principal}"));
    data(format!("origin {}", board.dialed()));
    if let Some(s) = agent_space {
        data(format!("agent space {s}"));
    }
    0
}

/// A `key_set` answer's enrolled fingerprints, for a listing.
#[allow(dead_code)]
fn enrolled_of(answer: &KeySetAnswer) -> Vec<Fingerprint> {
    match answer {
        KeySetAnswer::Set(s) => s.enrolled.iter().map(|e| e.fingerprint).collect(),
        KeySetAnswer::NotAnAccount => Vec::new(),
    }
}

/// The three facts, DATA on stdout, in the form `bind --payload` reads.
fn facts(f: &skep_client::sheet::Facts) {
    data(format!("account {}", f.account));
    data(format!("principal {}", f.principal));
    data(format!("origin {}", f.origin));
}

// ── enroll ──────────────────────────────────────────────────────────────

pub fn enroll(c: &Command) -> i32 {
    let board = match board_of(c) {
        Ok(b) => b,
        Err(u) => return usage(u),
    };
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    let principal = match principal_or_bound(c, &store, &board) {
        Ok(p) => p,
        Err(h) => return halt(h),
    };
    // `--reply`: the three facts re-derived, no write — not a person door.
    if let Some(prefix) = c.value("--reply", None) {
        return match enroll_walk::reply(&board, principal, &prefix) {
            Err(h) => halt(h),
            Ok(e) => {
                talk(format!("the reply, offered again (AUTH-5.32): {} stands ENROLLED at {}", e.fingerprints[0], e.facts.account));
                facts(&e.facts);
                0
            }
        };
    }
    if !has_terminal() {
        return no_terminal("enroll");
    }
    let Some(payload_arg) = c.value("--payload", None) else { return usage(Usage("--payload <file|-> is required (or --reply <fp-prefix>)".into())) };
    let payload = match read_payload(&payload_arg) {
        Ok(p) => p,
        Err(h) => return halt(h),
    };
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let mut person = Terminal::new();
    match enroll_walk::enroll(&board, &store, &mut person, &EnrollOptions { principal, payload }) {
        Err(h) => halt(h),
        Ok(e) => {
            for w in &e.warnings {
                talk(w);
            }
            if e.reconciled {
                talk("reconciled: every key of the payload already stands enrolled (AUTH-5.17) — nothing was written, and the three facts are the reply");
            }
            facts(&e.facts);
            0
        }
    }
}

// ── recover ─────────────────────────────────────────────────────────────

pub fn recover(c: &Command) -> i32 {
    let board = match board_of(c) {
        Ok(b) => b,
        Err(u) => return usage(u),
    };
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    if !has_terminal() {
        return no_terminal("recover");
    }
    let principal = match principal_or_bound(c, &store, &board) {
        Ok(p) => p,
        Err(h) => return halt(h),
    };
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    // `--key`/`SKEP_KEY` is NOT consulted here: the new device key is the
    // STORE's, as at `claim` (§2.2).
    let (host_name, date) = host_name_and_date();
    let opts = RecoverOptions {
        principal,
        anchor: c.all("--anchor").first().map(PathBuf::from),
        lost: c.all("--lost"),
        stolen: c.switch("--stolen").then_some(true),
        anchor_lost: c.switch("--anchor-lost"),
        anchor_out: c.all("--anchor-out").into_iter().map(PathBuf::from).collect(),
        paper: c.switch("--paper"),
        host_name,
        date,
    };
    let mut person = Terminal::new();
    match recover_walk::recover(&board, &store, &mut person, &opts) {
        Err(h) => halt(h),
        Ok(r) => {
            for w in &r.warnings {
                talk(w);
            }
            for l in &r.recovery_read {
                talk(format!("[recovery read] {l}"));
            }
            if let Some(line) = &r.binding_line {
                talk(format!("binding: {line}"));
            }
            facts(&r.facts);
            for fp in &r.enrolled {
                data(format!("enrolled {fp}"));
            }
            for fp in &r.retired {
                data(format!("retired {fp}"));
            }
            0
        }
    }
}

// ── retire ──────────────────────────────────────────────────────────────

pub fn retire(c: &Command) -> i32 {
    let board = match board_of(c) {
        Ok(b) => b,
        Err(u) => return usage(u),
    };
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    let Some(fingerprint_prefix) = c.value("--fingerprint", None) else { return usage(Usage("--fingerprint <fp-prefix> is required".into())) };
    if !has_terminal() {
        return no_terminal("retire");
    }
    let principal = match principal_or_bound(c, &store, &board) {
        Ok(p) => p,
        Err(h) => return halt(h),
    };
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let mut person = Terminal::new();
    match retire_walk::retire(&board, &store, &mut person, &RetireOptions { principal, fingerprint_prefix }) {
        Err(h) => halt(h),
        Ok(r) => {
            data(format!("retired {} at {}", r.fingerprint, r.account));
            if let RetireEnd::EndedByCommit { another_held } = r.end {
                talk(if another_held { "next: `skep session` with the key you still hold" } else { "next: `skep keygen`, then `skep recover` with a paper" });
            }
            0
        }
    }
}

// ── rotate ──────────────────────────────────────────────────────────────

pub fn rotate(c: &Command) -> i32 {
    let board = match board_of(c) {
        Ok(b) => b,
        Err(u) => return usage(u),
    };
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    if !has_terminal() {
        return no_terminal("rotate");
    }
    let principal = match principal_or_bound(c, &store, &board) {
        Ok(p) => p,
        Err(h) => return halt(h),
    };
    let payload = match c.value("--payload", None) {
        Some(arg) => match read_payload(&arg) {
            Ok(p) => Some(p),
            Err(h) => return halt(h),
        },
        None => None,
    };
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let mut person = Terminal::new();
    match rotate_walk::rotate(&board, &store, &mut person, &RotateOptions { principal, label: c.value("--label", None), payload }) {
        Err(h) => halt(h),
        Ok(r) => {
            for w in &r.warnings {
                talk(w);
            }
            if let Some(line) = &r.binding_line {
                talk(format!("binding: {line}"));
            }
            facts(&r.facts);
            data(format!("old {}", r.old));
            data(format!("new {}", r.new));
            data(format!("trail {}", r.trail));
            0
        }
    }
}

// ── handoff ─────────────────────────────────────────────────────────────

pub fn handoff(c: &Command) -> i32 {
    let board = match board_of(c) {
        Ok(b) => b,
        Err(u) => return usage(u),
    };
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    let Some(account) = c.value("--account", None) else { return usage(Usage("--account <address> is required".into())) };
    let payload = match c.value("--payload", None) {
        Some(arg) => match read_payload(&arg) {
            Ok(p) => Some(p),
            Err(h) => return halt(h),
        },
        None => None,
    };
    // The comparison and the confirmation make the `--payload` invocation a
    // person door; beat (a) alone is not one.
    if payload.is_some() && !has_terminal() {
        return no_terminal("handoff --payload");
    }
    let principal = match principal_or_bound(c, &store, &board) {
        Ok(p) => p,
        Err(h) => return halt(h),
    };
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let mut person = Terminal::new();
    let opts = HandoffOptions { principal, account, payload, anchor: c.all("--anchor").first().map(PathBuf::from) };
    match handoff_walk::handoff(&board, &store, &mut person, &opts) {
        Err(h) => halt(h),
        Ok(HandoffOutcome::Delegated { account, principal, already }) => {
            talk(if already { "beat (a) stands done: the address is printed again" } else { "beat (a) done: hand the address to the recipient; they run `skep accept --board <origin> --account <address>` and return their record for `skep handoff --payload`" });
            data(format!("account {account}"));
            data(format!("principal {principal}"));
            data(format!("origin {}", board.dialed()));
            0
        }
        Ok(HandoffOutcome::Seeded { facts: f, grade, reconciled, warnings }) => {
            for w in &warnings {
                talk(w);
            }
            talk(format!("the genesis is written at the {grade} grade{}; return the three facts below to the recipient for `skep bind`", if reconciled { " (reconciled from the records)" } else { "" }));
            facts(&f);
            0
        }
    }
}

// ── accept ──────────────────────────────────────────────────────────────

pub fn accept(c: &Command) -> i32 {
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    // `--reprint`: the record from the artifacts' public members — not a
    // person door.
    if c.switch("--reprint") {
        let anchors: Vec<PathBuf> = c.all("--anchor").into_iter().map(PathBuf::from).collect();
        let board = c.board().ok();
        return match accept_walk::reprint(&store, c.key().as_deref(), &anchors, board.as_ref()) {
            Err(h) => halt(h),
            Ok(record) => {
                data(record);
                0
            }
        };
    }
    if !has_terminal() {
        return no_terminal("accept");
    }
    let mut person = Terminal::new();
    // `--board` and `--account` REQUIRED: a run missing either ASKS and
    // generates nothing (AUTH RES-162).
    let board = match c.board() {
        Ok(o) => Board::new(o, PlainHttp::new()),
        Err(_) => {
            let Ok(text) = person.ask(Public(Question { text: "the board the account is on (a canonical origin, from the giver): ".into() })) else { return halt(Halt::face("no board was named", "the beat asks and generates nothing", "re-run with --board")) };
            match text.trim().parse::<skep_client::Origin>() {
                Ok(o) => Board::new(o, PlainHttp::new()),
                Err(e) => return usage(Usage(format!("--board: '{}' is {e}", text.trim()))),
            }
        }
    };
    let account = match c.value("--account", None) {
        Some(a) => a,
        None => match person.ask(Public(Question { text: "the address the giver handed you (--account): ".into() })) {
            Ok(a) if !a.trim().is_empty() => a.trim().to_string(),
            _ => return halt(Halt::face("no address was named", "AUTH RES-162: the beat holds the address before the keys are made, and generates nothing without it", "ask the giver for the address and re-run with --account")),
        },
    };
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let (host_name, date) = host_name_and_date();
    let opts = AcceptOptions {
        account,
        label: c.value("--label", None),
        anchor_out: c.all("--anchor-out").into_iter().map(PathBuf::from).collect(),
        paper: c.switch("--paper"),
        no_anchors: c.switch("--no-anchors"),
        hosted: None,
        host_name,
        date,
    };
    match accept_walk::accept(&board, &store, &mut person, &opts) {
        Err(h) => halt(h),
        Ok(a) => {
            // The record FIRST (DATA for the giver), then the device key's
            // fingerprint.
            data(a.record);
            data(a.device.to_hex());
            0
        }
    }
}
