//! The one registration-request composition (REG-4.67; REG-1.86; P28).
//!
//! An applicant holds keys and no account, so what it sends a door is a
//! request its own device key signs: its self-signed enrolments, framed
//! under `skep-registration-v1` over the door it is for, a freshness value
//! and the request's own shape, the frame's fields the body's own members
//! and one signature over them (REG-4.67, REG-4.73). This composition is
//! the applicant's whole side, on the applicant's own device: it reads no
//! board and opens no connection, and the only files it writes are key
//! files — the anchor sheets, and a device key where the store holds none.
//! The request is composed here and written by another hand: the door's
//! scribe or a sponsor deposits it (REG-4.68, REG-4.72), under a `sig` of
//! its own that this composition never makes.
//!
//! **The order** ([`registration_request`]). Every judgment a read alone can
//! make comes before anything is asked, generated or written (P13):
//!
//! 1. The door identifier, as given, by `DoorId::parse` (REG-4.74). Its
//!    form alone: whether a door answers to it is the door's own frame check.
//! 2. Every label a flag fixes, at its box (AUTH-1.24), and their count
//!    against the anchors this kind generates.
//! 3. The device key (REG-4.102, REG-4.104). One device key serves every
//!    board, so a key the store holds is named at its box and none is
//!    generated beside it: the file a caller names, else the store's one
//!    device key; more than one is the selection face, never a guess. Where
//!    the store holds none, a fresh registration generates one — after the
//!    moment, so a moment stopped short leaves no unbound key in the store
//!    — and a registration whose board carries on halts: its node account's
//!    working key is the device key that board's set already holds, taken
//!    here as the store's own and said as unchecked, no board being read.
//! 4. The backup moment's node arm (`Venue::Registration`; REG-4.103) over
//!    every pair the kind generates, each sheet read back and verified.
//! 5. The enrolments (REG-4.102): the node account's is the node pair's two
//!    anchor-flagged entries and the device key, device-flagged, and nothing
//!    else; on a fresh registration the board root's is the org root pair
//!    and the same device key. Each rides as `encode_enroll`'s text.
//! 6. The frame and its one signature by the device key, over a freshness
//!    value of thirty-two bytes from this client's own entropy (REG-4.84)
//!    and the `shape` read off the kind's own row (REG-4.104).
//! 7. The composition's check of its own output, as a reader will read it:
//!    the canonical parse under the kind's row, every enrolment naming the
//!    signer, and the signature over the frame re-built from the parsed
//!    members. A request that fails it is this client's fault and is never
//!    answered.
//!
//! What the person carries beside the body is [`say_request`]'s, said by
//! the caller once the body is handed out (AUTH-5.57 step 3): each key's
//! label beside its fingerprint in the grouped form, the thread's key, and
//! the disposition of this application's papers (AUTH-5.57 step 4;
//! REG-4.101). A run that stops between the moment's start and the request
//! says what it leaves behind.

use std::path::PathBuf;

use skep_identity::{encode_enroll, enrolled_signer, framed, parse_enroll, thread_key, AdmissionFrame, DoorId, Enrollment, Fingerprint, Freshness, LabelError, PublicKey, REGISTRATION_TAG};
use skep_registry::{encode_registration, parse_registration, BoardCarriesOn, Fresh, Hex64, HexDigits, RegistrationBody, RegistrationKind, MAX_REGISTRATION_REQUEST_BYTES};

use super::say;
use crate::ceremony::backup::{backup_moment, AnchorArtifact, BackupOptions, Venue};
use crate::halt::Halt;
use crate::person::{LabelBox, Person, Public};
use crate::sheet::{group_hex, render_inert, Label};
use crate::sign::{fresh_bytes, sig_hex, Signer};
use crate::store::{FileStore, KeyFacts, KeySelector, KeyStore, Purpose};

/// The composition's inputs.
#[derive(Debug, Clone)]
pub struct RegistrationOptions {
    /// `--door`: the door identifier, as given (REG-4.74).
    pub door: String,
    /// `--existing-board`: the applicant's board carries on (REG-4.204).
    ///
    /// The request is the board-carries-on row's and generates the node pair
    /// alone; absent, it is the fresh row's and generates both pairs.
    pub board_carries_on: bool,
    /// `--key`: the device key's file, named (`client.md` §3.5 arm 1).
    ///
    /// Absent, the device key is the store's one device key.
    pub key_file: Option<PathBuf>,
    /// `--label`: the byline of the device key this run generates.
    ///
    /// It is refused where the device key is named and none is generated.
    pub label: Option<String>,
    /// `--anchor-label`, one per anchor at most, in the moment's order.
    ///
    /// The order is the org root pair's a and b, then the node pair's; the
    /// node pair's two alone where the board carries on.
    pub anchor_labels: Vec<String>,
    /// `--anchor-out`, one destination per anchor at most, in that order.
    pub anchor_out: Vec<PathBuf>,
    /// `--paper`: the sheets printed besides, and the re-type asked.
    pub paper: bool,
    /// The machine's host name, for the anchor boxes' per-run default.
    pub host_name: String,
    /// The date, for the same per-run default.
    pub date: String,
}

/// What a key is in a request's enrolments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyRole {
    /// A sheet of the org root's pair, in the board root's enrolment.
    OrgRootAnchor,
    /// A sheet of the node identity's pair, in the node account's enrolment.
    NodeAnchor,
    /// The device key, in every enrolment the request carries.
    Device,
}

/// One key of a request, as the scannable form shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestKey {
    /// What the key is in the request.
    pub role: KeyRole,
    /// The key as a line names it: its pair and its sheet, or the device.
    pub named: String,
    /// The label its box fixed, as the enrolment carries it.
    pub label: String,
    /// The key's fingerprint.
    pub fingerprint: Fingerprint,
}

/// The device key a request is signed by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKey {
    /// The key's fingerprint: the request's `signer`.
    pub fingerprint: Fingerprint,
    /// The key's label, as every enrolment carries it.
    pub label: String,
    /// The key file's path.
    pub path: PathBuf,
    /// Whether this run generated the key; `false` where it was named.
    pub generated: bool,
}

/// A registration request, composed, signed and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationRequest {
    /// The request's kind: the row its `shape` names.
    pub kind: RegistrationKind,
    /// The request's body, canonical and with no `sig`: one line to carry.
    ///
    /// The `sig` member is the writing hand's, the scribe's or a sponsor's,
    /// and is never made here (REG-1.86).
    pub body: String,
    /// The door the request is framed for.
    pub door: DoorId,
    /// The request's freshness value.
    pub fresh: Freshness,
    /// The device key that signed the frame.
    pub device: DeviceKey,
    /// The org root pair's artifacts; empty where the board carries on.
    pub board_pair: Vec<AnchorArtifact>,
    /// The node pair's artifacts.
    pub node_pair: Vec<AnchorArtifact>,
    /// The request's keys, each once: the scannable form's lines.
    pub keys: Vec<RequestKey>,
    /// The thread's key: every key's fingerprint, ascending, each once.
    ///
    /// It is what the applicant finds its own thread by (REG-4.78).
    pub thread_key: Vec<Fingerprint>,
}

/// The enrolments a request carries, by its kind (REG-4.102).
///
/// The kind is read off them, so a request's row and its members never
/// disagree: a fresh request carries a board root's enrolment and a
/// board-carries-on request carries none.
#[derive(Debug, Clone)]
enum Enrolments {
    /// A fresh registration's: the node account's and the board root's.
    Fresh { node: Vec<Enrollment>, board: Vec<Enrollment> },
    /// A board-carries-on registration's: the node account's alone.
    BoardCarriesOn { node: Vec<Enrollment> },
}

impl Enrolments {
    /// Returns the kind whose row these enrolments are the members of.
    fn kind(&self) -> RegistrationKind {
        match self {
            Enrolments::Fresh { .. } => RegistrationKind::Fresh,
            Enrolments::BoardCarriesOn { .. } => RegistrationKind::BoardCarriesOn,
        }
    }

    /// Returns the node account's enrolment.
    fn node(&self) -> &[Enrollment] {
        match self {
            Enrolments::Fresh { node, .. } | Enrolments::BoardCarriesOn { node } => node,
        }
    }

    /// Returns the board root's enrolment, where the request carries one.
    fn board(&self) -> Option<&[Enrollment]> {
        match self {
            Enrolments::Fresh { board, .. } => Some(board),
            Enrolments::BoardCarriesOn { .. } => None,
        }
    }
}

/// The device-name box's statements at this door (AUTH-5.42).
fn device_box() -> Vec<String> {
    vec![
        "This name is permanent and cannot be edited: fixing a typo costs a keypair.".into(),
        "It is a byline: this name appears beside every write you make with this key, forever.".into(),
        "It holds the DEVICE's name — never your own and never your organisation's; a display name is a separate, changeable label.".into(),
        "At this door it rides onto a public thread on the registry's board, approved or DENIED, forever, in every key set this request \
         founds; and not every write under this byline is yours — the party that operates a board can write as you there, visibly and \
         permanently, which every copy that checks signatures will show was not you."
            .into(),
    ]
}

/// Returns the halt a door identifier that is none comes to.
///
/// `DoorId::parse` answers no reason, so the face names the one spelling.
fn door_refused(given: &str) -> Halt {
    Halt::face(
        format!("`{}` is not a door identifier", render_inert(given)),
        "a door identifier is ONE string in ONE spelling (REG-4.74): `realm:<64 lowercase hex> door:<address>`, with \
         `fork:<address>` between the two on a forked lineage — one space between terms and none around them, the hex lowercase, each \
         address in dotted decimal. The request is framed and signed over this string, so a string that is not its own spelling is \
         refused before anything is asked, generated or written",
        "copy the identifier exactly as the door publishes it and pass it as `--door '<identifier>'`, quoted: it holds a space",
    )
}

/// Returns the halt a label the enrollment record refuses comes to.
///
/// AUTH-1.24's domain is spelled twice, by this crate's `Label` and by
/// `skep-identity`'s record; a label the first admits and the second does
/// not is faced, never a panic.
fn record_refused(e: LabelError) -> Halt {
    Halt::face(
        format!("a label is refused by the enrollment record: {e}"),
        "AUTH-1.25: the record admits a label inside AUTH-1.24's domain alone, and a key's label is fixed in its file",
        "name the key inside the domain: non-empty, no line break, at most 128 bytes of UTF-8",
    )
}

/// Returns the halt of a request this client composed and cannot verify.
fn own_fault(what: impl Into<String>) -> Halt {
    Halt::face(
        "this client composed a registration request that does not verify, and answers none",
        what,
        "this is this client's fault, not your keys': nothing was printed and nothing was sent — report it with the command line that \
         met it. Any sheet this run wrote names no account and opens nothing",
    )
}

/// Returns the device key the store already holds, where it holds one.
///
/// It is the file `key_file` names (§3.5 arm 1), an anchor file refused
/// there, else the store's one device key; `None` where the store holds
/// none.
///
/// # Errors
///
/// The store's refusals; and more than one device key with none named — the
/// selection face, listing each by fingerprint and label, never a pick.
fn held_device_key(store: &FileStore, opts: &RegistrationOptions) -> Result<Option<KeyFacts>, Halt> {
    if let Some(path) = &opts.key_file {
        return Ok(Some(store.select(&KeySelector::Path(path), Purpose::Sign)?));
    }
    let mut keys = store.device_keys()?;
    if keys.len() > 1 {
        let list: Vec<String> = keys.iter().map(|k| format!("{} {}", k.fingerprint, k.label.as_deref().map(render_inert).unwrap_or_default())).collect();
        return Err(Halt::face(
            "more than one device key is in this store, and a registration is signed by ONE",
            format!(
                "the store holds:\n  {}\none device key serves every board you sign in to (REG-4.102), and which of these is yours here is \
                 never this command's to guess",
                list.join("\n  ")
            ),
            "name the key with `--key <path>` (`skep fingerprint --dir` lists them); never a pick",
        ));
    }
    Ok(keys.pop())
}

/// Names the device key the store holds, at its box (REG-4.104).
///
/// The box is a naming and never a generation: the key's label was fixed
/// when it was made. Where the board carries on, the key is taken as the
/// one that board's own set holds, and said as unchecked — no board is read.
///
/// # Errors
///
/// A `--label` beside a named key is refused, never dropped; and a key that
/// carries no label is faced, never sent (AUTH-5.42).
fn name_held_key(person: &mut dyn Person, key: &KeyFacts, opts: &RegistrationOptions) -> Result<Label, Halt> {
    let shown = key.label.as_deref().map(render_inert).unwrap_or_else(|| "(none)".into());
    if opts.label.is_some() {
        return Err(Halt::face(
            format!("`--label` names a device key to generate, and this registration generates none: its device key is `{shown}` ({})", key.fingerprint),
            if opts.board_carries_on {
                "where the board carries on, the node account's working key is the device key that board's own key set already holds \
                 (REG-4.102, REG-4.104): it is named at its box and never generated, and a key's label is fixed in its file — the flag \
                 could only be dropped"
            } else {
                "one device key serves every board you sign in to (REG-4.102): a key the store holds is named at its box and none is \
                 generated beside it, and a key's label is fixed in its file — the flag could only be dropped"
            },
            "run it again without `--label`; to register under another device key, name its file with `--key <path>` or its store with `--dir`",
        ));
    }
    let Some(label) = key.label.as_deref().and_then(|l| Label::new(l).ok()) else {
        return Err(Halt::face(
            format!("the device key {} carries NO label, and a registration never sends an empty byline", key.fingerprint),
            "AUTH-5.42; AUTH-5.57 step 2: an empty label is faced at its box and never sent in the request — the request's thread is \
             public forever, and a key's label is fixed in its file",
            "register under a device key that carries a name: `skep keygen --label <name>` makes one and `--key <path>` names it — \
             where the board carries on, it must be a key that board's own set already holds",
        ));
    };
    let standing = if opts.board_carries_on {
        "It is TAKEN AS the device key your board's own key set already holds — UNCHECKED: this command reads no board. Where your \
         board's set holds another key, stop here and run this from the store that holds it (`--dir`, or `--key <path>`): a node \
         account keyed to a device key your board has never seen shares nothing with it."
    } else {
        "It goes into BOTH key sets this request founds, the org root's and the node identity's."
    };
    say(
        person,
        "AUTH-5.42",
        format!(
            "THE DEVICE KEY IS NAMED HERE, never generated: `{shown}`, fingerprint {} — the one device key across every board you sign in \
             to (REG-4.102). Its name was fixed when the key was made and cannot be edited: it is the byline beside every write this key \
             makes, and at this door it rides onto a public thread on the registry's board, approved or DENIED, forever. {standing}",
            key.fingerprint
        ),
    );
    Ok(label)
}

/// Fixes the label of the device key this run will generate, at its box.
///
/// `--label` is judged by the domain test and its statements said; absent,
/// the box is asked, and re-asked on a refusal (AUTH-5.42; AUTH-1.24).
///
/// # Errors
///
/// A flag's label outside the domain, and an abandoned box.
fn device_label(person: &mut dyn Person, given: Option<Label>) -> Result<Label, Halt> {
    if let Some(label) = given {
        for s in device_box() {
            say(person, "AUTH-5.42", s);
        }
        return Ok(label);
    }
    loop {
        let text = person
            .label(Public(LabelBox { title: "name this device".into(), statements: device_box(), default: None }))
            .map_err(|_| Halt::face("no device name was given", "the box was abandoned", "run it again and answer the box, or pass `--label <name>`; nothing was generated"))?;
        match Label::new(&text) {
            Ok(label) => return Ok(label),
            Err(fault) => say(person, "AUTH-1.24", format!("that name is refused at the box: {fault}; name the device again")),
        }
    }
}

/// Says what a run stopped short of its request leaves behind.
///
/// AUTH-5.57 step 2: nothing was sent, and this composition writes no board
/// state; an anchor file written names no account and opens nothing.
/// `stored` is the key store's clause, true of where the run stopped.
fn stopped(person: &mut dyn Person, stored: &str) {
    say(
        person,
        "AUTH-5.57 step 2",
        format!(
            "this registration stops before its request, and nothing was sent anywhere: it reads and writes no board, so it leaves no \
             board state behind; any anchor file it wrote names no account and opens nothing, ever — destroy it, or keep it plainly \
             marked dead and never beside a live pair; {stored}"
        ),
    );
}

/// Returns one enrolment: a pair's two anchors, then the device key.
///
/// It is exactly three entries — R66's composition per account (REG-4.102)
/// — the pair's two anchor-flagged and the device key device-flagged, each
/// under the label its box fixed.
///
/// # Errors
///
/// A label the enrollment record refuses.
fn enrolment(pair: &[AnchorArtifact], device: &PublicKey, device_label: &Label) -> Result<Vec<Enrollment>, Halt> {
    let mut entries = Vec::with_capacity(pair.len() + 1);
    for anchor in pair {
        entries.push(Enrollment::new(anchor.public.clone(), true, Some(anchor.label.as_str().to_string())).map_err(record_refused)?);
    }
    entries.push(Enrollment::new(device.clone(), false, Some(device_label.as_str().to_string())).map_err(record_refused)?);
    Ok(entries)
}

/// Composes the request's body and signs its frame, once (REG-4.67).
///
/// The frame is `framed(skep-registration-v1, [door, fresh, shape, node,
/// board])`, `board` left out where the request carries no board root; each
/// field is the member of that name as the body writes it, `shape` the
/// kind's own row by its ordinal path. The body is `encode_registration`
/// with no `sig`.
///
/// # Errors
///
/// A member that is not in its body's form, which is this client's fault.
fn compose(door: &str, fresh: &Freshness, enrolments: &Enrolments, signer: &dyn Signer) -> Result<String, Halt> {
    let shape = enrolments.kind().row().ordinal_path();
    let node = encode_enroll(enrolments.node());
    let board = enrolments.board().map(encode_enroll);
    let frame = AdmissionFrame { door, fresh: fresh.as_str(), shape: &shape, node: &node, board: board.as_deref() };
    let signature = sig_hex(&signer.sign(&frame.to_bytes()));
    let members = (Hex64::new(fresh.as_str()), Hex64::new(signer.fingerprint().to_hex()), HexDigits::new(signature));
    let (Some(fresh), Some(signed_by), Some(signature)) = members else {
        return Err(own_fault("a member of the request is not in the form its body spells it in"));
    };
    let door = door.to_string();
    let body = match board {
        Some(board) => RegistrationBody::Fresh(Fresh { door, fresh, shape, node, board, signer: signed_by, signature }),
        None => RegistrationBody::BoardCarriesOn(BoardCarriesOn { door, fresh, shape, node, signer: signed_by, signature }),
    };
    Ok(encode_registration(&body, None))
}

/// Checks a composed request as its readers will, answering its thread key.
///
/// It is the console's check made here first (REG-4.95 step 2), over the
/// bytes about to be handed out and nothing this composition still holds:
/// the cap; the canonical parse under the kind's row, with no `sig`; the
/// door, the freshness value and the `shape` in their forms; each enrolment
/// a pair's two anchor-flagged entries and one device-flagged, every one
/// labelled (REG-4.102; AUTH-5.42); the `signer` enrolled by every enrolment
/// present and equal to `device`; and the signature over the frame re-built
/// from the parsed members.
///
/// # Errors
///
/// The first check that fails, named: the request is this client's fault.
fn verified(kind: RegistrationKind, body: &str, device: &PublicKey) -> Result<Vec<Fingerprint>, &'static str> {
    if body.len() > MAX_REGISTRATION_REQUEST_BYTES {
        return Err("the body runs past a registration request's cap");
    }
    let record = parse_registration(kind, body.as_bytes()).map_err(|_| "the body is not a canonical record under its own row")?;
    if record.sig.is_some() {
        return Err("the body carries a `sig`, which is the writing hand's and never the applicant's");
    }
    let members = record.body.request().ok_or("the body is no request's")?;
    if DoorId::parse(members.door).is_none() || Freshness::parse(members.fresh.as_str()).is_none() {
        return Err("the `door` or the `fresh` member is not in its form");
    }
    if members.shape != kind.row().ordinal_path() {
        return Err("the `shape` member does not name the request's own row");
    }
    let node = parse_enroll(members.node.as_bytes()).map_err(|_| "the `node` member is not a canonical enrollment record")?;
    let board = members.board.map(|b| parse_enroll(b.as_bytes())).transpose().map_err(|_| "the `board` member is not a canonical enrollment record")?;
    let enrolments: Vec<&[Enrollment]> = std::iter::once(node.as_slice()).chain(board.as_deref()).collect();
    for enrolment in &enrolments {
        let anchors = enrolment.iter().filter(|e| e.anchor).count();
        if enrolment.len() != 3 || anchors != 2 || enrolment.iter().any(|e| e.label().is_none()) {
            return Err("an enrolment is not a pair's two anchor-flagged entries and the device key, each labelled");
        }
    }
    let signer = Fingerprint::parse_hex(members.signer.as_str()).ok_or("the `signer` member is no fingerprint")?;
    let key = enrolled_signer(&signer, &enrolments).ok_or("an enrolment does not enrol the signer")?;
    if key != device {
        return Err("the signer is not the device key");
    }
    let signature = crate::hex::decode(members.signature.as_str()).ok_or("the `signature` member is not whole bytes of hex")?;
    let fields = members.frame_fields();
    let frame = framed(REGISTRATION_TAG, &fields.iter().map(|f| f.as_bytes()).collect::<Vec<_>>());
    skep_signature::verify(key.sig_alg_row().tag, key, &frame, &signature).map_err(|_| "the signature does not verify over the frame re-built from the body's members")?;
    Ok(thread_key(enrolments.iter().flat_map(|e| e.iter())))
}

/// Composes an applicant's registration request (the module's order).
///
/// It answers the request's body, signed and checked, with the public
/// facts of the keys it carries; the body is the caller's to hand out, and
/// [`say_request`] says what is carried beside it. Nothing of the request
/// is answered before every sheet of the run has read back and verified
/// (REG-4.103).
///
/// # Errors
///
/// In the module's order: a door identifier that is none; a flag's label
/// outside the domain, or more labels or destinations than the kind's
/// anchors; the device key's refusals — the store's own, more than one
/// device key with none named, none where the board carries on, a `--label`
/// beside a named key, a named key that carries no label; an abandoned box;
/// the backup moment's halts; the generation's; a label the enrollment
/// record refuses; and a request that fails its own check.
pub fn registration_request(person: &mut dyn Person, store: &FileStore, opts: &RegistrationOptions) -> Result<RegistrationRequest, Halt> {
    let kind = if opts.board_carries_on { RegistrationKind::BoardCarriesOn } else { RegistrationKind::Fresh };
    // 1 — the door, judged before anything is asked, generated or written.
    let Some(door) = DoorId::parse(&opts.door) else { return Err(door_refused(&opts.door)) };
    // 2 — every label a flag fixes, at its box; and their count, since a
    // value past the kind's anchors would be dropped or land on another
    // pair's sheet.
    let anchors = if opts.board_carries_on { 2 } else { 4 };
    for (flag, given) in [("--anchor-label", opts.anchor_labels.len()), ("--anchor-out", opts.anchor_out.len())] {
        if given > anchors {
            return Err(Halt::face(
                format!("`{flag}` is given {given} times, and this registration makes {anchors} anchors"),
                if opts.board_carries_on {
                    "where the board carries on, the request generates the node pair alone (REG-4.104): its sheets a and b, in that order"
                } else {
                    "a fresh registration generates two pairs (REG-4.104): the org root's sheets a and b, then the node pair's, in that order"
                },
                format!("give `{flag}` at most {anchors} times"),
            ));
        }
    }
    let anchor_labels: Vec<Label> = opts
        .anchor_labels
        .iter()
        .map(|l| Label::new(l))
        .collect::<Result<_, _>>()
        .map_err(|fault| Halt::face(format!("an anchor label is refused at the box: {fault}"), "AUTH-1.24's domain", "pass labels inside the domain"))?;
    // 3 — the device key: named where held, its label fixed at the box where
    // one is to be generated.
    let held = held_device_key(store, opts)?;
    if held.is_none() && opts.board_carries_on {
        return Err(Halt::face_at(
            store.root(),
            "the key store holds no device key, and a registration whose board carries on names one and generates none",
            "the node account's working key is the device key your board's own key set already holds (REG-4.102, REG-4.104): it is \
             named at its box and never made here — a key generated now would be one your board has never seen",
            "run this from the store that holds your board's device key (`--dir <path>`), or name its file with `--key <path>`; an org \
             with no board yet registers without `--existing-board`",
        ));
    }
    let given_label = match (&held, &opts.label) {
        (None, Some(text)) => Some(Label::new(text).map_err(|fault| {
            Halt::face(format!("the label is refused at the box: {fault}"), "AUTH-1.24's domain: non-empty, no line break, at most 128 bytes of UTF-8", "pass a label inside the domain")
        })?),
        _ => None,
    };
    let device_label = match &held {
        Some(key) => name_held_key(person, key, opts)?,
        None => device_label(person, given_label)?,
    };
    // 4 — the moment's node arm, over every pair this kind generates.
    let stored = match &held {
        Some(_) => "the key store is as it was: this run names its device key and generates none",
        None => "and nothing of this run is in the key store: its device key is generated after the moment",
    };
    let venue = Venue::Registration { board_carries_on: opts.board_carries_on };
    let moment = BackupOptions {
        labels: anchor_labels,
        destinations: opts.anchor_out.clone(),
        paper: opts.paper,
        store: Some(store.root().to_path_buf()),
        host_name: opts.host_name.clone(),
        date: opts.date.clone(),
    };
    let outcome = match backup_moment(person, &venue, &moment) {
        Ok(outcome) => outcome,
        Err(halt) => {
            stopped(person, stored);
            return Err(halt);
        }
    };
    let (board_pair, node_pair) = match (opts.board_carries_on, outcome.anchors.as_slice()) {
        (false, [root_a, root_b, node_a, node_b]) => (vec![root_a.clone(), root_b.clone()], vec![node_a.clone(), node_b.clone()]),
        (true, [node_a, node_b]) => (Vec::new(), vec![node_a.clone(), node_b.clone()]),
        _ => {
            stopped(person, stored);
            return Err(own_fault("the backup moment answered another count of anchors than this request's kind generates"));
        }
    };
    // The device key: the one named, or — only now, every sheet verified —
    // the one this run generates.
    let (key, generated) = match held {
        Some(key) => (key, false),
        None => {
            let made = match store.generate_and_sweep(Some(device_label.clone())) {
                Ok(made) => made,
                Err(e) => {
                    stopped(person, "and the key store holds nothing of this run's device key: its generation did not complete");
                    return Err(e.into());
                }
            };
            for swept in &made.swept {
                say(person, "§3a", format!("removed an unfinished key file {}, left by a generation that did not complete", swept.display()));
            }
            for (left, e) in &made.unswept {
                say(person, "§3a", format!("an unfinished key file could not be removed ({e}) and stands: {}", left.display()));
            }
            let path = store.key_path(&made.id.0);
            say(
                person,
                "§3a",
                format!(
                    "key file written: {} — the seed rests in this file and the filesystem's modes are its whole protection (0600 under \
                     0700): a same-user process reads it and a disk image carries it. It is your device key in every key set this request \
                     founds, and each account's own pair of sheets is what its loss recovers from",
                    path.display()
                ),
            );
            (store.select(&KeySelector::Path(&path), Purpose::Sign)?, true)
        }
    };
    let standing = if generated {
        "the device key this run generated stands in the key store, enrolled nowhere: the next run names it and generates none"
    } else {
        "the key store is as it was"
    };
    // 5–7 — the enrolments, the frame and its one signature, the check.
    let composed = (|| -> Result<(String, Freshness, Vec<Fingerprint>), Halt> {
        let node = enrolment(&node_pair, &key.public, &device_label)?;
        let enrolments = match kind {
            RegistrationKind::BoardCarriesOn => Enrolments::BoardCarriesOn { node },
            _ => Enrolments::Fresh { node, board: enrolment(&board_pair, &key.public, &device_label)? },
        };
        let signer = store.signer(&KeySelector::Path(&key.path))?;
        // The freshness value: thirty-two bytes of this client's own
        // entropy, as 64 lowercase hex (REG-4.84).
        let fresh = Freshness::parse(&crate::hex::encode(&fresh_bytes(32))).ok_or_else(|| own_fault("the freshness value is not 64 lowercase hex"))?;
        let body = compose(&opts.door, &fresh, &enrolments, &*signer)?;
        let thread = verified(enrolments.kind(), &body, &key.public).map_err(own_fault)?;
        Ok((body, fresh, thread))
    })();
    let (body, fresh, thread) = match composed {
        Ok(composed) => composed,
        Err(halt) => {
            stopped(person, standing);
            return Err(halt);
        }
    };
    // The request's keys, each once (AUTH-5.57 step 3): what the scannable
    // form shows beside the block.
    let sheet = |role: KeyRole, pair: &str, artifacts: &[AnchorArtifact]| -> Vec<RequestKey> {
        artifacts
            .iter()
            .zip(["a", "b"])
            .map(|(a, letter)| RequestKey { role, named: format!("{pair} pair, sheet {letter}"), label: a.label.as_str().to_string(), fingerprint: a.fingerprint })
            .collect()
    };
    let mut keys = sheet(KeyRole::OrgRootAnchor, "org root", &board_pair);
    keys.extend(sheet(KeyRole::NodeAnchor, "node", &node_pair));
    keys.push(RequestKey {
        role: KeyRole::Device,
        named: if opts.board_carries_on { "device key".into() } else { "device key, in both key sets".into() },
        label: device_label.as_str().to_string(),
        fingerprint: key.fingerprint,
    });
    Ok(RegistrationRequest {
        kind,
        body,
        door,
        fresh,
        device: DeviceKey { fingerprint: key.fingerprint, label: device_label.as_str().to_string(), path: key.path, generated },
        board_pair,
        node_pair,
        keys,
        thread_key: thread,
    })
}

/// Says what the person carries beside a request's body (AUTH-5.57 step 3).
///
/// It is the scannable form and the disposition, said once the body is
/// handed out, so they stand under the block and are not scrolled away by
/// it: each key once, its label rendered inert beside its fingerprint in
/// the grouped form (AUTH-5.1), for the out-of-band comparison with the
/// approver (AUTH-5.57 step 4); the thread's key, by which an applicant
/// holding no account finds its own thread (REG-4.78); and that the request
/// serves its one door and its sheets belong to this one application
/// (REG-4.74; AUTH-5.57 step 4; REG-4.101) — where the board carries on,
/// the node pair's two alone, never the org root's own.
pub fn say_request(person: &mut dyn Person, request: &RegistrationRequest) {
    say(
        person,
        "AUTH-5.57 step 3",
        format!(
            "THE REQUEST is composed, signed once by the device key, and checked: one block to carry to the door whole, its members plain \
             — never edited, never retyped. Its {} keys follow, each beside the name its box fixed: compare them with whoever approves \
             this request, out of band, before anything depends on it (AUTH-5.57 step 4).",
            request.keys.len()
        ),
    );
    for k in &request.keys {
        say(
            person,
            "AUTH-5.57 step 3",
            format!("{} — `{}`\n  {}", k.named, render_inert(&k.label), group_hex(&k.fingerprint.to_hex()).replace('\n', "\n  ")),
        );
    }
    say(
        person,
        "REG-4.78",
        format!(
            "the request's thread on the door's board is found by these {} fingerprints, in this order:\n  {}",
            request.thread_key.len(),
            request.thread_key.iter().map(Fingerprint::to_hex).collect::<Vec<_>>().join("\n  ")
        ),
    );
    let papers = match request.kind {
        RegistrationKind::BoardCarriesOn => {
            "the two NODE sheets this run made, and those alone — your org root's own two sheets are your live board's way back and no \
             paper of this application: never destroy them for it (REG-4.101)"
        }
        _ => "all four, both pairs",
    };
    say(
        person,
        "AUTH-5.57 step 4",
        format!(
            "THIS REQUEST IS FOR ONE DOOR, `{}`, and serves that door alone: carried to any other it is refused as framed for this \
             one (REG-4.74). What it carries — these keys and their names — is public on that door's board forever once the door \
             takes it, approved or not. And these sheets belong to THIS application: where it ends without an account — denied, \
             refused, cancelled or never collected — destroy them, {papers}, and generate fresh ones for any other door; the device key \
             your own client holds is not among them.",
            request.door
        ),
    );
}
