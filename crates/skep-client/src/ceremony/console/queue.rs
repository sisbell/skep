//! The queue read, triage, and the reads derived from it (REG-4.78 to
//! REG-4.85).
//!
//! **The queue is a read and never a document.** [`read_queue`] is one
//! search — the links typed a row under `request` whose `to` is the door's
//! binding-writing account — and what it keeps of the answer, in this
//! order, cheapest first:
//!
//! 1. The link as stored: its type exactly a request's row, fresh or
//!    board-carries-on and never the parent; its `to` exactly the door
//!    account; its home a doc 1; a position the board dates it at.
//! 2. **The admitted-homes guard.** The request's home is named by the
//!    `intake` term of the policy version standing at the request's own
//!    position. A request-typed record anywhere else is never parsed: its
//!    atom is not read, it is not listed and it is not answered. A door
//!    with no policy standing admits no home at all (REG-4.139).
//! 3. **The row guard.** The body's `shape` member, read off the head of
//!    the atom and no further, names the row the link is typed. A record
//!    whose link is typed another row than its applicant signed is a
//!    transcription's fault and no request: it is passed over, and said.
//! 4. **The shape, before the bytes** ([`request_shape`]; REG-4.78): "at
//!    most TWO enrolments of THREE keys each, every label at most 128
//!    bytes, a request past that shape refused cheaply before any tree is
//!    built". The body is walked for its enrolments' entries and labels
//!    alone. A request past the shape is never parsed: it stands on the
//!    queue failing, `enrolment-not-honored`, with none of its members
//!    read.
//! 5. The canonical parse under the row (`parse_registration`).
//! 6. **The framing re-check** ([`triage`]), whose verdict the request
//!    carries: the door it is framed for is this door; its freshness value
//!    is unspent — no earlier request at this door, by journal order,
//!    carries it; each enrolment is one this console honors — the
//!    enrollment grammar and the key kinds this console enrols; every
//!    enrolment present enrols the `signer`; and the one signature verifies
//!    under the signer's key over the frame re-built from the members.
//!
//! Triage writes nothing. A verdict that fails is what the approval's hand
//! writes as the refused answer; one that passes is what it approves.
//!
//! **The threads.** A request's answers are the registration records homed
//! in the door account's own doc 1 whose `to` is the request's link — the
//! one residence an answer grounds an act from (REG-4.79) — and its
//! approval link the link of that row there. From them each request stands
//! in one of three lists ([`State`]): waiting, with no answer; approved and
//! not collected, an approved answer whose node account has no doc 1 yet
//! ([`collected`]; REG-4.123 step 5); or closed.

use std::collections::HashSet;

use skep_identity::{enrolled_signer, framed, parse_enroll, thread_key, Enrollment, Fingerprint, ALG_FNDSA512_PREVIEW_ED25519, REGISTRATION_TAG};
use skep_registry::{parse_registration, t_approval, t_registration, t_request, Fault, RegistrationBody, RegistrationKind, RequestMembers};

use super::Door;
use crate::address::{account_of, doc_1_of, parse_address};
use crate::board::{frames, Answer, Board, Rejection, Token};
use crate::ceremony::deposit::closed_face;
use crate::ceremony::policy::{read_policy, PolicyChain};
use crate::ceremony::registry_record::{links_homed, links_to, one_address, stored_link, Atoms, StoredLink};
use crate::halt::Halt;

/// The most enrolments one request carries: its node account's, and its
/// board root's where it carries one (REG-4.78).
pub const MAX_ENROLMENTS: usize = 2;

/// The most keys one enrolment of a request names (REG-4.78).
pub const MAX_ENROLMENT_KEYS: usize = 3;

/// The most bytes a key's label holds in a request's enrolment (REG-4.78).
pub const MAX_LABEL_BYTES: usize = 128;

/// One key of a request, as a reviewer reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestKey {
    /// What the key is in the request: its pair and its sheet, or the
    /// device key.
    pub named: String,
    /// The label its enrolment carries; empty where it carries none.
    pub label: String,
    /// The key's fingerprint.
    pub fingerprint: Fingerprint,
}

/// The framing re-check's verdict on a request (REG-4.84, REG-4.85).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The request passes: the approval's hand may approve it.
    Passes,
    /// The request fails: the approval's hand writes the refused answer.
    Fails {
        /// The fault the refused answer states.
        fault: Fault,
        /// What the check found, in this console's words.
        why: String,
    },
}

/// One request on the queue: an admitted home's record, parsed and judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The request's link address: the name `approve` and `deny` take.
    pub link: String,
    /// The home the request is written on: an intake home's doc 1.
    pub home: String,
    /// The link's position: the request's place in journal order.
    pub at: u64,
    /// The board's testimony of when it committed, in milliseconds since
    /// the epoch, where it holds one.
    pub time: Option<u64>,
    /// The request's kind: the row its link is typed and its `shape` names.
    pub kind: RegistrationKind,
    /// The door the request is framed for, as written; empty where the
    /// request is past the shape, and so never parsed.
    pub door: String,
    /// The node account's enrolment, as its text: what a genesis takes
    /// verbatim (REG-4.95 step 2); empty where the request is never parsed.
    pub node: String,
    /// The fingerprints of the node enrolment's keys; empty where the
    /// enrolment does not parse.
    pub node_fingerprints: Vec<Fingerprint>,
    /// The fingerprint of the key that signed the frame: the device key;
    /// empty where the request is never parsed.
    pub signer: String,
    /// The request's keys, each once.
    pub keys: Vec<RequestKey>,
    /// The thread's key: every key's fingerprint, ascending, each once
    /// (REG-4.78); empty where an enrolment does not parse.
    pub thread_key: Vec<Fingerprint>,
    /// The framing re-check's verdict.
    pub verdict: Verdict,
}

/// One answer on a request's thread, homed in the door account's doc 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadAnswer {
    /// The answer's link address.
    pub link: String,
    /// The link's position.
    pub at: Option<u64>,
    /// The answer's body: approved, refused or denied.
    pub body: RegistrationBody,
}

/// The approval link of a request: the genesis the approval wrote.
///
/// Where two consoles each wrote one for a request, a thread holds the
/// first by journal order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalLink {
    /// The approval link's address.
    pub link: String,
    /// The genesis link it runs from.
    pub genesis: String,
    /// The link's position.
    pub at: Option<u64>,
}

/// Where a request stands, read off the board's records alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    /// No answer stands on the thread.
    Waiting,
    /// An approved answer stands, and the node account it names has no
    /// doc 1 yet: its first signed session is not taken (REG-4.123 step 5).
    ApprovedNotCollected,
    /// The thread is answered and nothing is owed on it: refused, denied,
    /// or approved and collected.
    Closed,
}

/// A request with its thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thread {
    /// The request.
    pub request: Request,
    /// The answers on its thread, in journal order.
    pub answers: Vec<ThreadAnswer>,
    /// The approval link, where an approval wrote one.
    pub approval: Option<ApprovalLink>,
    /// Where the request stands.
    pub state: State,
}

impl Thread {
    /// Returns the approved answer's body, where the thread holds one.
    pub fn approved(&self) -> Option<&skep_registry::Approved> {
        self.answers.iter().find_map(|answer| match &answer.body {
            RegistrationBody::Approved(approved) => Some(approved),
            _ => None,
        })
    }
}

/// A record of a request's type from an admitted home that is no request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassedOver {
    /// The link's address.
    pub link: String,
    /// Why it is no request.
    pub why: String,
}

/// The queue at a door: every request an admitted home wrote, with its
/// thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queue {
    /// The door's policy document, as read.
    pub policy: PolicyChain,
    /// The requests, in journal order, each with its thread.
    pub threads: Vec<Thread>,
    /// Records of a request's type from an admitted home that are no
    /// request: the row guard's, and the parse's.
    pub passed_over: Vec<PassedOver>,
}

impl Queue {
    /// Returns the thread of the request at `link`, where the queue holds it.
    pub fn thread(&self, link: &str) -> Option<&Thread> {
        self.threads.iter().find(|thread| thread.request.link == link)
    }

    /// Returns the requests no answer stands for, in journal order.
    pub fn waiting(&self) -> impl Iterator<Item = &Thread> {
        self.threads.iter().filter(|thread| thread.state == State::Waiting)
    }

    /// Returns the requests approved whose registration is not collected.
    ///
    /// Each holds an approved answer naming a node account that has no
    /// doc 1 yet (REG-4.123 step 5).
    pub fn approved_and_not_collected(&self) -> impl Iterator<Item = &Thread> {
        self.threads.iter().filter(|thread| thread.state == State::ApprovedNotCollected)
    }

    /// Returns the requests closed: refused, denied, or approved and
    /// collected.
    pub fn closed(&self) -> impl Iterator<Item = &Thread> {
        self.threads.iter().filter(|thread| thread.state == State::Closed)
    }
}

/// Returns whether the registration at `node_account` is collected.
///
/// A registration is collected where its node account holds a doc 1: the
/// account's first signed session mints it as its first act (REG-4.123
/// step 5; REG-4.97). The read is the metadata read at the computable
/// address, a guest's where no token is given: any document registered
/// there answers collected, and `doc_not_registered` answers not.
///
/// # Errors
///
/// The death signal under `token`, faced; a refusal other than
/// `doc_not_registered` and `withheld`, the board's; and [`Board::op`]'s
/// errors.
pub fn collected(board: &Board, token: Option<&Token>, node_account: &str) -> Result<bool, Halt> {
    match board.op(token, &frames::doc_metadata(&doc_1_of(node_account)))? {
        Answer::Closed => Err(closed_face("reading the node account's home")),
        Answer::Document(v) => match Rejection::of(&v) {
            None => Ok(true),
            Some(r) if r.key() == "doc_not_registered" => Ok(false),
            // A document registered there that this reader may not read is
            // a document all the same.
            Some(r) if r.key() == "withheld" => Ok(true),
            Some(r) => Err(r.refused(&v)),
        },
    }
}

/// Walks the strings of JSON text at their depths, building no tree.
///
/// `visit` is handed each string that stands as a value — a member's, or
/// an array's element — with its nesting depth, one inside the outer
/// object; the raw bytes of the member's name it stands under; its own raw
/// bytes; and the count of bytes it decodes to. It answers whether the
/// walk goes on. `entry` is handed the depth at which each object opens,
/// and answers the same. The walk judges no grammar: text that is no JSON
/// is walked as far as its quotes pair, and what a canonical parse refuses
/// it refuses later. It answers `false` where a callback stopped it, a
/// string does not close, or the text nests past sixty-three levels.
fn walk_strings<'t>(text: &'t [u8], mut entry: impl FnMut(usize) -> bool, mut visit: impl FnMut(usize, Option<&'t [u8]>, &'t [u8], usize) -> bool) -> bool {
    let (mut depth, mut i) = (0usize, 0usize);
    // One bit a level: whether the container open at that depth is an array.
    let mut arrays: u64 = 0;
    let mut name: Option<&'t [u8]> = None;
    let mut after_colon = false;
    while i < text.len() {
        match text[i] {
            b'"' => {
                let start = i + 1;
                let (mut j, mut decoded) = (start, 0usize);
                loop {
                    match text.get(j) {
                        None => return false,
                        Some(b'"') => break,
                        Some(b'\\') => match text.get(j + 1) {
                            Some(b'u') => {
                                let unit = |at: usize| text.get(at..at + 4).and_then(|hex| std::str::from_utf8(hex).ok()).and_then(|hex| u32::from_str_radix(hex, 16).ok());
                                let Some(first) = unit(j + 2) else { return false };
                                let pair = (0xD800..0xDC00).contains(&first) && text.get(j + 6..j + 8) == Some(b"\\u".as_slice()) && unit(j + 8).is_some_and(|low| (0xDC00..0xE000).contains(&low));
                                if pair {
                                    decoded += 4;
                                    j += 12;
                                } else {
                                    decoded += match first {
                                        0..=0x7F => 1,
                                        0x80..=0x7FF => 2,
                                        _ => 3,
                                    };
                                    j += 6;
                                }
                            }
                            Some(_) => {
                                decoded += 1;
                                j += 2;
                            }
                            None => return false,
                        },
                        Some(_) => {
                            decoded += 1;
                            j += 1;
                        }
                    }
                }
                let raw = &text[start..j];
                let in_array = depth > 0 && arrays & (1 << (depth - 1)) != 0;
                if in_array || after_colon {
                    if !visit(depth, name, raw, decoded) {
                        return false;
                    }
                    after_colon = false;
                } else {
                    name = Some(raw);
                }
                i = j + 1;
            }
            b':' => {
                after_colon = true;
                i += 1;
            }
            b',' => {
                after_colon = false;
                i += 1;
            }
            opening @ (b'{' | b'[') => {
                if depth >= 63 || (opening == b'{' && !entry(depth)) {
                    return false;
                }
                if opening == b'[' {
                    arrays |= 1 << depth;
                } else {
                    arrays &= !(1 << depth);
                }
                depth += 1;
                after_colon = false;
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                after_colon = false;
                i += 1;
            }
            _ => i += 1,
        }
    }
    true
}

/// Returns the `shape` member a request's body names, read off its head.
///
/// The body is walked no further than the member: a canonical request
/// spells `type`, `door`, `fresh` and then `shape`, ahead of its
/// enrolments and its signature (REG-1.86). `None` where the outer object
/// names no such string member.
pub fn shape_named(body: &[u8]) -> Option<&str> {
    let mut found = None;
    walk_strings(
        body,
        |_| true,
        |depth, name, raw, _| {
            if depth == 1 && name == Some(b"shape".as_slice()) {
                found = std::str::from_utf8(raw).ok();
                return false;
            }
            true
        },
    );
    found.filter(|shape| !shape.contains('\\'))
}

/// Judges one enrolment's shape before its keys are decoded (REG-4.78).
///
/// The text is walked for its entries and its labels alone: at most
/// [`MAX_ENROLMENT_KEYS`] keys, and every label at most
/// [`MAX_LABEL_BYTES`] bytes.
///
/// # Errors
///
/// What the shape breaks, in this console's words.
pub fn enrolment_shape(text: &str) -> Result<(), String> {
    let (mut keys, mut long) = (0usize, false);
    walk_strings(
        text.as_bytes(),
        |depth| {
            // An entry is an object inside the record's one array.
            if depth == 2 {
                keys += 1;
            }
            keys <= MAX_ENROLMENT_KEYS
        },
        |depth, name, _, decoded| {
            if depth == 3 && name == Some(b"label".as_slice()) && decoded > MAX_LABEL_BYTES {
                long = true;
                return false;
            }
            true
        },
    );
    if keys > MAX_ENROLMENT_KEYS {
        return Err(format!("an enrolment names more than {MAX_ENROLMENT_KEYS} keys"));
    }
    if long {
        return Err(format!("a key's label runs past {MAX_LABEL_BYTES} bytes"));
    }
    Ok(())
}

/// Judges a request's shape before any tree is built (REG-4.78).
///
/// The body is walked for its enrolment members alone — `node`, and `board`
/// where it carries one: at most [`MAX_ENROLMENTS`] of them, each judged by
/// [`enrolment_shape`]. An enrolment is a string member, so its text is one
/// string decoded and nothing more; no member is parsed, no key decoded. A
/// body the walk cannot read as that is the canonical parse's to refuse.
///
/// # Errors
///
/// What the shape breaks, in this console's words.
pub fn request_shape(body: &[u8]) -> Result<(), String> {
    let (mut enrolments, mut fault) = (0usize, None);
    walk_strings(
        body,
        |_| true,
        |depth, name, raw, _| {
            if depth != 1 || !(name == Some(b"node".as_slice()) || name == Some(b"board".as_slice())) {
                return true;
            }
            enrolments += 1;
            if enrolments > MAX_ENROLMENTS {
                fault = Some(format!("it carries more than {MAX_ENROLMENTS} enrolments"));
                return false;
            }
            // The member's text: one JSON string decoded, no tree built.
            let mut quoted = Vec::with_capacity(raw.len() + 2);
            quoted.push(b'"');
            quoted.extend_from_slice(raw);
            quoted.push(b'"');
            match serde_json::from_slice::<String>(&quoted).ok().map(|text| enrolment_shape(&text)) {
                Some(Err(why)) => {
                    fault = Some(why);
                    false
                }
                _ => true,
            }
        },
    );
    fault.map_or(Ok(()), Err)
}

/// What the framing re-check answers: its verdict, and what it parsed.
struct Triaged {
    verdict: Verdict,
    node: Vec<Enrollment>,
    board: Option<Vec<Enrollment>>,
}

/// Returns a failing verdict under `fault`.
fn fails(fault: Fault, why: impl Into<String>) -> Verdict {
    Verdict::Fails { fault, why: why.into() }
}

/// Runs the framing re-check over a request's members (REG-4.84; REG-4.95
/// step 2).
///
/// `door` is this door's identifier in its one spelling, and `spent`
/// whether an earlier request at this door, by journal order, carries the
/// request's freshness value. The checks run cheapest first, and the first
/// to fail names the fault: the door (`not-this-door`); the freshness value
/// (`freshness-spent`); each enrolment's grammar and the kinds of key this
/// console enrols — the production kind alone, a preview key being one no
/// served board enrols — and that every enrolment present enrols the
/// `signer` (`enrolment-not-honored`); and the one signature over the frame
/// re-built from the members, under the signer's key (`not-this-door`: the
/// payload carries no signature over this door's frame).
///
/// **Precondition.** The request's shape has passed ([`request_shape`]):
/// each enrolment names at most [`MAX_ENROLMENT_KEYS`] keys, so the parse
/// here decodes at most that many an enrolment.
fn triage(door: &str, members: &RequestMembers<'_>, spent: bool) -> Triaged {
    // The enrolments are parsed for what a reviewer reads of them whatever
    // the verdict.
    let parsed = |text: &str| parse_enroll(text.as_bytes()).ok();
    let (node, board) = (parsed(members.node), members.board.map(parsed));
    let held = |verdict: Verdict| Triaged { verdict, node: node.clone().unwrap_or_default(), board: board.clone().flatten() };
    if members.door != door {
        return held(fails(Fault::NotThisDoor, format!("it is framed for `{}`, and this door is `{door}`", crate::sheet::render_inert(members.door))));
    }
    if spent {
        return held(fails(Fault::FreshnessSpent, "an earlier request at this door carries its freshness value"));
    }
    let Some(node) = node else {
        return Triaged { verdict: fails(Fault::EnrolmentNotHonored, "its `node` member is no canonical enrollment record"), node: Vec::new(), board: None };
    };
    let board = match board {
        None => None,
        Some(Some(board)) => Some(board),
        Some(None) => return Triaged { verdict: fails(Fault::EnrolmentNotHonored, "its `board` member is no canonical enrollment record"), node, board: None },
    };
    let done = |verdict: Verdict| Triaged { verdict, node: node.clone(), board: board.clone() };
    let enrolments: Vec<&[Enrollment]> = std::iter::once(node.as_slice()).chain(board.as_deref()).collect();
    if enrolments.iter().flat_map(|enrolment| enrolment.iter()).any(|entry| entry.key.alg() == ALG_FNDSA512_PREVIEW_ED25519) {
        return done(fails(Fault::EnrolmentNotHonored, "an enrolment names a key of the preview kind, which this door does not enrol"));
    }
    let Some(signer) = Fingerprint::parse_hex(members.signer.as_str()) else {
        return done(fails(Fault::EnrolmentNotHonored, "its `signer` member is no fingerprint"));
    };
    let Some(key) = enrolled_signer(&signer, &enrolments) else {
        return done(fails(Fault::EnrolmentNotHonored, "an enrolment it carries does not enrol the key that signed it"));
    };
    let Some(signature) = crate::hex::decode(members.signature.as_str()) else {
        return done(fails(Fault::NotThisDoor, "its signature is not whole bytes of hex"));
    };
    let fields = members.frame_fields();
    let frame = framed(REGISTRATION_TAG, &fields.iter().map(|field| field.as_bytes()).collect::<Vec<_>>());
    if skep_signature::verify(key.sig_alg_row().tag, key, &frame, &signature).is_err() {
        return done(fails(Fault::NotThisDoor, "its signature does not verify over the frame re-built from its members"));
    }
    done(Verdict::Passes)
}

/// Returns the keys of a request, each once, as a reviewer reads them.
///
/// A pair's anchor-flagged entries are its sheets a and b in the record's
/// order, and the entry that is no anchor the device key, named once though
/// two enrolments carry it.
fn keys_of(node: &[Enrollment], board: Option<&[Enrollment]>) -> Vec<RequestKey> {
    let mut keys: Vec<RequestKey> = Vec::new();
    let mut devices: Vec<RequestKey> = Vec::new();
    for (pair, enrolment) in board.map(|board| ("org root", board)).into_iter().chain(std::iter::once(("node", node))) {
        let mut sheet = b'a';
        for entry in enrolment {
            let key = |named: String| RequestKey { named, label: entry.label().unwrap_or_default().to_string(), fingerprint: Fingerprint::of(&entry.key) };
            if entry.anchor {
                keys.push(key(format!("{pair} pair, sheet {}", sheet as char)));
                sheet = sheet.saturating_add(1);
            } else if !devices.iter().any(|device| device.fingerprint == Fingerprint::of(&entry.key)) {
                devices.push(key("device key".to_string()));
            }
        }
    }
    keys.extend(devices);
    keys
}

/// Reads the queue at `door`: every request an admitted home wrote, each
/// judged and with its thread (the module's order).
///
/// The read is a guest's, or `token`'s where one is given: every record it
/// reads is published. A door with no policy standing has an empty queue,
/// and no request is read at all.
///
/// # Errors
///
/// The death signal under `token`, faced; the board's refusal of a read;
/// an answer of a shape this client does not know; and [`Board::op`]'s
/// errors.
pub fn read_queue(board: &Board, token: Option<&Token>, door: &Door) -> Result<Queue, Halt> {
    let policy = read_policy(board, token, &door.account)?;
    let mut queue = Queue { policy, threads: Vec::new(), passed_over: Vec::new() };
    // No policy standing: no home is admitted, and nothing is parsed.
    if queue.policy.standing().is_err() {
        return Ok(queue);
    }
    let door_text = door.id.to_string();
    // 1 — the search under `request`, and each link as stored.
    let mut links = links_to(board, token, &t_request().to_string(), &door.account)?;
    links.sort();
    links.dedup();
    let mut stored: Vec<(StoredLink, RegistrationKind, u64)> = Vec::new();
    for link in links {
        let Some(found) = stored_link(board, token, &link)? else { continue };
        let Some(kind) = one_address(&found.value.ty).and_then(parse_address).and_then(|ty| RegistrationKind::at(&ty)).filter(|kind| kind.is_request()) else { continue };
        if one_address(&found.value.to) != Some(door.account.as_str()) {
            continue;
        }
        let home_is_doc_1 = account_of(&found.home).is_some_and(|account| doc_1_of(&account) == found.home);
        let Some(at) = found.value.at.filter(|_| home_is_doc_1) else { continue };
        stored.push((found, kind, at));
    }
    // Journal order: the freshness set's order, and the lists'.
    stored.sort_by(|a, b| (a.2, &a.0.link).cmp(&(b.2, &b.0.link)));
    let mut atoms = Atoms::new(board, token);
    let mut seen_fresh: HashSet<String> = HashSet::new();
    for (found, kind, at) in stored {
        // 2 — the admitted-homes guard, by the version at the request's own
        // position: a record on any other home is never parsed.
        let Some(home_account) = account_of(&found.home) else { continue };
        let admitted = queue.policy.standing_at(at).is_ok_and(|standing| standing.policy.intake.iter().any(|home| home.to_string() == home_account));
        if !admitted {
            continue;
        }
        let Some(atom) = one_address(&found.value.from).map(str::to_string) else { continue };
        let Some(bytes) = atoms.read(&found.home, &atom)? else { continue };
        // 3 — the row guard, off the body's head.
        let row = kind.row().ordinal_path();
        match shape_named(&bytes) {
            Some(shape) if shape == row => {}
            shape => {
                let named = shape.map(|shape| format!("`{}`", crate::sheet::render_inert(shape))).unwrap_or_else(|| "no row".to_string());
                queue.passed_over.push(PassedOver { link: found.link, why: format!("its link is typed the row {row} and its signed `shape` names {named}") });
                continue;
            }
        }
        // 4 — the shape, before any tree is built: a request past it is
        // never parsed, and stands failing with none of its members read.
        if let Err(why) = request_shape(&bytes) {
            let request = Request {
                link: found.link,
                home: found.home,
                at,
                time: found.time,
                kind,
                door: String::new(),
                node: String::new(),
                node_fingerprints: Vec::new(),
                signer: String::new(),
                keys: Vec::new(),
                thread_key: Vec::new(),
                verdict: fails(Fault::EnrolmentNotHonored, why),
            };
            queue.threads.push(Thread { request, answers: Vec::new(), approval: None, state: State::Waiting });
            continue;
        }
        // 5 — the canonical parse under the row.
        let record = match parse_registration(kind, &bytes) {
            Ok(record) => record,
            Err(refusal) => {
                queue.passed_over.push(PassedOver { link: found.link, why: format!("its body is no record of the row {row}: {}", refusal.token()) });
                continue;
            }
        };
        let Some(members) = record.body.request() else { continue };
        // 6 — the framing re-check. The freshness set is this door's own:
        // every request an admitted home wrote that is framed for it.
        let at_this_door = members.door == door_text;
        let spent = at_this_door && seen_fresh.contains(members.fresh.as_str());
        if at_this_door {
            seen_fresh.insert(members.fresh.as_str().to_string());
        }
        let triaged = triage(&door_text, &members, spent);
        let all: Vec<&Enrollment> = triaged.node.iter().chain(triaged.board.iter().flatten()).collect();
        let request = Request {
            link: found.link,
            home: found.home,
            at,
            time: found.time,
            kind,
            door: members.door.to_string(),
            node: members.node.to_string(),
            node_fingerprints: triaged.node.iter().map(|entry| Fingerprint::of(&entry.key)).collect(),
            signer: members.signer.as_str().to_string(),
            keys: keys_of(&triaged.node, triaged.board.as_deref()),
            thread_key: thread_key(all),
            verdict: triaged.verdict,
        };
        queue.threads.push(Thread { request, answers: Vec::new(), approval: None, state: State::Waiting });
    }
    if queue.threads.is_empty() {
        return Ok(queue);
    }
    // The threads: this door's own answers and approval links, homed in
    // its own doc 1 alone (REG-4.79).
    let mut own = links_homed(board, token, &door.home, &t_registration().to_string())?;
    own.sort();
    own.dedup();
    let approval_row = t_approval().to_string();
    for link in own {
        let Some(found) = stored_link(board, token, &link)? else { continue };
        let Some(request) = one_address(&found.value.to).map(str::to_string) else { continue };
        let Some(thread) = queue.threads.iter_mut().find(|thread| thread.request.link == request) else { continue };
        if found.value.typed_exactly(&approval_row) {
            // The first by journal order, where two consoles each wrote one.
            if let Some(genesis) = one_address(&found.value.from) {
                let link = ApprovalLink { link: found.link.clone(), genesis: genesis.to_string(), at: found.value.at };
                if thread.approval.as_ref().is_none_or(|held| (link.at, &link.link) < (held.at, &held.link)) {
                    thread.approval = Some(link);
                }
            }
            continue;
        }
        let Some(kind) = one_address(&found.value.ty).and_then(parse_address).and_then(|ty| RegistrationKind::at(&ty)) else { continue };
        if !matches!(kind, RegistrationKind::Approved | RegistrationKind::Refused | RegistrationKind::Denied) {
            continue;
        }
        let Some(atom) = one_address(&found.value.from).map(str::to_string) else { continue };
        let Some(bytes) = atoms.read(&found.home, &atom)? else { continue };
        let Ok(record) = parse_registration(kind, &bytes) else { continue };
        thread.answers.push(ThreadAnswer { link: found.link, at: found.value.at, body: record.body });
    }
    for thread in &mut queue.threads {
        thread.answers.sort_by(|a, b| (a.at, &a.link).cmp(&(b.at, &b.link)));
        thread.state = match (thread.answers.is_empty(), thread.approved().map(|approved| approved.node_address.to_string())) {
            (true, _) => State::Waiting,
            (false, Some(node)) if !collected(board, token, &node)? => State::ApprovedNotCollected,
            (false, _) => State::Closed,
        };
    }
    Ok(queue)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The row guard reads `shape` off the body's head and no further.
    #[test]
    fn the_shape_is_read_off_the_head_of_the_body() {
        let body = br#"{"type":"fresh","door":"realm:9f door:1.1.0.1","fresh":"5e","shape":"3.54.1.1","node":"{\"type\":\"skep-enroll\",\"shape\":\"x\"}","signer":"ab"}"#;
        assert_eq!(shape_named(body), Some("3.54.1.1"));
        assert_eq!(shape_named(br#"{"type":"fresh","node":"{\"shape\":\"3.54.1.1\"}"}"#), None, "a `shape` inside an enrolment's text is no member");
        assert_eq!(shape_named(br#"{"type":"fresh","inner":{"shape":"3.54.1.1"}}"#), None, "one nested deeper is none either");
        assert_eq!(shape_named(br#"{"shape":"3.54.1.2","shape2":"3.54.1.1"}"#), Some("3.54.1.2"));
        assert_eq!(shape_named(b""), None);
        assert_eq!(shape_named(br#"{"shape":"unterminated"#), None);
    }

    /// REG-4.78: at most three keys an enrolment, every label at most 128
    /// bytes, judged with no key decoded.
    #[test]
    fn an_enrolment_past_three_keys_or_a_label_past_128_bytes_breaks_the_shape() {
        let entry = |label: &str| format!(r#"{{"alg":"mldsa65-ed25519","key":"zz not hex at all","anchor":true,"label":"{label}"}}"#);
        let record = |entries: &[String]| format!(r#"{{"type":"skep-enroll","keys":[{}]}}"#, entries.join(","));
        let three = record(&[entry("a"), entry("b"), entry("c")]);
        assert_eq!(enrolment_shape(&three), Ok(()), "three keys, their bytes never decoded");
        let four = record(&[entry("a"), entry("b"), entry("c"), entry("d")]);
        assert_eq!(enrolment_shape(&four), Err("an enrolment names more than 3 keys".to_string()));
        assert_eq!(enrolment_shape(&record(&[entry(&"x".repeat(128))])), Ok(()), "a label of 128 bytes");
        assert_eq!(enrolment_shape(&record(&[entry(&"x".repeat(129))])), Err("a key's label runs past 128 bytes".to_string()));
        // The bound is on the bytes the label decodes to: 64 two-byte
        // letters are 128 bytes, and each escaped quote is one.
        assert_eq!(enrolment_shape(&record(&[entry(&"\u{e9}".repeat(64))])), Ok(()));
        assert!(enrolment_shape(&record(&[entry(&"\u{e9}".repeat(65))])).is_err());
        assert_eq!(enrolment_shape(&record(&[entry(&"\\\"".repeat(128))])), Ok(()), "128 escaped quotes are 128 bytes");
        assert!(enrolment_shape(&record(&[entry(&"\\u00e9".repeat(65))])).is_err(), "65 escaped two-byte letters are 130 bytes");
        assert_eq!(enrolment_shape("not json at all"), Ok(()), "the grammar is the parse's to refuse");
    }

    /// REG-4.78: a request's shape is judged off its body with no member
    /// parsed — its `node` and its `board`, each an enrolment written as a
    /// string, at most two of them.
    #[test]
    fn a_requests_shape_is_judged_off_its_enrolment_members_with_nothing_parsed() {
        let entry = |label: &str| format!(r#"{{"alg":"mldsa65-ed25519","key":"zz not hex at all","anchor":true,"label":"{label}"}}"#);
        let enrolment = |entries: &[String]| format!(r#"{{"type":"skep-enroll","keys":[{}]}}"#, entries.join(","));
        // A member is the enrolment's text as one JSON string.
        let member = |text: &str| serde_json::to_string(text).unwrap();
        let body = |node: &str, board: Option<&str>| {
            let board = board.map(|board| format!(r#""board":{},"#, member(board))).unwrap_or_default();
            format!(r#"{{"type":"fresh","door":"d","fresh":"f","shape":"3.54.1.1","node":{},{board}"signer":"not a fingerprint","signature":"zz"}}"#, member(node))
        };
        let three = enrolment(&[entry("a"), entry("b"), entry("c")]);
        let four = enrolment(&[entry("a"), entry("b"), entry("c"), entry("d")]);
        let long = enrolment(&[entry(&"x".repeat(129))]);
        assert_eq!(request_shape(body(&three, Some(&three)).as_bytes()), Ok(()), "two enrolments of three keys, no member of them parsed");
        assert_eq!(request_shape(body(&three, None).as_bytes()), Ok(()));
        assert_eq!(request_shape(body(&four, Some(&three)).as_bytes()), Err("an enrolment names more than 3 keys".to_string()));
        assert_eq!(request_shape(body(&three, Some(&four)).as_bytes()), Err("an enrolment names more than 3 keys".to_string()), "the board root's enrolment is judged as the node's is");
        assert_eq!(request_shape(body(&three, Some(&long)).as_bytes()), Err("a key's label runs past 128 bytes".to_string()));
        // A third enrolment member: no canonical request, and past the shape
        // before the parse says so.
        let third = format!(r#"{{"node":{m},"board":{m},"node":{m}}}"#, m = member(&three));
        assert_eq!(request_shape(third.as_bytes()), Err("it carries more than 2 enrolments".to_string()));
        // A `node` nested deeper is no member of the request.
        assert_eq!(request_shape(format!(r#"{{"inner":{{"node":{}}}}}"#, member(&four)).as_bytes()), Ok(()));
        assert_eq!(request_shape(b"not json at all"), Ok(()), "the grammar is the parse's to refuse");
    }
}
