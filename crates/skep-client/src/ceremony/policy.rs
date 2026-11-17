//! The door's policy document, read and written (REG-4.131; REG-4.139).
//!
//! A registry's door keeps its admission policy in one published document:
//! well-known document 5 of the door account, `<door>.0.5`, found by its
//! number and named by no link. Its versions are its chain — `<door>.0.5.1`,
//! `<door>.0.5.2`, … — and publishing the next version is the revision
//! (REG-4.132). Each version's whole content is one object under the
//! registry bodies' canonical rule, read by the one shared parser
//! (`skep_registry::parse_policy`), which this composition calls and never
//! restates.
//!
//! **The read** ([`read_policy`]). The document's state is read as a guest:
//! whether it is created, and each version with the position of the commit
//! that minted it and its text. A version's text is the per-byte words the
//! document arranges: a version holding anything else — a composite value
//! among them — holds no text and reads as no policy. A term read at a
//! position is the term of the version standing at that position
//! ([`PolicyChain::standing_at`]): the greatest version minted at or below
//! it.
//!
//! **No policy** ([`NoPolicy`]). A door whose document 5 is absent, is
//! created and holds no version, or whose standing version does not read as
//! an admission policy is shut exactly alike, for every reader: no request
//! is admitted and no approval is written. The standing version alone is
//! asked: one that does not parse is no policy, whatever the version before
//! it said.
//!
//! **The write** ([`set_policy`]). Four acts, from the door account's own
//! signed session, each under an idempotency id of its own:
//!
//! 1. the document created where it is absent
//!    (`create_well_known_document`, safe to repeat);
//! 2. a draft staged from the document;
//! 3. the file's bytes inserted into the draft as text, one value a byte;
//! 4. the draft's new words published as the document's next version — the
//!    first with no base, each later one off the head at the head's whole
//!    count, so the new version holds the new bytes and nothing of the old.
//!
//! The file is judged before any write ([`check_policy`]): its size against
//! the cap and its bytes by the shared parser, so a file that would stand
//! as no policy is never published. The write resumes by reading: where the
//! standing version already holds the file's bytes, nothing is published
//! and the answer says so.

use std::fmt;

use skep_identity::{entry_body_publication, entry_body_publish, DocTerm, ShotBase, ShotSegmentPiece};
use skep_registry::{parse_policy, AdmissionPolicy, MAX_REGISTRY_RECORD_BYTES};

use super::{attest_member, create_well_known_document};
use crate::address::{parse_address, well_known_of, POLICY_SLOT};
use crate::board::answers::{self, Delivered};
use crate::board::{acked_addr, acked_at, frames, Answer, Board, Rejection, Token};
use crate::ceremony::deposit::{closed_face, next_content_ordinal, shape_face};
use crate::ceremony::handshake::Session;
use crate::halt::Halt;
use crate::sign::{fresh_bytes, Signer};

/// The most bytes a door's policy document carries: 16 KiB.
///
/// It is the registry records' own cap, `MAX_REGISTRY_RECORD_BYTES`, which
/// the shared parser holds the document to.
pub const MAX_POLICY_BYTES: usize = MAX_REGISTRY_RECORD_BYTES;

/// Returns the address of `door`'s policy document: `<door>.0.5`.
pub fn policy_document(door: &str) -> String {
    well_known_of(door, POLICY_SLOT)
}

/// One published version of a door's policy document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVersion {
    /// The version's address, `<door>.0.5.<k>`: what a citation names.
    pub address: String,
    /// The position of the commit that minted the version.
    pub at: u64,
    /// The version's text; `None` where it arranges anything but text.
    pub text: Option<Vec<u8>>,
    /// The policy the text spells, or why it spells none.
    pub policy: Result<AdmissionPolicy, String>,
}

/// Why a door has no policy at a position (REG-4.139).
///
/// The four are one state to every reader — no request admitted, no
/// approval — and are told apart only so a face can name the act that
/// opens the door.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoPolicy {
    /// The door's document 5 is not created.
    Absent {
        /// The document's address.
        document: String,
    },
    /// The document is created and holds no version.
    Empty {
        /// The document's address.
        document: String,
    },
    /// No version stood yet at the position asked.
    NotYet {
        /// The document's first version.
        first: String,
        /// The position that version was minted at.
        at: u64,
        /// The position asked.
        asked: u64,
    },
    /// The version standing does not read as an admission policy.
    Unreadable {
        /// The version standing.
        version: String,
        /// The shared parser's cause, or that the version holds no text.
        cause: String,
    },
}

impl fmt::Display for NoPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoPolicy::Absent { document } => write!(f, "this door has no policy: its policy document {document} has not been created"),
            NoPolicy::Empty { document } => write!(f, "this door has no policy: its policy document {document} is created and holds no version"),
            NoPolicy::NotYet { first, at, asked } => write!(f, "no policy stood at position {asked}: the door's first policy version, {first}, was published at position {at}"),
            NoPolicy::Unreadable { version, cause } => write!(f, "this door has no policy: the version standing, {version}, does not read as an admission policy ({cause})"),
        }
    }
}

/// A policy standing at a position: the version, and the policy it spells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Standing<'c> {
    /// The version standing.
    pub version: &'c PolicyVersion,
    /// The policy its text spells.
    pub policy: &'c AdmissionPolicy,
}

/// A door's policy document as the board holds it: its version chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyChain {
    /// The document's address, `<door>.0.5`.
    pub document: String,
    /// Whether the document is created.
    pub created: bool,
    /// Its versions, in chain order: `.1`, `.2`, ….
    pub versions: Vec<PolicyVersion>,
}

impl PolicyChain {
    /// Returns the policy standing at `position`.
    ///
    /// It is the greatest version minted at or below the position, where
    /// that version reads as an admission policy.
    ///
    /// # Errors
    ///
    /// [`NoPolicy`]: the document absent or empty, no version minted yet at
    /// the position, or the version standing there unreadable — never an
    /// earlier version in its place.
    pub fn standing_at(&self, position: u64) -> Result<Standing<'_>, NoPolicy> {
        if !self.created {
            return Err(NoPolicy::Absent { document: self.document.clone() });
        }
        let Some(first) = self.versions.first() else { return Err(NoPolicy::Empty { document: self.document.clone() }) };
        let Some(version) = self.versions.iter().rev().find(|version| version.at <= position) else {
            return Err(NoPolicy::NotYet { first: first.address.clone(), at: first.at, asked: position });
        };
        match &version.policy {
            Ok(policy) => Ok(Standing { version, policy }),
            Err(cause) => Err(NoPolicy::Unreadable { version: version.address.clone(), cause: cause.clone() }),
        }
    }

    /// Returns the policy standing now: at the document's head.
    ///
    /// # Errors
    ///
    /// [`PolicyChain::standing_at`]'s, at the last position.
    pub fn standing(&self) -> Result<Standing<'_>, NoPolicy> {
        self.standing_at(u64::MAX)
    }
}

/// Returns the document a metadata read is answered with, or its rejection.
///
/// # Errors
///
/// The death signal under `token`, faced; and [`Board::op`]'s errors.
fn metadata(board: &Board, token: Option<&Token>, doc: &str) -> Result<Result<serde_json::Value, Rejection>, Halt> {
    match board.op(token, &frames::doc_metadata(doc))? {
        Answer::Closed => Err(closed_face("reading the policy document")),
        Answer::Document(v) => Ok(match Rejection::of(&v) {
            Some(r) if r.key() == "doc_not_registered" => Err(r),
            Some(r) => return Err(r.refused(&v)),
            None => Ok(v),
        }),
    }
}

/// Reads the text `member` arranges: its per-byte words, in order.
///
/// `None` where the member arranges a value that is no byte of text — a
/// composite value, a link position, a run the reader may not read.
///
/// # Errors
///
/// The death signal under `token`, faced; the board's refusal of a read; an
/// answer of a shape this client does not know; and [`Board::op`]'s errors.
fn text_of(board: &Board, token: Option<&Token>, member: &str) -> Result<Option<Vec<u8>>, Halt> {
    let during = "reading a policy version";
    let answered = |frame: &serde_json::Value| -> Result<serde_json::Value, Halt> {
        match board.op(token, frame)? {
            Answer::Closed => Err(closed_face(during)),
            Answer::Document(v) => match Rejection::of(&v) {
                Some(r) => Err(r.refused(&v)),
                None => Ok(v),
            },
        }
    };
    let extent = answers::content_extent(&answered(&frames::span_set(member))?);
    if extent == 0 {
        return Ok(Some(Vec::new()));
    }
    let v = answered(&frames::retrieve_v(member, 1, extent))?;
    let Some((items, _)) = answers::delivery(&v) else { return Err(shape_face(&v)) };
    let mut text = Vec::new();
    for item in items {
        match item {
            Delivered::Text(bytes) => text.extend(bytes),
            _ => return Ok(None),
        }
    }
    Ok(Some(text))
}

/// Reads a door's policy document: whether it is created, and its versions.
///
/// The read is a guest's, or `token`'s where one is given: the document is
/// published, so both are answered alike. Each version is read with the
/// position of the commit that minted it and its text, parsed by the shared
/// parser; the chain is walked from its first member until the board
/// answers no next one.
///
/// # Errors
///
/// The death signal under `token`, faced; the board's refusal of a read
/// other than `doc_not_registered`; a version the board dates at no
/// position, faced as the board's fault; an answer of a shape this client
/// does not know; and [`Board::op`]'s errors.
pub fn read_policy(board: &Board, token: Option<&Token>, door: &str) -> Result<PolicyChain, Halt> {
    let document = policy_document(door);
    if metadata(board, token, &document)?.is_err() {
        return Ok(PolicyChain { document, created: false, versions: Vec::new() });
    }
    let mut versions = Vec::new();
    for k in 1u64.. {
        let address = format!("{document}.{k}");
        let Ok(v) = metadata(board, token, &address)? else { break };
        let Some(at) = answers::metadata(&v).and_then(|m| m.at) else {
            return Err(Halt::face(
                format!("the board dates the policy version {address} at no position"),
                format!("`doc_metadata` answered no `at` for it (wire.md §The response envelope): {v}"),
                "this is a fault in the board: a policy version is read at the position it was published at; nothing was written",
            ));
        };
        let text = text_of(board, token, &address)?;
        let policy = match &text {
            None => Err("it holds a value that is no text".to_string()),
            Some(bytes) => parse_policy(bytes).map_err(|refusal| refusal.token()),
        };
        versions.push(PolicyVersion { address, at, text, policy });
    }
    Ok(PolicyChain { document, created: true, versions })
}

/// Judges a policy file before any write.
///
/// The file is the document's whole content: at most [`MAX_POLICY_BYTES`],
/// and one admission policy under the shared parser, in its one canonical
/// form.
///
/// # Errors
///
/// A file past the cap, and a file the parser refuses, each a halt naming
/// its cause: such a file would stand as no policy, and a door with no
/// policy is shut (REG-4.139).
pub fn check_policy(text: &[u8]) -> Result<AdmissionPolicy, Halt> {
    if text.len() > MAX_POLICY_BYTES {
        return Err(Halt::face(
            format!("the policy file is {} bytes, past the cap of {MAX_POLICY_BYTES}", text.len()),
            "a door's policy document is at most 16 KiB: past it every reader refuses the document, and the door would stand with no policy — no request admitted, no approval (REG-4.139)",
            "shorten the file — the grounds and the contact are its long members; nothing was written",
        ));
    }
    parse_policy(text).map_err(|refusal| {
        Halt::face(
            format!("the file is no admission policy: {}", refusal.token()),
            "a door's policy document is ONE object in its canonical form (REG-1.86): `type` `admission-policy`, then its members in the document's order, no \
             whitespace outside strings and no byte after the closing brace — a trailing newline among them. Published as it is, it would stand as no \
             policy, and the door would be shut (REG-4.139)",
            "correct the file — the cause names the member — and run it again; nothing was written",
        )
    })
}

/// What [`set_policy`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySet {
    /// The door's policy document, `<door>.0.5`.
    pub document: String,
    /// Whether this call created the document.
    pub created: bool,
    /// The version that holds the file's policy.
    pub version: String,
    /// Whether this call published it; `false` where the version standing
    /// already held the file's bytes, and nothing was published.
    pub published: bool,
    /// The position of the publication, where this call published.
    pub at: Option<u64>,
    /// The policy the file spells.
    pub policy: AdmissionPolicy,
}

/// Publishes `text` as the next version of the session account's policy.
///
/// It is the module's four acts, in order, from `session`, the door
/// account's own signed session, each attested where the board owes it
/// under `signer`, the session's key. The file is judged first
/// ([`check_policy`]). The document is then created where it is absent;
/// where the version standing already holds exactly these bytes nothing
/// more is written, and the answer says so
/// ([`PolicySet::published`]). Otherwise a draft is staged from the
/// document, the bytes are inserted into it as text, and the draft's new
/// words are published as the document's next version. A draft a stopped
/// run left is private and is never read.
///
/// # Errors
///
/// In order: [`check_policy`]'s halts, before any write; the creation's
/// (`create_well_known_document`); [`read_policy`]'s; the session closed at
/// any act; a board with no `H.1`; an `attestation_*` refusal faced as this
/// client's own frame; a publication that landed beside the chain, another
/// version having been published first; any other refusal, the board's;
/// and an answer of a shape this client does not know.
pub fn set_policy(board: &Board, session: &Session<'_>, signer: &dyn Signer, text: &[u8]) -> Result<PolicySet, Halt> {
    // Judged before any write (REG-4.139).
    let policy = check_policy(text)?;
    let words = std::str::from_utf8(text).map_err(|_| Halt::face("the policy file is not UTF-8", "the parser admitted bytes that are no text", "this is a fault in this client; nothing was written"))?;
    let door = session.account().to_string();
    // Each act its own id: the board answers a repeated id its first
    // acknowledgment, and no act here is another's.
    let run = crate::hex::encode(&fresh_bytes(8));
    let id = |act: &str| format!("set-policy.{run}.{act}");
    // (i) The document, where it is absent.
    let created = create_well_known_document(board, session, &door, POLICY_SLOT, signer, &id("create"))?;
    let document = created.addr;
    let chain = read_policy(board, Some(session.token()), &door)?;
    if let Some(head) = chain.versions.last() {
        if head.text.as_deref() == Some(text) {
            return Ok(PolicySet { document, created: created.created, version: head.address.clone(), published: false, at: None, policy });
        }
    }
    let op = |frame: &serde_json::Value, during: &str| -> Result<serde_json::Value, Halt> {
        match session.op(frame)? {
            Answer::Closed => Err(closed_face(during)),
            Answer::Document(v) => Ok(v),
        }
    };
    let acked = |v: &serde_json::Value| -> Result<String, Halt> {
        match (acked_addr(v), Rejection::of(v)) {
            (Some(addr), _) => Ok(addr.to_string()),
            (None, Some(r)) => Err(r.refused(v)),
            (None, None) => Err(shape_face(v)),
        }
    };
    // (ii) A draft staged from the document.
    let draft = acked(&op(&frames::stage(&document, Some(&id("stage"))), "staging the policy's draft")?)?;
    let staged = op(&frames::doc_metadata(&draft), "reading the staged draft")?;
    let Some(base) = answers::metadata(&staged) else {
        return Err(match Rejection::of(&staged) {
            Some(r) => r.refused(&staged),
            None => shape_face(&staged),
        });
    };
    // The base the board records for the draft: the head member and the
    // count the copy took of it, or the memberless document.
    let shot_base = match (base.base.as_deref(), base.base_copied) {
        (Some(member), Some(copied)) if member != document => Some((member.to_string(), copied)),
        _ => None,
    };
    // (iii) The file's bytes, as text, past what the copy took.
    let (ordinal, as_of) = next_content_ordinal(board, Some(session.token()), &draft)?;
    let first = acked(&op(&frames::insert_text(&draft, ordinal, words, as_of, Some(&id("insert"))), "writing the policy's text")?)?;
    // (iv) The publication: the draft's new words alone, off the head.
    let Some(term) = board.board_term()? else {
        return Err(Halt::face(
            "this board has no H.1 yet, so the policy cannot be published from this session",
            "a publication carries an `attest` naming `H.1`'s pair as its board term, and the board answers no head",
            "retry once the board has written its head; the draft this run staged is private and is never read",
        ));
    };
    let frame_fault = || Halt::face("the publication's frame could not be composed", "an address of the publication did not parse", "this is this client's frame; nothing was published");
    let (own, trunk) = (parse_address(&door).ok_or_else(frame_fault)?, parse_address(&document).ok_or_else(frame_fault)?);
    let base_address = match &shot_base {
        Some((member, _)) => Some(parse_address(member).ok_or_else(frame_fault)?),
        None => None,
    };
    let signed_base = match (&base_address, &shot_base) {
        (Some(member), Some((_, extent))) => Some(ShotBase { member, extent: *extent }),
        _ => None,
    };
    let pieces = text.iter().map(|byte| ShotSegmentPiece::Value(std::slice::from_ref(byte)));
    let body = entry_body_publication(entry_body_publish(pieces, signed_base), &[]);
    let runs = [frames::shot_run(&draft, &first, text.len() as u64)];
    let publish_id = id("publish");
    let frame = frames::publication(&frames::PublishFrame {
        doc: Some(&document),
        draft: Some(&draft),
        base: shot_base.as_ref().map(|(member, extent)| (member.as_str(), *extent)),
        runs: &runs,
        attest: Some(attest_member(term, &own, DocTerm::One(&trunk), &body, signer)),
        id: Some(&publish_id),
        ..frames::PublishFrame::default()
    });
    let v = op(&frame, "publishing the policy")?;
    let version = match (acked_addr(&v), Rejection::of(&v)) {
        (Some(addr), _) => addr.to_string(),
        (None, Some(r)) if r.key().starts_with("attestation_") => {
            return Err(Halt::face(
                "the board judged the publication's attest and refused",
                format!("{}: the frame this client composed did not verify under the set that opens the account as of the base, or the board had no head", r.token()),
                "this is this client's frame and never your act; `board_unavailable` is a reorder — retry once the head is written. Nothing was published",
            ))
        }
        (None, Some(r)) => return Err(r.refused(&v)),
        (None, None) => return Err(shape_face(&v)),
    };
    let next = format!("{document}.{}", chain.versions.len() + 1);
    if version != next {
        return Err(Halt::face(
            format!("the policy was published beside the chain, as {version}, and the door's standing policy did not move"),
            format!("another version was published while this run staged its own, so this one landed off the version it was staged from and not as {next}"),
            "run it again: it reads the version standing now and publishes after it",
        ));
    }
    Ok(PolicySet { document, created: created.created, version, published: true, at: acked_at(&v), policy })
}
