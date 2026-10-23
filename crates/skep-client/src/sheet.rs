//! The field set, their order and the grouping.
//!
//! This is `client.md` §1.1's `sheet` row: the key file's one JSON spelling
//! and its reader with its refusals, [`KeyFileError`] (§3.2); the byline a
//! key carries, [`Label`], one domain test (AUTH-1.24) wherever a label is
//! made — a box — or read — a file; the [`Seed`] every key's secret is born
//! into and the [`SeedText`] the sheet shows it as, each wiped on drop
//! (AUTH-5.54 step 3); the R42 grouping (AUTH-5.1: eight groups of eight
//! hex, a single space between groups, four groups to a line, for a
//! fingerprint wherever one is displayed and for the exported anchor seed on
//! the sheet alike), and the sheet's field list (AUTH-5.38) — the drawing is
//! each embedder's (§5.2). No scannable form (§9 item 13).

use std::borrow::Cow;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

use serde_json::Value;
use skep_identity::{Fingerprint, PublicKey, SigAlgRow, ALGS};
use skep_signature::HybridSigner;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::address::is_address_text;
use crate::hex;
use crate::origin::Origin;
use crate::sign::signer_from_seed_under;

#[cfg(test)]
mod tests;

/// The most bytes a key file holds (§3.2).
///
/// Its largest canonical spelling — the production kind's 3,968-hex key
/// beside its 64-hex seed and fingerprint, a 128-byte label escaped
/// six-fold, a 64-component account of twenty-digit components, an origin
/// of a host name's length — runs under 7 KiB, and this is nine times that,
/// room for an editor's whitespace. A file past it is no key file this
/// client wrote: [`KeyFile::parse`] refuses it, and the store's reader reads
/// no further than the byte past it.
pub const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// Reads a key file's bytes off `path`.
///
/// The path is the store's, an anchor handed in, or an export read back;
/// the read stops one byte past [`MAX_KEY_FILE_BYTES`], so
/// [`KeyFile::parse`] refuses an oversized file without its whole length
/// read.
///
/// # Errors
///
/// A path naming no regular file is refused before it is opened, and the
/// file opened is held to the same test: a device answers bytes forever, a
/// FIFO with no writer blocks its open, and neither is a key file. Either
/// refusal is `InvalidInput`; the metadata reads, the open and the read
/// return their own errors.
pub(crate) fn read_key_file(path: &Path) -> io::Result<Vec<u8>> {
    let not_a_file = || io::Error::new(io::ErrorKind::InvalidInput, "not a regular file");
    if !fs::metadata(path)?.is_file() {
        return Err(not_a_file());
    }
    let file = fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(not_a_file());
    }
    let mut bytes = Vec::new();
    file.take(MAX_KEY_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Returns `hex64` in AUTH-5.1's grouping.
///
/// It is 64 hex as eight groups of eight, a single space between groups,
/// four groups to a line (R42; RES-62 item 9, pick A).
pub fn group_hex(hex64: &str) -> String {
    let mut out = String::with_capacity(hex64.len() + hex64.len() / 8);
    push_grouped(&mut out, hex64.chars());
    out
}

/// Pushes `digits` onto `out` in AUTH-5.1's grouping.
///
/// The digits run eight to a group, a single space between groups and four
/// groups to a line: the one grouping, which [`group_hex`] writes for a
/// fingerprint and `Seed`'s own grouping writes for the sheet's seed text.
fn push_grouped(out: &mut String, digits: impl Iterator<Item = char>) {
    for (i, digit) in digits.enumerate() {
        if i > 0 && i % 8 == 0 {
            out.push(if i % 32 == 0 { '\n' } else { ' ' });
        }
        out.push(digit);
    }
}

/// Returns whether `typed` names `fp`.
///
/// `typed` is a fingerprint prefix read off a print and typed; read trimmed
/// and ASCII-lowercased, it names `fp` where it is at least one R42 group
/// (8 hex; §9 item 35; AUTH-5.1) and a prefix of the fingerprint's hex. It
/// is one rule for every place a person types a prefix beside a seed
/// (AUTH-5.39: the fingerprint first, "this is not the key on this paper —
/// re-scan").
pub(crate) fn typed_prefix_matches(typed: &str, fp: &Fingerprint) -> bool {
    let typed = typed.trim().to_ascii_lowercase();
    typed.len() >= 8 && fp.to_hex().starts_with(&typed)
}

/// Returns `label` rendered inert (AUTH-5.2).
///
/// Every C0 control, DEL and every bidi control (U+202A–U+202E,
/// U+2066–U+2069, U+200E, U+200F, U+061C) is shown as its code point, never
/// interpreted. The domain admits them (AUTH-1.24) and AUTH-5.3 declines to
/// narrow it, so the rendering is where they are disarmed.
pub fn render_inert(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    for c in label.chars() {
        let code = c as u32;
        let bidi = matches!(code, 0x202A..=0x202E | 0x2066..=0x2069 | 0x200E | 0x200F | 0x061C);
        if code < 0x20 || code == 0x7f || bidi {
            out.push_str(&format!("<U+{code:04X}>"));
        } else {
            out.push(c);
        }
    }
    out
}

/// The 32-byte seed — the paper backup's 64 hex — wiped on drop.
///
/// The wipe is derived, `Zeroize` and `ZeroizeOnDrop` together, as
/// skep-signature derives its half seeds' wipe: the `ZeroizeOnDrop` derive
/// writes both the `Drop` that overwrites the bytes, with writes the compiler
/// may not elide, and the marker this module's suite reads, so the drop
/// AUTH-5.54 step 3 owes is a wipe (`client.md` §3.4). Every seed the crate
/// makes is born in this value — drawn by [`Seed::fresh`], decoded by
/// [`Seed::from_hex`] — so no bare copy of its bytes outlives that drop. The
/// sheet shows the seed as a [`SeedText`], which wipes in turn; the hex
/// spelled from it — [`Seed::to_hex`], the key file's `seed` member — is a
/// plain `String` that no drop wipes. The signer derived from it wipes both
/// halves' keys on drop, the Ed25519 key and the ML-DSA-65 key, and what the
/// KDF and the key libraries compute from a secret inside a call is released
/// unwiped (`skep_signature::HybridSigner`'s doc): the drop is open work for
/// that residue, reported and not claimed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Seed([u8; 32]);

/// The bytes the sheet's seed text holds.
///
/// They are AUTH-5.1's grouping of the seed's 32 bytes: 64 hex, six spaces
/// between the groups of a line and one line break between the two lines.
const SEED_TEXT_LEN: usize = 71;

impl Seed {
    /// Returns a seed from its bytes.
    pub fn new(bytes: [u8; 32]) -> Seed {
        Seed(bytes)
    }

    /// Draws a fresh seed from the OS random source.
    ///
    /// The source is `getrandom`, the OS's cryptographic generator, and the
    /// seed is drawn straight into the value that zeroes it.
    ///
    /// # Panics
    ///
    /// Panics where the OS random source fails: fail-stop, no seed from
    /// anything weaker.
    pub fn fresh() -> Seed {
        let mut seed = Seed([0u8; 32]);
        getrandom::fill(&mut seed.0).expect("OS entropy unavailable");
        seed
    }

    /// Decodes a seed from its 64 hex, either case.
    ///
    /// The hex is a print's re-type or a key file's member, decoded straight
    /// into the value that zeroes it; the answer is `None` for any other
    /// text.
    pub fn from_hex(text: &str) -> Option<Seed> {
        let mut seed = Seed([0u8; 32]);
        hex::decode_into(text, &mut seed.0).then_some(seed)
    }

    /// Returns the bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the seed's 64 hex in a plain `String` that no drop wipes.
    ///
    /// It is the key file's `seed` member; the sheet shows the seed as a
    /// [`SeedText`] instead, which wipes.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Returns the seed in AUTH-5.1's grouping, as the sheet shows it.
    ///
    /// The digits are written from the bytes into one buffer of its final
    /// size, `SEED_TEXT_LEN`, so no growth leaves a copy of them behind the
    /// wipe.
    fn grouped(&self) -> SeedText {
        let mut text = String::with_capacity(SEED_TEXT_LEN);
        push_grouped(&mut text, self.0.iter().flat_map(|b| hex::digits(*b)));
        SeedText(text)
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(…)")
    }
}

/// The seed's 64 hex in AUTH-5.1's grouping, as the sheet shows it.
///
/// It is secret text, wiped on drop (AUTH-5.54 step 3). The wipe is
/// derived, `Zeroize` and `ZeroizeOnDrop` together, as [`Seed`]'s is: the
/// `ZeroizeOnDrop` derive writes both the `Drop` that overwrites the whole
/// buffer, its spare capacity included, and the marker this module's suite
/// reads. The library builds the text from the seed's bytes at its final
/// size ([`KeyFile::sheet`]), so no growth leaves a copy behind;
/// [`SheetFields::lines`] lends it and copies none of it, and a clone is a
/// `SeedText` that wipes in turn. What an embedder copies out of
/// [`SeedText::as_str`] to draw the sheet is the embedder's to wipe.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SeedText(String);

impl SeedText {
    /// Returns the text, lent.
    ///
    /// It is the one way the text is read.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A text taken as given — a fixture's or an embedder's.
///
/// The library's own seed text is built from the seed's bytes
/// ([`KeyFile::sheet`]).
impl From<&str> for SeedText {
    fn from(text: &str) -> SeedText {
        SeedText(text.to_owned())
    }
}

/// The text is secret, so it prints as none of itself.
impl fmt::Debug for SeedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SeedText(…)")
    }
}

/// A byline in AUTH-1.24's domain, never empty (AUTH-5.42).
///
/// It is non-empty, with no `\n`, and at most 128 bytes of UTF-8 counted as
/// `Enrollment::new` counts. Every box applies the domain test itself,
/// before anything is made from a label (P13; `client.md` §2.2 `keygen`),
/// and [`KeyFile::parse`] admits a file's `label` member by the same test.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Label(String);

/// Why a label is outside the domain.
///
/// It is faced at the box, with the byte count named where the limit is the
/// fault (AUTH-1.25's `TooLong` and `Newline`, and the empty label AUTH-5.42
/// faces).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelFault {
    /// The label is empty.
    Empty,
    /// The label holds a `\n`.
    Newline,
    /// The label runs past 128 bytes of UTF-8.
    TooLong { bytes: usize },
}

impl fmt::Display for LabelFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelFault::Empty => f.write_str("the label is empty — a name is required here"),
            LabelFault::Newline => f.write_str("the label holds a line break, which a label cannot"),
            LabelFault::TooLong { bytes } => write!(
                f,
                "the label is {bytes} bytes of UTF-8 and the limit is 128 bytes — counted in bytes, not characters"
            ),
        }
    }
}

impl std::error::Error for LabelFault {}

impl Label {
    /// Makes a label of `text` under the domain test (AUTH-1.24).
    ///
    /// # Errors
    ///
    /// In this order, the newline read before the length as
    /// `Enrollment::new` reads it (AUTH-1.25): [`LabelFault::Newline`] where
    /// `text` holds a `\n`; [`LabelFault::TooLong`] past 128 bytes;
    /// [`LabelFault::Empty`] for the empty text.
    pub fn new(text: &str) -> Result<Label, LabelFault> {
        if text.contains('\n') {
            return Err(LabelFault::Newline);
        }
        if text.len() > 128 {
            return Err(LabelFault::TooLong { bytes: text.len() });
        }
        if text.is_empty() {
            return Err(LabelFault::Empty);
        }
        Ok(Label(text.to_string()))
    }

    /// Returns the text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the label as a path component.
    ///
    /// ASCII alphanumerics are kept, lowercased; every other run of
    /// characters is one `-`, a `-` at either end trimmed, and `key` stands
    /// where nothing is left — the slug the anchor file's name takes (§6).
    pub fn slug(&self) -> String {
        let mut out = String::new();
        let mut dash = false;
        for c in self.0.chars() {
            if c.is_ascii_alphanumeric() {
                out.push(c.to_ascii_lowercase());
                dash = false;
            } else if !dash {
                out.push('-');
                dash = true;
            }
        }
        let trimmed = out.trim_matches('-').to_string();
        if trimmed.is_empty() { "key".to_string() } else { trimmed }
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The key file and the anchor export, one struct (§3.2).
///
/// Its members are `type`, `v`, `anchor`, `alg`, `seed`, `public`,
/// `fingerprint`, `label?`, `account?`, `principal?`, `origin?` —
/// AUTH-5.38's fields where the format allows, and no other member.
/// `public` and `fingerprint` are re-derived from the seed on every load
/// (AUTH-5.39 applied to the store's own files): a file whose members
/// disagree with its seed is "not the key this file names".
pub struct KeyFile {
    /// Whether the key is an anchor.
    pub anchor: bool,
    /// An `ALGS` token (AUTH-1.5).
    pub alg: String,
    seed: Seed,
    /// The public key the seed derives.
    pub public: PublicKey,
    /// The public key's fingerprint.
    pub fingerprint: Fingerprint,
    /// The label, present only where one exists — never `""` (AUTH-1.24).
    pub label: Option<String>,
    /// The account, one of AUTH-5.38's three facts.
    ///
    /// Each of the three is present where known at export.
    pub account: Option<String>,
    /// The principal, present where known at export.
    pub principal: Option<u64>,
    /// The origin, present where known at export.
    pub origin: Option<Origin>,
}

impl fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyFile({}, anchor {}, fingerprint {})", self.alg, self.anchor, self.fingerprint)
    }
}

/// A key file's refusals (§3.2).
///
/// They are the store's own faces and never wire tokens, each read off the
/// file's own contents: a state, rendered as AUTH-5.67's halt naming the
/// path and the state (the store's `From<StoreError> for Halt`); all exit 3
/// (§1.1's `halt` row). Non-exhaustive: the next format version's members
/// bring refusals of their own (§3.2's `custody`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyFileError {
    /// Past [`MAX_KEY_FILE_BYTES`], not JSON, or `type` is not `skep-key`.
    NotKeyFile,
    /// `v` above 1: "this file was written by a newer skep than this one".
    ///
    /// It is never "not a key file".
    Newer { v: u64 },
    /// A member missing, of the wrong type, out of its domain, or unknown.
    Schema { member: String },
    /// `public` or `fingerprint` does not re-derive from the seed (AUTH-5.39).
    ///
    /// It reads "this is not the key this file names".
    Disagrees,
    /// An anchor file selected to sign or to be enrolled as a device key.
    ///
    /// It fails §2.2's selection test: the walks that import an anchor are
    /// `skep recover` and, where its act is anchor-grade, `skep handoff`.
    AnchorAtSigningCommand,
}

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyFileError::NotKeyFile => f.write_str("this is not a skep key file"),
            KeyFileError::Newer { v } => write!(f, "this file was written by a newer skep than this one (v {v})"),
            KeyFileError::Schema { member } => write!(f, "the file's `{member}` member is missing, of the wrong type or outside its domain"),
            KeyFileError::Disagrees => f.write_str("this is not the key this file names: its public key and fingerprint do not re-derive from its seed"),
            KeyFileError::AnchorAtSigningCommand => f.write_str(
                "this is an ANCHOR's file, and an anchor is refused wherever a key is selected to sign or to be \
                 enrolled as a device key — the one walk that imports an anchor is `skep recover`",
            ),
        }
    }
}

impl std::error::Error for KeyFileError {}

/// The three AUTH-5.38 facts an artifact carries.
///
/// An artifact carries them where the account exists at export (the
/// notebook: `delegate` runs ahead of the backup moment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// The account.
    pub account: String,
    /// The principal.
    pub principal: u64,
    /// The board's origin.
    pub origin: Origin,
}

/// The sheet's field list, in order (AUTH-5.38; §5.2).
///
/// It holds the fields save `public` — the seed and the fingerprint grouped
/// (AUTH-5.1), the label rendered inert by [`SheetFields::lines`]
/// (AUTH-5.2), the three facts where they exist. The seed's text is a
/// [`SeedText`], wiped on drop, which [`SheetFields::lines`] lends. It is a
/// rendering of the fields and never of the file's bytes; read by a person,
/// parsed by nothing. Its `Debug` prints every field but the seed, which
/// shows as `…`: the sheet is a `Secret` moment's payload (§1.1's `person`
/// row), and a debug log of moments is an ordinary embedder's.
#[derive(Clone, PartialEq, Eq)]
pub struct SheetFields {
    /// Whether the key is an anchor.
    pub anchor: bool,
    /// The key's `ALGS` token.
    pub alg: String,
    /// The label as the file holds it, where one exists.
    pub label: Option<String>,
    /// The fingerprint's 64 hex.
    pub fingerprint_hex: String,
    /// The fingerprint's hex, grouped.
    pub fingerprint_grouped: String,
    /// The seed's hex, grouped — a [`SeedText`], wiped on drop.
    pub seed_grouped: SeedText,
    /// The account, where known.
    pub account: Option<String>,
    /// The principal, where known.
    pub principal: Option<u64>,
    /// The origin's canonical text, where known.
    pub origin: Option<String>,
}

impl SheetFields {
    /// Returns the labelled lines a terminal or a window draws.
    ///
    /// They come in the pinned order. Each value is lent from the fields —
    /// the seed's among them, never copied out of the [`SeedText`] that
    /// wipes it — and made fresh only where it is a rendering: the label
    /// rendered inert, the principal's digits.
    pub fn lines(&self) -> Vec<(&'static str, Cow<'_, str>)> {
        let mut out = vec![
            ("kind", Cow::Borrowed(if self.anchor { "ANCHOR (paper)" } else { "device key" })),
            ("alg", Cow::Borrowed(self.alg.as_str())),
        ];
        if let Some(label) = &self.label {
            out.push(("label", Cow::Owned(render_inert(label))));
        }
        out.push(("fingerprint", Cow::Borrowed(self.fingerprint_grouped.as_str())));
        out.push(("seed", Cow::Borrowed(self.seed_grouped.as_str())));
        if let Some(a) = &self.account {
            out.push(("account", Cow::Borrowed(a.as_str())));
        }
        if let Some(p) = self.principal {
            out.push(("principal", Cow::Owned(p.to_string())));
        }
        if let Some(o) = &self.origin {
            out.push(("origin", Cow::Borrowed(o.as_str())));
        }
        out
    }
}

impl fmt::Debug for SheetFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SheetFields")
            .field("anchor", &self.anchor)
            .field("alg", &self.alg)
            .field("label", &self.label)
            .field("fingerprint_hex", &self.fingerprint_hex)
            .field("fingerprint_grouped", &self.fingerprint_grouped)
            .field("seed_grouped", &format_args!("…"))
            .field("account", &self.account)
            .field("principal", &self.principal)
            .field("origin", &self.origin)
            .finish()
    }
}

/// Writes `s` to `out` with AUTH-2.130 clause 3's string escaping.
///
/// It is the spelling the file takes too (§3.2): `"`, `\` and U+0000–U+001F
/// escaped — the two-character forms where JSON defines one, `\u00xx`
/// lowercase otherwise — and nothing else.
fn escape_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

impl KeyFile {
    /// Makes a key file over `seed` under the production kind.
    ///
    /// Its byline is a [`Label`] — AUTH-1.24's domain, tested where the
    /// label was made, as [`KeyFile::parse`] tests a file's `label` member.
    pub fn new(seed: Seed, anchor: bool, label: Option<Label>, facts: Option<&Facts>) -> KeyFile {
        let signer = crate::sign::signer_from_seed(seed.bytes());
        let public = HybridSigner::public_key(&signer).clone();
        let fingerprint = Fingerprint::of(&public);
        KeyFile {
            anchor,
            alg: public.alg().to_string(),
            seed,
            public,
            fingerprint,
            label: label.map(|l| l.0),
            account: facts.map(|f| f.account.clone()),
            principal: facts.map(|f| f.principal),
            origin: facts.map(|f| f.origin.clone()),
        }
    }

    /// Returns the signer this file's seed derives.
    ///
    /// It is the in-memory arm of the `Signer` seam.
    ///
    /// # Panics
    ///
    /// Panics if `public`'s row is one this build holds no keygen rule for;
    /// every file [`KeyFile::new`] makes and [`KeyFile::parse`] reads holds a
    /// row it does, so the `expect` never fires on one of those.
    pub fn signer(&self) -> HybridSigner {
        signer_from_seed_under(self.public.sig_alg_row().tag, self.seed.bytes()).expect("the file's alg is a row this build holds")
    }

    /// Returns the seed's 64 hex in a plain `String` that no drop wipes.
    ///
    /// It is the key file's `seed` member, as [`Seed::to_hex`] spells it.
    pub fn seed_hex(&self) -> String {
        self.seed.to_hex()
    }

    /// Returns the sheet's fields (AUTH-5.38).
    ///
    /// The seed and the fingerprint are grouped (AUTH-5.1), the seed into a
    /// [`SeedText`] written straight from its bytes, which wipes on drop.
    pub fn sheet(&self) -> SheetFields {
        SheetFields {
            anchor: self.anchor,
            alg: self.alg.clone(),
            label: self.label.clone(),
            fingerprint_hex: self.fingerprint.to_hex(),
            fingerprint_grouped: group_hex(&self.fingerprint.to_hex()),
            seed_grouped: self.seed.grouped(),
            account: self.account.clone(),
            principal: self.principal,
            origin: self.origin.as_ref().map(|o| o.as_str().to_string()),
        }
    }

    /// Returns the file's one spelling (§3.2).
    ///
    /// Members come in schema order, with no whitespace outside strings, hex
    /// lowercase, AUTH-2.130 clause 3's escapes, and one `\n` after the
    /// closing brace — so two conforming writers emit one byte string for
    /// one key.
    pub fn to_json(&self) -> String {
        let mut out = String::from("{\"type\":\"skep-key\",\"v\":1,\"anchor\":");
        out.push_str(if self.anchor { "true" } else { "false" });
        out.push_str(",\"alg\":");
        escape_json_string(&self.alg, &mut out);
        out.push_str(",\"seed\":\"");
        out.push_str(&self.seed.to_hex());
        out.push_str("\",\"public\":\"");
        out.push_str(&self.public.to_hex());
        out.push_str("\",\"fingerprint\":\"");
        out.push_str(&self.fingerprint.to_hex());
        out.push('"');
        if let Some(label) = &self.label {
            out.push_str(",\"label\":");
            escape_json_string(label, &mut out);
        }
        if let Some(account) = &self.account {
            out.push_str(",\"account\":");
            escape_json_string(account, &mut out);
        }
        if let Some(principal) = self.principal {
            out.push_str(&format!(",\"principal\":{principal}"));
        }
        if let Some(origin) = &self.origin {
            out.push_str(",\"origin\":");
            escape_json_string(origin.as_str(), &mut out);
        }
        out.push_str("}\n");
        out
    }

    /// Parses `bytes` under the schema with a standard parser (§3.2).
    ///
    /// Whitespace, member order, escape spelling, a CRLF or a missing
    /// newline are all admitted.
    ///
    /// # Errors
    ///
    /// The refusals are the store's own, each a state a face names beside
    /// the path: [`KeyFileError::NotKeyFile`] for bytes past
    /// [`MAX_KEY_FILE_BYTES`], which are no key file whatever they spell, or
    /// bytes that are not JSON or whose `type` is not `skep-key`;
    /// [`KeyFileError::Newer`] for a `v` above 1; [`KeyFileError::Schema`]
    /// for a member missing, of the wrong type, out of its domain, or
    /// unknown; [`KeyFileError::Disagrees`] where `public` or `fingerprint`
    /// does not re-derive from the seed.
    pub fn parse(bytes: &[u8]) -> Result<KeyFile, KeyFileError> {
        if bytes.len() as u64 > MAX_KEY_FILE_BYTES {
            return Err(KeyFileError::NotKeyFile);
        }
        let value: Value = serde_json::from_slice(bytes).map_err(|_| KeyFileError::NotKeyFile)?;
        let obj = value.as_object().ok_or(KeyFileError::NotKeyFile)?;
        if obj.get("type").and_then(Value::as_str) != Some("skep-key") {
            return Err(KeyFileError::NotKeyFile);
        }
        let schema = |member: &str| KeyFileError::Schema { member: member.to_string() };
        match obj.get("v") {
            Some(Value::Number(n)) => match n.as_u64() {
                Some(1) => {}
                Some(v) if v > 1 => return Err(KeyFileError::Newer { v }),
                _ => return Err(schema("v")),
            },
            _ => return Err(schema("v")),
        }
        const MEMBERS: [&str; 11] =
            ["type", "v", "anchor", "alg", "seed", "public", "fingerprint", "label", "account", "principal", "origin"];
        if let Some(unknown) = obj.keys().find(|k| !MEMBERS.contains(&k.as_str())) {
            return Err(schema(unknown));
        }
        let anchor = obj.get("anchor").and_then(Value::as_bool).ok_or_else(|| schema("anchor"))?;
        let alg = obj.get("alg").and_then(Value::as_str).ok_or_else(|| schema("alg"))?;
        if !ALGS.iter().any(|row| row.token == alg) {
            return Err(schema("alg"));
        }
        let seed_hex = obj.get("seed").and_then(Value::as_str).ok_or_else(|| schema("seed"))?;
        let seed = Seed::from_hex(seed_hex).ok_or_else(|| schema("seed"))?;
        let public_hex = obj.get("public").and_then(Value::as_str).ok_or_else(|| schema("public"))?;
        let public = PublicKey::parse(alg, public_hex).map_err(|_| schema("public"))?;
        let fingerprint = obj
            .get("fingerprint")
            .and_then(Value::as_str)
            .and_then(Fingerprint::parse_hex)
            .ok_or_else(|| schema("fingerprint"))?;
        let label = match obj.get("label") {
            None => None,
            Some(Value::String(s)) if Label::new(s).is_ok() => Some(s.clone()),
            Some(_) => return Err(schema("label")),
        };
        let account = match obj.get("account") {
            None => None,
            Some(Value::String(s)) if is_address_text(s) => Some(s.clone()),
            Some(_) => return Err(schema("account")),
        };
        let principal = match obj.get("principal") {
            None => None,
            Some(Value::Number(n)) => match n.as_u64() {
                Some(p) if p <= (1u64 << 53) - 1 => Some(p),
                _ => return Err(schema("principal")),
            },
            Some(_) => return Err(schema("principal")),
        };
        let origin = match obj.get("origin") {
            None => None,
            Some(Value::String(s)) => Some(Origin::parse(s).ok_or_else(|| schema("origin"))?),
            Some(_) => return Err(schema("origin")),
        };
        // AUTH-5.39 applied to the store: `public` and `fingerprint` must
        // agree with the seed — both re-derived and compared on every load.
        let tag = SigAlgRow::of_token(alg).ok_or_else(|| schema("alg"))?.tag;
        let derived = signer_from_seed_under(tag, seed.bytes()).ok_or_else(|| schema("alg"))?;
        if HybridSigner::public_key(&derived) != &public || Fingerprint::of(&public) != fingerprint {
            return Err(KeyFileError::Disagrees);
        }
        Ok(KeyFile { anchor, alg: alg.to_string(), seed, public, fingerprint, label, account, principal, origin })
    }
}
