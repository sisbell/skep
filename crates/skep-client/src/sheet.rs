//! The field set, their order and the grouping (`client.md` §1.1's `sheet`
//! row): the key file's ONE JSON spelling and its reader with its refusals,
//! [`KeyFileError`] (§3.2, RULED); the byline a key carries, [`Label`], one
//! domain test (AUTH-1.24) wherever a label is made — a box — or read — a
//! file; the [`Seed`] every key's secret is born into; the R42 grouping
//! (AUTH-5.1: eight groups of eight hex, a single space between groups, four
//! groups to a line, for a fingerprint wherever one is displayed and for the
//! exported anchor SEED on the sheet alike), and the sheet's field list
//! (AUTH-5.38) — the DRAWING is each embedder's (§5.2). No scannable form
//! (§9 item 13).

use std::fmt;

use serde_json::Value;
use skep_identity::{Fingerprint, PublicKey, SigAlgRow, ALGS};
use skep_signature::HybridSigner;

use crate::address::is_address_text;
use crate::hex;
use crate::origin::Origin;
use crate::sign::signer_from_seed_under;

/// AUTH-5.1 — 64 hex as EIGHT GROUPS OF EIGHT, a single space between
/// groups, FOUR GROUPS TO A LINE (R42; RES-62 item 9, pick A).
pub fn group_hex(hex64: &str) -> String {
    let groups: Vec<&str> = (0..hex64.len()).step_by(8).map(|i| &hex64[i..(i + 8).min(hex64.len())]).collect();
    groups
        .chunks(4)
        .map(|line| line.join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}

/// AUTH-5.2 — a label rendered INERT: every C0 control, DEL and every bidi
/// control (U+202A–U+202E, U+2066–U+2069, U+200E, U+200F, U+061C) shown as
/// its code point, never interpreted. The domain admits them (AUTH-1.24)
/// and AUTH-5.3 declines to narrow it, so the rendering is where they are
/// disarmed.
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

/// The 32-byte seed — the paper backup's 64 hex — zeroed on drop, best
/// effort: this crate takes no zeroizing dependency and forbids unsafe code,
/// so the overwrite is a plain store the compiler is free to elide. Every
/// seed the crate makes is BORN in this value — drawn by [`Seed::fresh`],
/// decoded by [`Seed::from_hex`] — so no bare copy outlives the DROP
/// AUTH-5.54 step 3 owes. The signer derived from it wipes its Ed25519 half
/// on drop and releases the ML-DSA-65 half unwiped
/// (`skep_signature::HybridSigner`'s doc): the DROP is OPEN WORK for that
/// half, reported and not claimed.
pub struct Seed([u8; 32]);

impl Seed {
    /// A seed from its bytes.
    pub fn new(bytes: [u8; 32]) -> Seed {
        Seed(bytes)
    }

    /// A fresh seed from the OS random source (`getrandom`, a `CryptoRng`),
    /// fail-stop — no seed from anything weaker — drawn straight into the
    /// value that zeroes it.
    pub fn fresh() -> Seed {
        let mut seed = Seed([0u8; 32]);
        getrandom::fill(&mut seed.0).expect("OS entropy unavailable");
        seed
    }

    /// A seed from its 64 hex, either case — a print's re-type, a key file's
    /// member — decoded straight into the value that zeroes it; `None` for
    /// any other text.
    pub fn from_hex(text: &str) -> Option<Seed> {
        let mut seed = Seed([0u8; 32]);
        hex::decode_into(text, &mut seed.0).then_some(seed)
    }

    /// The bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The seed's 64 hex — the sheet's one secret field.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.0 = [0u8; 32];
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(…)")
    }
}

/// A byline in AUTH-1.24's DOMAIN, never empty (AUTH-5.42): non-empty, no
/// `\n`, at most 128 BYTES of UTF-8 counted as `Enrollment::new` counts.
/// Every box applies the domain test ITSELF, before anything is made from a
/// label (P13; `client.md` §2.2 `keygen`), and [`KeyFile::parse`] admits a
/// file's `label` member by the same test.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Label(String);

/// Why a label is outside the domain — faced at the box, with the byte
/// count named where the limit is the fault (AUTH-1.25's `TooLong` and
/// `Newline`, and the empty label AUTH-5.42 faces).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelFault {
    Empty,
    Newline,
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

impl Label {
    /// The domain test (AUTH-1.24), the newline read before the length as
    /// `Enrollment::new` reads it (AUTH-1.25).
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

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The label as a path component: ASCII alphanumerics kept, every other
    /// character a `-`, runs collapsed — the slug the anchor file's name
    /// takes (§6).
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

/// THE KEY FILE AND THE ANCHOR EXPORT, one struct (§3.2, RULED 2026-09-22
/// "b"): `type`, `v`, `anchor`, `alg`, `seed`, `public`, `fingerprint`,
/// `label?`, `account?`, `principal?`, `origin?` — AUTH-5.38's fields where
/// the format allows, and no other member. `public` and `fingerprint` are
/// RE-DERIVED from the seed on every load (AUTH-5.39 applied to the store's
/// own files): a file whose members disagree with its seed is "not the key
/// this file names".
pub struct KeyFile {
    pub anchor: bool,
    /// An `ALGS` token (AUTH-1.5).
    pub alg: String,
    seed: Seed,
    pub public: PublicKey,
    pub fingerprint: Fingerprint,
    /// Present only where a label exists — never `""` (AUTH-1.24).
    pub label: Option<String>,
    /// AUTH-5.38's three facts, present where known at export.
    pub account: Option<String>,
    pub principal: Option<u64>,
    pub origin: Option<Origin>,
}

impl fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyFile({}, anchor {}, fingerprint {})", self.alg, self.anchor, self.fingerprint)
    }
}

/// A KEY FILE'S REFUSALS (§3.2) — the store's own faces and never wire
/// tokens, each read off the FILE's own contents: a state, rendered as
/// AUTH-5.67's halt naming the path and the state
/// ([`store_halt`](crate::store::store_halt)); all exit 3 (§1.1's `halt` row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyFileError {
    /// Not JSON, or `type` is not `skep-key`.
    NotKeyFile,
    /// `v` above 1: "this file was written by a newer skep than this one",
    /// never "not a key file".
    Newer { v: u64 },
    /// A member missing, of the wrong type, out of its domain, or unknown.
    Schema { member: String },
    /// `public` or `fingerprint` does not re-derive from the seed: "this is
    /// not the key this file names" (AUTH-5.39).
    Disagrees,
    /// An anchor file where a key was selected to SIGN or to be enrolled as a
    /// device key (§2.2's selection test): the one walk that imports an
    /// anchor is `skep recover`.
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

/// The three AUTH-5.38 facts an artifact carries where the account exists
/// at export (the notebook: `delegate` runs ahead of the backup moment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    pub account: String,
    pub principal: u64,
    pub origin: Origin,
}

/// The sheet's FIELD LIST, in order (AUTH-5.38; §5.2): the fields SAVE
/// `public` — the seed and the fingerprint grouped (AUTH-5.1), the label
/// inert (AUTH-5.2), the three facts where they exist. A rendering of the
/// fields and never of the file's bytes; read by a person, parsed by nothing.
/// Its `Debug` prints every field but the seed, which shows as `…`: the
/// sheet is a SECRET moment's payload (§1.1's `person` row), and a debug
/// log of moments is an ordinary embedder's.
#[derive(Clone, PartialEq, Eq)]
pub struct SheetFields {
    pub anchor: bool,
    pub alg: String,
    pub label: Option<String>,
    pub fingerprint_hex: String,
    pub fingerprint_grouped: String,
    pub seed_grouped: String,
    pub account: Option<String>,
    pub principal: Option<u64>,
    pub origin: Option<String>,
}

impl SheetFields {
    /// The labelled lines a terminal or a window draws, in the pinned order.
    pub fn lines(&self) -> Vec<(String, String)> {
        let mut out = vec![
            ("kind".to_string(), if self.anchor { "ANCHOR (paper)".to_string() } else { "device key".to_string() }),
            ("alg".to_string(), self.alg.clone()),
        ];
        if let Some(label) = &self.label {
            out.push(("label".to_string(), render_inert(label)));
        }
        out.push(("fingerprint".to_string(), self.fingerprint_grouped.clone()));
        out.push(("seed".to_string(), self.seed_grouped.clone()));
        if let Some(a) = &self.account {
            out.push(("account".to_string(), a.clone()));
        }
        if let Some(p) = self.principal {
            out.push(("principal".to_string(), p.to_string()));
        }
        if let Some(o) = &self.origin {
            out.push(("origin".to_string(), o.clone()));
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

/// AUTH-2.130 clause 3's string escaping, the spelling the file takes too
/// (§3.2): `"`, `\` and U+0000–U+001F escaped — the two-character forms
/// where JSON defines one, `\u00xx` lowercase otherwise — and nothing else.
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
    /// A key file over `seed` under the production kind, its byline a
    /// [`Label`] — AUTH-1.24's domain, tested where the label was made, as
    /// [`KeyFile::parse`] tests a file's `label` member.
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

    /// The signer this file's seed derives — the in-memory arm of the
    /// `Signer` seam.
    pub fn signer(&self) -> HybridSigner {
        signer_from_seed_under(self.public.sig_alg_row().tag, self.seed.bytes()).expect("the file's alg is a row this build holds")
    }

    /// The seed's 64 hex, the sheet's one secret field.
    pub fn seed_hex(&self) -> String {
        self.seed.to_hex()
    }

    /// The sheet's fields (AUTH-5.38), the seed and the fingerprint grouped
    /// (AUTH-5.1).
    pub fn sheet(&self) -> SheetFields {
        SheetFields {
            anchor: self.anchor,
            alg: self.alg.clone(),
            label: self.label.clone(),
            fingerprint_hex: self.fingerprint.to_hex(),
            fingerprint_grouped: group_hex(&self.fingerprint.to_hex()),
            seed_grouped: group_hex(&self.seed.to_hex()),
            account: self.account.clone(),
            principal: self.principal,
            origin: self.origin.as_ref().map(|o| o.as_str().to_string()),
        }
    }

    /// THE ONE SPELLING (§3.2): members in schema order, no whitespace
    /// outside strings, hex lowercase, AUTH-2.130 clause 3's escapes, one
    /// `\n` after the closing brace — so two conforming writers emit one byte
    /// string for one key.
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

    /// READ by a standard parser under the schema (§3.2): whitespace, member
    /// order, escape spelling, a CRLF or a missing newline all ADMITTED; the
    /// refusals the store's own — `NotKeyFile`, `Newer{v}`, `Schema{member}`,
    /// `Disagrees` — each a state a face names beside the path.
    pub fn parse(bytes: &[u8]) -> Result<KeyFile, KeyFileError> {
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
        // AGREE with the seed — both re-derived and compared on every load.
        let tag = SigAlgRow::of_token(alg).ok_or_else(|| schema("alg"))?.tag;
        let derived = signer_from_seed_under(tag, seed.bytes()).ok_or_else(|| schema("alg"))?;
        if HybridSigner::public_key(&derived) != &public || Fingerprint::of(&public) != fingerprint {
            return Err(KeyFileError::Disagrees);
        }
        Ok(KeyFile { anchor, alg: alg.to_string(), seed, public, fingerprint, label, account, principal, origin })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AUTH-5.1 — eight groups of eight, four to a line.
    #[test]
    fn the_grouping_is_eight_by_eight_four_to_a_line() {
        let hex64 = "0123456789abcdef".repeat(4);
        let grouped = group_hex(&hex64);
        let lines: Vec<&str> = grouped.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "01234567 89abcdef 01234567 89abcdef");
        assert_eq!(lines[1], lines[0]);
    }

    /// AUTH-5.2 — control and bidi characters render as code points.
    #[test]
    fn a_label_renders_inert() {
        assert_eq!(render_inert("ok name"), "ok name");
        assert_eq!(render_inert("a\u{202E}b\u{07}"), "a<U+202E>b<U+0007>");
    }

    /// AUTH-1.24/1.25 at the box: 128 bytes admitted, 129 refused with the byte
    /// count named (AUTH-2.96's vector row), a newline refused, the empty label
    /// faced (AUTH-5.42).
    #[test]
    fn the_label_domain_is_tested_at_the_box() {
        assert!(Label::new(&"a".repeat(128)).is_ok());
        assert_eq!(Label::new(&"a".repeat(129)).unwrap_err(), LabelFault::TooLong { bytes: 129 });
        assert_eq!(Label::new("two\nlines").unwrap_err(), LabelFault::Newline);
        assert_eq!(Label::new("").unwrap_err(), LabelFault::Empty);
        assert!(Label::new("my phone ").is_ok(), "a trailing space is in the domain");
        assert_eq!(Label::new("Paper A / 2026").unwrap().slug(), "paper-a-2026");
        // Bytes, not characters: 43 three-byte characters are 129 bytes.
        assert_eq!(Label::new(&"€".repeat(43)).unwrap_err(), LabelFault::TooLong { bytes: 129 });
    }

    /// A seed is born in its zeroing value: drawn fresh, or decoded from its
    /// 64 hex in either case — any other text is no seed; and the sheet
    /// prints every field but the seed.
    #[test]
    fn a_seed_is_drawn_or_decoded_into_its_value_and_the_sheet_hides_it() {
        assert_ne!(Seed::fresh().bytes(), Seed::fresh().bytes());
        assert_eq!(Seed::from_hex(&"AB".repeat(32)).map(|s| *s.bytes()), Some([0xab; 32]));
        assert!(Seed::from_hex(&"ab".repeat(31)).is_none() && Seed::from_hex(&"zz".repeat(32)).is_none());
        let file = KeyFile::new(Seed::new([4u8; 32]), true, Some(Label::new("paper").unwrap()), None);
        let printed = format!("{:?}", file.sheet());
        assert!(printed.contains(&file.fingerprint.to_hex()) && printed.contains("seed_grouped: …"), "{printed}");
        assert!(!printed.contains(&file.seed_hex()[..8]), "the seed never prints: {printed}");
    }

    /// §3.2 — one spelling written, a standard parser reading it back:
    /// whitespace and member order admitted, the refusals the store's own.
    #[test]
    fn the_key_file_round_trips_and_refuses_by_state() {
        let facts = Facts { account: "1.0.1".into(), principal: 1, origin: Origin::parse("http://127.0.0.1:8642").unwrap() };
        let file = KeyFile::new(Seed::new([3u8; 32]), true, Some(Label::new("paper-a").unwrap()), Some(&facts));
        let json = file.to_json();
        assert!(json.starts_with("{\"type\":\"skep-key\",\"v\":1,\"anchor\":true,\"alg\":\"mldsa65-ed25519\",\"seed\":\""));
        assert!(json.ends_with("\"origin\":\"http://127.0.0.1:8642\"}\n"));
        assert!(!json.contains(' '));
        let again = KeyFile::parse(json.as_bytes()).unwrap();
        assert_eq!(again.fingerprint, file.fingerprint);
        assert_eq!(again.label.as_deref(), Some("paper-a"));
        assert_eq!(again.principal, Some(1));
        // An editor-touched file still opens: whitespace, CRLF, member order.
        let v: Value = serde_json::from_str(&json).unwrap();
        let pretty = serde_json::to_string_pretty(&v).unwrap().replace('\n', "\r\n");
        assert_eq!(KeyFile::parse(pretty.as_bytes()).unwrap().fingerprint, file.fingerprint);
        // The refusals.
        assert_eq!(KeyFile::parse(b"not json").unwrap_err(), KeyFileError::NotKeyFile);
        assert_eq!(KeyFile::parse(br#"{"type":"skep-enroll"}"#).unwrap_err(), KeyFileError::NotKeyFile);
        let mut newer = v.clone();
        newer["v"] = Value::from(2);
        assert_eq!(KeyFile::parse(newer.to_string().as_bytes()).unwrap_err(), KeyFileError::Newer { v: 2 });
        let mut extra = v.clone();
        extra["custody"] = Value::from("x");
        assert_eq!(KeyFile::parse(extra.to_string().as_bytes()).unwrap_err(), KeyFileError::Schema { member: "custody".into() });
        // The file's `label` member is held to the box's own domain test.
        for bad in [String::new(), "two\nlines".into(), "a".repeat(129)] {
            let mut bad_label = v.clone();
            bad_label["label"] = Value::from(bad);
            assert_eq!(KeyFile::parse(bad_label.to_string().as_bytes()).unwrap_err(), KeyFileError::Schema { member: "label".into() });
        }
        let mut bad_seed = v.clone();
        bad_seed["seed"] = Value::from("00".repeat(32));
        assert_eq!(KeyFile::parse(bad_seed.to_string().as_bytes()).unwrap_err(), KeyFileError::Disagrees);
        let mut wrong_type = v.clone();
        wrong_type["anchor"] = Value::from("yes");
        assert_eq!(KeyFile::parse(wrong_type.to_string().as_bytes()).unwrap_err(), KeyFileError::Schema { member: "anchor".into() });
    }
}
