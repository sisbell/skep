//! The field set, their order and the grouping (`client.md` §1.1's `sheet`
//! row): the key file's ONE JSON spelling and its reader (§3.2, RULED), the
//! R42 grouping (AUTH-5.1: eight groups of eight hex, a single space between
//! groups, four groups to a line, for a fingerprint wherever one is displayed
//! and for the exported anchor SEED on the sheet alike), and the sheet's
//! field list (AUTH-5.38) — the DRAWING is each embedder's (§5.2). No
//! scannable form (§9 item 13).

use std::fmt;

use serde_json::Value;
use skep_identity::{Fingerprint, PublicKey, SigAlgRow, ALGS};
use skep_signature::HybridSigner;

use crate::hex;
use crate::origin::Origin;
use crate::sign::signer_from_seed_under;
use crate::store::KeyFileError;

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
/// so the overwrite is a plain store the compiler is free to elide. The
/// signer derived from it wipes its Ed25519 half on drop and releases the
/// ML-DSA-65 half unwiped (`skep_signature::HybridSigner`'s doc): the DROP
/// AUTH-5.54 step 3 owes is OPEN WORK for that half, reported and not
/// claimed.
pub struct Seed([u8; 32]);

impl Seed {
    /// A seed from its bytes.
    pub fn new(bytes: [u8; 32]) -> Seed {
        Seed(bytes)
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// A key file over `seed` under the production kind.
    pub fn new(seed: Seed, anchor: bool, label: Option<String>, facts: Option<&Facts>) -> KeyFile {
        let signer = crate::sign::signer_from_seed(seed.bytes());
        let public = HybridSigner::public_key(&signer).clone();
        let fingerprint = Fingerprint::of(&public);
        KeyFile {
            anchor,
            alg: public.alg().to_string(),
            seed,
            public,
            fingerprint,
            label: label.filter(|l| !l.is_empty()),
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
        let seed = Seed(hex::decode32(seed_hex).ok_or_else(|| schema("seed"))?);
        let public_hex = obj.get("public").and_then(Value::as_str).ok_or_else(|| schema("public"))?;
        let public = PublicKey::parse(alg, public_hex).map_err(|_| schema("public"))?;
        let fingerprint = obj
            .get("fingerprint")
            .and_then(Value::as_str)
            .and_then(Fingerprint::parse_hex)
            .ok_or_else(|| schema("fingerprint"))?;
        let label = match obj.get("label") {
            None => None,
            Some(Value::String(s)) if !s.is_empty() && !s.contains('\n') && s.len() <= 128 => Some(s.clone()),
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

/// An address in its one spelling: dotted decimal naturals, no sign, no
/// leading zero, at least one component.
pub fn is_address_text(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|c| {
            !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit()) && (c == "0" || !c.starts_with('0'))
        })
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

    /// §3.2 — one spelling written, a standard parser reading it back:
    /// whitespace and member order admitted, the refusals the store's own.
    #[test]
    fn the_key_file_round_trips_and_refuses_by_state() {
        let facts = Facts { account: "1.0.1".into(), principal: 1, origin: Origin::parse("http://127.0.0.1:8642").unwrap() };
        let file = KeyFile::new(Seed::new([3u8; 32]), true, Some("paper-a".into()), Some(&facts));
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
        let mut empty_label = v.clone();
        empty_label["label"] = Value::from("");
        assert_eq!(KeyFile::parse(empty_label.to_string().as_bytes()).unwrap_err(), KeyFileError::Schema { member: "label".into() });
        let mut bad_seed = v.clone();
        bad_seed["seed"] = Value::from("00".repeat(32));
        assert_eq!(KeyFile::parse(bad_seed.to_string().as_bytes()).unwrap_err(), KeyFileError::Disagrees);
        let mut wrong_type = v.clone();
        wrong_type["anchor"] = Value::from("yes");
        assert_eq!(KeyFile::parse(wrong_type.to_string().as_bytes()).unwrap_err(), KeyFileError::Schema { member: "anchor".into() });
    }
}
