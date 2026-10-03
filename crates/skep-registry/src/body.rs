//! THE TWO BODIES THIS CRATE PINS — the BINDING's and the ENDPOINT's
//! (REG-1.86's table, its first two rows) — under THE CANONICAL RULE: the
//! credential records' admission sentence applied to a flat one-object body,
//! `parse(b)` answering a body only where `b == encode(parse(b))`. So each
//! body has ONE form, the bytes a record-grade signature ranges over are the
//! bytes every reader parses, and a body spelled any other way — a space, a
//! member out of order, a non-shortest escape, a member twice — is no record
//! at every parser alike.
//!
//! THE ENCODING is the credential records' rule applied to a flat object:
//! `{"type":"<the row's string>"`, then the row's members in the table's
//! order (`prefix` for the binding, `origins` for the endpoint), then
//! `replaces` where present, then `sig` where present, `}` — no whitespace
//! outside strings, strings escaped by the shortest JSON escapes and no
//! others (`"`, `\`, the five named C0 controls, `\u00xx` lowercase for the
//! rest; nothing else escaped), no byte after the brace.
//!
//! WHAT THE PARSE CHECKS IS THE FORM, NEVER THE ADMISSIBILITY (REG-1.86
//! (c), (d), (g)): `type` is the string of the kind THE CALLER NAMES — the
//! link's slot — and a foreign `type` is refused; NO MEMBER IS A JSON NUMBER,
//! anywhere in the body; no member stands beside the row's own, `replaces`
//! and `sig`; `prefix` and `replaces` are addresses in dotted decimal, the
//! local form; `origins` is a non-empty array of strings. Whether an origin
//! is https with a routable host is the resolver's question, and whether
//! `replaces` names the deposit current at the record's position is the
//! reader's currency rule (REG-1.10, REG-2.24); neither is asked here. `sig`
//! is answered as the string found, present or absent, beside the SIG-LESS
//! CANONICAL PROJECTION a verifier frames (REG-1.86 (e)).
//!
//! THE CAP, [`MAX_REGISTRY_RECORD_BYTES`]: a body past it is refused before
//! any tree is built, since a JSON parser builds its whole tree before the
//! first schema check. A SIGNED body carries its `sig` inside the cap: the
//! hybrid blob's hex is 6,746 characters under the production row, so a
//! binding signed is some seven kilobytes though its members are under a
//! hundred bytes, and an endpoint's a few hundred more.
//!
//! The other five body kinds — the takedown record's base reading, the
//! disavowal, the two ground records, the org-chosen succession policy —
//! have rows ([`crate::rows`]) and no parser here: their schemas are pinned
//! where their own rules land.

use std::fmt::Write as _;

use serde_json::Value;
use skep_address::{validate, Nat, Tumbler};

use crate::rows::Kind;

/// The most bytes a registry record body may carry, `sig` included, a body
/// past it refused ([`Refusal::PastCap`]) before any parse — 16 KiB, an
/// interim pin confirmed at the registry's review round: the production
/// row's `sig` is 6,746 bytes of hex on its own, so a signed binding is
/// near seven kilobytes and a signed endpoint with a long list of origins
/// stays under this with room; a body of twice the signature's width is
/// no record of either kind.
pub const MAX_REGISTRY_RECORD_BYTES: usize = 16 * 1024;

/// The two kinds whose bodies this crate parses — the kind the caller names
/// for a parse, read off the link's type slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BodyKind {
    Binding,
    Endpoint,
}

impl BodyKind {
    /// The `type` member's string (REG-1.86 (a)): the kind's name
    /// lowercased.
    pub fn type_value(self) -> &'static str {
        match self {
            BodyKind::Binding => "binding",
            BodyKind::Endpoint => "endpoint",
        }
    }

    /// The row's kind.
    pub fn kind(self) -> Kind {
        match self {
            BodyKind::Binding => Kind::Binding,
            BodyKind::Endpoint => Kind::Endpoint,
        }
    }

    /// The kind a `type` string names, where it names one of the two.
    pub fn of_type_value(s: &str) -> Option<BodyKind> {
        match s {
            "binding" => Some(BodyKind::Binding),
            "endpoint" => Some(BodyKind::Endpoint),
            _ => None,
        }
    }
}

/// THE BINDING's body (REG-1.86's table; REG-2.19): the prefix in address
/// form, the binding's one non-address term — the account rides the link's
/// target and is no member — and `replaces`, the link's address of the
/// binding this one replaces at that prefix, absent on an allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub prefix: String,
    pub replaces: Option<String>,
}

/// THE ENDPOINT's body (REG-1.86's table; REG-1.9, REG-1.10): the org's
/// ordered list of origins, at least one, the order load-bearing at the
/// resolver's walk, and `replaces`, the link's address of the endpoint
/// deposit this one replaces in that doc 1, absent on the org's first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub origins: Vec<String>,
    pub replaces: Option<String>,
}

/// A body of one of the two kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Binding(Binding),
    Endpoint(Endpoint),
}

impl Body {
    /// The body's kind — the `type` member it is encoded under.
    pub fn kind(&self) -> BodyKind {
        match self {
            Body::Binding(_) => BodyKind::Binding,
            Body::Endpoint(_) => BodyKind::Endpoint,
        }
    }

    /// The `replaces` member, where the body carries one.
    pub fn replaces(&self) -> Option<&str> {
        match self {
            Body::Binding(b) => b.replaces.as_deref(),
            Body::Endpoint(e) => e.replaces.as_deref(),
        }
    }
}

/// A parsed record: the body and the `sig` member's string as it stands —
/// present or absent, the empty string included, which is a `sig` and never
/// `None`. What a verifier reads off a committed atom: `sig` the signature
/// under trial, [`Record::canonical_sigless`] the bytes it was made over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub body: Body,
    pub sig: Option<String>,
}

impl Record {
    /// The sig-less canonical projection — [`encode`] of the body with no
    /// `sig` — the body-bytes row of the `record` grammar a record-grade
    /// signature ranges over.
    pub fn canonical_sigless(&self) -> String {
        encode(&self.body, None)
    }
}

/// Why bytes are no record of the kind named — each its own cause, joined to
/// the daemon's refusal token by [`Refusal::token`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Past [`MAX_REGISTRY_RECORD_BYTES`]: parsed by no reader at all.
    PastCap,
    /// The bytes are no UTF-8 text.
    NotUtf8,
    /// The text is no JSON value — a trailing non-whitespace byte included.
    NotJson,
    /// A JSON value that is no object.
    NotAnObject,
    /// A JSON number somewhere in the body (REG-1.86 (d)): the whole body's
    /// range, tested before any member is read.
    Number,
    /// The `type` member is absent, no string, or not the string of the
    /// kind the caller named: a record of that kind it is not (REG-1.86 (a)).
    WrongType,
    /// A member the row requires is absent.
    MissingMember(&'static str),
    /// A member beside the row's own, `replaces` and `sig` ("NOTHING ELSE").
    UnknownMember,
    /// A member that must be a string is not: `prefix`, `replaces`, `sig`.
    NotAString(&'static str),
    /// A member that must parse as an address in dotted decimal does not —
    /// `prefix`, `replaces` — the one spelling of that address included
    /// (no leading zero, no sign, every component a decimal natural, the
    /// whole T4-valid).
    NotAnAddress(&'static str),
    /// `origins` is no array of strings.
    OriginsNotStrings,
    /// `origins` is empty: "AT LEAST ONE entry", and `[]` is a body no
    /// reader holds.
    EmptyOrigins,
    /// The members each pass and the bytes are still not the canonical
    /// re-encoding of what they spell: whitespace, another member order, a
    /// member twice, a non-shortest escape, a byte after the brace.
    NotCanonical,
}

impl Refusal {
    /// The machine token: the cause's own name, a member name joined after
    /// a colon where the cause names one.
    pub fn token(&self) -> String {
        match self {
            Refusal::PastCap => "past_cap".into(),
            Refusal::NotUtf8 => "not_utf8".into(),
            Refusal::NotJson => "not_json".into(),
            Refusal::NotAnObject => "not_an_object".into(),
            Refusal::Number => "number".into(),
            Refusal::WrongType => "wrong_type".into(),
            Refusal::MissingMember(m) => format!("missing_member:{m}"),
            Refusal::UnknownMember => "unknown_member".into(),
            Refusal::NotAString(m) => format!("not_a_string:{m}"),
            Refusal::NotAnAddress(m) => format!("not_an_address:{m}"),
            Refusal::OriginsNotStrings => "origins_not_strings".into(),
            Refusal::EmptyOrigins => "empty_origins".into(),
            Refusal::NotCanonical => "not_canonical".into(),
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.token())
    }
}

impl std::error::Error for Refusal {}

/// THE ONE PARSER: the record `bytes` spell under the kind the caller names,
/// under the canonical rule — a record is answered only where `bytes ==
/// encode(parse(bytes))` — or why they are none. Total over any bytes: no
/// panic, no tree past the cap, and the JSON parser answers only "is this
/// JSON, and which"; every verdict is this schema's own. The checks run in
/// the order the causes are listed on [`Refusal`]: the cap, the text, the
/// value, the object, the number scan, `type`, the member set, each member's
/// form, then the canonical compare.
pub fn parse(kind: BodyKind, bytes: &[u8]) -> Result<Record, Refusal> {
    if bytes.len() > MAX_REGISTRY_RECORD_BYTES {
        return Err(Refusal::PastCap);
    }
    let text = core::str::from_utf8(bytes).map_err(|_| Refusal::NotUtf8)?;
    let value: Value = serde_json::from_str(text).map_err(|_| Refusal::NotJson)?;
    let object = value.as_object().ok_or(Refusal::NotAnObject)?;
    if holds_a_number(&value) {
        return Err(Refusal::Number);
    }
    if object.get("type").and_then(Value::as_str) != Some(kind.type_value()) {
        return Err(Refusal::WrongType);
    }
    let own: &[&str] = match kind {
        BodyKind::Binding => &["prefix"],
        BodyKind::Endpoint => &["origins"],
    };
    if object.keys().any(|k| k != "type" && k != "replaces" && k != "sig" && !own.contains(&k.as_str()))
    {
        return Err(Refusal::UnknownMember);
    }
    let replaces = optional_address(object, "replaces")?;
    let sig = match object.get("sig") {
        None => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => return Err(Refusal::NotAString("sig")),
    };
    let body = match kind {
        BodyKind::Binding => {
            let prefix = required_string(object, "prefix")?;
            if !address_form(prefix) {
                return Err(Refusal::NotAnAddress("prefix"));
            }
            Body::Binding(Binding { prefix: prefix.to_owned(), replaces })
        }
        BodyKind::Endpoint => {
            let origins = object
                .get("origins")
                .ok_or(Refusal::MissingMember("origins"))?
                .as_array()
                .ok_or(Refusal::OriginsNotStrings)?;
            let origins: Vec<String> = origins
                .iter()
                .map(|o| o.as_str().map(str::to_owned).ok_or(Refusal::OriginsNotStrings))
                .collect::<Result<_, _>>()?;
            if origins.is_empty() {
                return Err(Refusal::EmptyOrigins);
            }
            Body::Endpoint(Endpoint { origins, replaces })
        }
    };
    // THE ADMISSION SENTENCE: admit only where the input is the canonical
    // re-encoding of what it spells — by the public encoder itself, the
    // function a signer composes with, `sig` included.
    if encode(&body, sig) != text {
        return Err(Refusal::NotCanonical);
    }
    Ok(Record { body, sig: sig.map(str::to_owned) })
}

/// Whether any value in the tree is a JSON number (REG-1.86 (d)).
fn holds_a_number(v: &Value) -> bool {
    match v {
        Value::Number(_) => true,
        Value::Array(items) => items.iter().any(holds_a_number),
        Value::Object(members) => members.values().any(holds_a_number),
        Value::Null | Value::Bool(_) | Value::String(_) => false,
    }
}

/// A required string member.
fn required_string<'o>(
    object: &'o serde_json::Map<String, Value>,
    member: &'static str,
) -> Result<&'o str, Refusal> {
    match object.get(member) {
        None => Err(Refusal::MissingMember(member)),
        Some(Value::String(s)) => Ok(s.as_str()),
        Some(_) => Err(Refusal::NotAString(member)),
    }
}

/// An optional member that, where present, is a string in address form.
fn optional_address(
    object: &serde_json::Map<String, Value>,
    member: &'static str,
) -> Result<Option<String>, Refusal> {
    match object.get(member) {
        None => Ok(None),
        Some(Value::String(s)) => {
            if !address_form(s) {
                return Err(Refusal::NotAnAddress(member));
            }
            Ok(Some(s.clone()))
        }
        Some(_) => Err(Refusal::NotAString(member)),
    }
}

/// Whether `s` is an address in dotted decimal, in its ONE spelling: every
/// component a decimal natural with no sign, no separator and no leading
/// zero, the whole a T4-valid address, and the address's own rendering the
/// string itself.
fn address_form(s: &str) -> bool {
    let comps: Option<Vec<Nat>> = s
        .split('.')
        .map(|c| (!c.is_empty() && c.bytes().all(|b| b.is_ascii_digit())).then(|| c.parse::<Nat>().ok()).flatten())
        .collect();
    let Some(comps) = comps else { return false };
    let Ok(tumbler) = Tumbler::new(comps) else { return false };
    validate(tumbler).is_ok_and(|address| address.tumbler().to_string() == s)
}

/// THE CANONICAL FORM — the one byte string a body has, with its `sig` where
/// one is given: what a signer composes (with `None`, then with the `sig` it
/// made), what a verifier re-spells, and what [`parse`] holds its input to.
pub fn encode(body: &Body, sig: Option<&str>) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("{\"type\":\"");
    out.push_str(body.kind().type_value());
    out.push('"');
    match body {
        Body::Binding(b) => {
            out.push_str(",\"prefix\":");
            escape_json_string(&b.prefix, &mut out);
        }
        Body::Endpoint(e) => {
            out.push_str(",\"origins\":[");
            for (i, origin) in e.origins.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                escape_json_string(origin, &mut out);
            }
            out.push(']');
        }
    }
    if let Some(replaces) = body.replaces() {
        out.push_str(",\"replaces\":");
        escape_json_string(replaces, &mut out);
    }
    if let Some(sig) = sig {
        out.push_str(",\"sig\":");
        escape_json_string(sig, &mut out);
    }
    out.push('}');
    out
}

/// A JSON string in the canonical escaping — the credential records' rule:
/// `"` and `\` escaped, the five named C0 controls by their short escapes,
/// the remaining C0 controls as `\u00xx` in lowercase hex, and nothing else
/// escaped.
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
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(prefix: &str, replaces: Option<&str>) -> Body {
        Body::Binding(Binding { prefix: prefix.into(), replaces: replaces.map(str::to_owned) })
    }

    /// The canonical rule read from both sides: a body's encoding parses to
    /// itself, with and without a `sig`, and the parse's sig-less projection
    /// is the encoding with none.
    #[test]
    fn encode_then_parse_is_a_fixpoint() {
        let body = Body::Endpoint(Endpoint {
            origins: vec!["https://acme.example".into(), "http://x.onion".into()],
            replaces: Some("1.0.2.0.1.0.2.1".into()),
        });
        for sig in [None, Some("ab"), Some("")] {
            let text = encode(&body, sig);
            let record = parse(BodyKind::Endpoint, text.as_bytes()).expect("canonical");
            assert_eq!(record.body, body);
            assert_eq!(record.sig.as_deref(), sig);
            assert_eq!(record.canonical_sigless(), encode(&body, None));
            assert_eq!(encode(&record.body, record.sig.as_deref()), text);
        }
        assert_eq!(
            encode(&binding("1.5", None), None),
            r#"{"type":"binding","prefix":"1.5"}"#
        );
    }

    /// The escaping is the shortest JSON escape and no other, so a body
    /// spelled with a longer escape of the same string is not canonical.
    #[test]
    fn strings_take_the_shortest_escapes_alone() {
        let body = Body::Endpoint(Endpoint { origins: vec!["a\"b\\c\n\u{1}/é".into()], replaces: None });
        assert_eq!(
            encode(&body, None),
            "{\"type\":\"endpoint\",\"origins\":[\"a\\\"b\\\\c\\n\\u0001/é\"]}"
        );
        let longer = "{\"type\":\"endpoint\",\"origins\":[\"a\\\"b\\\\c\\n\\u0001\\/é\"]}";
        assert_eq!(parse(BodyKind::Endpoint, longer.as_bytes()), Err(Refusal::NotCanonical));
    }

    /// The address form is one spelling: a sign, a separator, a leading
    /// zero, an empty component and a T4-invalid tumbler are each refused.
    #[test]
    fn the_address_form_is_one_spelling() {
        for ok in ["1", "1.5", "1.0.1.0.1.0.2.3", "1.1.0.1"] {
            assert!(address_form(ok), "{ok}");
        }
        for bad in ["", "+1.5", "1_0.5", "01.5", "1..5", "1.5.", "1.5.0", "a", "1.5 ", "1.-5"] {
            assert!(!address_form(bad), "{bad}");
        }
    }

    /// The cap bounds the parse, never a record: a body one byte past it is
    /// refused before any tree is built, and a binding signed under the
    /// production row — its `sig` 6,746 hex characters — is well under it.
    #[test]
    fn the_cap_bounds_the_parse() {
        assert_eq!(MAX_REGISTRY_RECORD_BYTES, 16_384);
        let signed = encode(&binding("1.5", None), Some(&"ab".repeat(3373)));
        assert!(signed.len() < MAX_REGISTRY_RECORD_BYTES / 2, "{}", signed.len());
        assert!(parse(BodyKind::Binding, signed.as_bytes()).is_ok());
        let mut past = b"{".to_vec();
        past.resize(MAX_REGISTRY_RECORD_BYTES + 1, b' ');
        assert_eq!(parse(BodyKind::Binding, &past), Err(Refusal::PastCap));
        past.truncate(MAX_REGISTRY_RECORD_BYTES);
        assert_eq!(parse(BodyKind::Binding, &past), Err(Refusal::NotJson), "at the cap: parsed, and no JSON");
    }
}
