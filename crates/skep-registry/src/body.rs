//! THE TWO BODIES THIS CRATE PINS — the BINDING's and the ENDPOINT's
//! (REG-1.86's table, its first two rows) — under THE CANONICAL RULE: the
//! credential records' admission sentence applied to a flat one-object body,
//! `parse(b)` answering a body only where `b == encode(parse(b))`. So each
//! body has ONE form: the sig-less projection a record-grade signature
//! ranges over is the one every reader re-derives, byte for byte, from the
//! bytes it parses, and a body spelled any other way — a space, a member out
//! of order, a non-shortest escape, a member twice — is no record at every
//! parser alike.
//!
//! THE ENCODING is the credential records' rule applied to a flat object:
//! `{"type":"<the row's string>"`, then the row's own members in the order
//! REG-1.86's table lists them (`prefix` for the binding, `origins` for the
//! endpoint), then `replaces` where present, then `sig` where present, `}` —
//! no whitespace outside strings, strings escaped by the shortest JSON
//! escapes and no others (`"`, `\`, the five named C0 controls, `\u00xx`
//! lowercase for the rest; nothing else escaped), no byte after the brace.
//!
//! WHAT THE PARSE CHECKS IS THE FORM, NEVER THE ADMISSIBILITY (REG-1.86
//! (c), (d), (g)): `type` is the string of the kind THE CALLER NAMES — the
//! link's slot — and any other `type` is refused (`wrong_type`); NO MEMBER IS
//! A JSON NUMBER, anywhere in the body; no member stands beside the row's
//! own, `replaces` and `sig`; the ADDRESS MEMBERS — `prefix` and `replaces`,
//! the members written in address form — each spell an address in its one
//! dotted-decimal spelling; `origins` is a non-empty array of strings; and
//! `sig`, where present, is a string (REG-1.86 (e): "a STRING where signed
//! ops comes to write one"), the one form [`encode`] writes it in.
//! Whether an origin is https with a routable host is the resolver's
//! question; whether an address member is written in the LOCAL FORM of the
//! board the record is homed on (REG-1.86 (c), (g)) is its writer's — a
//! global-form address is spelled alike, and no parse tells the two apart;
//! and whether `replaces` names the deposit current at the record's position
//! is the reader's currency rule (REG-1.10, REG-2.24). None is asked here.
//! `sig` is answered as the string found, present or absent, beside the
//! SIG-LESS CANONICAL PROJECTION a verifier frames (REG-1.86 (e)).
//!
//! WHAT THE PARSE CHECKS, THE TYPES CARRY: an address member is the
//! [`Address`] it spells and the origins are [`Origins`], never empty. So a
//! reader takes each member as the value it is and converts or checks
//! nothing again, and every [`Body`] a caller can build encodes to bytes
//! [`parse`] admits, the cap aside — a signer never signs a body the daemon
//! then refuses for its form.
//!
//! THE CAP, [`MAX_REGISTRY_RECORD_BYTES`], counts every byte, `sig`
//! included: a body past it is refused before any tree is built, since a
//! JSON parser builds its whole tree before the first schema check. What it
//! is priced against — a signed body's size, and what a hostile body costs a
//! reader — the constant's own doc states.
//!
//! The other five body-bearing rows — the takedown record's base reading,
//! the disavowal, the two ground records, the org-chosen succession policy,
//! subtype rows all and none a kind — stand in the table ([`crate::rows()`])
//! with their `type` strings and have no parser here: their schemas are
//! pinned where their own rules land (REG-1.86 (h)).

use std::fmt::Write as _;

use serde_json::Value;
use skep_address::{validate, Address, Nat, Tumbler};

use crate::rows::Kind;

/// The most bytes a registry record body may carry, `sig` included, a body
/// past it refused ([`ParseRefusal::PastCap`]) before any parse — 16 KiB, an
/// interim pin confirmed at the registry's review round: a `sig` under
/// `mldsa65-ed25519` is 6,746 bytes of hex on its own, so a signed binding
/// is near seven kilobytes and a signed endpoint with a long list of
/// origins stays under this with room. The cap counts every byte, `sig`
/// included: a body of exactly 16 KiB is a record where it is canonical,
/// and one byte more is no record of either kind.
///
/// WHAT IT BOUNDS UNDER ATTACK, measured on a release build (Apple M1 Max):
/// the tree `serde_json` builds before the first schema check — at worst
/// some 125 times the body, a chain of one-member objects holding a
/// 632-byte B-tree leaf per five bytes, 2 MB at this cap — and the decimal
/// conversions of an address member, superlinear in one component's
/// digits: [`parse`] reads a component once and renders it twice, and a
/// verifier's [`Record::canonical_sigless`] renders it a third time, each
/// doubling of the digits multiplying a read by four (num-bigint's decimal
/// read is QUADRATIC) and a rendering by under three. One component filling
/// this cap, 16,352 digits, costs [`parse`] 1.1 ms and the verifier 0.45 ms
/// more, where a `sig` filling it costs [`parse`] 0.04 ms. A reader that
/// parses under a lock holds it that long per body — the daemon does, under
/// its serialization lock at a declared `insert` (skepd's
/// `declared_record_atom`), before the write's `attest` is asked for — so
/// the cap prices that lock: at the credential records' 128 KiB the same
/// three conversions cost 34 ms, some thirty times this cap's.
pub const MAX_REGISTRY_RECORD_BYTES: usize = 16 * 1024;

/// The two kinds whose bodies this crate parses — the kind the caller names
/// for a parse, read off the link's type slot (REG-1.86 (a)) and never off
/// the body: the body's own `type` member is what [`parse`] holds AGAINST
/// the kind named, so nothing here maps a `type` string to a kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BodyKind {
    Binding,
    Endpoint,
}

impl BodyKind {
    /// The `type` member's string (REG-1.86 (a)), read off the kind's own
    /// row in the table ([`crate::Row::type_value`]) — what [`encode`]
    /// writes and [`parse`] holds the member to, so the table's column is
    /// the one spelling and the vector set, pinning the bytes, pins it.
    fn type_value(self) -> &'static str {
        let kind = match self {
            BodyKind::Binding => Kind::Binding,
            BodyKind::Endpoint => Kind::Endpoint,
        };
        kind.row().type_value.expect("the binding's and the endpoint's rows carry a body")
    }
}

/// THE BINDING's body (REG-1.86's table; REG-2.19): the prefix, written in
/// address form, and `replaces`, the link's address of the binding this one
/// replaces at that prefix, absent on an allocation — each the [`Address`]
/// its member spells. The prefix is what REG-2.19 calls the binding's "one
/// non-address term": the one term no slot of the link carries, written in
/// address form all the same; the account the binding binds it to rides the
/// link's target and is no member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub prefix: Address,
    pub replaces: Option<Address>,
}

/// THE ENDPOINT's body (REG-1.86's table; REG-1.9, REG-1.10): the org's
/// [`Origins`], and `replaces`, the link's address of the endpoint deposit
/// this one replaces in the org's doc 1, absent on the org's first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub origins: Origins,
    pub replaces: Option<Address>,
}

/// AN ENDPOINT's ORIGINS (REG-1.9): the org's ordered list, AT LEAST ONE
/// entry, the order load-bearing at the resolver's walk. Never empty: a list
/// of no origin is no value of this type, so `[]` — which no reader holds
/// ([`ParseRefusal::EmptyOrigins`]) — is a body no caller can build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origins(Vec<String>);

impl Origins {
    /// The origins `origins` in their order — `None` where there are none.
    pub fn new(origins: Vec<String>) -> Option<Origins> {
        (!origins.is_empty()).then_some(Origins(origins))
    }

    /// The origins in the org's order.
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    /// The origins in the org's order, as the list they are.
    pub fn into_vec(self) -> Vec<String> {
        self.0
    }

    /// Borrowed origins in the org's order — the iterator `&Origins` walks.
    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.0.iter()
    }
}

impl IntoIterator for Origins {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Origins {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
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
    pub fn replaces(&self) -> Option<&Address> {
        match self {
            Body::Binding(b) => b.replaces.as_ref(),
            Body::Endpoint(e) => e.replaces.as_ref(),
        }
    }
}

/// A parsed record: the body and the `sig` member's string as it stands —
/// present or absent, the empty string included, which is a `sig` and never
/// `None`. What a verifier reads off a committed atom: `sig` the signature
/// under trial, and [`Record::canonical_sigless`] the body its `record`
/// frame carries — the frame, not these bytes alone, being what the
/// signature was made over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub body: Body,
    pub sig: Option<String>,
}

impl Record {
    /// The sig-less canonical projection (REG-1.86 (e)) — [`encode`] of the
    /// body with no `sig` — the bytes a record-grade signature ranges over,
    /// framed as the `record` grammar's row (5), skep-identity's
    /// `RecordRows::sigless_canonical_record`.
    pub fn canonical_sigless(&self) -> String {
        encode(&self.body, None)
    }
}

/// A body member beside `type` (REG-1.86's table), by the one name a body
/// spells it under: the name [`parse`] reads the member by, [`encode`]
/// writes it under, and a refusal names — `type` aside, which opens every
/// body and whose every fault is [`ParseRefusal::WrongType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Member {
    /// `prefix` — the binding's own member.
    Prefix,
    /// `origins` — the endpoint's own member.
    Origins,
    /// `replaces` — the link's address of the record this one replaces.
    Replaces,
    /// `sig` — the signature, where the record is signed.
    Sig,
}

impl Member {
    /// The member's name as a body spells it: what [`parse`] reads the
    /// member by, what [`encode`] writes it under, and the tail of its
    /// refusal's token.
    pub fn name(self) -> &'static str {
        match self {
            Member::Prefix => "prefix",
            Member::Origins => "origins",
            Member::Replaces => "replaces",
            Member::Sig => "sig",
        }
    }
}

/// Why bytes are no record of the kind named — each its own cause, joined to
/// the daemon's refusal token by [`ParseRefusal::token`] — listed in the order of
/// [`parse`]'s stages, the members' causes answered member by member in the
/// order `parse` states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseRefusal {
    /// Past [`MAX_REGISTRY_RECORD_BYTES`]: parsed by no reader at all.
    PastCap,
    /// The bytes are no UTF-8 text.
    NotUtf8,
    /// The text is no JSON value — a trailing non-whitespace byte included —
    /// or one [`parse`]'s value stage declines to read: a value nested deeper
    /// than it reads, a number too large for a 64-bit float, an escaped
    /// unpaired surrogate, a byte-order mark ahead of the value.
    NotJson,
    /// A JSON value that is no object.
    NotAnObject,
    /// A JSON number somewhere in the value the parse read (REG-1.86 (d)):
    /// the whole value's range, tested before any member is read. A number
    /// only in an occurrence the value stage did not keep — the earlier of a
    /// member spelled twice — is answered [`ParseRefusal::NotCanonical`], and
    /// one too large for a 64-bit float, which the value stage reads as no
    /// value at all, [`ParseRefusal::NotJson`].
    Number,
    /// The `type` member is absent, no string, or not the string of the
    /// kind the caller named: a record of that kind it is not (REG-1.86 (a)).
    WrongType,
    /// A member beside the row's own, `replaces` and `sig` ("NOTHING ELSE").
    UnknownMember,
    /// A member the row requires is absent: `prefix` or `origins`.
    MissingMember(Member),
    /// A member that must be a string is not: `prefix`, `replaces`, `sig`.
    NotAString(Member),
    /// A member that must parse as an address in dotted decimal does not —
    /// `prefix`, `replaces` — the one spelling of that address included
    /// (no zero-padded component, no sign, every component a decimal
    /// natural, the whole T4-valid).
    NotAnAddress(Member),
    /// `origins` is no array of strings.
    OriginsNotStrings,
    /// `origins` is empty: "AT LEAST ONE entry", and `[]` is a body no
    /// reader holds.
    EmptyOrigins,
    /// The members each pass and the bytes are still not the canonical
    /// re-encoding of what they spell: whitespace outside strings, between
    /// the tokens or around the object; another member order; a member twice
    /// (the occurrence the value stage kept passing); a non-shortest escape.
    /// Whitespace is the one thing outside the object the value stage reads
    /// past: any other byte after the closing brace is
    /// [`ParseRefusal::NotJson`].
    NotCanonical,
}

impl ParseRefusal {
    /// The machine token: the cause's own name, a member name joined after
    /// a colon where the cause names one.
    pub fn token(&self) -> String {
        match self {
            ParseRefusal::PastCap => "past_cap".into(),
            ParseRefusal::NotUtf8 => "not_utf8".into(),
            ParseRefusal::NotJson => "not_json".into(),
            ParseRefusal::NotAnObject => "not_an_object".into(),
            ParseRefusal::Number => "number".into(),
            ParseRefusal::WrongType => "wrong_type".into(),
            ParseRefusal::UnknownMember => "unknown_member".into(),
            ParseRefusal::MissingMember(m) => format!("missing_member:{}", m.name()),
            ParseRefusal::NotAString(m) => format!("not_a_string:{}", m.name()),
            ParseRefusal::NotAnAddress(m) => format!("not_an_address:{}", m.name()),
            ParseRefusal::OriginsNotStrings => "origins_not_strings".into(),
            ParseRefusal::EmptyOrigins => "empty_origins".into(),
            ParseRefusal::NotCanonical => "not_canonical".into(),
        }
    }
}

impl std::fmt::Display for ParseRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.token())
    }
}

impl std::error::Error for ParseRefusal {}

/// THE ONE PARSER: the record `bytes` spell under the kind the caller names,
/// under the canonical rule — a record is answered only where `bytes ==
/// encode(parse(bytes))` — or why they are none. Total over any bytes: no
/// panic, and no tree past the cap.
///
/// WHAT A RECORD PROMISES, so its reader checks none of it again: it is of
/// THE KIND NAMED — `record.body.kind() == kind`, a [`Body::Binding`] under
/// [`BodyKind::Binding`] and a [`Body::Endpoint`] under
/// [`BodyKind::Endpoint`], so a caller that named the kind meets no other
/// variant; `encode(&record.body, record.sig.as_deref())` is `bytes`, byte
/// for byte; and `bytes` are at most [`MAX_REGISTRY_RECORD_BYTES`]. So bytes
/// that are a record under one kind are `wrong_type` under the other: a
/// record under one kind at most.
///
/// THE STAGES, the first to fault naming the refusal ([`ParseRefusal`]): the cap;
/// the text; the value; the object; the number scan; `type`; the member set;
/// then each member's form, one member at a time — `replaces`, then `sig`,
/// then the row's own (`prefix` or `origins`), a required member's absence
/// answered at its own turn; then the canonical compare. So a body with two
/// faults answers the earlier stage's: `{"type":"binding","tier":"root"}`
/// is `unknown_member`, and `{"type":"binding","replaces":"x"}`
/// `not_an_address:replaces`.
///
/// THE VALUE STAGE is `serde_json`'s, and where RFC 8259 leaves a parser a
/// choice (§4, §6, §8.1, §8.2, §9) this parser adopts serde_json's as its
/// own. A member spelled twice is read at its LAST occurrence, so a fault in
/// an earlier one — a number, a wrong `type` — surfaces as `not_canonical`.
/// And serde_json reads no value — `not_json` — from four texts RFC 8259
/// lets a parser refuse: a value nested more than 127 objects and arrays
/// deep, the body's own object counted; a number too large for a 64-bit
/// float (`1e400` — one that rounds to zero, `1e-400`, is read, and is
/// `number`); an escaped unpaired surrogate (`"\ud800"`); and a byte-order
/// mark ahead of the value. Past those choices `not_json` is RFC 8259's
/// grammar, and every other refusal is this schema's.
pub fn parse(kind: BodyKind, bytes: &[u8]) -> Result<Record, ParseRefusal> {
    if bytes.len() > MAX_REGISTRY_RECORD_BYTES {
        return Err(ParseRefusal::PastCap);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ParseRefusal::NotUtf8)?;
    let value: Value = serde_json::from_str(text).map_err(|_| ParseRefusal::NotJson)?;
    let Value::Object(mut object) = value else { return Err(ParseRefusal::NotAnObject) };
    if object.values().any(holds_a_number) {
        return Err(ParseRefusal::Number);
    }
    if object.get("type").and_then(Value::as_str) != Some(kind.type_value()) {
        return Err(ParseRefusal::WrongType);
    }
    let own = match kind {
        BodyKind::Binding => Member::Prefix,
        BodyKind::Endpoint => Member::Origins,
    };
    let known = [own, Member::Replaces, Member::Sig];
    if object.keys().any(|k| k != "type" && !known.iter().any(|m| m.name() == k)) {
        return Err(ParseRefusal::UnknownMember);
    }
    // The strings the record keeps — `sig` and the origins — are moved out of
    // the tree the parse owns; an address member is read where it stands.
    let replaces = address_member(&object, Member::Replaces)?;
    let sig = match object.remove(Member::Sig.name()) {
        None => None,
        Some(Value::String(s)) => Some(s),
        Some(_) => return Err(ParseRefusal::NotAString(Member::Sig)),
    };
    let body = match kind {
        BodyKind::Binding => {
            let prefix = address_member(&object, Member::Prefix)?
                .ok_or(ParseRefusal::MissingMember(Member::Prefix))?;
            Body::Binding(Binding { prefix, replaces })
        }
        BodyKind::Endpoint => {
            let origins = object
                .remove(Member::Origins.name())
                .ok_or(ParseRefusal::MissingMember(Member::Origins))?;
            let Value::Array(origins) = origins else {
                return Err(ParseRefusal::OriginsNotStrings);
            };
            let origins = origins
                .into_iter()
                .map(|o| match o {
                    Value::String(s) => Ok(s),
                    _ => Err(ParseRefusal::OriginsNotStrings),
                })
                .collect::<Result<_, _>>()?;
            let origins = Origins::new(origins).ok_or(ParseRefusal::EmptyOrigins)?;
            Body::Endpoint(Endpoint { origins, replaces })
        }
    };
    // THE ADMISSION SENTENCE: admit only where the input is the canonical
    // re-encoding of what it spells — by the public encoder itself, the
    // function a signer composes with, `sig` included.
    if encode(&body, sig.as_deref()) != text {
        return Err(ParseRefusal::NotCanonical);
    }
    Ok(Record { body, sig })
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

/// An address member: the [`Address`] its string spells in its one
/// spelling ([`address_of`]), `None` where the body carries no such member.
/// Whether that absence is a fault is the caller's, as REG-1.86's table
/// makes it: `prefix` is required, `replaces` is not.
fn address_member(
    object: &serde_json::Map<String, Value>,
    member: Member,
) -> Result<Option<Address>, ParseRefusal> {
    match object.get(member.name()) {
        None => Ok(None),
        Some(Value::String(s)) => address_of(s).map(Some).ok_or(ParseRefusal::NotAnAddress(member)),
        Some(_) => Err(ParseRefusal::NotAString(member)),
    }
}

/// The address `s` spells in dotted decimal, where `s` is that address's
/// ONE spelling — its own rendering, the one [`encode`] writes an address
/// member as — else `None`. The rendering compare is the whole test: a
/// component is read by `Nat`'s parse, which admits a sign, `_` separators
/// and zero padding, and a rendering writes none of them; T4 validity is
/// `validate`'s.
fn address_of(s: &str) -> Option<Address> {
    let comps: Option<Vec<Nat>> = s.split('.').map(|c| c.parse::<Nat>().ok()).collect();
    let tumbler = Tumbler::new(comps?).ok()?;
    validate(tumbler).ok().filter(|address| address.to_string() == s)
}

/// THE CANONICAL FORM — the one byte string a body has, with its `sig` where
/// one is given: what a signer composes (with `None`, then with the `sig` it
/// made), what a verifier re-spells, and what [`parse`] holds its input to.
///
/// TOTAL, AND IT MEASURES NOTHING: every body encodes, with any `sig`, and
/// the result is a record at [`parse`] — under `body.kind()`, of that body
/// and that `sig` — exactly where it is at most [`MAX_REGISTRY_RECORD_BYTES`];
/// one byte past, it is `past_cap`. The measure is the composer's, taken on
/// the SIGNED bytes before they are deposited: the `sig` counts inside the
/// cap (the cap's doc prices a signed body), so a body whose sig-less form
/// is far under the cap can be past it signed.
pub fn encode(body: &Body, sig: Option<&str>) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("{\"type\":\"");
    out.push_str(body.kind().type_value());
    out.push('"');
    match body {
        Body::Binding(b) => {
            push_member_opening(Member::Prefix, &mut out);
            escape_json_string(&b.prefix.to_string(), &mut out);
        }
        Body::Endpoint(e) => {
            push_member_opening(Member::Origins, &mut out);
            out.push('[');
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
        push_member_opening(Member::Replaces, &mut out);
        escape_json_string(&replaces.to_string(), &mut out);
    }
    if let Some(sig) = sig {
        push_member_opening(Member::Sig, &mut out);
        escape_json_string(sig, &mut out);
    }
    out.push('}');
    out
}

/// A member's opening in the canonical form (REG-1.86 (h)), `,"<name>":` —
/// the comma ahead of it and its name as [`Member::name`] spells it, the
/// name [`parse`] reads the member by — so the two sides of the canonical
/// rule spell every member alike.
fn push_member_opening(member: Member, out: &mut String) {
    out.push_str(",\"");
    out.push_str(member.name());
    out.push_str("\":");
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

    fn address(s: &str) -> Address {
        address_of(s).expect("an address in its one spelling")
    }

    fn binding(prefix: &str, replaces: Option<&str>) -> Body {
        Body::Binding(Binding { prefix: address(prefix), replaces: replaces.map(address) })
    }

    fn origins(list: &[&str]) -> Origins {
        Origins::new(list.iter().map(|o| o.to_string()).collect()).expect("at least one origin")
    }

    /// The canonical rule read from both sides: a body's encoding parses to
    /// itself, with and without a `sig`, and the parse's sig-less projection
    /// is the encoding with none.
    #[test]
    fn encode_then_parse_is_a_fixpoint() {
        let body = Body::Endpoint(Endpoint {
            origins: origins(&["https://acme.example", "http://x.onion"]),
            replaces: Some(address("1.0.2.0.1.0.2.1")),
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
        let body =
            Body::Endpoint(Endpoint { origins: origins(&["a\"b\\c\n\u{1}/é"]), replaces: None });
        assert_eq!(
            encode(&body, None),
            "{\"type\":\"endpoint\",\"origins\":[\"a\\\"b\\\\c\\n\\u0001/é\"]}"
        );
        let longer = "{\"type\":\"endpoint\",\"origins\":[\"a\\\"b\\\\c\\n\\u0001\\/é\"]}";
        assert_eq!(parse(BodyKind::Endpoint, longer.as_bytes()), Err(ParseRefusal::NotCanonical));
    }

    /// The address form is one spelling: a sign, a separator, a zero-padded
    /// component, an empty component and a T4-invalid tumbler are each
    /// refused.
    #[test]
    fn the_address_form_is_one_spelling() {
        for ok in ["1", "1.5", "1.0.1.0.1.0.2.3", "1.1.0.1"] {
            assert!(address_of(ok).is_some(), "{ok}");
        }
        for bad in ["", "+1.5", "1_0.5", "01.5", "1..5", "1.5.", "1.5.0", "a", "1.5 ", "1.-5"] {
            assert!(address_of(bad).is_none(), "{bad}");
        }
    }

    /// THE PARSE READS A SPELLING, NEVER WHICH FORM — LOCAL OR GLOBAL — IT IS
    /// WRITTEN IN (REG-1.86 (c), (f)): Legal's prefix in its board's local
    /// form, `1.3`, and in the global form, `1.5.3`, are each a binding of the
    /// address it spells — which form a member takes is its writer's to hold,
    /// and no parse can see it.
    #[test]
    fn the_parse_cannot_tell_a_local_form_from_a_global_one() {
        for prefix in ["1.3", "1.5.3"] {
            let text = format!(r#"{{"type":"binding","prefix":"{prefix}"}}"#);
            let record = parse(BodyKind::Binding, text.as_bytes()).expect("a binding");
            assert_eq!(record.body, binding(prefix, None), "{prefix}");
        }
    }

    /// AN ADDRESS MEMBER IS THE ADDRESS IT SPELLS, at any size the cap
    /// admits (wire.md §Value encodings: a component is one decimal
    /// natural): a component past a machine word, one of 4,097 digits —
    /// past the board's wire cap on a component, which a record's own cap
    /// bounds instead — and one of 16,352, the body exactly the cap, which
    /// [`MAX_REGISTRY_RECORD_BYTES`] prices: each reads as the address whose
    /// rendering is the member, and the body re-encodes byte for byte.
    #[test]
    fn an_address_member_is_the_address_it_spells_at_any_size() {
        let filling = format!("1.{}", "9".repeat(16_352));
        let at_cap = format!(r#"{{"type":"binding","prefix":"{filling}"}}"#);
        assert_eq!(at_cap.len(), MAX_REGISTRY_RECORD_BYTES, "the priced body fills the cap");
        let prefixes =
            ["1.18446744073709551616".to_owned(), format!("1.{}", "9".repeat(4097)), filling];
        for prefix in prefixes {
            let text = format!(r#"{{"type":"binding","prefix":"{prefix}"}}"#);
            let record = parse(BodyKind::Binding, text.as_bytes()).expect("canonical");
            let Body::Binding(b) = &record.body else { panic!("a binding") };
            assert_eq!(b.prefix.to_string(), prefix);
            assert_eq!(encode(&record.body, None), text);
        }
    }

    /// EVERY BODY A CALLER CAN BUILD IS A RECORD, at bodies a hand chose:
    /// what the parse checks, the types carry — an address member an
    /// `Address`, the origins one or more — so these bodies, their strings
    /// holding every C0 control, a quote, a backslash and text past ASCII,
    /// each with each of three `sig`s, encode to bytes the parse admits as
    /// that body; and no `Origins` is empty. The law over bodies no hand
    /// chose is the integration suite's (`tests/it/body/laws.rs`).
    #[test]
    fn every_body_a_caller_builds_encodes_to_a_record() {
        assert_eq!(Origins::new(Vec::new()), None);
        let controls: String = (0u8..0x20).map(char::from).collect();
        let bodies = [
            binding("1", None),
            binding("1.18446744073709551616", Some("1.0.1.0.1.0.2.18446744073709551616")),
            Body::Endpoint(Endpoint {
                origins: origins(&[&controls, "\"\\/é\u{7f}\u{2028}", ""]),
                replaces: Some(address("1.0.2.0.1.0.2.1")),
            }),
        ];
        for body in bodies {
            for sig in [None, Some(""), Some("\u{0}\"ab")] {
                let record = parse(body.kind(), encode(&body, sig).as_bytes()).expect("a record");
                assert_eq!((&record.body, record.sig.as_deref()), (&body, sig));
            }
        }
    }

    /// The origins walk as the collection they are, in the org's order and
    /// whole, a repeated origin two entries: by reference, as `for origin in
    /// &origins` and `iter` do, by value, and whole, as `as_slice` and
    /// `into_vec` hand them — `into_vec` the list the resolver walks.
    #[test]
    fn origins_walk_in_the_orgs_order() {
        let order = ["https://b.example", "http://a.onion", "http://a.onion", "https://a.example"];
        let list = origins(&order);
        let mut walked = Vec::new();
        for origin in &list {
            walked.push(origin.as_str());
        }
        assert_eq!(walked, order);
        assert!(list.iter().map(String::as_str).eq(order));
        assert_eq!(list.as_slice(), order);
        assert_eq!(list.clone().into_vec(), order);
        assert_eq!(list.into_iter().collect::<Vec<String>>(), order);
    }

    /// The cap bounds the parse, never a record: a body one byte past it is
    /// refused before any tree is built, a binding signed under
    /// `mldsa65-ed25519` — its `sig` 6,746 hex characters — is well under
    /// it, and the `sig` counts inside it: a binding signed up to exactly the
    /// cap is a record, and one `sig` byte more — which `encode`, measuring
    /// nothing, writes whole — is past it.
    #[test]
    fn the_cap_bounds_the_parse() {
        assert_eq!(MAX_REGISTRY_RECORD_BYTES, 16_384);
        let signed = encode(&binding("1.5", None), Some(&"ab".repeat(3373)));
        assert!(signed.len() < MAX_REGISTRY_RECORD_BYTES / 2, "{}", signed.len());
        assert!(parse(BodyKind::Binding, signed.as_bytes()).is_ok());
        let mut padded = b"{".to_vec();
        padded.resize(MAX_REGISTRY_RECORD_BYTES + 1, b' ');
        assert_eq!(parse(BodyKind::Binding, &padded), Err(ParseRefusal::PastCap));
        padded.truncate(MAX_REGISTRY_RECORD_BYTES);
        assert_eq!(parse(BodyKind::Binding, &padded), Err(ParseRefusal::NotJson), "at the cap: parsed, and no JSON");
        let around_the_sig = encode(&binding("1.5", None), Some("")).len();
        let sig = "a".repeat(MAX_REGISTRY_RECORD_BYTES - around_the_sig);
        let at_cap = encode(&binding("1.5", None), Some(&sig));
        assert_eq!(at_cap.len(), MAX_REGISTRY_RECORD_BYTES);
        let record = parse(BodyKind::Binding, at_cap.as_bytes()).expect("a record at the cap");
        assert_eq!(record.sig.as_deref(), Some(sig.as_str()));
        let one_past = encode(&binding("1.5", None), Some(&format!("{sig}a")));
        assert_eq!(one_past.len(), MAX_REGISTRY_RECORD_BYTES + 1, "encode measures nothing");
        assert_eq!(parse(BodyKind::Binding, one_past.as_bytes()), Err(ParseRefusal::PastCap));
    }
}
