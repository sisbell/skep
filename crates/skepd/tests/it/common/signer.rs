//! THE TEST SIGNER (signed ops; the placement investigation §4.3) — the
//! FRONTEND's stand-in: a token → (principal, seed) registry the two
//! session-opening helpers fill, and the composition of the ENTRY frame from
//! the frame a suite is about to post — `board` read off `H.1`, `account` off
//! `principal_prefix`, `doc` and `body` per op cell of the ten: the three
//! mints' EMPTY body over the parent account; a link write's slots AS THE
//! STORE WILL HOLD THEM — an address-form slot spelled as its unit spans, a
//! V-spec slot RESOLVED through the wire's own `image` read over its source
//! before signing (the read that answers a V-span's I-extents; see
//! [`resolve_specs`]); an `edit_link`'s pair of homes and its original's
//! unit span; a `publish`'s body in the ADDRESS FORM (l6-A4): the runs the
//! commit copies in by their values, read back over the wire from their
//! origins, its windows by address, and its base — signed by the seed's
//! hybrid key and attached as the frame's top-level `attest`.

use std::num::NonZeroU64;
use std::sync::{LazyLock, PoisonError};

// The frame's own unit span, named ahead of the glob so it shadows the
// suite's JSON helper of the same name.
use skep_identity::unit_span;

use super::*;

/// A process-wide map behind a lock, built on first use.
type Registry<K, V> = LazyLock<Mutex<HashMap<K, V>>>;

/// Token → (principal, seed): the sessions the suites opened with a seed
/// carrier. Process-wide, keyed by the token alone (tokens are 128-bit
/// random, so two daemons in one process never collide).
static SIGNERS: Registry<String, (u64, [u8; 32])> = LazyLock::new(Default::default);

/// Port → the board term, `H.1`'s pair, read once per board: `H.1` is pinned
/// forever, so a board's first read is its last. Keyed by the PORT a board
/// answers at, which outlives the board — so every spawn here forgets the
/// port it binds ([`forget_port`]) before a pair is read off it.
static BOARD_TERMS: Registry<u16, BoardTerm> = LazyLock::new(Default::default);

/// (port, principal) → the account's local address, read once per board —
/// forgotten with the port as [`BOARD_TERMS`] is.
static ACCOUNTS: Registry<(u16, u64), String> = LazyLock::new(Default::default);

/// A daemon now answers at `port`, so whatever [`BOARD_TERMS`] and [`ACCOUNTS`]
/// hold for that port was ANOTHER board's: ports recycle across the daemons
/// one test process serves ([`spawn_under`]'s note), and `H.1`'s pair is one
/// board's for ever, not one port's. Kept, a stale pair signs every attested
/// write over another board's chain and answers a fresh board's "no `H.1`
/// yet" with the old board's. Called by every spawn here as the port is bound.
pub(super) fn forget_port(port: u16) {
    with_map(&BOARD_TERMS, |m| {
        m.remove(&port);
    });
    with_map(&ACCOUNTS, |m| m.retain(|(p, _), _| *p != port));
}

fn with_map<K, V, R>(cell: &Registry<K, V>, f: impl FnOnce(&mut HashMap<K, V>) -> R) -> R {
    f(&mut *cell.lock().unwrap_or_else(PoisonError::into_inner))
}

/// Register `token` as a session `principal` opened with the seed carrier
/// `sk`: every frame [`op`] posts under it whose op is in the checked set is
/// signed by that seed's hybrid key.
pub fn register_signer(token: &str, principal: u64, sk: &SigningKey) {
    let seed = seed_of(sk);
    with_map(&SIGNERS, |m| {
        m.insert(token.to_string(), (principal, seed));
    });
}

/// The signer a token names, if a seed carrier opened it.
pub fn signer_of(token: &str) -> Option<(u64, [u8; 32])> {
    with_map(&SIGNERS, |m| m.get(token).copied())
}

/// `H.1`'s address — the first member of the head document's chain.
pub const HEAD_MEMBER_1: &str = "1.1.0.1.0.2.1";

/// THE BOARD TERM: `H.1`'s `(position, chain)` pair, read off the wire by
/// `retrieve_v` on the pinned member (guest-readable) and parsed off the
/// `skep-head` record; `None` while the board has no `H.1`.
pub fn board_term(port: u16) -> Option<BoardTerm> {
    if let Some(term) = with_map(&BOARD_TERMS, |m| m.get(&port).copied()) {
        return Some(term);
    }
    let v = op_as_written(port, None, &retrieve_frame(HEAD_MEMBER_1, 1, 1));
    if v["resp"].as_str() != Some("delivery") {
        return None;
    }
    let text = v["items"].as_array()?.first()?["atom"].as_str()?.to_string();
    let rec: Value = serde_json::from_str(&text).ok()?;
    let log_position = rec["position"].as_u64()?;
    let chain_hex = rec["chain"].as_str()?;
    let chain: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&chain_hex[2 * i..2 * i + 2], 16).ok())
        .collect::<Option<_>>()?;
    let term = BoardTerm { log_position, chain: <[u8; 32]>::try_from(chain).ok()? };
    with_map(&BOARD_TERMS, |m| {
        m.insert(port, term);
    });
    Some(term)
}

/// The account a principal acts as, in the board's local form — the frame's
/// `account` term (`principal_prefix`, read once per principal per board).
pub fn account_of(port: u16, token: &str, principal: u64) -> Option<String> {
    if let Some(a) = with_map(&ACCOUNTS, |m| m.get(&(port, principal)).cloned()) {
        return Some(a);
    }
    let v = op_as_written(
        port,
        Some(token),
        &format!(r#"{{"op":"principal_prefix","principal":{principal}}}"#),
    );
    let addr = v["addr"].as_str()?.to_string();
    with_map(&ACCOUNTS, |m| {
        m.insert((port, principal), addr.clone());
    });
    Some(addr)
}

fn parse_addr(s: &str) -> Option<Address> {
    let comps: Option<Vec<Nat>> = s.split('.').map(|c| c.parse::<u64>().ok().map(Nat::from)).collect();
    validate(Tumbler::new(comps?).ok()?).ok()
}

fn parse_tumbler(s: &str) -> Option<Tumbler> {
    let comps: Option<Vec<Nat>> = s.split('.').map(|c| c.parse::<u64>().ok().map(Nat::from)).collect();
    Tumbler::new(comps?).ok()
}

/// A span as the wire spells one — `{"start": <tumbler>, "width": <tumbler>}`.
fn parse_span(v: &Value) -> Option<Span> {
    let start = parse_tumbler(v["start"].as_str()?)?;
    let width = parse_tumbler(v["width"].as_str()?)?;
    Span::new(start, width).ok()
}

/// A stored content extent from a run as `image` answers it — its I-start and
/// its width in positions — the span a run's `iextent` spells: the start's
/// own tumbler, and a width of zeros at every component but the last, which
/// holds the count.
fn extent_span(i_start: &str, width: u64) -> Option<Span> {
    let start = parse_tumbler(i_start)?;
    let mut comps = vec![Nat::from(0u64); start.len()];
    *comps.last_mut()? = Nat::from(width);
    Span::new(start, Tumbler::new(comps).ok()?).ok()
}

/// M5's `trunk_of` over the dotted spelling: a version member cut back to
/// its document — the components through the first past the second `0`
/// separator (node, then `0`, the account, then `0`, the document's first
/// component).
pub fn trunk_of_str(doc: &str) -> String {
    let comps: Vec<&str> = doc.split('.').collect();
    let mut zeros = comps.iter().enumerate().filter(|(_, c)| **c == "0").map(|(i, _)| i);
    let (Some(_first), Some(second)) = (zeros.next(), zeros.next()) else {
        return doc.to_string();
    };
    comps[..=(second + 1).min(comps.len() - 1)].join(".")
}

/// One `values` element's values, by the wire's write-form rule: a string
/// and `{"hex"}` mint one value per byte, `{"atom"}` and `{"atom_hex"}` one
/// composite value.
fn write_form_values(v: &Value, out: &mut Vec<Vec<u8>>) -> Option<()> {
    match v {
        Value::String(s) => out.extend(s.bytes().map(|b| vec![b])),
        Value::Object(m) => {
            if let Some(h) = m.get("hex").and_then(Value::as_str) {
                out.extend(unhex(h)?.into_iter().map(|b| vec![b]));
            } else if let Some(s) = m.get("atom").and_then(Value::as_str) {
                out.push(s.as_bytes().to_vec());
            } else if let Some(h) = m.get("atom_hex").and_then(Value::as_str) {
                out.push(unhex(h)?);
            } else {
                return None;
            }
        }
        _ => return None,
    }
    Some(())
}

/// One delivery item's values, by the read side's rule: `{"content"}` and
/// `{"hex"}` one value per byte, `{"atom"}`/`{"atom_hex"}` one; a `ref` or a
/// withheld run is no content the signer can hold.
fn delivery_item_values(v: &Value, out: &mut Vec<Vec<u8>>) -> Option<()> {
    let m = v.as_object()?;
    if let Some(s) = m.get("content").and_then(Value::as_str) {
        out.extend(s.bytes().map(|b| vec![b]));
    } else if let Some(h) = m.get("hex").and_then(Value::as_str) {
        out.extend(unhex(h)?.into_iter().map(|b| vec![b]));
    } else if let Some(s) = m.get("atom").and_then(Value::as_str) {
        out.push(s.as_bytes().to_vec());
    } else if let Some(h) = m.get("atom_hex").and_then(Value::as_str) {
        out.push(unhex(h)?);
    } else {
        return None;
    }
    Some(())
}

fn unhex(h: &str) -> Option<Vec<u8>> {
    if h.len() % 2 != 0 {
        return None;
    }
    (0..h.len() / 2).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok()).collect()
}

/// THE SIGNER'S RESOLVE — a V-spec slot's spans AS THE STORE WILL HOLD THEM,
/// read through the wire's own `image` answer over each spec's source: the
/// I-runs the region maps onto, each run's I-start and width spelled as the
/// run's extent, in the order the specs are given — the row the daemon
/// composes from M7's own resolution of the same specs over the base the
/// transaction opens on. `None` where a source cannot be read (a withheld
/// draft, an unregistered document): the signer composes no slot it cannot
/// read, as a frontend holding no grant could not, and the frame goes out as
/// written.
///
/// Two spellings a frontend cannot reach through `image` are stated and not
/// hidden: `image` answers a PUBLISHED source's head (head-float) where the
/// store resolves a slot against the address named, and it answers a run
/// placed twice by transclusion ONCE where the store keeps both; a spec over
/// either resolves to a row the daemon refuses `signature`. Every V-spec
/// slot the suites sign names a draft's own positions, where the two agree.
pub fn resolve_specs(port: u16, token: &str, specs: &[(Address, Span)]) -> Option<Vec<Span>> {
    let mut spans = Vec::new();
    for (source, span) in specs {
        let frame = json!({
            "op": "image",
            "d": source.to_string(),
            "region": [{"start": span.start().to_string(), "width": span.width().to_string()}],
        });
        let v = op_as_written(port, Some(token), &frame.to_string());
        if v["resp"].as_str() != Some("runs") {
            return None;
        }
        for (i_start, width) in runs_in(&v) {
            spans.push(extent_span(&i_start, width)?);
        }
    }
    Some(spans)
}

/// A V-spec array as the wire carries one — `[{"source": …, "span": …}, …]`.
fn parse_specs(specs: &[Value]) -> Option<Vec<(Address, Span)>> {
    specs
        .iter()
        .map(|s| {
            let source = parse_addr(s["source"].as_str()?)?;
            Some((source, parse_span(&s["span"])?))
        })
        .collect()
}

/// A link slot as the frame carries it — THE SLOT AS STORED: an address form
/// (`{"addrs": [...]}`) spelled as its unit spans, one per address; a V-spec
/// form — the bare array `make_link` and an `edit_link` successor's `from`
/// and `to` take, or the `{"resolve": [...]}` object its type slot takes —
/// resolved through [`resolve_specs`]. `None` where the slot is no slot, or
/// a source cannot be read.
fn signer_slot(port: u16, token: &str, v: &Value) -> Option<Vec<Span>> {
    match v {
        Value::Object(m) => {
            if let Some(addrs) = m.get("addrs").and_then(Value::as_array) {
                addrs.iter().map(|a| Some(unit_span(&parse_addr(a.as_str()?)?))).collect()
            } else if let Some(specs) = m.get("resolve").and_then(Value::as_array) {
                resolve_specs(port, token, &parse_specs(specs)?)
            } else {
                None
            }
        }
        Value::Array(specs) => resolve_specs(port, token, &parse_specs(specs)?),
        _ => None,
    }
}

/// One segment of a `publish` body as the signer composes it (the address
/// form, l6-A4), owned: a copied position's value, or a window's start and
/// width.
pub enum SignerSegment {
    Value(Vec<u8>),
    Window(Address, u64),
}

impl SignerSegment {
    pub fn as_shot(&self) -> ShotSegmentPiece<'_> {
        match self {
            SignerSegment::Value(v) => ShotSegmentPiece::Value(v),
            SignerSegment::Window(start, width) => ShotSegmentPiece::Window {
                start,
                width: NonZeroU64::new(*width)
                    .expect("a window the signer composes holds at least one position"),
            },
        }
    }
}

/// The values at every content I-address of `origin`, keyed by address, as
/// `token` reads them: the document's V→I image and its delivery read once,
/// the image inverted to place each I-address; `None` where the origin
/// cannot be read (a withheld source: the client cannot compose that body,
/// which is the design's own point). Every read here is UNJUDGED: a refusal
/// (an unregistered or a withheld origin) means the client cannot compose
/// this body, and the frame goes out as written.
fn origin_values(port: u16, token: &str, origin: &str) -> Option<HashMap<String, Vec<u8>>> {
    let set = op_as_written(port, Some(token), &spanset_frame(origin));
    if set["resp"].as_str() != Some("span_set") {
        return None;
    }
    let extent: u64 = set["set"]
        .as_array()?
        .iter()
        .find(|s| s["start"].as_str() == Some("1.1"))
        .and_then(|s| s["width"].as_str()?.strip_prefix("0.")?.parse().ok())
        .unwrap_or(0);
    let mut map = HashMap::new();
    if extent > 0 {
        let image = op_as_written(port, Some(token), &image_frame(origin, 1, extent));
        if image["resp"].as_str() != Some("runs") {
            return None;
        }
        let addrs = expand_runs(&runs_in(&image));
        let delivery = op_as_written(port, Some(token), &retrieve_frame(origin, 1, extent));
        if delivery["resp"].as_str() != Some("delivery") {
            return None;
        }
        let mut values = Vec::new();
        for item in delivery["items"].as_array()? {
            delivery_item_values(item, &mut values)?;
        }
        if values.len() != addrs.len() {
            return None;
        }
        for (a, v) in addrs.into_iter().zip(values) {
            map.insert(a, v);
        }
    }
    Some(map)
}

/// THE ADDRESS FORM of a `publish` frame's runs, as the commit will place
/// them (l6-A4; M5's `Shot::address_form`, restated over the wire's own
/// spellings): a run of the shot document's own I-space, or of the staging
/// draft's, is COPIED IN — its values in V-order, read back over the wire
/// from the document that MINTED the addresses (the I-address's own, as an
/// honest client that placed them knows it, never the stated `origin`, which
/// the store judges) or taken from `supplied`, in V-order, where the caller
/// holds them; any other run is a WINDOW by its address and width, two
/// I-adjacent windows in a row merged into one as the placement merges them.
/// `None` where a copied origin cannot be read.
pub fn publish_segments(
    port: u16,
    token: &str,
    frame: &Value,
    supplied: Option<&[&[u8]]>,
) -> Option<Vec<SignerSegment>> {
    let trunk = trunk_of_str(frame["doc"].as_str()?);
    let draft = frame.get("draft").and_then(Value::as_str).map(trunk_of_str);
    let mut per_origin: HashMap<String, HashMap<String, Vec<u8>>> = HashMap::new();
    let mut supplied = supplied.map(|values| values.iter());
    let mut out: Vec<SignerSegment> = Vec::new();
    for run in frame["runs"].as_array()? {
        let i_start = run["i_start"].as_str()?;
        let width: u64 = run["width"].as_str()?.parse().ok()?;
        if !i_start.contains(".0.1.") {
            return None;
        }
        let origin = origin_of(i_start);
        let origin_doc = trunk_of_str(&origin);
        let copied = origin_doc == trunk || draft.as_deref() == Some(origin_doc.as_str());
        if copied {
            let addrs = expand_runs(&[(i_start.to_string(), width)]);
            match supplied.as_mut() {
                Some(values) => {
                    for _ in addrs {
                        out.push(SignerSegment::Value(values.next()?.to_vec()));
                    }
                }
                None => {
                    if !per_origin.contains_key(&origin) {
                        per_origin.insert(origin.clone(), origin_values(port, token, &origin)?);
                    }
                    let map = &per_origin[&origin];
                    for a in addrs {
                        out.push(SignerSegment::Value(map.get(&a)?.clone()));
                    }
                }
            }
        } else {
            // A window — one with the window before it when I-adjacent: the
            // same content I-space, starting where the last one reaches.
            let (prefix, ordinal) = i_start.rsplit_once('.')?;
            let ordinal: u64 = ordinal.parse().ok()?;
            let merged = match out.last_mut() {
                Some(SignerSegment::Window(start, held)) => {
                    let spelled = start.to_string();
                    let (held_prefix, held_ordinal) = spelled.rsplit_once('.')?;
                    let held_ordinal: u64 = held_ordinal.parse().ok()?;
                    if held_prefix == prefix && held_ordinal + *held == ordinal {
                        *held += width;
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            };
            if !merged {
                out.push(SignerSegment::Window(parse_addr(i_start)?, width));
            }
        }
    }
    Some(out)
}

/// A `publish` frame's BASE as the body spells it (V; bu7-E2): the member
/// the frame's `base` names and the extent its `base_extent` counts —
/// `Some(None)` where the frame carries neither (the birth shape), `None`
/// where one is carried without the other or is no address or count.
fn base_of(frame: &Value) -> Option<Option<(Address, u64)>> {
    match (frame.get("base"), frame.get("base_extent")) {
        (None, None) => Some(None),
        (Some(member), Some(extent)) => {
            Some(Some((parse_addr(member.as_str()?)?, extent.as_str()?.parse().ok()?)))
        }
        _ => None,
    }
}

/// The ten op-kind tokens the checked set admits an `attest` on — the ones
/// [`entry_frame_for`] composes a frame for.
const CHECKED_SET: [&str; 10] = [
    "create_new_document",
    "fork",
    "version",
    "insert",
    "publish",
    "make_link",
    "emit",
    "nullify",
    "assert_sup",
    "edit_link",
];

/// The ENTRY frame for `frame` as `principal` would sign it on this board,
/// or `None` where a member cannot be composed (no `H.1` yet, an unreadable
/// copied origin or slot source, an op outside the ten). Every address the
/// frame names is PARSED before it is framed, so `entry_frame` spells the
/// address and not the string the frame happened to carry; every link slot
/// is composed AS THE STORE WILL HOLD IT ([`signer_slot`]).
pub fn entry_frame_for(port: u16, token: &str, principal: u64, frame: &Value) -> Option<Vec<u8>> {
    let op = frame["op"].as_str()?;
    let board = board_term(port)?;
    let account = parse_addr(&account_of(port, token, principal)?)?;
    let alg = SigAlgRow::of_tag(FIXTURE_TAG)?.token;
    let slot = |v: &Value| signer_slot(port, token, v);
    // THE PAIR'S ROW: the one op whose `doc` names two homes; every other
    // op's `doc` is one address.
    let mut pair: Option<(Address, Address)> = None;
    let (doc, body) = match op {
        // The three mints: the EMPTY body over the parent account — the
        // request's `account`, or the principal's own.
        "create_new_document" => (
            parse_addr(frame["account"].as_str()?)?,
            entry_body_empty(ContentFreeOp::CreateNewDocument),
        ),
        "fork" => (account.clone(), entry_body_empty(ContentFreeOp::Fork)),
        "version" => (account.clone(), entry_body_empty(ContentFreeOp::Version)),
        "insert" => {
            let doc = parse_addr(&trunk_of_str(frame["doc"].as_str()?))?;
            let declared = match frame.get("deposit").and_then(Value::as_str) {
                Some(ty) => Some(parse_addr(ty)?),
                None => None,
            };
            let mut values = Vec::new();
            for v in frame["values"].as_array()? {
                write_form_values(v, &mut values)?;
            }
            (doc, entry_body_insert(declared.as_ref(), values.iter().map(Vec::as_slice)))
        }
        "make_link" => {
            let (from, to, ty) = (slot(&frame["from"])?, slot(&frame["to"])?, slot(&frame["ty"])?);
            let slots = LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) };
            let body = match frame.get("replaces").and_then(Value::as_str) {
                Some(named) => entry_body_make_link_replacing(slots, &parse_addr(named)?),
                None => entry_body_make_link(slots),
            };
            (parse_addr(frame["home"].as_str()?)?, body)
        }
        "emit" => {
            let ty: Vec<Span> = frame["ty"].as_array()?.iter().map(parse_span).collect::<Option<_>>()?;
            let from = [unit_span(&parse_addr(frame["from"].as_str()?)?)];
            let to: Vec<Span> =
                frame["to"].as_array()?.iter().map(|a| Some(unit_span(&parse_addr(a.as_str()?)?))).collect::<Option<_>>()?;
            let slots = LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) };
            (parse_addr(frame["home"].as_str()?)?, entry_body_emit(slots))
        }
        "nullify" => {
            let home = parse_addr(frame["home"].as_str()?)?;
            let (from, to) = ([unit_span(&home)], [unit_span(&parse_addr(frame["target"].as_str()?)?)]);
            let ty = [unit_span(&parse_addr(T_RETRACTION)?)];
            let slots = LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) };
            (home, entry_body_nullify(slots))
        }
        "assert_sup" => {
            let from = [unit_span(&parse_addr(frame["old"].as_str()?)?)];
            let to = [unit_span(&parse_addr(frame["new"].as_str()?)?)];
            let ty = [unit_span(&parse_addr(T_SUPERSEDES)?)];
            let slots = LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) };
            (parse_addr(frame["home"].as_str()?)?, entry_body_assert_sup(slots))
        }
        "edit_link" => {
            let successor = &frame["successor"];
            let (from, to, ty) = (slot(&successor["from"])?, slot(&successor["to"])?, slot(&successor["ty"])?);
            let slots = LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) };
            let original = unit_span(&parse_addr(frame["original"].as_str()?)?);
            let (d_s, d_a) = (parse_addr(frame["d_s"].as_str()?)?, parse_addr(frame["d_a"].as_str()?)?);
            pair = Some((d_s.clone(), d_a));
            (d_s, entry_body_edit_link(slots, &original))
        }
        "publish" => {
            let segments = publish_segments(port, token, frame, None)?;
            let base = base_of(frame)?;
            let base = base.as_ref().map(|(member, extent)| ShotBase { member, extent: *extent });
            (
                parse_addr(&trunk_of_str(frame["doc"].as_str()?))?,
                entry_body_publish(segments.iter().map(SignerSegment::as_shot), base),
            )
        }
        _ => return None,
    };
    let term = match &pair {
        Some((d_s, d_a)) => DocTerm::Pair { d_s, d_a },
        None => DocTerm::One(&doc),
    };
    Some(entry_frame(alg, board, &account, term, &body))
}

/// The `attest` member carrying `sig` under the fixtures' tag
/// ([`FIXTURE_TAG`]): `{"alg": <that row's token>, "sig": <hex>}`.
pub fn attest_member(sig: &[u8]) -> Value {
    json!({"alg": SigAlgRow::of_tag(FIXTURE_TAG).expect("tag 1").token, "sig": hex(sig)})
}

/// `frame` with an `attest` member attached that verifies over no frame —
/// the fixtures' row at its width exactly, every byte zero: what a cell sends
/// where the check must reach its composition — (1) stands ahead of it, so
/// an unattested frame never does — and the answer must not turn on a
/// signature: the store's own refusal, which the check passes such a write
/// through to whatever it carries.
pub fn with_unverifiable_attest(frame: &str) -> String {
    let mut v: Value = serde_json::from_str(frame).expect("a JSON frame");
    let width = SigAlgRow::of_tag(FIXTURE_TAG).expect("tag 1").sig_len();
    v["attest"] = attest_member(&vec![0u8; width]);
    v.to_string()
}

// ── the record grade (signed ops, 2a) ───────────────────────────────────────
//
// A credential record's `sig` rides INSIDE its atom, made over the entry
// frame under the `record` grammar (the frame merge, fm-I): `alg` the signing
// key's token, `board` `H.1`'s pair, `account` the HOME's account, `doc` the
// home, and the body's five rows — the link's type address, its target
// address (none at a targetless kind), the `replaces` row EMPTY, the lineage
// row EMPTY, and the sig-less canonical record. The daemon composes the same
// bytes at the record's `make_link` from the stored atom and the link's
// slots, and so does a mirror from `find_links` and `retrieve`; what the
// signer needs beyond its own record is the board term, the home's account —
// read off the wire by ω, `effective_owner`, as the daemon reads it — and the
// link's type and target it is about to name.

/// The account a home document belongs to, in the board's local form — ω
/// over the home, read off the wire (`effective_owner`, AUTH-6.37) as the
/// daemon's own composer reads it; `None` where no registered prefix owns it.
pub fn home_account_of(port: u16, home: &str) -> Option<String> {
    effective_owner(port, None, home).map(|(prefix, _)| prefix)
}

/// THE RECORD FRAME a credential record's `sig` is made over, composed from
/// what the signer holds: `board` off `H.1`, `account` the home's by ω, `doc`
/// the home, the `record` body over `ty`, `to` and `canonical` — the sig-less
/// canonical record — with both optional rows EMPTY. `None` where the board
/// has no `H.1` yet or the home no owner.
pub fn record_frame_for(
    port: u16,
    alg: &str,
    home: &str,
    ty: &str,
    to: &[&str],
    canonical: &[u8],
) -> Option<Vec<u8>> {
    let board = board_term(port)?;
    let account = parse_addr(&home_account_of(port, home)?)?;
    let home = parse_addr(home)?;
    let ty = parse_addr(ty)?;
    let to: Vec<Address> = to.iter().map(|a| parse_addr(a)).collect::<Option<_>>()?;
    let body = entry_body_record(RecordRows {
        ty: &ty,
        to: &to,
        replaces: None,
        lineage_fork_point: None,
        sigless_canonical_record: canonical,
    });
    Some(entry_frame(alg, board, &account, DocTerm::One(&home), &body))
}

/// The record `entries` SIGNED at the record grade by `signer` for a deposit
/// homed in `home`, typed `ty`, naming `to` — the atom's TEXT: the canonical
/// record carrying, as its `sig`, the hybrid blob's hex over
/// [`record_frame_for`]'s frame under the signer's own token. `None` where the
/// frame cannot be composed (no `H.1`, an unowned home).
pub fn signed_record_text<T: RecordEntry>(
    port: u16,
    signer: &HybridSigner,
    home: &str,
    ty: &str,
    to: &[&str],
    entries: &[T],
) -> Option<String> {
    let alg = SigAlgRow::of_tag(signer.tag())?.token;
    let canonical = canonical_record(entries, None);
    let frame = record_frame_for(port, alg, home, ty, to, canonical.as_bytes())?;
    Some(canonical_record(entries, Some(&hex(&signer.sign(&frame)))))
}

/// A record ATOM (its JSON fragment, as [`json_atom`] spells one) RE-SIGNED
/// for the deposit its caller is about to make — homed in `home`, typed `ty`,
/// naming `to` — under the key that opened `token`'s session: the atom's text
/// is parsed by the kind `ty` names (the record grade's own parse,
/// `parse_record_value`), the entries re-encoded with the `sig` the frame's
/// signature makes. THE ATOM IS RETURNED AS GIVEN where nothing can be
/// signed: a bare or foreign token (no seed carrier opened it), a board with
/// no `H.1` yet (at or below the claim, where no record is judged, A5), a type
/// of no record-bearing kind, or a text no parser admits (a malformed record,
/// which the fold refuses ahead of any signature and which a cell sends on
/// purpose) — so every helper that lands a record can pass through here, and
/// only a record the daemon would judge is signed. Every address the frame
/// names is PARSED before it is framed, so a leading-zero spelling on the
/// wire signs its one address.
pub fn signed_atom(port: u16, token: &str, home: &str, ty: &str, to: &[&str], atom: &str) -> String {
    let Some((_, seed)) = signer_of(token) else {
        return atom.to_string();
    };
    let Ok(Value::String(text)) = serde_json::from_str::<Value>(atom) else {
        return atom.to_string();
    };
    let signer = HybridSigner::from_seed(FIXTURE_TAG, &seed).expect("tag 1");
    let signed = match ty {
        T_ENROLL => parse_record_value::<Enrollment>(text.as_bytes())
            .ok()
            .and_then(|v| signed_record_text(port, &signer, home, ty, to, &v.entries)),
        T_RETIRE => parse_record_value::<Fingerprint>(text.as_bytes())
            .ok()
            .and_then(|v| signed_record_text(port, &signer, home, ty, to, &v.entries)),
        _ => None,
    };
    signed.map_or_else(|| atom.to_string(), |text| json_atom(&text))
}

/// The VALUES at content ordinals `from ..` of `doc`, as `token` reads them —
/// one entry per position (a per-byte run one byte each, an atom whole).
pub fn values_of(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for item in delivery(port, token, doc, from, width).as_array().expect("items") {
        delivery_item_values(item, &mut out).expect("a content item");
    }
    out
}

/// [`op`] for a `publish` whose COPIED runs' VALUES the caller supplies — the
/// bytes it places, in V-order — signed over the body those values, the
/// frame's windows by address and its base extent make: for a shot whose
/// values the caller knows without reading them back over the wire, and for
/// the cells showing that a signature over values the caller may NOT read
/// decides nothing — a window is signed by address and never read, and a
/// copied run the daemon cannot read composes no body, so whatever is
/// attached, the store's own refusal answers, or the check's value-blind
/// `attestation_invalid:withheld`.
pub fn op_with_publish_values(port: u16, token: &str, frame: &str, values: &[&[u8]]) -> Value {
    let Some((principal, seed)) = signer_of(token) else {
        return op_as_written(port, Some(token), frame);
    };
    let mut v: Value = serde_json::from_str(frame).expect("a JSON frame");
    let (Some(board), Some(account)) = (board_term(port), account_of(port, token, principal)) else {
        return op_as_written(port, Some(token), frame);
    };
    let account = parse_addr(&account).expect("the daemon's own account prefix is an address");
    let alg = SigAlgRow::of_tag(FIXTURE_TAG).expect("tag 1").token;
    let doc = parse_addr(&trunk_of_str(v["doc"].as_str().expect("doc"))).expect("a document address");
    let segments = publish_segments(port, token, &v, Some(values))
        .expect("the frame's runs are content runs and the values supplied cover the copied ones");
    let base = base_of(&v).expect("a member and a count, or no base");
    let base = base.as_ref().map(|(member, extent)| ShotBase { member, extent: *extent });
    let body = entry_body_publish(segments.iter().map(SignerSegment::as_shot), base);
    let bytes = entry_frame(alg, board, &account, DocTerm::One(&doc), &body);
    let signer = HybridSigner::from_seed(FIXTURE_TAG, &seed).expect("tag 1");
    v["attest"] = attest_member(&signer.sign(&bytes));
    op_as_written(port, Some(token), &v.to_string())
}

/// [`op`]'s composition: the frame with its `attest` attached where the
/// token names a signer, the op is in the checked set and its entry frame
/// composes; the frame as written otherwise.
pub fn attach_attest(port: u16, token: &str, frame: &str) -> String {
    let Some((principal, seed)) = signer_of(token) else {
        return frame.to_string();
    };
    let Ok(mut v) = serde_json::from_str::<Value>(frame) else {
        return frame.to_string();
    };
    if !v["op"].as_str().is_some_and(|op| CHECKED_SET.contains(&op)) {
        return frame.to_string();
    }
    if v.get("attest").is_some() {
        return frame.to_string();
    }
    let Some(bytes) = entry_frame_for(port, token, principal, &v) else {
        return frame.to_string();
    };
    let signer = HybridSigner::from_seed(FIXTURE_TAG, &seed).expect("tag 1");
    let sig = signer.sign(&bytes);
    v["attest"] = attest_member(&sig);
    v.to_string()
}
