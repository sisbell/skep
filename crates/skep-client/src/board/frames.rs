//! The wire's frames, spelled once (wire.md §Operations).
//!
//! Every frame this crate sends through [`Board::op`](super::Board::op) is
//! built here. Every address is carried as the caller spells it; the daemon
//! parses leniently and this client composes canonically.

use serde_json::{json, Value};

/// The grants class type address.
///
/// wire.md §The read predicate: "`ty` the grants class
/// `1.1.0.1.0.1.0.3.90`". It is the type slot of every grant, of the record
/// that revokes one (PUB-5.13, PUB-5.15), and of the principal-keyed
/// discovery read's `ty`. The one home of the constant, which the `share`
/// module and the search consumer both name.
pub const T_GRANT: &str = "1.1.0.1.0.1.0.3.90";

/// The `replaces` class type address (wire.md §Links (writes)).
///
/// PUB-1.27's row, PUB-5.15: it is the type of the second link a
/// `make_link` carrying a `replaces` member deposits beside the first —
/// `from` the first link's address, `to` the state it names — which is how
/// a listed grant's `replaces` is read back.
pub const T_REPLACES: &str = "1.1.0.1.0.1.0.3.12";

/// The correspondence record class (wire.md §The publish shot and head-float,
/// the correspondence records).
///
/// The wire: "a link typed the correspondence class `1.1.0.1.0.1.0.3.102.1`
/// (§Credential refusals — the class's one writer is this shot; no request
/// deposits one), `from` the piece's draft-native I-span and `to` the
/// member's I-span it became". The publication composition reads them and
/// never writes one, and keeps a row only where the STORED type slot is this
/// address exactly (the wire's type match is by overlap, so a query answers
/// the parent `3.102` too).
pub const T_CORRESPONDENCE: &str = "1.1.0.1.0.1.0.3.102.1";

/// The held-removal type (the registry's vocabulary, `3.24`; the link-sets
/// design §2, §5.2).
///
/// The vocabulary's row: "The held removal: a published mark taken off in a
/// draft, written at the chord and retracted at the next publication of its
/// words" — `from` empty, `to` the published mark by address. The panel
/// reads `D`'s records of this exact type as the formatting line's job list.
pub const T_HELD_REMOVAL: &str = "1.1.0.1.0.1.0.3.24";

/// The read-with type (wire.md §The publish shot and head-float, the
/// deposits).
///
/// The wire: "a read-with is typed `3.71`, `from` the edition, `to` the set,
/// homed in the set".
pub const T_READ_WITH: &str = "1.1.0.1.0.1.0.3.71";

/// The edition-claim type (wire.md §The publish shot and head-float, the
/// deposits).
///
/// The wire: "the edition claim (`claim: true`, typed `3.14`, `from` the
/// edition, `to` the `draft`) homed in it".
pub const T_EDITION: &str = "1.1.0.1.0.1.0.3.14";

/// The registry document the commons types are defined in (wire.md §Link
/// discovery reads, "The name of a type").
///
/// A formatting type's parameter span — a heading's level — names a position
/// in this document, the one other span the formatting line's type slot may
/// carry (the link-sets design §5.2).
pub const REGISTRY_DOCUMENT: &str = "1.1.0.1.0.1";

/// Builds `{"op":"principal_prefix","principal":n}`.
pub fn principal_prefix(principal: u64) -> Value {
    json!({"op": "principal_prefix", "principal": principal})
}

/// Builds `{"op":"next_account_prefix","parent":…}`.
pub fn next_account_prefix(parent: &str) -> Value {
    json!({"op": "next_account_prefix", "parent": parent})
}

/// Builds `{"op":"effective_owner","addr":…}` (AUTH-6.37).
pub fn effective_owner(addr: &str) -> Value {
    json!({"op": "effective_owner", "addr": addr})
}

/// Builds `{"op":"key_set","account":…}` (AUTH-6.18).
pub fn key_set(account: &str) -> Value {
    json!({"op": "key_set", "account": account})
}

/// Builds `{"op":"delegate","new_prefix":…,"new_id":…}`.
pub fn delegate(new_prefix: &str, new_id: u64, id: Option<&str>) -> Value {
    with_id(json!({"op": "delegate", "new_prefix": new_prefix, "new_id": new_id}), id)
}

/// Builds `{"op":"create_new_document","account":…,"published":true}`.
///
/// The flag is passed affirmatively at every mint this crate makes
/// (PUB-8.21; AUTH RES-182).
pub fn create_home(account: &str, id: Option<&str>) -> Value {
    with_id(json!({"op": "create_new_document", "account": account, "published": true}), id)
}

/// Builds `{"op":"create_new_document","account":…,"published":<flag>}`.
///
/// The three-valued flag is passed affirmatively either way (wire.md
/// §Namespace): `true` a mint born published, `false` a private draft, the
/// merge journal's (the merge record's decision 7). [`create_home`] is the
/// `true` form every home mint takes.
pub fn create_document(account: &str, published: bool, id: Option<&str>) -> Value {
    with_id(json!({"op": "create_new_document", "account": account, "published": published}), id)
}

/// Builds `{"op":"retrieve_doc_v_span_set","doc":…}`.
///
/// It reads the extents a deposit's next free content ordinal is read off,
/// and is the doc-1 resume read.
pub fn span_set(doc: &str) -> Value {
    json!({"op": "retrieve_doc_v_span_set", "doc": doc})
}

/// Builds `retrieve_v` over content ordinals `from ..` of `doc`.
///
/// It reads `width` of them.
pub fn retrieve_v(doc: &str, from: u64, width: u64) -> Value {
    json!({"op": "retrieve_v", "specs": [{"doc": doc, "span": {"start": format!("1.{from}"), "width": format!("0.{width}")}}]})
}

/// Builds `image` over content ordinals `from ..` of `doc`.
pub fn image(doc: &str, from: u64, width: u64) -> Value {
    json!({"op": "image", "d": doc, "region": [{"start": format!("1.{from}"), "width": format!("0.{width}")}]})
}

/// Builds one depth-2 content V-span: `width` positions from ordinal `from`.
///
/// It is the element of every `region` array (wire.md §Link discovery
/// reads: "arrays of depth-2 content V-spans in `d`").
pub fn v_span(from: u64, width: u64) -> Value {
    json!({"start": format!("1.{from}"), "width": format!("0.{width}")})
}

/// Builds a `region` array over several V-spans, each `(from, width)`.
pub fn region_of(spans: &[(u64, u64)]) -> Vec<Value> {
    spans.iter().map(|&(from, width)| v_span(from, width)).collect()
}

/// Builds `{"op":"find_links_v","d":…,"region":[…]}` over SEVERAL V-spans.
///
/// wire.md §Link discovery reads: "the active links whose endsets touch the
/// region". The region is one array of every span given, so a selection in
/// pieces is one read — the frontend's builder takes one span; this one is
/// the publication composition's enumeration read (the link-sets design
/// §5.1: "ONE `find_links_v {d: D, region: ⟨the selection's V-spans, as one
/// region array⟩}`"). It draws on the per-document pool.
pub fn find_links_v(d: &str, region: &[(u64, u64)]) -> Value {
    json!({"op": "find_links_v", "d": d, "region": region_of(region)})
}

/// Builds `{"op":"count_v_by_home","d":…,"region":[…],"n":…,"except":[…]}`.
///
/// wire.md §Link discovery reads: the count by home that lifts no link, per
/// readable home holding an active link that touches the region; `except`
/// the homes passed uncounted, sent only where any is named.
pub fn count_v_by_home(d: &str, region: &[(u64, u64)], n: u64, except: &[&str]) -> Value {
    let mut frame = json!({"op": "count_v_by_home", "d": d, "region": region_of(region), "n": n});
    if !except.is_empty() {
        frame["except"] = json!(except);
    }
    frame
}

/// Builds `{"op":"find_links_v_history","d":…,"region":[…],"cur":…,"n":…}`.
///
/// wire.md §Link discovery reads: the retracted-links read, every link ever
/// made whose endsets touch the region, windowed past the cursor `cur` —
/// `null` at the start — up to `n` rows.
pub fn find_links_v_history(d: &str, region: &[(u64, u64)], cur: Option<&str>, n: u64) -> Value {
    json!({"op": "find_links_v_history", "d": d, "region": region_of(region), "cur": cur, "n": n})
}

/// Builds `{"op":"project","a":…,"slot":…,"d":…}`.
///
/// wire.md §Link discovery reads: the I→V projection of link `a`'s slot
/// (1 from, 2 to, 3 type) into document `d` → `span_set`.
pub fn project(a: &str, slot: u8, d: &str) -> Value {
    json!({"op": "project", "a": a, "slot": slot, "d": d})
}

/// Builds `{"op":"edition_claims","target":…}` (wire.md §Link discovery
/// reads; PUB-8.46).
///
/// It reads every admitted, unsuperseded claim of the edition class whose
/// `to` denotes `target`, retracted or not, each with its home.
pub fn edition_claims(target: &str) -> Value {
    json!({"op": "edition_claims", "target": target})
}

/// Builds one I-span `{"start":…,"width":…}` of `width` positions from the
/// content I-address `start`.
///
/// The width is spelled at the start's depth — zeros then the count — as a
/// stored slot spells it (wire.md §Value encodings).
pub fn i_span(start: &str, width: u64) -> Value {
    let depth = start.split('.').count();
    json!({"start": start, "width": format!("{}{width}", "0.".repeat(depth - 1))})
}

/// Builds one span of a `links` entry's I-span form: `{"start":…,"width":…}`
/// with the width a plain decimal natural, `width` positions from the
/// content I-address `start`.
///
/// It is the request's spelling (wire.md §Arrangement, `publish`: "the
/// I-span form `{"spans": […]}`", as the daemon's own suite spells it,
/// `"width": "5"`), where a STORED span and a four-set slot spell the width
/// as a displacement at the start's depth ([`i_span`]).
pub fn end_span(start: &str, width: u64) -> Value {
    json!({"start": start, "width": width.to_string()})
}

/// One slot constraint of a four-set query (wire.md §Link discovery reads).
#[derive(Debug, Clone, Copy)]
pub enum Slot<'a> {
    /// `"any"` — unconstrained.
    Any,
    /// `"empty"` — constrained to nothing.
    Empty,
    /// A span list: each an I-span as [`i_span`] or [`unit_span`] spells it.
    Spans(&'a [Value]),
}

impl Slot<'_> {
    fn wire(&self) -> Value {
        match self {
            Slot::Any => Value::from("any"),
            Slot::Empty => Value::from("empty"),
            Slot::Spans(spans) => Value::Array(spans.to_vec()),
        }
    }
}

/// Builds the GENERAL four-set query, each slot `"any"`, `"empty"` or a span
/// list.
///
/// wire.md §Link discovery reads: `find_links_ftt`'s descriptor. The three
/// one-span builders below stay for their readers; this one is the
/// publication composition's — the read-through's `{to: [the selection's
/// I-spans]}` and the two batched reads over the records' `from` spans (the
/// link-sets design §5.1), the twin pre-check's `{home: [D], ty: [the
/// subtype], from: [the draft-native spans]}` (§5.7) and the record reads.
/// A query constraining a `from` or a `to`, or a `home` naming one
/// document, takes no permit; one constraining `ty` alone is a class scan
/// (the wire's bound) and this crate sends none.
pub fn find_links_four(home: Slot<'_>, from: Slot<'_>, to: Slot<'_>, ty: Slot<'_>) -> Value {
    json!({"op": "find_links_ftt", "q": {"home": home.wire(), "from": from.wire(), "to": to.wire(), "ty": ty.wire()}})
}

/// Builds `{"op":"read_link","a":…}`.
pub fn read_link(a: &str) -> Value {
    json!({"op": "read_link", "a": a})
}

/// Builds `{"op":"doc_metadata","doc":…}` (wire.md §Namespace; PUB-8.12).
///
/// It reads the publication bit and the chain's facts of `doc` — a version
/// member answers its document's state, an unregistered address
/// `doc_not_registered`, which is how the feed consumer probes a trunk's
/// members (`search.md` §2.4).
pub fn doc_metadata(doc: &str) -> Value {
    json!({"op": "doc_metadata", "doc": doc})
}

/// Builds `{"op":"universal_grants"}` (wire.md §Grants; PUB-8.47).
///
/// It is the any-principal discovery read, run beside the principal-keyed
/// grant query at every poll of the feed consumer (`client.md` §4e.3;
/// R90 (b)).
pub fn universal_grants() -> Value {
    json!({"op": "universal_grants"})
}

/// Builds one region of a `compare` operand.
///
/// It covers content ordinals `from ..` of `doc`, `width` of them.
pub fn region(doc: &str, from: u64, width: u64) -> Value {
    json!({"doc": doc, "spans": [{"start": format!("1.{from}"), "width": format!("0.{width}")}]})
}

/// Builds `{"op":"compare","rho1":[…],"rho2":[…]}`.
///
/// It reads the shared-content correspondence between two region sets
/// (wire.md §Content & provenance reads), each a list of [`region`]s — the
/// jump's one read (`search.md` §3.4), its `rho1` the band the page
/// composes and never the hit's span.
pub fn compare(rho1: &[Value], rho2: &[Value]) -> Value {
    json!({"op": "compare", "rho1": rho1, "rho2": rho2})
}

/// Builds a declared deposit of one atom into `doc` at `ordinal`.
///
/// `deposit` names the record's class type address (AUTH-5.4; PUB-2.64).
pub fn insert_atom(doc: &str, ordinal: u64, atom: &str, deposit_type: &str, id: Option<&str>) -> Value {
    with_id(
        json!({
            "op": "insert",
            "doc": doc,
            "at": {"subspace": "1", "ordinal": ordinal.to_string()},
            "values": [{"atom": atom}],
            "deposit": deposit_type,
        }),
        id,
    )
}

/// Builds a plain insert of one atom into the draft `doc`.
///
/// It lands at content ordinal `ordinal` (wire.md §Arrangement, `insert`):
/// `values` one composite `atom` and no `deposit` member — an append into
/// the writer's own draft, the merge journal's (the merge record's §4),
/// where a declaration would be inert. [`insert_atom`] is the declared form
/// a credential record takes.
pub fn insert_plain_atom(doc: &str, ordinal: u64, atom: &str, id: Option<&str>) -> Value {
    with_id(
        json!({
            "op": "insert",
            "doc": doc,
            "at": {"subspace": "1", "ordinal": ordinal.to_string()},
            "values": [{"atom": atom}],
        }),
        id,
    )
}

/// Builds `{"op":"delete","doc":…,"p":{…},"width":…}` (wire.md §Arrangement).
///
/// It removes `width` content positions of the draft `doc` from ordinal `p`
/// — one in-place edit of the merge's draft landing (the merge record's
/// §1.5).
pub fn delete(doc: &str, p: u64, width: u64, id: Option<&str>) -> Value {
    with_id(
        json!({"op": "delete", "doc": doc, "p": {"subspace": "1", "ordinal": p.to_string()}, "width": width.to_string()}),
        id,
    )
}

/// Builds `{"op":"reinstate","doc":…,"at":{…},"runs":[…]}`.
///
/// It places `runs` by identity before content ordinal `at` of the draft
/// `doc` (wire.md §Arrangement, `reinstate`), each as [`shot_run`] spells it
/// — the other in-place edit of the merge's draft landing.
pub fn reinstate(doc: &str, at: u64, runs: &[Value], id: Option<&str>) -> Value {
    with_id(
        json!({"op": "reinstate", "doc": doc, "at": {"subspace": "1", "ordinal": at.to_string()}, "runs": runs}),
        id,
    )
}

/// Builds one run of a `publish` or a `reinstate` frame.
///
/// It holds `origin`, `i_start`, `width` (wire.md §Arrangement, `publish`):
/// `origin` the document that minted the run's addresses, `i_start` the
/// first, `width` the count.
pub fn shot_run(origin: &str, i_start: &str, width: u64) -> Value {
    json!({"origin": origin, "i_start": i_start, "width": width.to_string()})
}

/// Builds the BARE shot — `{"op":"publish","doc":…,"runs":[…]}`.
///
/// It carries `base` and `base_extent` together where the shot is staged
/// from a member (neither is the birth version), `draft` the staging draft
/// whose runs are re-inserted where one is named, `runs` the whole
/// arrangement in V-order as [`shot_run`] spells each, `attest` where the
/// caller composed one (signed ops: the entry frame over the trunk with the
/// `publish` body) and `id` the per-session idempotency key (wire.md
/// §Arrangement, `publish`; §The publish shot and head-float). It is
/// [`publication`] with no optional member — the shot as before the
/// publication's members, which the daemon admits unchanged.
pub fn publish(
    doc: &str,
    base: Option<(&str, u64)>,
    draft: Option<&str>,
    runs: &[Value],
    attest: Option<Value>,
    id: Option<&str>,
) -> Value {
    publication(&PublishFrame { doc: Some(doc), base, draft, runs, attest, id, ..PublishFrame::default() })
}

/// Every member of a `publish` request (wire.md §Arrangement, `publish`;
/// §The publish shot and head-float; `crates/skep-mcp/tools.json`'s
/// `publish` entry — the twelve members as the catalog spells them: `doc`,
/// `draft`, `runs`, `places`, `base`, `base_extent`, `account`, `mint`,
/// `claim`, `links`, `retract`, `read_with`).
///
/// The two forms the link-sets design §5.7 draws: the DOCUMENT form, `doc`
/// present and `account` absent; THE MINT FORM, `account` present with
/// `mint` and `doc` ABSENT — the edition minted in the commit, named by the
/// tag `edition` and its member by the tag `member`. `claim` rides only with
/// `mint` in this build (the catalog: "Not admitted without mint in this
/// build"). A member left at its default is not spelled, so a frame carrying
/// none of the optional members is the bare shot byte for byte.
#[derive(Debug, Clone, Default)]
pub struct PublishFrame<'a> {
    /// The published document, the trunk — the document form.
    pub doc: Option<&'a str>,
    /// The parent account the edition is minted under — the mint form.
    pub account: Option<&'a str>,
    /// `mint: true`, with `account` and no `doc`.
    pub mint: bool,
    /// `claim: true`: the edition claim homed in the minted edition, `to` the
    /// draft.
    pub claim: bool,
    /// The base member and `base_extent`, together or neither.
    pub base: Option<(&'a str, u64)>,
    /// The staging draft.
    pub draft: Option<&'a str>,
    /// The runs in V-order, each as [`shot_run`] spells it.
    pub runs: &'a [Value],
    /// The kept places, parallel to `runs` — each a [`place`] or `null`;
    /// sent only where some entry is a place.
    pub places: &'a [Value],
    /// The `links` entries, each as [`link_entry`] spells it.
    pub links: &'a [Value],
    /// The `retract` entries: link addresses.
    pub retract: &'a [&'a str],
    /// The `read_with` entries: published documents.
    pub read_with: &'a [&'a str],
    /// The `attest` member where the caller composed one.
    pub attest: Option<Value>,
    /// The per-session idempotency key.
    pub id: Option<&'a str>,
}

/// Builds a `publish` request with every member [`PublishFrame`] names.
///
/// The members are spelled as `tools.json`'s `publish` entry and wire.md
/// §Arrangement spell them; `places` is sent only where an entry is a place
/// (a list of `null`s is the shot as before, so it is left out), `links`,
/// `retract` and `read_with` only where non-empty, `mint` and `claim` only
/// where true.
pub fn publication(p: &PublishFrame<'_>) -> Value {
    let mut frame = with_id(json!({"op": "publish", "runs": p.runs}), p.id);
    if let Some(doc) = p.doc {
        frame["doc"] = Value::String(doc.to_string());
    }
    if let Some(account) = p.account {
        frame["account"] = Value::String(account.to_string());
    }
    if p.mint {
        frame["mint"] = Value::Bool(true);
    }
    if p.claim {
        frame["claim"] = Value::Bool(true);
    }
    if let Some((member, extent)) = p.base {
        frame["base"] = Value::String(member.to_string());
        frame["base_extent"] = Value::String(extent.to_string());
    }
    if let Some(draft) = p.draft {
        frame["draft"] = Value::String(draft.to_string());
    }
    if p.places.iter().any(|place| !place.is_null()) {
        frame["places"] = Value::Array(p.places.to_vec());
    }
    if !p.links.is_empty() {
        frame["links"] = Value::Array(p.links.to_vec());
    }
    if !p.retract.is_empty() {
        frame["retract"] = json!(p.retract);
    }
    if !p.read_with.is_empty() {
        frame["read_with"] = json!(p.read_with);
    }
    if let Some(a) = &p.attest {
        frame["attest"] = a.clone();
    }
    frame
}

/// Builds one kept place: the content V-position at `ordinal`.
///
/// wire.md §The publish shot and head-float, the kept places: "the V-place
/// the run held in the draft when the client composed the request".
pub fn place(ordinal: u64) -> Value {
    json!({"subspace": "1", "ordinal": ordinal.to_string()})
}

/// Builds one `links` entry: `{home, from, to, ty, old?}`.
///
/// `home` is the tag `member` or a published document's address; each end
/// one of the three forms — [`addrs_end`], [`spans_end`],
/// [`member_end`]; `ty` the address or the I-span form; `old` the private
/// original where one stands behind the copy (wire.md §Arrangement,
/// `publish`).
pub fn link_entry(home: &str, from: Value, to: Value, ty: Value, old: Option<&str>) -> Value {
    let mut entry = json!({"home": home, "from": from, "to": to, "ty": ty});
    if let Some(old) = old {
        entry["old"] = Value::String(old.to_string());
    }
    entry
}

/// Builds an end in the address form: `{"addrs": […]}`.
///
/// The tags `member` and `edition` are admitted among the addresses.
pub fn addrs_end(addrs: &[&str]) -> Value {
    json!({"addrs": addrs})
}

/// Builds an end in the I-span form: `{"spans": […]}`, each as [`i_span`]
/// spells it.
pub fn spans_end(spans: &[Value]) -> Value {
    json!({"spans": spans})
}

/// Builds an end in THE MEMBER-POSITION FORM: `{"member": [{ordinal,
/// width}, …]}`, each span `(ordinal, width)` of the member's own positions
/// inside `[1, placed]`.
///
/// The spelling must be canonical — the lowest member positions holding
/// each value, consecutive positions merged (wire.md §Arrangement,
/// `publish`) — which the publication composition computes from its own
/// runs; this builder spells what it is handed.
pub fn member_end(spans: &[(u64, u64)]) -> Value {
    let rows: Vec<Value> = spans.iter().map(|&(ordinal, width)| json!({"ordinal": ordinal.to_string(), "width": width.to_string()})).collect();
    json!({"member": rows})
}

/// Builds `{"op":"in_claims","view":"active","y":…}`.
///
/// It reads the active supersession claims whose `old` is `y` (wire.md
/// §Link discovery reads) — the merge's read ahead of its claim (the merge
/// record's §1.5), and the publication's filter's first read per candidate
/// (the link-sets design §5.1).
pub fn in_claims(y: &str) -> Value {
    json!({"op": "in_claims", "view": "active", "y": y})
}

/// Builds `{"op":"out_claims","view":"active","x":…}`.
///
/// It reads the active supersession claims whose `new` is `x` (wire.md
/// §Link discovery reads) — the publication's filter's second read per
/// candidate, which finds the original a candidate supersedes (the
/// link-sets design §5.1, W17).
pub fn out_claims(x: &str) -> Value {
    json!({"op": "out_claims", "view": "active", "x": x})
}

/// Builds an address-form `make_link` homed in `home`.
///
/// AUTH-5.4: deposit slots are address-form only.
pub fn make_link(home: &str, from: &[&str], to: &[&str], ty: &str, id: Option<&str>) -> Value {
    with_id(
        json!({
            "op": "make_link",
            "home": home,
            "from": {"addrs": from},
            "to": {"addrs": to},
            "ty": {"addrs": [ty]},
        }),
        id,
    )
}

/// Builds [`make_link`]'s frame with the optional `replaces` member.
///
/// wire.md §Links (writes); PUB-5.15 (iv): `replaces` is the address of the
/// record whose state this link replaces — a re-share's the revocation it
/// follows — or `None`, the empty state, where the member is not sent and
/// the frame is [`make_link`]'s exactly. The one builder that spells the
/// member; a caller of [`make_link`] sends no `replaces`.
pub fn make_link_replacing(home: &str, from: &[&str], to: &[&str], ty: &str, replaces: Option<&str>, id: Option<&str>) -> Value {
    let mut frame = make_link(home, from, to, ty, id);
    if let Some(r) = replaces {
        frame["replaces"] = Value::String(r.to_string());
    }
    frame
}

/// Builds the unit subtree span at `addr` as a four-set slot.
///
/// It is the spelling M7's `enc` stores for an address-form slot.
pub fn unit_span(addr: &str) -> Value {
    let depth = addr.split('.').count();
    let width = format!("{}1", "0.".repeat(depth - 1));
    json!([{"start": addr, "width": width}])
}

/// Builds `find_links_ftt` over `ty` and `to`.
///
/// Two slots are constrained, so it is no class scan and takes no permit
/// (wire.md §Link discovery reads).
pub fn find_links_ftt(ty: &str, to: &str) -> Value {
    json!({"op": "find_links_ftt", "q": {"home": "any", "from": "any", "to": unit_span(to), "ty": unit_span(ty)}})
}

/// Builds `find_links_ftt` over `ty` and `from`.
///
/// It is the claim link's shape, and the supersession trail's resume read
/// (`from` the old enroll link).
pub fn find_links_ftt_from(ty: &str, from: &str) -> Value {
    json!({"op": "find_links_ftt", "q": {"home": "any", "from": unit_span(from), "to": "any", "ty": unit_span(ty)}})
}

/// Builds `find_links_ftt` over `ty` and `home`.
///
/// It reads every deposit of `ty` homed in one document, the head
/// invariant's enumeration read (AUTH-5.59's head: "every account whose
/// honored genesis stands in the doc 1 of an account the enumeration
/// already holds"). Two slots constrained, so no class scan.
pub fn find_links_ftt_home(ty: &str, home: &str) -> Value {
    json!({"op": "find_links_ftt", "q": {"home": unit_span(home), "from": "any", "to": "any", "ty": unit_span(ty)}})
}

/// Builds `{"op":"assert_sup","home":…,"old":…,"new":…}`.
///
/// It is the supersession trail (AUTH-5.59 step 2; wire.md §Links
/// (writes)), with its `attest` member where the caller composed one
/// (signed ops: publish-class into a published doc 1 from a signed
/// session).
pub fn assert_sup(home: &str, old: &str, new: &str, attest: Option<Value>, id: Option<&str>) -> Value {
    let mut frame = with_id(json!({"op": "assert_sup", "home": home, "old": old, "new": new}), id);
    if let Some(a) = attest {
        frame["attest"] = a;
    }
    frame
}

fn with_id(mut frame: Value, id: Option<&str>) -> Value {
    if let Some(id) = id {
        frame["id"] = Value::String(id.to_string());
    }
    frame
}
