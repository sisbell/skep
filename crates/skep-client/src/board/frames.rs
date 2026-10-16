//! The wire's frames, spelled once (wire.md §Operations): every frame this
//! crate sends through [`Board::op`](super::Board::op) is built here. Every
//! address is carried as the caller spells it; the daemon parses leniently
//! and this client composes canonically.

use serde_json::{json, Value};

/// The GRANTS class type address (wire.md §The read predicate: "`ty` the
/// grants class `1.1.0.1.0.1.0.3.90`"): the type slot of every grant, of
/// the record that revokes one (PUB-5.13, PUB-5.15), and of the
/// principal-keyed discovery read's `ty`. The one home of the constant,
/// which the `share` module and the search consumer both name.
pub const T_GRANT: &str = "1.1.0.1.0.1.0.3.90";

/// The `replaces` class type address (wire.md §Links (writes); PUB-1.27's
/// row, PUB-5.15): the type of the second link a `make_link` carrying a
/// `replaces` member deposits beside the first — `from` the first link's
/// address, `to` the state it names — which is how a listed grant's
/// `replaces` is read back.
pub const T_REPLACES: &str = "1.1.0.1.0.1.0.3.12";

/// `{"op":"principal_prefix","principal":n}`.
pub fn principal_prefix(principal: u64) -> Value {
    json!({"op": "principal_prefix", "principal": principal})
}

/// `{"op":"next_account_prefix","parent":…}`.
pub fn next_account_prefix(parent: &str) -> Value {
    json!({"op": "next_account_prefix", "parent": parent})
}

/// `{"op":"effective_owner","addr":…}` (AUTH-6.37).
pub fn effective_owner(addr: &str) -> Value {
    json!({"op": "effective_owner", "addr": addr})
}

/// `{"op":"key_set","account":…}` (AUTH-6.18).
pub fn key_set(account: &str) -> Value {
    json!({"op": "key_set", "account": account})
}

/// `{"op":"delegate","new_prefix":…,"new_id":…}`.
pub fn delegate(new_prefix: &str, new_id: u64, id: Option<&str>) -> Value {
    with_id(json!({"op": "delegate", "new_prefix": new_prefix, "new_id": new_id}), id)
}

/// `{"op":"create_new_document","account":…,"published":true}` — the
/// flag passed AFFIRMATIVELY at every mint this crate makes (PUB-8.21;
/// AUTH RES-182).
pub fn create_home(account: &str, id: Option<&str>) -> Value {
    with_id(json!({"op": "create_new_document", "account": account, "published": true}), id)
}

/// `{"op":"create_new_document","account":…,"published":<flag>}` — the
/// three-valued flag passed AFFIRMATIVELY either way (wire.md §Namespace):
/// `true` a mint born published, `false` a PRIVATE draft, the merge
/// journal's (the merge record's decision 7). [`create_home`] is the `true`
/// form every home mint takes.
pub fn create_document(account: &str, published: bool, id: Option<&str>) -> Value {
    with_id(json!({"op": "create_new_document", "account": account, "published": published}), id)
}

/// `{"op":"retrieve_doc_v_span_set","doc":…}` — the extents a deposit's
/// next free content ordinal is read off, and the doc-1 resume read.
pub fn span_set(doc: &str) -> Value {
    json!({"op": "retrieve_doc_v_span_set", "doc": doc})
}

/// `retrieve_v` over content ordinals `from ..` of `doc`, `width` of
/// them.
pub fn retrieve_v(doc: &str, from: u64, width: u64) -> Value {
    json!({"op": "retrieve_v", "specs": [{"doc": doc, "span": {"start": format!("1.{from}"), "width": format!("0.{width}")}}]})
}

/// `image` over content ordinals `from ..` of `doc`.
pub fn image(doc: &str, from: u64, width: u64) -> Value {
    json!({"op": "image", "d": doc, "region": [{"start": format!("1.{from}"), "width": format!("0.{width}")}]})
}

/// `{"op":"read_link","a":…}`.
pub fn read_link(a: &str) -> Value {
    json!({"op": "read_link", "a": a})
}

/// `{"op":"doc_metadata","doc":…}` (wire.md §Namespace; PUB-8.12): the
/// publication bit and the chain's facts of `doc` — a version member answers
/// its document's state, an unregistered address `doc_not_registered`,
/// which is how the feed consumer probes a trunk's members (`search.md`
/// §2.4).
pub fn doc_metadata(doc: &str) -> Value {
    json!({"op": "doc_metadata", "doc": doc})
}

/// `{"op":"universal_grants"}` (wire.md §Grants; PUB-8.47): the
/// any-principal discovery read, run beside the principal-keyed grant query
/// at every poll of the feed consumer (`client.md` §4e.3; R90 (b)).
pub fn universal_grants() -> Value {
    json!({"op": "universal_grants"})
}

/// One region of a `compare` operand: content ordinals `from ..` of `doc`,
/// `width` of them.
pub fn region(doc: &str, from: u64, width: u64) -> Value {
    json!({"doc": doc, "spans": [{"start": format!("1.{from}"), "width": format!("0.{width}")}]})
}

/// `{"op":"compare","rho1":[…],"rho2":[…]}` (wire.md §Content & provenance
/// reads): the shared-content correspondence between two region sets, each
/// a list of [`region`]s — the jump's one read (`search.md` §3.4), its
/// `rho1` the BAND the page composes and never the hit's span.
pub fn compare(rho1: &[Value], rho2: &[Value]) -> Value {
    json!({"op": "compare", "rho1": rho1, "rho2": rho2})
}

/// A DECLARED deposit of one atom into `doc` at `ordinal` (AUTH-5.4;
/// PUB-2.64): `deposit` naming the record's class TYPE address.
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

/// A PLAIN insert of one atom into the DRAFT `doc` at content ordinal
/// `ordinal` (wire.md §Arrangement, `insert`): `values` one composite
/// `atom` and NO `deposit` member — an append into the writer's own draft,
/// the merge journal's (the merge record's §4), where a declaration would
/// be inert. [`insert_atom`] is the DECLARED form a credential record takes.
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

/// `{"op":"delete","doc":…,"p":{…},"width":…}` (wire.md §Arrangement):
/// `width` content positions of the draft `doc` from ordinal `p` removed —
/// one in-place edit of the merge's draft landing (the merge record's §1.5).
pub fn delete(doc: &str, p: u64, width: u64, id: Option<&str>) -> Value {
    with_id(
        json!({"op": "delete", "doc": doc, "p": {"subspace": "1", "ordinal": p.to_string()}, "width": width.to_string()}),
        id,
    )
}

/// `{"op":"reinstate","doc":…,"at":{…},"runs":[…]}` (wire.md §Arrangement,
/// `reinstate`): `runs` placed BY IDENTITY before content ordinal `at` of
/// the draft `doc`, each as [`shot_run`] spells it — the other in-place
/// edit of the merge's draft landing.
pub fn reinstate(doc: &str, at: u64, runs: &[Value], id: Option<&str>) -> Value {
    with_id(
        json!({"op": "reinstate", "doc": doc, "at": {"subspace": "1", "ordinal": at.to_string()}, "runs": runs}),
        id,
    )
}

/// One run of a `publish` or a `reinstate` frame — `origin`, `i_start`,
/// `width` (wire.md §Arrangement, `publish`): `origin` the document that
/// minted the run's addresses, `i_start` the first, `width` the count.
pub fn shot_run(origin: &str, i_start: &str, width: u64) -> Value {
    json!({"origin": origin, "i_start": i_start, "width": width.to_string()})
}

/// THE SHOT — `{"op":"publish","doc":…,"runs":[…]}` with `base` and
/// `base_extent` together where the shot is staged from a member (neither
/// is the birth version), `draft` the staging draft whose runs are
/// re-inserted where one is named, `runs` the WHOLE arrangement in V-order
/// as [`shot_run`] spells each, `attest` where the caller composed one
/// (signed ops: the entry frame over the trunk with the `publish` body) and
/// `id` the per-session idempotency key (wire.md §Arrangement, `publish`;
/// §The publish shot and head-float).
pub fn publish(
    doc: &str,
    base: Option<(&str, u64)>,
    draft: Option<&str>,
    runs: &[Value],
    attest: Option<Value>,
    id: Option<&str>,
) -> Value {
    let mut frame = with_id(json!({"op": "publish", "doc": doc, "runs": runs}), id);
    if let Some((member, extent)) = base {
        frame["base"] = Value::String(member.to_string());
        frame["base_extent"] = Value::String(extent.to_string());
    }
    if let Some(draft) = draft {
        frame["draft"] = Value::String(draft.to_string());
    }
    if let Some(a) = attest {
        frame["attest"] = a;
    }
    frame
}

/// `{"op":"in_claims","view":"active","y":…}` (wire.md §Link discovery
/// reads): the ACTIVE supersession claims whose `old` is `y` — the merge's
/// read ahead of its claim (the merge record's §1.5).
pub fn in_claims(y: &str) -> Value {
    json!({"op": "in_claims", "view": "active", "y": y})
}

/// An address-form `make_link` homed in `home` (AUTH-5.4: deposit slots
/// are address-form only).
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

/// [`make_link`]'s frame with the optional `replaces` member (wire.md
/// §Links (writes); PUB-5.15 (iv)): `replaces` the address of the record
/// whose STATE this link replaces — a re-share's the revocation it follows —
/// or `None`, the EMPTY state, where the member is not sent and the frame is
/// [`make_link`]'s exactly. The one builder that spells the member; every
/// existing caller of [`make_link`] sends its frame unchanged.
pub fn make_link_replacing(home: &str, from: &[&str], to: &[&str], ty: &str, replaces: Option<&str>, id: Option<&str>) -> Value {
    let mut frame = make_link(home, from, to, ty, id);
    if let Some(r) = replaces {
        frame["replaces"] = Value::String(r.to_string());
    }
    frame
}

/// The unit subtree span at `addr` as a four-set slot — the spelling
/// M7's `enc` stores for an address-form slot.
pub fn unit_span(addr: &str) -> Value {
    let depth = addr.split('.').count();
    let width = format!("{}1", "0.".repeat(depth - 1));
    json!([{"start": addr, "width": width}])
}

/// `find_links_ftt` over `ty` and `to` — two slots constrained, so it is
/// no class scan and takes no permit (wire.md §Link discovery reads).
pub fn find_links_ftt(ty: &str, to: &str) -> Value {
    json!({"op": "find_links_ftt", "q": {"home": "any", "from": "any", "to": unit_span(to), "ty": unit_span(ty)}})
}

/// `find_links_ftt` over `ty` and `from` — the claim link's shape, and
/// the supersession trail's resume read (`from` the OLD enroll link).
pub fn find_links_ftt_from(ty: &str, from: &str) -> Value {
    json!({"op": "find_links_ftt", "q": {"home": "any", "from": unit_span(from), "to": "any", "ty": unit_span(ty)}})
}

/// `find_links_ftt` over `ty` and `home` — every deposit of `ty` HOMED in
/// one document, the head invariant's enumeration read (AUTH-5.59's
/// head: "every account whose honored genesis stands in the doc 1 of an
/// account the enumeration already holds"). Two slots constrained, so no
/// class scan.
pub fn find_links_ftt_home(ty: &str, home: &str) -> Value {
    json!({"op": "find_links_ftt", "q": {"home": unit_span(home), "from": "any", "to": "any", "ty": unit_span(ty)}})
}

/// `{"op":"assert_sup","home":…,"old":…,"new":…}` — the supersession
/// trail (AUTH-5.59 step 2; wire.md §Links (writes)), with its `attest`
/// member where the caller composed one (signed ops: publish-class into
/// a published doc 1 from a signed session).
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
