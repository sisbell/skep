//! The helpers the register, vector-matrix, H1-residue and cascade suites
//! share (PUB round 2, lane 4): positions and verdicts, principals and
//! seats, arrangement writes, the publish shot, reads, links, history and
//! the dump, and the claim ceremony parameterized. A suite that defines a
//! local item of one of these names shadows the glob import, as Rust's glob
//! rules allow, so the older suites' own `stranger`/`head` helpers stand
//! untouched beside these.

use std::collections::BTreeSet;

use super::*;

/// The ceremony atom: the claimant's doc 1's one content element, at its
/// first content ordinal.
pub const CEREMONY_ATOM: &str = "1.0.1.0.1.0.1.1";

/// The audit-view classes' type addresses — the engine's commons pins
/// (`skep_engine::types`), spelled as a client names them — and the two
/// classes read under the ACTIVE view beside them.
pub const T_SUCCESSOR_OF_CLASS: &str = "1.1.0.1.0.1.0.3.59";
pub const T_ENDORSE_CLASS: &str = "1.1.0.1.0.1.0.3.42";
pub const T_MARKER_CLASS: &str = "1.1.0.1.0.1.0.3.91";
pub const T_DESIGNATION_CLASS: &str = "1.1.0.1.0.1.0.3.22";
pub const T_RAIL_CLASS: &str = "1.1.0.1.0.1.0.3.60";
pub const T_STEWARD_CLASS: &str = "1.1.0.1.0.1.0.3.61";
pub const T_EDITION_CLASS: &str = "1.1.0.1.0.1.0.3.14";

/// The daemon's publish-class refusal, in the `auth_wire` `code:detail`
/// convention — the verdict every bare-session cell of the gate answers.
pub const GATED: &str = "credential_refused:signed_session_required";

// ── positions, verdicts, shapes ──────────────────────────────────────────

/// The committed head, off `/health`.
pub fn head_position(port: u16) -> u64 {
    json(&get(port, "/health").1)["log_position"].as_u64().expect("log_position")
}

/// The committed position a write's ack carries.
pub fn acked_at(v: &Value) -> u64 {
    assert!(
        matches!(v["resp"].as_str(), Some("ack" | "ack_addr" | "ack_edit")),
        "not a write ack: {v}"
    );
    v["at"].as_u64().expect("write acks carry at")
}

/// A response's verdict: `ok` for any ack; a rejection's code, or
/// `credential_refused:<token>` for the daemon-originated family (the
/// `auth_wire` convention); anything else spelled out.
pub fn verdict(v: &Value) -> String {
    match v["resp"].as_str() {
        Some("ack") | Some("ack_addr") | Some("ack_edit") => "ok".to_string(),
        Some("rejected") => match (v["code"].as_str().unwrap_or("?"), v["detail"].as_str()) {
            ("credential_refused", Some(d)) => format!("credential_refused:{d}"),
            (code, _) => code.to_string(),
        },
        other => format!("resp:{other:?}"),
    }
}

/// PUB-8.4 / PUB-8.5: `withheld`, `reorder`, `site.addr` the document, and
/// no `detail`, ever.
pub fn assert_withheld(v: &Value, doc: &str) {
    let rej = expect_resp(v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("withheld"), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("reorder"), "{v}");
    assert_eq!(rej["site"]["addr"].as_str(), Some(doc), "the withheld document: {v}");
    assert!(rej.get("detail").is_none(), "withheld carries no detail: {v}");
}

/// The delivery's withheld arm (PUB-8.10): one item per masked RUN.
pub fn withheld_item(origin: &str, width: u64) -> Value {
    json!({"withheld": {"origin": origin, "width": width.to_string()}})
}

/// The addresses of an `addrs` answer.
pub fn addrs_of(v: &Value) -> Vec<String> {
    expect_resp(v, "addrs")["addrs"]
        .as_array()
        .expect("addrs")
        .iter()
        .map(|a| a.as_str().expect("an address").to_string())
        .collect()
}

// ── principals and seats ─────────────────────────────────────────────────

/// A seated principal: its account, its BARE session, and its MINT-FIRST
/// home (doc 1, born published).
pub struct Seat {
    pub account: String,
    pub session: String,
    pub doc1: String,
}

/// The next delegable prefix under `parent`, as `token` (`None` = the guest —
/// the read is exempt from the predicate, PUB-6.50).
pub fn next_prefix_under(port: u16, token: Option<&str>, parent: &str) -> String {
    let v = op(port, token, &format!(r#"{{"op":"next_account_prefix","parent":"{parent}"}}"#));
    expect_resp(&v, "maybe_addr")["addr"]
        .as_str()
        .unwrap_or_else(|| panic!("no delegable prefix under {parent}: {v}"))
        .to_string()
}

/// Delegate a fresh account under `parent` from `by`'s session and open a
/// bare session for principal `id`. Returns `(account, session)`.
pub fn delegate_under(port: u16, by: &str, parent: &str, id: u64) -> (String, String) {
    let account = next_prefix_under(port, Some(by), parent);
    expect_resp(
        &op(port, Some(by), &format!(r#"{{"op":"delegate","new_prefix":"{account}","new_id":{id}}}"#)),
        "ack_addr",
    );
    (account, open_session(port, id))
}

/// A stranger under node 1, delegated from the bootstrap principal — no home
/// yet. Returns `(account, bare session)`.
pub fn bootstrap_delegate(port: u16, id: u64) -> (String, String) {
    let boot = open_session(port, 0);
    delegate_under(port, &boot, "1", id)
}

pub fn create_frame(account: &str, published: Option<bool>) -> String {
    let flag = match published {
        Some(b) => format!(r#","published":{b}"#),
        None => String::new(),
    };
    format!(r#"{{"op":"create_new_document","account":"{account}"{flag}}}"#)
}

/// A flagless mint into `account` from `session` — the home where the
/// account is empty, a private draft afterwards.
pub fn create_doc(port: u16, session: &str, account: &str) -> String {
    acked_addr(&op(port, Some(session), &create_frame(account, None)))
}

/// A stranger under node 1 with its home minted: the NON-ENTITLED reader
/// and writer of the H1 matrix (or the GRANT-HOLDER once granted).
pub fn seat_stranger(port: u16, id: u64) -> Seat {
    let (account, session) = bootstrap_delegate(port, id);
    let doc1 = create_doc(port, &session, &account);
    Seat { account, session, doc1 }
}

/// Reserve `parent`'s AGENT SPACE — its computed first sub-account `X.1` —
/// with a HELD, keyless delegation. Since RES-80 (AUTH-2.62) `X.1` takes NO
/// genesis (`not_genesis_registry` forever), so a hire keys a LATER child of
/// `parent`; reserving `X.1` makes the next `next_account_prefix(parent)` a
/// later child, whose genesis registry is `parent` (AUTH-2.62's
/// `Some(Account(parent))` arm) and whose hire into `parent`'s doc 1 is
/// honored. `by` owns `parent`; `holder_id` is a throwaway principal. Answers
/// the agent-space account. Delegation is ω-gated, never a credential write, so
/// a bare `by` suffices.
pub fn reserve_agent_space(port: u16, by: &str, parent: &str, holder_id: u64) -> String {
    let agent_space = next_prefix_under(port, Some(by), parent);
    expect_resp(
        &op(port, Some(by), &format!(r#"{{"op":"delegate","new_prefix":"{agent_space}","new_id":{holder_id}}}"#)),
        "ack_addr",
    );
    agent_space
}

/// A sub-account the OWNER delegates beneath the claimant's account, its
/// home minted — a SUBTREE reader of every draft of the owner's (PUB-1.4,
/// PUB-1.32). The claimant's computed first sub-account is the AGENT SPACE and
/// takes no genesis (RES-80), so this reserves it first and seats a LATER
/// child, which a hire into the claimant's doc 1 can key.
pub fn seat_sub_account(port: u16, owner: &str, id: u64) -> Seat {
    reserve_agent_space(port, owner, CLAIMANT_ACCOUNT, 100_000 + id);
    let (account, session) = delegate_under(port, owner, CLAIMANT_ACCOUNT, id);
    let doc1 = create_doc(port, &session, &account);
    Seat { account, session, doc1 }
}

/// A later mint into the claimant's account — flagless, hence PRIVATE.
pub fn owner_draft(port: u16, owner: &str) -> String {
    create_doc(port, owner, CLAIMANT_ACCOUNT)
}

/// An EDITION of the claimant's: an explicit `published:true` mint from the
/// signed session the publish class demands — born empty.
pub fn published_edition(port: u16, signed: &str) -> String {
    acked_addr(&op(port, Some(signed), &create_frame(CLAIMANT_ACCOUNT, Some(true))))
}

// ── arrangement writes ───────────────────────────────────────────────────

/// A per-byte PROSE insert, undeclared or DECLARED. What a declared one here
/// deposits is PUB-2.60's residue — bytes of the depositor's choosing under a
/// declared class type — so it names a MEMBER type, [`T_ENROLL`], which the
/// door admits on the type alone (PUB-2.11, RES-249/261), what the bytes are
/// being nothing it can test.
pub fn insert_frame(doc: &str, ordinal: u64, text: &str, deposit: bool) -> String {
    let declaration = if deposit { format!(r#","deposit":"{T_ENROLL}""#) } else { String::new() };
    format!(
        r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":["{text}"]{declaration}}}"#
    )
}

/// An UNDECLARED per-byte insert — the draft's own edit.
pub fn insert_text(port: u16, session: &str, doc: &str, ordinal: u64, text: &str) -> Value {
    op(port, Some(session), &insert_frame(doc, ordinal, text, false))
}

/// A DECLARED per-byte deposit at a fresh position — the one insert a
/// published document admits (PUB-2.59). Returns the first minted I-address.
pub fn deposit_text(port: u16, signed: &str, doc: &str, ordinal: u64, text: &str) -> String {
    acked_addr(&op(port, Some(signed), &insert_frame(doc, ordinal, text, true)))
}

/// A private draft of the claimant's holding `text` from ordinal 1.
pub fn draft_with(port: u16, owner: &str, text: &str) -> String {
    let d = owner_draft(port, owner);
    expect_resp(&insert_text(port, owner, &d, 1, text), "ack_addr");
    d
}

/// A published edition of the claimant's holding `text` from ordinal 1 — a
/// declared deposit into the empty edition.
pub fn edition_with(port: u16, signed: &str, text: &str) -> String {
    let e = published_edition(port, signed);
    deposit_text(port, signed, &e, 1, text);
    e
}

pub fn copy_frame(doc: &str, at: u64, source: &str, from: u64, width: u64) -> String {
    format!(
        r#"{{"op":"copy","doc":"{doc}","at":{{"subspace":"1","ordinal":"{at}"}},"specs":[{{"source":"{source}","span":{{"start":"1.{from}","width":"0.{width}"}}}}]}}"#
    )
}

pub fn copy_span(port: u16, session: &str, doc: &str, at: u64, source: &str, from: u64, width: u64) -> Value {
    op(port, Some(session), &copy_frame(doc, at, source, from, width))
}

pub fn delete_frame(doc: &str, at: u64, width: u64) -> String {
    format!(
        r#"{{"op":"delete","doc":"{doc}","p":{{"subspace":"1","ordinal":"{at}"}},"width":"{width}"}}"#
    )
}

pub fn rearrange_frame(doc: &str, cuts: [u64; 3]) -> String {
    let [a, b, c] = cuts;
    format!(
        r#"{{"op":"rearrange","doc":"{doc}","cuts":[{{"subspace":"1","ordinal":"{a}"}},{{"subspace":"1","ordinal":"{b}"}},{{"subspace":"1","ordinal":"{c}"}}]}}"#
    )
}

pub fn fork_frame(published: Option<bool>) -> String {
    match published {
        Some(b) => format!(r#"{{"op":"fork","published":{b}}}"#),
        None => r#"{"op":"fork"}"#.to_string(),
    }
}

/// `version` with the three-valued flag as the client sends it.
pub fn version_frame(d_src: &str, published: Option<bool>) -> String {
    let flag = match published {
        Some(b) => format!(r#","published":{b}"#),
        None => String::new(),
    };
    format!(r#"{{"op":"version","d_src":"{d_src}"{flag}}}"#)
}

pub fn version_of(port: u16, session: &str, d_src: &str, published: Option<bool>) -> Value {
    op(port, Some(session), &version_frame(d_src, published))
}

// ── the publish shot ─────────────────────────────────────────────────────

/// One run of a shot, as the client renders it.
pub fn run(origin: &str, i_start: &str, width: u64) -> String {
    format!(r#"{{"origin":"{origin}","i_start":"{i_start}","width":"{width}"}}"#)
}

/// The shot: `base` with the extent the staged copy took (both or neither —
/// neither is the birth version), the staging `draft` when there is one, and
/// the runs.
pub fn publish_frame(doc: &str, base: Option<(&str, u64)>, draft: Option<&str>, runs: &[String]) -> String {
    let base = base
        .map(|(m, extent)| format!(r#","base":"{m}","base_extent":"{extent}""#))
        .unwrap_or_default();
    let draft = draft.map(|d| format!(r#","draft":"{d}""#)).unwrap_or_default();
    format!(r#"{{"op":"publish","doc":"{doc}"{base}{draft},"runs":[{}]}}"#, runs.join(","))
}

/// One shot from the signed session; the minted member's address.
pub fn shot(
    port: u16,
    signed: &str,
    doc: &str,
    base: Option<(&str, u64)>,
    draft: Option<&str>,
    runs: &[String],
) -> String {
    acked_addr(&op(port, Some(signed), &publish_frame(doc, base, draft, runs)))
}

/// The DOCUMENT that minted a content I-address: the prefix before its last
/// `.0.1.` (subspace 1, the content subspace) — `1.0.1.0.5.0.1.3` is
/// `1.0.1.0.5`'s, and a member-chain mint `1.0.1.0.5.1.0.1.2` is the
/// member's.
pub fn origin_of(i_addr: &str) -> String {
    let idx = i_addr.rfind(".0.1.").unwrap_or_else(|| panic!("{i_addr} is not a content I-address"));
    i_addr[..idx].to_string()
}

/// `width` consecutive content I-addresses of `doc` from its `first`
/// ordinal — the addresses a per-byte insert of that width mints.
pub fn i_range(doc: &str, first: u64, width: u64) -> Vec<String> {
    (0..width).map(|k| format!("{doc}.0.1.{}", first + k)).collect()
}

/// Every I-address an image's runs cover, in order.
pub fn expand_runs(runs: &[(String, u64)]) -> Vec<String> {
    let mut out = Vec::new();
    for (start, width) in runs {
        let (prefix, last) = start.rsplit_once('.').expect("a dotted address");
        let n: u64 = last.parse().expect("a decimal component");
        for k in 0..*width {
            out.push(format!("{prefix}.{}", n + k));
        }
    }
    out
}

/// The runs a shot re-supplies for content ordinals `from ..` of `doc`, each
/// its own origin — what a client renders from the head it stages off.
pub fn shot_runs(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<String> {
    image_runs(port, token, doc, from, width)
        .iter()
        .map(|(i_start, w)| run(&origin_of(i_start), i_start, *w))
        .collect()
}

// ── reads ────────────────────────────────────────────────────────────────

pub fn retrieve_frame(doc: &str, from: u64, width: u64) -> String {
    format!(
        r#"{{"op":"retrieve_v","specs":[{{"doc":"{doc}","span":{{"start":"1.{from}","width":"0.{width}"}}}}]}}"#
    )
}

pub fn read1_frame(doc: &str) -> String {
    retrieve_frame(doc, 1, 1)
}

pub fn spanset_frame(doc: &str) -> String {
    format!(r#"{{"op":"retrieve_doc_v_span_set","doc":"{doc}"}}"#)
}

pub fn doc_metadata_frame(doc: &str) -> String {
    format!(r#"{{"op":"doc_metadata","doc":"{doc}"}}"#)
}

/// The owner-of-address read (AUTH-6.37): one argument, `addr`.
pub fn effective_owner_frame(addr: &str) -> String {
    format!(r#"{{"op":"effective_owner","addr":"{addr}"}}"#)
}

pub fn image_frame(doc: &str, from: u64, width: u64) -> String {
    format!(r#"{{"op":"image","d":"{doc}","region":[{{"start":"1.{from}","width":"0.{width}"}}]}}"#)
}

pub fn show_origin_frame(doc: &str, from: u64, width: u64) -> String {
    format!(
        r#"{{"op":"show_origin","doc":"{doc}","span":{{"start":"1.{from}","width":"0.{width}"}}}}"#
    )
}

pub fn read_link_frame(a: &str) -> String {
    format!(r#"{{"op":"read_link","a":"{a}"}}"#)
}

/// The `d`/`region` fields naming content ordinals `from ..` of `doc`.
pub fn region(doc: &str, from: u64, width: u64) -> String {
    format!(r#""d":"{doc}","region":[{{"start":"1.{from}","width":"0.{width}"}}]"#)
}

pub fn find_links_frame(doc: &str, from: u64, width: u64) -> String {
    format!(r#"{{"op":"find_links_v",{}}}"#, region(doc, from, width))
}

/// A region for `compare`'s `rho1`/`rho2` and `find_docs_containing`'s
/// `regions`: content ordinals `from ..` of `doc`.
pub fn region_spec(doc: &str, from: u64, width: u64) -> String {
    format!(r#"{{"doc":"{doc}","spans":[{{"start":"1.{from}","width":"0.{width}"}}]}}"#)
}

/// The delivery items of content ordinals `from ..` of `doc`, as `token`.
pub fn delivery(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Value {
    let v = op(port, token, &retrieve_frame(doc, from, width));
    expect_resp(&v, "delivery")["items"].clone()
}

/// The per-byte text at content ordinals `from ..` of `doc`, as `token`
/// (atoms, refs and withheld items contribute nothing).
pub fn text_of(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> String {
    delivery(port, token, doc, from, width)
        .as_array()
        .expect("items")
        .iter()
        .map(|i| i["content"].as_str().unwrap_or(""))
        .collect()
}

/// The content extent `doc` answers — `retrieve_doc_v_span_set`'s content
/// span width, `0` when the set carries none.
pub fn content_extent(port: u16, token: Option<&str>, doc: &str) -> u64 {
    let v = op(port, token, &spanset_frame(doc));
    expect_resp(&v, "span_set")["set"]
        .as_array()
        .expect("set")
        .iter()
        .find(|s| s["start"].as_str() == Some("1.1"))
        .map(|s| {
            s["width"]
                .as_str()
                .expect("width")
                .strip_prefix("0.")
                .expect("a depth-2 width")
                .parse()
                .expect("a count")
        })
        .unwrap_or(0)
}

/// The runs of a `runs` answer: `(i_start, width)`.
pub fn runs_in(v: &Value) -> Vec<(String, u64)> {
    expect_resp(v, "runs")["runs"]
        .as_array()
        .expect("runs")
        .iter()
        .map(|r| {
            (
                r["i_start"].as_str().expect("i_start").to_string(),
                r["width"].as_str().expect("width").parse().expect("a count"),
            )
        })
        .collect()
}

/// The V→I image of content ordinals `from ..` of `doc`.
pub fn image_runs(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<(String, u64)> {
    runs_in(&op(port, token, &image_frame(doc, from, width)))
}

/// The origin documents of content ordinals `from ..` of `doc`.
pub fn origins_of(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<String> {
    addrs_of(&op(port, token, &show_origin_frame(doc, from, width)))
}

/// The whole `doc_metadata` answer for `doc`, as `token`.
pub fn doc_metadata(port: u16, token: Option<&str>, doc: &str) -> Value {
    op(port, token, &doc_metadata_frame(doc))
}

/// ω's pair for `addr` as `token` (`None` = the guest), off the head:
/// `(prefix, principal)`, or `None` where BOTH members are null. A reply
/// carrying one member without the other is a shape violation (AUTH-6.37:
/// null TOGETHER) and panics here, so every cell that reads through this
/// helper pins the pairing.
pub fn effective_owner(port: u16, token: Option<&str>, addr: &str) -> Option<(String, u64)> {
    owner_pair(&op(port, token, &effective_owner_frame(addr)))
}

/// The pair out of one `effective_owner` answer — `/op`'s or `/op-at`'s.
pub fn owner_pair(v: &Value) -> Option<(String, u64)> {
    let v = expect_resp(v, "effective_owner");
    // Indexing a missing key reads as null, so presence is asked for itself:
    // an absent owner is two nulls, never two omissions.
    for member in ["prefix", "principal"] {
        assert!(v.get(member).is_some(), "`{member}` is ALWAYS present: {v}");
    }
    match (&v["prefix"], &v["principal"]) {
        (Value::Null, Value::Null) => None,
        (Value::String(prefix), Value::Number(principal)) => Some((
            prefix.clone(),
            principal.as_u64().unwrap_or_else(|| panic!("a principal id is a u64: {v}")),
        )),
        _ => panic!("`prefix` and `principal` travel TOGETHER, carried or null: {v}"),
    }
}

/// The any-principal discovery read (PUB-8.47): no argument.
pub fn universal_grants_frame() -> String {
    r#"{"op":"universal_grants"}"#.to_string()
}

/// The rows out of one `universal_grants` answer — `/op`'s or `/op-at`'s —
/// as `(prefix, issuers)` in the order served. `rows` is ALWAYS present (the
/// guest's answer is the empty array under the same tag) and every row is
/// exactly `prefix` and `issuers`; a shape violation panics here, so every
/// cell read through this helper pins the shape.
pub fn grant_rows(v: &Value) -> Vec<(String, Vec<String>)> {
    let v = expect_resp(v, "universal_grants");
    let rows = v
        .get("rows")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("`rows` is ALWAYS present, an array: {v}"));
    rows.iter()
        .map(|row| {
            assert_eq!(
                row.as_object().map(|o| o.len()),
                Some(2),
                "a row is exactly `prefix` and `issuers`: {v}"
            );
            let prefix = row["prefix"]
                .as_str()
                .unwrap_or_else(|| panic!("a row carries `prefix`, an address: {v}"))
                .to_string();
            let issuers = row["issuers"]
                .as_array()
                .unwrap_or_else(|| panic!("a row carries `issuers`, an array: {v}"))
                .iter()
                .map(|i| i.as_str().unwrap_or_else(|| panic!("an issuer is an address: {v}")).to_string())
                .collect();
            (prefix, issuers)
        })
        .collect()
}

/// The any-principal discovery read as `token` (`None` = the guest), off the
/// head: the served rows, `(prefix, issuers)` each.
pub fn universal_grants(port: u16, token: Option<&str>) -> Vec<(String, Vec<String>)> {
    grant_rows(&op(port, token, &universal_grants_frame()))
}

/// The link value at `a` as `token`: `null` where absent.
pub fn read_link(port: u16, token: Option<&str>, a: &str) -> Value {
    let v = op(port, token, &read_link_frame(a));
    expect_resp(&v, "link_value")["link"].clone()
}

pub fn find_links_v(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<String> {
    addrs_of(&op(port, token, &find_links_frame(doc, from, width)))
}

pub fn count_v(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> u64 {
    let v = op(port, token, &format!(r#"{{"op":"count_v",{}}}"#, region(doc, from, width)));
    expect_resp(&v, "count")["n"].as_u64().expect("n")
}

/// The first page of `window_v` over the region (`cur: null`, `n: 16`).
pub fn window_v(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<String> {
    let v = op(
        port,
        token,
        &format!(r#"{{"op":"window_v","cur":null,"n":16,{}}}"#, region(doc, from, width)),
    );
    batch_of(&v)
}

/// The addresses of a `page` answer's batch.
pub fn batch_of(v: &Value) -> Vec<String> {
    expect_resp(v, "page")["window"]["batch"]
        .as_array()
        .expect("batch")
        .iter()
        .map(|a| a.as_str().expect("an address").to_string())
        .collect()
}

/// The `(slot, endset)` pairs of `retrieve_endsets` over the region.
pub fn endset_pairs(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<Value> {
    let v = op(port, token, &format!(r#"{{"op":"retrieve_endsets",{}}}"#, region(doc, from, width)));
    expect_resp(&v, "endsets")["pairs"].as_array().expect("pairs").clone()
}

pub fn find_docs_containing(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<String> {
    addrs_of(&op(
        port,
        token,
        &format!(r#"{{"op":"find_docs_containing","regions":[{}]}}"#, region_spec(doc, from, width)),
    ))
}

/// The links the delete of `width` positions at `p` in `doc` would orphan —
/// a preview, nothing written.
pub fn orphans_of(port: u16, token: Option<&str>, doc: &str, p: u64, width: u64) -> Vec<String> {
    let v = op(
        port,
        token,
        &format!(
            r#"{{"op":"delete_orphans","d":"{doc}","p":{{"subspace":"1","ordinal":"{p}"}},"width":"{width}"}}"#
        ),
    );
    expect_resp(&v, "orphans")["orphaned"]
        .as_array()
        .expect("orphaned")
        .iter()
        .map(|a| a.as_str().expect("an address").to_string())
        .collect()
}

fn claim_addrs(v: &Value) -> Vec<String> {
    expect_resp(v, "claims")["claims"]
        .as_array()
        .expect("claims")
        .iter()
        .map(|c| c["claim"].as_str().expect("claim").to_string())
        .collect()
}

/// The claims whose `old` is `y`, under `view`, as `token`.
pub fn claims_in(port: u16, token: Option<&str>, y: &str, view: &str) -> Vec<String> {
    claim_addrs(&op(port, token, &format!(r#"{{"op":"in_claims","view":"{view}","y":"{y}"}}"#)))
}

/// The claims whose `new` is `x`, under `view`, as `token`.
pub fn claims_out(port: u16, token: Option<&str>, x: &str, view: &str) -> Vec<String> {
    claim_addrs(&op(port, token, &format!(r#"{{"op":"out_claims","view":"{view}","x":"{x}"}}"#)))
}

/// The shared positions `compare` reports between content ordinals `1 ..
/// w1` of `d1` and `1 .. w2` of `d2`, expanded per position to
/// `(ordinal in d1, ordinal in d2)` — a statement about correspondence that
/// does not depend on how the report cuts its pairs.
pub fn compare_positions(
    port: u16,
    token: Option<&str>,
    d1: &str,
    w1: u64,
    d2: &str,
    w2: u64,
) -> BTreeSet<(u64, u64)> {
    let v = op(
        port,
        token,
        &format!(
            r#"{{"op":"compare","rho1":[{}],"rho2":[{}]}}"#,
            region_spec(d1, 1, w1),
            region_spec(d2, 1, w2)
        ),
    );
    let mut set = BTreeSet::new();
    for p in expect_resp(&v, "compare")["pairs"].as_array().expect("pairs") {
        let ordinal = |u: &Value| -> u64 {
            assert_eq!(u["subspace"].as_str(), Some("1"), "a content correspondence: {v}");
            u["ordinal"].as_str().expect("ordinal").parse().expect("a count")
        };
        let (u1, u2) = (ordinal(&p["u1"]), ordinal(&p["u2"]));
        let width: u64 = p["width"].as_str().expect("width").parse().expect("a count");
        for k in 0..width {
            set.insert((u1 + k, u2 + k));
        }
    }
    set
}

/// The correspondence of a shared PREFIX of `n` positions: ordinal `k` of
/// one document is ordinal `k` of the other.
pub fn shared_prefix(n: u64) -> BTreeSet<(u64, u64)> {
    (1..=n).map(|k| (k, k)).collect()
}

// ── links ────────────────────────────────────────────────────────────────

/// A one-spec V-spec array over content ordinals `from ..` of `doc`.
pub fn vspec(doc: &str, from: u64, width: u64) -> String {
    format!(r#"[{{"source":"{doc}","span":{{"start":"1.{from}","width":"0.{width}"}}}}]"#)
}

/// An address-form slot naming `addrs` verbatim.
pub fn addrs_slot(addrs: &[&str]) -> String {
    let quoted: Vec<String> = addrs.iter().map(|a| format!("\"{a}\"")).collect();
    format!(r#"{{"addrs":[{}]}}"#, quoted.join(","))
}

/// A ghost type under `home`'s never-occupied subspace 3, address-form.
pub fn ghost_ty(home: &str, n: u64) -> String {
    addrs_slot(&[&format!("{home}.0.3.6.{n}")])
}

/// `edit_link`'s content-RESOLVED successor type slot: `{"resolve":
/// [v-specs…]}` (wire.md §Operations, `edit_link`). The successor's `from`
/// and `to` are bare V-spec arrays, its `ty` an OBJECT naming exactly one of
/// `addrs`/`resolve` — a bare array there is `malformed`, unlike
/// `make_link`'s slots, where the bare array IS the resolve form.
pub fn resolve_slot(vspecs: &str) -> String {
    format!(r#"{{"resolve":{vspecs}}}"#)
}

/// `show_deletions` between `d_a` and `d_b`, both directions.
pub fn deletions_frame(d_a: &str, d_b: &str) -> String {
    format!(r#"{{"op":"show_deletions","d_a":"{d_a}","d_b":"{d_b}"}}"#)
}

/// `make_link` homed in `home`, each slot already JSON (a V-spec array or an
/// address form).
pub fn link_frame(home: &str, from: &str, to: &str, ty: &str) -> String {
    format!(r#"{{"op":"make_link","home":"{home}","from":{from},"to":{to},"ty":{ty}}}"#)
}

/// An address-form link of type `ty` homed in `home`.
pub fn typed_link_frame(home: &str, from: &[&str], to: &[&str], ty: &str) -> String {
    link_frame(home, &addrs_slot(from), &addrs_slot(to), &addrs_slot(&[ty]))
}

pub fn typed_link(port: u16, session: &str, home: &str, from: &[&str], to: &[&str], ty: &str) -> Value {
    op(port, Some(session), &typed_link_frame(home, from, to, ty))
}

/// An address-form link under a fresh ghost type `{home}.0.3.6.{n}`, empty
/// `from`/`to`; the link's address.
pub fn ghost_link(port: u16, session: &str, home: &str, n: u64) -> String {
    acked_addr(&op(port, Some(session), &link_frame(home, r#"{"addrs":[]}"#, r#"{"addrs":[]}"#, &ghost_ty(home, n))))
}

/// The shipped `retired` class's unary tuple over a ghost root under `home`
/// — the one class the open `emit` surface may write under standard genesis.
pub fn emit_frame(home: &str) -> String {
    format!(
        r#"{{"op":"emit","home":"{home}","ty":[{{"start":"1.1.0.1.0.1.0.1.3","width":"0.0.0.0.0.0.0.0.1"}}],"from":"{home}.0.3.9.1","to":[]}}"#
    )
}

pub fn nullify_frame(home: &str, target: &str) -> String {
    format!(r#"{{"op":"nullify","home":"{home}","target":"{target}"}}"#)
}

pub fn assert_sup_frame(home: &str, old: &str, new: &str) -> String {
    format!(r#"{{"op":"assert_sup","home":"{home}","new":"{new}","old":"{old}"}}"#)
}

/// `edit_link` of `original`: the successor homed in `d_s`, the claim in
/// `d_a`; the successor's `from` empty, its `to` and `ty` as given (JSON).
pub fn edit_link_frame(original: &str, d_s: &str, d_a: &str, to: &str, ty: &str) -> String {
    format!(
        r#"{{"op":"edit_link","original":"{original}","d_s":"{d_s}","d_a":"{d_a}","successor":{{"from":[],"to":{to},"ty":{ty}}}}}"#
    )
}

/// The unit span at `addr` — `enc([addr])`'s shape — as a one-span slot.
pub fn unit_span(addr: &str) -> String {
    let depth = addr.split('.').count();
    let width = format!("{}1", "0.".repeat(depth - 1));
    format!(r#"[{{"start":"{addr}","width":"{width}"}}]"#)
}

/// A four-set query frame for `op` (`find_links_ftt` / `count_ftt` /
/// `window_ftt`), each slot already JSON (`"any"`, `"empty"` or a span
/// array); the windowed form starts at `cur: null`.
pub fn ftt_frame(op_name: &str, home: &str, from: &str, to: &str, ty: &str) -> String {
    let cur = if op_name == "window_ftt" { r#""cur":null,"n":16,"# } else { "" };
    format!(r#"{{"op":"{op_name}",{cur}"q":{{"from":{from},"home":{home},"to":{to},"ty":{ty}}}}}"#)
}

/// The class scan over `ty` alone: `home`/`from`/`to` all `"any"`.
pub fn class_scan(op_name: &str, ty_addr: &str) -> String {
    ftt_frame(op_name, r#""any""#, r#""any""#, r#""any""#, &unit_span(ty_addr))
}

// ── history and the dump ─────────────────────────────────────────────────

/// One `/op-at` exchange presenting `token` (`None` = the guest).
pub fn op_at(port: u16, token: Option<&str>, at: u64, frame: &str) -> (u16, Value) {
    let body = format!(r#"{{"at":{at},"frame":{frame}}}"#);
    let (st, body) = http(port, "POST", "/op-at", token, body.as_bytes());
    (st, json(&body))
}

/// A `200` historical answer.
pub fn op_at_ok(port: u16, token: Option<&str>, at: u64, frame: &str) -> Value {
    let (st, v) = op_at(port, token, at, frame);
    assert_eq!(st, 200, "historical read failed at {at}: {v}");
    v
}

/// The `/dump` text at `token`'s class, live or as of `at`.
pub fn dump_text(port: u16, token: Option<&str>, at: Option<u64>) -> String {
    let path = match at {
        Some(n) => format!("/dump?at={n}"),
        None => "/dump".to_string(),
    };
    let (st, body) = http(port, "GET", &path, token, b"");
    assert_eq!(st, 200, "{path}: {}", String::from_utf8_lossy(&body));
    String::from_utf8(body).expect("a dump is UTF-8 text")
}

/// The end (exclusive) of the bracketed value opening at `open_at`, skipping
/// quoted strings — the dump's rendered maps and sequences nest.
fn matching_close(text: &str, open_at: usize) -> usize {
    let bytes = text.as_bytes();
    let (open, close) = match bytes[open_at] {
        b'{' => (b'{', b'}'),
        b'[' => (b'[', b']'),
        other => panic!("no bracket opens at {open_at}: {:?}", other as char),
    };
    let mut depth = 0usize;
    let mut in_str = false;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate().skip(open_at) {
        if in_str {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_str = false;
            }
            continue;
        }
        if b == b'"' {
            in_str = true;
        } else if b == open {
            depth += 1;
        } else if b == close {
            depth -= 1;
            if depth == 0 {
                return i + 1;
            }
        }
    }
    panic!("an unbalanced bracket at {open_at}")
}

/// The dump with its `authoritative.namespace` section cut out — the
/// identity section a draft's REGISTRATION lands in (existence is visible,
/// PUB-1.14), so what remains is the guest-readable projection proper:
/// content, arrangements, links, grants, hints and the publication slice.
pub fn without_namespace_section(dump: &str) -> String {
    let key = "\"namespace\": ";
    let start = dump.find(key).unwrap_or_else(|| panic!("the dump renders a namespace section:\n{dump}"));
    let end = matching_close(dump, start + key.len());
    let cut_from = if dump[..start].ends_with(", ") { start - 2 } else { start };
    format!("{}{}", &dump[..cut_from], &dump[end..])
}

/// The dump's PUBLICATION section: the draft addresses readable at the
/// dump's class, in address order.
///
/// The ROOT section — a SEQUENCE of dotted addresses, and the root map's
/// last key (`authoritative` < `grants` < `hints` < `publication`) — and NOT
/// M3's own `publication` MAP inside `authoritative.namespace`, which the
/// dump renders first and whose keys are bare tumblers (digit sequences, no
/// quotes): a forward search for `"publication": ` lands on that map and
/// splits it into nothing, which read every owner's slice as empty. The
/// sequence-opening form is unique to the root section (the map opens with
/// `{`, and `hints.publication.drafts` is a map under another key), and
/// `rfind` takes the last one.
pub fn publication_slice(dump: &str) -> Vec<String> {
    let key = "\"publication\": [";
    let start = dump.rfind(key).unwrap_or_else(|| panic!("the dump renders a publication section:\n{dump}"));
    let open = start + key.len() - 1;
    let end = matching_close(dump, open);
    dump[open + 1..end - 1]
        .split('"')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, s)| s.to_string())
        .collect()
}

// ── the claim ceremony, parameterized ────────────────────────────────────

/// Steps 1–4 of the claim ceremony (AUTH-5.55) for a FRESH top-level account
/// on an UNCLAIMED board: `delegate` from principal 0 at the next top-level
/// prefix, the home mint, the genesis record of `keys` (each with its anchor
/// flag) as one atom at doc 1's first ordinal, and the `T_ENROLL` link
/// naming it — a keyed PARTIAL, the claim (step 5) withheld.
pub fn seed_partial(port: u16, id: u64, keys: &[(&SigningKey, bool)]) -> Seat {
    let (account, session) = bootstrap_delegate(port, id);
    let doc1 = create_doc(port, &session, &account);
    let v = op(
        port,
        Some(&session),
        &format!(
            r#"{{"op":"insert","doc":"{doc1}","at":{{"subspace":"1","ordinal":"1"}},"values":[{{"atom":{}}}],"deposit":"{T_ENROLL}"}}"#,
            enroll_atom_flagged(keys)
        ),
    );
    let atom = acked_addr(&v);
    let v = typed_link(port, &session, &doc1, &[atom.as_str()], &[account.as_str()], T_ENROLL);
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "the genesis deposit of {account}: {v}");
    Seat { account, session, doc1 }
}

/// The claim ceremony's last step: the claim link in `doc1`, `from` the
/// claiming account, `to` empty, no payload.
pub fn claim_frame(doc1: &str, account: &str) -> String {
    typed_link_frame(doc1, &[account], &[], T_CLAIM)
}
