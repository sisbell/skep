//! The verb an op's name reads as — the canonical verbs, the stem table read
//! in order, the meta names and their observation escape — the one reading
//! both passes dispatch on.

use serde_json::Value;

use super::{
    arrow_results, field, looks_like_spanset, op_name, position_from_op_name, strings_of,
    ANNOTATION_KEYS,
};
use crate::tum::is_link_address;

/// The canonical verb an op's name reads as — the one reading of "what kind
/// of op is this" both passes dispatch on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    CreateDocument,
    CreateDocuments,
    CreateChain,
    Setup,
    OpenDocument,
    CloseDocument,
    Insert,
    InsertLoop,
    InteriorTyping,
    Delete,
    DeleteAll,
    Vcopy,
    Pivot,
    Swap,
    Rearrange,
    CreateVersion,
    CreateLink,
    FollowLink,
    Traverse,
    FindLinks,
    FindDocuments,
    RetrieveContents,
    RetrieveVspan,
    RetrieveVspanset,
    RetrieveEndsets,
    CompareVersions,
    Account,
    CreateNode,
    Connect,
    Observe,
    Meta,
}

impl Verb {
    pub fn name(self) -> &'static str {
        match self {
            Verb::CreateDocument => "create_document",
            Verb::CreateDocuments => "create_documents",
            Verb::CreateChain => "create_chain",
            Verb::Setup => "setup",
            Verb::OpenDocument => "open_document",
            Verb::CloseDocument => "close_document",
            Verb::Insert => "insert",
            Verb::InsertLoop => "insert_loop",
            Verb::InteriorTyping => "interior_typing",
            Verb::Delete => "delete",
            Verb::DeleteAll => "delete_all",
            Verb::Vcopy => "vcopy",
            Verb::Pivot => "pivot",
            Verb::Swap => "swap",
            Verb::Rearrange => "rearrange",
            Verb::CreateVersion => "create_version",
            Verb::CreateLink => "create_link",
            Verb::FollowLink => "follow_link",
            Verb::Traverse => "traverse",
            Verb::FindLinks => "find_links",
            Verb::FindDocuments => "find_documents",
            Verb::RetrieveContents => "retrieve_contents",
            Verb::RetrieveVspan => "retrieve_vspan",
            Verb::RetrieveVspanset => "retrieve_vspanset",
            Verb::RetrieveEndsets => "retrieve_endsets",
            Verb::CompareVersions => "compare_versions",
            Verb::Account => "account",
            Verb::CreateNode => "create_node",
            Verb::Connect => "connect",
            Verb::Observe => "observe",
            Verb::Meta => "meta",
        }
    }

    /// Does an op of this verb change a document's content subspace?
    pub fn writes_content(self) -> bool {
        matches!(
            self,
            Verb::Insert
                | Verb::InsertLoop
                | Verb::InteriorTyping
                | Verb::Delete
                | Verb::DeleteAll
                | Verb::Vcopy
                | Verb::Pivot
                | Verb::Swap
                | Verb::Rearrange
        )
    }
}

/// The verb an op's own name reads as — [`normalize`] over the op, the one
/// reading every forward scan asks "what kind of op is this" through.
pub fn verb_of(op: &Value) -> Option<Verb> {
    normalize(op_name(op), op)
}

/// Does this op read a document's whole content: a
/// [`Verb::RetrieveContents`] read that no span, spec set or position
/// narrows — by a field, or by its name's own position tokens
/// ("text_at_1_3", "pos_1_4", "link_at_2_1")? Only such a read testifies to
/// everything a document holds.
pub fn reads_whole_content(op: &Value) -> bool {
    const NARROWING: &[&str] =
        &["span", "spans", "vspan", "specs", "specset", "positions", "address", "at", "position"];
    verb_of(op) == Some(Verb::RetrieveContents)
        && field(op, NARROWING).is_none()
        && position_from_op_name(op_name(op)).is_none()
}

/// The meta/diagnostic op names (per the brief): executed nothing, compared
/// nothing, counted separately — UNLESS the op carries observation data
/// (a vspanset/contents bundle), in which case it is an [`Verb::Observe`]
/// probe (internal/interior_typing_two_characters's `initial_state`).
const META: &[&str] = &[
    "snapshot", "dump_state", "verify", "setup", "analysis", "note", "summary", "initial_state",
    "final_state",
];

/// Longest-matching verb stem, checked in table order (specific before
/// general — `vspanset` before `vspan`, `delete_all` before `delete`).
const STEMS: &[(&str, Verb)] = &[
    ("create_node", Verb::CreateNode),
    ("create_chain", Verb::CreateChain),
    ("create_and_transclude", Verb::Vcopy),
    ("create_documents", Verb::CreateDocuments),
    ("create_document", Verb::CreateDocument),
    ("create_doc", Verb::CreateDocument),
    ("create_sources", Verb::CreateDocuments),
    ("create_target", Verb::CreateDocument),
    ("create_multiple_targets", Verb::CreateDocuments),
    ("open_document", Verb::OpenDocument),
    ("close_document", Verb::CloseDocument),
    ("create_version", Verb::CreateVersion),
    ("version", Verb::CreateVersion),
    ("create_links", Verb::CreateLink),
    ("create_link", Verb::CreateLink),
    ("makelink", Verb::CreateLink),
    ("interior_typing", Verb::InteriorTyping),
    ("insert_loop", Verb::InsertLoop),
    ("insert", Verb::Insert),
    ("append", Verb::Insert),
    ("delete_all", Verb::DeleteAll),
    ("remove_all", Verb::DeleteAll),
    ("delete", Verb::Delete),
    ("remove", Verb::Delete),
    ("vcopy", Verb::Vcopy),
    ("copy", Verb::Vcopy),
    ("pivot", Verb::Pivot),
    ("swap", Verb::Swap),
    ("rearrange", Verb::Rearrange),
    ("reverse_traversal", Verb::Traverse),
    ("traverse", Verb::Traverse),
    ("follow_links", Verb::Traverse),
    ("follow_link", Verb::FollowLink),
    ("find_links", Verb::FindLinks),
    ("links_", Verb::FindLinks),
    ("links", Verb::FindLinks),
    ("find_documents", Verb::FindDocuments),
    ("find_docs", Verb::FindDocuments),
    // A roster of the documents a setup made, `{op: "docs", A: id, …}`
    // (isolation/cross_document_transclusion_isolation) — see `roster`.
    ("docs", Verb::CreateDocuments),
    ("retrieve_vspanset", Verb::RetrieveVspanset),
    ("vspanset", Verb::RetrieveVspanset),
    ("retrieve_vspan", Verb::RetrieveVspan),
    ("vspan", Verb::RetrieveVspan),
    ("retrieve_endsets", Verb::RetrieveEndsets),
    ("endsets", Verb::RetrieveEndsets),
    ("retrieve_contents", Verb::RetrieveContents),
    ("retrieve", Verb::RetrieveContents),
    ("contents", Verb::RetrieveContents),
    ("content", Verb::RetrieveContents),
    ("text_at", Verb::RetrieveContents),
    ("pos_", Verb::RetrieveContents),
    ("link_at", Verb::RetrieveContents),
    ("full_text", Verb::RetrieveContents),
    ("full_content", Verb::RetrieveContents),
    ("compare", Verb::CompareVersions),
    ("comparisons", Verb::CompareVersions),
    ("account", Verb::Account),
    ("connect", Verb::Connect),
    // The new-corpus checkpoint op: vspanset+contents bundle, or a bare
    // failed probe of a never-created doc (error field only).
    ("probe", Verb::Observe),
];

/// Does the op carry observation data (a probe bundle)? A vspanset or
/// contents field, a docs map, a targets list or a positions map does; so
/// does a reply-shaped `result`/`before`/`after`/`empty`, and a string array
/// under any key that is no annotation — a snapshot's `A_content`
/// (isolation/cross_document_transclusion_isolation) is an observation of
/// document A, not commentary.
pub fn has_observation_fields(op: &Value) -> bool {
    let Some(o) = op.as_object() else { return false };
    for (k, v) in o {
        match k.as_str() {
            "vspanset" | "vspans" | "contents" | "content" | "positions" | "docs" | "targets" => {
                return true
            }
            "result" | "before" | "after" | "empty"
                if strings_of(v).is_some() || looks_like_spanset(v) =>
            {
                return true;
            }
            k if !ANNOTATION_KEYS.contains(&k)
                && v.as_array().is_some_and(|a| a.iter().all(Value::is_string)) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

/// Normalize an op's name to a canonical verb: meta list (with the
/// observation-bundle escape), then the stem table, then a field-shape
/// fallback for pure state-probe names. `None` ⇒ inexpressible.
pub fn normalize(op_name: &str, op: &Value) -> Option<Verb> {
    let l = op_name.to_ascii_lowercase();
    if l == "setup" {
        return Some(Verb::Setup);
    }
    if META.iter().any(|m| l == *m || l.starts_with(&format!("{m}_"))) {
        return Some(if has_observation_fields(op) { Verb::Observe } else { Verb::Meta });
    }
    for (stem, verb) in STEMS {
        if l.starts_with(stem) {
            return Some(*verb);
        }
    }
    if !arrow_results(op).is_empty() {
        return Some(Verb::CreateLink);
    }
    // Shape fallback for unknown probe names.
    if let Some(res) = op.get("result") {
        if looks_like_spanset(res) {
            return Some(Verb::RetrieveVspanset);
        }
        if let Some(arr) = res.as_array() {
            if !arr.is_empty() && arr.iter().all(|v| v.as_str().is_some_and(is_link_address))
            {
                return Some(Verb::FindLinks);
            }
            if arr.iter().all(|v| v.as_str().is_some()) {
                return Some(Verb::RetrieveContents);
            }
        }
    }
    if has_observation_fields(op) {
        return Some(Verb::Observe);
    }
    None
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// A meta-named op that carries an observation — a string array under a
    /// key no annotation holds, a docs map, a reply-shaped result — is a probe;
    /// one that carries none stays meta.
    #[test]
    fn a_meta_named_op_that_carries_an_observation_is_a_probe() {
        let verb = |op: Value| normalize(op_name(&op), &op);
        assert_eq!(verb(json!({"op": "snapshot", "A_content": ["X"]})), Some(Verb::Observe));
        assert_eq!(verb(json!({"op": "dump_state", "docs": {"A": ["X"]}})), Some(Verb::Observe));
        assert_eq!(verb(json!({"op": "verify", "result": ["X"]})), Some(Verb::Observe));
        let commented = json!({"op": "snapshot", "comment": "before the delete"});
        assert_eq!(verb(commented), Some(Verb::Meta));
        assert_eq!(verb(json!({"op": "summary", "counts": {"links": 2}})), Some(Verb::Meta));
    }

    /// The stem table reads in order, so a stem that starts with an earlier one
    /// would never be reached: none is shadowed, and each reads as its own verb.
    #[test]
    fn no_verb_stem_is_shadowed_by_an_earlier_one() {
        for (i, (stem, verb)) in STEMS.iter().enumerate() {
            let shadowing = STEMS[..i].iter().find(|(earlier, _)| stem.starts_with(earlier));
            assert_eq!(shadowing, None, "stem `{stem}` is shadowed");
            assert_eq!(normalize(stem, &json!({ "op": stem })), Some(*verb), "stem `{stem}`");
        }
    }
}
