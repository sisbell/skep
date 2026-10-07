//! The recorded-evidence policies both passes apply. Each reads what the
//! scenario recorded about an op — the op's own post-state, or the next
//! probe of its document — to decide what the op did: which document a
//! doc-less insert aimed at, where an insert landed and how wide it was,
//! whether a delete removed anything and exactly what. The grounding
//! pre-pass and the translator call the same function, so the two cannot
//! disagree about what the evidence says; the field grammar both read the
//! evidence through is `fields`'s.

use serde_json::Value;

use crate::fields::{
    expect_strings, field, label_of, locate, resolve_position, span_dict, str_field,
};
use crate::shadow::Shadow;
use crate::tum::parse_dotted;

/// The next full-content probe of `doc` after op `i` (doc-field probes,
/// docs-map probes, and per-target `targets` entries — identity/
/// identity_multi_document_sharing records each created target's content
/// only inside a `targets` array).
pub fn next_content_probe(all: &[Value], i: usize, doc: &str, shadow: &Shadow) -> Option<String> {
    let content = |s: Vec<String>| -> Option<String> {
        if s.iter().any(|x| {
            (x.contains('.') && parse_dotted(x).is_some()) || crate::fields::is_python_repr(x)
        }) {
            None // an address string / client repr is not content
        } else {
            Some(s.join(""))
        }
    };
    for op in &all[i + 1..] {
        if let Some(map) = op.get("docs").and_then(Value::as_object) {
            for (name, exp) in map {
                if shadow.resolve_doc(name).as_deref() == Some(doc) {
                    if let Some(s) = expect_strings(exp).and_then(content) {
                        return Some(s);
                    }
                }
            }
        }
        if let Some(entries) = op.get("targets").and_then(Value::as_array) {
            for e in entries {
                let named = e
                    .get("docid")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| {
                        e.get("doc")
                            .and_then(Value::as_str)
                            .and_then(|n| shadow.resolve_doc(n))
                    });
                if named.as_deref() == Some(doc) {
                    if let Some(s) =
                        e.get("contents").and_then(expect_strings).and_then(content)
                    {
                        return Some(s);
                    }
                }
            }
        }
        let label = label_of(op).to_ascii_lowercase();
        if !(label.starts_with("content") || label.starts_with("retrieve")) {
            continue;
        }
        let target = str_field(op, &["doc", "docid"]).and_then(|s| shadow.resolve_doc(s));
        if target.as_deref() != Some(doc) {
            continue;
        }
        if let Some(v) = field(op, &["result", "content", "contents"]) {
            if let Some(s) = expect_strings(v).and_then(content) {
                return Some(s);
            }
        }
    }
    None
}

/// A doc-less insert's re-aim: the next recorded clean single-span vspanset
/// probe (before any other write) whose width equals ITS doc's current
/// extent plus this insert's length — the golden's own testimony of which
/// document the script inserted into (content/insert_vspace_mapping: the
/// register held the fresh version; the probe pins the original). Returns
/// the re-aimed doc only when it differs from `current`.
pub fn insert_aim_from_probe(
    all: &[Value],
    i: usize,
    shadow: &Shadow,
    current: &str,
    text: &str,
) -> Option<String> {
    let writes = ["insert", "append", "delete", "remove", "vcopy", "copy", "pivot", "swap",
        "rearrange"];
    for op in &all[i + 1..] {
        let label = label_of(op).to_ascii_lowercase();
        if writes.iter().any(|w| label.starts_with(w)) {
            return None; // another write intervenes — probe no longer pins this insert
        }
        let Some((_, docid, spans)) = crate::fields::harvest_spanset(op) else { continue };
        let Some(docref) =
            docid.or_else(|| str_field(op, &["doc", "docid"]).map(str::to_string))
        else {
            continue;
        };
        let Some(d) = shadow.resolve_doc(&docref) else { continue };
        let [(start, w)] = spans.as_slice() else { continue };
        if start != "1.1" {
            continue;
        }
        let Some(w) = crate::tum::parse_width(w) else { continue };
        if d != current && shadow.text_len(&d) + text.len() as u64 == w {
            return Some(d);
        }
        return None; // the probe is satisfied by the current aim (or ambiguous)
    }
    None
}

/// Recorded-vspanset width authority for an append-shaped insert: the doc's
/// (or an intervening version-of-the-doc's) next clean single-span vspanset
/// probe records `new_len + pad` for a small pad — the script inserted more
/// than the golden's text field carries. Returns the pad width.
///
/// DECLINED when links were seated between the insert and the probe: the
/// surplus is then udanax's version link CARRYOVER, not unrecorded text —
/// provenance/createnewversion_text_vs_links records 0.34 for a 33-char
/// insert, and its own whole-extent retrieve delivers 33 text chars PLUS
/// the link marker, proving position 34 is the carried link (rounds 4–6
/// padded a ghost space here, fabricating the one byte that made the
/// version-extent comparison agree; see `VERSION_LINK_CARRYOVER_ANALYSIS`).
pub fn insert_pad_width(
    all: &[Value],
    i: usize,
    shadow: &Shadow,
    doc: &str,
    new_len: u64,
) -> Option<u64> {
    let writes = ["insert", "append", "delete", "remove", "vcopy", "copy", "pivot", "swap",
        "rearrange"];
    let mut aliases: Vec<String> = vec![doc.to_string()];
    let mut links_seen = 0u64;
    for op in &all[i + 1..] {
        let label = label_of(op).to_ascii_lowercase();
        if label.starts_with("create_link") || label.starts_with("makelink") {
            links_seen += match field(op, &["result", "results"]) {
                Some(Value::Array(a)) => a.len() as u64,
                _ => 1,
            };
            continue;
        }
        if writes.iter().any(|w| label.starts_with(w)) {
            // A write into the doc ends the probe's authority over THIS
            // insert. A NAMED target that resolves elsewhere — or resolves
            // nowhere YET because it names a doc created between here and
            // there ("target" at scan time of versions/version_copies_link_
            // subspace op1) — is a write to another doc; only a doc-less or
            // alias-named write kills the scan.
            let raw = str_field(op, &["to", "dest", "target", "target_doc", "doc", "docid"]);
            let target = raw.and_then(|s| shadow.resolve_doc(s));
            match (raw, target) {
                (_, Some(t)) if !aliases.contains(&t) => continue,
                (Some(r), None) if !aliases.iter().any(|a| a.as_str() == r) => continue,
                _ => return None,
            }
        }
        if label.starts_with("create_version") || label.starts_with("version") {
            let src = str_field(op, &["from", "source", "of", "original"])
                .and_then(|s| shadow.resolve_doc(s));
            if src.as_deref() == Some(doc) || src.is_some_and(|s| aliases.contains(&s)) {
                if let Some(Value::String(res)) = field(op, &["result"]) {
                    aliases.push(res.clone());
                }
                aliases.push("version".to_string());
            }
            continue;
        }
        let Some((_, docid, spans)) = crate::fields::harvest_spanset(op) else { continue };
        let docref = docid
            .or_else(|| str_field(op, &["doc", "docid"]).map(str::to_string));
        let Some(docref) = docref else { continue };
        let matches = aliases.contains(&docref)
            || shadow.resolve_doc(&docref).is_some_and(|d| aliases.contains(&d));
        if !matches {
            continue;
        }
        let [(start, w)] = spans.as_slice() else { continue };
        if start != "1.1" {
            continue; // the malformed two-subspace pair never reaches here
        }
        let Some(w) = crate::tum::parse_width(w) else { continue };
        if w > new_len && w - new_len <= 2 {
            if links_seen > 0 {
                return None; // surplus = carried links, not unrecorded text
            }
            return Some(w - new_len);
        }
        return None; // clean probe consistent with (or below) the field text
    }
    None
}

/// A doc-less, position-less insert whose own recorded post-state shows the
/// text embedded MID-document: the position is recoverable as the single
/// gap where `post == pre[..k] + text + pre[k..]` — recorded post-state as
/// first authority (iaddress_allocation/interleaved_insert_delete's
/// insert_2 "BBB" turns "AA" into "ABBBA"). Returns the 1-based ordinal
/// only when the append shape does NOT already reproduce the post-state.
pub fn insert_pos_from_post_state(op: &Value, shadow: &Shadow, doc: &str, text: &str) -> Option<u64> {
    let v = field(op, &["result", "remaining", "expected_contents"])?;
    let strings = expect_strings(v)?;
    if strings.iter().any(|s| {
        (s.contains('.') && parse_dotted(s).is_some()) || crate::fields::is_python_repr(s)
    }) {
        return None;
    }
    let post = strings.join("");
    let pre = shadow.text_string(doc);
    if post.len() != pre.len() + text.len() || text.is_empty() {
        return None;
    }
    if post == format!("{pre}{text}") {
        return None; // the append shape already explains it
    }
    // Byte-level gap scan (no char-boundary slicing risk).
    let (p, t, q) = (post.as_bytes(), text.as_bytes(), pre.as_bytes());
    (0..=q.len())
        .find(|&k| p[..k] == q[..k] && p[k..k + t.len()] == *t && p[k + t.len()..] == q[k..])
        .map(|k| k as u64 + 1)
}

/// Was this delete a no-op in udanax? The doc's recorded post-delete content
/// equals its pre-delete content byte-for-byte (delete_all/delete_all_with_
/// links: `remove "entire document"` followed by a retrieve recording the
/// FULL text — udanax removed nothing, whatever the label claims). The
/// harness then also executes nothing, same family as `client-error:no-op`.
pub fn delete_is_noop(shadow: &Shadow, all: &[Value], i: usize, doc: &str) -> bool {
    let pre = shadow.text_string(doc);
    if pre.is_empty() {
        return false;
    }
    post_state_of(all, i, doc, shadow, &all[i]) == Some(pre)
}

/// The delete region in any of the goldens' shapes (dict span, decorated
/// span string, text, start+width/end/count), with the round-3 boundary
/// discipline: a numeric span (dict, start+width, positional description)
/// is what the client sent — authoritative. A TEXT-located span is a
/// reconstruction, and the recorded post-state, where present, tells
/// exactly what udanax removed (the whitespace-diff cluster: recorded
/// deletes took a boundary space the located text missed) — so the
/// post-state diff overrides it, and absent post-state the flanked-by-
/// spaces configuration widens by the trailing space. Returns
/// (ord, width, grounding tag).
pub fn resolve_delete_span(
    shadow: &Shadow,
    all: &[Value],
    i: usize,
    doc: &str,
    op: &Value,
) -> Option<(u64, u64, &'static str)> {
    if let Some((sub, ord, w)) = field(op, &["span", "vspan"]).and_then(span_dict) {
        return if sub == 1 { Some((ord, w, "explicit")) } else { None };
    }
    if let Some(start) = str_field(op, &["start", "address", "at"]) {
        if let Some((sub, ord, _)) = resolve_position(shadow, doc, start) {
            if sub != 1 {
                return None;
            }
            if let Some(w) = str_field(op, &["width"]).and_then(crate::tum::parse_width) {
                return Some((ord, w, "explicit"));
            }
            if let Some(e) = str_field(op, &["end"]) {
                return match parse_dotted(e)?.as_slice() {
                    [0, w] => Some((ord, *w, "explicit")),
                    [1, eord] if *eord >= ord => Some((ord, eord - ord, "explicit")),
                    _ => None,
                };
            }
            if let Some(n) = field(op, &["count"]).and_then(Value::as_u64) {
                return Some((ord, n, "explicit"));
            }
        }
    }
    // `removed`/`deleted` field: a V-position ("1.2" = one element) or an
    // inclusive range ("1.3-1.4") — the client's numeric record
    // (iaddress_allocation/interleaved_insert_delete).
    if let Some(r) = str_field(op, &["removed", "deleted"]) {
        if let Some((ord, w)) = removed_range(r) {
            return Some((ord, w, "explicit"));
        }
    }
    let pre = shadow.text_string(doc);
    let post = post_state_of(all, i, doc, shadow, op);
    if let Some(desc) = str_field(op, &["span", "vspan", "text"]) {
        if let Some(l) = locate(shadow, Some(doc), desc) {
            if l.how != "text-located" {
                // Numeric-precise description ("1.1 length 3", "1.3 for
                // 0.5", ranges): keep as sent.
                return Some((l.ord, l.width, "explicit"));
            }
            // A text-located span is a reconstruction; the recorded
            // post-state, where present, tells exactly what udanax removed.
            if let Some(post) = &post {
                if let Some((ord, w)) = single_gap_diff(pre.as_bytes(), post.as_bytes()) {
                    let tag = if (ord, w) == (l.ord, l.width) {
                        "text-located"
                    } else {
                        "delete-span-from-post-state"
                    };
                    return Some((ord, w, tag));
                }
            }
            let b = pre.as_bytes();
            let after = b.get((l.ord - 1 + l.width) as usize);
            let before = if l.ord >= 2 { b.get(l.ord as usize - 2) } else { None };
            if after == Some(&b' ') && (l.ord == 1 || before == Some(&b' ')) {
                return Some((l.ord, l.width + 1, "delete-span-widened-boundary"));
            }
            return Some((l.ord, l.width, "text-located"));
        }
    }
    // No groundable description at all: the recorded post-state is the
    // first authority (delete_A carries only its result.content), then a
    // label-borne text ("delete_A" removed "A") — round-5 item 9's
    // restored grounding order.
    if !pre.is_empty() {
        if let Some(post) = &post {
            if let Some((ord, w)) = single_gap_diff(pre.as_bytes(), post.as_bytes()) {
                return Some((ord, w, "delete-span-from-post-state"));
            }
        }
    }
    if let Some(t) = delete_text_from_label(op) {
        if let Some((_, ord)) = shadow.find_text(Some(doc), &t) {
            return Some((ord, t.len() as u64, "delete-text-from-label"));
        }
    }
    None
}

/// `removed`-field forms: "1.2" (V-position, one element) or "1.3-1.4"
/// (inclusive ordinal range) → (ordinal, width).
fn removed_range(s: &str) -> Option<(u64, u64)> {
    let s = s.trim();
    if let Some((ord, w)) = crate::fields::ordinal_range(s) {
        return Some((ord, w));
    }
    match crate::tum::parse_vpos(s) {
        Some((1, ord)) => Some((ord, 1)),
        _ => None,
    }
}

/// Label-borne deleted text, mirroring `insert_text`'s label grammar:
/// `delete_A` → "A" (iaddress_allocation/delete_does_not_affect_next_
/// insert). Descriptive tails (delete_all, delete_vspan…) carry no text.
fn delete_text_from_label(op: &Value) -> Option<String> {
    let label = label_of(op);
    let rest = label.strip_prefix("delete_").or_else(|| label.strip_prefix("remove_"))?;
    if rest.is_empty()
        || rest.contains('_')
        || matches!(rest, "all" | "vspan" | "text" | "attempt" | "loop")
    {
        return None;
    }
    Some(rest.to_string())
}

/// The doc's recorded content right after op `i`: the op's own post-write
/// keys, else the next full-content probe with no intervening write.
fn post_state_of(
    all: &[Value],
    i: usize,
    doc: &str,
    shadow: &Shadow,
    op: &Value,
) -> Option<String> {
    let content = |v: &Value| -> Option<String> {
        let s = expect_strings(v)?;
        if s.iter().any(|x| {
            (x.contains('.') && parse_dotted(x).is_some()) || crate::fields::is_python_repr(x)
        }) {
            return None;
        }
        Some(s.join(""))
    };
    // Own keys; "after" only in structured form — a bare string under
    // "after" is a phase label ("link1"), never content.
    let own = field(op, &["remaining", "result", "expected_contents"])
        .or_else(|| field(op, &["after"]).filter(|v| !v.is_string()));
    if let Some(v) = own {
        if let Some(s) = content(v) {
            return Some(s);
        }
    }
    let writes = ["insert", "delete", "remove", "vcopy", "copy", "pivot", "swap", "rearrange"];
    for later in &all[i + 1..] {
        let label = label_of(later).to_ascii_lowercase();
        if writes.iter().any(|w| label.starts_with(w)) {
            return None;
        }
        if let Some(map) = later.get("docs").and_then(Value::as_object) {
            for (name, exp) in map {
                if shadow.resolve_doc(name).as_deref() == Some(doc) {
                    if let Some(s) = content(exp) {
                        return Some(s);
                    }
                }
            }
        }
        if !(label.starts_with("content") || label.starts_with("retrieve")) {
            continue;
        }
        // A doc-less content probe targets the register — the same doc the
        // write did, per the scripts' scope discipline (delete_all_with_
        // links' post-remove retrieve carries no doc field).
        let probe_doc = str_field(later, &["doc", "docid"]).and_then(|s| shadow.resolve_doc(s));
        if probe_doc.is_some() && probe_doc.as_deref() != Some(doc) {
            continue;
        }
        // A narrowed read is not a whole-document post-state.
        if field(later, &["span", "spans", "specs", "specset", "positions", "address", "at"])
            .is_some()
        {
            continue;
        }
        // "after"-keyed replies count too (delete_all/delete_all_with_links
        // records its post-remove retrieve under "after"), structured only.
        let reply = field(later, &["result", "content", "contents"])
            .or_else(|| field(later, &["after"]).filter(|v| !v.is_string()));
        if let Some(v) = reply {
            if let Some(s) = content(v) {
                return Some(s);
            }
        }
    }
    None
}

/// A single contiguous deletion explaining pre → post: the longest common
/// prefix that leaves a matching suffix. `None` when no single gap explains
/// the difference (the delete then stays as located and diverges honestly).
fn single_gap_diff(pre: &[u8], post: &[u8]) -> Option<(u64, u64)> {
    if post.len() >= pre.len() {
        return None;
    }
    let width = pre.len() - post.len();
    let mut a = pre.iter().zip(post).take_while(|(x, y)| x == y).count();
    loop {
        if pre[a + width..] == post[a..] {
            return Some((a as u64 + 1, width as u64));
        }
        if a == 0 {
            return None;
        }
        a -= 1;
    }
}
