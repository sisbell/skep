//! The recorded-evidence policies both passes apply. Each reads what the
//! scenario recorded about an op — the op's own post-state, the next probe
//! of its document, or the follow just before it — to decide what the op
//! did: whether udanax made the change at all; where an insert or a vcopy
//! lands — the document a doc-less one aimed at, the position, how wide an
//! insert was; whether a delete removed anything and exactly what; what a
//! read read — a follow's landing, an extent narrower than the whole
//! document, the one place a per-document reply stands. The grounding
//! pre-pass and the play pass call the same function, so the two cannot
//! disagree about what the evidence says; the field grammar both read the
//! evidence through is `fields`'s.

use serde_json::Value;

use crate::fields::{
    as_text, client_side_failure, doc_from_op_name, expected_failure, field, insert_text,
    is_position_marker, locate, op_name, raw_spanset_of, reads_whole_content, recorded_content,
    resolve_position, span_dict, str_field, strings_of, target_replies, verb_of, CopySource,
    Grounding, PositionGrounding, Verb, CONTENT_READS, POST_WRITE_KEYS,
};
use crate::shadow::Shadow;
use crate::tum::{is_link_address, parse_dotted, parse_vpos, parse_width, VPoint, VRegion};

/// Did udanax make the change this op records? Not when the recording
/// client crashed before the op reached udanax ([`client_side_failure`]),
/// and not when the recording marks the op failed ([`expected_failure`]).
/// The one answer to the question both passes ask before an op changes the
/// golden-side world: the pre-pass applies an op exactly when this says
/// yes, and the play pass mirrors a write into its shadow, or lets a
/// creation enter it, exactly when this says yes.
pub fn took_effect(op: &Value) -> bool {
    client_side_failure(op).is_none() && expected_failure(op).is_none()
}

/// Did the recording make a version before op `i` — a `create_version`
/// udanax carried out ([`took_effect`])? Such a version is what a later
/// reference to "the version" names, whether or not skep made it too: one
/// skep refused to make leaves those references ungroundable (rulings 20,
/// 20a).
pub fn version_made_before(ops: &[Value], i: usize) -> bool {
    ops[..i].iter().any(|op| verb_of(op) == Some(Verb::CreateVersion) && took_effect(op))
}

/// What the recording says of the change an op asks for — the one input to
/// the shadow's mirror rule (`play`'s world-change methods).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// The recording says udanax made the change ([`took_effect`]).
    Made,
    /// It says udanax did not: the client crashed, or the op is recorded
    /// failed.
    NotMade,
    /// No recorded op made it: setup the grounding pre-pass inferred the
    /// script performed — golden-side by construction.
    Inferred,
}

impl Effect {
    /// What the recording says of `op`'s change.
    pub fn of(op: &Value) -> Effect {
        if took_effect(op) {
            Effect::Made
        } else {
            Effect::NotMade
        }
    }

    /// Does the golden-side world reflect the change?
    pub fn reaches_shadow(self) -> bool {
        matches!(self, Effect::Made | Effect::Inferred)
    }
}

/// The next full-content probe of `doc` after op `i` — a doc-field read of
/// the whole document, a docs-map probe, or a per-target `targets` entry
/// (identity/identity_multi_document_sharing records each created target's
/// content only inside a `targets` array) — its reply read as the play pass
/// compares it (`fields::recorded_content`, `fields::target_replies`).
pub fn next_content_probe(ops: &[Value], i: usize, shadow: &Shadow, doc: &str) -> Option<String> {
    let text = |v: &Value| strings_of(v).as_deref().and_then(as_text);
    for op in &ops[i + 1..] {
        if let Some(map) = op.get("docs").and_then(Value::as_object) {
            for (name, exp) in map {
                if shadow.resolve_doc(name).as_deref() == Some(doc) {
                    if let Some(s) = text(exp) {
                        return Some(s);
                    }
                }
            }
        }
        for (named, strings) in target_replies(op, shadow) {
            if named == doc {
                if let Some(s) = as_text(&strings) {
                    return Some(s);
                }
            }
        }
        if !reads_whole_content(op) {
            continue;
        }
        let target = str_field(op, &["doc", "docid"]).and_then(|s| shadow.resolve_doc(s));
        if target.as_deref() != Some(doc) {
            continue;
        }
        let reply = recorded_content(op, CONTENT_READS).map(|(_, strings)| strings);
        if let Some(s) = reply.as_deref().and_then(as_text) {
            return Some(s);
        }
    }
    None
}

/// A doc-less insert's re-aim: the next recorded clean single-span vspanset
/// probe (before any other write) whose width equals ITS doc's current
/// extent plus this insert's length `len` — the golden's own testimony of
/// which document the script inserted into (content/insert_vspace_mapping:
/// the register held the fresh version; the probe pins the original).
/// Returns the re-aimed doc only when it differs from `current`.
pub fn insert_aim_from_probe(
    ops: &[Value],
    i: usize,
    shadow: &Shadow,
    current: &str,
    len: u64,
) -> Option<String> {
    for op in &ops[i + 1..] {
        if verb_of(op).is_some_and(Verb::writes_content) {
            return None; // another write intervenes — probe no longer pins this insert
        }
        let Some((_, docid, spans)) = crate::fields::recorded_spanset(op) else { continue };
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
        if d != current && shadow.text_len(&d) + len == w {
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
    ops: &[Value],
    i: usize,
    shadow: &Shadow,
    doc: &str,
    new_len: u64,
) -> Option<u64> {
    let mut aliases: Vec<String> = vec![doc.to_string()];
    let mut links_seen = 0u64;
    for op in &ops[i + 1..] {
        let verb = verb_of(op);
        if verb == Some(Verb::CreateLink) {
            links_seen += match field(op, &["result", "results"]) {
                Some(Value::Array(a)) => a.len() as u64,
                _ => 1,
            };
            continue;
        }
        if verb.is_some_and(Verb::writes_content) {
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
        if verb == Some(Verb::CreateVersion) {
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
        let Some((_, docid, spans)) = crate::fields::recorded_spanset(op) else { continue };
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
pub fn insert_position_from_post_state(
    op: &Value,
    shadow: &Shadow,
    doc: &str,
    text: &str,
) -> Option<u64> {
    let post = as_text(&strings_of(field(op, POST_WRITE_KEYS)?)?)?;
    let pre = shadow.text_string(doc);
    if text.is_empty() || post == format!("{pre}{text}") {
        return None; // nothing inserted, or the append shape already explains it
    }
    insert_gap(pre.as_bytes(), text.as_bytes(), post.as_bytes())
}

/// The smallest 1-based ordinal `k + 1` with `post == pre[..k] + text +
/// pre[k..]` — `None` unless `post` is exactly `text` longer than `pre` —
/// a byte-level scan, so no char boundary is ever sliced. `k` is pinned
/// between the two common runs: `post[..k] == pre[..k]` holds exactly up to
/// their common prefix, and `post[k + |text|..] == pre[k..]` exactly from
/// where their common suffix begins, so only that window is scanned for
/// `text`.
fn insert_gap(pre: &[u8], text: &[u8], post: &[u8]) -> Option<u64> {
    if post.len() != pre.len() + text.len() {
        return None;
    }
    let prefix = post.iter().zip(pre).take_while(|(x, y)| x == y).count();
    // At most `pre`'s length: the zip stops at the shorter side.
    let suffix = post.iter().rev().zip(pre.iter().rev()).take_while(|(x, y)| x == y).count();
    (pre.len() - suffix..=prefix)
        .find(|&k| post[k..k + text.len()] == *text)
        .map(|k| k as u64 + 1)
}

/// Where an insert lands: the document — the op's own, or the one its next
/// recorded vspanset re-aims it at — the V-position it lands at, and the
/// bytes it places. `appended` = it lands at the document's end because
/// nothing positions it: no recorded position, and none its own post-state
/// pins.
#[derive(Debug, PartialEq, Eq)]
pub struct InsertLanding {
    pub doc: String,
    pub at: VPoint,
    pub bytes: Vec<u8>,
    pub appended: bool,
}

/// Insert op `i` of `ops`, aimed at golden `doc`, read as both passes read
/// it: its text (a field, a strings array, or its name — policy
/// `args-from-op-name`); a re-aim, when it names no document and the next
/// recorded vspanset shows another document grew by exactly its text
/// ([`insert_aim_from_probe`], `insert-aim-from-recorded-vspanset`); its
/// position — recorded ([`resolve_position`], the grounding policy
/// tagged), pinned by its own post-state ([`insert_position_from_post_state`],
/// `insert-position-from-post-state`), else the end (`position-end`); and,
/// when it appends or lands in an empty document, the pad
/// [`insert_pad_width`] reads off the recorded vspanset
/// (`insert-padded-to-recorded-vspanset:+N`). Every policy applied is
/// pushed to `adaptations`. `Err` names what cannot be read: a missing text,
/// or a recorded position this grammar cannot ground.
pub fn resolve_insert(
    ops: &[Value],
    i: usize,
    shadow: &Shadow,
    doc: &str,
    adaptations: &mut Vec<String>,
) -> Result<InsertLanding, String> {
    let op = &ops[i];
    let mut text = insert_text(op).ok_or("insert without text")?;
    if str_field(op, &["text"]).is_none() && op_name(op).starts_with("insert_") {
        adaptations.push("args-from-op-name".into());
    }
    let mut doc = doc.to_string();
    if str_field(op, &["doc", "docid"]).is_none() && doc_from_op_name(op_name(op)).is_none() {
        if let Some(aimed) = insert_aim_from_probe(ops, i, shadow, &doc, text.len() as u64) {
            adaptations.push("insert-aim-from-recorded-vspanset".into());
            doc = aimed;
        }
    }
    let (at, appended) = match str_field(op, &["address", "at", "position", "vaddr"]) {
        Some(p) => {
            let (at, how) = resolve_position(shadow, &doc, p)
                .ok_or_else(|| format!("insert position `{p}` is not groundable"))?;
            adaptations.extend(how.map(|how| how.tag().to_string()));
            (at, false)
        }
        None => match insert_position_from_post_state(op, shadow, &doc, &text) {
            Some(ord) => {
                adaptations.push("insert-position-from-post-state".into());
                (VPoint::content(ord), false)
            }
            None => {
                adaptations.push("position-end".into());
                (VPoint::content(shadow.text_len(&doc) + 1), true)
            }
        },
    };
    if at.sub == 1 && (appended || shadow.text_len(&doc) == 0) {
        let new_len = shadow.text_len(&doc) + text.len() as u64;
        if let Some(pad) = insert_pad_width(ops, i, shadow, &doc, new_len) {
            adaptations.push(format!("insert-padded-to-recorded-vspanset:+{pad}"));
            text.push_str(&" ".repeat(pad as usize));
        }
    }
    Ok(InsertLanding { doc, at, bytes: text.into_bytes(), appended })
}

/// The document vcopy op `i` of `ops` copies into, its `sources` read by
/// `fields::vcopy_sources`, as both passes read it: its
/// `to`/`dest`/`target`/`target_doc` reference — a position marker
/// ("end", "end of doc") naming the first source's document
/// (edgecases/vcopy_to_same_document's self-transclusion) — else its
/// `doc`/`docid` reference; else the document whose next content probe
/// holds the copied bytes, one other than the first source's preferred
/// (`vcopy-dest-from-evidence`: endsets/endsets_transcluded_source copies
/// into a second document the register never pointed at). `Ok(None)` when
/// nothing names or evidences one: each pass aims by its own `doc_arg`.
/// `Err` carries a recorded reference that resolves to nothing, which no
/// pass re-aims.
pub fn vcopy_destination(
    ops: &[Value],
    i: usize,
    shadow: &Shadow,
    sources: &[CopySource],
    adaptations: &mut Vec<String>,
) -> Result<Option<String>, String> {
    let op = &ops[i];
    let first_source = sources.first().map(|s| s.doc.as_str());
    let named = |r: &str| {
        let dest = shadow.resolve_doc(r);
        dest.map(Some).ok_or_else(|| format!("vcopy destination `{r}` resolves to nothing"))
    };
    if let Some(r) = str_field(op, &["to", "dest", "target", "target_doc"]) {
        if is_position_marker(r) {
            return Ok(first_source.map(str::to_string));
        }
        return named(r);
    }
    if let Some(r) = str_field(op, &["doc", "docid"]) {
        return named(r);
    }
    let copied: Vec<u8> = sources
        .iter()
        .filter(|s| s.region.sub == 1)
        .flat_map(|s| shadow.slice(&s.doc, s.region.ord, s.region.width))
        .collect();
    if copied.is_empty() {
        return Ok(None); // no bytes, so no probe can hold them
    }
    let copied_text = String::from_utf8_lossy(&copied).into_owned();
    let evidenced: Vec<&String> = shadow
        .created()
        .iter()
        .filter(|d| next_content_probe(ops, i, shadow, d).is_some_and(|p| p.contains(&copied_text)))
        .collect();
    let aimed = evidenced
        .iter()
        .find(|d| Some(d.as_str()) != first_source)
        .or_else(|| evidenced.first())
        .map(|d| d.to_string());
    if aimed.is_some() {
        adaptations.push("vcopy-dest-from-evidence".into());
    }
    Ok(aimed)
}

/// The content ordinal vcopy `op` copies to in golden `dest`, as both
/// passes read it: a recorded `address`/`at`/`position`, grounded against
/// the shadow and tagged with how ([`resolve_position`]); else a `to`
/// beginning "start" — ordinal 1 (`position-start`); else `Ok(None)`, the
/// destination's end (`position-end`), which each pass reads off its own
/// shadow. `Err` names a recorded position this grammar cannot ground in
/// the content subspace.
pub fn vcopy_ordinal(
    op: &Value,
    shadow: &Shadow,
    dest: &str,
    adaptations: &mut Vec<String>,
) -> Result<Option<u64>, String> {
    if let Some(p) = str_field(op, &["address", "at", "position"]) {
        return match resolve_position(shadow, dest, p) {
            Some((VPoint { sub: 1, ord }, how)) => {
                adaptations.extend(how.map(|how| how.tag().to_string()));
                Ok(Some(ord))
            }
            _ => Err(format!("vcopy position `{p}` is not groundable")),
        };
    }
    let to = str_field(op, &["to", "dest", "target", "target_doc"]);
    if to.is_some_and(|s| s.trim().to_ascii_lowercase().starts_with("start")) {
        adaptations.push("position-start".into());
        return Ok(Some(1));
    }
    adaptations.push("position-end".into());
    Ok(None)
}

/// The landing a doc-less read right after a follow reads (policy
/// `retrieve-follow-landing`): when op `i` names no document and no
/// `full_*` name makes it a whole-document read, and the op before it is a
/// follow or a traversal whose recorded result is a vspec, the document and
/// the regions that vspec names — the link destination the script had just
/// followed (links/follow_link op 8), never the register's document. `None`
/// when the shape does not apply. The one reading both passes aim such a
/// read by.
pub fn follow_landing(ops: &[Value], i: usize) -> Option<(String, Vec<VRegion>)> {
    let op = &ops[i];
    let full = op_name(op).to_ascii_lowercase().starts_with("full_");
    if full || str_field(op, &["doc", "docid"]).is_some() {
        return None;
    }
    let prev = ops.get(i.checked_sub(1)?)?;
    if !matches!(verb_of(prev), Some(Verb::FollowLink | Verb::Traverse)) {
        return None;
    }
    let (docid, spans) = raw_spanset_of(field(prev, &["result"])?)?;
    let regions: Vec<VRegion> = spans
        .iter()
        .map(|(start, w)| Some(parse_vpos(start)?.region(parse_width(w)?)))
        .collect::<Option<_>>()?;
    (!regions.is_empty()).then_some((docid?, regions))
}

/// The narrower extent a whole-document read's recorded reply shows the
/// script read (policy `read-scoped-to-recorded-extent`): the length of the
/// reply's text, when it falls one or two positions short of `doc`'s content
/// in the shadow — the recorded reality — and that content opens with the
/// reply's first text: the script's specset was that much narrower than the
/// document (provenance/createnewversion_text_vs_links reads 33 of 34). A
/// larger shortfall is a world that diverged, never a narrower read. Link
/// addresses in the reply count no text. `None` when the read is the whole
/// document.
pub fn scoped_read(recorded: &[String], shadow: &Shadow, doc: &str) -> Option<u64> {
    let n = shadow.text_len(doc);
    let text: Vec<&String> = recorded.iter().filter(|s| !is_link_address(s)).collect();
    let text_len = text.iter().map(|s| s.len() as u64).sum::<u64>();
    let held = shadow.text_string(doc);
    let opens = text.first().is_some_and(|first| held.starts_with(first.as_str()));
    let short = text_len > 0 && text_len < n && n - text_len <= 2;
    (short && held.len() as u64 >= text_len && opens).then_some(text_len)
}

/// The region a per-document reply was read at, when it narrows (policy
/// `read-span-from-recorded-strings`): its one recorded string — nonempty,
/// no link address, other than `doc`'s whole content — found in the shadow,
/// the script's unrecorded specset reconstructed golden-side
/// (internal/ispan_partial_overlap's `source: ["CDEFG"]`). `None` when the
/// reply is read against the whole document.
pub fn reply_narrowing(recorded: &[String], shadow: &Shadow, doc: &str) -> Option<VRegion> {
    let [s] = recorded else { return None };
    if s.is_empty() || is_link_address(s) || *s == shadow.text_string(doc) {
        return None;
    }
    let (_, ord) = shadow.find_text(Some(doc), s)?;
    Some(VPoint::content(ord).region(s.len() as u64))
}

/// Was this delete a no-op in udanax? The doc's recorded post-delete content
/// equals its pre-delete content byte-for-byte (delete_all/delete_all_with_
/// links: `remove "entire document"` followed by a retrieve recording the
/// FULL text — udanax removed nothing, whatever the op's name claims). The
/// harness then also executes nothing, same family as `client-error:no-op`.
pub fn delete_is_noop(ops: &[Value], i: usize, shadow: &Shadow, doc: &str) -> bool {
    let pre = shadow.text_string(doc);
    if pre.is_empty() {
        return false;
    }
    post_state_of(ops, i, shadow, doc) == Some(pre)
}

/// How a delete's region was read, and so what authority its position
/// carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeleteGrounding {
    /// Numbers the recording client sent as numbers: a span dict, a start
    /// V-position with its width / end / count, or a `removed` range.
    Sent,
    /// Numbers the recording client sent in words — "1.1 length 3", "1.3
    /// for 0.5", an ordinal range — read by the description grammar
    /// ([`Grounding::Span`], [`Grounding::Range`]).
    Described(Grounding),
    /// A start the recording described — "end", "position 6", "after X" —
    /// grounded against the shadow, with its width / end / count sent.
    DescribedStart(PositionGrounding),
    /// A text description located in the shadow (a reconstruction); the
    /// recorded post-state, where there is one, agrees with it.
    Located(Grounding),
    /// The recorded post-state's single-gap diff: exactly what udanax
    /// removed.
    FromPostState,
    /// A located text widened by the boundary space the scripts' deletes
    /// took with it.
    WidenedBoundary,
    /// The text a `delete_A` op's name carries, located in the shadow.
    FromOpName,
}

impl DeleteGrounding {
    /// The adaptation tag the report records; a region sent as numbers
    /// carries none.
    pub fn tag(self) -> Option<&'static str> {
        match self {
            DeleteGrounding::Sent => None,
            DeleteGrounding::Described(g) | DeleteGrounding::Located(g) => Some(g.tag()),
            DeleteGrounding::DescribedStart(how) => Some(how.tag()),
            DeleteGrounding::FromPostState => Some("delete-span-from-post-state"),
            DeleteGrounding::WidenedBoundary => Some("delete-span-widened-boundary"),
            DeleteGrounding::FromOpName => Some("delete-text-from-op-name"),
        }
    }

    /// Is the region's position pinned — sent, in numbers or in words, a
    /// start described by number or by the document's bounds, or read off
    /// the recorded post-state — rather than found by searching the shadow
    /// for text? An undo reinserts a pinned delete's bytes at its recorded
    /// ordinal first; a text-found one at the end first (a seed prefix
    /// shifts an append-built document's text rightward).
    pub fn position_pinned(self) -> bool {
        match self {
            DeleteGrounding::Sent
            | DeleteGrounding::Described(_)
            | DeleteGrounding::FromPostState
            | DeleteGrounding::WidenedBoundary => true,
            DeleteGrounding::DescribedStart(how) => !how.is_text(),
            DeleteGrounding::Located(_) | DeleteGrounding::FromOpName => false,
        }
    }
}

/// Delete op `i` of `ops`'s content region in golden `doc`, in any of the
/// goldens' shapes (dict span, decorated span string, text,
/// start+width/end/count), with the round-3 boundary discipline: a numeric
/// span — a dict, a start with its width, end or count, a positional
/// description — is what the client sent, authoritative, a start it
/// described ("end", "after X") grounded against the shadow and tagged with
/// how ([`DeleteGrounding::DescribedStart`]). A TEXT-located span is a
/// reconstruction, and the
/// recorded post-state, where present, tells exactly what udanax removed
/// (the whitespace-diff cluster: recorded deletes took a boundary space the
/// located text missed) — so the post-state diff overrides it, and absent
/// post-state the flanked-by-spaces configuration widens by the trailing
/// space. Returns the region and how it was read.
pub fn resolve_delete_span(
    ops: &[Value],
    i: usize,
    shadow: &Shadow,
    doc: &str,
) -> Option<(VRegion, DeleteGrounding)> {
    use DeleteGrounding::{
        Described, DescribedStart, FromOpName, FromPostState, Located, Sent, WidenedBoundary,
    };
    let op = &ops[i];
    let content = |ord: u64, width: u64| VPoint::content(ord).region(width);
    if let Some(region) = field(op, &["span", "vspan"]).and_then(span_dict) {
        return (region.sub == 1).then_some((region, Sent));
    }
    if let Some(start) = str_field(op, &["start", "address", "at"]) {
        if let Some((at, how)) = resolve_position(shadow, doc, start) {
            if at.sub != 1 {
                return None;
            }
            let grounded = how.map_or(Sent, DescribedStart);
            if let Some(w) = str_field(op, &["width"]).and_then(crate::tum::parse_width) {
                return Some((at.region(w), grounded));
            }
            if let Some(e) = str_field(op, &["end"]) {
                return match parse_dotted(e)?.as_slice() {
                    [0, w] => Some((at.region(*w), grounded)),
                    [1, eord] if *eord >= at.ord => Some((at.region(eord - at.ord), grounded)),
                    _ => None,
                };
            }
            if let Some(n) = field(op, &["count"]).and_then(Value::as_u64) {
                return Some((at.region(n), grounded));
            }
        }
    }
    // `removed`/`deleted` field: a V-position ("1.2" = one element) or an
    // inclusive range ("1.3-1.4") — the client's numeric record
    // (iaddress_allocation/interleaved_insert_delete).
    if let Some(r) = str_field(op, &["removed", "deleted"]) {
        if let Some(region) = removed_range(r) {
            return Some((region, Sent));
        }
    }
    let pre = shadow.text_string(doc);
    let post = post_state_of(ops, i, shadow, doc);
    if let Some(desc) = str_field(op, &["span", "vspan", "text"]) {
        if let Some(l) = locate(shadow, Some(doc), desc) {
            if !l.how.is_text() {
                // Numeric-precise description ("1.1 length 3", "1.3 for
                // 0.5", ranges): numbers sent in words, kept as sent.
                return Some((l.region(), Described(l.how)));
            }
            // A text-located span is a reconstruction; the recorded
            // post-state, where present, tells exactly what udanax removed.
            if let Some(post) = &post {
                if let Some(removed) = single_gap_diff(pre.as_bytes(), post.as_bytes()) {
                    let how = if removed == l.region() { Located(l.how) } else { FromPostState };
                    return Some((removed, how));
                }
            }
            let b = pre.as_bytes();
            let after = b.get((l.ord - 1 + l.width) as usize);
            let before = if l.ord >= 2 { b.get(l.ord as usize - 2) } else { None };
            if after == Some(&b' ') && (l.ord == 1 || before == Some(&b' ')) {
                return Some((content(l.ord, l.width + 1), WidenedBoundary));
            }
            return Some((l.region(), Located(l.how)));
        }
    }
    // No groundable description at all: the recorded post-state is the
    // first authority (delete_A carries only its result.content), then a
    // text the op's name carries ("delete_A" removed "A") — round-5 item
    // 9's restored grounding order.
    if !pre.is_empty() {
        if let Some(post) = &post {
            if let Some(removed) = single_gap_diff(pre.as_bytes(), post.as_bytes()) {
                return Some((removed, FromPostState));
            }
        }
    }
    if let Some(t) = delete_text_from_op_name(op) {
        if let Some((_, ord)) = shadow.find_text(Some(doc), &t) {
            return Some((content(ord, t.len() as u64), FromOpName));
        }
    }
    None
}

/// `removed`-field forms: "1.2" (V-position, one element) or "1.3-1.4"
/// (inclusive ordinal range) → the content region they name.
fn removed_range(s: &str) -> Option<VRegion> {
    let s = s.trim();
    if let Some((ord, width)) = crate::fields::ordinal_range(s) {
        return Some(VPoint::content(ord).region(width));
    }
    match parse_vpos(s) {
        Some(at @ VPoint { sub: 1, .. }) => Some(at.region(1)),
        _ => None,
    }
}

/// Deleted text carried by the op's name, mirroring `insert_text`'s
/// grammar: `delete_A` → "A" (iaddress_allocation/delete_does_not_affect_
/// next_insert). Descriptive tails (delete_all, delete_vspan…) carry no
/// text.
fn delete_text_from_op_name(op: &Value) -> Option<String> {
    let name = op_name(op);
    let rest = name.strip_prefix("delete_").or_else(|| name.strip_prefix("remove_"))?;
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
fn post_state_of(ops: &[Value], i: usize, shadow: &Shadow, doc: &str) -> Option<String> {
    let op = &ops[i];
    let content = |v: &Value| strings_of(v).as_deref().and_then(as_text);
    // Own keys; "after" only in structured form — a bare string under
    // "after" is a phase name ("link1"), never content.
    let own =
        field(op, POST_WRITE_KEYS).or_else(|| field(op, &["after"]).filter(|v| !v.is_string()));
    if let Some(v) = own {
        if let Some(s) = content(v) {
            return Some(s);
        }
    }
    for later in &ops[i + 1..] {
        if verb_of(later).is_some_and(Verb::writes_content) {
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
        // A narrowed read is not a whole-document post-state.
        if !reads_whole_content(later) {
            continue;
        }
        // A doc-less content probe targets the register — the same doc the
        // write did, per the scripts' scope discipline (delete_all_with_
        // links' post-remove retrieve carries no doc field).
        let probe_doc = str_field(later, &["doc", "docid"]).and_then(|s| shadow.resolve_doc(s));
        if probe_doc.is_some() && probe_doc.as_deref() != Some(doc) {
            continue;
        }
        // The reply, read as the play pass compares it
        // (`fields::recorded_content`): under "after" (delete_all/
        // delete_all_with_links' post-remove retrieve), stringified by the
        // recording client (rearrange_semantics/pivot_v3_*).
        let reply = recorded_content(later, CONTENT_READS).map(|(_, strings)| strings);
        if let Some(s) = reply.as_deref().and_then(as_text) {
            return Some(s);
        }
    }
    None
}

/// A single contiguous deletion explaining pre → post, as the content
/// region it removed: the longest common prefix that leaves a matching
/// suffix. `None` when no single gap explains the difference (the delete
/// then stays as located and diverges honestly). Only the longest common
/// prefix is tried: a suffix that matches from an earlier start matches
/// from every later one, so a gap that fails there fails everywhere.
fn single_gap_diff(pre: &[u8], post: &[u8]) -> Option<VRegion> {
    if post.len() >= pre.len() {
        return None;
    }
    let width = pre.len() - post.len();
    let a = pre.iter().zip(post).take_while(|(x, y)| x == y).count();
    (pre[a + width..] == post[a..]).then(|| VPoint::content(a as u64 + 1).region(width as u64))
}

#[cfg(test)]
mod tests;
