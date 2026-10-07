//! The description grammar: a recorded description — a position, a span, a
//! range, a text with its occurrence or its document — grounded against the
//! shadow, never guessed.
//!
//! Decoration grammar (each form calibrated against named golden files):
//! * `"end"` / `"start"` / `"position 6"` / `"after First"` — positions
//!   (internal/insert_only_baseline, versions/version_insert_in_middle,
//!   discovery/insert_multiple_times_accumulates_docispan).
//! * `"1.1 length 3"` — span (edgecases/delete_first_char,
//!   delete_all/delete_all_incrementally).
//! * `"1.16-1.20"` — a bare inclusive ordinal range (links/delete_at_root_
//!   origin_height_1).
//! * `"quick (5-9)"` / `"ABCD (1-4)"` — text with inclusive ordinal range
//!   (content/retrieve_noncontiguous_spans, edgecases/overlapping_vcopy).
//! * `"1-char span at 1.1"` — width + position (edgecases/
//!   link_zero_width_endpoints).
//! * `"just 'S'"` / `"first occurrence of 'text' (1.10-1.13)"` — quoted text
//!   (edgecases/vcopy_single_char, internal/internal_transclusion_with_link).
//! * `"source:here"` — doc-qualified text (versions/version_with_links).
//! * `"doc1[1.2-1.4]"` — doc-qualified range (subspace/
//!   insert_text_check_link_positions).
//! * `"all of B"` / `"all"` / `"full document"` — whole extent (content/
//!   nested_vcopy, spanfilade/delete_all_transcluded_content,
//!   links/overlapping_links).
//! * `"bank (first)"` / `"shared (transcluded)"` — text with a descriptive
//!   parenthetical, stripped (links/overlapping_links_different_targets,
//!   endsets/endsets_transcluded_source); `"DEF (from C)"` — the
//!   parenthetical names the document (identity/identity_partial_transclusion).

use super::DocSpans;
use crate::shadow::Shadow;
use crate::tum::{parse_dotted, parse_vpos, parse_width, VPoint, VRegion};

/// How a description grounded to a region. A TEXT grounding found the
/// described bytes by searching the shadow — a reconstruction, which
/// recorded evidence may correct (a delete's post-state diff); every other
/// grounding is numbers the recording client sent, which stand as sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Grounding {
    /// The described text, found verbatim, doc-qualified, or quoted.
    Text,
    /// The Nth occurrence of the described text ("bank (second)").
    NthText,
    /// A numeric span: "1.1 length 3", "1.3 for 0.5", "1-char span at 1.1".
    Span,
    /// An inclusive ordinal range: "1.16-1.20", "positions 1-4",
    /// "doc1[1.2-1.4]", "quick (5-9)".
    Range,
    /// A document's whole current extent: "all", "all of B", "entire …".
    WholeExtent,
}

impl Grounding {
    /// The adaptation tag the report records for this grounding.
    pub fn tag(self) -> &'static str {
        match self {
            Grounding::Text => "text-located",
            Grounding::NthText => "text-located:nth-occurrence",
            Grounding::Span => "span-from-description",
            Grounding::Range => "range-from-description",
            Grounding::WholeExtent => "whole-extent",
        }
    }

    /// Is the region a text reconstruction rather than numbers sent?
    pub fn is_text(self) -> bool {
        matches!(self, Grounding::Text | Grounding::NthText)
    }
}

/// A located region: golden doc + 1-based content ordinal + width.
#[derive(Clone, Debug)]
pub struct Located {
    pub doc: String,
    pub ord: u64,
    pub width: u64,
    /// How the description grounded.
    pub how: Grounding,
}

impl Located {
    /// The located content-subspace region — a description grounds in the
    /// content subspace only.
    pub fn region(&self) -> VRegion {
        VPoint::content(self.ord).region(self.width)
    }

    /// The located region as one document side of a spec.
    pub fn into_side(self) -> DocSpans {
        let region = self.region();
        (self.doc, vec![region])
    }
}

/// Resolve a decorated span/text description against the shadow. `doc_hint`
/// narrows the search when the caller knows the document. Never guesses: a
/// description this grammar cannot ground returns `None` and the caller
/// classifies the op inexpressible with the text recorded.
pub fn locate(shadow: &Shadow, doc_hint: Option<&str>, desc: &str) -> Option<Located> {
    let desc = desc.trim();

    // Plain text, found verbatim — the common case; try before any grammar.
    if let Some((doc, ord)) = shadow.find_text(doc_hint, desc) {
        return Some(Located { doc, ord, width: desc.len() as u64, how: Grounding::Text });
    }

    // "S.O length N" (delete_first_char).
    if let Some((pos, len)) = desc.split_once(" length ") {
        if let (Some(VPoint { sub: 1, ord }), Ok(w)) =
            (parse_vpos(pos.trim()), len.trim().parse::<u64>())
        {
            let doc = doc_hint.map(str::to_string).or_else(|| shadow.current())?;
            return Some(Located { doc, ord, width: w, how: Grounding::Span });
        }
    }

    // "1.3 for 0.5 (CDEFG)" — the client's own "S for W" span idiom with an
    // optional reminder parenthetical (isolation/delete_does_not_affect_
    // other_documents). Numeric, so it counts as sent, never reconstructed.
    {
        let core = desc.split(" (").next().unwrap_or(desc).trim();
        if let Some((pos, w)) = core.split_once(" for ") {
            if let (Some(VPoint { sub: 1, ord }), Some(w)) =
                (parse_vpos(pos.trim()), parse_width(w.trim()))
            {
                if w > 0 {
                    let doc = doc_hint.map(str::to_string).or_else(|| shadow.current())?;
                    return Some(Located { doc, ord, width: w, how: Grounding::Span });
                }
            }
        }
    }

    // "1.16-1.20" — a bare inclusive ordinal range (links/delete_at_root_
    // origin_height_1's create_link `source` and `target`).
    if let Some((ord, w)) = ordinal_range(desc) {
        let doc = doc_hint.map(str::to_string).or_else(|| shadow.current())?;
        return Some(Located { doc, ord, width: w, how: Grounding::Range });
    }

    // "positions 1-4 (Orig)" — explicit ordinal range with a reminder
    // parenthetical (edgecases/vcopy_to_same_document's `from`).
    {
        let core = desc.split(" (").next().unwrap_or(desc).trim();
        if let Some(r) =
            core.strip_prefix("positions ").or_else(|| core.strip_prefix("position "))
        {
            if let Some((ord, w)) = ordinal_range(r.trim()) {
                let doc = doc_hint.map(str::to_string).or_else(|| shadow.current())?;
                return Some(Located { doc, ord, width: w, how: Grounding::Range });
            }
        }
    }

    // "N-char span at S.O" (link_zero_width_endpoints).
    if let Some(idx) = desc.find("-char span at ") {
        let n = desc[..idx].trim().parse::<u64>().ok()?;
        let ord = parse_vpos(desc[idx + "-char span at ".len()..].trim())?.ord;
        let doc = doc_hint.map(str::to_string).or_else(|| shadow.current())?;
        return Some(Located { doc, ord, width: n.max(1), how: Grounding::Span });
    }

    // "doc[A-B]" bracket range (insert_text_check_link_positions) and the
    // single-position form "doc1[1.2]" (createlink_check_text_positions) —
    // one content ordinal, width 1.
    if let Some((docref, rest)) = desc.split_once('[') {
        if let Some(range) = rest.strip_suffix(']') {
            if let Some(doc) = shadow.resolve_doc(docref.trim()) {
                if let Some((ord, w)) = ordinal_range(range) {
                    return Some(Located { doc, ord, width: w, how: Grounding::Range });
                }
                if let Some(VPoint { sub: 1, ord }) = parse_vpos(range.trim()) {
                    return Some(Located { doc, ord, width: 1, how: Grounding::Range });
                }
            }
        }
    }

    // "doc:text" qualified text (version_with_links "source:here").
    if let Some((docref, text)) = desc.split_once(':') {
        if let Some(doc) = shadow.resolve_doc(docref.trim()) {
            let t = text.trim();
            if let Some((d, ord)) = shadow.find_text(Some(&doc), t) {
                return Some(Located { doc: d, ord, width: t.len() as u64, how: Grounding::Text });
            }
        }
    }

    // "all of B" / "all" / "full document" / "entire …" — whole extent.
    let whole = |doc: String| -> Option<Located> {
        let n = shadow.text_len(&doc);
        if n == 0 {
            return None;
        }
        Some(Located { doc, ord: 1, width: n, how: Grounding::WholeExtent })
    };
    if let Some(rest) = desc.strip_prefix("all of ") {
        if let Some(doc) = shadow.resolve_doc(rest.trim()) {
            return whole(doc);
        }
    }
    if desc == "all" || desc == "full document" || desc.starts_with("entire") {
        let doc = doc_hint.map(str::to_string).or_else(|| shadow.current())?;
        return whole(doc);
    }

    // Trailing parenthetical: "text (5-9)" range, "text (from C)" doc
    // qualifier, "bank (second)" occurrence selector, or descriptive junk
    // to strip ("shared (transcluded)").
    if let Some(open) = desc.rfind('(') {
        if desc.ends_with(')') {
            let head = desc[..open].trim();
            let inner = &desc[open + 1..desc.len() - 1];
            if let Some((ord, w)) = ordinal_range(inner) {
                let doc = doc_hint
                    .map(str::to_string)
                    .or_else(|| shadow.find_text(None, head).map(|(d, _)| d))
                    .or_else(|| shadow.current())?;
                // The explicit range is authoritative; the head text is a
                // reminder (retrieve_noncontiguous_spans "quick (5-9)").
                return Some(Located { doc, ord, width: w, how: Grounding::Range });
            }
            if let Some(docref) = inner.strip_prefix("from ") {
                if let Some(doc) = shadow.resolve_doc(docref.trim()) {
                    if let Some((d, ord)) = shadow.find_text(Some(&doc), head) {
                        return Some(Located {
                            doc: d,
                            ord,
                            width: head.len() as u64,
                            how: Grounding::Text,
                        });
                    }
                }
            }
            // "(first)" / "(second)" / "(first, same span)" — an occurrence
            // selector, honored, not stripped: round 3 landed every
            // "bank (second)" on the FIRST occurrence, giving
            // overlapping_links_different_targets a third overlapping link.
            if let Some(n) = occurrence_of(inner) {
                if !head.is_empty() {
                    if let Some((d, ord)) = shadow.find_text_nth(doc_hint, head, n) {
                        return Some(Located {
                            doc: d,
                            ord,
                            width: head.len() as u64,
                            how: Grounding::NthText,
                        });
                    }
                    return None; // selector present but unsatisfiable
                }
            }
            if !head.is_empty() {
                if let Some((d, ord)) = shadow.find_text(doc_hint, head) {
                    return Some(Located {
                        doc: d,
                        ord,
                        width: head.len() as u64,
                        how: Grounding::Text,
                    });
                }
            }
        }
    }

    // Quoted text anywhere: "just 'S'", "first occurrence of 'text' (…)".
    if let Some(q) = quoted(desc) {
        if let Some((d, ord)) = shadow.find_text(doc_hint, &q) {
            return Some(Located { doc: d, ord, width: q.len() as u64, how: Grounding::Text });
        }
    }

    None
}

/// An occurrence-selector parenthetical's ordinal: "first" → 1,
/// "first, same span" → 1, "second" → 2 … `None` for anything else.
fn occurrence_of(inner: &str) -> Option<u64> {
    let word = inner.split([',', ' ']).next()?.trim().to_ascii_lowercase();
    match word.as_str() {
        "first" => Some(1),
        "second" => Some(2),
        "third" => Some(3),
        "fourth" => Some(4),
        "fifth" => Some(5),
        _ => None,
    }
}

/// "5-9" or "1.5-1.9" inclusive ordinal range → (start ordinal, width).
pub fn ordinal_range(s: &str) -> Option<(u64, u64)> {
    let (a, b) = s.split_once('-')?;
    let pv = |x: &str| -> Option<u64> {
        let x = x.trim();
        match parse_dotted(x)?.as_slice() {
            [o] => Some(*o),
            [1, o] => Some(*o),
            _ => None,
        }
    };
    let (start, end) = (pv(a)?, pv(b)?);
    if end >= start && start > 0 {
        Some((start, end - start + 1))
    } else {
        None
    }
}

/// First 'single'- or "double"-quoted segment.
pub fn quoted(s: &str) -> Option<String> {
    for q in ['\'', '"'] {
        if let Some(i) = s.find(q) {
            if let Some(j) = s[i + 1..].find(q) {
                let inner = &s[i + 1..i + 1 + j];
                if !inner.is_empty() {
                    return Some(inner.to_string());
                }
            }
        }
    }
    None
}

/// How a described position grounded: the forms of position a recording
/// describes rather than sends as a V-position ([`resolve_position`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PositionGrounding {
    /// "end" / "append": one past the document's content.
    End,
    /// "start" / "beginning": the first content position.
    Start,
    /// "position N": content ordinal N.
    Numbered,
    /// "after X": just past the text X, found in the shadow.
    AfterText,
    /// "before X": at the text X, found in the shadow.
    BeforeText,
}

impl PositionGrounding {
    /// The adaptation tag the report records for this grounding.
    pub fn tag(self) -> &'static str {
        match self {
            PositionGrounding::End => "position-end",
            PositionGrounding::Start => "position-start",
            PositionGrounding::Numbered => "position-from-description",
            PositionGrounding::AfterText => "position-after-text",
            PositionGrounding::BeforeText => "position-before-text",
        }
    }

    /// Was the position found by searching the shadow for text — a
    /// reconstruction — rather than read from a number or the document's
    /// bounds?
    pub fn is_text(self) -> bool {
        matches!(self, PositionGrounding::AfterText | PositionGrounding::BeforeText)
    }
}

/// A position description → the V-position it names and how it grounded,
/// against the shadow when relative; an explicit V-position carries no
/// grounding, being what the client sent. `None` = not a position this
/// grammar speaks.
pub fn resolve_position(
    shadow: &Shadow,
    doc: &str,
    desc: &str,
) -> Option<(VPoint, Option<PositionGrounding>)> {
    use PositionGrounding::{AfterText, BeforeText, End, Numbered, Start};
    let desc = desc.trim();
    if let Some(at) = parse_vpos(desc) {
        return Some((at, None));
    }
    let content = |ord: u64, how: PositionGrounding| Some((VPoint::content(ord), Some(how)));
    match desc {
        "end" | "append" => return content(shadow.text_len(doc) + 1, End),
        "start" | "beginning" => return content(1, Start),
        _ => {}
    }
    if let Some(n) = desc.strip_prefix("position ").and_then(|x| x.trim().parse::<u64>().ok()) {
        return content(n, Numbered);
    }
    if let Some(t) = desc.strip_prefix("after ") {
        let t = t.trim();
        if let Some((_, ord)) = shadow.find_text(Some(doc), t) {
            return content(ord + t.len() as u64, AfterText);
        }
        // Case-insensitive fallback: descriptions say "after first" for "First ".
        if let Some((_, ord, w)) = shadow.find_text_ignoring_case(doc, t) {
            return content(ord + w, AfterText);
        }
    }
    if let Some(t) = desc.strip_prefix("before ") {
        if let Some((_, ord)) = shadow.find_text(Some(doc), t.trim()) {
            return content(ord, BeforeText);
        }
    }
    None
}
