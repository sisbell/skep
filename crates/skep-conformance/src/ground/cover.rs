//! Expansion-plan covers: a destination's probed content rebuilt as insert
//! and copy steps — from the scenario's recorded comparison pairs where they
//! pin each shared region exactly, else greedily from the source documents'
//! text — and the forward scans that decide whether an append-shaped vcopy
//! needs such a plan at all. Each reads the shadow and the recorded ops,
//! never the simulation's state.

use serde_json::Value;

use super::{held_range, SetupStep};
use crate::fields::{field, insert_text, reads_whole_content, span_dict, str_field, verb_of, Verb};
use crate::shadow::Shadow;
use crate::tum::VRegion;

/// The shortest run a cover copies: a shared run below it is filler text.
const MIN_COPY: usize = 4;

/// Greedy cover of `expected` by substrings of the sources (copies, ≥
/// [`MIN_COPY`] chars) with literal fillers between — the reconstruction of
/// an unrecorded insert/vcopy interleaving. Verified downstream by the
/// scenario's own compare/find ops. A matched copy never keeps trailing
/// whitespace (round-3: content/vcopy_from_multiple_documents's own
/// comparisons record width 8 "Source A" where the greedy match took
/// "Source A " — the scripts copied word-shaped regions and joined with
/// literal separators), so the maximal match is trimmed back to its last
/// non-space byte before it drops below the copy floor. Each source's text
/// is rendered once for the whole cover.
pub(super) fn cover_with_sources(
    shadow: &Shadow,
    dest: &str,
    sources: &[String],
    expected: &str,
) -> Vec<SetupStep> {
    let e = expected.as_bytes();
    let texts: Vec<(&String, String)> =
        sources.iter().map(|src| (src, shadow.text_string(src))).collect();
    let mut steps: Vec<SetupStep> = Vec::new();
    let mut filler: Vec<u8> = Vec::new();
    let mut i = 0usize;
    while i < e.len() {
        let mut best: Option<(String, u64, usize)> = None; // (src, ord, len)
        for (src, text) in &texts {
            if let Some((ord, mut len)) = longest_occurring_prefix(text.as_bytes(), &e[i..]) {
                while len > MIN_COPY && e[i + len - 1].is_ascii_whitespace() {
                    len -= 1;
                }
                if best.as_ref().is_none_or(|(_, _, bl)| len > *bl) {
                    best = Some(((*src).clone(), ord, len));
                }
            }
        }
        match best {
            Some((src, ord, len)) => {
                if !filler.is_empty() {
                    steps.push(SetupStep::Insert {
                        doc: dest.to_string(),
                        bytes: std::mem::take(&mut filler),
                    });
                }
                steps.push(SetupStep::Copy { doc: dest.to_string(), src, ord, width: len as u64 });
                i += len;
            }
            None => {
                filler.push(e[i]);
                i += 1;
            }
        }
    }
    if !filler.is_empty() {
        steps.push(SetupStep::Insert { doc: dest.to_string(), bytes: filler });
    }
    steps
}

/// The longest prefix of `needle`, [`MIN_COPY`] bytes or more, that occurs
/// in `text`, as (the 1-based ordinal of its first occurrence, its length).
/// Whether a prefix occurs is monotone in its length — every prefix of an
/// occurring prefix occurs — so the length is found by bisection, each
/// probe one scan of `text`.
fn longest_occurring_prefix(text: &[u8], needle: &[u8]) -> Option<(u64, usize)> {
    let first = |len: usize| text.windows(len).position(|w| *w == needle[..len]);
    let (mut lo, mut hi) = (MIN_COPY, needle.len().min(text.len()));
    if hi < lo {
        return None;
    }
    first(lo)?;
    // `lo` occurs; the longest prefix that does lies in [lo, hi].
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if first(mid).is_some() {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    first(lo).map(|p| (p as u64 + 1, lo))
}

/// Does a later vcopy/copy op (before `dest`'s next content probe) also
/// build `dest`? Guard for the full pair-cover strategy.
pub(super) fn later_copy_into(all: &[Value], i: usize, dest: &str, shadow: &Shadow) -> bool {
    for op in &all[i + 1..] {
        if verb_of(op) != Some(Verb::Vcopy) {
            continue;
        }
        let target = str_field(op, &["to", "dest", "target", "target_doc", "doc", "docid"])
            .and_then(|s| shadow.resolve_doc(s));
        if target.as_deref() == Some(dest) || target.is_none() {
            return true; // an unaimed later copy is conservatively a builder
        }
    }
    false
}

/// The concatenated text of the recorded APPEND edits into `dest` between
/// op `i` and `dest`'s next content probe — the probe suffix those later
/// ops will contribute. `None` when any later edit into `dest` is not a
/// derivable append (position args, deletes, rearranges, underivable copy
/// text) — the caller then skips the copy-extension heuristic.
pub(super) fn later_appends_text(
    all: &[Value],
    i: usize,
    dest: &str,
    shadow: &Shadow,
) -> Option<String> {
    let mut out = String::new();
    for op in &all[i + 1..] {
        if reads_whole_content(op) {
            let target = str_field(op, &["doc", "docid"]).and_then(|s| shadow.resolve_doc(s));
            if target.as_deref() == Some(dest) {
                return Some(out); // reached the probe
            }
        }
        let verb = verb_of(op);
        if !verb.is_some_and(Verb::writes_content) {
            continue;
        }
        let target = str_field(op, &["to", "dest", "target", "target_doc", "doc", "docid"])
            .and_then(|s| shadow.resolve_doc(s));
        if target.as_deref() != Some(dest) {
            continue; // a write to another doc
        }
        let positioned = str_field(op, &["address", "at", "position", "vaddr"]).is_some();
        if positioned || verb != Some(Verb::Insert) {
            return None; // not a derivable append into dest
        }
        out.push_str(&insert_text(op)?);
    }
    Some(out)
}

/// One recorded shared-span evidence pair — the scenario's own testimony
/// that `width` content positions of `src` from `src_ord` landed in `dest`
/// at `dest_ord`. Ordered field by field, in declaration order: among the
/// pairs of one destination, by where each landed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct SharedPair {
    pub(super) dest: String,
    pub(super) dest_ord: u64,
    pub(super) src: String,
    pub(super) src_ord: u64,
    pub(super) width: u64,
}

/// Harvest every recorded comparison pair in the scenario, both shapes:
/// entries `{source: "A", shared: [{target: {…}, source: {…}}]}` inside a
/// results/comparisons array (content/vcopy_from_multiple_documents — the
/// dest is the scenario's target-role doc), and compare ops whose `label`
/// field is `"<x>_vs_<y>"` and whose top-level `shared` items key the sides
/// `a`/`b` positionally (identity/identity_mixed_sources).
pub(super) fn comparison_pairs(all: &[Value], shadow: &Shadow) -> Vec<SharedPair> {
    let mut out: Vec<SharedPair> = Vec::new();
    for op in all {
        if verb_of(op) != Some(Verb::CompareVersions) {
            continue;
        }
        if let Some(entries) = field(op, &["results", "comparisons"]).and_then(Value::as_array) {
            let dest = shadow.resolve_doc("target").or_else(|| shadow.current());
            for entry in entries {
                let (Some(dest), Some(src)) = (
                    dest.clone(),
                    entry.get("source").and_then(Value::as_str).and_then(|s| shadow.resolve_doc(s)),
                ) else {
                    continue;
                };
                let Some(shared) = entry.get("shared").and_then(Value::as_array) else { continue };
                for item in shared {
                    let tgt = item.get("target").and_then(span_dict);
                    let ssp = item.get("source").and_then(span_dict);
                    if let (
                        Some(VRegion { sub: 1, ord: dest_ord, width }),
                        Some(VRegion { sub: 1, ord: src_ord, width: src_width }),
                    ) = (tgt, ssp)
                    {
                        if width == src_width {
                            out.push(SharedPair {
                                dest: dest.clone(),
                                dest_ord,
                                src: src.clone(),
                                src_ord,
                                width,
                            });
                        }
                    }
                }
            }
            continue;
        }
        // A "<x>_vs_<y>" `label` field + top-level shared, sides keyed a/b.
        if let Some((dx, dy)) = str_field(op, &["label"])
            .and_then(|l| l.split_once("_vs_"))
            .and_then(|(x, y)| Some((shadow.resolve_doc(x)?, shadow.resolve_doc(y)?)))
        {
            let Some(shared) = field(op, &["shared"]).and_then(Value::as_array) else { continue };
            for item in shared {
                let a = item.get("a").and_then(span_dict);
                let b = item.get("b").and_then(span_dict);
                if let (
                    Some(VRegion { sub: 1, ord: dest_ord, width }),
                    Some(VRegion { sub: 1, ord: src_ord, width: src_width }),
                ) = (a, b)
                {
                    if width == src_width {
                        out.push(SharedPair {
                            dest: dx.clone(),
                            dest_ord,
                            src: dy.clone(),
                            src_ord,
                            width,
                        });
                    }
                }
            }
            continue;
        }
        // Named sides with docids inline or resolvable key names
        // (content/vcopy_multiple_spans: items keyed source/target with
        // docid+span dicts; versions/cross_version_vcopy: items keyed
        // original/version with bare span dicts). Direction is unknowable
        // here, so BOTH orientations are emitted; consumers filter by their
        // destination and verify bytes, so a wrong orientation never binds.
        let Some(shared) =
            field(op, &["shared", "result", "shared_spans", "pairs"]).and_then(Value::as_array)
        else {
            continue;
        };
        for item in shared {
            let Some(io) = item.as_object() else { continue };
            let sides: Vec<(String, VRegion)> = io
                .iter()
                .filter_map(|(k, v)| {
                    let (docref, region) = if let Some(region) = span_dict(v) {
                        (k.as_str(), region)
                    } else {
                        let o = v.as_object()?;
                        let d = o.get("docid").and_then(Value::as_str);
                        let sp = o.get("span").or_else(|| {
                            o.get("spans").and_then(Value::as_array).and_then(|a| a.first())
                        })?;
                        (d.unwrap_or(k.as_str()), span_dict(sp)?)
                    };
                    if region.sub != 1 {
                        return None;
                    }
                    Some((shadow.resolve_doc(docref)?, region))
                })
                .collect();
            if let [(da, a), (db, b)] = sides.as_slice() {
                if a.width == b.width && da != db {
                    let pair = |dest: &String, d: &VRegion, src: &String, s: &VRegion| SharedPair {
                        dest: dest.clone(),
                        dest_ord: d.ord,
                        src: src.clone(),
                        src_ord: s.ord,
                        width: d.width,
                    };
                    out.push(pair(da, a, db, b));
                    out.push(pair(db, b, da, a));
                }
            }
        }
    }
    out
}

/// Evidence-driven cover: when the scenario's later comparisons record
/// exactly which (source, span) each shared region came from and where it
/// landed in `dest`, build the plan from THOSE pairs — the minimal cover
/// consistent with the recorded widths. Every pair is verified byte-for-byte
/// against the sources and the expected text; any mismatch abandons the
/// evidence path (caller falls back to the greedy cover).
pub(super) fn cover_from_comparisons(
    shadow: &Shadow,
    dest: &str,
    expected: &str,
    all: &[Value],
) -> Option<Vec<SetupStep>> {
    let mut pairs: Vec<SharedPair> =
        comparison_pairs(all, shadow).into_iter().filter(|p| p.dest == dest).collect();
    if pairs.is_empty() {
        return None;
    }
    pairs.sort();
    let e = expected.as_bytes();
    let mut steps: Vec<SetupStep> = Vec::new();
    let mut at = 0usize; // 0-based cursor into expected
    for SharedPair { dest_ord, src, src_ord, width, .. } in pairs {
        // Out-of-range evidence — an ordinal 0, an end past the probe's —
        // or a region overlapping the last abandons the evidence path.
        let landed = held_range(e.len(), dest_ord, width).filter(|r| r.start >= at)?;
        let src_bytes = shadow.slice(&src, src_ord, width);
        if src_bytes != e[landed.clone()] {
            return None; // evidence disagrees with the probe text
        }
        if landed.start > at {
            let filler = e[at..landed.start].to_vec();
            steps.push(SetupStep::Insert { doc: dest.to_string(), bytes: filler });
        }
        steps.push(SetupStep::Copy { doc: dest.to_string(), src, ord: src_ord, width });
        at = landed.end;
    }
    if at < e.len() {
        steps.push(SetupStep::Insert { doc: dest.to_string(), bytes: e[at..].to_vec() });
    }
    Some(steps)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every string over {A, B} up to `max` bytes, shortest first.
    fn strings(max: usize) -> Vec<Vec<u8>> {
        let mut all = vec![Vec::new()];
        for len in 1..=max {
            for bits in 0..1u32 << len {
                all.push((0..len).map(|k| if bits >> k & 1 == 0 { b'A' } else { b'B' }).collect());
            }
        }
        all
    }

    /// The prefix search grown one byte at a time, each length a scan of
    /// `text` — the reference the bisection must reproduce.
    fn grown(text: &[u8], needle: &[u8]) -> Option<(u64, usize)> {
        let hi = needle.len().min(text.len());
        let mut found = None;
        let mut lo = MIN_COPY;
        while lo <= hi {
            match text.windows(lo).position(|w| *w == needle[..lo]) {
                Some(p) => {
                    found = Some((p as u64 + 1, lo));
                    lo += 1;
                }
                None => break,
            }
        }
        found
    }

    /// Bisection finds the longest occurring prefix, and its first
    /// occurrence, exactly where growing it a byte at a time does — for
    /// every text and needle over {A, B} short enough to enumerate.
    #[test]
    fn bisection_finds_the_prefix_growth_finds() {
        let (texts, needles) = (strings(7), strings(6));
        for text in &texts {
            for needle in &needles {
                let (t, n) = (text.as_slice(), needle.as_slice());
                assert_eq!(longest_occurring_prefix(t, n), grown(t, n), "{t:?} / {n:?}");
            }
        }
    }
}
