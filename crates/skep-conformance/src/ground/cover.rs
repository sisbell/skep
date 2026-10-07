//! Expansion-plan covers: a destination's probed content rebuilt as insert
//! and copy steps — from the scenario's recorded comparison pairs where they
//! pin each shared region exactly, else greedily from the source documents'
//! text — and the forward scans that decide whether an append-shaped vcopy
//! needs such a plan at all. Each reads the shadow and the recorded ops,
//! never the simulation's state.

use serde_json::Value;

use super::SetupStep;
use crate::fields::{field, insert_text, reads_whole_content, span_dict, str_field, verb_of, Verb};
use crate::shadow::Shadow;

/// Greedy cover of `expected` by substrings of the sources (copies, ≥ 4
/// chars) with literal fillers between — the reconstruction of an
/// unrecorded insert/vcopy interleaving. Verified downstream by the
/// scenario's own compare/find ops. A matched copy never keeps trailing
/// whitespace (round-3: content/vcopy_from_multiple_documents's own
/// comparisons record width 8 "Source A" where the greedy match took
/// "Source A " — the scripts copied word-shaped regions and joined with
/// literal separators), so the maximal match is trimmed back to its last
/// non-space byte before it drops below the copy floor.
pub(super) fn cover_with_sources(
    shadow: &Shadow,
    dest: &str,
    sources: &[String],
    expected: &str,
) -> Vec<SetupStep> {
    const MIN_COPY: usize = 4;
    let e = expected.as_bytes();
    let mut steps: Vec<SetupStep> = Vec::new();
    let mut filler: Vec<u8> = Vec::new();
    let mut i = 0usize;
    while i < e.len() {
        let mut best: Option<(String, u64, usize)> = None; // (src, ord, len)
        for src in sources {
            let text = shadow.text_string(src);
            let t = text.as_bytes();
            let hi = (e.len() - i).min(t.len());
            let mut found: Option<(u64, usize)> = None;
            let mut lo = MIN_COPY;
            while lo <= hi {
                let needle = &e[i..i + lo];
                match t.windows(lo).position(|w| w == needle) {
                    Some(p) => {
                        found = Some((p as u64 + 1, lo));
                        lo += 1;
                    }
                    None => break,
                }
            }
            if let Some((ord, mut len)) = found {
                while len > MIN_COPY && e[i + len - 1].is_ascii_whitespace() {
                    len -= 1;
                }
                if best.as_ref().is_none_or(|(_, _, bl)| len > *bl) {
                    best = Some((src.clone(), ord, len));
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

/// One recorded shared-span evidence pair: dest doc, dest ordinal, source
/// doc, source ordinal, width — the scenario's own testimony of which
/// region came from where.
pub(super) type SharedPair = (String, u64, String, u64, u64);

/// Harvest every recorded comparison pair in the scenario, both shapes:
/// entries `{source: "A", shared: [{target: {…}, source: {…}}]}` inside a
/// results/comparisons array (content/vcopy_from_multiple_documents — the
/// dest is the scenario's target-role doc), and compare ops labeled
/// `"<x>_vs_<y>"` whose top-level `shared` items key the sides `a`/`b`
/// positionally (identity/identity_mixed_sources).
pub(super) fn comparison_pairs(all: &[Value], shadow: &Shadow) -> Vec<SharedPair> {
    let mut out: Vec<SharedPair> = Vec::new();
    for op in all {
        if verb_of(op) != Some(Verb::Compare) {
            continue;
        }
        if let Some(entries) = field(op, &["results", "comparisons"]).and_then(Value::as_array) {
            let dest = shadow.resolve_doc("target").or_else(|| shadow.scoped());
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
                    if let (Some((1, tord, w)), Some((1, sord, sw))) = (tgt, ssp) {
                        if w == sw {
                            out.push((dest.clone(), tord, src.clone(), sord, w));
                        }
                    }
                }
            }
            continue;
        }
        // "<x>_vs_<y>" label + top-level shared, sides keyed a/b.
        if let Some((dx, dy)) = str_field(op, &["label"])
            .and_then(|l| l.split_once("_vs_"))
            .and_then(|(x, y)| Some((shadow.resolve_doc(x)?, shadow.resolve_doc(y)?)))
        {
            let Some(shared) = field(op, &["shared"]).and_then(Value::as_array) else { continue };
            for item in shared {
                let a = item.get("a").and_then(span_dict);
                let b = item.get("b").and_then(span_dict);
                if let (Some((1, aord, w)), Some((1, bord, bw))) = (a, b) {
                    if w == bw {
                        out.push((dx.clone(), aord, dy.clone(), bord, w));
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
            let sides: Vec<(String, u64, u64)> = io
                .iter()
                .filter_map(|(k, v)| {
                    let (docref, sub, ord, w) = if let Some((sub, ord, w)) = span_dict(v) {
                        (k.as_str(), sub, ord, w)
                    } else {
                        let o = v.as_object()?;
                        let d = o.get("docid").and_then(Value::as_str);
                        let sp = o.get("span").or_else(|| {
                            o.get("spans").and_then(Value::as_array).and_then(|a| a.first())
                        })?;
                        let (sub, ord, w) = span_dict(sp)?;
                        (d.unwrap_or(k.as_str()), sub, ord, w)
                    };
                    if sub != 1 {
                        return None;
                    }
                    let doc = shadow.resolve_doc(docref)?;
                    Some((doc, ord, w))
                })
                .collect();
            if let [(da, oa, wa), (db, ob, wb)] = sides.as_slice() {
                if wa == wb && da != db {
                    out.push((da.clone(), *oa, db.clone(), *ob, *wa));
                    out.push((db.clone(), *ob, da.clone(), *oa, *wa));
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
    let mut pairs: Vec<(u64, String, u64, u64)> = comparison_pairs(all, shadow)
        .into_iter()
        .filter(|(d, _, _, _, _)| d == dest)
        .map(|(_, tord, src, sord, w)| (tord, src, sord, w))
        .collect();
    if pairs.is_empty() {
        return None;
    }
    pairs.sort();
    let e = expected.as_bytes();
    let mut steps: Vec<SetupStep> = Vec::new();
    let mut at = 0usize; // 0-based cursor into expected
    for (tord, src, sord, w) in pairs {
        let (t0, w) = ((tord - 1) as usize, w as usize);
        if t0 < at || t0 + w > e.len() {
            return None; // overlapping or out-of-range evidence
        }
        let src_bytes = shadow.slice(&src, sord, w as u64);
        if src_bytes != e[t0..t0 + w] {
            return None; // evidence disagrees with the probe text
        }
        if t0 > at {
            steps.push(SetupStep::Insert { doc: dest.to_string(), bytes: e[at..t0].to_vec() });
        }
        steps.push(SetupStep::Copy { doc: dest.to_string(), src, ord: sord, width: w as u64 });
        at = t0 + w;
    }
    if at < e.len() {
        steps.push(SetupStep::Insert { doc: dest.to_string(), bytes: e[at..].to_vec() });
    }
    Some(steps)
}
