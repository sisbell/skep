//! Comparators, one per result type. Every comparator returns either
//! agreement or a rendered (expected, actual) pair — the actual side
//! rendered THROUGH the bijection so the report reads in golden terms with
//! skep extras visibly tagged. Nothing here mutates state except the
//! α-bijection's sanctioned binding move ("when a golden op's result is an
//! address and skep's response carries one, bind golden→skep" — probe
//! results included), and nothing adjusts a value except under an explicit
//! allowlist grant threaded in by the caller.

use skep_address::{Address, SpanSet};
use skep_retrieval::DeliveryItem;

use crate::alpha::Alpha;
use crate::fields::RawSpan;
use crate::tum::span_strings;

/// Disagreement payload: (expected, actual), both rendered.
pub type Verdict = Result<(), (String, String)>;

// ── text content: literal equality ─────────────────────────────────────────

/// One golden/skep content sequence, normalized: consecutive text glued into
/// one segment, addresses kept as segments of their own. udanax's
/// retrieve_contents returns one string per spec while skep's RetrieveV
/// delivers one item per V-position — gluing consecutive text on BOTH sides
/// removes exactly that packaging difference and nothing else.
#[derive(Debug, PartialEq, Eq)]
pub enum Segment {
    Text(String),
    Addr(String), // rendered in golden terms
}

fn push_text(out: &mut Vec<Segment>, s: &str) {
    if let Some(Segment::Text(t)) = out.last_mut() {
        t.push_str(s);
        return;
    }
    out.push(Segment::Text(s.to_string()));
}

pub fn render_segments(segs: &[Segment]) -> String {
    let parts: Vec<String> = segs
        .iter()
        .map(|s| match s {
            Segment::Text(t) => format!("{t:?}"),
            Segment::Addr(a) => format!("@{a}"),
        })
        .collect();
    format!("[{}]", parts.join(", "))
}

/// Content comparator: golden strings vs a skep delivery. Before comparing,
/// index-aligned (golden address, skep address) pairs where NEITHER side is
/// bound yet are bound into α — the read result names an address exactly the
/// way a write ack does (subspace/insert_text_check_link_positions probes
/// link position 2.1 and records the link id, which no earlier op bound).
/// Text is literal equality; addresses compare up to the bijection.
pub fn compare_content(
    expected: &[String],
    items: &[DeliveryItem],
    alpha: &mut Alpha,
) -> Verdict {
    // Segment the golden side.
    let mut want: Vec<Segment> = Vec::new();
    for s in expected {
        if crate::fields::is_link_address(s) {
            want.push(Segment::Addr(s.clone()));
        } else {
            push_text(&mut want, s);
        }
    }
    // Segment the skep side, addresses kept raw for the binding pass.
    enum RawSeg {
        Text(String),
        Addr(Address),
    }
    let mut raw: Vec<RawSeg> = Vec::new();
    for it in items {
        match it {
            DeliveryItem::Content(v) => {
                let s = String::from_utf8_lossy(v.as_bytes()).into_owned();
                match raw.last_mut() {
                    Some(RawSeg::Text(t)) => t.push_str(&s),
                    _ => raw.push(RawSeg::Text(s)),
                }
            }
            DeliveryItem::Ref(a) => raw.push(RawSeg::Addr(a.clone())),
        }
    }
    // Opportunistic index-aligned binding.
    if want.len() == raw.len() {
        for (w, r) in want.iter().zip(&raw) {
            if let (Segment::Addr(g), RawSeg::Addr(a)) = (w, r) {
                if alpha.peek_translate(g).is_none() && !alpha.is_bound_skep(a) {
                    alpha.bind(g, a);
                }
            }
        }
    }
    // Force translation attempts for golden addr items so never-bound
    // references surface as findings even when skep returned nothing.
    for seg in &want {
        if let Segment::Addr(g) = seg {
            let _ = alpha.translate(g);
        }
    }
    let got: Vec<Segment> = raw
        .into_iter()
        .map(|r| match r {
            RawSeg::Text(t) => Segment::Text(t),
            RawSeg::Addr(a) => Segment::Addr(alpha.render_skep(&a)),
        })
        .collect();
    if want == got {
        Ok(())
    } else {
        Err((render_segments(&want), render_segments(&got)))
    }
}

// ── address sets: set equality under the bijection ─────────────────────────

/// Sets of links or documents. Golden strings are translated through α (a
/// never-bound expected address is itself a finding recorded by `translate`);
/// skep extras render tagged. `exclude` drops harness-infrastructure
/// addresses (the types doc) from the skep side — part of the named
/// `type_registry` policy, recorded by the caller.
///
/// Binding move: when, after matching every already-bound expected address,
/// the still-unbound goldens and the unmatched skep addresses are EQUAL in
/// number, they are paired in address order and bound — links homed in one
/// document are allocated in the same subspace order on both sides, so the
/// positional pairing is structural, and a wrong pairing surfaces later as
/// an α double-bind finding, never silently.
pub fn compare_addr_sets(
    expected_golden: &[String],
    actual: &[Address],
    alpha: &mut Alpha,
    exclude: impl Fn(&Address) -> bool,
    adaptations: &mut Vec<String>,
) -> Verdict {
    let mut got: Vec<Address> = actual.iter().filter(|a| !exclude(a)).cloned().collect();
    got.sort_by_key(crate::tum::addr_str);
    got.dedup_by_key(|a| crate::tum::addr_str(a));

    let mut want_goldens: Vec<String> = expected_golden.to_vec();
    want_goldens.sort();
    want_goldens.dedup();
    // The golden listing one address twice is a recording defect
    // (insert_text_check_both_link_positions's find_links). The set
    // comparison absorbs it; the tag keeps the defect visible.
    if want_goldens.len() != expected_golden.len() {
        adaptations.push("golden-duplicate-result".into());
    }

    // Peek-translate (no findings yet) to split bound from unbound.
    let bound: Vec<Option<Address>> =
        want_goldens.iter().map(|g| alpha.peek_translate(g)).collect();
    let bound_strs: Vec<String> = bound.iter().flatten().map(crate::tum::addr_str).collect();
    let unbound: Vec<&String> = want_goldens
        .iter()
        .zip(&bound)
        .filter(|(_, b)| b.is_none())
        .map(|(g, _)| g)
        .collect();
    let unmatched: Vec<&Address> = got
        .iter()
        .filter(|a| {
            let s = crate::tum::addr_str(a);
            !bound_strs.contains(&s) && !alpha.is_bound_skep(a)
        })
        .collect();
    if !unbound.is_empty() && unbound.len() == unmatched.len() {
        for (g, a) in unbound.iter().zip(&unmatched) {
            alpha.bind(g.as_str(), a);
        }
        adaptations.push(format!("alpha-bind-from-result:{}", unbound.len()));
    }

    let mut want: Vec<String> = Vec::new();
    for g in &want_goldens {
        match alpha.translate(g) {
            Some(a) => want.push(crate::tum::addr_str(&a)),
            None => want.push(format!("unbound:{g}")),
        }
    }
    let mut got_strs: Vec<String> = got.iter().map(crate::tum::addr_str).collect();
    want.sort();
    want.dedup();
    got_strs.sort();
    got_strs.dedup();
    if want == got_strs {
        Ok(())
    } else {
        let exp: Vec<String> = want_goldens;
        let act: Vec<String> = got.iter().map(|a| alpha.render_skep(a)).collect();
        Err((format!("{exp:?}"), format!("{act:?}")))
    }
}

// ── spans / vspansets: structural comparison on RAW recorded strings ───────

/// Structural span comparison: count, ordering, widths — on the RAW
/// (start, width) strings. The expected side is exactly what the recording
/// client wrote (decoded-tumbler `str()` forms); the actual side is skep's
/// spans rendered the same dotted way. No reinterpretation: a malformed
/// recorded shape (see [`collapsed_subspace_shape`]) compares as recorded
/// and diverges honestly. Width tolerance applies ONLY where the caller
/// passes a granted allowlist tolerance and both widths parse; start
/// positions are always exact.
pub fn compare_spansets(expected: &[RawSpan], actual: &SpanSet, width_tolerance: u64) -> Verdict {
    let mut want: Vec<RawSpan> = expected.to_vec();
    let mut got: Vec<RawSpan> = actual.iter().map(span_strings).collect();
    want.sort();
    got.sort();
    let ok = want.len() == got.len()
        && want.iter().zip(&got).all(|(w, g)| {
            w.0 == g.0
                && (w.1 == g.1
                    || (width_tolerance > 0 && widths_within(&w.1, &g.1, width_tolerance)))
        });
    if ok {
        Ok(())
    } else {
        Err((format!("{want:?}"), format!("{got:?}")))
    }
}

fn widths_within(a: &str, b: &str, tol: u64) -> bool {
    match (crate::tum::parse_width(a), crate::tum::parse_width(b)) {
        (Some(x), Some(y)) => x.abs_diff(y) <= tol,
        _ => false,
    }
}

/// Detect udanax's malformed two-subspace vspanset reply, so the report can
/// carry the standing analysis alongside the raw disagreement.
///
/// The evidence (all from the vendored goldens): a document occupying ONLY
/// the content subspace records a well-formed set ("1.1"/"0.24" —
/// link_poom/three_links_vspan_growth op 1); ONLY the link subspace, a
/// well-formed set ("2.1"/"0.1" — links/delete_text_before_link after the
/// full text delete); but BOTH subspaces record the pair
/// ("0"/"0.…", "1"/"1") whose widths track neither text length (0.1 for
/// text widths 3, 7, 10, 24 but 0.4 for width 5 —
/// links/multiple_text_insertions_with_links) nor link count (identical for
/// 1, 2 and 3 links — three_links_vspan_growth). Single-component starts
/// ("0", "1") are not V-positions in the goldens' own `subspace.ordinal`
/// vocabulary. No representational reading reproduces those widths, so the
/// harness does NOT normalize them — the cluster stays divergent with this
/// analysis attached for one-shot adjudication.
pub fn collapsed_subspace_shape(expected: &[RawSpan]) -> bool {
    expected.len() >= 2 && expected.iter().any(|(s, _)| !s.contains('.'))
}

pub const COLLAPSED_SUBSPACE_ANALYSIS: &str =
    "udanax two-subspace vspanset shape: when a document occupies both the content and link \
     subspaces, udanax-green's RETRIEVEDOCVSPANSET reply degenerates to a pair like \
     [(\"0\",\"0.1\"), (\"1\",\"1\")] whose widths track neither text length nor link count \
     (single-subspace documents record well-formed spans). Not provably representational — \
     compared raw and left divergent for operator adjudication.";

// ── counts: exact modulo declared delta ────────────────────────────────────

pub fn compare_count(expected: u64, delta: i64, actual: usize) -> Verdict {
    let adjusted = expected as i128 + delta as i128;
    if adjusted == actual as i128 {
        Ok(())
    } else {
        Err((
            if delta == 0 {
                format!("{expected}")
            } else {
                format!("{expected} (+{delta} allowlisted)")
            },
            format!("{actual}"),
        ))
    }
}

// ── expected-failure ───────────────────────────────────────────────────────

/// The golden recorded a non-null `error` for this op: udanax (or its
/// client) failed it. Agreement means skep also rejected; a skep success is
/// a divergence for the operators.
pub fn compare_expected_failure(golden_error: &str, skep_rejected: Option<&str>) -> Verdict {
    match skep_rejected {
        Some(_) => Ok(()),
        None => Err((
            format!("failure: {golden_error:?}"),
            "skep accepted the operation".to_string(),
        )),
    }
}
