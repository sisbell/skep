//! Comparators, one per result type. Every comparator returns either
//! agreement or a rendered (expected, actual) pair — the actual side
//! rendered THROUGH the bijection so the report reads in golden terms with
//! skep extras visibly tagged. Nothing here mutates state and nothing here
//! adjusts a value except under an explicit allowlist grant threaded in by
//! the caller.

use skep_address::{Address, SpanSet};
use skep_retrieval::DeliveryItem;

use crate::alpha::Alpha;
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

pub fn segments_from_golden(items: &[String], alpha: &mut Alpha) -> Vec<Segment> {
    let mut out: Vec<Segment> = Vec::new();
    for s in items {
        if crate::alpha::looks_like_address(s) && s.contains('.') {
            out.push(Segment::Addr(s.to_string()));
        } else {
            push_text(&mut out, s);
        }
    }
    // Force translation attempts for golden addr items so never-bound
    // references surface as findings even when skep returns nothing.
    for seg in &out {
        if let Segment::Addr(g) = seg {
            let _ = alpha.translate(g);
        }
    }
    out
}

pub fn segments_from_delivery(items: &[DeliveryItem], alpha: &Alpha) -> Vec<Segment> {
    let mut out: Vec<Segment> = Vec::new();
    for it in items {
        match it {
            DeliveryItem::Content(v) => {
                push_text(&mut out, &String::from_utf8_lossy(v.as_bytes()))
            }
            DeliveryItem::Ref(a) => out.push(Segment::Addr(alpha.render_skep(a))),
        }
    }
    out
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

/// Text content comparator: literal equality of the normalized segment
/// sequences (text literal, addresses up to the bijection — golden Addr
/// segments were rendered from golden strings, delivery Addr segments
/// through reverse-α, so equal strings ⇔ α-consistent).
pub fn compare_segments(expected: &[Segment], actual: &[Segment]) -> Verdict {
    if expected == actual {
        Ok(())
    } else {
        Err((render_segments(expected), render_segments(actual)))
    }
}

// ── address sets: set equality under the bijection ─────────────────────────

/// Sets of links or documents. Golden strings are translated through α (a
/// never-bound expected address is itself a finding recorded by `translate`);
/// skep extras render tagged. `exclude` drops harness-infrastructure
/// addresses (the types doc) from the skep side — part of the named
/// `type_registry` policy, recorded by the caller.
pub fn compare_addr_sets(
    expected_golden: &[String],
    actual: &[Address],
    alpha: &mut Alpha,
    exclude: impl Fn(&Address) -> bool,
) -> Verdict {
    let mut want: Vec<String> = Vec::new();
    for g in expected_golden {
        // Render expected in golden terms; translation both binds the
        // finding on misses and gives us the skep-side key for matching.
        match alpha.translate(g) {
            Some(a) => want.push(crate::tum::addr_str(&a)),
            None => want.push(format!("unbound:{g}")),
        }
    }
    let mut got: Vec<String> = actual
        .iter()
        .filter(|a| !exclude(a))
        .map(|a| crate::tum::addr_str(a))
        .collect();
    want.sort();
    want.dedup();
    got.sort();
    got.dedup();
    if want == got {
        Ok(())
    } else {
        let exp: Vec<String> = expected_golden.to_vec();
        let act: Vec<String> = actual
            .iter()
            .filter(|a| !exclude(a))
            .map(|a| alpha.render_skep(a))
            .collect();
        Err((format!("{exp:?}"), format!("{act:?}")))
    }
}

// ── spans / vspansets: structural comparison ───────────────────────────────

/// Structural span comparison: count, ordering, widths. Expected side is
/// golden `(start, width)` dotted strings; actual is a skep `SpanSet` (V-
/// space, depth-2). Width tolerance applies ONLY where the caller passes a
/// granted allowlist tolerance; start positions are always exact.
pub fn compare_spansets(
    expected: &[(String, String)],
    actual: &SpanSet,
    width_tolerance: u64,
) -> Verdict {
    let mut want: Vec<(String, String)> = expected.to_vec();
    let mut got: Vec<(String, String)> = actual.iter().map(span_strings).collect();
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
