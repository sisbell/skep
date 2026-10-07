//! Comparators, one per result type. Every comparator returns either
//! agreement or a rendered [`Disagreement`] — its actual side rendered
//! THROUGH the bijection so the report reads in golden terms with skep
//! extras visibly tagged. Nothing here mutates state except the
//! α-bijection's sanctioned binding move ("when a golden op's result is an
//! address and skep's response carries one, bind golden→skep" — probe
//! results included), and nothing adjusts a value except under an
//! adjustment the allowlist declares, threaded in by the caller — and a
//! comparator whose agreement the adjustment made records that it did.

use std::collections::BTreeSet;

use skep_address::{Address, SpanSet};
use skep_retrieval::DeliveryItem;

use crate::allowlist::{Adjustments, COUNT_ADJUSTED, WIDTH_ADJUSTED};
use crate::alpha::Alpha;
use crate::fields::RawSpan;
use crate::outcome::Disagreement;
use crate::tum::{parse_dotted, span_strings};

/// A comparator's answer: agreement, or the disagreement, both sides
/// rendered.
pub type Comparison = Result<(), Disagreement>;

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
) -> Comparison {
    // Segment the golden side.
    let mut want: Vec<Segment> = Vec::new();
    for s in expected {
        if crate::tum::is_link_address(s) {
            want.push(Segment::Addr(s.clone()));
        } else {
            push_text(&mut want, s);
        }
    }
    // Segment the skep side, addresses kept raw for the binding pass.
    enum RawSeg {
        Text(String),
        Addr(Address),
        // A masked run (lane 3.3, §4): its own segment, matching no golden
        // content, so a delivery carrying one diverges from a golden that does
        // not (the two-account goldens item 6 names).
        Withheld(String),
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
            DeliveryItem::Withheld { origin, width } => {
                raw.push(RawSeg::Withheld(format!("«withheld {origin} w{width}»")))
            }
        }
    }
    // Opportunistic index-aligned binding: an unbound golden address paired
    // positionally with an unbound skep address is an α-bind opportunity
    // (the sanctioned move) — never a raw emission.
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
    // Address equality goes THROUGH the bijection (element lift included) —
    // a golden link id that translates via its bound doc prefix must equal
    // the delivered skep address, whether or not the pair was ever bound
    // exactly (subspace/insert_text_check_link_positions reads link
    // position 2.1 of a doc whose create_link recorded no result).
    let equal = want.len() == raw.len()
        && want.iter().zip(&raw).all(|(w, r)| match (w, r) {
            (Segment::Text(a), RawSeg::Text(b)) => a == b,
            (Segment::Addr(g), RawSeg::Addr(a)) => alpha.peek_translate(g).as_ref() == Some(a),
            _ => false,
        });
    if equal {
        return Ok(());
    }
    // Report rendering: skep addresses reverse-translate (bound golden
    // address or reverse lift) so the reader sees golden terms, extras tagged.
    let got: Vec<Segment> = raw
        .into_iter()
        .map(|r| match r {
            RawSeg::Text(t) => Segment::Text(t),
            RawSeg::Addr(a) => Segment::Addr(alpha.render_skep(&a)),
            RawSeg::Withheld(m) => Segment::Text(m),
        })
        .collect();
    Err(Disagreement { expected: render_segments(&want), actual: render_segments(&got) })
}

// ── address sets: set equality under the bijection ─────────────────────────

/// Sets of links or documents. Golden strings are translated through α (a
/// never-bound expected address is itself a finding recorded by
/// `Alpha::translate`); skep extras render tagged. `exclude` drops
/// harness-infrastructure addresses (the types doc) from the skep side —
/// part of the named `types_document` policy, recorded by the caller.
///
/// Binding move: when, after matching every already-bound expected address,
/// the still-unbound goldens and the unmatched skep addresses are EQUAL in
/// number, they are paired in address order and bound — links homed in one
/// document are allocated in the same subspace order on both sides, so the
/// positional pairing is structural, and a wrong pairing surfaces later as
/// an α double-bind finding, never silently. Address order is tumbler order
/// on both sides — component by component, numerically — so `…0.9` pairs
/// ahead of `…0.10` exactly as the two systems allocated them.
pub fn compare_addr_sets(
    expected_golden: &[String],
    actual: &[Address],
    alpha: &mut Alpha,
    exclude: impl Fn(&Address) -> bool,
    adaptations: &mut Vec<String>,
) -> Comparison {
    let mut got: Vec<Address> = actual.iter().filter(|a| !exclude(a)).cloned().collect();
    got.sort();
    got.dedup();

    let mut want_goldens: Vec<String> = expected_golden.to_vec();
    want_goldens.sort_by(|a, b| parse_dotted(a).cmp(&parse_dotted(b)).then_with(|| a.cmp(b)));
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
    let unbound: Vec<&String> = want_goldens
        .iter()
        .zip(&bound)
        .filter(|(_, b)| b.is_none())
        .map(|(g, _)| g)
        .collect();
    let unmatched: Vec<&Address> = got
        .iter()
        .filter(|a| !bound.iter().flatten().any(|b| b == *a) && !alpha.is_bound_skep(a))
        .collect();
    if !unbound.is_empty() && unbound.len() == unmatched.len() {
        for (g, a) in unbound.iter().zip(&unmatched) {
            alpha.bind(g.as_str(), a);
        }
        adaptations.push(format!("alpha-bind-from-result:{}", unbound.len()));
    }

    // Every golden is translated, so each one still unbound records its own
    // finding; the sets agree only when every golden has an image and the
    // images are exactly skep's answer.
    let translated: Vec<Option<Address>> =
        want_goldens.iter().map(|g| alpha.translate(g)).collect();
    let want: Option<BTreeSet<&Address>> = translated.iter().map(Option::as_ref).collect();
    if want.is_some_and(|want| want == got.iter().collect::<BTreeSet<_>>()) {
        Ok(())
    } else {
        let actual: Vec<String> = got.iter().map(|a| alpha.render_skep(a)).collect();
        Err(Disagreement { expected: format!("{want_goldens:?}"), actual: format!("{actual:?}") })
    }
}

// ── spans / vspansets: structural comparison on RAW recorded strings ───────

/// Structural span comparison: count, ordering, widths — on the RAW
/// (start, width) strings. The expected side is exactly what the recording
/// client wrote (decoded-tumbler `str()` forms); the actual side is skep's
/// spans rendered the same dotted way. No reinterpretation: a malformed
/// recorded shape (see [`collapsed_subspace_shape`]) compares as recorded
/// and diverges honestly. Width tolerance applies ONLY where the allowlist
/// declares one and both widths parse; start positions are always exact. An
/// agreement the tolerance made is recorded as [`WIDTH_ADJUSTED`].
pub fn compare_spansets(
    expected: &[RawSpan],
    actual: &SpanSet,
    adjustments: &Adjustments,
    adaptations: &mut Vec<String>,
) -> Comparison {
    let mut want: Vec<RawSpan> = expected.to_vec();
    let mut got: Vec<RawSpan> = actual.iter().map(span_strings).collect();
    want.sort();
    got.sort();
    let tol = adjustments.width_tolerance;
    let mut tolerated = false;
    let ok = want.len() == got.len()
        && want.iter().zip(&got).all(|(w, g)| {
            if w.0 != g.0 {
                return false;
            }
            if w.1 == g.1 {
                return true;
            }
            let within = tol > 0 && widths_within(&w.1, &g.1, tol);
            tolerated |= within;
            within
        });
    if ok {
        if tolerated {
            adaptations.push(WIDTH_ADJUSTED.into());
        }
        Ok(())
    } else {
        Err(Disagreement { expected: format!("{want:?}"), actual: format!("{got:?}") })
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
/// harness does NOT normalize them: the cluster is compared raw, this
/// analysis attached — ruled udanax-malformed-vspanset (decisions.md
/// ruling 1).
pub fn collapsed_subspace_shape(expected: &[RawSpan]) -> bool {
    expected.len() >= 2 && expected.iter().any(|(s, _)| !s.contains('.'))
}

pub const COLLAPSED_SUBSPACE_ANALYSIS: &str =
    "udanax two-subspace vspanset shape: when a document occupies both the content and link \
     subspaces, udanax-green's RETRIEVEDOCVSPANSET reply degenerates to a pair like \
     [(\"0\",\"0.1\"), (\"1\",\"1\")] whose widths track neither text length nor link count \
     (single-subspace documents record well-formed spans). Not provably representational — \
     compared raw, never coerced; ruled udanax-malformed-vspanset (decisions.md ruling 1).";

/// The second standing cluster: versions and the link subspace.
///
/// The evidence (all from the vendored goldens): udanax's CREATENEWVERSION
/// carries the source's link subspace into the new version, and the
/// version's RETRIEVEDOCVSPANSET flattens it onto the content extent's tail
/// — provenance/createnewversion_text_vs_links records width 0.34 for a
/// 33-char text, and its own whole-extent retrieve delivers those 33 chars
/// PLUS the link marker, so position 34 IS the carried link (not an
/// unrecorded 34th text byte); versions/version_copies_link_subspace
/// records 0.15 = 14 text + 1 link the same way. skep's Version installs a
/// content-subspace-only snapshot (M5 `VersionSnapshot`, ASN-0123 V2), so
/// the version's link subspace is empty: the link item and the +links
/// extent are absent, while link DISCOVERY from the version (FindLinksV
/// over the shared I-content) agrees on both sides. A real design
/// divergence, compared raw and never papered over — ruled
/// version-link-carryover (decisions.md ruling 15).
pub const VERSION_LINK_CARRYOVER_ANALYSIS: &str =
    "udanax version link carryover: CREATENEWVERSION carries the source's link subspace into \
     the version and the version's vspanset flattens it onto the content extent's tail \
     (createnewversion_text_vs_links: 0.34 = 33 text + 1 link, its whole-extent retrieve \
     delivering 33 chars plus the link marker; version_copies_link_subspace: 0.15 = 14 + 1). \
     skep's Version installs a content-subspace-only snapshot (M5 VersionSnapshot, ASN-0123 \
     V2), so the version's link subspace is empty — the link item and the +links extent are \
     absent, while link discovery from the version agrees on both sides. Real design \
     divergence, compared raw — ruled version-link-carryover (decisions.md ruling 15).";

// ── counts: exact modulo declared delta ────────────────────────────────────

/// A recorded count against skep's, exact up to the count delta the
/// allowlist declares; an agreement the delta made is recorded as
/// [`COUNT_ADJUSTED`].
pub fn compare_count(
    expected: u64,
    actual: usize,
    adjustments: &Adjustments,
    adaptations: &mut Vec<String>,
) -> Comparison {
    let delta = adjustments.count_delta;
    let adjusted = expected as i128 + delta as i128;
    if adjusted == actual as i128 {
        if delta != 0 {
            adaptations.push(COUNT_ADJUSTED.into());
        }
        Ok(())
    } else {
        Err(Disagreement {
            expected: if delta == 0 {
                format!("{expected}")
            } else {
                format!("{expected} (+{delta} allowlisted)")
            },
            actual: format!("{actual}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skep_address::{Nat, Span};
    use skep_content::Val;

    use crate::alpha::FindingKind;
    use crate::tum::{addr, tum};

    /// One delivered content item per byte, as RetrieveV delivers text.
    fn text(s: &str) -> Vec<DeliveryItem> {
        s.bytes().map(|b| DeliveryItem::Content(Val::new(vec![b]))).collect()
    }

    fn strings(ss: &[&str]) -> Vec<String> {
        ss.iter().map(|s| s.to_string()).collect()
    }

    /// Content agrees only byte for byte once consecutive text is glued on
    /// both sides: case, length and a withheld run all disagree — a
    /// withheld run is its own segment, never glued and never dropped.
    #[test]
    fn content_agrees_only_byte_for_byte_once_text_is_glued() {
        let mut alpha = Alpha::new();
        let mut cmp = |want: &[&str], got: &[DeliveryItem]| {
            compare_content(&strings(want), got, &mut alpha)
        };
        assert_eq!(cmp(&["AB", "CD"], &text("ABCD")), Ok(()));
        let crossed = Disagreement { expected: r#"["ABCD"]"#.into(), actual: r#"["ABXD"]"#.into() };
        assert_eq!(cmp(&["ABCD"], &text("ABXD")), Err(crossed));
        assert!(cmp(&["ab"], &text("AB")).is_err());
        assert!(cmp(&["ABCD"], &text("ABC")).is_err());
        let origin = addr(&[1, 0, 1, 0, 3]).expect("valid");
        let mut withheld = text("AB");
        withheld.push(DeliveryItem::Withheld { origin, width: Nat::from(2u64) });
        withheld.extend(text("CD"));
        assert!(cmp(&["ABCD"], &withheld).is_err());
    }

    /// A delivered address compares through α — the image of the golden
    /// address agrees, any other disagrees — and an unbound golden address
    /// binds to a delivered one only where the two sequences align one for
    /// one; otherwise it surfaces as never bound.
    #[test]
    fn a_delivered_address_compares_through_the_bijection() {
        let link = |n: u64| DeliveryItem::Ref(addr(&[1, 0, 1, 0, 3, 0, 2, n]).expect("valid"));
        let mut alpha = Alpha::new();
        alpha.bind("1.1.0.1.0.1", &addr(&[1, 0, 1, 0, 3]).expect("valid"));
        let want = strings(&["AB", "1.1.0.1.0.1.0.2.1"]);
        let with = |item: DeliveryItem| [text("AB"), vec![item]].concat();
        assert_eq!(compare_content(&want, &with(link(1)), &mut alpha), Ok(()));
        assert!(compare_content(&want, &with(link(2)), &mut alpha).is_err());
        assert_eq!(alpha.drain_findings().count(), 0);

        let stray = addr(&[1, 0, 1, 0, 7, 0, 2, 1]).expect("valid");
        let delivered = [DeliveryItem::Ref(stray.clone())];
        let mut fresh = Alpha::new();
        let misaligned = strings(&["1.1.0.1.0.9.0.2.1", "X"]);
        assert!(compare_content(&misaligned, &delivered, &mut fresh).is_err());
        assert_eq!(fresh.peek("1.1.0.1.0.9.0.2.1"), None);
        let found: Vec<FindingKind> = fresh.drain_findings().map(|f| f.kind).collect();
        assert_eq!(found, [FindingKind::NeverBound]);
        let aligned = strings(&["1.1.0.1.0.9.0.2.1"]);
        assert_eq!(compare_content(&aligned, &delivered, &mut fresh), Ok(()));
        assert_eq!(fresh.peek("1.1.0.1.0.9.0.2.1"), Some(stray));
    }

    /// An address set agrees only with exactly skep's answer, harness
    /// infrastructure excluded: a superset or a subset disagrees, rendered
    /// in golden terms, and unbound golden addresses with no partners to
    /// pair one for one bind nothing and surface as never bound.
    #[test]
    fn an_address_set_agrees_only_with_exactly_skeps_answer() {
        fn sets(
            want: &[&str],
            got: &[Address],
            alpha: &mut Alpha,
            infra: Option<&Address>,
        ) -> Comparison {
            let exclude = |x: &Address| infra.is_some_and(|i| i == x);
            compare_addr_sets(&strings(want), got, alpha, exclude, &mut Vec::new())
        }
        let a = addr(&[1, 0, 1, 0, 3]).expect("valid");
        let b = addr(&[1, 0, 1, 0, 4]).expect("valid");
        let mut alpha = Alpha::new();
        alpha.bind("1.1.0.1.0.1", &a);
        alpha.bind("1.1.0.1.0.2", &b);
        let both = [a.clone(), b.clone()];
        let only_a = std::slice::from_ref(&a);
        assert_eq!(sets(&["1.1.0.1.0.1"], only_a, &mut alpha, None), Ok(()));
        let superset = Disagreement {
            expected: r#"["1.1.0.1.0.1"]"#.into(),
            actual: r#"["1.1.0.1.0.1", "1.1.0.1.0.2"]"#.into(),
        };
        assert_eq!(sets(&["1.1.0.1.0.1"], &both, &mut alpha, None), Err(superset));
        assert!(sets(&["1.1.0.1.0.1", "1.1.0.1.0.2"], only_a, &mut alpha, None).is_err());
        assert_eq!(sets(&["1.1.0.1.0.1"], &both, &mut alpha, Some(&b)), Ok(()));

        let mut fresh = Alpha::new();
        let stray = addr(&[1, 0, 1, 0, 9]).expect("valid");
        assert!(sets(&["1.1.0.1.0.7", "1.1.0.1.0.8"], &[stray], &mut fresh, None).is_err());
        assert_eq!(fresh.len(), 0);
        let found: Vec<FindingKind> = fresh.drain_findings().map(|f| f.kind).collect();
        assert_eq!(found, [FindingKind::NeverBound, FindingKind::NeverBound]);
    }

    /// A declared width tolerance widens widths alone: it never moves a
    /// start, and never covers a span the other side lacks.
    #[test]
    fn a_width_tolerance_never_moves_a_start() {
        let set = SpanSet::singleton(Span::new(tum(&[1, 1]), tum(&[0, 5])).expect("a span"));
        let tolerant = Adjustments { width_tolerance: 1, count_delta: 0 };
        let moved = [("1.2".to_string(), "0.5".to_string())];
        assert!(compare_spansets(&moved, &set, &tolerant, &mut Vec::new()).is_err());
        let span = |start: &str, width: &str| (start.to_string(), width.to_string());
        let extra = [span("1.1", "0.5"), span("1.7", "0.1")];
        assert!(compare_spansets(&extra, &set, &tolerant, &mut Vec::new()).is_err());
    }

    /// Unbound results pair in tumbler order on both sides: golden
    /// `…0.9`/`…0.10` bind to skep's `…0.11`/`…0.12` in allocation order,
    /// where a string sort would cross them.
    #[test]
    fn unbound_results_pair_in_tumbler_order() {
        let mut alpha = Alpha::new();
        let (eleven, twelve) =
            (addr(&[1, 0, 1, 0, 11]).expect("valid"), addr(&[1, 0, 1, 0, 12]).expect("valid"));
        let want = ["1.1.0.1.0.10".to_string(), "1.1.0.1.0.9".to_string()];
        let mut adaptations = Vec::new();
        let comparison = compare_addr_sets(
            &want,
            &[twelve.clone(), eleven.clone()],
            &mut alpha,
            |_| false,
            &mut adaptations,
        );
        assert_eq!(comparison, Ok(()));
        assert_eq!(adaptations, ["alpha-bind-from-result:2"]);
        assert_eq!(alpha.peek("1.1.0.1.0.9"), Some(eleven));
        assert_eq!(alpha.peek("1.1.0.1.0.10"), Some(twelve));
    }

    /// A comparator records an allowlist adjustment only when the
    /// adjustment, not the raw values, made its agreement.
    #[test]
    fn an_adjustment_is_recorded_only_when_it_made_the_agreement() {
        let set = SpanSet::singleton(Span::new(tum(&[1, 1]), tum(&[0, 5])).expect("a span"));
        let width = Adjustments { width_tolerance: 1, count_delta: 0 };
        let exact = [("1.1".to_string(), "0.5".to_string())];
        let off_by_one = [("1.1".to_string(), "0.4".to_string())];
        let mut adaptations = Vec::new();
        assert_eq!(compare_spansets(&exact, &set, &width, &mut adaptations), Ok(()));
        assert!(adaptations.is_empty(), "an exact width used no adjustment");
        assert_eq!(compare_spansets(&off_by_one, &set, &width, &mut adaptations), Ok(()));
        assert_eq!(adaptations, [WIDTH_ADJUSTED]);
        let none = Adjustments::default();
        assert!(compare_spansets(&off_by_one, &set, &none, &mut Vec::new()).is_err());

        let delta = Adjustments { width_tolerance: 0, count_delta: 1 };
        let mut adaptations = Vec::new();
        let unadjusted = compare_count(3, 3, &delta, &mut Vec::new());
        let disagreement =
            Disagreement { expected: "3 (+1 allowlisted)".into(), actual: "3".into() };
        assert_eq!(unadjusted, Err(disagreement));
        assert_eq!(compare_count(3, 3, &Adjustments::default(), &mut adaptations), Ok(()));
        assert!(adaptations.is_empty());
        assert_eq!(compare_count(3, 4, &delta, &mut adaptations), Ok(()));
        assert_eq!(adaptations, [COUNT_ADJUSTED]);
    }
}
