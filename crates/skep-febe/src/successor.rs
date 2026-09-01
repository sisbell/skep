//! EDITLINK's read-assembled successor (§4): the one request whose slots M10
//! builds itself, from content V-specs resolved through M5 off a snapshot
//! pinned BEFORE the write transaction. Recorded I-addresses are permanent,
//! so the source document's arrangement may move underneath with no hazard,
//! and the operation is still one M2 transaction.

use skep_address::{content_subspace, Span};
use skep_arrangement::{M5State, Run, VSpec};
use skep_links::Endset;
use skep_namespace::M3State;

use crate::op::OpKind;
use crate::reject::{reject1, RejectCode, Rejection};

/// Assemble one successor slot from its content V-specs.
///
/// Every spec is checked before it is resolved, because M5's `resolve` is
/// total: it answers ⟨⟩ for a spec it cannot honour — a malformed span, or a
/// source that is no registered document — and depositing that ⟨⟩ would
/// commit a successor with a silently empty slot. Both faults are typed
/// instead: `IllFormedSpec` for a span that is not a content V-span,
/// `SourceNotRegistered` for a source M3 does not know, which is `Reorder`
/// and so tells a client that arrives ahead of its own CREATENEWDOCUMENT to
/// try again.
///
/// Past the checks the tail is infallible: `Run::iextent` is total (every
/// `Run` has `width ≥ 1` and an element-level `i_start`). An empty from/to
/// is structurally fine; M7 gates the type slot.
pub(crate) fn endset_from_vspecs(
    m3: &M3State,
    m5: &M5State,
    specs: &[VSpec],
) -> Result<Endset, Rejection> {
    let mut spans = Vec::new();
    for vs in specs {
        if !is_content_vspan(&vs.span) {
            return Err(reject1(OpKind::EditLink, RejectCode::IllFormedSpec));
        }
        if !m3.is_registered_document(&vs.source) {
            return Err(reject1(OpKind::EditLink, RejectCode::SourceNotRegistered));
        }
        spans.extend(m5.resolve(&vs.source, &vs.span).iter().map(Run::iextent));
    }
    Ok(Endset::from_spans(spans))
}

/// The content-V well-formedness predicate makelink applies to its own
/// `Resolve` specs: a depth-2 V-position in the content subspace with an
/// ordinal displacement — `#start = 2 ∧ start₁ = s_C ∧ #width = 2 ∧
/// width₁ = 0`.
///
/// The V-position's subspace is the start's FIRST component, not M1's
/// `Address::subspace()` (which needs zeros = 3 and would reject every
/// depth-2 spec). Every component read is fallible, so a span of any shape
/// answers rather than faulting, which is what `execute`'s Total contract
/// needs.
fn is_content_vspan(span: &Span) -> bool {
    let start = span.start();
    let width = span.width();
    start.len() == 2
        && width.len() == 2
        && start.get(1) == Some(&content_subspace())
        && width.get(1).is_some_and(|w| w.bits() == 0) // ordinal-level
}

#[cfg(test)]
mod tests {
    use skep_address::{validate, Address, Nat, Tumbler};

    use super::*;

    fn t(comps: &[u32]) -> Tumbler {
        Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")
    }
    fn a(comps: &[u32]) -> Address {
        validate(t(comps)).unwrap_or_else(|_| panic!("T4-valid test address"))
    }
    fn span(start: &[u32], width: &[u32]) -> Span {
        Span::new(t(start), t(width)).unwrap_or_else(|_| panic!("well-formed test span"))
    }

    /// §4: the content-V guard — depth-2, content-subspace (s_C), ordinal-
    /// level — answering for a span of any shape, deeper and shallower
    /// included.
    #[test]
    fn content_vspan_guard() {
        assert!(is_content_vspan(&span(&[1, 1], &[0, 2])));
        assert!(!is_content_vspan(&span(&[2, 1], &[0, 1]))); // link subspace
        assert!(!is_content_vspan(&span(&[1, 1], &[1, 0]))); // not ordinal-level
        assert!(!is_content_vspan(&span(&[5], &[1]))); // shallower than depth 2
        assert!(!is_content_vspan(&span(&[1, 1, 1], &[0, 0, 1])));
    }

    /// §4: each fault is typed and told apart — an ill-formed span is
    /// Permanent, an unregistered source is Reorder — and neither reaches
    /// `resolve`, whose ⟨⟩ would otherwise be deposited as an empty slot.
    #[test]
    fn every_unresolvable_spec_is_typed_before_resolve() {
        let m3 = M3State::genesis();
        let m5 = M5State::genesis();
        let doc = a(&[1, 0, 1, 0, 1]);

        let ill_formed = VSpec { source: doc.clone(), span: span(&[2, 1], &[0, 1]) };
        let rej = endset_from_vspecs(&m3, &m5, &[ill_formed]).expect_err("link-subspace span");
        assert_eq!(rej.op, OpKind::EditLink);
        assert_eq!(rej.code, RejectCode::IllFormedSpec);

        // Well formed, and genesis M3 has registered no document: the spec
        // would resolve to ⟨⟩, so it is refused instead.
        let unregistered = VSpec { source: doc, span: span(&[1, 1], &[0, 1]) };
        let rej = endset_from_vspecs(&m3, &m5, &[unregistered]).expect_err("unregistered source");
        assert_eq!(rej.code, RejectCode::SourceNotRegistered);
        assert_eq!(rej.disposition, crate::reject::Disposition::Reorder);

        // No specs is not a fault: an empty slot the CALLER asked for.
        assert!(endset_from_vspecs(&m3, &m5, &[]).expect("empty is fine").is_empty());
    }
}
