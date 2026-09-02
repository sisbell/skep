//! EDITLINK's read-assembled successor (§4): the one request whose slots M10
//! builds itself, from content V-specs resolved through M5 off a snapshot
//! pinned BEFORE the write transaction. Recorded I-addresses are permanent,
//! so the source document's arrangement may move underneath with no hazard,
//! and the operation is still one M2 transaction.
//!
//! Building a slot here rather than in M7 means the per-slot span budget is
//! M10's to enforce for this one request, and enforcing it means counting as
//! the spans are produced — see [`endset_from_vspecs`].

use skep_address::{content_subspace, Span};
use skep_arrangement::{M5State, VSpec};
use skep_links::{Endset, MAX_SLOT_SPANS};
use skep_namespace::M3State;

use crate::op::OpKind;
use crate::reject::{rejection, FaultSite, RejectCode, Rejection};

/// Assemble one successor slot from its content V-specs.
///
/// M5's `resolve` is total, and answers ⟨⟩ four ways: a span whose shape is
/// not depth-2 ordinal-level; a document with no entry in M5's arrangement
/// map; a subspace outside {s_C, s_L}; and a well-formed spec whose ordinal
/// range holds nothing. A ⟨⟩ deposited into a slot is indistinguishable from
/// a slot the caller meant to leave empty, so the two faults a client can
/// act on are typed here, ahead of `resolve`:
///
/// * `IllFormedSpec` — the span is not a content V-span ([`is_content_vspan`]
///   covers the shape and subspace cases together). Permanent: the request
///   itself is what is wrong.
/// * `SourceNotRegistered` — M3 does not know the source. This is M10's own
///   precondition, not a restatement of anything `resolve` checks: `resolve`
///   consults M5's arrangement map and never M3's registry. It is here
///   because it is the fault with a remedy — `Reorder`, telling a client that
///   arrived ahead of its own CREATENEWDOCUMENT to try again.
///
/// The other two ⟨⟩ sources survive the guard and are deposited as an empty
/// slot: M5 arranges a document lazily, so a freshly created one is
/// registered and unarranged at once, and an in-range-looking ordinal may
/// simply hold nothing. That is deliberate — MAKELINK's `SlotArg::Resolve`
/// slots build from the same run list and deposit the same empty endset, and
/// an EDITLINK successor stricter than the MAKELINK it supersedes would be a
/// different operation.
///
/// The slot is BOUNDED at [`MAX_SLOT_SPANS`] — M7's per-slot budget, named
/// rather than respelled — and the count is taken AS THE SPANS ARE PRODUCED,
/// so an over-budget slot stops accumulating instead of being built and then
/// measured. That discipline is what makes the third fault, `SlotTooLarge`,
/// worth typing here: a spec's expansion is not the request's size but the
/// SOURCE document's fragmentation (one run per contiguous I-segment), so a
/// short list of specs over a fragmented document names spans without bound,
/// and each is two multi-component tumblers — order half a kilobyte live.
/// M7's `editlink` holds the finished slots to the same number, but it does
/// so inside its transaction, by which point the peak has been paid; refusing
/// as we build costs the client nothing (the same code, the same `Permanent`
/// disposition, the same refusal) and costs the engine one slot's worth of
/// spans instead of every spec's.
///
/// What remains unbounded is ONE spec's own `resolve` vector, which is M5's
/// allocation and one document's fragmentation — the same residual M7 carries
/// for MAKELINK's `Resolve` slots.
///
/// PRECEDENCE within the slot, since several specs may be wrong and exactly
/// one answer goes back: the specs are walked in order and the FIRST offending
/// one speaks, with `IllFormedSpec` ahead of `SourceNotRegistered` on that
/// spec. `SlotTooLarge` can arise only after every spec walked so far has
/// passed both. The two per-spec refusals localize the offender in
/// `site.index`; `SlotTooLarge` carries no site, being the slot's fault rather
/// than one spec's. [`FaultSite`] names no SLOT, so that index is read against
/// the slot the request-level precedence names — see [`crate::SuccessorSpec`].
///
/// Past the guard and under the budget the tail is infallible: `Run::iextent`
/// is total (every `Run` has `width ≥ 1` and an element-level `i_start`). An
/// empty from/to is structurally fine; M7 gates the type slot.
pub(crate) fn endset_from_vspecs(
    m3: &M3State,
    m5: &M5State,
    specs: &[VSpec],
) -> Result<Endset, Rejection> {
    let mut spans = Vec::new();
    for (index, vs) in specs.iter().enumerate() {
        if !is_content_vspan(&vs.span) {
            return Err(at_spec(index, RejectCode::IllFormedSpec));
        }
        if !m3.is_registered_document(&vs.source) {
            return Err(at_spec(index, RejectCode::SourceNotRegistered));
        }
        for run in m5.resolve(&vs.source, &vs.span) {
            if spans.len() == MAX_SLOT_SPANS {
                return Err(rejection(OpKind::EditLink, RejectCode::SlotTooLarge));
            }
            spans.push(run.iextent());
        }
    }
    Ok(Endset::from_spans(spans))
}

/// The refusal for one offending spec, localized by its position in the slot
/// under construction — the same `site.index` M6 threads for a malformed span
/// in a multi-spec request, so a client reads one field for both.
fn at_spec(index: usize, code: RejectCode) -> Rejection {
    Rejection::classified(
        OpKind::EditLink,
        code,
        Some(FaultSite { index: Some(index), ..FaultSite::default() }),
    )
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

    fn tum(comps: &[u32]) -> Tumbler {
        Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")
    }
    fn addr(comps: &[u32]) -> Address {
        validate(tum(comps)).unwrap_or_else(|_| panic!("T4-valid test address"))
    }
    fn span(start: &[u32], width: &[u32]) -> Span {
        Span::new(tum(start), tum(width)).unwrap_or_else(|_| panic!("well-formed test span"))
    }

    /// §4: the content-V guard — depth-2, content-subspace (s_C), ordinal-
    /// level — answering for a span of any shape, deeper and shallower
    /// included.
    #[test]
    fn only_a_depth_two_ordinal_level_content_span_passes_the_guard() {
        assert!(is_content_vspan(&span(&[1, 1], &[0, 2])));
        assert!(!is_content_vspan(&span(&[2, 1], &[0, 1]))); // link subspace
        assert!(!is_content_vspan(&span(&[1, 1], &[1, 0]))); // not ordinal-level
        assert!(!is_content_vspan(&span(&[5], &[1]))); // shallower than depth 2
        assert!(!is_content_vspan(&span(&[1, 1, 1], &[0, 0, 1])));
    }

    /// §4: the two faults this guard owns are typed and told apart — an
    /// ill-formed span is Permanent, an unregistered source is Reorder — and
    /// neither reaches `resolve`, whose ⟨⟩ would otherwise be deposited as an
    /// empty slot. Each localizes the offending spec in `site.index`.
    #[test]
    fn the_two_faults_this_guard_owns_are_typed_before_resolve() {
        let m3 = M3State::genesis();
        let m5 = M5State::genesis();
        let doc = addr(&[1, 0, 1, 0, 1]);

        let ill_formed = VSpec { source: doc.clone(), span: span(&[2, 1], &[0, 1]) };
        let rej = endset_from_vspecs(&m3, &m5, &[ill_formed]).expect_err("link-subspace span");
        assert_eq!(rej.op, OpKind::EditLink);
        assert_eq!(rej.code, RejectCode::IllFormedSpec);
        assert_eq!(rej.site.expect("localized").index, Some(0));

        // Well formed, and genesis M3 has registered no document: the spec
        // would resolve to ⟨⟩, so it is refused instead.
        let unregistered = VSpec { source: doc, span: span(&[1, 1], &[0, 1]) };
        let rej = endset_from_vspecs(&m3, &m5, &[unregistered]).expect_err("unregistered source");
        assert_eq!(rej.code, RejectCode::SourceNotRegistered);
        assert_eq!(rej.disposition, crate::reject::Disposition::Reorder);
        assert_eq!(rej.site.expect("localized").index, Some(0));

        // No specs is not a fault: an empty slot the CALLER asked for.
        assert!(endset_from_vspecs(&m3, &m5, &[]).expect("empty is fine").is_empty());
    }

    /// §4: within a slot the FIRST offending spec speaks, and `IllFormedSpec`
    /// speaks ahead of `SourceNotRegistered` on that spec — so a slot wrong
    /// in two places gets one answer, and the answer says which spec it is
    /// about.
    #[test]
    fn the_first_offending_spec_speaks_and_names_itself() {
        let m3 = M3State::genesis();
        let m5 = M5State::genesis();
        let doc = addr(&[1, 0, 1, 0, 1]);
        let ill_formed = || VSpec { source: doc.clone(), span: span(&[2, 1], &[0, 1]) };
        let unregistered = || VSpec { source: doc.clone(), span: span(&[1, 1], &[0, 1]) };

        // Both faults on ONE spec: the span is judged first.
        let rej = endset_from_vspecs(&m3, &m5, &[ill_formed()]).expect_err("both faults");
        assert_eq!(rej.code, RejectCode::IllFormedSpec, "the span is judged before the source");

        // Two offending specs, the later one ill-formed: the earlier speaks,
        // and its index is what comes back.
        let rej = endset_from_vspecs(&m3, &m5, &[unregistered(), ill_formed()])
            .expect_err("two offenders");
        assert_eq!(rej.code, RejectCode::SourceNotRegistered, "the first offender speaks");
        assert_eq!(rej.site.expect("localized").index, Some(0));
    }
}
