//! The pinned payload read — AUTH-2.3–2.5, AUTH-2.36–2.45.
//!
//! One doorkeeper: world SPANS in, record bytes out. The four payload pins
//! (the per-span check order, the reach walk, the byte cap, home anchoring)
//! are PERMANENT protocol pins — I2 frozen constants (AUTH-2.90). A Rust
//! non-folding reader obtains the read by LINKING [`record_bytes`], never by
//! re-implementing it (AUTH-2.37). The bytes it answers are the grammar's
//! input; `crate::payload` takes them from there.

use skep_address::{document_of, shift, validate, Address, Level, Nat, Span};

use crate::payload::{PayloadError, MAX_RECORD_BYTES};
use crate::seam::Values;

/// AUTH-2.36 — THE ONE implementation of the pinned payload read: the
/// link's own FROM endset, its I-spans' bytes read in ENDSET ORDER and
/// concatenated, verbatim (SPAN BINDING, AUTH-2.3 — nothing sorts, dedups,
/// normalizes or coalesces; spans may repeat, overlap, or split a line,
/// AUTH-2.4). Bound at [`Values`] — the one-method supertrait, never the
/// whole world seam; [`MAX_RECORD_BYTES`] is INTERNAL and not a parameter.
///
/// Per SPAN, in endset order, the checks run in THIS order — the first
/// failure is the verdict (AUTH-2.38), and the per-span INTERLEAVE is pinned
/// (AUTH-2.39: each span's checks and positions complete before the next
/// span's checks begin — never a home pass over every span first):
///
/// 1. the start VALIDATES to an `Address` (M1), else `ForeignContent`;
/// 2. the start is an element POSITION — element field EXACTLY two
///    components, a subspace and an ordinal (AUTH-2.40); a document-level
///    start, a subspace-only start, and a deeper element field are each
///    T4-valid NON-positions ⇒ `ForeignContent`, never coerced. The test
///    constrains the field's SHAPE, never which subspace it names
///    (AUTH-2.41: a link-subspace start IS a position and walks to
///    `MissingValue`);
/// 3. `document_of(start) == home` (HOME ANCHORING, AUTH-2.44), else
///    `ForeignContent` before a byte of that span is read;
///
/// then, per POSITION of the span — the reach WALK is M1 `shift(t, 1)` from
/// `span.start()`, taken while the address is still inside the span's reach,
/// NEVER a count read off `width`'s last component (AUTH-2.42):
///
/// 4. the value — `ctx.value_at(t)`; `None` ⇒ `MissingValue` (reachable:
///    an endset names addresses verbatim, AUTH-2.45);
/// 5. the cap — `TooLarge` iff the bytes appended so far plus THIS value's
///    length exceed `MAX_RECORD_BYTES`, checked BEFORE appending
///    (AUTH-2.43), so at most `MAX_RECORD_BYTES` bytes are ever copied.
///
/// Termination rides on the byte cap alone, and so on AUTH-1.22's wire-codec
/// premise: a span whose width acts above the element level covers every
/// ordinal above its start, so only growing `out` ends the walk. That premise
/// is [`Values`]' declared obligation, debug-asserted here at the one call
/// that depends on it; a round admitting zero-byte values must add a second
/// bound before this walk can run under it.
pub fn record_bytes(
    ctx: &impl Values,
    home: &Address,
    from: &[Span],
) -> Result<Vec<u8>, PayloadError> {
    let one = Nat::from(1u32);
    let mut out: Vec<u8> = Vec::new();
    for span in from {
        // 1 — validity (checked ONCE per span, ahead of the walk: AUTH-2.30).
        let Ok(start) = validate(span.start().clone()) else {
            return Err(PayloadError::ForeignContent);
        };
        // 2 — position-hood (AUTH-2.40): element level, field = subspace·ordinal.
        let is_position = start.level() == Level::Element
            && start.element_field().is_some_and(|field| field.len() == 2);
        if !is_position {
            return Err(PayloadError::ForeignContent);
        }
        // 3 — home anchoring (AUTH-2.44), before a byte of the span is read.
        let Some(span_doc) = document_of(&start) else {
            // Unreachable: an Element-level address has a document prefix;
            // kept total rather than panicking (AUTH-2.57).
            return Err(PayloadError::ForeignContent);
        };
        if span_doc != *home {
            return Err(PayloadError::ForeignContent);
        }
        // The reach walk (AUTH-2.42).
        let mut t = span.start().clone();
        while span.contains(&t) {
            // 4 — the value, as of the ctx's position (AUTH-2.38 item 4).
            let Some(value) = ctx.value_at(&t) else {
                return Err(PayloadError::MissingValue);
            };
            debug_assert!(
                !value.is_empty(),
                "Values answered a zero-byte value at a covered position — \
                 AUTH-1.22's premise is broken and this walk is unbounded"
            );
            // 5 — the cap, BEFORE the value is appended (AUTH-2.43).
            if out.len() + value.len() > MAX_RECORD_BYTES {
                return Err(PayloadError::TooLarge);
            }
            out.extend_from_slice(value);
            t = shift(&t, &one);
        }
    }
    Ok(out)
}
