//! The pinned payload read — AUTH-2.3–2.5, AUTH-2.36–2.45.
//!
//! One doorkeeper: world spans in, record bytes out. The four payload pins
//! (the per-span check order, the reach walk, the byte cap, home anchoring)
//! are permanent protocol pins — I2 frozen constants (AUTH-2.90). A Rust
//! non-folding reader obtains the read by linking [`record_bytes`], never by
//! re-implementing it (AUTH-2.37). The bytes it answers are the grammar's
//! input; `crate::payload` takes them from there.

use skep_address::{document_of, shift, validate, Address, Level, Nat, Span};

use crate::payload::{PayloadError, MAX_RECORD_BYTES};
use crate::seam::Values;

/// Reads a record's bytes off the link's `from` spans (AUTH-2.36).
///
/// It is the one implementation of the pinned payload read: the link's own
/// `from` endset, its I-spans' bytes read in endset order and concatenated,
/// verbatim (span binding, AUTH-2.3 — nothing sorts, dedups, normalizes or
/// coalesces; spans may repeat, overlap, or split an entry, AUTH-2.4).
/// Bound at [`Values`] — the one-method supertrait, never the whole world
/// seam; the cap, [`MAX_RECORD_BYTES`], is fixed inside the read and is not
/// a parameter.
///
/// **Precondition.** `home` is the link's home document: a document-level
/// address, what M1 `document_of` answers for the link's own address
/// (AUTH-2.82). Check 3 compares `document_of(start)` — always a document —
/// against it, so a `home` at any other level matches nothing a span can
/// carry: every span refuses `ForeignContent` and every record is inert,
/// silently and in release. Nothing here checks it and there is nothing to
/// check — `home` is the caller's own datum. [`LinkDeposit`]'s precondition
/// places it on that type's constructors (AUTH-2.23) — the fold hook has it
/// from `document_of`, the daemon's precheck in `skep-core` owes it of the
/// request frame's `home` — and a non-folding reader linking this function
/// (AUTH-2.37) owes the same.
///
/// [`LinkDeposit`]: crate::LinkDeposit
///
/// # Errors
///
/// Per span, in endset order, the checks run in this order — the first
/// failure is the verdict (AUTH-2.38), and the per-span interleave is pinned
/// (AUTH-2.39: each span's checks and positions complete before the next
/// span's checks begin — never a home pass over every span first):
///
/// 1. the start validates to an `Address` (M1), else `ForeignContent`;
/// 2. the start is an element position — element field exactly two
///    components, a subspace and an ordinal (AUTH-2.40); a document-level
///    start, a subspace-only start, and a deeper element field are each
///    T4-valid non-positions ⇒ `ForeignContent`, never coerced. The test
///    constrains the field's shape, never which subspace it names
///    (AUTH-2.41: a link-subspace start is a position and walks to
///    `MissingValue`);
/// 3. `document_of(start) == home` (home anchoring, AUTH-2.44), else
///    `ForeignContent` before a byte of that span is read;
///
/// then, per position of the span — the reach walk is M1 `shift(t, 1)` from
/// `span.start()`, taken while the address is still inside the span's reach,
/// never a count read off `width`'s last component (AUTH-2.42):
///
/// 4. the value — `ctx.value_at(t)`; `None` ⇒ `MissingValue` (reachable:
///    an endset names addresses verbatim, AUTH-2.45);
/// 5. the cap — `TooLarge` iff the bytes appended so far plus this value's
///    length exceed `MAX_RECORD_BYTES`, checked before appending
///    (AUTH-2.43), so at most `MAX_RECORD_BYTES` bytes are ever copied.
///
/// Termination is bounded twice, because a span whose width acts above the
/// element level covers every ordinal above its start and so bounds nothing
/// itself. The byte cap ends the walk on a conforming ctx — one that keeps
/// AUTH-1.22's wire-codec premise, [`Values`]' declared obligation, that
/// every value carries at least one byte. Where a ctx answers a zero-byte
/// value at every position such a span covers, the cap can never fire, and
/// in a release build the per-record position budget below ends the walk
/// instead, in bounded work, answering `TooLarge` past `MAX_RECORD_BYTES`
/// positions.
///
/// The budget is not a sixth pinned check and does not touch AUTH-2.38's
/// order: it sits after items 4 and 5, and it cannot fire on a conforming
/// ctx in any cell — after the k-th append such a ctx has `out.len() >= k`,
/// and item 5 has already refused every `k > MAX_RECORD_BYTES`.
///
/// # Panics
///
/// Panics in a debug build where `ctx` answers a zero-byte value at a
/// position the walk reaches: the wire-codec premise above, broken.
pub fn record_bytes(
    ctx: &impl Values,
    home: &Address,
    from: &[Span],
) -> Result<Vec<u8>, PayloadError> {
    let one = Nat::from(1u32);
    let mut out: Vec<u8> = Vec::new();
    // AUTH-1.22's premise as a bound rather than a note: in a release build,
    // the only thing that ends this walk over a span whose width acts above
    // the element level under a ctx answering a zero-byte value at every
    // position the span covers, and unreachable under one that keeps the
    // premise. It bounds the worst case; it does not detect a violation
    // (`Values`).
    let mut positions: usize = 0;
    for span in from {
        // 1 — validity (checked once per span, ahead of the walk: AUTH-2.30).
        let Ok(start) = validate(span.start().clone()) else {
            return Err(PayloadError::ForeignContent);
        };
        // 2 — position-hood (AUTH-2.40): element level, field =
        // subspace·ordinal.
        let is_position = start.level() == Level::Element
            && start.element_field().is_some_and(|field| field.len() == 2);
        if !is_position {
            return Err(PayloadError::ForeignContent);
        }
        // 3 — home anchoring (AUTH-2.44), before a byte of the span is read.
        let Some(span_doc) = document_of(&start) else {
            // Unreachable: an element-level address has a document prefix;
            // kept total rather than panicking (AUTH-2.57).
            return Err(PayloadError::ForeignContent);
        };
        if span_doc != *home {
            return Err(PayloadError::ForeignContent);
        }
        // The reach walk (AUTH-2.42). The span's reach — `start ⊕ width`, M1
        // `Span::reach` — is a derivation of two operands this loop never
        // touches, so it is taken once per span. M1's `Span::contains`
        // recomputes it on every call, and `⊕` allocates and clones one
        // component per component of `width`, whose tail it copies verbatim
        // into the reach; T12 bounds the width's action point and says nothing
        // about its component count, so a wire-chosen width can be
        // arbitrarily long. Asked per position, inside a loop the byte cap
        // bounds at `MAX_RECORD_BYTES`, that would let one width multiply the
        // work of every position it covers; taken here, the per-position cost
        // is the start's component count, which home anchoring pins at
        // `#home + 3`.
        let reach = span.reach();
        let mut pos = span.start().clone();
        // `start ≤ pos < reach` — M1 `Span::contains`' half-open membership,
        // spelled against the reach above. Two spellings of one rule, so the
        // agreement is checked rather than assumed:
        // `reach_walk_membership_agrees_with_span_contains`.
        while *span.start() <= pos && pos < reach {
            // 4 — the value, as of the ctx's commit (AUTH-2.38 item 4).
            let Some(value) = ctx.value_at(&pos) else {
                return Err(PayloadError::MissingValue);
            };
            debug_assert!(
                !value.is_empty(),
                "Values answered a zero-byte value at a covered position — \
                 AUTH-1.22's premise is broken and the byte cap bounds nothing"
            );
            // 5 — the cap, before the value is appended (AUTH-2.43).
            if out.len() + value.len() > MAX_RECORD_BYTES {
                return Err(PayloadError::TooLarge);
            }
            out.extend_from_slice(value);
            // The position budget, after items 4 and 5 so the pinned fault
            // precedence is untouched. `>` and not `>=`: a record of exactly
            // `MAX_RECORD_BYTES` one-byte positions is a legal record — the
            // exceed-only boundary of AUTH-2.43, read in positions.
            positions += 1;
            if positions > MAX_RECORD_BYTES {
                return Err(PayloadError::TooLarge);
            }
            pos = shift(&pos, &one);
        }
    }
    Ok(out)
}
