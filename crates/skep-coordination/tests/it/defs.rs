//! M9 contract tests over a real kernel (InMemory), group B — predicate
//! definitions as content: store/register/evaluate/supersede/certify/
//! retract, the PR-ENC byte contract as `register_pred` reads it back, the
//! memo's two permanent statuses and the answers it never keeps, and the
//! registration probes — class-free beside the guest-class look, and exact
//! where PL's `is_K` matches by coverage. Every assertion states a claim the
//! design or interface makes — nothing more.
//!
//! The claims live in this module's children, one concern each: `lifecycle`
//! (define, register, retract and supersede, and what each returns), `gates`
//! (every refusal a def write meets, and the order they speak in), `budgets`
//! (the resource doors on the stored-bytes path), `resolution` (the memo's
//! statuses, and the registration probes: class-free beside the guest-class
//! look, and matching a start exactly), `evaluation` (a stored def's
//! denotation, its argument door, and the source form it is stored as) and
//! `certification` (`certify_stable`'s legs). The PR-ENC spellings below are
//! what `gates`, `budgets` and `resolution` forge stored content with.

mod budgets;
mod certification;
mod evaluation;
mod gates;
mod lifecycle;
mod resolution;

/// PR-ENC's minimal-form LEB128, the one length/count encoding the format
/// uses.
fn varint(mut x: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let limb = (x & 0x7f) as u8;
        x >>= 7;
        if x == 0 {
            out.push(limb);
            return out;
        }
        out.push(limb | 0x80);
    }
}

/// PR-ENC's envelope around a payload: the minimal varint length, then the
/// bytes.
fn envelope(payload: Vec<u8>) -> Vec<u8> {
    let mut out = varint(payload.len() as u64);
    out.extend(payload);
    out
}

/// A hand-forged closed body `¬^depth ⊤` in PR-ENC (`¬` is one tag per
/// level over the closed `True`, which the codec's own suite pins).
fn forged_negations(depth: usize) -> Vec<u8> {
    let mut payload = vec![0u8]; // no parameters
    payload.extend(std::iter::repeat_n(7u8, depth)); // NOT, per level
    payload.extend([2u8, 1]); // LIT, TRUE
    envelope(payload)
}
