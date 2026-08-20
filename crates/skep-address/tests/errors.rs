//! The uniform rejection surface: every public error of this crate renders
//! itself and travels as a [`std::error::Error`] — required of the three that
//! back a validating deserialization shadow, and held uniformly so that a
//! caller boxing any of the others meets the same surface.

mod common;

use std::error::Error;

use common::*;
use skep_address::*;

/// Accepts only a rejection carrying the whole surface, and reads its
/// rendering back THROUGH the box — so a rejection that stopped being
/// reportable fails to compile here rather than at the boundary that needed
/// it.
fn reported<E: Error + 'static>(e: E) -> String {
    let boxed: Box<dyn Error> = Box::new(e);
    boxed.to_string()
}

/// One instance of every public rejection, each produced by the operation that
/// owns it. Renderings are distinct, so a message identifies which refusal was
/// met rather than merely reporting that one was.
#[test]
fn every_public_rejection_reports_itself() {
    let elem = addr(&[1, 0, 2, 0, 5, 0, 1, 9]);
    let renderings = [
        reported(Tumbler::new(std::iter::empty::<Nat>()).unwrap_err()), // EmptySequence
        reported(validate(t(&[0])).unwrap_err()),                       // T4Error
        reported(add(&t(&[1]), &t(&[0, 0])).unwrap_err()),              // AddPrecond
        reported(sub(&t(&[1, 2]), &t(&[1, 3])).unwrap_err()),           // SubPrecond
        reported(checked_inc(&elem, 2).unwrap_err()),                   // GateViolation
        reported(intersect(&sp(&[1], &[2]), &sp(&[5, 0], &[6, 0])).unwrap_err()), // LevelMismatch
        reported(Span::new(t(&[1]), t(&[0])).unwrap_err()),             // T12Clause
        reported(Span::from_endpoints(t(&[2]), &t(&[2])).unwrap_err()), // WfError
        reported(split(&sp(&[1], &[9]), &t(&[1])).unwrap_err()),        // SplitError
        reported(
            elem_addr(ElemPos {
                doc: addr(&[1, 0, 2]),
                subspace: n(1),
                ordinal: n(1),
            })
            .unwrap_err(),
        ), // ElemError
    ];
    for (i, r) in renderings.iter().enumerate() {
        assert!(!r.is_empty(), "rejection {i} renders as the empty string");
        for other in &renderings[i + 1..] {
            assert_ne!(r, other, "two rejections render identically: {r}");
        }
    }
}
