//! THE RESUME's ARMS (`search.md` §5.4; ITEM 1 RULED (a) and its riders), one
//! test per arm, named by §5.4's words — the fence: `history_reclaimed` with
//! the `H.k` byte-equal is FROM THE FLOOR and with the `H.k` different is
//! DIVERGED, a test that fails if the byte-compare is dropped.

use super::*;
use skep_address::{validate, Address, Nat, Tumbler};

fn chain(fill: u8) -> Chain {
    Chain::from_bytes([fill; 32])
}

fn at(position: u64, fill: u8) -> ChainAt {
    ChainAt { position, chain: chain(fill) }
}

/// `1.1.0.1.0.2.k` — a head member's address.
fn member(k: u32) -> Address {
    let t = Tumbler::new([1u32, 1, 0, 1, 0, 2, k].map(Nat::from)).expect("nonempty");
    validate(t).expect("a T4-valid address")
}

fn head(k: u32, position: u64, fill: u8) -> HeadRecord {
    HeadRecord { member: member(k), at: at(position, fill) }
}

/// §5.4: "an EQUAL chain resumes".
#[test]
fn an_equal_chain_resumes() {
    let held = at(900, 0xAA);
    let saved = head(3, 512, 0x33);
    let verdict = Resume::judge(held, Some(&saved), &ChainAnswer::Chain(chain(0xAA)));
    assert_eq!(verdict, Resume::Equal);
    assert_eq!(Resume::judge(held, None, &ChainAnswer::Chain(chain(0xAA))), Resume::Equal);
}

/// §5.4, ITEM 1 (a) with rider 1: "`history_reclaimed` … KEEPS THE FILE":
/// the `H.k` re-read byte-equal, "each range resumes from the `floor` the
/// answer carries" — and from the beginning where the answer named none.
#[test]
fn history_reclaimed_with_the_h_k_byte_equal_resumes_from_the_floor() {
    let held = at(900, 0xAA);
    let saved = head(3, 512, 0x33);
    let reclaimed = ChainAnswer::Reclaimed { floor: Some(2048), head: Some(at(512, 0x33)) };
    assert_eq!(
        Resume::judge(held, Some(&saved), &reclaimed),
        Resume::FromTheFloor { floor: Some(2048) }
    );
    let unknown = ChainAnswer::Reclaimed { floor: None, head: Some(at(512, 0x33)) };
    assert_eq!(Resume::judge(held, Some(&saved), &unknown), Resume::FromTheFloor { floor: None });
}

/// §5.4, rider 1: the `H.k` "different, gone, or superseded by an older
/// newest head" takes the DIVERGED disposition — a different chain at the
/// same position, the same chain at a different position, the member gone,
/// and a file that saved no head to compare — the saved pair carried for the
/// face. The compare is byte-equal: position AND chain.
#[test]
fn history_reclaimed_with_a_different_h_k_is_diverged() {
    let held = at(900, 0xAA);
    let saved = head(3, 512, 0x33);
    let diverged = Resume::Diverged { saved: held };
    let reclaimed = |head| ChainAnswer::Reclaimed { floor: Some(2048), head };
    assert_eq!(
        Resume::judge(held, Some(&saved), &reclaimed(Some(at(512, 0x34)))),
        diverged,
        "a different chain at the saved position"
    );
    assert_eq!(
        Resume::judge(held, Some(&saved), &reclaimed(Some(at(513, 0x33)))),
        diverged,
        "the saved chain at another position"
    );
    assert_eq!(Resume::judge(held, Some(&saved), &reclaimed(None)), diverged, "gone");
    assert_eq!(
        Resume::judge(held, None, &reclaimed(Some(at(512, 0x33)))),
        diverged,
        "no saved head to stand by"
    );
}

/// §5.4, rider 2: "`beyond_head` … is FACED BEFORE ANYTHING IS REBUILT" —
/// the verdict carries the saved pair as the wire's evidence of a re-chained
/// journal, and the head the answer named.
#[test]
fn beyond_head_is_faced_with_the_saved_pair_as_the_evidence() {
    let held = at(900, 0xAA);
    let saved = head(3, 512, 0x33);
    assert_eq!(
        Resume::judge(held, Some(&saved), &ChainAnswer::BeyondHead { head: 640 }),
        Resume::BeyondHead { saved: held, head: 640 }
    );
}

/// §5.4, rider 2: "a DIFFERENT chain … is FACED BEFORE ANYTHING IS REBUILT"
/// — the saved pair and the chain found, for the face.
#[test]
fn a_different_chain_is_faced_with_the_saved_pair_as_the_evidence() {
    let held = at(900, 0xAA);
    let saved = head(3, 512, 0x33);
    assert_eq!(
        Resume::judge(held, Some(&saved), &ChainAnswer::Chain(chain(0xAB))),
        Resume::DifferentChain { saved: held, found: chain(0xAB) }
    );
}

/// §5.4: "`history_busy` is retry-class and retried, never a rebuild".
#[test]
fn history_busy_is_retry_class() {
    let held = at(900, 0xAA);
    let saved = head(3, 512, 0x33);
    assert_eq!(Resume::judge(held, Some(&saved), &ChainAnswer::Busy), Resume::Busy);
    assert_eq!(Resume::judge(held, None, &ChainAnswer::Busy), Resume::Busy);
}
