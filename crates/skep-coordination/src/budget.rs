//! §Internal 1/4 — the resource budget: what an untrusted PL term may command
//! of the process, and how each walk charges against it. Two numbers bound a
//! term — [`MAX_DEPTH`] its nesting, [`MAX_TERM_NODES`] its size — one prices
//! a reference ([`DERIVATION_COST`]) and one prices a node ([`weight`]); three
//! doors enforce them, the def decoder's, the checker's and the expander's,
//! differing only in the refusal each answers with (`Malformed`,
//! `TypeError::{TooDeep, TooLarge}`, `ExpansionTooLarge`).
//!
//! Every walk over a term recurses once per former on the caller's thread and
//! none is bounded otherwise, so the caps are set against a MEASURED stack and
//! a MEASURED node size rather than chosen, and the suite drives each walk at
//! its boundary on a default thread — a cap raised past the budget, or a walk
//! grown past it, aborts there rather than in a daemon.

use crate::ast::{Lit, Term};

/// The ONE bound on the nesting of a PL tree, counted THROUGH references:
/// every walk over a term — the def decoder, the checker, the evaluator, the
/// expander, the analyzer — recurses once per former on the caller's thread,
/// and none is bounded otherwise. The decoder refuses a stored body nested
/// past it (`Malformed`); the checker refuses any term, stored or supplied,
/// whose evaluable projection — `Reg`-expansion joins and reference reaches
/// included — would carry a walk past it (`TypeError::TooDeep`), and records
/// each checked term's reach as `TypedTerm::reach`, so a reference chain is
/// bounded at registration rather than discovered at a cold derivation. The
/// value sits where all of the walks fit a default 2 MiB thread with margin in
/// a debug build (the checker, the heaviest, overflows one near 200 levels
/// there; a release build carries several times that), and far above any
/// hand-authored body. The suite runs each walk at exactly this depth on a
/// default thread (`a_hand_forged_body_at_the_decode_cap_survives_every_walk`,
/// `a_reference_chain_at_the_cap_derives_cold_and_one_deeper_is_refused`), so
/// a cap raised past the budget, or a walk grown past it, aborts there rather
/// than in a daemon.
pub(crate) const MAX_DEPTH: u32 = 128;

/// The levels a reference costs beyond its own node, in [`MAX_DEPTH`]'s
/// units: the frames between a `Ref` node's check and its referent's — the
/// resolver, the memo probe, the derivation — and the evaluator's and
/// expander's re-entry at the referent. Each argument is charged one more on
/// top of this (the flat expansion's `Let` per argument). Set against the
/// same measurement as [`MAX_DEPTH`]: the chain test derives a chain
/// registered to the cap cold, on a default thread, so a cost set too low
/// aborts there.
pub(crate) const DERIVATION_COST: u32 = 2;

/// The ONE budget on the SIZE of a PL tree, counted in NODES AND IN THE
/// PAYLOAD UNITS A NODE CARRIES ([`weight`]), so what it bounds is the tree's
/// bytes and not merely its node count: what the def decoder builds from one
/// run, what the checker traverses and builds (`Reg` expansion instantiates a
/// body once per cataloged class, so nested `Reg` quantifiers multiply — six
/// over a bare leaf fit, seven do not — and a `Arc`-shared input is charged
/// per traversal, as a tree), and what the expander traverses and builds for
/// one flat reference expansion. A node is ~100 bytes behind its `Arc` and a
/// payload unit 24–56, so the budget is ~6 MiB of nodes plus ~4 MiB of
/// payload — held per memo entry and per captured rule trigger for the life
/// of the process, and transiently per expansion — against hand-authored
/// predicates of tens to hundreds of nodes. Past it: `Malformed` at the
/// decoder, `TypeError::TooLarge` at the checker, `ExpansionTooLarge` at the
/// expander.
pub(crate) const MAX_TERM_NODES: usize = 1 << 16;

/// A node's charge against [`MAX_TERM_NODES`]: one unit for the node itself,
/// plus one for each unit of PAYLOAD it carries that no gate bounds — a
/// `Lit::Addr`'s tumbler components, a `Lit::Nat`'s 64-bit limbs, a `Ref`'s
/// address components. Measured, each of those is 24–56 bytes against a bare
/// node's ~100, so the units are comparable; each is also COPIED WHOLE by
/// every pass that rebuilds the tree, and that is the reason for the charge:
/// `Reg` expansion instantiates a body once per cataloged class and a
/// reference expansion once per reference, so a payload charged as one node
/// would multiply by 5^d resp. 2^d while the node count did not. A type
/// position's endset is deliberately NOT charged — `Checker::guarded` refuses
/// a non-cataloged key at the first instance, so it is copied once and dies.
pub(crate) fn weight(t: &Term) -> usize {
    1 + match t {
        Term::Lit(Lit::Addr(a)) => a.tumbler().len(),
        Term::Lit(Lit::Nat(n)) => usize::try_from(n.bits().div_ceil(64)).unwrap_or(usize::MAX),
        Term::Ref { addr, .. } => addr.tumbler().len(),
        _ => 0,
    }
}
