//! §Internal 1/4 — the resource budget: what an untrusted PL term may command
//! of the process, and how each walk charges against it. Two numbers bound a
//! term — [`MAX_DEPTH`] its nesting, [`MAX_TERM_NODES`] its size — a pair of
//! functions prices a reference in levels ([`argument_depth`],
//! [`reference_reach`], over [`DERIVATION_COST`]), one prices a node
//! ([`weight`]), and one counter spends the size ([`Budget`]); three doors
//! enforce them, the def decoder's, the checker's and the expander's,
//! differing only in the refusal each answers with (`Malformed`,
//! `TypeError::{TooDeep, TooLarge}`, `ExpansionTooLarge`).
//!
//! Every walk over a term recurses once per former on the caller's thread and
//! none is bounded otherwise, so the caps are set against a MEASURED stack and
//! a MEASURED node size rather than chosen, and the suite drives each walk at
//! its boundary on a default thread — a cap raised past the budget, or a walk
//! grown past it, aborts there rather than in a daemon.

use std::cell::Cell;

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
/// expander's re-entry at the referent. [`reference_reach`] composes this
/// with the flat expansion's `Let` chain and the referent's own reach;
/// [`argument_depth`] places each argument in that chain. Set against the
/// same measurement as [`MAX_DEPTH`]: the chain test derives a chain
/// registered to the cap cold, on a default thread, so a cost set too low
/// aborts there.
pub(crate) const DERIVATION_COST: u32 = 2;

/// The level at which argument `i` of a reference at level `node` is checked
/// — which is the level its own expansion will occupy. PR3a realizes a
/// reference as a `Let` chain binding the arguments ABOVE the referent's
/// body, argument `i` at position `i`, so argument `i` expands `i` levels
/// below the node's children and must be charged there. Charging every
/// argument at the children's level bounds the referent's splice point and
/// nothing else: `arity + argument reach` could carry the flat expansion past
/// [`MAX_DEPTH`] while every recorded level stayed inside it — and that
/// expansion is what `certify_stable`'s and `certify_rule`'s analyses walk,
/// with no depth bound of their own.
pub(crate) fn argument_depth(node: u32, i: usize) -> u32 {
    node.saturating_add(1).saturating_add(u32::try_from(i).unwrap_or(u32::MAX))
}

/// The deepest level a walk through a reference at level `node` reaches: past
/// [`DERIVATION_COST`] to the referent's own check, past the flat expansion's
/// `Let` chain (one level per argument — PR3a), and through the referent's
/// recorded reach. With [`argument_depth`] this is the WHOLE of what a
/// reference costs in levels, stated here so the checker that charges it and
/// the expander that builds to match cannot drift: a change to `expand.rs`'s
/// realization of a reference is a change to these two functions, and the
/// checker follows.
pub(crate) fn reference_reach(node: u32, arity: usize, referent_reach: u32) -> u32 {
    node.saturating_add(DERIVATION_COST)
        .saturating_add(u32::try_from(arity).unwrap_or(u32::MAX))
        .saturating_add(referent_reach)
}

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
    // Saturating, as [`Budget::charge`] is: a payload count that saturates
    // must not then wrap the node's own unit back to zero and charge nothing.
    1usize.saturating_add(match t {
        Term::Lit(Lit::Addr(a)) => a.tumbler().len(),
        Term::Lit(Lit::Nat(n)) => usize::try_from(n.bits().div_ceil(64)).unwrap_or(usize::MAX),
        Term::Ref { addr, .. } => addr.tumbler().len(),
        _ => 0,
    })
}

/// ONE walk's spend against [`MAX_TERM_NODES`] — the counter the def decoder,
/// the checker (together with its `Reg` substitution) and the expander each
/// charge [`weight`] units to. The arithmetic lives here and nowhere else: a
/// second copy of "saturating add, compare to the cap" could drift into a
/// plain `+`, and a wrapped counter bounds nothing while the cap it reads
/// still looks right.
///
/// A `Cell`, so a pass whose walk takes `&self` (the checker's) and a
/// sub-walk sharing the same counter (its `Reg` substitution's) need no
/// threaded `&mut`.
#[derive(Debug, Default)]
pub(crate) struct Budget(Cell<usize>);

impl Budget {
    /// Charge `weight` units — a node and the payload it carries. `false`
    /// once the budget is spent AND EVERY TIME AFTER: the count only grows
    /// and saturates, which is why no walk needs an `exhausted` flag beside
    /// its counter.
    pub(crate) fn charge(&self, weight: usize) -> bool {
        let n = self.0.get().saturating_add(weight);
        self.0.set(n);
        n <= MAX_TERM_NODES
    }

    /// Is the budget spent? For the walks that cannot refuse at the node
    /// where it happens — a `Rewrite` returns a `Term`, not a `Result` — and
    /// so must ask afterwards.
    pub(crate) fn spent(&self) -> bool {
        self.0.get() > MAX_TERM_NODES
    }
}
