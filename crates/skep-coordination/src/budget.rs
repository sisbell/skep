//! §Internal 1/4 — the resource budget: what an untrusted PL term may command
//! of the process, and how each walk charges against it. Two numbers bound a
//! term — [`MAX_DEPTH`] its nesting, [`MAX_TERM_NODES`] its size — three
//! functions place a reference in levels ([`referent_depth`],
//! [`argument_depth`], [`reference_reach`]), one prices a built node
//! ([`weight`]), and one counter spends the size ([`Budget`]). Three doors
//! enforce the two numbers — the def decoder's, the checker's and the
//! expander's — refusing as `Malformed`, `TypeError::{TooDeep, TooLarge}` and
//! `ExpansionTooLarge`. Only the checker and the expander price by
//! [`weight`]: the decoder must refuse a count before the node it sizes
//! exists, so it charges every count it reads (`codec`'s `Rd::charge`) —
//! never less than [`weight`] charges the node it builds.
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
/// `a_reference_chain_at_the_cap_derives_cold_and_one_deeper_is_refused`,
/// `an_argument_free_reference_chain_at_the_cap_derives_cold`), so a cap
/// raised past the budget, or a walk grown past it, aborts there rather than
/// in a daemon.
pub(crate) const MAX_DEPTH: u32 = 128;

/// The levels a reference costs beyond its own node, in [`MAX_DEPTH`]'s
/// units: the frames between a `Ref` node's check and its referent's — the
/// resolver, the memo probe, the derivation — and the evaluator's and
/// expander's re-entry at the referent. [`referent_depth`] carries a walk
/// across these frames to the referent's root; [`reference_reach`] adds the
/// flat expansion's `Let` chain and the referent's own reach. Set against the
/// same measurement as [`MAX_DEPTH`], at its worst case: a chain of
/// argument-free references spends every level it is charged on derivations,
/// so registered to the cap it derives 65 deep on a cold memo — the deepest
/// derivation legitimate content can demand — and the suite derives it on a
/// default thread (`an_argument_free_reference_chain_at_the_cap_derives_cold`),
/// so a cost set too low, or a derivation frame grown past the budget, fails
/// there. Private to this module, as [`MAX_TERM_NODES`] is: a reference is
/// placed only through the three functions below, so its arithmetic has one
/// copy.
const DERIVATION_COST: u32 = 2;

/// The level at which a walk through a reference at level `depth` reaches
/// its referent's root, [`DERIVATION_COST`]'s frames past the reference:
/// where a cold derivation starts the referent's own check, and so the level
/// the checker asks the resolver for the referent at. A derivation from here
/// of a def that fits at level 0 — every def `register_pred` admits —
/// reaches this level plus the referent's reach, which is WITHIN
/// [`reference_reach`]: the charge adds the flat expansion's `Let` chain,
/// and no derivation builds one. So a derivation refused here means the
/// charge is past the cap too, and a cold memo never refuses a reference the
/// warm one would admit.
pub(crate) fn referent_depth(depth: u32) -> u32 {
    depth.saturating_add(DERIVATION_COST)
}

/// The level at which argument `i` of a reference at level `depth` is checked
/// — which is the level its own expansion will occupy. PR3a realizes a
/// reference as a `Let` chain binding the arguments ABOVE the referent's
/// body, argument `i` at position `i`, so argument `i` expands `i` levels
/// below the node's children and must be charged there. Charging every
/// argument at the children's level bounds the referent's splice point and
/// nothing else: `arity + argument reach` could carry the flat expansion past
/// [`MAX_DEPTH`] while every recorded level stayed inside it — and that
/// expansion is what `certify_stable`'s and `certify_rule`'s analyses walk,
/// with no depth bound of their own.
pub(crate) fn argument_depth(depth: u32, i: usize) -> u32 {
    depth.saturating_add(1).saturating_add(u32::try_from(i).unwrap_or(u32::MAX))
}

/// The deepest level a walk through a reference at level `depth` reaches:
/// past [`referent_depth`] to the referent's root, past the flat expansion's
/// `Let` chain (one level per argument — PR3a), and through the referent's
/// recorded reach. With [`referent_depth`] and [`argument_depth`] this is the
/// WHOLE of what a reference costs in levels, stated here so the checker that
/// charges it, the derivation it asks for, and the expander that builds to
/// match cannot drift: a change to `expand.rs`'s realization of a reference,
/// or to the frames a derivation spends, is a change to these three
/// functions, and the checker follows.
pub(crate) fn reference_reach(depth: u32, arity: usize, referent_reach: u32) -> u32 {
    referent_depth(depth)
        .saturating_add(u32::try_from(arity).unwrap_or(u32::MAX))
        .saturating_add(referent_reach)
}

/// The ONE budget on the SIZE of a PL tree, counted in NODES AND IN THE
/// PAYLOAD UNITS A NODE CARRIES ([`weight`]; the decoder charges the counts it
/// reads, at least as much), so what it bounds is the tree's bytes and not
/// merely its node count: what the def decoder builds from one run, what the
/// checker traverses and builds (`Reg` expansion instantiates a body once per
/// cataloged class, so nested `Reg` quantifiers multiply — six over a bare
/// leaf fit, seven do not — and a `Arc`-shared input is charged per
/// traversal, as a tree), and what the expander traverses and builds for one
/// flat reference expansion. A node is ~100 bytes behind its `Arc` and a
/// payload unit 24–56, so the budget is ~6 MiB of nodes plus ~4 MiB of
/// payload — held per memo entry and per captured rule trigger for the life
/// of the process, and transiently per expansion — against hand-authored
/// predicates of tens to hundreds of nodes. Past it: `Malformed` at the
/// decoder, `TypeError::TooLarge` at the checker, `ExpansionTooLarge` at the
/// expander. Private to this module: a walk reaches the cap only through
/// [`Budget`], so the comparison against it has one copy.
const MAX_TERM_NODES: usize = 1 << 16;

/// A built node's charge against [`MAX_TERM_NODES`] — what the checker and
/// the expander charge per node they visit or build (the decoder charges the
/// counts it reads instead, at least as much): one unit for the node itself,
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
///
/// No `_` arm, deliberately: the default here would be "no payload", the
/// unsafe answer for a former or literal that carries one, so one added to
/// `ast.rs` is priced here before the crate compiles. An atom, a prim or a
/// domain carries no such payload: its unbounded parts are child terms, each
/// charged as its own node, and its type positions are cataloged.
pub(crate) fn weight(t: &Term) -> usize {
    // Saturating, as [`Budget::charge`] is: a payload count that saturates
    // must not then wrap the node's own unit back to zero and charge nothing.
    1usize.saturating_add(match t {
        Term::Lit(Lit::Addr(a)) => a.tumbler().len(),
        Term::Lit(Lit::Nat(n)) => usize::try_from(n.bits().div_ceil(64)).unwrap_or(usize::MAX),
        Term::Ref { addr, .. } => addr.tumbler().len(),
        Term::Lit(Lit::True | Lit::False | Lit::BotAddr | Lit::BotNat)
        | Term::Var(_)
        | Term::Atom(_)
        | Term::Prim(_)
        | Term::And(..)
        | Term::Or(..)
        | Term::Not(_)
        | Term::Implies(..)
        | Term::Iff(..)
        | Term::Forall { .. }
        | Term::Exists { .. }
        | Term::Let { .. }
        | Term::IfSome { .. }
        | Term::Count(_)
        | Term::MaxT1(_)
        | Term::MinT1(_)
        | Term::BigUnion { .. }
        | Term::Reflect(_) => 0,
    })
}

/// ONE walk's spend against [`MAX_TERM_NODES`] — the counter the def decoder,
/// the checker (together with its `Reg` substitution) and the expander each
/// charge: the checker and the expander [`weight`] units per node, the decoder
/// every count it reads, before that count sizes anything. The arithmetic
/// lives here and nowhere else: a second copy of "saturating add, compare to
/// the cap" could drift into a plain `+`, and a wrapped counter bounds nothing
/// while the cap it reads still looks right.
///
/// A `Cell`, so a pass whose walk takes `&self` (the checker's) and a
/// sub-walk sharing the same counter (its `Reg` substitution's) need no
/// threaded `&mut`.
#[derive(Debug, Default)]
pub(crate) struct Budget(Cell<usize>);

impl Budget {
    /// Charge `weight` units — a built node and the payload it carries
    /// ([`weight`]), or a count the decoder read. `false` once the budget is
    /// spent AND EVERY TIME AFTER: the count only grows and saturates, which
    /// is why no walk needs an `exhausted` flag beside its counter.
    #[must_use = "the answer is the door: drop it and the walk builds past the budget"]
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

    /// The units charged so far — test builds only, for the law that the
    /// decoder never charges less than [`weight`] prices what it builds.
    #[cfg(test)]
    pub(crate) fn units(&self) -> usize {
        self.0.get()
    }
}
