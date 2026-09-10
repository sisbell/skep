//! §3 — the four-set descriptor family (ASN-0121/0132): address-keyed,
//! conjunctive, link-store-local (FL-LOC — no document gate), monotone absent
//! retraction (FL-MON/CN-MONO). Not a restriction of the region family and
//! not built on it (ASN-0121 is explicit; Conflicts #2) — the same per-slot
//! `stab` combined oppositely (AND vs OR), with the AND owned by M7's
//! `match_links` (Conflicts #1: M8 implements no combiner).

use im::OrdSet;
use skep_address::Address;
use skep_kernel::Snapshot;
use skep_links::{LinkState, View};

use crate::helpers::{home_readable, window_over};
use crate::types::{Cursor, FourSet, Window};
use crate::DiscoveryWorld;

/// ASN-0121's CANDIDATE set: the descriptor's constrained LINK slots handed
/// to M7's AND-of-ORs over the ACTIVE view, and no constraints at all
/// (`(∗,∗,∗)`) reading as the whole active slice. It is not yet the match —
/// the home slot is not a link slot, and narrowing by it is the residence
/// post-filter [`satisfying`] applies. The descriptor reads its own slots —
/// which are the zero, which drop out — in [`FourSet::link_constraints`].
///
/// The unsatisfiable case returns without touching the store. M7 would answer
/// the same way if it could be asked — `stab(slot, ⟨⟩, ·) = ∅` empties the
/// AND — but an `Empty` slot carries no endset to ask WITH, so this is where
/// FL-EMP is answered for the link slots, not merely where it is anticipated.
pub(crate) fn candidates(l: &LinkState, q: &FourSet) -> OrdSet<Address> {
    match q.link_constraints() {
        None => OrdSet::new(), // FL-EMP: some slot is the zero
        Some(constraints) => l.match_links(&constraints, View::Active),
    }
}

/// `sat(·, q, Σ)` — THE one definition of "matches" for the descriptor
/// family. ASN-0132's CN-ENUM forces exactly one, consumed by enumeration and
/// by count alike, so [`findlinks_ftt_on`] and [`count_ftt_on`] are two
/// read-outs of this one set and cannot disagree about which links match.
///
/// ASN-0121's [`candidates`] narrowed by the residence post-filter
/// [`FourSet::at_home`] — the home-bound placement M8 chose, since M8 owns no
/// index dimension keyed on `home(a)` (Conflicts #7: a home-only query
/// degrades to a full active scan, accepted).
pub(crate) fn satisfying(l: &LinkState, q: &FourSet) -> OrdSet<Address> {
    candidates(l, q)
        .into_iter()
        .filter(|a| q.at_home(a))
        .collect()
}

/// FINDLINKS over the four-set descriptor (ASN-0121): the links satisfying
/// the descriptor, in address order. Total — no doc gate (FL-LOC).
/// `(∗,∗,∗,∗)` = the whole addressable slice (FL-WILD); any constrained-empty
/// slot ⇒ `[]` (FL-EMP). Monotone absent retraction (FL-MON): a found link
/// stays found unless nullified.
///
/// Answers for NO READER: every satisfying link is disclosed, whatever its
/// home — the route for principal-free callers. A caller answering for a
/// reading principal asks [`findlinks_ftt_on_where`].
pub fn findlinks_ftt_on<W: DiscoveryWorld>(s: &Snapshot<W>, q: &FourSet) -> Vec<Address> {
    findlinks_ftt_on_where(s, q, &|_| true)
}

/// [`findlinks_ftt_on`] with the result-set filter (PUB round 2, lane 3.3,
/// §3): every satisfying link whose HOME the reader may not read is dropped at
/// its identity. The descriptor's own `home` slot is a COVERAGE constraint
/// (CN-STAB); this consult is the authorization one, orthogonal to it.
pub fn findlinks_ftt_on_where<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    q: &FourSet,
    readable: &dyn Fn(&Address) -> bool,
) -> Vec<Address> {
    satisfying(s.world().links(), q)
        .into_iter()
        .filter(|a| home_readable(readable, a))
        .collect()
}

/// The count operation over the descriptor family (ASN-0132 CN-*): the
/// existence census — monotone absent retraction (CN-MONO). The cardinality
/// of the same `sat` set [`findlinks_ftt_on`] enumerates, so CN-ENUM's
/// `count = |enumeration|` holds by construction rather than by promise.
///
/// CN-ZERO: a returned `0` is a verdict over the WHOLE addressable store —
/// no addressable link satisfies `q` — never present unreachability (which is
/// [`crate::count_v_on`]'s D-ZERO) and never an exhaustion artefact of a scan
/// that gave up. The third zero, the degenerate request that names nothing,
/// is answerable off the descriptor alone through
/// [`FourSet::is_unsatisfiable`]: same number, different assertion.
///
/// Answers for NO READER, counting every satisfying link whatever its home;
/// a caller answering for a reading principal asks [`count_ftt_on_where`].
pub fn count_ftt_on<W: DiscoveryWorld>(s: &Snapshot<W>, q: &FourSet) -> usize {
    count_ftt_on_where(s, q, &|_| true)
}

/// [`count_ftt_on`] answering the FILTERED cardinality (PUB round 2, lane 3.3,
/// §3; PUB-6.19): the count is of the satisfying links surviving the home
/// consult, by ENUMERATION — the same set [`findlinks_ftt_on_where`] returns.
pub fn count_ftt_on_where<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    q: &FourSet,
    readable: &dyn Fn(&Address) -> bool,
) -> usize {
    satisfying(s.world().links(), q)
        .into_iter()
        .filter(|a| home_readable(readable, a))
        .count()
}

/// Windowed enumeration over the descriptor family (ASN-0108, the
/// `Match = findlinks_FTT` reading — the same cursor mechanism as `window_v`
/// instantiated over the conjunctive family). `n = 0` is clamped to 1 (total
/// API, W9).
///
/// EVERY `Address` IS A LEGAL CURSOR, and none is checked: resume is a
/// key-cut strictly past `cur`, never a lookup of it, so a cursor naming a
/// link that has since been nullified or has stopped satisfying `q` still
/// resumes at the right place (W8), and no continuously-matching link is
/// skipped or duplicated (W4/W5). A caller relaying a cursor from a request
/// owes it no validation.
///
/// The one place `sat` is spelled apart rather than composed: the same
/// candidate conjunction, then the same residence post-filter, but applied
/// LAZILY during the range walk — so a home-narrow query never materializes
/// the filtered set. The links this pages over are exactly the ones
/// [`findlinks_ftt_on`] returns.
///
/// Answers for NO READER, paging every satisfying link whatever its home; a
/// caller answering for a reading principal asks [`window_ftt_on_where`].
pub fn window_ftt_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    q: &FourSet,
    cur: Cursor,
    n: usize,
) -> Window {
    window_ftt_on_where(s, q, cur, n, &|_| true)
}

/// [`window_ftt_on`] with the result-set filter (PUB round 2, lane 3.3, §3):
/// the home consult joins the residence post-filter in the lazy `keep`, so a
/// masked link is skipped before the window slice (PUB-6.14), never counted
/// against `n`.
pub fn window_ftt_on_where<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    q: &FourSet,
    cur: Cursor,
    n: usize,
    readable: &dyn Fn(&Address) -> bool,
) -> Window {
    let cand = candidates(s.world().links(), q);
    window_over(&cand, cur, n, |a| q.at_home(a) && home_readable(readable, a))
}
