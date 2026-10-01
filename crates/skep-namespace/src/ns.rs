//! Namespaces — ASN-0040's `(anchor, g)`: one chain, one frontier, one lock
//! (§1/§3). [`NsKey`] is the frontier-map key and, through the injective
//! [`ns_lock_key`], the lock key. It is built only here: by the five
//! anchor-side constructors ([`content_ns`], [`link_ns`], [`version_ns`],
//! [`document_ns`], [`account_ns`]), by [`namespace_of`] from a member, or by
//! its at-rest door. Its fields are private to this module, so the key a mint
//! reads, the key its `Allocate` advances and the lock its caller holds cannot
//! be spelled two ways. Also here: the chain-family rule that picks every
//! generator, a chain's members by ordinal, and the two opening slots
//! published to callers outside M3 ([`first_document_address`],
//! [`first_version_address`]).

use serde::{Deserialize, Serialize};
use skep_address::{
    checked_inc, inc, is_t4_valid, parent, shift, validate, Address, GateViolation, Level, Nat,
    Tumbler,
};
use skep_kernel::{LockKey, Space};

/// A namespace — ASN-0040's `(p, d)`: chain anchor `parent` + generator
/// [`Generator`]. THE frontier-map key, and (through the injective
/// [`ns_lock_key`] encoding) the lock key — one key type, one code path, so
/// the two can never drift (§1). Keying by `(parent, g)` keeps the document
/// chain `(A, 2)` and the version chain `(d, 1)` on SEPARATE frontiers by
/// construction (ASN-0123 VD — the entire fix for ASN-0103's
/// version/document collision, requiring no length filter).
///
/// `parent` is a bare `Tumbler` rather than an `Address` because the content
/// and link anchors are `inc(d, 2)` and `inc(b_C(d), 0)`, which M1 returns as
/// tumblers — so the anchor constructors carry no `validate` of their own and
/// `M3State::next_in` re-lifts the anchor at the one place it needs an
/// [`Address`].
///
/// What this type owes, and owes on EVERY `(Tumbler, Generator)` pair it can
/// be built from, is that [`ns_lock_key`] is injective — distinct namespaces,
/// distinct locks. That holds for any nonempty anchor whatever its shape, so
/// it is stated without a proviso and needs none.
///
/// A T4-valid anchor is NOT this type's invariant. It is a precondition of
/// `M3State::next_in`, discharged there by the caller's own gate and stated
/// beside the `validate` that consumes it — which is why a key may exist that
/// no `next_in` path can reach, and why that costs nothing.
///
/// `Ord` is the frontier map's key order (2026-09-23, QUEUE item 10 option
/// (i)): the anchor's tumbler order, then the generator's numeral. It is what
/// makes the checkpoint's `frontiers` bytes a function of the contents — no
/// read consults it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "NsKeyShadow")]
pub(crate) struct NsKey {
    parent: Tumbler,
    g: Generator,
}

/// The at-rest shadow of [`NsKey`] — same fields, same order, so the
/// checkpoint encoding is the struct's own — and the ONE door a frontier key
/// re-enters memory through.
///
/// It re-establishes the T4 HALF of `M3State::next_in`'s anchor
/// precondition — the half a decoder holding one key can settle — for keys
/// that arrive with no caller to establish it. In process, a `next_in` caller
/// establishes T4-validity through its own gate before it calls; a checkpoint
/// is bytes, and `Tumbler` admits any nonempty component sequence — `[1, 0]`
/// decodes and is not T4-valid — so a loaded key would otherwise be a panic
/// waiting for the first reader to dereference it. One T4 scan per key at
/// load, no allocation.
///
/// The other half — [`Generator::NextField`] paired with an Element-level
/// anchor — is not this door's, and needs no door: it is a property of the
/// PAIR, which a per-key check could settle but need not, because it fails
/// soft. `checked_inc` refuses `k = 2` at that tier, so `next_in` answers
/// `GateViolation` and the mint surfaces [`MintError::Gate`]; there is no
/// panic to prevent.
///
/// No key read out of `frontiers` reaches `next_in` today — all five mints
/// build a fresh key from a `*_ns` constructor, and loaded keys are only ever
/// hashed for lookup. So this door is defence for the first frontier-
/// enumerating or re-keying reader to appear, and that reader is why it is
/// here: M3 publishes no enumeration over its frontier map, which is why the
/// engine's observation surface reads this slice through its serde bytes
/// instead.
///
/// [`MintError::Gate`]: crate::MintError::Gate
#[derive(Deserialize)]
struct NsKeyShadow {
    parent: Tumbler,
    g: Generator,
}

impl TryFrom<NsKeyShadow> for NsKey {
    type Error = &'static str;
    fn try_from(shadow: NsKeyShadow) -> Result<NsKey, &'static str> {
        if !is_t4_valid(&shadow.parent) {
            return Err("a namespace anchor is T4-valid (ASN-0040 (p, d))");
        }
        Ok(NsKey {
            parent: shadow.parent,
            g: shadow.g,
        })
    }
}

/// The chain generator — ASN-0040's `d`: [`Generator::SameField`] extends the
/// anchor's own field, [`Generator::NextField`] opens the next one. An enum
/// because `g ∈ {1, 2}` exhausts it: no third generator is representable, in
/// memory or off a checkpoint, so `M3State::next_in` can only hand M1's
/// `checked_inc` a `k` its TA5a gate admits by shape (`k ≥ 3` is refused
/// there, and is what M1 asks a minting producer never to derive from input).
/// What survives is the one refusal a precondition owns rather than the type:
/// `NextField` off an Element anchor, which every mint's registered-entity
/// gate already excludes. Encodes as its numeral, so the checkpointed
/// frontier key and [`ns_lock_key`]'s trailing byte read the same either way.
/// Orders by declaration, which is numeral order (`SameField` = 1 before
/// `NextField` = 2): the second component of [`NsKey`]'s key order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
enum Generator {
    SameField,
    NextField,
}

impl Generator {
    /// The `k` this generator denotes in M1's `inc(t, k)` — which field of the
    /// anchor the chain advances. A widening of the numeral, so it cannot
    /// disagree with what a checkpoint or a lock key carries.
    fn inc_k(self) -> usize {
        usize::from(u8::from(self))
    }
}

impl From<Generator> for u8 {
    /// The generator's numeral — ASN-0040's `d`, and the byte itself: what a
    /// checkpointed frontier key carries and what [`ns_lock_key`] pushes.
    /// [`Generator::try_from`] is its inverse.
    fn from(g: Generator) -> u8 {
        match g {
            Generator::SameField => 1,
            Generator::NextField => 2,
        }
    }
}

impl TryFrom<u8> for Generator {
    type Error = &'static str;
    fn try_from(numeral: u8) -> Result<Generator, &'static str> {
        match numeral {
            1 => Ok(Generator::SameField),
            2 => Ok(Generator::NextField),
            _ => Err("a namespace generator is 1 or 2 (ASN-0040 (p, d))"),
        }
    }
}

/// THE chain-family rule: the generator carrying an anchor at one tier to a
/// child at another — same tier extends the anchor's own field, a lower tier
/// opens the next one. Every `NsKey`'s `g` comes from here, and this is what
/// keeps the document chain `(A, 2)` and the version chain `(d, 1)` on
/// separate frontiers (ASN-0123 VD).
///
/// Both arguments are M1 [`Level`]s — the vocabulary the corpus states the
/// tiers in, and the answer an [`Address`] already carries, so the rule that
/// decides which frontier a mint lands on is never spelled in the encoding's
/// numerals.
fn generator(anchor: Level, child: Level) -> Generator {
    if anchor == child {
        Generator::SameField
    } else {
        Generator::NextField
    }
}

/// THE namespace derivation from the child side: the [`NsKey`] `a` sits in —
/// chain anchor `parent(a)`, generator [`generator`]. Pure M1, and total:
/// `None` EXACTLY for a parentless 1-component node (e.g. `[7]`), which is
/// T4-valid yet anchors no chain — M1's `parent` returns `None` there, and
/// that is the one input for which no namespace exists.
///
/// Every child-side reader of a frontier key routes through here —
/// membership for its chain range probe, the fold for its frontier advance —
/// so the key a staged `Allocate` advances is the key its mint read, by
/// construction (§1/§2). Anchor-side keys come from the `*_ns` family below,
/// one per chain, and both sides take their `g` from [`generator`] at the
/// same tier pair, which is what makes them one key. Callers that hold a
/// ≥ 2-component address by their own gate discharge the `None` case with an
/// `expect` that names that gate.
pub(crate) fn namespace_of(a: &Address) -> Option<NsKey> {
    let par = parent(a)?;
    let g = generator(par.level(), a.level());
    Some(NsKey {
        parent: par.tumbler().clone(),
        g,
    })
}

// The namespace helpers — the ONE code path each mint, each chain
// `*_lock_key` and the account peek reuse (§1/§3). The subspace identifier is
// the element-field's FIRST component, and M1 names both numerals:
// `content_subspace()` = 1, `link_subspace()` = 2. It is NEVER the `.0.`
// separator (the corpus-wide misread to guard against); `s_C ≠ s_L` is what
// makes content and link address spaces disjoint by construction (SD/L14,
// T7). The two element-field constructors reach those bases by M1 arithmetic
// rather than by naming a subspace: `inc(d, 2)` opens the element field at
// `s_C`, and `inc(b_C(d), 0)` steps it on to `s_L`.
//
// Each fixed family's `g` is what `generator` yields at that family's FIXED
// tier pair, noted beside each constructor, so the variants below and the
// chain-family rule cannot drift apart unnoticed.
/// `b_C(d) = inc(d, 2)` — the content sub-allocator's anchor, named because
/// [`link_ns`] is defined off it: `b_L(d) = inc(b_C(d), 0)` (§3).
fn content_base(home: &Address) -> Tumbler {
    inc(home.tumbler(), 2)
}
pub(crate) fn content_ns(home: &Address) -> NsKey {
    // b_C(d); Element → Element.
    NsKey {
        parent: content_base(home),
        g: Generator::SameField,
    }
}
pub(crate) fn link_ns(home: &Address) -> NsKey {
    // b_L(d) = inc(b_C(d), 0); Element → Element.
    NsKey {
        parent: inc(&content_base(home), 0),
        g: Generator::SameField,
    }
}
pub(crate) fn version_ns(source: &Address) -> NsKey {
    // (source, 1) — Document → Document, the ASN-0123 separate chain.
    NsKey {
        parent: source.tumbler().clone(),
        g: Generator::SameField,
    }
}
pub(crate) fn document_ns(account: &Address) -> NsKey {
    // (account, 2) — Account → Document.
    NsKey {
        parent: account.tumbler().clone(),
        g: Generator::NextField,
    }
}

/// `A_account(N)` and the sub-account family: the account chain under
/// `parent` — `(N, 2)` under a node, `(A, 1)` under an account (the sixth
/// family ASN-0042 licenses — Conflicts §8). The one family whose `g` is not
/// fixed: the target is account-tier by definition, so the chain-family rule
/// picks.
pub(crate) fn account_ns(parent: &Address) -> NsKey {
    NsKey {
        parent: parent.tumbler().clone(),
        g: generator(parent.level(), Level::Account),
    }
}

/// `c₁` of the chain `key` names — `inc(anchor, g)`, the address its FIRST
/// member occupies, allocated or not. THE one spelling of a chain's opening
/// address: [`nth_in`] advances it to any later member, and
/// [`first_document_address`] and [`first_version_address`] publish it for
/// the two chains a caller outside M3 has to name.
///
/// PRECONDITION — the anchor precondition `M3State::next_in` states, and
/// which the five mints discharge by their own gates; the two published
/// slots discharge it by cloning their anchor from an [`Address`]. The
/// [`Generator::NextField`]/Element half is not a panic here either:
/// `checked_inc` refuses `k = 2` at that tier and this answers
/// [`GateViolation`].
fn first_in(key: &NsKey) -> Result<Address, GateViolation> {
    let anchor = validate(key.parent.clone()).expect(
        "first_in precondition: a T4-valid anchor — the caller's gate, or NsKeyShadow, established it",
    );
    checked_inc(&anchor, key.g.inc_k())
}

/// `cₙ` of the chain `key` names, for `n ≥ 1`: [`first_in`] with its
/// trailing ordinal advanced by `n − 1` — THE one spelling of a chain member
/// by ordinal, which `M3State::next_in` asks for at `m + 1` and
/// [`M3State::latest_version`] at `m`. M1's `shift` is ordinal-only and
/// SAFE here: `c₁` is a FULL address carrying its ordinal in the last
/// position, never a bare `doc·0·subspace` base (the TA7a hazard); and it
/// is total at 0, so `n = 1` is `c₁` itself with no branch. Re-`validate`
/// is total, since `cₙ` differs from the gated `c₁` only in a positive
/// ordinal.
///
/// PRECONDITION `n ≥ 1` — a chain opens at ordinal 1. Both callers
/// discharge it (`next_in` passes `m + 1`; `latest_version` answers `None`
/// at `m = 0`), and `Nat`'s subtraction panics on underflow if one does not.
///
/// [`M3State::latest_version`]: crate::M3State::latest_version
pub(crate) fn nth_in(key: &NsKey, n: &Nat) -> Result<Address, GateViolation> {
    let c1 = first_in(key)?;
    Ok(validate(shift(c1.tumbler(), &(n - &Nat::from(1u32))))
        .expect("differs from gated c1 only in a positive ordinal"))
}

/// The address an account's FIRST document occupies — `c₁` of the
/// `(account, 2)` chain, `A·0·1` (§1), which AUTH names an account's **doc 1**
/// (AUTH-2.126: the doc-1 form is `A·0·1`) and PUB names the account's
/// **home** (PUB-1.17: born published by default) — a word this module keeps
/// for the document an element is minted under, so here it says doc 1. `None`
/// unless `account` is account-tier, because no other tier anchors a document
/// chain: a node's `(N, 2)` chain is the ACCOUNT chain, and a document's next
/// field is its content base.
///
/// Registry-free, like [`prefix_contains`]: it names the SLOT and claims
/// nothing about what is in it — which is why it is spelled differently from
/// the corpus's "doc 1", a phrase that names the document. Whether the
/// account HAS any documents is [`M3State::has_documents`], which reads the
/// chain's frontier; the slot itself is public for the other question asked
/// of that chain from outside M3 — is `d` the account's first document —
/// which is otherwise answerable only by rebuilding the chain's anchor and
/// opening ordinal, and those are M3's alone.
///
/// [`prefix_contains`]: crate::prefix_contains
/// [`M3State::has_documents`]: crate::M3State::has_documents
pub fn first_document_address(account: &Address) -> Option<Address> {
    (account.level() == Level::Account).then(|| {
        first_in(&document_ns(account))
            .expect("an Account anchor is not Element-level, so TA5a admits k = 2")
    })
}

/// The address a document's FIRST version occupies — `c₁` of the
/// `(source, 1)` version chain, `D·1` (§1; ASN-0123 VD), which the
/// doc-metadata read reports as a document's birth version (PUB-8.12).
/// `None` unless `source` is document-tier, because no other tier anchors a
/// version chain: the same key under an account is the SUB-ACCOUNT chain
/// (Conflicts §8), and a node's or an element's `(a, 1)` chain is minted by
/// nothing.
///
/// Registry-free, like [`first_document_address`], and its twin on the
/// version chain: it names the SLOT and claims nothing about what is in it
/// — [`M3State::latest_version`] is the chain's other end, the latest member
/// that IS registered. Public for the reason its sibling is: the slot is
/// otherwise answerable only by rebuilding the chain's anchor and opening
/// ordinal, which are M3's alone.
///
/// [`M3State::latest_version`]: crate::M3State::latest_version
pub fn first_version_address(source: &Address) -> Option<Address> {
    (source.level() == Level::Document)
        .then(|| first_in(&version_ns(source)).expect("k = 1 passes TA5a on every anchor"))
}

// The three key domains M3 serializes on — namespace frontiers, THE principal
// registry, THE node registry — must occupy disjoint byte spaces (§1/§8: an
// alias would under-serialize a namespace and REUSE an address, the one fatal
// error). Each takes its own tag from M2's central `Space` enum
// (`Space::Namespace` / `Space::Principals` / `Space::Nodes`), where every
// tag in the system is assigned, so the disjointness holds against the other
// stores' key spaces too and not merely against M3's own.

/// The injective, space-tagged `NsKey → LockKey` encoding (§1): tag byte,
/// 8-byte BE component count, each component length-delimited (8-byte BE
/// length + minimal BE magnitude bytes), then `g`. Injectivity is what
/// guarantees distinct namespaces map to distinct locks; both the
/// `*_lock_key` constructors and the frontier advance route through the SAME
/// `*_ns` helper and THIS encoding, so the held lock key and the staged
/// frontier key are the same bytes by one code path.
///
/// The two length fields are the width of the counts they carry —
/// `Tumbler::len` and a magnitude's byte length are both `usize`, and both
/// are written whole. A narrower field would make injectivity conditional on
/// no tumbler and no component exceeding it, and neither bound is one M3
/// imposes or could test: M1 leaves component count and magnitude alike
/// unbounded (T0). Injectivity is the property this key exists for, so it is
/// stated without a proviso.
pub(crate) fn ns_lock_key(key: &NsKey) -> LockKey {
    let mut bytes = Vec::new();
    bytes.extend((key.parent.len() as u64).to_be_bytes());
    for comp in &key.parent {
        let magnitude = comp.to_bytes_be();
        bytes.extend((magnitude.len() as u64).to_be_bytes());
        bytes.extend(magnitude);
    }
    bytes.push(u8::from(key.g));
    LockKey::new(Space::Namespace, &bytes)
}

#[cfg(test)]
mod tests;
