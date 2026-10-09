//! §B register_node: validate-not-mint admission — no seat granted, nothing
//! asked of the address's ancestors — in its pinned guard order, with the
//! depth cap at its exact edge.

use crate::common::*;

use skep_address::Level;
use skep_namespace::{
    HasM3, M3Rec, M3State, Namespace, RegisterNodeError, BOOTSTRAP_PRINCIPAL, MAX_NODE_COMPONENTS,
};

#[test]
fn register_node_validates_and_admits_supplied_addresses() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);

    // Ordinary admission (ASN-0047): the address is SUPPLIED, validated,
    // registered.
    let (node, seq) = ns.register_node(t(&[1, 7])).expect("register");
    assert_eq!(node, a(&[1, 7]));
    assert_eq!(k.current_seq(), seq);
    let snap = k.snapshot();
    let m3 = snap.world().m3();
    assert_eq!(m3.entity_level(&node), Some(Level::Node));
    assert!(m3.is_allocated(&node));
    // A provisioned node stays bootstrap-owned via ω until an account is
    // delegated beneath it (Conflicts §7)…
    assert_eq!(m3.effective_owner(&node), Some(BOOTSTRAP_PRINCIPAL));
    // …from π₀'s own seat at [1]: admission seats no one at the node itself,
    // which the id alone cannot show — a seat staged at [1,7] for π₀ would
    // answer the same id.
    assert_eq!(m3.effective_owner_prefix(&node), Some(&a(&[1])));
    // …and delegation beneath it works through the ordinary gate.
    let peek = m3.next_account_prefix(&node).expect("peek under new node");
    assert_eq!(peek, a(&[1, 7, 0, 1]));
    ns.delegate(BOOTSTRAP_PRINCIPAL, peek.into(), ID1)
        .expect("delegate under the new node");

    // Admission asks nothing of the address's ANCESTORS: a node address names
    // a provisioning path originated OUTSIDE the docuverse, so `nodes` is
    // deliberately non-contiguous and P8 is not a gate here — [1,5,7] is
    // admitted while [1,5] is registered nowhere.
    assert_eq!(
        ns.register_node(t(&[1, 5, 7]))
            .expect("a node whose parent is unregistered")
            .0,
        a(&[1, 5, 7])
    );
    assert_eq!(
        k.snapshot().world().m3().entity_level(&a(&[1, 5, 7])),
        Some(Level::Node)
    );
    assert_eq!(k.snapshot().world().m3().entity_level(&a(&[1, 5])), None);

    // Rejections, in the documented guard order. The first three are pure
    // pre-work (validity, level and depth read the address alone); `NotFresh`
    // reads the registry under the held key, and `NotDescendantOfBootstrap`
    // reads none, following it because the order is the contract.
    let before = k.current_seq();
    // NotValid — not T4 ([1,0] has a trailing zero).
    assert_eq!(
        rejected(ns.register_node(t(&[1, 0]))),
        RegisterNodeError::NotValid
    );
    // NotNode — account-level input; checked before lineage ([2,0,1] is
    // also not bootstrap-descended).
    assert_eq!(
        rejected(ns.register_node(t(&[2, 0, 1]))),
        RegisterNodeError::NotNode
    );
    // NotNode precedes NotFresh: [1,7,0,1] is account-level AND registered
    // (the delegation above allocated it).
    assert_eq!(
        rejected(ns.register_node(t(&[1, 7, 0, 1]))),
        RegisterNodeError::NotNode
    );
    // TooDeep — `nodes` is the one registry M3 cannot keep in frontier form,
    // so an entry's component COUNT is refused rather than stored (magnitude
    // is M1-unbounded — see `MAX_NODE_COMPONENTS`). The probe is otherwise
    // impeccable — node-level, fresh, bootstrap-descended — so depth is the
    // only guard that can be refusing it.
    let over_cap_node: Vec<u32> = std::iter::repeat_n(1u32, MAX_NODE_COMPONENTS + 1).collect();
    assert_eq!(a(&over_cap_node).level(), Level::Node);
    assert_eq!(
        rejected(ns.register_node(t(&over_cap_node))),
        RegisterNodeError::TooDeep
    );
    // NotNode precedes TooDeep: an equally over-long ACCOUNT-tier address is
    // refused for its tier, since depth bounds the node registry alone.
    let mut over_cap_acct = vec![1u32, 0];
    over_cap_acct.extend(std::iter::repeat_n(1u32, MAX_NODE_COMPONENTS + 1));
    assert_eq!(
        rejected(ns.register_node(t(&over_cap_acct))),
        RegisterNodeError::NotNode
    );
    // NotFresh — duplicates surface typed, never a silent coalesce; the
    // seeded [1] and the just-registered [1,7] alike.
    assert_eq!(
        rejected(ns.register_node(t(&[1]))),
        RegisterNodeError::NotFresh
    );
    assert_eq!(
        rejected(ns.register_node(t(&[1, 7]))),
        RegisterNodeError::NotFresh
    );
    // NotDescendantOfBootstrap — [1] ≼ addr fails.
    assert_eq!(
        rejected(ns.register_node(t(&[2]))),
        RegisterNodeError::NotDescendantOfBootstrap
    );
    // A rejected admission commits nothing, whichever guard refused it.
    assert_eq!(k.current_seq(), before);

    // The cap is exactly where it says it is: one component shorter than the
    // refusal above is admitted, so `TooDeep` bounds the registry rather than
    // narrowing what provisioning may name.
    let at_cap: Vec<u32> = std::iter::repeat_n(1u32, MAX_NODE_COMPONENTS).collect();
    assert_eq!(
        ns.register_node(t(&at_cap)).expect("at the cap").0,
        a(&at_cap)
    );
    assert_eq!(
        k.snapshot().world().m3().entity_level(&a(&at_cap)),
        Some(Level::Node)
    );

    // TooDeep precedes NotFresh: an over-cap address that is ALSO registered.
    // `register_node` cannot reach that state — the cap refuses admission —
    // and `apply_m3` documents it as representable, since the record door
    // deliberately does not carry the cap (an over-cap entry is a permanent
    // resource charge, and nothing more).
    let seeded = World {
        m3: M3State::genesis().apply_m3(&M3Rec::register_node(a(&over_cap_node))),
    };
    let over_cap_k = mem_kernel(seeded);
    assert_eq!(
        rejected(Namespace::new(&over_cap_k).register_node(t(&over_cap_node))),
        RegisterNodeError::TooDeep
    );

    // NotFresh precedes NotDescendantOfBootstrap: [2] is registered AND off
    // the bootstrap lineage — a state `register_node` itself cannot reach,
    // so seed it through the fold.
    let seeded = World {
        m3: M3State::genesis().apply_m3(&M3Rec::register_node(a(&[2]))),
    };
    let off_lineage_k = mem_kernel(seeded);
    assert_eq!(
        rejected(Namespace::new(&off_lineage_k).register_node(t(&[2]))),
        RegisterNodeError::NotFresh
    );
}
