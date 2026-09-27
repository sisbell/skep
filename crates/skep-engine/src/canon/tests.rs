// The root re-exports name the derive MACROS as well as the traits; the
// parent's `serde::ser::Serialize` is the trait alone, so the explicit
// imports here shadow the glob's for the derives below.
use serde::{Deserialize, Serialize};

use super::*;

fn render_of(tree: &SerdeTree) -> String {
    tree.to_string()
}

/// The determinism clause in miniature: two maps with equal entries in
/// different collection order render byte-identically.
#[test]
fn map_entry_order_is_canonicalized() {
    let ab = SerdeTree::Map(vec![
        (SerdeTree::Str("a".into()), SerdeTree::U64(1)),
        (SerdeTree::Str("b".into()), SerdeTree::U64(2)),
    ]);
    let ba = SerdeTree::Map(vec![
        (SerdeTree::Str("b".into()), SerdeTree::U64(2)),
        (SerdeTree::Str("a".into()), SerdeTree::U64(1)),
    ]);
    assert_eq!(render_of(&ab), render_of(&ba));
    assert_eq!(render_of(&ab), r#"{"a": 1, "b": 2}"#);
}

/// The pair-sort's reason, in miniature: two entries whose KEYS render
/// alike still sort totally, because the value is part of the sort key.
/// `sort` is stable, so a key-only sort would keep collection order here
/// and leak back exactly the instance-specific iteration this transcode
/// exists to remove.
#[test]
fn entries_whose_keys_render_alike_sort_by_value_too() {
    let ab = SerdeTree::Map(vec![
        (SerdeTree::U64(1), SerdeTree::Str("a".into())),
        (SerdeTree::I64(1), SerdeTree::Str("b".into())),
    ]);
    let ba = SerdeTree::Map(vec![
        (SerdeTree::I64(1), SerdeTree::Str("b".into())),
        (SerdeTree::U64(1), SerdeTree::Str("a".into())),
    ]);
    assert_eq!(render_of(&ab), render_of(&ba));
    assert_eq!(render_of(&ab), r#"{1: "a", 1: "b"}"#);
}

/// …and the value orders a run of alike keys WITHOUT moving the run among
/// its neighbours: the order is (rendered key, rendered value) over the
/// whole map, so a run sits where its key sorts and orders itself inside.
/// The sort renders a value only inside such a run, and a render that
/// ordered a run against its neighbours, or left it in collection order,
/// fails here in one collection order or both.
#[test]
fn a_run_of_alike_keys_orders_itself_among_distinct_neighbours() {
    let collected = vec![
        (SerdeTree::U64(1), SerdeTree::Str("b".into())),
        (SerdeTree::U64(2), SerdeTree::Str("a".into())),
        (SerdeTree::I64(1), SerdeTree::Str("a".into())),
        (SerdeTree::U64(0), SerdeTree::Str("z".into())),
    ];
    let reversed: Vec<_> = collected.iter().rev().cloned().collect();
    let pinned = r#"{0: "z", 1: "a", 1: "b", 2: "a"}"#;
    assert_eq!(render_of(&SerdeTree::Map(collected)), pinned);
    assert_eq!(render_of(&SerdeTree::Map(reversed)), pinned);
}

/// Sequences keep their order — it is semantic upstream.
#[test]
fn seq_order_is_preserved() {
    let s = SerdeTree::Seq(vec![SerdeTree::U64(2), SerdeTree::U64(1)]);
    assert_eq!(render_of(&s), "[2, 1]");
}

/// A serde derive round-trips through the transcode structurally.
#[test]
fn a_serde_derive_transcodes_structurally() {
    #[derive(serde::Serialize)]
    enum E {
        A,
        B(u32),
    }
    #[derive(serde::Serialize)]
    struct S {
        x: Vec<E>,
        y: Option<bool>,
    }
    let v = S { x: vec![E::A, E::B(7)], y: Some(true) };
    assert_eq!(render_of(&to_tree(&v)), r#"{"x": [A, B(7)], "y": some(true)}"#);
}

/// Every scalar arm's text, pinned: the rendering IS the format the
/// harnesses compare, so each shape is stated here rather than left to
/// whichever world happens to contain one.
#[test]
fn each_scalar_arm_renders_its_pinned_form() {
    for (tree, text) in [
        (SerdeTree::Unit, "()"),
        (SerdeTree::Bool(false), "false"),
        (SerdeTree::I64(-3), "-3"),
        (SerdeTree::I128(-3), "-3"),
        (SerdeTree::U128(3), "3"),
        (SerdeTree::F64Bits(0.5f64.to_bits()), "f64:0x3fe0000000000000"),
        (SerdeTree::Char('q'), "'q'"),
        (SerdeTree::Bytes(vec![0x00, 0x0f, 0xff]), "0x000fff"),
        (SerdeTree::Null, "none"),
        (SerdeTree::Opt(Box::new(SerdeTree::U64(1))), "some(1)"),
        (SerdeTree::Named("V", Box::new(SerdeTree::Unit)), "V"),
        (SerdeTree::Named("V", Box::new(SerdeTree::U64(1))), "V(1)"),
    ] {
        assert_eq!(render_of(&tree), text);
    }
}

/// The transcode walks the checkpoint's data model, so a `Serialize` impl
/// that branches on `is_human_readable` renders the branch bincode stores.
#[test]
fn the_transcode_takes_the_checkpoint_s_serde_branch() {
    struct Branching;
    impl Serialize for Branching {
        fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            if s.is_human_readable() {
                s.serialize_str("prose")
            } else {
                s.serialize_u64(1)
            }
        }
    }
    assert_eq!(render_of(&to_tree(&Branching)), "1");
}

/// The way back, over the shapes the exception set's seed needs and the
/// ones a store slice could add: nested sequences of narrow integers
/// (num-bigint's digit form), maps with structured keys, options, nested
/// structs, and every enum variant shape. A value that goes in through
/// `Serialize` comes back out through `Deserialize` equal.
#[test]
fn a_tree_deserializes_back_into_the_value_that_produced_it() {
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    enum E {
        Unit,
        Newtype(u32),
        Tuple(u8, String),
        Struct { a: bool, b: Option<i64> },
    }
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    struct Key(Vec<u32>);
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct S {
        digits: Vec<Vec<u32>>,
        by_key: std::collections::BTreeMap<Key, bool>,
        maybe: Option<Option<u8>>,
        none: Option<u8>,
        variants: Vec<E>,
        text: String,
        wide: u128,
    }
    let value = S {
        digits: vec![vec![1, 2], vec![u32::MAX], vec![]],
        by_key: [(Key(vec![1, 0, 1]), false), (Key(vec![1, 0, 2]), true)].into_iter().collect(),
        maybe: Some(Some(7)),
        none: None,
        variants: vec![
            E::Unit,
            E::Newtype(9),
            E::Tuple(3, "t".into()),
            E::Struct { a: true, b: Some(-4) },
        ],
        text: "τ".into(),
        wide: u128::MAX,
    };
    let tree = to_tree(&value);
    let back = S::deserialize(TreeDe(&tree)).expect("the tree re-enters through S's own door");
    assert_eq!(back, value);
}

/// A shadow's `try_from` refusal travels as an error, never a panic: the
/// tree holds a value the target type's own door rejects.
#[test]
fn a_target_type_s_refusal_is_an_error_not_a_panic() {
    let tree = to_tree(&300u32);
    assert!(u8::deserialize(TreeDe(&tree)).is_err(), "300 is not a u8");
    let tree = to_tree(&vec![1u32, 2]);
    assert!(bool::deserialize(TreeDe(&tree)).is_err(), "a sequence is not a bool");
}

/// The way back answers the way in's serde branch, so a branching impl
/// reads what it wrote rather than the human-readable form it never
/// produced.
#[test]
fn the_deserializer_reports_the_checkpoint_s_serde_branch() {
    struct Branching(bool);
    impl<'de> Deserialize<'de> for Branching {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let human = d.is_human_readable();
            let _ = u64::deserialize(d)?;
            Ok(Branching(human))
        }
    }
    let tree = to_tree(&1u64);
    let back = Branching::deserialize(TreeDe(&tree)).expect("an integer node");
    assert!(!back.0, "the tree was collected under the non-human-readable branch");
}
