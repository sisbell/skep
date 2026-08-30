//! A canonicalizing serde transcode: any `Serialize` value → a [`SerdeTree`]
//! → deterministic text. The one rule that earns its keep: **map entries are
//! sorted by their rendered key**, so a slice whose internal map iterates in
//! instance-specific order (M3's frontier `im::HashMap` hashes with a
//! per-instance `RandomState`; M4's map iterates in hash-trie order) still
//! renders byte-identically for equal contents. Sequences keep their order —
//! for the slices' `im::Vector`/`im::OrdSet` fields that order is semantic or
//! already sorted. No iteration-order dependence survives this path, which is
//! the world dump's determinism clause.

use std::fmt::{self, Write as _};

use serde::ser::{self, Serialize};

/// The serde data model, flattened to the shapes the world's serde forms
/// actually use, as a value a transcode can collect into. It holds entries
/// and elements in the order the `Serialize` impl produced them; canonical
/// order is [`render`]'s doing, established as the text is written.
///
/// So this type is deliberately NOT comparable. Two trees with equal contents
/// in different collection order are equal only once rendered, and comparing
/// worlds therefore means comparing renderings: a derived `==` here would
/// answer the question this transcode exists to answer, and answer it wrong.
#[derive(Clone, Debug)]
pub(crate) enum SerdeTree {
    Unit,
    Bool(bool),
    I64(i64),
    U64(u64),
    I128(i128),
    U128(u128),
    /// Bit pattern, so NaN payloads and signed zeros stay canonical.
    F64Bits(u64),
    Char(char),
    Str(String),
    /// serde's `serialize_bytes`, which no type in the world reaches: serde
    /// has no byte specialization for `[u8]`, so M4's `Val` transcodes as a
    /// [`SerdeTree::Seq`] of [`SerdeTree::U64`] — one node per byte — and the
    /// only way here is a slice that adopts a `serde_bytes` shadow. Worth
    /// knowing before reading a dump's size off this arm: the content term is
    /// the sequence's, roughly a node and several digits per byte, and not
    /// the two hex characters below.
    Bytes(Vec<u8>),
    Null,
    Opt(Box<SerdeTree>),
    Seq(Vec<SerdeTree>),
    /// Entries as collected; [`render`] sorts them by the rendered (key,
    /// value) PAIR. The value belongs in the sort key because the order must
    /// be TOTAL: `sort` is stable, so entries whose keys render alike would
    /// otherwise keep their collection order and leak back exactly the
    /// instance-specific iteration this transcode exists to remove.
    Map(Vec<(SerdeTree, SerdeTree)>),
    /// An enum variant (or named wrapper) around its payload.
    Named(&'static str, Box<SerdeTree>),
}

/// Transcode any serde-serializable value.
///
/// The `expect` rests on this, and on nothing weaker: the transcode itself
/// raises `ser::Error::custom` in one place — a map value arriving before its
/// key, which serde's own contract forbids — so the only way to an `Err` is a
/// `Serialize` impl in the world's closure raising it. None can today,
/// because every impl in that closure is a derive or a library's (`im`,
/// `num-bigint`, serde's `rc` impls) and every serde shadow is spelled
/// `into`, which cannot fail, rather than `try_into`. A slice that adds a
/// fallible `serialize_with`, or writes a shadow `try_into` on the serialize
/// side, is what makes this reachable — and it lands in the world dump, i.e.
/// on whatever route serves one. Fail-stop is right for an oracle; the point
/// is that the change which breaks it should land beside this sentence.
pub(crate) fn to_tree<T: Serialize + ?Sized>(v: &T) -> SerdeTree {
    v.serialize(SerdeTreeSer).expect("canonical transcode is total over the world's serde forms")
}

/// The deterministic text is the tree's `Display`: maps render `{k: v, …}`
/// with entries sorted by (rendered key, rendered value), and everything else
/// renders structurally. Writing through the formatter rather than building
/// intermediate strings keeps a whole-world render to the allocations the sort
/// genuinely needs — the map entries', whose sort key IS their rendering.
impl fmt::Display for SerdeTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerdeTree::Unit => f.write_str("()"),
            SerdeTree::Bool(b) => f.write_str(if *b { "true" } else { "false" }),
            SerdeTree::I64(v) => write!(f, "{v}"),
            SerdeTree::U64(v) => write!(f, "{v}"),
            SerdeTree::I128(v) => write!(f, "{v}"),
            SerdeTree::U128(v) => write!(f, "{v}"),
            SerdeTree::F64Bits(b) => write!(f, "f64:0x{b:016x}"),
            SerdeTree::Char(ch) => write!(f, "{ch:?}"),
            SerdeTree::Str(s) => write!(f, "{s:?}"),
            SerdeTree::Bytes(b) => {
                f.write_str("0x")?;
                for byte in b {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
            SerdeTree::Null => f.write_str("none"),
            SerdeTree::Opt(v) => write!(f, "some({v})"),
            SerdeTree::Seq(items) => {
                f.write_str("[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{item}")?;
                }
                f.write_str("]")
            }
            SerdeTree::Map(entries) => {
                let mut rendered: Vec<(String, String)> =
                    entries.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
                rendered.sort();
                f.write_str("{")?;
                for (i, (k, v)) in rendered.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{k}: {v}")?;
                }
                f.write_str("}")
            }
            SerdeTree::Named(name, inner) => {
                f.write_str(name)?;
                if !matches!(**inner, SerdeTree::Unit) {
                    write!(f, "({inner})")?;
                }
                Ok(())
            }
        }
    }
}

/// Append a tree's deterministic text to `out`, for a caller assembling one
/// rendering out of several pieces.
pub(crate) fn render(tree: &SerdeTree, out: &mut String) {
    write!(out, "{tree}").expect("writing to a String cannot fail")
}

/// The transcode's error carrier — reachable only via `ser::Error::custom`
/// from a foreign `Serialize` impl.
#[derive(Debug)]
pub(crate) struct CanonError(String);

impl fmt::Display for CanonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "canonical transcode: {}", self.0)
    }
}

impl std::error::Error for CanonError {}

impl ser::Error for CanonError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        CanonError(msg.to_string())
    }
}

struct SerdeTreeSer;

impl ser::Serializer for SerdeTreeSer {
    type Ok = SerdeTree;
    type Error = CanonError;
    type SerializeSeq = SeqBuild;
    type SerializeTuple = SeqBuild;
    type SerializeTupleStruct = SeqBuild;
    type SerializeTupleVariant = VariantSeqBuild;
    type SerializeMap = MapBuild;
    type SerializeStruct = StructBuild;
    type SerializeStructVariant = VariantStructBuild;

    /// This transcode walks the same data model M2's checkpoint does —
    /// bincode, which answers `false` — so a `Serialize` impl that branches on
    /// this flag takes the checkpoint's branch here too, and the authoritative
    /// section keeps rendering the form the journal stores. serde's default is
    /// `true`, and no slice branches today; answering `false` is what keeps
    /// the first one that does from silently moving the dump off the bytes it
    /// is the oracle for.
    fn is_human_readable(&self) -> bool {
        false
    }

    fn serialize_bool(self, v: bool) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::I64(v.into()))
    }
    fn serialize_i16(self, v: i16) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::I64(v.into()))
    }
    fn serialize_i32(self, v: i32) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::I64(v.into()))
    }
    fn serialize_i64(self, v: i64) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::I64(v))
    }
    fn serialize_i128(self, v: i128) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::I128(v))
    }
    fn serialize_u8(self, v: u8) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::U64(v.into()))
    }
    fn serialize_u16(self, v: u16) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::U64(v.into()))
    }
    fn serialize_u32(self, v: u32) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::U64(v.into()))
    }
    fn serialize_u64(self, v: u64) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::U64(v))
    }
    fn serialize_u128(self, v: u128) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::U128(v))
    }
    fn serialize_f32(self, v: f32) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::F64Bits(f64::from(v).to_bits()))
    }
    fn serialize_f64(self, v: f64) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::F64Bits(v.to_bits()))
    }
    fn serialize_char(self, v: char) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::Char(v))
    }
    fn serialize_str(self, v: &str) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::Str(v.to_owned()))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::Bytes(v.to_vec()))
    }
    fn serialize_none(self) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::Null)
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::Opt(Box::new(value.serialize(SerdeTreeSer)?)))
    }
    fn serialize_unit(self) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::Unit)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::Unit)
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::Named(variant, Box::new(SerdeTree::Unit)))
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<SerdeTree, CanonError> {
        // Transparent, matching the serde data model.
        value.serialize(SerdeTreeSer)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::Named(variant, Box::new(value.serialize(SerdeTreeSer)?)))
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<SeqBuild, CanonError> {
        Ok(SeqBuild(Vec::with_capacity(len.unwrap_or(0))))
    }
    fn serialize_tuple(self, len: usize) -> Result<SeqBuild, CanonError> {
        Ok(SeqBuild(Vec::with_capacity(len)))
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<SeqBuild, CanonError> {
        Ok(SeqBuild(Vec::with_capacity(len)))
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<VariantSeqBuild, CanonError> {
        Ok(VariantSeqBuild { variant, items: Vec::with_capacity(len) })
    }
    fn serialize_map(self, len: Option<usize>) -> Result<MapBuild, CanonError> {
        Ok(MapBuild { entries: Vec::with_capacity(len.unwrap_or(0)), pending: None })
    }
    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<StructBuild, CanonError> {
        Ok(StructBuild(Vec::with_capacity(len)))
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<VariantStructBuild, CanonError> {
        Ok(VariantStructBuild { variant, fields: Vec::with_capacity(len) })
    }
}

struct SeqBuild(Vec<SerdeTree>);

impl ser::SerializeSeq for SeqBuild {
    type Ok = SerdeTree;
    type Error = CanonError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CanonError> {
        self.0.push(value.serialize(SerdeTreeSer)?);
        Ok(())
    }
    fn end(self) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::Seq(self.0))
    }
}

impl ser::SerializeTuple for SeqBuild {
    type Ok = SerdeTree;
    type Error = CanonError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CanonError> {
        self.0.push(value.serialize(SerdeTreeSer)?);
        Ok(())
    }
    fn end(self) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::Seq(self.0))
    }
}

impl ser::SerializeTupleStruct for SeqBuild {
    type Ok = SerdeTree;
    type Error = CanonError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CanonError> {
        self.0.push(value.serialize(SerdeTreeSer)?);
        Ok(())
    }
    fn end(self) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::Seq(self.0))
    }
}

struct VariantSeqBuild {
    variant: &'static str,
    items: Vec<SerdeTree>,
}

impl ser::SerializeTupleVariant for VariantSeqBuild {
    type Ok = SerdeTree;
    type Error = CanonError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CanonError> {
        self.items.push(value.serialize(SerdeTreeSer)?);
        Ok(())
    }
    fn end(self) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::Named(self.variant, Box::new(SerdeTree::Seq(self.items))))
    }
}

struct MapBuild {
    entries: Vec<(SerdeTree, SerdeTree)>,
    pending: Option<SerdeTree>,
}

impl ser::SerializeMap for MapBuild {
    type Ok = SerdeTree;
    type Error = CanonError;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), CanonError> {
        self.pending = Some(key.serialize(SerdeTreeSer)?);
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CanonError> {
        let key = self
            .pending
            .take()
            .ok_or_else(|| ser::Error::custom("map value serialized before its key"))?;
        self.entries.push((key, value.serialize(SerdeTreeSer)?));
        Ok(())
    }
    fn end(self) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::Map(self.entries))
    }
}

struct StructBuild(Vec<(SerdeTree, SerdeTree)>);

impl ser::SerializeStruct for StructBuild {
    type Ok = SerdeTree;
    type Error = CanonError;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), CanonError> {
        self.0.push((SerdeTree::Str(key.to_owned()), value.serialize(SerdeTreeSer)?));
        Ok(())
    }
    fn end(self) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::Map(self.0))
    }
}

struct VariantStructBuild {
    variant: &'static str,
    fields: Vec<(SerdeTree, SerdeTree)>,
}

impl ser::SerializeStructVariant for VariantStructBuild {
    type Ok = SerdeTree;
    type Error = CanonError;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), CanonError> {
        self.fields.push((SerdeTree::Str(key.to_owned()), value.serialize(SerdeTreeSer)?));
        Ok(())
    }
    fn end(self) -> Result<SerdeTree, CanonError> {
        Ok(SerdeTree::Named(self.variant, Box::new(SerdeTree::Map(self.fields))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render_of(tree: &SerdeTree) -> String {
        let mut s = String::new();
        render(tree, &mut s);
        s
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
}
