//! A canonicalizing serde transcode: any `Serialize` value → a [`SerdeTree`]
//! → deterministic text. The one rule that earns its keep: **map entries are
//! sorted by their rendered key**, so a slice whose internal map iterates in
//! instance-specific order (M3's frontier `im::HashMap` hashes with a
//! per-instance `RandomState`; M4's map iterates in hash-trie order) still
//! renders byte-identically for equal contents. Sequences keep their order —
//! for the slices' `im::Vector`/`im::OrdSet` fields that order is semantic or
//! already sorted. No iteration-order dependence survives this path, which is
//! the world dump's determinism clause.

use std::fmt;

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

/// Transcode any serde-serializable value. Total over the world's serde
/// forms: the only error path is a `Serialize` impl calling
/// `ser::Error::custom`, which none of the slices' impls do.
pub(crate) fn to_tree<T: Serialize + ?Sized>(v: &T) -> SerdeTree {
    v.serialize(SerdeTreeSer).expect("canonical transcode is total over the world's serde forms")
}

/// Render a [`SerdeTree`] as deterministic text, appending to `out`.
/// Maps render `{k: v, …}` with entries sorted by (rendered key, rendered
/// value); everything else renders structurally.
pub(crate) fn render(c: &SerdeTree, out: &mut String) {
    match c {
        SerdeTree::Unit => out.push_str("()"),
        SerdeTree::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        SerdeTree::I64(v) => out.push_str(&v.to_string()),
        SerdeTree::U64(v) => out.push_str(&v.to_string()),
        SerdeTree::I128(v) => out.push_str(&v.to_string()),
        SerdeTree::U128(v) => out.push_str(&v.to_string()),
        SerdeTree::F64Bits(b) => out.push_str(&format!("f64:0x{b:016x}")),
        SerdeTree::Char(ch) => out.push_str(&format!("{ch:?}")),
        SerdeTree::Str(s) => out.push_str(&format!("{s:?}")),
        SerdeTree::Bytes(b) => {
            out.push_str("0x");
            for byte in b {
                out.push_str(&format!("{byte:02x}"));
            }
        }
        SerdeTree::Null => out.push_str("none"),
        SerdeTree::Opt(v) => {
            out.push_str("some(");
            render(v, out);
            out.push(')');
        }
        SerdeTree::Seq(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render(item, out);
            }
            out.push(']');
        }
        SerdeTree::Map(entries) => {
            let mut rendered: Vec<(String, String)> = entries
                .iter()
                .map(|(k, v)| {
                    let mut ks = String::new();
                    render(k, &mut ks);
                    let mut vs = String::new();
                    render(v, &mut vs);
                    (ks, vs)
                })
                .collect();
            rendered.sort();
            out.push('{');
            for (i, (k, v)) in rendered.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(k);
                out.push_str(": ");
                out.push_str(v);
            }
            out.push('}');
        }
        SerdeTree::Named(name, inner) => {
            out.push_str(name);
            if !matches!(**inner, SerdeTree::Unit) {
                out.push('(');
                render(inner, out);
                out.push(')');
            }
        }
    }
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

    fn rendered(c: &SerdeTree) -> String {
        let mut s = String::new();
        render(c, &mut s);
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
        assert_eq!(rendered(&ab), rendered(&ba));
        assert_eq!(rendered(&ab), r#"{"a": 1, "b": 2}"#);
    }

    /// Sequences keep their order — it is semantic upstream.
    #[test]
    fn seq_order_is_preserved() {
        let s = SerdeTree::Seq(vec![SerdeTree::U64(2), SerdeTree::U64(1)]);
        assert_eq!(rendered(&s), "[2, 1]");
    }

    /// A serde derive round-trips through the transcode structurally.
    #[test]
    fn serde_forms_transcode() {
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
        assert_eq!(rendered(&to_tree(&v)), r#"{"x": [A, B(7)], "y": some(true)}"#);
    }
}
