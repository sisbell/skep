//! A canonicalizing serde transcode: any `Serialize` value → a [`Canon`]
//! tree → deterministic text. The one rule that earns its keep: **map
//! entries are sorted by their rendered key**, so a slice whose internal map
//! iterates in instance-specific order (M3's frontier `im::HashMap` hashes
//! with a per-instance `RandomState`; M4's map iterates in hash-trie order)
//! still renders byte-identically for equal contents. Sequences keep their
//! order — for the slices' `im::Vector`/`im::OrdSet` fields that order is
//! semantic or already sorted. No iteration-order dependence survives this
//! path, which is the observe contract's determinism clause.

use std::fmt;

use serde::ser::{self, Serialize};

/// The canonical value tree (the serde data model, flattened to what the
/// world's serde forms actually use).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Canon {
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
    Opt(Box<Canon>),
    Seq(Vec<Canon>),
    /// Entries as collected; sorted by rendered key at [`render`] time.
    Map(Vec<(Canon, Canon)>),
    /// An enum variant (or named wrapper) around its payload.
    Named(&'static str, Box<Canon>),
}

/// Transcode any serde-serializable value. Total over the world's serde
/// forms: the only error path is a `Serialize` impl calling
/// `ser::Error::custom`, which none of the slices' impls do.
pub(crate) fn to_canon<T: Serialize + ?Sized>(v: &T) -> Canon {
    v.serialize(CanonSer).expect("canonical transcode is total over the world's serde forms")
}

/// Render a [`Canon`] tree as deterministic text, appending to `out`.
/// Maps render `{k: v, …}` with entries sorted by (rendered key, rendered
/// value); everything else renders structurally.
pub(crate) fn render(c: &Canon, out: &mut String) {
    match c {
        Canon::Unit => out.push_str("()"),
        Canon::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Canon::I64(v) => out.push_str(&v.to_string()),
        Canon::U64(v) => out.push_str(&v.to_string()),
        Canon::I128(v) => out.push_str(&v.to_string()),
        Canon::U128(v) => out.push_str(&v.to_string()),
        Canon::F64Bits(b) => out.push_str(&format!("f64:0x{b:016x}")),
        Canon::Char(ch) => out.push_str(&format!("{ch:?}")),
        Canon::Str(s) => out.push_str(&format!("{s:?}")),
        Canon::Bytes(b) => {
            out.push_str("0x");
            for byte in b {
                out.push_str(&format!("{byte:02x}"));
            }
        }
        Canon::Null => out.push_str("none"),
        Canon::Opt(v) => {
            out.push_str("some(");
            render(v, out);
            out.push(')');
        }
        Canon::Seq(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render(item, out);
            }
            out.push(']');
        }
        Canon::Map(entries) => {
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
        Canon::Named(name, inner) => {
            out.push_str(name);
            if **inner != Canon::Unit {
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

struct CanonSer;

impl ser::Serializer for CanonSer {
    type Ok = Canon;
    type Error = CanonError;
    type SerializeSeq = SeqBuild;
    type SerializeTuple = SeqBuild;
    type SerializeTupleStruct = SeqBuild;
    type SerializeTupleVariant = VariantSeqBuild;
    type SerializeMap = MapBuild;
    type SerializeStruct = StructBuild;
    type SerializeStructVariant = VariantStructBuild;

    fn serialize_bool(self, v: bool) -> Result<Canon, CanonError> {
        Ok(Canon::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<Canon, CanonError> {
        Ok(Canon::I64(v.into()))
    }
    fn serialize_i16(self, v: i16) -> Result<Canon, CanonError> {
        Ok(Canon::I64(v.into()))
    }
    fn serialize_i32(self, v: i32) -> Result<Canon, CanonError> {
        Ok(Canon::I64(v.into()))
    }
    fn serialize_i64(self, v: i64) -> Result<Canon, CanonError> {
        Ok(Canon::I64(v))
    }
    fn serialize_i128(self, v: i128) -> Result<Canon, CanonError> {
        Ok(Canon::I128(v))
    }
    fn serialize_u8(self, v: u8) -> Result<Canon, CanonError> {
        Ok(Canon::U64(v.into()))
    }
    fn serialize_u16(self, v: u16) -> Result<Canon, CanonError> {
        Ok(Canon::U64(v.into()))
    }
    fn serialize_u32(self, v: u32) -> Result<Canon, CanonError> {
        Ok(Canon::U64(v.into()))
    }
    fn serialize_u64(self, v: u64) -> Result<Canon, CanonError> {
        Ok(Canon::U64(v))
    }
    fn serialize_u128(self, v: u128) -> Result<Canon, CanonError> {
        Ok(Canon::U128(v))
    }
    fn serialize_f32(self, v: f32) -> Result<Canon, CanonError> {
        Ok(Canon::F64Bits(f64::from(v).to_bits()))
    }
    fn serialize_f64(self, v: f64) -> Result<Canon, CanonError> {
        Ok(Canon::F64Bits(v.to_bits()))
    }
    fn serialize_char(self, v: char) -> Result<Canon, CanonError> {
        Ok(Canon::Char(v))
    }
    fn serialize_str(self, v: &str) -> Result<Canon, CanonError> {
        Ok(Canon::Str(v.to_owned()))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<Canon, CanonError> {
        Ok(Canon::Bytes(v.to_vec()))
    }
    fn serialize_none(self) -> Result<Canon, CanonError> {
        Ok(Canon::Null)
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Canon, CanonError> {
        Ok(Canon::Opt(Box::new(value.serialize(CanonSer)?)))
    }
    fn serialize_unit(self) -> Result<Canon, CanonError> {
        Ok(Canon::Unit)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Canon, CanonError> {
        Ok(Canon::Unit)
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<Canon, CanonError> {
        Ok(Canon::Named(variant, Box::new(Canon::Unit)))
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Canon, CanonError> {
        // Transparent, matching the serde data model.
        value.serialize(CanonSer)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Canon, CanonError> {
        Ok(Canon::Named(variant, Box::new(value.serialize(CanonSer)?)))
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

struct SeqBuild(Vec<Canon>);

impl ser::SerializeSeq for SeqBuild {
    type Ok = Canon;
    type Error = CanonError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CanonError> {
        self.0.push(value.serialize(CanonSer)?);
        Ok(())
    }
    fn end(self) -> Result<Canon, CanonError> {
        Ok(Canon::Seq(self.0))
    }
}

impl ser::SerializeTuple for SeqBuild {
    type Ok = Canon;
    type Error = CanonError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CanonError> {
        self.0.push(value.serialize(CanonSer)?);
        Ok(())
    }
    fn end(self) -> Result<Canon, CanonError> {
        Ok(Canon::Seq(self.0))
    }
}

impl ser::SerializeTupleStruct for SeqBuild {
    type Ok = Canon;
    type Error = CanonError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CanonError> {
        self.0.push(value.serialize(CanonSer)?);
        Ok(())
    }
    fn end(self) -> Result<Canon, CanonError> {
        Ok(Canon::Seq(self.0))
    }
}

struct VariantSeqBuild {
    variant: &'static str,
    items: Vec<Canon>,
}

impl ser::SerializeTupleVariant for VariantSeqBuild {
    type Ok = Canon;
    type Error = CanonError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CanonError> {
        self.items.push(value.serialize(CanonSer)?);
        Ok(())
    }
    fn end(self) -> Result<Canon, CanonError> {
        Ok(Canon::Named(self.variant, Box::new(Canon::Seq(self.items))))
    }
}

struct MapBuild {
    entries: Vec<(Canon, Canon)>,
    pending: Option<Canon>,
}

impl ser::SerializeMap for MapBuild {
    type Ok = Canon;
    type Error = CanonError;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), CanonError> {
        self.pending = Some(key.serialize(CanonSer)?);
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CanonError> {
        let key = self
            .pending
            .take()
            .ok_or_else(|| ser::Error::custom("map value serialized before its key"))?;
        self.entries.push((key, value.serialize(CanonSer)?));
        Ok(())
    }
    fn end(self) -> Result<Canon, CanonError> {
        Ok(Canon::Map(self.entries))
    }
}

struct StructBuild(Vec<(Canon, Canon)>);

impl ser::SerializeStruct for StructBuild {
    type Ok = Canon;
    type Error = CanonError;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), CanonError> {
        self.0.push((Canon::Str(key.to_owned()), value.serialize(CanonSer)?));
        Ok(())
    }
    fn end(self) -> Result<Canon, CanonError> {
        Ok(Canon::Map(self.0))
    }
}

struct VariantStructBuild {
    variant: &'static str,
    fields: Vec<(Canon, Canon)>,
}

impl ser::SerializeStructVariant for VariantStructBuild {
    type Ok = Canon;
    type Error = CanonError;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), CanonError> {
        self.fields.push((Canon::Str(key.to_owned()), value.serialize(CanonSer)?));
        Ok(())
    }
    fn end(self) -> Result<Canon, CanonError> {
        Ok(Canon::Named(self.variant, Box::new(Canon::Map(self.fields))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(c: &Canon) -> String {
        let mut s = String::new();
        render(c, &mut s);
        s
    }

    /// The determinism clause in miniature: two maps with equal entries in
    /// different collection order render byte-identically.
    #[test]
    fn map_entry_order_is_canonicalized() {
        let ab = Canon::Map(vec![
            (Canon::Str("a".into()), Canon::U64(1)),
            (Canon::Str("b".into()), Canon::U64(2)),
        ]);
        let ba = Canon::Map(vec![
            (Canon::Str("b".into()), Canon::U64(2)),
            (Canon::Str("a".into()), Canon::U64(1)),
        ]);
        assert_eq!(rendered(&ab), rendered(&ba));
        assert_eq!(rendered(&ab), r#"{"a": 1, "b": 2}"#);
    }

    /// Sequences keep their order — it is semantic upstream.
    #[test]
    fn seq_order_is_preserved() {
        let s = Canon::Seq(vec![Canon::U64(2), Canon::U64(1)]);
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
        assert_eq!(rendered(&to_canon(&v)), r#"{"x": [A, B(7)], "y": some(true)}"#);
    }
}
