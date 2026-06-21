//! Simple Binary protocol, versions 1 and 2.
//!
//! Wire format (from `cpp/inc/bond/protocol/simple_binary.h`):
//! * Untagged and schema-driven: fields are written positionally in schema
//!   order (base-class fields first), with **no** type tags or field ids.
//! * All scalars are fixed-width little-endian (as in Fast Binary).
//! * Lengths/counts are a fixed `u32` in v1 and a LEB128 varint in v2.
//! * `bonded<T>` is always a **fixed** `u32` length followed by a marshaled
//!   payload, even in v2.
//!
//! Because the payload carries no type information, both reading and writing
//! require a [`SchemaDef`].

use crate::constants::{BondDataType, ListSubType, ProtocolType, V1, V2, DEFAULT_MAX_DEPTH};
use crate::error::{Error, Result};
use crate::reader::Reader;
use crate::schema::{SchemaDef, TypeDef};
use crate::value::{Field, Struct, Value};
use crate::writer::Writer;

/// A Simple Binary reader. Requires a schema to interpret the payload.
pub struct SimpleReader<'a> {
    reader: Reader<'a>,
    version: u16,
}

impl<'a> SimpleReader<'a> {
    /// Creates a Simple Binary reader for the given version (1 or 2).
    pub fn new(buf: &'a [u8], version: u16) -> Result<Self> {
        if version != V1 && version != V2 {
            return Err(Error::UnsupportedVersion {
                protocol: ProtocolType::Simple,
                version,
            });
        }
        Ok(SimpleReader {
            reader: Reader::new(buf),
            version,
        })
    }

    /// Borrows the underlying cursor.
    pub fn cursor(&self) -> &Reader<'a> {
        &self.reader
    }

    #[inline]
    fn read_length(&mut self) -> Result<usize> {
        if self.version == V2 {
            Ok(self.reader.read_varint_u32()? as usize)
        } else {
            Ok(self.reader.read_le_u32()? as usize)
        }
    }

    /// Reads the schema's root struct into a [`Struct`].
    pub fn read_root(&mut self, schema: &SchemaDef) -> Result<Struct> {
        let root = &schema.root;
        if root.id != BondDataType::Struct {
            return Err(Error::SchemaError(
                "Simple Binary root must be a struct".into(),
            ));
        }
        self.read_struct(schema, root.struct_def, 0)
    }

    fn read_struct(&mut self, schema: &SchemaDef, index: u16, depth: usize) -> Result<Struct> {
        if depth > DEFAULT_MAX_DEPTH {
            return Err(Error::DepthLimitExceeded(DEFAULT_MAX_DEPTH));
        }
        let mut fields = Vec::new();
        self.read_struct_fields(schema, index, &mut fields, depth)?;
        Ok(Struct { fields })
    }

    fn read_struct_fields(
        &mut self,
        schema: &SchemaDef,
        index: u16,
        fields: &mut Vec<Field>,
        depth: usize,
    ) -> Result<()> {
        let sd = schema
            .struct_def(index)
            .ok_or_else(|| Error::SchemaError(format!("no struct at index {index}")))?;
        if let Some(base) = &sd.base_def {
            self.read_struct_fields(schema, base.struct_def, fields, depth)?;
        }
        for fd in &sd.fields {
            let value = self.read_value(schema, &fd.type_def, depth + 1)?;
            fields.push(Field {
                id: fd.id,
                name: Some(fd.metadata.name.clone()),
                value,
            });
        }
        Ok(())
    }

    fn read_value(&mut self, schema: &SchemaDef, td: &TypeDef, depth: usize) -> Result<Value> {
        if depth > DEFAULT_MAX_DEPTH {
            return Err(Error::DepthLimitExceeded(DEFAULT_MAX_DEPTH));
        }
        Ok(match td.id {
            BondDataType::Bool => Value::Bool(self.reader.read_bool()?),
            BondDataType::UInt8 => Value::UInt8(self.reader.read_u8()?),
            BondDataType::UInt16 => Value::UInt16(self.reader.read_le_u16()?),
            BondDataType::UInt32 => Value::UInt32(self.reader.read_le_u32()?),
            BondDataType::UInt64 => Value::UInt64(self.reader.read_le_u64()?),
            BondDataType::Int8 => Value::Int8(self.reader.read_i8()?),
            BondDataType::Int16 => Value::Int16(self.reader.read_le_i16()?),
            BondDataType::Int32 => Value::Int32(self.reader.read_le_i32()?),
            BondDataType::Int64 => Value::Int64(self.reader.read_le_i64()?),
            BondDataType::Float => Value::Float(self.reader.read_le_f32()?),
            BondDataType::Double => Value::Double(self.reader.read_le_f64()?),
            BondDataType::String => {
                let len = self.read_length()?;
                Value::Str(self.reader.read_utf8(len)?.to_owned())
            }
            BondDataType::WString => {
                let units = self.read_length()?;
                Value::WStr(self.reader.read_utf16(units)?)
            }
            BondDataType::Struct => {
                if td.bonded_type {
                    // bonded: always fixed u32 length + marshaled payload.
                    let len = self.reader.read_le_u32()? as usize;
                    Value::Bonded(self.reader.read_bytes(len)?.to_vec())
                } else {
                    Value::Struct(self.read_struct(schema, td.struct_def, depth + 1)?)
                }
            }
            BondDataType::List => {
                let element = td.element_type()?;
                let count = self.read_length()?;
                match td.sub_type {
                    ListSubType::Blob => {
                        let bytes = self.reader.read_bytes(count)?.to_vec();
                        Value::Blob(bytes)
                    }
                    ListSubType::Nullable => {
                        let value = if count == 0 {
                            None
                        } else {
                            // A nullable holds at most one value; extra elements
                            // would be malformed but we read exactly `count`.
                            let mut last = None;
                            for _ in 0..count {
                                last = Some(Box::new(self.read_value(schema, element, depth + 1)?));
                            }
                            last
                        };
                        Value::Nullable {
                            element: element.id,
                            value,
                        }
                    }
                    ListSubType::None => {
                        let items = self.read_elements(schema, element, count, depth)?;
                        Value::List {
                            element: element.id,
                            items,
                        }
                    }
                }
            }
            BondDataType::Set => {
                let element = td.element_type()?;
                let count = self.read_length()?;
                let items = self.read_elements(schema, element, count, depth)?;
                Value::Set {
                    element: element.id,
                    items,
                }
            }
            BondDataType::Map => {
                let key_td = td.key_type()?;
                let val_td = td.element_type()?;
                let count = self.read_length()?;
                let mut entries = Vec::with_capacity(count.min(4096));
                for _ in 0..count {
                    let k = self.read_value(schema, key_td, depth + 1)?;
                    let v = self.read_value(schema, val_td, depth + 1)?;
                    entries.push((k, v));
                }
                Value::Map {
                    key: key_td.id,
                    value: val_td.id,
                    entries,
                }
            }
            other => {
                return Err(Error::SchemaError(format!(
                    "unsupported type {other:?} in Simple Binary schema"
                )))
            }
        })
    }

    fn read_elements(
        &mut self,
        schema: &SchemaDef,
        element: &TypeDef,
        count: usize,
        depth: usize,
    ) -> Result<Vec<Value>> {
        let mut items = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            items.push(self.read_value(schema, element, depth + 1)?);
        }
        Ok(items)
    }
}


/// Parses a Simple Binary payload using `schema`.
pub fn parse(buf: &[u8], schema: &SchemaDef, version: u16) -> Result<Struct> {
    let mut reader = SimpleReader::new(buf, version)?;
    reader.read_root(schema)
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// A Simple Binary serializer. Requires a schema to lay out fields.
pub struct SimpleWriter {
    version: u16,
}

impl SimpleWriter {
    /// Creates a Simple Binary writer for the given version (1 or 2).
    pub fn new(version: u16) -> Result<Self> {
        if version != V1 && version != V2 {
            return Err(Error::UnsupportedVersion {
                protocol: ProtocolType::Simple,
                version,
            });
        }
        Ok(SimpleWriter { version })
    }

    #[inline]
    fn write_length(&self, out: &mut Writer, len: usize) {
        if self.version == V2 {
            out.write_varint_u32(len as u32);
        } else {
            out.write_le_u32(len as u32);
        }
    }

    /// Serializes the schema's root struct from `value`, appending to `out`.
    pub fn write_root(&self, out: &mut Writer, schema: &SchemaDef, value: &Struct) -> Result<()> {
        let root = &schema.root;
        if root.id != BondDataType::Struct {
            return Err(Error::SchemaError(
                "Simple Binary root must be a struct".into(),
            ));
        }
        self.write_struct_fields(out, schema, root.struct_def, value, 0)
    }

    fn write_struct_fields(
        &self,
        out: &mut Writer,
        schema: &SchemaDef,
        index: u16,
        value: &Struct,
        depth: usize,
    ) -> Result<()> {
        if depth > DEFAULT_MAX_DEPTH {
            return Err(Error::DepthLimitExceeded(DEFAULT_MAX_DEPTH));
        }
        let sd = schema
            .struct_def(index)
            .ok_or_else(|| Error::SchemaError(format!("no struct at index {index}")))?;
        if let Some(base) = &sd.base_def {
            self.write_struct_fields(out, schema, base.struct_def, value, depth)?;
        }
        for fd in &sd.fields {
            let field_value = value.get(fd.id).ok_or_else(|| {
                Error::SchemaError(format!(
                    "value is missing field id {} ({})",
                    fd.id, fd.metadata.name
                ))
            })?;
            self.write_value(out, schema, &fd.type_def, field_value, depth)?;
        }
        Ok(())
    }

    fn write_value(
        &self,
        out: &mut Writer,
        schema: &SchemaDef,
        td: &TypeDef,
        value: &Value,
        depth: usize,
    ) -> Result<()> {
        match (td.id, value) {
            (BondDataType::Bool, Value::Bool(v)) => out.write_bool(*v),
            (BondDataType::UInt8, Value::UInt8(v)) => out.write_u8(*v),
            (BondDataType::UInt16, Value::UInt16(v)) => out.write_le_u16(*v),
            (BondDataType::UInt32, Value::UInt32(v)) => out.write_le_u32(*v),
            (BondDataType::UInt64, Value::UInt64(v)) => out.write_le_u64(*v),
            (BondDataType::Int8, Value::Int8(v)) => out.write_i8(*v),
            (BondDataType::Int16, Value::Int16(v)) => out.write_le_i16(*v),
            (BondDataType::Int32, Value::Int32(v)) => out.write_le_i32(*v),
            (BondDataType::Int64, Value::Int64(v)) => out.write_le_i64(*v),
            (BondDataType::Float, Value::Float(v)) => out.write_le_f32(*v),
            (BondDataType::Double, Value::Double(v)) => out.write_le_f64(*v),
            (BondDataType::String, Value::Str(s)) => {
                self.write_length(out, s.len());
                out.write_bytes(s.as_bytes());
            }
            (BondDataType::WString, Value::WStr(s)) => {
                let units = s.encode_utf16().count();
                self.write_length(out, units);
                out.write_utf16(s);
            }
            (BondDataType::Struct, Value::Struct(s)) => {
                self.write_struct_fields(out, schema, td.struct_def, s, depth + 1)?;
            }
            (BondDataType::Struct, Value::Bonded(payload)) => {
                out.write_le_u32(payload.len() as u32);
                out.write_bytes(payload);
            }
            (BondDataType::List, Value::List { items, .. }) => {
                let element = td.element_type()?;
                self.write_length(out, items.len());
                for item in items {
                    self.write_value(out, schema, element, item, depth + 1)?;
                }
            }
            (BondDataType::List, Value::Blob(bytes)) => {
                self.write_length(out, bytes.len());
                out.write_bytes(bytes);
            }
            (BondDataType::List, Value::Nullable { value, .. }) => {
                let element = td.element_type()?;
                match value {
                    None => self.write_length(out, 0),
                    Some(inner) => {
                        self.write_length(out, 1);
                        self.write_value(out, schema, element, inner, depth + 1)?;
                    }
                }
            }
            (BondDataType::Set, Value::Set { items, .. }) => {
                let element = td.element_type()?;
                self.write_length(out, items.len());
                for item in items {
                    self.write_value(out, schema, element, item, depth + 1)?;
                }
            }
            (BondDataType::Map, Value::Map { entries, .. }) => {
                let key_td = td.key_type()?;
                let val_td = td.element_type()?;
                self.write_length(out, entries.len());
                for (k, v) in entries {
                    self.write_value(out, schema, key_td, k, depth + 1)?;
                    self.write_value(out, schema, val_td, v, depth + 1)?;
                }
            }
            (expected, actual) => {
                return Err(Error::SchemaError(format!(
                    "Simple Binary value/type mismatch: schema says {expected:?}, value is {:?}",
                    actual.type_of()
                )));
            }
        }
        Ok(())
    }
}

/// Serializes a struct to bytes using Simple Binary `version` and `schema`.
pub fn write(value: &Struct, schema: &SchemaDef, version: u16) -> Result<Vec<u8>> {
    let writer = SimpleWriter::new(version)?;
    let mut out = Writer::new();
    writer.write_root(&mut out, schema, value)?;
    Ok(out.into_bytes())
}
