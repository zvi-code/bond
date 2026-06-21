//! Fast Binary protocol, version 1.
//!
//! Wire format (from `cpp/inc/bond/protocol/fast_binary.h`):
//! * Field header is a 1-byte type followed (for real fields) by a 2-byte
//!   little-endian id. `BT_STOP` / `BT_STOP_BASE` are a lone type byte.
//! * All integers are written fixed-width little-endian — no varint, no
//!   zig-zag.
//! * `string`/`wstring` and container counts use LEB128 varints.
//! * Structs have no length prefix.

use crate::constants::{BondDataType, ProtocolType, V1};
use crate::error::Result;
use crate::reader::Reader;
use crate::value::{Struct, Value};
use crate::writer::Writer;

use super::TaggedReader;

/// A Fast Binary reader over a byte slice.
pub struct FastReader<'a> {
    reader: Reader<'a>,
}

impl<'a> FastReader<'a> {
    /// Creates a Fast Binary reader.
    pub fn new(buf: &'a [u8]) -> Self {
        FastReader {
            reader: Reader::new(buf),
        }
    }

    /// Borrows the underlying cursor.
    pub fn cursor(&self) -> &Reader<'a> {
        &self.reader
    }
}

impl<'a> TaggedReader<'a> for FastReader<'a> {
    fn protocol(&self) -> ProtocolType {
        ProtocolType::Fast
    }

    fn read_struct_begin(&mut self) -> Result<()> {
        Ok(())
    }

    fn read_field_begin(&mut self) -> Result<(BondDataType, u16)> {
        let raw = self.reader.read_u8()?;
        let ty = BondDataType::from_u8(raw)?;
        if matches!(ty, BondDataType::Stop | BondDataType::StopBase) {
            Ok((ty, 0))
        } else {
            let id = self.reader.read_le_u16()?;
            Ok((ty, id))
        }
    }

    fn read_container_begin(&mut self) -> Result<(usize, BondDataType)> {
        let ty = BondDataType::from_u8(self.reader.read_u8()?)?;
        let count = self.reader.read_varint_u32()? as usize;
        Ok((count, ty))
    }

    fn read_map_begin(&mut self) -> Result<(usize, BondDataType, BondDataType)> {
        let key = BondDataType::from_u8(self.reader.read_u8()?)?;
        let value = BondDataType::from_u8(self.reader.read_u8()?)?;
        let count = self.reader.read_varint_u32()? as usize;
        Ok((count, key, value))
    }

    fn read_bool(&mut self) -> Result<bool> {
        self.reader.read_bool()
    }
    fn read_uint8(&mut self) -> Result<u8> {
        self.reader.read_u8()
    }
    fn read_uint16(&mut self) -> Result<u16> {
        self.reader.read_le_u16()
    }
    fn read_uint32(&mut self) -> Result<u32> {
        self.reader.read_le_u32()
    }
    fn read_uint64(&mut self) -> Result<u64> {
        self.reader.read_le_u64()
    }
    fn read_int8(&mut self) -> Result<i8> {
        self.reader.read_i8()
    }
    fn read_int16(&mut self) -> Result<i16> {
        self.reader.read_le_i16()
    }
    fn read_int32(&mut self) -> Result<i32> {
        self.reader.read_le_i32()
    }
    fn read_int64(&mut self) -> Result<i64> {
        self.reader.read_le_i64()
    }
    fn read_float(&mut self) -> Result<f32> {
        self.reader.read_le_f32()
    }
    fn read_double(&mut self) -> Result<f64> {
        self.reader.read_le_f64()
    }
    fn read_str(&mut self) -> Result<&'a str> {
        let len = self.reader.read_varint_u32()? as usize;
        self.reader.read_utf8(len)
    }
    fn read_wstring(&mut self) -> Result<String> {
        let units = self.reader.read_varint_u32()? as usize;
        self.reader.read_utf16(units)
    }
}

/// Parses a Fast Binary struct into a [`Struct`].
pub fn parse(buf: &[u8]) -> Result<Struct> {
    let mut reader = FastReader::new(buf);
    super::read_struct(&mut reader)
}

/// Validates a Fast Binary payload without building a DOM (zero-allocation,
/// fastest path). Returns `Ok(())` only if the whole struct is well-formed.
pub fn validate(buf: &[u8]) -> Result<()> {
    let mut reader = FastReader::new(buf);
    super::validate(&mut reader)
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// A Fast Binary serializer.
#[derive(Default)]
pub struct FastWriter;

impl FastWriter {
    /// Creates a Fast Binary writer.
    pub fn new() -> Self {
        FastWriter
    }

    /// Serializes a struct, appending to `out`.
    pub fn write_struct(&self, out: &mut Writer, value: &Struct) {
        for field in &value.fields {
            let ty = field.value.type_of();
            out.write_u8(ty.as_u8());
            out.write_le_u16(field.id);
            self.write_value(out, &field.value);
        }
        out.write_u8(BondDataType::Stop.as_u8());
    }

    fn write_container_begin(&self, out: &mut Writer, size: usize, element: BondDataType) {
        out.write_u8(element.as_u8());
        out.write_varint_u32(size as u32);
    }

    fn write_value(&self, out: &mut Writer, value: &Value) {
        match value {
            Value::Bool(v) => out.write_bool(*v),
            Value::UInt8(v) => out.write_u8(*v),
            Value::UInt16(v) => out.write_le_u16(*v),
            Value::UInt32(v) => out.write_le_u32(*v),
            Value::UInt64(v) => out.write_le_u64(*v),
            Value::Int8(v) => out.write_i8(*v),
            Value::Int16(v) => out.write_le_i16(*v),
            Value::Int32(v) => out.write_le_i32(*v),
            Value::Int64(v) => out.write_le_i64(*v),
            Value::Float(v) => out.write_le_f32(*v),
            Value::Double(v) => out.write_le_f64(*v),
            Value::Str(s) => {
                out.write_varint_u32(s.len() as u32);
                out.write_bytes(s.as_bytes());
            }
            Value::WStr(s) => {
                let units = s.encode_utf16().count();
                out.write_varint_u32(units as u32);
                out.write_utf16(s);
            }
            Value::Struct(s) => self.write_struct(out, s),
            Value::List { element, items } => {
                self.write_container_begin(out, items.len(), *element);
                for item in items {
                    self.write_value(out, item);
                }
            }
            Value::Set { element, items } => {
                self.write_container_begin(out, items.len(), *element);
                for item in items {
                    self.write_value(out, item);
                }
            }
            Value::Map { key, value, entries } => {
                out.write_u8(key.as_u8());
                out.write_u8(value.as_u8());
                out.write_varint_u32(entries.len() as u32);
                for (k, v) in entries {
                    self.write_value(out, k);
                    self.write_value(out, v);
                }
            }
            Value::Nullable { element, value } => {
                let n = if value.is_some() { 1 } else { 0 };
                self.write_container_begin(out, n, *element);
                if let Some(inner) = value {
                    self.write_value(out, inner);
                }
            }
            Value::Blob(bytes) => {
                self.write_container_begin(out, bytes.len(), BondDataType::Int8);
                out.write_bytes(bytes);
            }
            Value::Bonded(payload) => out.write_bytes(payload),
        }
    }
}

/// Serializes a struct to a fresh `Vec<u8>` using Fast Binary.
pub fn write(value: &Struct) -> Result<Vec<u8>> {
    let writer = FastWriter::new();
    let mut out = Writer::new();
    writer.write_struct(&mut out, value);
    let _ = V1; // documents the only supported version
    Ok(out.into_bytes())
}
