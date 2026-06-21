//! Compact Binary protocol, versions 1 and 2.
//!
//! Wire format (from `cpp/inc/bond/protocol/compact_binary.h`):
//! * Field header packs the 5-bit type with the 16-bit id using a 3-bit marker
//!   in the top bits: ids 0..=5 inline, ids 6..=255 add one byte, larger ids
//!   add a little-endian `u16`.
//! * In v2 every struct is prefixed with a varint length covering its body and
//!   terminating `BT_STOP`, enabling O(1) skipping.
//! * `uint16/32/64` are LEB128 varints; `int16/32/64` are zig-zag varints;
//!   `bool`/`int8`/`uint8` are one byte; `float`/`double` are fixed LE.
//! * In v2 a `list`/`set` with fewer than 7 elements packs the count into the
//!   type byte (`(count + 1) << 5`).

use crate::constants::{BondDataType, ProtocolType, V1, V2};
use crate::error::{Error, Result};
use crate::reader::Reader;
use crate::value::{Struct, Value};
use crate::writer::Writer;

use super::TaggedReader;

/// A Compact Binary reader over a byte slice.
pub struct CompactReader<'a> {
    reader: Reader<'a>,
    version: u16,
}

impl<'a> CompactReader<'a> {
    /// Creates a reader for the given protocol `version` (1 or 2).
    pub fn new(buf: &'a [u8], version: u16) -> Result<Self> {
        if version != V1 && version != V2 {
            return Err(Error::UnsupportedVersion {
                protocol: ProtocolType::Compact,
                version,
            });
        }
        Ok(CompactReader {
            reader: Reader::new(buf),
            version,
        })
    }

    /// The protocol version (1 or 2).
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Borrows the underlying cursor (e.g. to check for trailing bytes).
    pub fn cursor(&self) -> &Reader<'a> {
        &self.reader
    }
}

impl<'a> TaggedReader<'a> for CompactReader<'a> {
    fn protocol(&self) -> ProtocolType {
        ProtocolType::Compact
    }

    fn read_struct_begin(&mut self) -> Result<()> {
        if self.version == V2 {
            // Length prefix; not needed for forward reading but must be consumed.
            self.reader.read_varint_u32()?;
        }
        Ok(())
    }

    fn read_field_begin(&mut self) -> Result<(BondDataType, u16)> {
        let raw = self.reader.read_u8()?;
        let ty = BondDataType::from_u8(raw & 0x1f)?;
        let id_marker = raw & (0x07 << 5);
        let id = if id_marker == (0x07 << 5) {
            self.reader.read_le_u16()?
        } else if id_marker == (0x06 << 5) {
            self.reader.read_u8()? as u16
        } else {
            (id_marker >> 5) as u16
        };
        Ok((ty, id))
    }

    fn read_container_begin(&mut self) -> Result<(usize, BondDataType)> {
        let raw = self.reader.read_u8()?;
        let ty = BondDataType::from_u8(raw & 0x1f)?;
        let count = if self.version == V2 && (raw & (0x07 << 5)) != 0 {
            ((raw >> 5) - 1) as usize
        } else {
            self.reader.read_varint_u32()? as usize
        };
        Ok((count, ty))
    }

    fn read_map_begin(&mut self) -> Result<(usize, BondDataType, BondDataType)> {
        let key = BondDataType::from_u8(self.reader.read_u8()?)?;
        let value = BondDataType::from_u8(self.reader.read_u8()?)?;
        let count = self.reader.read_varint_u32()? as usize;
        Ok((count, key, value))
    }

    fn try_fast_skip_struct(&mut self) -> Result<bool> {
        if self.version == V2 {
            let len = self.reader.read_varint_u32()? as usize;
            self.reader.skip_bytes(len)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn read_bool(&mut self) -> Result<bool> {
        self.reader.read_bool()
    }
    fn read_uint8(&mut self) -> Result<u8> {
        self.reader.read_u8()
    }
    fn read_uint16(&mut self) -> Result<u16> {
        self.reader.read_varint_u16()
    }
    fn read_uint32(&mut self) -> Result<u32> {
        self.reader.read_varint_u32()
    }
    fn read_uint64(&mut self) -> Result<u64> {
        self.reader.read_varint_u64()
    }
    fn read_int8(&mut self) -> Result<i8> {
        self.reader.read_i8()
    }
    fn read_int16(&mut self) -> Result<i16> {
        self.reader.read_zigzag_i16()
    }
    fn read_int32(&mut self) -> Result<i32> {
        self.reader.read_zigzag_i32()
    }
    fn read_int64(&mut self) -> Result<i64> {
        self.reader.read_zigzag_i64()
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

/// Parses a Compact Binary struct of the given version into a [`Struct`].
pub fn parse(buf: &[u8], version: u16) -> Result<Struct> {
    let mut reader = CompactReader::new(buf, version)?;
    super::read_struct(&mut reader)
}

/// Validates a Compact Binary payload without building a DOM (zero-allocation,
/// fastest path). Returns `Ok(())` only if the whole struct is well-formed.
pub fn validate(buf: &[u8], version: u16) -> Result<()> {
    let mut reader = CompactReader::new(buf, version)?;
    super::validate(&mut reader)
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// A Compact Binary serializer.
pub struct CompactWriter {
    version: u16,
}

impl CompactWriter {
    /// Creates a writer for the given version (1 or 2).
    pub fn new(version: u16) -> Result<Self> {
        if version != V1 && version != V2 {
            return Err(Error::UnsupportedVersion {
                protocol: ProtocolType::Compact,
                version,
            });
        }
        Ok(CompactWriter { version })
    }

    /// Serializes a struct, appending to `out`.
    pub fn write_struct(&self, out: &mut Writer, value: &Struct) {
        if self.version == V2 {
            // Serialize the body to a temporary buffer to learn its length.
            let mut body = Writer::new();
            self.write_struct_body(&mut body, value);
            out.write_varint_u32(body.len() as u32);
            out.write_bytes(body.as_bytes());
        } else {
            self.write_struct_body(out, value);
        }
    }

    fn write_struct_body(&self, out: &mut Writer, value: &Struct) {
        for field in &value.fields {
            self.write_field_begin(out, field.value.type_of(), field.id);
            self.write_value(out, &field.value);
        }
        out.write_u8(BondDataType::Stop.as_u8());
    }

    fn write_field_begin(&self, out: &mut Writer, ty: BondDataType, id: u16) {
        let t = ty.as_u8();
        if id <= 5 {
            out.write_u8(t | ((id as u8) << 5));
        } else if id <= 0xff {
            out.write_u8(t | (0x06 << 5));
            out.write_u8(id as u8);
        } else {
            out.write_u8(t | (0x07 << 5));
            out.write_le_u16(id);
        }
    }

    fn write_container_begin(&self, out: &mut Writer, size: usize, element: BondDataType) {
        if self.version == V2 && size < 7 {
            out.write_u8(element.as_u8() | (((size as u8) + 1) << 5));
        } else {
            out.write_u8(element.as_u8());
            out.write_varint_u32(size as u32);
        }
    }

    fn write_value(&self, out: &mut Writer, value: &Value) {
        match value {
            Value::Bool(v) => out.write_bool(*v),
            Value::UInt8(v) => out.write_u8(*v),
            Value::UInt16(v) => out.write_varint_u16(*v),
            Value::UInt32(v) => out.write_varint_u32(*v),
            Value::UInt64(v) => out.write_varint_u64(*v),
            Value::Int8(v) => out.write_i8(*v),
            Value::Int16(v) => out.write_zigzag_i16(*v),
            Value::Int32(v) => out.write_zigzag_i32(*v),
            Value::Int64(v) => out.write_zigzag_i64(*v),
            Value::Float(v) => out.write_le_f32(*v),
            Value::Double(v) => out.write_le_f64(*v),
            Value::Str(s) => {
                out.write_varint_u32(s.len() as u32);
                out.write_bytes(s.as_bytes());
            }
            Value::WStr(s) => {
                // Length is in UTF-16 code units; reserve then write.
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
            Value::Bonded(payload) => {
                // bonded<T> inline is just the struct payload bytes.
                out.write_bytes(payload);
            }
        }
    }
}

/// Serializes a struct to a fresh `Vec<u8>` using Compact Binary `version`.
pub fn write(value: &Struct, version: u16) -> Result<Vec<u8>> {
    let writer = CompactWriter::new(version)?;
    let mut out = Writer::new();
    writer.write_struct(&mut out, value);
    Ok(out.into_bytes())
}
