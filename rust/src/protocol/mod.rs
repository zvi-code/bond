//! Protocol implementations and the shared tagged-reader abstraction.
//!
//! The two *tagged* protocols (Compact Binary, Fast Binary) are self-describing
//! and share all of their structural parsing logic through the
//! [`TaggedReader`] trait plus the generic [`read_struct`] / [`read_value`] /
//! [`skip_value`] free functions in this module. Only the leaf encodings differ
//! between them, so each protocol implements just those.
//!
//! The two *untagged* protocols ([`simple`]) and the text protocol
//! ([`simple_json`]) are schema-driven and live in their own modules.

pub mod compact;
pub mod fast;
pub mod simple;
pub mod simple_json;

use crate::constants::{BondDataType, ProtocolType, DEFAULT_MAX_DEPTH};
use crate::error::{Error, Result};
use crate::value::{Field, Struct, Value};

/// A self-describing (tagged) Bond reader.
///
/// Implementors provide only leaf reads and struct/container framing; the
/// generic functions in this module supply the recursive structure so that
/// Compact and Fast Binary share one DOM builder and one skip routine.
pub trait TaggedReader<'de> {
    /// Which protocol this reader implements.
    fn protocol(&self) -> ProtocolType;

    /// Reads the start of a struct (consumes the length prefix in Compact v2).
    fn read_struct_begin(&mut self) -> Result<()>;

    /// Reads a field header, returning its type and ordinal. A type of
    /// [`BondDataType::Stop`] terminates the struct; [`BondDataType::StopBase`]
    /// separates base-class fields from derived ones.
    fn read_field_begin(&mut self) -> Result<(BondDataType, u16)>;

    /// Reads the header of a `list`/`set`, returning element count and type.
    fn read_container_begin(&mut self) -> Result<(usize, BondDataType)>;

    /// Reads the header of a `map`, returning entry count and key/value types.
    fn read_map_begin(&mut self) -> Result<(usize, BondDataType, BondDataType)>;

    /// Fast-skips a struct if the protocol allows it (Compact v2 length
    /// prefix). Returns `true` if the entire struct was consumed; `false` if
    /// the caller must fall back to skipping field by field.
    fn try_fast_skip_struct(&mut self) -> Result<bool> {
        Ok(false)
    }

    /// Reads a `bool`.
    fn read_bool(&mut self) -> Result<bool>;
    /// Reads a `uint8`.
    fn read_uint8(&mut self) -> Result<u8>;
    /// Reads a `uint16`.
    fn read_uint16(&mut self) -> Result<u16>;
    /// Reads a `uint32`.
    fn read_uint32(&mut self) -> Result<u32>;
    /// Reads a `uint64`.
    fn read_uint64(&mut self) -> Result<u64>;
    /// Reads an `int8`.
    fn read_int8(&mut self) -> Result<i8>;
    /// Reads an `int16`.
    fn read_int16(&mut self) -> Result<i16>;
    /// Reads an `int32`.
    fn read_int32(&mut self) -> Result<i32>;
    /// Reads an `int64`.
    fn read_int64(&mut self) -> Result<i64>;
    /// Reads a `float`.
    fn read_float(&mut self) -> Result<f32>;
    /// Reads a `double`.
    fn read_double(&mut self) -> Result<f64>;
    /// Reads a `string`, borrowing from the input (zero-copy, SIMD-validated).
    fn read_str(&mut self) -> Result<&'de str>;
    /// Reads a `wstring`, decoding UTF-16 into an owned `String`.
    fn read_wstring(&mut self) -> Result<String>;
}

/// Reads a complete struct from the root of a tagged payload.
pub fn read_struct<'de, R: TaggedReader<'de>>(reader: &mut R) -> Result<Struct> {
    read_struct_inner(reader, 0)
}

fn read_struct_inner<'de, R: TaggedReader<'de>>(reader: &mut R, depth: usize) -> Result<Struct> {
    if depth > DEFAULT_MAX_DEPTH {
        return Err(Error::DepthLimitExceeded(DEFAULT_MAX_DEPTH));
    }
    reader.read_struct_begin()?;
    let mut fields = Vec::new();
    loop {
        let (ty, id) = reader.read_field_begin()?;
        match ty {
            BondDataType::Stop => break,
            BondDataType::StopBase => continue,
            _ => {
                let value = read_value(reader, ty, depth + 1)?;
                fields.push(Field { id, name: None, value });
            }
        }
    }
    Ok(Struct { fields })
}

/// Reads a single value of the given (already-known) type.
pub fn read_value<'de, R: TaggedReader<'de>>(
    reader: &mut R,
    ty: BondDataType,
    depth: usize,
) -> Result<Value> {
    if depth > DEFAULT_MAX_DEPTH {
        return Err(Error::DepthLimitExceeded(DEFAULT_MAX_DEPTH));
    }
    Ok(match ty {
        BondDataType::Bool => Value::Bool(reader.read_bool()?),
        BondDataType::UInt8 => Value::UInt8(reader.read_uint8()?),
        BondDataType::UInt16 => Value::UInt16(reader.read_uint16()?),
        BondDataType::UInt32 => Value::UInt32(reader.read_uint32()?),
        BondDataType::UInt64 => Value::UInt64(reader.read_uint64()?),
        BondDataType::Int8 => Value::Int8(reader.read_int8()?),
        BondDataType::Int16 => Value::Int16(reader.read_int16()?),
        BondDataType::Int32 => Value::Int32(reader.read_int32()?),
        BondDataType::Int64 => Value::Int64(reader.read_int64()?),
        BondDataType::Float => Value::Float(reader.read_float()?),
        BondDataType::Double => Value::Double(reader.read_double()?),
        BondDataType::String => Value::Str(reader.read_str()?.to_owned()),
        BondDataType::WString => Value::WStr(reader.read_wstring()?),
        BondDataType::Struct => Value::Struct(read_struct_inner(reader, depth + 1)?),
        BondDataType::List => {
            let (count, element) = reader.read_container_begin()?;
            let items = read_elements(reader, element, count, depth)?;
            Value::List { element, items }
        }
        BondDataType::Set => {
            let (count, element) = reader.read_container_begin()?;
            let items = read_elements(reader, element, count, depth)?;
            Value::Set { element, items }
        }
        BondDataType::Map => {
            let (count, key, value) = reader.read_map_begin()?;
            let mut entries = Vec::with_capacity(count.min(4096));
            for _ in 0..count {
                let k = read_value(reader, key, depth + 1)?;
                let v = read_value(reader, value, depth + 1)?;
                entries.push((k, v));
            }
            Value::Map { key, value, entries }
        }
        BondDataType::Stop | BondDataType::StopBase | BondDataType::Unavailable => {
            return Err(Error::Message(format!(
                "unexpected control type {ty:?} where a value was expected"
            )));
        }
    })
}

fn read_elements<'de, R: TaggedReader<'de>>(
    reader: &mut R,
    element: BondDataType,
    count: usize,
    depth: usize,
) -> Result<Vec<Value>> {
    // Cap the pre-allocation so a corrupt huge count cannot OOM us before the
    // underlying reads fail on EOF.
    let mut items = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        items.push(read_value(reader, element, depth + 1)?);
    }
    Ok(items)
}

/// Fully traverses (validates) a struct at the root of a tagged payload without
/// allocating a DOM. Every byte is read and bounds-checked; returns `Ok(())`
/// only if the entire struct is well-formed. This is the fastest,
/// zero-allocation path for high-volume ingestion and integrity checking.
pub fn validate<'de, R: TaggedReader<'de>>(reader: &mut R) -> Result<()> {
    skip_value_inner(reader, BondDataType::Struct, 0, false)
}

/// Skips a value of the given type without materializing it.
///
/// When skipping unknown fields, the protocol's fast-skip (e.g. the Compact v2
/// length prefix) is used. For full validation use [`validate`].
pub fn skip_value<'de, R: TaggedReader<'de>>(
    reader: &mut R,
    ty: BondDataType,
    depth: usize,
) -> Result<()> {
    skip_value_inner(reader, ty, depth, true)
}

fn skip_value_inner<'de, R: TaggedReader<'de>>(
    reader: &mut R,
    ty: BondDataType,
    depth: usize,
    fast: bool,
) -> Result<()> {
    if depth > DEFAULT_MAX_DEPTH {
        return Err(Error::DepthLimitExceeded(DEFAULT_MAX_DEPTH));
    }
    match ty {
        BondDataType::Bool | BondDataType::UInt8 | BondDataType::Int8 => {
            reader.read_uint8()?;
        }
        BondDataType::UInt16 => {
            reader.read_uint16()?;
        }
        BondDataType::UInt32 => {
            reader.read_uint32()?;
        }
        BondDataType::UInt64 => {
            reader.read_uint64()?;
        }
        BondDataType::Int16 => {
            reader.read_int16()?;
        }
        BondDataType::Int32 => {
            reader.read_int32()?;
        }
        BondDataType::Int64 => {
            reader.read_int64()?;
        }
        BondDataType::Float => {
            reader.read_float()?;
        }
        BondDataType::Double => {
            reader.read_double()?;
        }
        BondDataType::String => {
            reader.read_str()?;
        }
        BondDataType::WString => {
            reader.read_wstring()?;
        }
        BondDataType::Struct => {
            // Fast-skip only when allowed; validation always descends.
            if fast && reader.try_fast_skip_struct()? {
                return Ok(());
            }
            reader.read_struct_begin()?;
            loop {
                let (fty, _id) = reader.read_field_begin()?;
                match fty {
                    BondDataType::Stop => break,
                    BondDataType::StopBase => continue,
                    _ => skip_value_inner(reader, fty, depth + 1, fast)?,
                }
            }
        }
        BondDataType::List | BondDataType::Set => {
            let (count, element) = reader.read_container_begin()?;
            for _ in 0..count {
                skip_value_inner(reader, element, depth + 1, fast)?;
            }
        }
        BondDataType::Map => {
            let (count, key, value) = reader.read_map_begin()?;
            for _ in 0..count {
                skip_value_inner(reader, key, depth + 1, fast)?;
                skip_value_inner(reader, value, depth + 1, fast)?;
            }
        }
        BondDataType::Stop | BondDataType::StopBase | BondDataType::Unavailable => {
            return Err(Error::Message(format!(
                "unexpected control type {ty:?} while skipping"
            )));
        }
    }
    Ok(())
}
