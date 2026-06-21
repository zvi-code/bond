//! Wire-format constants: data types, protocol magic numbers, versions.
//!
//! All values mirror `idl/bond/core/bond_const.bond` and
//! `cpp/inc/bond/core/bond_version.h` in the reference implementation.

use crate::error::{Error, Result};

/// The on-wire type tag for every Bond value, mirroring `BondDataType`.
///
/// Values match the reference `enum BondDataType` exactly.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum BondDataType {
    /// Marks the end of a struct.
    Stop = 0,
    /// Marks the end of a base struct within an inheritance chain.
    StopBase = 1,
    /// `bool`.
    Bool = 2,
    /// `uint8`.
    UInt8 = 3,
    /// `uint16`.
    UInt16 = 4,
    /// `uint32`.
    UInt32 = 5,
    /// `uint64`.
    UInt64 = 6,
    /// `float`.
    Float = 7,
    /// `double`.
    Double = 8,
    /// `string` (UTF-8).
    String = 9,
    /// A nested struct.
    Struct = 10,
    /// `list<T>` / `vector<T>` (also `nullable<T>` and `blob` via sub-type).
    List = 11,
    /// `set<T>`.
    Set = 12,
    /// `map<K, V>`.
    Map = 13,
    /// `int8`.
    Int8 = 14,
    /// `int16`.
    Int16 = 15,
    /// `int32`.
    Int32 = 16,
    /// `int64`.
    Int64 = 17,
    /// `wstring` (UTF-16LE).
    WString = 18,
    /// Sentinel for "type not available".
    Unavailable = 127,
}

impl BondDataType {
    /// Maps a raw wire byte to a [`BondDataType`], rejecting unknown values.
    #[inline]
    pub fn from_u8(value: u8) -> Result<Self> {
        Ok(match value {
            0 => BondDataType::Stop,
            1 => BondDataType::StopBase,
            2 => BondDataType::Bool,
            3 => BondDataType::UInt8,
            4 => BondDataType::UInt16,
            5 => BondDataType::UInt32,
            6 => BondDataType::UInt64,
            7 => BondDataType::Float,
            8 => BondDataType::Double,
            9 => BondDataType::String,
            10 => BondDataType::Struct,
            11 => BondDataType::List,
            12 => BondDataType::Set,
            13 => BondDataType::Map,
            14 => BondDataType::Int8,
            15 => BondDataType::Int16,
            16 => BondDataType::Int32,
            17 => BondDataType::Int64,
            18 => BondDataType::WString,
            127 => BondDataType::Unavailable,
            other => return Err(Error::UnknownType(other)),
        })
    }

    /// The raw wire byte for this type.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// True for fixed-size scalar types (`bool`, integers, `float`, `double`).
    #[inline]
    pub const fn is_basic(self) -> bool {
        matches!(
            self,
            BondDataType::Bool
                | BondDataType::UInt8
                | BondDataType::UInt16
                | BondDataType::UInt32
                | BondDataType::UInt64
                | BondDataType::Int8
                | BondDataType::Int16
                | BondDataType::Int32
                | BondDataType::Int64
                | BondDataType::Float
                | BondDataType::Double
        )
    }

    /// True for the container types (`list`, `set`, `map`).
    #[inline]
    pub const fn is_container(self) -> bool {
        matches!(
            self,
            BondDataType::List | BondDataType::Set | BondDataType::Map
        )
    }

    /// True for the string types (`string`, `wstring`).
    #[inline]
    pub const fn is_string(self) -> bool {
        matches!(self, BondDataType::String | BondDataType::WString)
    }
}

/// Distinguishes the sub-kinds of `BT_LIST` (mirrors `ListSubType`).
///
/// On the wire a `nullable<T>` and a `blob` are both encoded as `BT_LIST`;
/// this enum records the original intent when a schema is available.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum ListSubType {
    /// Ordinary `list` / `vector`.
    None = 0,
    /// `nullable<T>`.
    Nullable = 1,
    /// `blob`.
    Blob = 2,
}

/// The protocol magic numbers (mirrors `ProtocolType`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u16)]
pub enum ProtocolType {
    /// The actual protocol is encoded in the marshaled payload header.
    Marshaled = 0x0000,
    /// Fast Binary protocol.
    Fast = 0x464d,
    /// Compact Binary protocol.
    Compact = 0x4243,
    /// Simple JSON protocol.
    SimpleJson = 0x4a53,
    /// Simple Binary protocol.
    Simple = 0x5053,
}

impl ProtocolType {
    /// Maps a 2-byte magic number to a [`ProtocolType`].
    #[inline]
    pub fn from_u16(value: u16) -> Result<Self> {
        Ok(match value {
            0x0000 => ProtocolType::Marshaled,
            0x464d => ProtocolType::Fast,
            0x4243 => ProtocolType::Compact,
            0x4a53 => ProtocolType::SimpleJson,
            0x5053 => ProtocolType::Simple,
            other => return Err(Error::UnknownProtocol(other)),
        })
    }

    /// The 2-byte magic for this protocol.
    #[inline]
    pub const fn magic(self) -> u16 {
        self as u16
    }
}

/// Protocol version `1`.
pub const V1: u16 = 0x0001;
/// Protocol version `2`.
pub const V2: u16 = 0x0002;

/// Default maximum recursion depth, guarding against malicious nesting.
pub const DEFAULT_MAX_DEPTH: usize = 256;
