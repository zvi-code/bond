//! The dynamic value model (DOM): a protocol-independent in-memory
//! representation of any Bond value.
//!
//! Tagged protocols (Compact, Fast) are fully self-describing and parse
//! directly into a [`Value`]. Untagged protocols (Simple Binary) and typed
//! Simple JSON require a schema to produce one.

use crate::constants::BondDataType;

/// Any Bond value.
///
/// Containers carry their element type(s) so that empty containers can still be
/// re-serialized into the tagged protocols, which require a type tag.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// `bool`.
    Bool(bool),
    /// `uint8`.
    UInt8(u8),
    /// `uint16`.
    UInt16(u16),
    /// `uint32`.
    UInt32(u32),
    /// `uint64`.
    UInt64(u64),
    /// `int8`.
    Int8(i8),
    /// `int16`.
    Int16(i16),
    /// `int32`.
    Int32(i32),
    /// `int64`.
    Int64(i64),
    /// `float`.
    Float(f32),
    /// `double`.
    Double(f64),
    /// `string` (UTF-8).
    Str(String),
    /// `wstring` (UTF-16).
    WStr(String),
    /// A (possibly nested) struct.
    Struct(Struct),
    /// `list<T>` / `vector<T>`.
    List {
        /// Element type tag.
        element: BondDataType,
        /// The elements.
        items: Vec<Value>,
    },
    /// `set<T>`.
    Set {
        /// Element type tag.
        element: BondDataType,
        /// The elements.
        items: Vec<Value>,
    },
    /// `map<K, V>`.
    Map {
        /// Key type tag.
        key: BondDataType,
        /// Value type tag.
        value: BondDataType,
        /// The entries.
        entries: Vec<(Value, Value)>,
    },
    /// `nullable<T>` (a `list` of length 0 or 1 on the wire).
    Nullable {
        /// Element type tag.
        element: BondDataType,
        /// The contained value, if present.
        value: Option<Box<Value>>,
    },
    /// `blob` (a `list<int8>` on the wire).
    Blob(Vec<u8>),
    /// `bonded<T>`: an opaque marshaled payload.
    Bonded(Vec<u8>),
}

impl Value {
    /// The wire type tag for this value.
    pub fn type_of(&self) -> BondDataType {
        match self {
            Value::Bool(_) => BondDataType::Bool,
            Value::UInt8(_) => BondDataType::UInt8,
            Value::UInt16(_) => BondDataType::UInt16,
            Value::UInt32(_) => BondDataType::UInt32,
            Value::UInt64(_) => BondDataType::UInt64,
            Value::Int8(_) => BondDataType::Int8,
            Value::Int16(_) => BondDataType::Int16,
            Value::Int32(_) => BondDataType::Int32,
            Value::Int64(_) => BondDataType::Int64,
            Value::Float(_) => BondDataType::Float,
            Value::Double(_) => BondDataType::Double,
            Value::Str(_) => BondDataType::String,
            Value::WStr(_) => BondDataType::WString,
            Value::Struct(_) | Value::Bonded(_) => BondDataType::Struct,
            Value::List { .. } | Value::Nullable { .. } | Value::Blob(_) => BondDataType::List,
            Value::Set { .. } => BondDataType::Set,
            Value::Map { .. } => BondDataType::Map,
        }
    }
}

/// A struct value: an ordered collection of fields.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Struct {
    /// The fields, in serialization order.
    pub fields: Vec<Field>,
}

impl Struct {
    /// Creates an empty struct.
    pub fn new() -> Self {
        Struct::default()
    }

    /// Appends a field with the given id and value.
    pub fn with_field(mut self, id: u16, value: Value) -> Self {
        self.fields.push(Field {
            id,
            name: None,
            value,
        });
        self
    }

    /// Returns the value of the field with the given id, if present.
    pub fn get(&self, id: u16) -> Option<&Value> {
        self.fields.iter().find(|f| f.id == id).map(|f| &f.value)
    }

    /// Returns the value of the first field with the given name, if present.
    pub fn get_by_name(&self, name: &str) -> Option<&Value> {
        self.fields
            .iter()
            .find(|f| f.name.as_deref() == Some(name))
            .map(|f| &f.value)
    }
}

/// A single field within a [`Struct`].
#[derive(Clone, Debug, PartialEq)]
pub struct Field {
    /// The field ordinal (always meaningful for binary protocols).
    pub id: u16,
    /// The field name, when known (Simple JSON, or schema-driven parsing).
    pub name: Option<String>,
    /// The field's value.
    pub value: Value,
}

impl Field {
    /// Creates a field from an id and value.
    pub fn new(id: u16, value: Value) -> Self {
        Field {
            id,
            name: None,
            value,
        }
    }

    /// Creates a named field from an id, name and value.
    pub fn named(id: u16, name: impl Into<String>, value: Value) -> Self {
        Field {
            id,
            name: Some(name.into()),
            value,
        }
    }
}
