//! Runtime schema types, mirroring `idl/bond/core/bond.bond`.
//!
//! A [`SchemaDef`] describes the layout of a Bond struct at runtime. It is
//! required to parse the untagged Simple Binary protocol (whose payload has no
//! type tags) and to map Simple JSON field names to ordinals.
//!
//! The struct/field ordinals in the doc-comments correspond to the Bond field
//! ids in `bond.bond`, so a [`SchemaDef`] can itself be (de)serialized as an
//! ordinary Bond struct.

use crate::constants::{BondDataType, ListSubType};
use crate::error::{Error, Result};

/// Field modifier (`bond.bond` `enum Modifier`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Modifier {
    /// `optional` (the default).
    #[default]
    Optional,
    /// `required`.
    Required,
    /// `required_optional`.
    RequiredOptional,
}

/// A tagged-union default value (`bond.bond` `struct Variant`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Variant {
    /// `0:` unsigned default.
    pub uint_value: u64,
    /// `1:` signed default.
    pub int_value: i64,
    /// `2:` floating default.
    pub double_value: f64,
    /// `3:` string default.
    pub string_value: String,
    /// `4:` wstring default.
    pub wstring_value: String,
    /// `5:` set when the field's default is "nothing".
    pub nothing: bool,
}

/// Metadata attached to a struct or field (`bond.bond` `struct Metadata`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Metadata {
    /// `0:` name of the field or struct.
    pub name: String,
    /// `1:` fully-qualified name (structs only).
    pub qualified_name: String,
    /// `2:` arbitrary attributes.
    pub attributes: Vec<(String, String)>,
    /// `3:` field modifier (unused for structs).
    pub modifier: Modifier,
    /// `4:` default value (unused for structs).
    pub default_value: Variant,
}

impl Metadata {
    /// Metadata carrying only a name.
    pub fn named(name: impl Into<String>) -> Self {
        Metadata {
            name: name.into(),
            ..Default::default()
        }
    }
}

/// A type definition (`bond.bond` `struct TypeDef`).
#[derive(Clone, Debug, PartialEq)]
pub struct TypeDef {
    /// `0:` the type tag.
    pub id: BondDataType,
    /// `1:` index into [`SchemaDef::structs`] when `id == Struct`.
    pub struct_def: u16,
    /// `2:` element type for `list`/`set`, or value type for `map`.
    pub element: Option<Box<TypeDef>>,
    /// `3:` key type for `map`.
    pub key: Option<Box<TypeDef>>,
    /// `4:` true when the type is `bonded<T>`.
    pub bonded_type: bool,
    /// Non-wire hint distinguishing `list` / `nullable` / `blob` (all `BT_LIST`
    /// on the wire). Defaults to [`ListSubType::None`].
    pub sub_type: ListSubType,
}

impl Default for TypeDef {
    fn default() -> Self {
        TypeDef {
            id: BondDataType::Struct,
            struct_def: 0,
            element: None,
            key: None,
            bonded_type: false,
            sub_type: ListSubType::None,
        }
    }
}

impl TypeDef {
    /// A scalar/string type.
    pub fn scalar(id: BondDataType) -> Self {
        TypeDef {
            id,
            ..Default::default()
        }
    }

    /// A reference to the struct at `index` in [`SchemaDef::structs`].
    pub fn struct_ref(index: u16) -> Self {
        TypeDef {
            id: BondDataType::Struct,
            struct_def: index,
            ..Default::default()
        }
    }

    /// A `bonded<T>` reference to the struct at `index`.
    pub fn bonded_ref(index: u16) -> Self {
        TypeDef {
            id: BondDataType::Struct,
            struct_def: index,
            bonded_type: true,
            ..Default::default()
        }
    }

    /// A `list<element>`.
    pub fn list(element: TypeDef) -> Self {
        TypeDef {
            id: BondDataType::List,
            element: Some(Box::new(element)),
            ..Default::default()
        }
    }

    /// A `set<element>`.
    pub fn set(element: TypeDef) -> Self {
        TypeDef {
            id: BondDataType::Set,
            element: Some(Box::new(element)),
            ..Default::default()
        }
    }

    /// A `map<key, value>`.
    pub fn map(key: TypeDef, value: TypeDef) -> Self {
        TypeDef {
            id: BondDataType::Map,
            element: Some(Box::new(value)),
            key: Some(Box::new(key)),
            ..Default::default()
        }
    }

    /// A `nullable<element>`.
    pub fn nullable(element: TypeDef) -> Self {
        TypeDef {
            id: BondDataType::List,
            element: Some(Box::new(element)),
            sub_type: ListSubType::Nullable,
            ..Default::default()
        }
    }

    /// A `blob`.
    pub fn blob() -> Self {
        TypeDef {
            id: BondDataType::List,
            element: Some(Box::new(TypeDef::scalar(BondDataType::Int8))),
            sub_type: ListSubType::Blob,
            ..Default::default()
        }
    }

    /// The element type of a `list`/`set`/`nullable`, or the value type of a
    /// `map`. Errors if absent (a malformed schema).
    pub fn element_type(&self) -> Result<&TypeDef> {
        self.element
            .as_deref()
            .ok_or_else(|| Error::SchemaError("container is missing its element type".into()))
    }

    /// The key type of a `map`. Errors if absent.
    pub fn key_type(&self) -> Result<&TypeDef> {
        self.key
            .as_deref()
            .ok_or_else(|| Error::SchemaError("map is missing its key type".into()))
    }
}

/// A field definition (`bond.bond` `struct FieldDef`).
#[derive(Clone, Debug, PartialEq)]
pub struct FieldDef {
    /// `0:` field metadata.
    pub metadata: Metadata,
    /// `1:` the field ordinal.
    pub id: u16,
    /// `2:` the field's type.
    pub type_def: TypeDef,
}

impl FieldDef {
    /// A field with the given id, name and type.
    pub fn new(id: u16, name: impl Into<String>, type_def: TypeDef) -> Self {
        FieldDef {
            metadata: Metadata::named(name),
            id,
            type_def,
        }
    }
}

/// A struct definition (`bond.bond` `struct StructDef`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StructDef {
    /// `0:` struct metadata.
    pub metadata: Metadata,
    /// `1:` the base struct, if any.
    pub base_def: Option<TypeDef>,
    /// `2:` the fields.
    pub fields: Vec<FieldDef>,
}

impl StructDef {
    /// A struct with the given name and fields and no base.
    pub fn new(name: impl Into<String>, fields: Vec<FieldDef>) -> Self {
        StructDef {
            metadata: Metadata::named(name),
            base_def: None,
            fields,
        }
    }
}

/// A complete schema (`bond.bond` `struct SchemaDef`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SchemaDef {
    /// `0:` all struct definitions referenced by the schema.
    pub structs: Vec<StructDef>,
    /// `1:` the root type.
    pub root: TypeDef,
}

impl SchemaDef {
    /// Builds a schema whose root is the struct at `structs[root_index]`.
    pub fn with_root_struct(structs: Vec<StructDef>, root_index: u16) -> Self {
        SchemaDef {
            structs,
            root: TypeDef::struct_ref(root_index),
        }
    }

    /// Looks up a struct definition by index.
    pub fn struct_def(&self, index: u16) -> Option<&StructDef> {
        self.structs.get(index as usize)
    }
}
