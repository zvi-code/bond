//! # bond
//!
//! A complete, high-performance Rust parser and writer for the
//! [Microsoft Bond](https://github.com/microsoft/bond) serialization format.
//!
//! ## Coverage
//!
//! Every Bond wire protocol and version is supported, for reading and writing:
//!
//! | Protocol     | Versions | Tagged? | Needs schema? |
//! |--------------|----------|---------|---------------|
//! | Compact Binary | v1, v2 | yes     | no            |
//! | Fast Binary    | v1     | yes     | no            |
//! | Simple Binary  | v1, v2 | no      | yes           |
//! | Simple JSON    | v1     | text    | for exact types |
//!
//! All Bond data types are handled: `bool`, every sized signed/unsigned
//! integer, `float`, `double`, `string` (UTF-8), `wstring` (UTF-16),
//! `struct`, `list`/`vector`, `set`, `map`, `nullable`, `blob`, and
//! `bonded<T>`.
//!
//! ## Design
//!
//! * The two tagged protocols share a single DOM builder and skip routine
//!   through the [`protocol::TaggedReader`] trait, so structural logic is
//!   written once.
//! * Parsing is bounds-checked everywhere: a malformed payload yields an
//!   [`Error`], never a panic.
//! * Hot primitives are SIMD-accelerated — UTF-8 validation via `simdutf8`,
//!   and LEB128 varint terminator search via NEON (aarch64) / SSE2 (x86_64),
//!   each with a scalar fallback (see [`varint`]).
//!
//! ## Quick start
//!
//! ```
//! use bond::{Struct, Value, compact};
//!
//! let s = Struct::new()
//!     .with_field(0, Value::Int32(-42))
//!     .with_field(1, Value::Str("hello".into()));
//!
//! // Serialize to Compact Binary v2 and read it back.
//! let bytes = compact::write(&s, bond::V2).unwrap();
//! let parsed = compact::parse(&bytes, bond::V2).unwrap();
//! assert_eq!(parsed, s);
//! ```

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod constants;
pub mod error;
pub mod gen;
pub mod marshal;
pub mod protocol;
pub mod reader;
pub mod schema;
pub mod value;
pub mod varint;
pub mod writer;

// --- Core re-exports for ergonomic top-level use ---

pub use constants::{BondDataType, ListSubType, ProtocolType, DEFAULT_MAX_DEPTH, V1, V2};
pub use error::{Error, Result};
pub use reader::Reader;
pub use schema::{FieldDef, Metadata, Modifier, SchemaDef, StructDef, TypeDef, Variant};
pub use value::{Field, Struct, Value};
pub use writer::Writer;

pub use marshal::{
    detect, marshal, marshal_with_schema, transcode_tagged, unmarshal, unmarshal_with_schema,
    Unmarshaled,
};

// Protocol modules are exposed both under `protocol::` and at the crate root
// for convenience (`bond::compact::parse`, etc.).
pub use protocol::{compact, fast, simple, simple_json};

/// Parses a tagged (Compact/Fast) marshaled payload, or any payload with a
/// schema, returning the detected protocol/version and the value. This is the
/// most convenient entry point for "parse any Bond file" use cases.
pub fn parse_any(bytes: &[u8], schema: Option<&SchemaDef>) -> Result<Unmarshaled> {
    match schema {
        Some(s) => unmarshal_with_schema(bytes, s),
        None => unmarshal(bytes),
    }
}
