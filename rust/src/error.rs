//! Error and `Result` types for Bond parsing and serialization.

use crate::constants::{BondDataType, ProtocolType};
use core::fmt;

/// The result type used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// All errors that can occur while reading or writing Bond payloads.
///
/// Reading a *broken* Bond file always surfaces as one of these variants rather
/// than a panic, satisfying the "reply with error if the bond file format is
/// broken" guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The input ended before a complete value could be read.
    UnexpectedEof {
        /// How many more bytes were required.
        needed: usize,
        /// How many bytes were actually available.
        available: usize,
    },
    /// A type byte on the wire did not correspond to any known `BondDataType`.
    UnknownType(u8),
    /// The 2-byte protocol magic did not match any known protocol.
    UnknownProtocol(u16),
    /// The protocol is recognized but the version is not supported.
    UnsupportedVersion {
        /// The protocol whose version is unsupported.
        protocol: ProtocolType,
        /// The version found on the wire.
        version: u16,
    },
    /// A variable-length integer was longer than its type allows (corrupt data).
    VarintOverflow,
    /// A `string`/`blob` payload was not valid UTF-8.
    InvalidUtf8,
    /// A `wstring` payload was not valid UTF-16.
    InvalidUtf16,
    /// Recursion exceeded the configured depth limit (protection against
    /// malicious deeply-nested payloads).
    DepthLimitExceeded(usize),
    /// A declared container/string length exceeds the bytes actually available,
    /// or a configured sanity limit.
    LengthOutOfBounds {
        /// The length declared on the wire.
        declared: usize,
        /// The number of bytes actually remaining.
        available: usize,
    },
    /// The operation requires a schema (untagged protocols / typed Simple JSON)
    /// but none was supplied.
    SchemaRequired,
    /// The supplied schema was internally inconsistent.
    SchemaError(String),
    /// A value on the wire did not have the type the schema or context required.
    TypeMismatch {
        /// The type that was expected.
        expected: BondDataType,
        /// The type that was actually found.
        actual: BondDataType,
    },
    /// A Simple JSON document could not be parsed or did not match the expected
    /// Bond JSON mapping.
    Json(String),
    /// Any other error with a human-readable message.
    Message(String),
}

impl Error {
    /// Convenience constructor for [`Error::UnexpectedEof`].
    pub(crate) fn eof(needed: usize, available: usize) -> Self {
        Error::UnexpectedEof { needed, available }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnexpectedEof { needed, available } => write!(
                f,
                "unexpected end of input: needed {needed} byte(s) but only {available} available"
            ),
            Error::UnknownType(t) => write!(f, "unknown Bond data type {t}"),
            Error::UnknownProtocol(m) => write!(f, "unknown protocol magic 0x{m:04x}"),
            Error::UnsupportedVersion { protocol, version } => {
                write!(f, "unsupported version {version} for protocol {protocol:?}")
            }
            Error::VarintOverflow => write!(f, "variable-length integer overflow (corrupt data)"),
            Error::InvalidUtf8 => write!(f, "string is not valid UTF-8"),
            Error::InvalidUtf16 => write!(f, "wstring is not valid UTF-16"),
            Error::DepthLimitExceeded(d) => write!(f, "recursion depth limit ({d}) exceeded"),
            Error::LengthOutOfBounds {
                declared,
                available,
            } => write!(
                f,
                "declared length {declared} exceeds {available} available byte(s)"
            ),
            Error::SchemaRequired => write!(f, "this operation requires a schema"),
            Error::SchemaError(m) => write!(f, "schema error: {m}"),
            Error::TypeMismatch { expected, actual } => {
                write!(f, "type mismatch: expected {expected:?}, found {actual:?}")
            }
            Error::Json(m) => write!(f, "Simple JSON error: {m}"),
            Error::Message(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e.to_string())
    }
}
