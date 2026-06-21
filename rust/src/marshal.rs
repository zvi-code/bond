//! Marshaling: the 4-byte `[magic:u16 LE][version:u16 LE]` header that prefixes
//! a payload so the protocol can be auto-detected on read, plus transcoding
//! between protocols.

use crate::constants::{ProtocolType, V1, V2};
use crate::error::{Error, Result};
use crate::protocol::{compact, fast, simple, simple_json};
use crate::schema::SchemaDef;
use crate::value::Struct;

/// The result of unmarshaling: the detected protocol/version and the value.
#[derive(Clone, Debug, PartialEq)]
pub struct Unmarshaled {
    /// The protocol detected from the header.
    pub protocol: ProtocolType,
    /// The version detected from the header.
    pub version: u16,
    /// The parsed value.
    pub value: Struct,
}

/// Writes the 4-byte marshaling header for a binary protocol.
fn write_header(out: &mut Vec<u8>, protocol: ProtocolType, version: u16) {
    out.extend_from_slice(&protocol.magic().to_le_bytes());
    out.extend_from_slice(&version.to_le_bytes());
}

/// Marshals a value with a tagged protocol (Compact or Fast), prefixing the
/// 4-byte header. Returns an error for schema-driven protocols.
pub fn marshal(value: &Struct, protocol: ProtocolType, version: u16) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_header(&mut out, protocol, version);
    match protocol {
        ProtocolType::Compact => {
            let writer = compact::CompactWriter::new(version)?;
            let mut w = crate::writer::Writer::new();
            writer.write_struct(&mut w, value);
            out.extend_from_slice(w.as_bytes());
        }
        ProtocolType::Fast => {
            let bytes = fast::write(value)?;
            out.extend_from_slice(&bytes);
        }
        ProtocolType::Simple | ProtocolType::SimpleJson => {
            return Err(Error::SchemaRequired);
        }
        ProtocolType::Marshaled => {
            return Err(Error::UnknownProtocol(ProtocolType::Marshaled.magic()));
        }
    }
    Ok(out)
}

/// Marshals a value with any protocol, using `schema` for the schema-driven
/// ones. Tagged protocols ignore the schema.
pub fn marshal_with_schema(
    value: &Struct,
    protocol: ProtocolType,
    version: u16,
    schema: &SchemaDef,
) -> Result<Vec<u8>> {
    match protocol {
        ProtocolType::Compact | ProtocolType::Fast => marshal(value, protocol, version),
        ProtocolType::Simple => {
            let mut out = Vec::new();
            write_header(&mut out, protocol, version);
            out.extend_from_slice(&simple::write(value, schema, version)?);
            Ok(out)
        }
        ProtocolType::SimpleJson => {
            // Simple JSON is text and is not given a binary header.
            simple_json::write(value, false)
        }
        ProtocolType::Marshaled => Err(Error::UnknownProtocol(ProtocolType::Marshaled.magic())),
    }
}

/// Detects the protocol and version from a 4-byte header without parsing the
/// body. Returns `None` if the input does not start with a known binary magic.
pub fn detect(bytes: &[u8]) -> Option<(ProtocolType, u16)> {
    if bytes.len() < 4 {
        return None;
    }
    let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    let version = u16::from_le_bytes([bytes[2], bytes[3]]);
    match ProtocolType::from_u16(magic) {
        Ok(p @ (ProtocolType::Compact | ProtocolType::Fast | ProtocolType::Simple)) => {
            Some((p, version))
        }
        _ => None,
    }
}

/// Unmarshals a tagged (Compact/Fast) payload, auto-detecting the protocol.
///
/// Returns [`Error::SchemaRequired`] if the header indicates a schema-driven
/// protocol; use [`unmarshal_with_schema`] for those.
pub fn unmarshal(bytes: &[u8]) -> Result<Unmarshaled> {
    let (protocol, version) = detect(bytes)
        .ok_or_else(|| Error::UnknownProtocol(peek_magic(bytes)))?;
    let body = &bytes[4..];
    let value = match protocol {
        ProtocolType::Compact => compact::parse(body, version)?,
        ProtocolType::Fast => {
            check_version(protocol, version, &[V1])?;
            fast::parse(body)?
        }
        ProtocolType::Simple => return Err(Error::SchemaRequired),
        _ => return Err(Error::UnknownProtocol(protocol.magic())),
    };
    Ok(Unmarshaled {
        protocol,
        version,
        value,
    })
}

/// Unmarshals any payload, using `schema` for schema-driven protocols.
pub fn unmarshal_with_schema(bytes: &[u8], schema: &SchemaDef) -> Result<Unmarshaled> {
    match detect(bytes) {
        Some((protocol, version)) => {
            let body = &bytes[4..];
            let value = match protocol {
                ProtocolType::Compact => compact::parse(body, version)?,
                ProtocolType::Fast => {
                    check_version(protocol, version, &[V1])?;
                    fast::parse(body)?
                }
                ProtocolType::Simple => {
                    check_version(protocol, version, &[V1, V2])?;
                    simple::parse(body, schema, version)?
                }
                _ => return Err(Error::UnknownProtocol(protocol.magic())),
            };
            Ok(Unmarshaled {
                protocol,
                version,
                value,
            })
        }
        None => {
            // No binary header: assume Simple JSON text.
            let value = simple_json::parse_with_schema(bytes, schema)?;
            Ok(Unmarshaled {
                protocol: ProtocolType::SimpleJson,
                version: V1,
                value,
            })
        }
    }
}

fn peek_magic(bytes: &[u8]) -> u16 {
    if bytes.len() >= 2 {
        u16::from_le_bytes([bytes[0], bytes[1]])
    } else {
        0
    }
}

fn check_version(protocol: ProtocolType, version: u16, allowed: &[u16]) -> Result<()> {
    if allowed.contains(&version) {
        Ok(())
    } else {
        Err(Error::UnsupportedVersion { protocol, version })
    }
}

/// Transcodes a tagged payload from one protocol/version to another by parsing
/// it to the DOM and re-serializing. Schema-driven targets are not supported by
/// this convenience wrapper.
pub fn transcode_tagged(
    bytes: &[u8],
    from: ProtocolType,
    from_version: u16,
    to: ProtocolType,
    to_version: u16,
) -> Result<Vec<u8>> {
    let value = match from {
        ProtocolType::Compact => compact::parse(bytes, from_version)?,
        ProtocolType::Fast => fast::parse(bytes)?,
        _ => return Err(Error::SchemaRequired),
    };
    match to {
        ProtocolType::Compact => compact::write(&value, to_version),
        ProtocolType::Fast => fast::write(&value),
        ProtocolType::SimpleJson => simple_json::write(&value, false),
        _ => Err(Error::SchemaRequired),
    }
}
