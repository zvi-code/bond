//! Malformed-input tests: a broken Bond payload must yield an `Err`, never a
//! panic, and the error variant should reflect the failure.

use bond::{compact, fast, Error, Struct, Value, V1, V2};

#[test]
fn truncated_compact_is_eof() {
    // A field header announcing an int32 value, but no value bytes follow.
    let bytes = [0x10u8]; // INT32, id 0
    match compact::parse(&bytes, V1) {
        Err(Error::UnexpectedEof { .. }) => {}
        other => panic!("expected EOF, got {other:?}"),
    }
}

#[test]
fn unknown_type_byte_is_rejected() {
    // Type nibble 19 is not a valid BondDataType.
    let bytes = [19u8, 0x00];
    match compact::parse(&bytes, V1) {
        Err(Error::UnknownType(19)) => {}
        other => panic!("expected UnknownType, got {other:?}"),
    }
}

#[test]
fn varint_overflow_is_rejected() {
    // A uint32 field whose varint never terminates (11 continuation bytes).
    let mut bytes = vec![0x05u8]; // UINT32, id 0
    bytes.extend(std::iter::repeat(0x80).take(11));
    match compact::parse(&bytes, V1) {
        Err(Error::VarintOverflow) => {}
        other => panic!("expected VarintOverflow, got {other:?}"),
    }
}

#[test]
fn huge_string_length_is_bounded() {
    // STRING field, id 0, with a declared length far exceeding the payload.
    // Header 0x09, varint length 0xFFFFFF07 (~big), then nothing.
    let mut bytes = vec![0x09u8];
    bond::varint::encode_u32(1_000_000, &mut bytes);
    match compact::parse(&bytes, V1) {
        Err(Error::UnexpectedEof { .. }) => {}
        other => panic!("expected EOF for oversized string, got {other:?}"),
    }
}

#[test]
fn depth_limit_protects_against_nesting_bombs() {
    // Build a struct nested far deeper than the limit and confirm the parser
    // rejects it rather than overflowing the stack.
    let mut v = Value::Bool(true);
    for _ in 0..(bond::DEFAULT_MAX_DEPTH + 50) {
        v = Value::Struct(Struct::new().with_field(0, v));
    }
    let root = Struct::new().with_field(0, v);
    let bytes = compact::write(&root, V1).unwrap();
    match compact::parse(&bytes, V1) {
        Err(Error::DepthLimitExceeded(_)) => {}
        other => panic!("expected DepthLimitExceeded, got {other:?}"),
    }
}

#[test]
fn fast_truncated_field_id_is_eof() {
    // Type byte for a real field but no room for the 2-byte id.
    let bytes = [0x10u8, 0x00];
    assert!(matches!(fast::parse(&bytes), Err(Error::UnexpectedEof { .. })));
}

#[test]
fn unsupported_version_is_rejected() {
    let s = Struct::new().with_field(0, Value::Int32(1));
    let bytes = compact::write(&s, V2).unwrap();
    match compact::parse(&bytes, 7) {
        Err(Error::UnsupportedVersion { .. }) => {}
        other => panic!("expected UnsupportedVersion, got {other:?}"),
    }
}

#[test]
fn invalid_utf8_string_is_rejected() {
    // STRING field id 0, length 2, bytes 0xFF 0xFF (invalid UTF-8).
    let bytes = [0x09u8, 0x02, 0xFF, 0xFF, 0x00];
    match compact::parse(&bytes, V1) {
        Err(Error::InvalidUtf8) => {}
        other => panic!("expected InvalidUtf8, got {other:?}"),
    }
}

#[test]
fn unknown_protocol_magic_is_rejected() {
    let bytes = [0xEE, 0xEE, 0x01, 0x00, 0x00];
    assert!(matches!(
        bond::unmarshal(&bytes),
        Err(Error::UnknownProtocol(_))
    ));
}

#[test]
fn empty_input_is_eof_not_panic() {
    assert!(compact::parse(&[], V1).is_err());
    assert!(fast::parse(&[]).is_err());
}
