//! Exact wire-format vectors, hand-computed from the reference encoding rules,
//! pinning the byte layout of each protocol so regressions are caught.

use bond::{compact, fast, marshal, ProtocolType};
use bond::{BondDataType, Struct, Value, V1, V2};

/// `{ 0: int32 = -5, 1: string = "hi" }`
fn sample() -> Struct {
    Struct::new()
        .with_field(0, Value::Int32(-5))
        .with_field(1, Value::Str("hi".into()))
}

#[test]
fn compact_v1_field_header_and_zigzag() {
    // field0: type=INT32(0x10), id=0 -> 0x10 ; zigzag(-5)=9 -> 0x09
    // field1: type=STRING(0x09), id=1 -> 0x09|0x20=0x29 ; len 2 -> 0x02 ; "hi"
    // stop -> 0x00
    let bytes = compact::write(&sample(), V1).unwrap();
    assert_eq!(
        bytes,
        vec![0x10, 0x09, 0x29, 0x02, 0x68, 0x69, 0x00],
        "compact v1 layout"
    );
    assert_eq!(compact::parse(&bytes, V1).unwrap(), sample());
}

#[test]
fn compact_v2_struct_length_prefix() {
    // Same body as v1 (7 bytes) prefixed with its varint length 0x07.
    let bytes = compact::write(&sample(), V2).unwrap();
    assert_eq!(
        bytes,
        vec![0x07, 0x10, 0x09, 0x29, 0x02, 0x68, 0x69, 0x00],
        "compact v2 layout"
    );
    assert_eq!(compact::parse(&bytes, V2).unwrap(), sample());
}

#[test]
fn compact_v2_small_count_container() {
    // list<int8> = [1, 2, 3]
    // container header v2: type INT8(14) | ((3+1)<<5) = 14 | 0x80 = 0x8E
    let s = Struct::new().with_field(
        0,
        Value::List {
            element: BondDataType::Int8,
            items: vec![Value::Int8(1), Value::Int8(2), Value::Int8(3)],
        },
    );
    let bytes = compact::write(&s, V2).unwrap();
    // body: field0 header (LIST=11, id0 -> 0x0B), container 0x8E, 1,2,3, stop
    let body = vec![0x0B, 0x8E, 0x01, 0x02, 0x03, 0x00];
    let mut expected = vec![body.len() as u8];
    expected.extend(body);
    assert_eq!(bytes, expected, "compact v2 small-count list");
    assert_eq!(compact::parse(&bytes, V2).unwrap(), s);
}

#[test]
fn compact_v1_large_count_container() {
    // In v1 (and v2 for >=7 elements) the count is a separate varint.
    let s = Struct::new().with_field(
        0,
        Value::List {
            element: BondDataType::Int8,
            items: (0..7).map(Value::Int8).collect(),
        },
    );
    let bytes = compact::write(&s, V1).unwrap();
    // field0 header 0x0B, element type INT8 0x0E, count 0x07, 0..6, stop
    assert_eq!(
        bytes,
        vec![0x0B, 0x0E, 0x07, 0, 1, 2, 3, 4, 5, 6, 0x00]
    );
    assert_eq!(compact::parse(&bytes, V1).unwrap(), s);
}

#[test]
fn fast_fixed_width_layout() {
    // field0: type INT32(0x10), id LE 0x0000, value -5 LE = FB FF FF FF
    // field1: type STRING(0x09), id LE 0x0100, len varint 0x02, "hi"
    // stop 0x00
    let bytes = fast::write(&sample()).unwrap();
    assert_eq!(
        bytes,
        vec![
            0x10, 0x00, 0x00, 0xFB, 0xFF, 0xFF, 0xFF, // field0
            0x09, 0x01, 0x00, 0x02, 0x68, 0x69, // field1
            0x00, // stop
        ],
        "fast binary layout"
    );
    assert_eq!(fast::parse(&bytes).unwrap(), sample());
}

#[test]
fn compact_field_id_encodings() {
    // id in (5,255] -> 2-byte header; id in (255,65535] -> 3-byte header.
    let s = Struct::new()
        .with_field(200, Value::Bool(true))
        .with_field(1000, Value::Bool(false));
    let bytes = compact::write(&s, V1).unwrap();
    // field 200: type BOOL(2) | (0x06<<5)=0xC2, id byte 200=0xC8, value 0x01
    // field 1000: type BOOL(2) | (0x07<<5)=0xE2, id LE 0xE8 0x03, value 0x00
    assert_eq!(
        bytes,
        vec![0xC2, 0xC8, 0x01, 0xE2, 0xE8, 0x03, 0x00, 0x00]
    );
    assert_eq!(compact::parse(&bytes, V1).unwrap(), s);
}

#[test]
fn marshal_header_bytes() {
    // Compact v2 marshaled: magic 0x4243 LE, version 0x0002 LE, then payload.
    let bytes = marshal(&sample(), ProtocolType::Compact, V2).unwrap();
    assert_eq!(&bytes[0..4], &[0x43, 0x42, 0x02, 0x00], "marshal header");
    let detected = bond::detect(&bytes).unwrap();
    assert_eq!(detected, (ProtocolType::Compact, V2));
}

#[test]
fn empty_struct_roundtrips() {
    let s = Struct::new();
    // v1: just a stop byte.
    assert_eq!(compact::write(&s, V1).unwrap(), vec![0x00]);
    // v2: length 1 + stop.
    assert_eq!(compact::write(&s, V2).unwrap(), vec![0x01, 0x00]);
    assert_eq!(fast::write(&s).unwrap(), vec![0x00]);
}

#[test]
fn all_scalar_types_roundtrip_compact() {
    let s = Struct::new()
        .with_field(0, Value::Bool(true))
        .with_field(1, Value::UInt8(255))
        .with_field(2, Value::UInt16(65535))
        .with_field(3, Value::UInt32(4_000_000_000))
        .with_field(4, Value::UInt64(u64::MAX))
        .with_field(5, Value::Int8(-128))
        .with_field(6, Value::Int16(-32768))
        .with_field(7, Value::Int32(i32::MIN))
        .with_field(8, Value::Int64(i64::MIN))
        .with_field(9, Value::Float(3.5))
        .with_field(10, Value::Double(-2.25))
        .with_field(11, Value::WStr("héllo 🦀".into()));
    for &ver in &[V1, V2] {
        let bytes = compact::write(&s, ver).unwrap();
        assert_eq!(compact::parse(&bytes, ver).unwrap(), s, "v{ver}");
    }
    let bytes = fast::write(&s).unwrap();
    assert_eq!(fast::parse(&bytes).unwrap(), s);
}
