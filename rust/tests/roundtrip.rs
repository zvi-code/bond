//! Round-trip coverage: for many random (schema, value) pairs, serialize with
//! every protocol and confirm the parse reproduces the value.
//!
//! Tagged protocols (Compact, Fast) cannot recover field names or the
//! `nullable`/`blob` sub-kinds (all `BT_LIST` on the wire), so the expected
//! value is normalized for those comparisons. Schema-driven protocols (Simple
//! Binary, Simple JSON) recover the exact types and compare directly.

use bond::{compact, fast, simple, simple_json};
use bond::{BondDataType, Field, Struct, Value, V1, V2};

/// Lowers a value to the form a tagged reader will produce: no field names,
/// `nullable`/`blob` collapsed to `list`.
fn normalize_tagged(v: &Value) -> Value {
    match v {
        Value::Struct(s) => Value::Struct(normalize_struct(s)),
        Value::List { element, items } => Value::List {
            element: *element,
            items: items.iter().map(normalize_tagged).collect(),
        },
        Value::Set { element, items } => Value::Set {
            element: *element,
            items: items.iter().map(normalize_tagged).collect(),
        },
        Value::Map { key, value, entries } => Value::Map {
            key: *key,
            value: *value,
            entries: entries
                .iter()
                .map(|(k, v)| (normalize_tagged(k), normalize_tagged(v)))
                .collect(),
        },
        Value::Nullable { element, value } => Value::List {
            element: *element,
            items: value
                .as_ref()
                .map(|b| vec![normalize_tagged(b)])
                .unwrap_or_default(),
        },
        Value::Blob(bytes) => Value::List {
            element: BondDataType::Int8,
            items: bytes.iter().map(|&b| Value::Int8(b as i8)).collect(),
        },
        other => other.clone(),
    }
}

fn normalize_struct(s: &Struct) -> Struct {
    Struct {
        fields: s
            .fields
            .iter()
            .map(|f| Field {
                id: f.id,
                name: None,
                value: normalize_tagged(&f.value),
            })
            .collect(),
    }
}

#[test]
fn roundtrip_all_protocols_many_seeds() {
    for seed in 0..300u64 {
        let (schema, value) = bond::gen::Generator::new(seed).generate();
        let expected_tagged = normalize_struct(&value);

        // Compact Binary v1 and v2.
        for &ver in &[V1, V2] {
            let bytes = compact::write(&value, ver).unwrap();
            let parsed = compact::parse(&bytes, ver)
                .unwrap_or_else(|e| panic!("compact v{ver} seed {seed}: {e}"));
            assert_eq!(parsed, expected_tagged, "compact v{ver} seed {seed}");
        }

        // Fast Binary.
        let bytes = fast::write(&value).unwrap();
        let parsed = fast::parse(&bytes).unwrap_or_else(|e| panic!("fast seed {seed}: {e}"));
        assert_eq!(parsed, expected_tagged, "fast seed {seed}");

        // Simple Binary v1 and v2 (schema-driven, exact recovery).
        for &ver in &[V1, V2] {
            let bytes = simple::write(&value, &schema, ver)
                .unwrap_or_else(|e| panic!("simple v{ver} write seed {seed}: {e}"));
            let parsed = simple::parse(&bytes, &schema, ver)
                .unwrap_or_else(|e| panic!("simple v{ver} parse seed {seed}: {e}"));
            assert_eq!(parsed, value, "simple v{ver} seed {seed}");
        }

        // Simple JSON (schema-driven, exact recovery).
        let bytes = simple_json::write(&value, false)
            .unwrap_or_else(|e| panic!("json write seed {seed}: {e}"));
        let parsed = simple_json::parse_with_schema(&bytes, &schema)
            .unwrap_or_else(|e| panic!("json parse seed {seed}: {e}"));
        assert_eq!(parsed, value, "simple json seed {seed}");
    }
}

#[test]
fn roundtrip_pretty_json() {
    let (schema, value) = bond::gen::Generator::new(42).generate();
    let bytes = simple_json::write(&value, true).unwrap();
    let parsed = simple_json::parse_with_schema(&bytes, &schema).unwrap();
    assert_eq!(parsed, value);
}

#[test]
fn marshal_unmarshal_tagged() {
    use bond::{marshal, unmarshal, ProtocolType};
    let (_schema, value) = bond::gen::Generator::new(7).generate();
    let expected = normalize_struct(&value);

    for (proto, ver) in [
        (ProtocolType::Compact, V1),
        (ProtocolType::Compact, V2),
        (ProtocolType::Fast, V1),
    ] {
        let bytes = marshal(&value, proto, ver).unwrap();
        let out = unmarshal(&bytes).unwrap();
        assert_eq!(out.protocol, proto);
        assert_eq!(out.version, ver);
        assert_eq!(out.value, expected, "{proto:?} v{ver}");
    }
}

#[test]
fn marshal_unmarshal_simple_with_schema() {
    use bond::{marshal_with_schema, unmarshal_with_schema, ProtocolType};
    let (schema, value) = bond::gen::Generator::new(11).generate();

    for &ver in &[V1, V2] {
        let bytes = marshal_with_schema(&value, ProtocolType::Simple, ver, &schema).unwrap();
        let out = unmarshal_with_schema(&bytes, &schema).unwrap();
        assert_eq!(out.protocol, ProtocolType::Simple);
        assert_eq!(out.version, ver);
        assert_eq!(out.value, value, "simple v{ver}");
    }
}

#[test]
fn transcode_compact_to_fast() {
    use bond::{transcode_tagged, ProtocolType};
    let (_schema, value) = bond::gen::Generator::new(99).generate();
    let compact_bytes = compact::write(&value, V2).unwrap();
    let fast_bytes =
        transcode_tagged(&compact_bytes, ProtocolType::Compact, V2, ProtocolType::Fast, V1).unwrap();
    let from_fast = fast::parse(&fast_bytes).unwrap();
    let from_compact = compact::parse(&compact_bytes, V2).unwrap();
    assert_eq!(from_fast, from_compact);
}
