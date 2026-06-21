//! Coverage for features the random generator does not exercise: struct
//! inheritance, `bonded<T>`, schema-less JSON, header-less JSON unmarshal, and
//! the zero-allocation `validate` path.

use bond::{compact, gen, simple, simple_json};
use bond::{
    unmarshal_with_schema, BondDataType, Field, FieldDef, Metadata, ProtocolType, SchemaDef,
    Struct, StructDef, TypeDef, Value, V1, V2,
};

#[test]
fn schemaless_json_parses_losslessly() {
    let json = br#"{"a": 1, "b": "x", "c": [1, 2, 3], "d": true, "e": null, "f": -9}"#;
    let s = simple_json::parse(json).unwrap();
    assert_eq!(s.get_by_name("a"), Some(&Value::Int64(1)));
    assert_eq!(s.get_by_name("b"), Some(&Value::Str("x".into())));
    assert_eq!(s.get_by_name("d"), Some(&Value::Bool(true)));
    assert_eq!(s.get_by_name("f"), Some(&Value::Int64(-9)));
    match s.get_by_name("c").unwrap() {
        Value::List { items, .. } => assert_eq!(items.len(), 3),
        other => panic!("expected list, got {other:?}"),
    }
    match s.get_by_name("e").unwrap() {
        Value::Nullable { value: None, .. } => {}
        other => panic!("expected null, got {other:?}"),
    }
}

#[test]
fn simple_binary_and_json_inheritance() {
    // Base { 0: int32 base_a; 1: string base_b }
    // Derived : Base { 2: bool d; 3: int64 e }   (distinct ids across the chain)
    let base = StructDef::new(
        "Base",
        vec![
            FieldDef::new(0, "base_a", TypeDef::scalar(BondDataType::Int32)),
            FieldDef::new(1, "base_b", TypeDef::scalar(BondDataType::String)),
        ],
    );
    let mut derived = StructDef::new(
        "Derived",
        vec![
            FieldDef::new(2, "d", TypeDef::scalar(BondDataType::Bool)),
            FieldDef::new(3, "e", TypeDef::scalar(BondDataType::Int64)),
        ],
    );
    derived.base_def = Some(TypeDef::struct_ref(0));
    let schema = SchemaDef::with_root_struct(vec![base, derived], 1);

    // The DOM is flat: base fields first, then derived (the read order).
    let value = Struct {
        fields: vec![
            Field::named(0, "base_a", Value::Int32(-7)),
            Field::named(1, "base_b", Value::Str("hi".into())),
            Field::named(2, "d", Value::Bool(true)),
            Field::named(3, "e", Value::Int64(123_456_789)),
        ],
    };

    for ver in [V1, V2] {
        let bytes = simple::write(&value, &schema, ver).unwrap();
        let parsed = simple::parse(&bytes, &schema, ver).unwrap();
        assert_eq!(parsed, value, "simple v{ver} inheritance");
    }
    let jbytes = simple_json::write(&value, false).unwrap();
    let jparsed = simple_json::parse_with_schema(&jbytes, &schema).unwrap();
    assert_eq!(jparsed, value, "json inheritance");
}

#[test]
fn bonded_field_roundtrips_in_simple() {
    // Outer { 0: bonded<Inner> b }
    let inner = StructDef::new(
        "Inner",
        vec![FieldDef::new(0, "x", TypeDef::scalar(BondDataType::Int32))],
    );
    let outer = StructDef::new(
        "Outer",
        vec![FieldDef {
            metadata: Metadata::named("b"),
            id: 0,
            type_def: TypeDef::bonded_ref(0),
        }],
    );
    let schema = SchemaDef::with_root_struct(vec![inner, outer], 1);

    // bonded carries an opaque marshaled payload; verify the bytes survive.
    let payload = vec![0x43u8, 0x42, 0x02, 0x00, 0x01, 0x00];
    let value = Struct {
        fields: vec![Field::named(0, "b", Value::Bonded(payload.clone()))],
    };
    for ver in [V1, V2] {
        let bytes = simple::write(&value, &schema, ver).unwrap();
        let parsed = simple::parse(&bytes, &schema, ver).unwrap();
        assert_eq!(parsed, value, "bonded simple v{ver}");
    }
}

#[test]
fn validate_agrees_with_parse() {
    let (_schema, value) = gen::Generator::new(123).generate();
    let bytes = compact::write(&value, V2).unwrap();
    assert!(compact::validate(&bytes, V2).is_ok());
    // A truncated payload must fail validation rather than panic.
    assert!(compact::validate(&bytes[..bytes.len() - 1], V2).is_err());

    let fast_bytes = bond::fast::write(&value).unwrap();
    assert!(bond::fast::validate(&fast_bytes).is_ok());
}

#[test]
fn unmarshal_detects_headerless_json() {
    let (schema, value) = gen::Generator::new(5).generate();
    let jbytes = simple_json::write(&value, false).unwrap();
    let out = unmarshal_with_schema(&jbytes, &schema).unwrap();
    assert_eq!(out.protocol, ProtocolType::SimpleJson);
    assert_eq!(out.value, value);
}

#[test]
fn parse_any_convenience() {
    let (_schema, value) = gen::Generator::new(8).generate();
    let bytes = bond::marshal(&value, ProtocolType::Compact, V2).unwrap();
    let out = bond::parse_any(&bytes, None).unwrap();
    assert_eq!(out.protocol, ProtocolType::Compact);
}
