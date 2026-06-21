//! Simple JSON protocol.
//!
//! Mapping (from `cpp/inc/bond/protocol/simple_json_writer.h`):
//! * struct  -> JSON object keyed by field name (numeric id as fallback)
//! * list/set/vector -> JSON array
//! * map     -> **flat** JSON array `[k, v, k, v, ...]`
//! * nullable -> `null` when empty, `[value]` when present
//! * blob    -> JSON array of `int8` values
//! * scalars -> JSON number / bool / string
//!
//! Two parsing modes are offered: a schema-less mode that preserves the JSON
//! structure losslessly (containers all become [`Value::List`] because their
//! Bond kind is ambiguous without a schema), and a schema-driven mode that
//! recovers the exact Bond types.

use serde_json::Value as Json;

use crate::constants::BondDataType;
use crate::error::{Error, Result};
use crate::schema::{SchemaDef, TypeDef};
use crate::value::{Field, Struct, Value};

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Serializes a struct to Simple JSON. `pretty` selects indented output.
pub fn write(value: &Struct, pretty: bool) -> Result<Vec<u8>> {
    let json = struct_to_json(value)?;
    let s = if pretty {
        serde_json::to_string_pretty(&json)?
    } else {
        serde_json::to_string(&json)?
    };
    Ok(s.into_bytes())
}

fn struct_to_json(s: &Struct) -> Result<Json> {
    let mut map = serde_json::Map::with_capacity(s.fields.len());
    for f in &s.fields {
        let key = f
            .name
            .clone()
            .unwrap_or_else(|| f.id.to_string());
        map.insert(key, value_to_json(&f.value)?);
    }
    Ok(Json::Object(map))
}

fn number_f64(v: f64) -> Json {
    // Standard JSON cannot represent non-finite values; emit null for them.
    serde_json::Number::from_f64(v).map_or(Json::Null, Json::Number)
}

fn value_to_json(value: &Value) -> Result<Json> {
    Ok(match value {
        Value::Bool(v) => Json::Bool(*v),
        Value::UInt8(v) => Json::Number((*v).into()),
        Value::UInt16(v) => Json::Number((*v).into()),
        Value::UInt32(v) => Json::Number((*v).into()),
        Value::UInt64(v) => Json::Number((*v).into()),
        Value::Int8(v) => Json::Number((*v).into()),
        Value::Int16(v) => Json::Number((*v).into()),
        Value::Int32(v) => Json::Number((*v).into()),
        Value::Int64(v) => Json::Number((*v).into()),
        Value::Float(v) => number_f64(*v as f64),
        Value::Double(v) => number_f64(*v),
        Value::Str(s) => Json::String(s.clone()),
        Value::WStr(s) => Json::String(s.clone()),
        Value::Struct(s) => struct_to_json(s)?,
        Value::List { items, .. } | Value::Set { items, .. } => {
            Json::Array(items.iter().map(value_to_json).collect::<Result<_>>()?)
        }
        Value::Map { entries, .. } => {
            // Flat [k, v, k, v, ...].
            let mut arr = Vec::with_capacity(entries.len() * 2);
            for (k, v) in entries {
                arr.push(value_to_json(k)?);
                arr.push(value_to_json(v)?);
            }
            Json::Array(arr)
        }
        Value::Nullable { value, .. } => match value {
            None => Json::Null,
            Some(inner) => Json::Array(vec![value_to_json(inner)?]),
        },
        Value::Blob(bytes) => Json::Array(
            bytes
                .iter()
                .map(|&b| Json::Number((b as i8).into()))
                .collect(),
        ),
        Value::Bonded(_) => {
            return Err(Error::Json(
                "cannot serialize bonded<T> to Simple JSON without a schema".into(),
            ))
        }
    })
}

// ---------------------------------------------------------------------------
// Schema-less parsing
// ---------------------------------------------------------------------------

/// Parses Simple JSON without a schema into a structurally-faithful tree.
///
/// Container kind is not recoverable without a schema, so every JSON array
/// becomes a [`Value::List`]; use [`parse_with_schema`] for exact types.
pub fn parse(bytes: &[u8]) -> Result<Struct> {
    let json: Json = serde_json::from_slice(bytes)?;
    match json {
        Json::Object(_) => json_to_struct_schemaless(&json),
        _ => Err(Error::Json("top-level Simple JSON value must be an object".into())),
    }
}

fn json_to_struct_schemaless(json: &Json) -> Result<Struct> {
    let obj = json
        .as_object()
        .ok_or_else(|| Error::Json("expected JSON object for struct".into()))?;
    let mut fields = Vec::with_capacity(obj.len());
    for (k, v) in obj {
        let id = k.parse::<u16>().unwrap_or(0);
        fields.push(Field {
            id,
            name: Some(k.clone()),
            value: json_to_value_schemaless(v)?,
        });
    }
    Ok(Struct { fields })
}

fn json_to_value_schemaless(json: &Json) -> Result<Value> {
    Ok(match json {
        Json::Null => Value::Nullable {
            element: BondDataType::Unavailable,
            value: None,
        },
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int64(i)
            } else if let Some(u) = n.as_u64() {
                Value::UInt64(u)
            } else {
                Value::Double(n.as_f64().unwrap_or(0.0))
            }
        }
        Json::String(s) => Value::Str(s.clone()),
        Json::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(json_to_value_schemaless(it)?);
            }
            let element = out.first().map_or(BondDataType::Unavailable, Value::type_of);
            Value::List { element, items: out }
        }
        Json::Object(_) => Value::Struct(json_to_struct_schemaless(json)?),
    })
}

// ---------------------------------------------------------------------------
// Schema-driven parsing
// ---------------------------------------------------------------------------

/// Parses Simple JSON using `schema`, recovering exact Bond types.
pub fn parse_with_schema(bytes: &[u8], schema: &SchemaDef) -> Result<Struct> {
    let json: Json = serde_json::from_slice(bytes)?;
    let root = &schema.root;
    if root.id != BondDataType::Struct {
        return Err(Error::SchemaError("Simple JSON root must be a struct".into()));
    }
    json_to_struct_typed(&json, schema, root.struct_def, 0)
}

fn json_to_struct_typed(
    json: &Json,
    schema: &SchemaDef,
    index: u16,
    depth: usize,
) -> Result<Struct> {
    let obj = json
        .as_object()
        .ok_or_else(|| Error::Json("expected JSON object for struct".into()))?;
    let mut fields = Vec::new();
    collect_struct_fields_typed(obj, schema, index, &mut fields, depth)?;
    Ok(Struct { fields })
}

fn collect_struct_fields_typed(
    obj: &serde_json::Map<String, Json>,
    schema: &SchemaDef,
    index: u16,
    fields: &mut Vec<Field>,
    depth: usize,
) -> Result<()> {
    let sd = schema
        .struct_def(index)
        .ok_or_else(|| Error::SchemaError(format!("no struct at index {index}")))?;
    if let Some(base) = &sd.base_def {
        collect_struct_fields_typed(obj, schema, base.struct_def, fields, depth)?;
    }
    for fd in &sd.fields {
        // Match by metadata name first, then by the field id rendered as a string.
        let id_key = fd.id.to_string();
        let jv = obj
            .get(&fd.metadata.name)
            .or_else(|| obj.get(&id_key));
        if let Some(jv) = jv {
            let value = json_to_value_typed(jv, schema, &fd.type_def, depth + 1)?;
            fields.push(Field {
                id: fd.id,
                name: Some(fd.metadata.name.clone()),
                value,
            });
        }
    }
    Ok(())
}

fn num_err(what: &str) -> Error {
    Error::Json(format!("expected JSON number for {what}"))
}

fn json_to_value_typed(
    json: &Json,
    schema: &SchemaDef,
    td: &TypeDef,
    depth: usize,
) -> Result<Value> {
    use BondDataType::*;
    Ok(match td.id {
        Bool => Value::Bool(json.as_bool().ok_or_else(|| Error::Json("expected bool".into()))?),
        UInt8 => Value::UInt8(json.as_u64().ok_or_else(|| num_err("uint8"))? as u8),
        UInt16 => Value::UInt16(json.as_u64().ok_or_else(|| num_err("uint16"))? as u16),
        UInt32 => Value::UInt32(json.as_u64().ok_or_else(|| num_err("uint32"))? as u32),
        UInt64 => Value::UInt64(json.as_u64().ok_or_else(|| num_err("uint64"))?),
        Int8 => Value::Int8(json.as_i64().ok_or_else(|| num_err("int8"))? as i8),
        Int16 => Value::Int16(json.as_i64().ok_or_else(|| num_err("int16"))? as i16),
        Int32 => Value::Int32(json.as_i64().ok_or_else(|| num_err("int32"))? as i32),
        Int64 => Value::Int64(json.as_i64().ok_or_else(|| num_err("int64"))?),
        Float => Value::Float(json_to_f64(json) as f32),
        Double => Value::Double(json_to_f64(json)),
        String => Value::Str(
            json.as_str()
                .ok_or_else(|| Error::Json("expected string".into()))?
                .to_owned(),
        ),
        WString => Value::WStr(
            json.as_str()
                .ok_or_else(|| Error::Json("expected wstring".into()))?
                .to_owned(),
        ),
        Struct => Value::Struct(json_to_struct_typed(json, schema, td.struct_def, depth + 1)?),
        List => {
            use crate::constants::ListSubType;
            let element = td.element_type()?;
            match td.sub_type {
                ListSubType::Nullable => match json {
                    Json::Null => Value::Nullable {
                        element: element.id,
                        value: None,
                    },
                    Json::Array(arr) if arr.len() == 1 => Value::Nullable {
                        element: element.id,
                        value: Some(Box::new(json_to_value_typed(
                            &arr[0],
                            schema,
                            element,
                            depth + 1,
                        )?)),
                    },
                    _ => {
                        return Err(Error::Json(
                            "nullable must be null or a single-element array".into(),
                        ))
                    }
                },
                ListSubType::Blob => {
                    let arr = json
                        .as_array()
                        .ok_or_else(|| Error::Json("expected array for blob".into()))?;
                    let mut bytes = Vec::with_capacity(arr.len());
                    for it in arr {
                        bytes.push(it.as_i64().ok_or_else(|| num_err("blob byte"))? as i8 as u8);
                    }
                    Value::Blob(bytes)
                }
                ListSubType::None => {
                    let items = json_array_to_items(json, schema, element, depth)?;
                    Value::List {
                        element: element.id,
                        items,
                    }
                }
            }
        }
        Set => {
            let element = td.element_type()?;
            let items = json_array_to_items(json, schema, element, depth)?;
            Value::Set {
                element: element.id,
                items,
            }
        }
        Map => {
            let key_td = td.key_type()?;
            let val_td = td.element_type()?;
            let arr = json
                .as_array()
                .ok_or_else(|| Error::Json("expected flat array for map".into()))?;
            if arr.len() % 2 != 0 {
                return Err(Error::Json("map array must have an even length".into()));
            }
            let mut entries = Vec::with_capacity(arr.len() / 2);
            for pair in arr.chunks_exact(2) {
                let k = json_to_value_typed(&pair[0], schema, key_td, depth + 1)?;
                let v = json_to_value_typed(&pair[1], schema, val_td, depth + 1)?;
                entries.push((k, v));
            }
            Value::Map {
                key: key_td.id,
                value: val_td.id,
                entries,
            }
        }
        other => {
            return Err(Error::SchemaError(format!(
                "unsupported type {other:?} in Simple JSON schema"
            )))
        }
    })
}

fn json_to_f64(json: &Json) -> f64 {
    // Non-finite values were serialized as null; recover them as 0.0.
    json.as_f64().unwrap_or(0.0)
}

fn json_array_to_items(
    json: &Json,
    schema: &SchemaDef,
    element: &TypeDef,
    depth: usize,
) -> Result<Vec<Value>> {
    let arr = json
        .as_array()
        .ok_or_else(|| Error::Json("expected array".into()))?;
    let mut items = Vec::with_capacity(arr.len());
    for it in arr {
        items.push(json_to_value_typed(it, schema, element, depth + 1)?);
    }
    Ok(items)
}

