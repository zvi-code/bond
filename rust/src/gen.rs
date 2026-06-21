//! Deterministic Bond data generation.
//!
//! Produces matching ([`SchemaDef`], [`Struct`]) pairs from a seed, covering
//! every Bond type. Used by the test suite for round-trip coverage and by the
//! benchmark suite to build representative small and large payloads. Generation
//! is fully deterministic for a given seed (via `rand_chacha`), so failures are
//! reproducible.

use rand::Rng;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha8Rng;

use crate::constants::{BondDataType, ListSubType};
use crate::schema::{FieldDef, SchemaDef, StructDef, TypeDef};
use crate::value::{Field, Struct, Value};

/// Tunable limits controlling generated shapes.
#[derive(Clone, Debug)]
pub struct GenConfig {
    /// Maximum nesting depth for structs and containers.
    pub max_depth: usize,
    /// Maximum number of fields per struct.
    pub max_fields: usize,
    /// Maximum number of elements per container.
    pub max_container_len: usize,
    /// Maximum length of generated strings (in characters).
    pub max_string_len: usize,
    /// Whether to include `wstring` fields (UTF-16).
    pub allow_wstring: bool,
    /// Whether to include `nullable`, `blob` and non-scalar containers.
    pub allow_complex: bool,
}

impl Default for GenConfig {
    fn default() -> Self {
        GenConfig {
            max_depth: 4,
            max_fields: 6,
            max_container_len: 8,
            max_string_len: 16,
            allow_wstring: true,
            allow_complex: true,
        }
    }
}

/// A seeded generator of Bond schemas and values.
pub struct Generator {
    rng: ChaCha8Rng,
    cfg: GenConfig,
    structs: Vec<StructDef>,
}

const UNICODE_POOL: &[char] = &[
    'a', 'Z', '0', ' ', '_', '\n', '"', '\\', 'é', 'ß', 'Ω', '中', '文', '🦀', '😀', '𝄞',
];

impl Generator {
    /// Creates a generator with the default configuration and the given seed.
    pub fn new(seed: u64) -> Self {
        Self::with_config(seed, GenConfig::default())
    }

    /// Creates a generator with an explicit configuration.
    pub fn with_config(seed: u64, cfg: GenConfig) -> Self {
        Generator {
            rng: ChaCha8Rng::seed_from_u64(seed),
            cfg,
            structs: Vec::new(),
        }
    }

    /// Generates a random schema together with a conforming value.
    pub fn generate(&mut self) -> (SchemaDef, Struct) {
        self.structs.clear();
        let root_idx = self.gen_struct_def(0);
        let schema = SchemaDef {
            structs: std::mem::take(&mut self.structs),
            root: TypeDef::struct_ref(root_idx),
        };
        let value = self.gen_struct_value(&schema, root_idx, 0);
        (schema, value)
    }

    /// Builds a large payload: a root struct containing one big list of small
    /// records, useful for throughput benchmarking. Returns the schema and the
    /// value; `records` controls the element count.
    pub fn generate_large(&mut self, records: usize) -> (SchemaDef, Struct) {
        // Inner record: a handful of scalar/string fields.
        let inner = StructDef::new(
            "Record",
            vec![
                FieldDef::new(0, "id", TypeDef::scalar(BondDataType::Int64)),
                FieldDef::new(1, "name", TypeDef::scalar(BondDataType::String)),
                FieldDef::new(2, "score", TypeDef::scalar(BondDataType::Double)),
                FieldDef::new(3, "active", TypeDef::scalar(BondDataType::Bool)),
                FieldDef::new(4, "tags", TypeDef::list(TypeDef::scalar(BondDataType::String))),
            ],
        );
        let root = StructDef::new(
            "Batch",
            vec![FieldDef::new(
                0,
                "records",
                TypeDef::list(TypeDef::struct_ref(0)),
            )],
        );
        let schema = SchemaDef::with_root_struct(vec![inner, root], 1);

        let mut items = Vec::with_capacity(records);
        for i in 0..records {
            items.push(Value::Struct(
                Struct::new()
                    .with_field(0, Value::Int64(i as i64))
                    .with_field(1, Value::Str(self.gen_string()))
                    .with_field(2, Value::Double(self.gen_f64()))
                    .with_field(3, Value::Bool(self.rng.gen()))
                    .with_field(
                        4,
                        Value::List {
                            element: BondDataType::String,
                            items: (0..self.rng.gen_range(0..4))
                                .map(|_| Value::Str(self.gen_string()))
                                .collect(),
                        },
                    ),
            ));
        }
        let value = Struct::new().with_field(
            0,
            Value::List {
                element: BondDataType::Struct,
                items,
            },
        );
        (schema, value)
    }

    // --- schema generation ---

    fn gen_struct_def(&mut self, depth: usize) -> u16 {
        let nfields = self.rng.gen_range(1..=self.cfg.max_fields.max(1));
        let mut fields = Vec::with_capacity(nfields);
        for i in 0..nfields {
            let td = self.gen_type_def(depth + 1);
            fields.push(FieldDef::new(i as u16, format!("f{i}"), td));
        }
        let idx = self.structs.len() as u16;
        self.structs
            .push(StructDef::new(format!("S{idx}"), fields));
        idx
    }

    fn gen_type_def(&mut self, depth: usize) -> TypeDef {
        // Near the depth limit, only emit leaf types.
        let complex_ok = self.cfg.allow_complex && depth < self.cfg.max_depth;
        let n = if complex_ok { 18 } else { 12 };
        match self.rng.gen_range(0..n) {
            0 => TypeDef::scalar(BondDataType::Bool),
            1 => TypeDef::scalar(BondDataType::UInt8),
            2 => TypeDef::scalar(BondDataType::UInt16),
            3 => TypeDef::scalar(BondDataType::UInt32),
            4 => TypeDef::scalar(BondDataType::UInt64),
            5 => TypeDef::scalar(BondDataType::Int8),
            6 => TypeDef::scalar(BondDataType::Int16),
            7 => TypeDef::scalar(BondDataType::Int32),
            8 => TypeDef::scalar(BondDataType::Int64),
            9 => TypeDef::scalar(BondDataType::Float),
            10 => TypeDef::scalar(BondDataType::Double),
            11 => {
                if self.cfg.allow_wstring && self.rng.gen_bool(0.5) {
                    TypeDef::scalar(BondDataType::WString)
                } else {
                    TypeDef::scalar(BondDataType::String)
                }
            }
            12 => TypeDef::struct_ref(self.gen_struct_def(depth + 1)),
            13 => TypeDef::list(self.gen_type_def(depth + 1)),
            14 => TypeDef::set(self.gen_basic_type_def()),
            15 => TypeDef::map(self.gen_basic_type_def(), self.gen_type_def(depth + 1)),
            16 => TypeDef::nullable(self.gen_type_def(depth + 1)),
            _ => TypeDef::blob(),
        }
    }

    /// A scalar or string type, suitable for set elements and map keys.
    fn gen_basic_type_def(&mut self) -> TypeDef {
        match self.rng.gen_range(0..12) {
            0 => TypeDef::scalar(BondDataType::Bool),
            1 => TypeDef::scalar(BondDataType::UInt8),
            2 => TypeDef::scalar(BondDataType::UInt16),
            3 => TypeDef::scalar(BondDataType::UInt32),
            4 => TypeDef::scalar(BondDataType::UInt64),
            5 => TypeDef::scalar(BondDataType::Int8),
            6 => TypeDef::scalar(BondDataType::Int16),
            7 => TypeDef::scalar(BondDataType::Int32),
            8 => TypeDef::scalar(BondDataType::Int64),
            9 => TypeDef::scalar(BondDataType::Float),
            10 => TypeDef::scalar(BondDataType::Double),
            _ => TypeDef::scalar(BondDataType::String),
        }
    }

    // --- value generation conforming to a TypeDef ---

    fn gen_struct_value(&mut self, schema: &SchemaDef, index: u16, depth: usize) -> Struct {
        let sd = schema.structs[index as usize].clone();
        let mut fields = Vec::with_capacity(sd.fields.len());
        for fd in &sd.fields {
            let value = self.gen_value(schema, &fd.type_def, depth + 1);
            fields.push(Field {
                id: fd.id,
                name: Some(fd.metadata.name.clone()),
                value,
            });
        }
        Struct { fields }
    }

    fn gen_value(&mut self, schema: &SchemaDef, td: &TypeDef, depth: usize) -> Value {
        match td.id {
            BondDataType::Bool => Value::Bool(self.rng.gen()),
            BondDataType::UInt8 => Value::UInt8(self.rng.gen()),
            BondDataType::UInt16 => Value::UInt16(self.rng.gen()),
            BondDataType::UInt32 => Value::UInt32(self.rng.gen()),
            BondDataType::UInt64 => Value::UInt64(self.rng.gen()),
            BondDataType::Int8 => Value::Int8(self.rng.gen()),
            BondDataType::Int16 => Value::Int16(self.rng.gen()),
            BondDataType::Int32 => Value::Int32(self.rng.gen()),
            BondDataType::Int64 => Value::Int64(self.rng.gen()),
            BondDataType::Float => Value::Float(self.gen_f64() as f32),
            BondDataType::Double => Value::Double(self.gen_f64()),
            BondDataType::String => Value::Str(self.gen_string()),
            BondDataType::WString => Value::WStr(self.gen_string()),
            BondDataType::Struct => {
                Value::Struct(self.gen_struct_value(schema, td.struct_def, depth))
            }
            BondDataType::List => self.gen_list_value(schema, td, depth),
            BondDataType::Set => {
                let element = td.element.as_deref().unwrap();
                let len = self.rng.gen_range(0..=self.cfg.max_container_len);
                let items = (0..len)
                    .map(|_| self.gen_value(schema, element, depth + 1))
                    .collect();
                Value::Set {
                    element: element.id,
                    items,
                }
            }
            BondDataType::Map => {
                let key_td = td.key.as_deref().unwrap();
                let val_td = td.element.as_deref().unwrap();
                let len = self.rng.gen_range(0..=self.cfg.max_container_len);
                let entries = (0..len)
                    .map(|_| {
                        (
                            self.gen_value(schema, key_td, depth + 1),
                            self.gen_value(schema, val_td, depth + 1),
                        )
                    })
                    .collect();
                Value::Map {
                    key: key_td.id,
                    value: val_td.id,
                    entries,
                }
            }
            other => panic!("generator does not handle type {other:?}"),
        }
    }

    fn gen_list_value(&mut self, schema: &SchemaDef, td: &TypeDef, depth: usize) -> Value {
        let element = td.element.as_deref().unwrap();
        match td.sub_type {
            ListSubType::Blob => {
                let len = self.rng.gen_range(0..=self.cfg.max_container_len * 2);
                let mut bytes = vec![0u8; len];
                self.rng.fill(bytes.as_mut_slice());
                Value::Blob(bytes)
            }
            ListSubType::Nullable => {
                if self.rng.gen_bool(0.5) {
                    Value::Nullable {
                        element: element.id,
                        value: None,
                    }
                } else {
                    Value::Nullable {
                        element: element.id,
                        value: Some(Box::new(self.gen_value(schema, element, depth + 1))),
                    }
                }
            }
            ListSubType::None => {
                let len = self.rng.gen_range(0..=self.cfg.max_container_len);
                let items = (0..len)
                    .map(|_| self.gen_value(schema, element, depth + 1))
                    .collect();
                Value::List {
                    element: element.id,
                    items,
                }
            }
        }
    }

    // --- leaf value helpers ---

    fn gen_string(&mut self) -> String {
        let len = self.rng.gen_range(0..=self.cfg.max_string_len);
        (0..len)
            .map(|_| UNICODE_POOL[self.rng.gen_range(0..UNICODE_POOL.len())])
            .collect()
    }

    /// A finite `f64` (no NaN/Inf, so values compare equal and survive JSON).
    fn gen_f64(&mut self) -> f64 {
        // Mix of "nice" integers and arbitrary finite reals.
        if self.rng.gen_bool(0.3) {
            self.rng.gen_range(-1_000_000i64..1_000_000) as f64
        } else {
            // Uniform in a wide finite range.
            (self.rng.gen::<f64>() - 0.5) * 1e9
        }
    }
}
