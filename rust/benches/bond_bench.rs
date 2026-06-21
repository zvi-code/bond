//! Benchmark suite for the Bond parser and writer.
//!
//! Covers parsing and serialization across every protocol, for both small
//! records and large batches, plus the SIMD varint primitive in isolation.
//! Throughput is reported in bytes so results are comparable across protocols.
//!
//! Run with `cargo bench`. Datasets are generated deterministically so numbers
//! are stable across runs.

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};

use bond::gen::Generator;
use bond::{compact, fast, simple, simple_json, SchemaDef, Struct, V1, V2};

/// A serialized dataset together with what is needed to parse it back.
struct Dataset {
    schema: SchemaDef,
    value: Struct,
    compact_v1: Vec<u8>,
    compact_v2: Vec<u8>,
    fast: Vec<u8>,
    simple_v1: Vec<u8>,
    simple_v2: Vec<u8>,
    json: Vec<u8>,
}

impl Dataset {
    fn build(schema: SchemaDef, value: Struct) -> Self {
        Dataset {
            compact_v1: compact::write(&value, V1).unwrap(),
            compact_v2: compact::write(&value, V2).unwrap(),
            fast: fast::write(&value).unwrap(),
            simple_v1: simple::write(&value, &schema, V1).unwrap(),
            simple_v2: simple::write(&value, &schema, V2).unwrap(),
            json: simple_json::write(&value, false).unwrap(),
            schema,
            value,
        }
    }
}

fn parse_group(c: &mut Criterion, name: &str, d: &Dataset) {
    let mut g = c.benchmark_group(name);
    let cases: &[(&str, &[u8])] = &[
        ("compact_v1", &d.compact_v1),
        ("compact_v2", &d.compact_v2),
        ("fast", &d.fast),
        ("simple_v1", &d.simple_v1),
        ("simple_v2", &d.simple_v2),
        ("simple_json", &d.json),
    ];
    for (label, bytes) in cases {
        g.throughput(Throughput::Bytes(bytes.len() as u64));
        g.bench_with_input(BenchmarkId::from_parameter(label), bytes, |b, bytes| {
            b.iter(|| match *label {
                "compact_v1" => {
                    black_box(compact::parse(black_box(bytes), V1).unwrap());
                }
                "compact_v2" => {
                    black_box(compact::parse(black_box(bytes), V2).unwrap());
                }
                "fast" => {
                    black_box(fast::parse(black_box(bytes)).unwrap());
                }
                "simple_v1" => {
                    black_box(simple::parse(black_box(bytes), &d.schema, V1).unwrap());
                }
                "simple_v2" => {
                    black_box(simple::parse(black_box(bytes), &d.schema, V2).unwrap());
                }
                _ => {
                    black_box(simple_json::parse_with_schema(black_box(bytes), &d.schema).unwrap());
                }
            });
        });
    }
    g.finish();
}

fn serialize_group(c: &mut Criterion, name: &str, d: &Dataset) {
    let mut g = c.benchmark_group(name);
    g.throughput(Throughput::Bytes(d.compact_v2.len() as u64));
    g.bench_function("compact_v2", |b| {
        b.iter(|| black_box(compact::write(black_box(&d.value), V2).unwrap()))
    });
    g.throughput(Throughput::Bytes(d.fast.len() as u64));
    g.bench_function("fast", |b| {
        b.iter(|| black_box(fast::write(black_box(&d.value)).unwrap()))
    });
    g.throughput(Throughput::Bytes(d.simple_v2.len() as u64));
    g.bench_function("simple_v2", |b| {
        b.iter(|| black_box(simple::write(black_box(&d.value), &d.schema, V2).unwrap()))
    });
    g.throughput(Throughput::Bytes(d.json.len() as u64));
    g.bench_function("simple_json", |b| {
        b.iter(|| black_box(simple_json::write(black_box(&d.value), false).unwrap()))
    });
    g.finish();
}

fn bench_parsing(c: &mut Criterion) {
    // Small record: exercises field-header and scalar decode overhead.
    let (schema, value) = Generator::new(1).generate();
    let small = Dataset::build(schema, value);
    parse_group(c, "parse/small", &small);
    serialize_group(c, "serialize/small", &small);

    // Large batch: ~50k records, exercises throughput-bound paths.
    let (schema, value) = Generator::new(2).generate_large(50_000);
    let large = Dataset::build(schema, value);
    parse_group(c, "parse/large", &large);
    serialize_group(c, "serialize/large", &large);
    traverse_group(c, "validate/large", &large);
}

/// Zero-allocation traversal: reads and bounds-checks every byte but builds no
/// DOM — the high-volume ingestion / integrity-check path.
fn traverse_group(c: &mut Criterion, name: &str, d: &Dataset) {
    let mut g = c.benchmark_group(name);
    g.throughput(Throughput::Bytes(d.compact_v2.len() as u64));
    g.bench_function("compact_v2", |b| {
        b.iter(|| compact::validate(black_box(&d.compact_v2), V2).unwrap())
    });
    g.throughput(Throughput::Bytes(d.fast.len() as u64));
    g.bench_function("fast", |b| {
        b.iter(|| fast::validate(black_box(&d.fast)).unwrap())
    });
    g.finish();
}

fn bench_varint(c: &mut Criterion) {
    // A dense run of multi-byte varints, the case the SIMD terminator search
    // accelerates.
    let mut buf = Vec::new();
    for i in 0..10_000u64 {
        bond::varint::encode_u64(i.wrapping_mul(0x9E3779B97F4A7C15), &mut buf);
    }
    let mut g = c.benchmark_group("varint");
    g.throughput(Throughput::Bytes(buf.len() as u64));
    g.bench_function("decode_run", |b| {
        b.iter(|| {
            let mut slice = black_box(buf.as_slice());
            let mut sum = 0u64;
            while !slice.is_empty() {
                let (v, n) = bond::varint::decode_u64(slice).unwrap();
                sum = sum.wrapping_add(v);
                slice = &slice[n..];
            }
            black_box(sum)
        })
    });
    g.finish();
}

criterion_group!(benches, bench_parsing, bench_varint);
criterion_main!(benches);
