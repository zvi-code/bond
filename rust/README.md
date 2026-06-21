# bond (Rust)

A complete, high-performance Rust parser and writer for the
[Microsoft Bond](https://github.com/microsoft/bond) serialization format.

It parses **any valid Bond payload** across every protocol and version, returns
a structured **error for any broken payload** (never panics), and is built for
**massive data ingestion** — small records and multi-gigabyte batches alike —
with SIMD-accelerated hot paths.

## Protocol & type coverage

| Protocol         | Versions | Tagged | Schema needed | Read | Write |
|------------------|----------|--------|---------------|------|-------|
| Compact Binary   | v1, v2   | yes    | no            | ✅   | ✅    |
| Fast Binary      | v1       | yes    | no            | ✅   | ✅    |
| Simple Binary    | v1, v2   | no     | yes           | ✅   | ✅    |
| Simple JSON      | v1       | text   | for exact types | ✅ | ✅    |
| Marshaling header (auto protocol detection) | — | — | — | ✅ | ✅ |

All Bond data types are supported: `bool`, every sized signed/unsigned integer,
`float`, `double`, `string` (UTF-8), `wstring` (UTF-16), `struct` (with
inheritance), `list`/`vector`, `set`, `map`, `nullable`, `blob`, `bonded<T>`,
and enums (carried as `int32`).

## Design

* **One primitive layer.** A single bounds-checked [`Reader`]/[`Writer`] pair
  and a single varint/zig-zag module are reused by every protocol.
* **Shared structural logic.** Both tagged protocols (Compact, Fast) implement
  only their leaf encodings via the `TaggedReader` trait; the DOM builder, the
  field-skipper and the validator are written once and shared.
* **No panics on bad input.** Every read is bounds-checked; malformed data
  yields an `Error`. Recursion is depth-limited to defuse nesting bombs.
* **SIMD where it pays.** UTF-8 validation uses `simdutf8`
  (AVX2/SSE4.2/NEON); LEB128 varint terminator search uses NEON (aarch64) and
  SSE2 (x86_64) intrinsics, each with a scalar fallback verified against the
  scalar path in tests.

## Usage

```rust
use bond::{compact, simple, Struct, Value, V2};

// Build a value and round-trip it through Compact Binary v2 (no schema needed).
let s = Struct::new()
    .with_field(0, Value::Int32(-42))
    .with_field(1, Value::Str("hello".into()));

let bytes = compact::write(&s, V2)?;
let parsed = compact::parse(&bytes, V2)?;
assert_eq!(parsed, s);
# Ok::<(), bond::Error>(())
```

Auto-detect a marshaled payload:

```rust
let out = bond::unmarshal(&bytes)?;          // tagged protocols
println!("{:?} v{}", out.protocol, out.version);
```

Schema-driven protocols (Simple Binary / typed Simple JSON):

```rust
let bytes = simple::write(&value, &schema, V2)?;
let parsed = simple::parse(&bytes, &schema, V2)?;
```

Zero-allocation validation / ingestion (fastest path — reads and bounds-checks
every byte without building a DOM):

```rust
bond::compact::validate(&bytes, V2)?;   // Ok(()) iff well-formed
```

## Data generation

`bond::gen::Generator` produces matching `(SchemaDef, Struct)` pairs
deterministically from a seed, covering every type — used by the test and
benchmark suites:

```rust
let (schema, value) = bond::gen::Generator::new(42).generate();
let (schema, big)   = bond::gen::Generator::new(7).generate_large(50_000);
```

## Benchmarks

```
cargo bench
```

Criterion benchmarks cover parse, serialize and validate across all protocols
for both small records and large (50k-record) batches, plus the varint
primitive. Indicative throughput on Apple M-series (aarch64/NEON):

| Workload (large batch)        | Throughput      |
|-------------------------------|-----------------|
| `validate` Fast Binary        | ~520 MiB/s      |
| `validate` Compact Binary v2  | ~405 MiB/s      |
| `parse` (full DOM) Fast       | ~245 MiB/s      |
| `parse` (full DOM) Compact v2 | ~190 MiB/s      |
| `parse` Simple JSON           | ~95 MiB/s       |
| varint decode (dense run)     | ~1.7 GiB/s      |

## Tests

```
cargo test
```

Covers: random round-trips across all protocols over hundreds of seeds;
hand-computed wire-format vectors pinning the exact byte layout; broken-input
rejection (truncation, unknown types, varint overflow, oversized lengths,
invalid UTF-8, nesting bombs); SIMD-vs-scalar equivalence; inheritance; and
`bonded<T>`.
