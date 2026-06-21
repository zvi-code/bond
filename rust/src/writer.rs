//! Append-only output buffer with primitive writes, the mirror of [`Reader`].
//!
//! [`Reader`]: crate::reader::Reader

use crate::varint;

/// A growable byte buffer for serializing Bond payloads.
#[derive(Default, Clone, Debug)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Creates an empty writer.
    #[inline]
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    /// Creates a writer with pre-allocated capacity.
    #[inline]
    pub fn with_capacity(cap: usize) -> Self {
        Writer {
            buf: Vec::with_capacity(cap),
        }
    }

    /// Consumes the writer, returning the serialized bytes.
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Borrows the bytes written so far.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Current length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// True if nothing has been written.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Writes a single byte.
    #[inline]
    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Writes a signed byte.
    #[inline]
    pub fn write_i8(&mut self, v: i8) {
        self.buf.push(v as u8);
    }

    /// Writes a `bool` as `0x01`/`0x00`.
    #[inline]
    pub fn write_bool(&mut self, v: bool) {
        self.buf.push(v as u8);
    }

    /// Appends a raw byte slice.
    #[inline]
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Writes a LEB128 `u64`.
    #[inline]
    pub fn write_varint_u64(&mut self, v: u64) {
        varint::encode_u64(v, &mut self.buf);
    }

    /// Writes a LEB128 `u32`.
    #[inline]
    pub fn write_varint_u32(&mut self, v: u32) {
        varint::encode_u32(v, &mut self.buf);
    }

    /// Writes a LEB128 `u16`.
    #[inline]
    pub fn write_varint_u16(&mut self, v: u16) {
        varint::encode_u16(v, &mut self.buf);
    }

    /// Writes a zig-zag LEB128 `i64`.
    #[inline]
    pub fn write_zigzag_i64(&mut self, v: i64) {
        self.write_varint_u64(varint::zigzag_encode_i64(v));
    }

    /// Writes a zig-zag LEB128 `i32`.
    #[inline]
    pub fn write_zigzag_i32(&mut self, v: i32) {
        self.write_varint_u32(varint::zigzag_encode_i32(v));
    }

    /// Writes a zig-zag LEB128 `i16`.
    #[inline]
    pub fn write_zigzag_i16(&mut self, v: i16) {
        self.write_varint_u16(varint::zigzag_encode_i16(v));
    }

    /// Reserves space for at least `additional` more bytes.
    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        self.buf.reserve(additional);
    }

    /// Overwrites bytes starting at `offset` (used for back-patching lengths).
    #[inline]
    pub fn patch(&mut self, offset: usize, bytes: &[u8]) {
        self.buf[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
}

/// Generates fixed-width little-endian writers.
macro_rules! write_fixed {
    ($name:ident, $ty:ty) => {
        impl Writer {
            /// Writes a fixed-width little-endian value.
            #[inline]
            pub fn $name(&mut self, v: $ty) {
                self.buf.extend_from_slice(&v.to_le_bytes());
            }
        }
    };
}

write_fixed!(write_le_u16, u16);
write_fixed!(write_le_u32, u32);
write_fixed!(write_le_u64, u64);
write_fixed!(write_le_i16, i16);
write_fixed!(write_le_i32, i32);
write_fixed!(write_le_i64, i64);
write_fixed!(write_le_f32, f32);
write_fixed!(write_le_f64, f64);

impl Writer {
    /// Writes UTF-16LE code units for `s`, returning how many code units were
    /// written (which may exceed `s.chars().count()` for astral characters).
    #[inline]
    pub fn write_utf16(&mut self, s: &str) -> usize {
        let mut units = 0;
        for u in s.encode_utf16() {
            self.write_le_u16(u);
            units += 1;
        }
        units
    }
}
