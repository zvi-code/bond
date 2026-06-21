//! Zero-copy byte cursor with bounds-checked primitive reads.
//!
//! Every read validates bounds and returns [`Error::UnexpectedEof`] on
//! underflow, so no malformed input can cause a panic. Fixed-width integers
//! are read little-endian via `from_le_bytes`, which the compiler lowers to a
//! single load on little-endian targets. String validation uses the
//! SIMD-accelerated `simdutf8` crate.

use crate::error::{Error, Result};
use crate::varint;

/// A cursor over an immutable byte slice.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Creates a reader over `buf`, positioned at the start.
    #[inline]
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// The current byte offset.
    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Number of bytes not yet consumed.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// True if all input has been consumed.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// The not-yet-consumed tail of the buffer.
    #[inline]
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    #[inline]
    fn ensure(&self, n: usize) -> Result<()> {
        if self.remaining() < n {
            Err(Error::eof(n, self.remaining()))
        } else {
            Ok(())
        }
    }

    /// Reads a single byte.
    #[inline]
    pub fn read_u8(&mut self) -> Result<u8> {
        self.ensure(1)?;
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Returns the next byte without consuming it.
    #[inline]
    pub fn peek_u8(&self) -> Result<u8> {
        self.ensure(1)?;
        Ok(self.buf[self.pos])
    }

    /// Reads `n` bytes as a zero-copy slice.
    #[inline]
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.ensure(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Advances the cursor by `n` bytes without returning them.
    #[inline]
    pub fn skip_bytes(&mut self, n: usize) -> Result<()> {
        self.ensure(n)?;
        self.pos += n;
        Ok(())
    }

    /// Reads a `bool` (any non-zero byte is `true`).
    #[inline]
    pub fn read_bool(&mut self) -> Result<bool> {
        Ok(self.read_u8()? != 0)
    }

    /// Reads a signed byte.
    #[inline]
    pub fn read_i8(&mut self) -> Result<i8> {
        Ok(self.read_u8()? as i8)
    }
}

/// Generates fixed-width little-endian readers.
macro_rules! read_fixed {
    ($name:ident, $ty:ty) => {
        impl<'a> Reader<'a> {
            /// Reads a fixed-width little-endian value.
            #[inline]
            pub fn $name(&mut self) -> Result<$ty> {
                const N: usize = core::mem::size_of::<$ty>();
                self.ensure(N)?;
                let mut bytes = [0u8; N];
                bytes.copy_from_slice(&self.buf[self.pos..self.pos + N]);
                self.pos += N;
                Ok(<$ty>::from_le_bytes(bytes))
            }
        }
    };
}

read_fixed!(read_le_u16, u16);
read_fixed!(read_le_u32, u32);
read_fixed!(read_le_u64, u64);
read_fixed!(read_le_i16, i16);
read_fixed!(read_le_i32, i32);
read_fixed!(read_le_i64, i64);
read_fixed!(read_le_f32, f32);
read_fixed!(read_le_f64, f64);

impl<'a> Reader<'a> {
    /// Reads a LEB128 `u64`.
    #[inline]
    pub fn read_varint_u64(&mut self) -> Result<u64> {
        let (v, n) = varint::decode_u64(self.rest())?;
        self.pos += n;
        Ok(v)
    }

    /// Reads a LEB128 `u32`.
    #[inline]
    pub fn read_varint_u32(&mut self) -> Result<u32> {
        let (v, n) = varint::decode_u32(self.rest())?;
        self.pos += n;
        Ok(v)
    }

    /// Reads a LEB128 `u16`.
    #[inline]
    pub fn read_varint_u16(&mut self) -> Result<u16> {
        let (v, n) = varint::decode_u16(self.rest())?;
        self.pos += n;
        Ok(v)
    }

    /// Reads a zig-zag LEB128 `i64`.
    #[inline]
    pub fn read_zigzag_i64(&mut self) -> Result<i64> {
        Ok(varint::zigzag_decode_i64(self.read_varint_u64()?))
    }

    /// Reads a zig-zag LEB128 `i32`.
    #[inline]
    pub fn read_zigzag_i32(&mut self) -> Result<i32> {
        Ok(varint::zigzag_decode_i32(self.read_varint_u32()?))
    }

    /// Reads a zig-zag LEB128 `i16`.
    #[inline]
    pub fn read_zigzag_i16(&mut self) -> Result<i16> {
        Ok(varint::zigzag_decode_i16(self.read_varint_u16()?))
    }

    /// Reads `len` bytes and validates them as UTF-8 (SIMD-accelerated),
    /// returning a borrowed `&str`.
    #[inline]
    pub fn read_utf8(&mut self, len: usize) -> Result<&'a str> {
        let bytes = self.read_bytes(len)?;
        simdutf8::basic::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)
    }

    /// Reads `len` UTF-16LE code units (`2 * len` bytes) and decodes them to a
    /// `String`.
    #[inline]
    pub fn read_utf16(&mut self, code_units: usize) -> Result<String> {
        let byte_len = code_units
            .checked_mul(2)
            .ok_or(Error::LengthOutOfBounds {
                declared: code_units,
                available: self.remaining(),
            })?;
        let bytes = self.read_bytes(byte_len)?;
        let iter = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]));
        char::decode_utf16(iter)
            .collect::<core::result::Result<String, _>>()
            .map_err(|_| Error::InvalidUtf16)
    }
}
