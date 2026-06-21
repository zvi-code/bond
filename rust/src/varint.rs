//! Variable-length integer (LEB128) and zig-zag codecs.
//!
//! Bond encodes `uint16`/`uint32`/`uint64` as LEB128 varints, and
//! `int16`/`int32`/`int64` as zig-zag-then-LEB128. The hot path here is the
//! single-byte varint (by far the most common on the wire), which is handled
//! with a branch-light scalar fast path. Locating the terminator of a
//! multi-byte varint is accelerated with SIMD (NEON on aarch64, SSE2 on
//! x86_64) via [`first_terminator`], with a scalar fallback everywhere else.

use crate::error::{Error, Result};

/// Maximum number of bytes in a LEB128-encoded `u64`.
pub const MAX_VARINT_LEN_U64: usize = 10;

/// Decodes a LEB128 `u64` from the front of `buf`.
///
/// Returns the decoded value and the number of bytes consumed.
#[inline]
pub fn decode_u64(buf: &[u8]) -> Result<(u64, usize)> {
    // Fast path: single-byte varint (high bit clear). This is the overwhelming
    // majority of varints in real payloads (small ids, lengths, counts).
    match buf.first() {
        Some(&b) if b < 0x80 => return Ok((b as u64, 1)),
        None => return Err(Error::eof(1, 0)),
        _ => {}
    }

    // Multi-byte: find the terminator (first byte with the high bit clear).
    let term = match first_terminator(buf) {
        Some(idx) => idx,
        None => {
            // No terminator within the available bytes.
            if buf.len() >= MAX_VARINT_LEN_U64 {
                return Err(Error::VarintOverflow);
            }
            return Err(Error::eof(buf.len() + 1, buf.len()));
        }
    };

    let len = term + 1;
    if len > MAX_VARINT_LEN_U64 {
        return Err(Error::VarintOverflow);
    }

    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for &byte in &buf[..len] {
        // The 10th byte of a u64 varint may only carry a single payload bit.
        if shift >= 63 && (byte & 0x7f) > 0x01 {
            return Err(Error::VarintOverflow);
        }
        value |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
    }
    Ok((value, len))
}

/// Decodes a LEB128 `u32`, rejecting values that do not fit.
#[inline]
pub fn decode_u32(buf: &[u8]) -> Result<(u32, usize)> {
    let (v, n) = decode_u64(buf)?;
    if v > u32::MAX as u64 {
        return Err(Error::VarintOverflow);
    }
    Ok((v as u32, n))
}

/// Decodes a LEB128 `u16`, rejecting values that do not fit.
#[inline]
pub fn decode_u16(buf: &[u8]) -> Result<(u16, usize)> {
    let (v, n) = decode_u64(buf)?;
    if v > u16::MAX as u64 {
        return Err(Error::VarintOverflow);
    }
    Ok((v as u16, n))
}

/// Number of bytes the LEB128 encoding of `value` occupies.
#[inline]
pub fn encoded_len_u64(value: u64) -> usize {
    // ceil(bits / 7), with a minimum of one byte (for value 0).
    let bits = 64 - value.leading_zeros() as usize;
    ((bits + 6) / 7).max(1)
}

/// Appends the LEB128 encoding of `value` to `out`.
#[inline]
pub fn encode_u64(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            out.push(byte | 0x80);
        } else {
            out.push(byte);
            break;
        }
    }
}

/// Appends the LEB128 encoding of a `u32`.
#[inline]
pub fn encode_u32(value: u32, out: &mut Vec<u8>) {
    encode_u64(value as u64, out);
}

/// Appends the LEB128 encoding of a `u16`.
#[inline]
pub fn encode_u16(value: u16, out: &mut Vec<u8>) {
    encode_u64(value as u64, out);
}

// ---------------------------------------------------------------------------
// Zig-zag
// ---------------------------------------------------------------------------

/// Zig-zag encodes a signed 64-bit integer to unsigned.
#[inline]
pub const fn zigzag_encode_i64(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

/// Zig-zag decodes an unsigned 64-bit integer to signed.
#[inline]
pub const fn zigzag_decode_i64(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

/// Zig-zag encodes a signed 32-bit integer.
#[inline]
pub const fn zigzag_encode_i32(v: i32) -> u32 {
    ((v << 1) ^ (v >> 31)) as u32
}

/// Zig-zag decodes to a signed 32-bit integer.
#[inline]
pub const fn zigzag_decode_i32(v: u32) -> i32 {
    ((v >> 1) as i32) ^ -((v & 1) as i32)
}

/// Zig-zag encodes a signed 16-bit integer.
#[inline]
pub const fn zigzag_encode_i16(v: i16) -> u16 {
    ((v << 1) ^ (v >> 15)) as u16
}

/// Zig-zag decodes to a signed 16-bit integer.
#[inline]
pub const fn zigzag_decode_i16(v: u16) -> i16 {
    ((v >> 1) as i16) ^ -((v & 1) as i16)
}

// ---------------------------------------------------------------------------
// SIMD terminator search
// ---------------------------------------------------------------------------

/// Returns the index of the first byte in `buf` whose high bit is clear (the
/// terminating byte of a LEB128 varint), searching at most the first 16 bytes.
///
/// Uses NEON on aarch64 and SSE2 on x86_64 when at least 16 bytes are
/// available; otherwise falls back to a scalar scan. The result is identical
/// to the scalar implementation by construction (verified in tests).
#[inline]
pub fn first_terminator(buf: &[u8]) -> Option<usize> {
    if buf.len() >= 16 {
        // SAFETY: length checked to be >= 16.
        #[cfg(target_arch = "aarch64")]
        unsafe {
            return first_terminator_neon(buf);
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            return first_terminator_sse2(buf);
        }
    }
    first_terminator_scalar(buf)
}

/// Portable scalar terminator search.
#[inline]
fn first_terminator_scalar(buf: &[u8]) -> Option<usize> {
    buf.iter()
        .take(MAX_VARINT_LEN_U64)
        .position(|&b| b & 0x80 == 0)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn first_terminator_neon(buf: &[u8]) -> Option<usize> {
    use core::arch::aarch64::*;
    // SAFETY: caller guarantees at least 16 readable bytes at buf.as_ptr().
    // Load 16 bytes; a "terminator" lane is one whose high bit is clear.
    let v = unsafe { vld1q_u8(buf.as_ptr()) };
    let high = vandq_u8(v, vdupq_n_u8(0x80));
    // 0xFF in lanes where the high bit was clear (a terminator), 0x00 otherwise.
    let term = vceqq_u8(high, vdupq_n_u8(0));
    // Compress 16 lanes (0x00/0xFF) into a 64-bit mask of 4 bits per lane.
    let narrowed = vshrn_n_u16(vreinterpretq_u16_u8(term), 4);
    let mask = vget_lane_u64(vreinterpret_u64_u8(narrowed), 0);
    if mask == 0 {
        None
    } else {
        let idx = (mask.trailing_zeros() >> 2) as usize;
        if idx < MAX_VARINT_LEN_U64 {
            Some(idx)
        } else {
            None
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn first_terminator_sse2(buf: &[u8]) -> Option<usize> {
    use core::arch::x86_64::*;
    // SAFETY: caller guarantees at least 16 readable bytes at buf.as_ptr().
    let v = unsafe { _mm_loadu_si128(buf.as_ptr() as *const __m128i) };
    // movemask gathers the top bit of each byte: bit set => continuation.
    let cont = _mm_movemask_epi8(v) as u32;
    // Terminators are bytes with the top bit clear within the low 16 bits.
    let term = (!cont) & 0xffff;
    if term == 0 {
        None
    } else {
        let idx = term.trailing_zeros() as usize;
        if idx < MAX_VARINT_LEN_U64 {
            Some(idx)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_varint() {
        let cases = [
            0u64,
            1,
            127,
            128,
            300,
            16383,
            16384,
            u32::MAX as u64,
            u64::MAX,
            1 << 63,
        ];
        for &v in &cases {
            let mut buf = Vec::new();
            encode_u64(v, &mut buf);
            assert_eq!(buf.len(), encoded_len_u64(v), "len mismatch for {v}");
            let (decoded, n) = decode_u64(&buf).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(n, buf.len());
        }
    }

    #[test]
    fn zigzag_roundtrip() {
        for v in [0i64, -1, 1, -2, 2, i64::MIN, i64::MAX, -1234567, 7654321] {
            assert_eq!(zigzag_decode_i64(zigzag_encode_i64(v)), v);
        }
        for v in [0i32, -1, 1, i32::MIN, i32::MAX] {
            assert_eq!(zigzag_decode_i32(zigzag_encode_i32(v)), v);
        }
        for v in [0i16, -1, 1, i16::MIN, i16::MAX] {
            assert_eq!(zigzag_decode_i16(zigzag_encode_i16(v)), v);
        }
    }

    #[test]
    fn simd_matches_scalar() {
        // Exhaustively place a terminator at each position within a 32-byte
        // buffer and confirm SIMD agrees with the scalar reference.
        for term_pos in 0..32usize {
            let mut buf = vec![0x80u8; 32];
            buf[term_pos] = 0x00; // terminator
            let simd = first_terminator(&buf);
            let scalar = first_terminator_scalar(&buf);
            assert_eq!(simd, scalar, "mismatch at term_pos={term_pos}");
        }
        // All-continuation buffer.
        let all_cont = vec![0x80u8; 32];
        assert_eq!(first_terminator(&all_cont), first_terminator_scalar(&all_cont));
    }

    #[test]
    fn overflow_detected() {
        // 11 continuation bytes -> overflow.
        let buf = vec![0x80u8; 11];
        assert_eq!(decode_u64(&buf), Err(Error::VarintOverflow));
    }

    #[test]
    fn truncated_is_eof() {
        // High-bit-set bytes with no terminator and fewer than 10 bytes.
        let buf = vec![0x80u8, 0x80, 0x80];
        assert!(matches!(decode_u64(&buf), Err(Error::UnexpectedEof { .. })));
    }
}
