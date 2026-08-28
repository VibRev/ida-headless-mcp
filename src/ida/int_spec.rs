//! Width, signedness and byte order for the integer read/write tools.
//!
//! `get_u8` / `get_u16` / `get_u32` / `get_u64` spell width in the tool name
//! and pin the other two axes: always unsigned, always the database's byte
//! order. Reading an `int32_t` field, or reading a little-endian value out of
//! a big-endian firmware image, has no answer on that surface — the caller gets
//! the raw bytes back and reassembles them itself.
//!
//! One `ty` token carries all three axes instead: `i32`, `u16be`, `i64le`.

use crate::error::ToolError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Byte order for a multi-byte integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Endian {
    Little,
    Big,
}

/// Integer width in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntWidth {
    W8,
    W16,
    W32,
    W64,
}

impl IntWidth {
    pub fn bytes(self) -> usize {
        match self {
            Self::W8 => 1,
            Self::W16 => 2,
            Self::W32 => 4,
            Self::W64 => 8,
        }
    }

    fn parse(digits: &str) -> Option<Self> {
        match digits {
            "8" => Some(Self::W8),
            "16" => Some(Self::W16),
            "32" => Some(Self::W32),
            "64" => Some(Self::W64),
            _ => None,
        }
    }
}

impl fmt::Display for IntWidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.bytes() * 8)
    }
}

/// A fully specified integer type: `i32`, `u16be`, `u64le`.
///
/// An absent byte order means "whatever the database says", which is what the
/// `get_u*` tools have always done and stays the default here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct IntSpec {
    pub signed: bool,
    pub width: IntWidth,
    pub endian: Option<Endian>,
}

impl IntSpec {
    /// Decode `bytes` into a signed or unsigned value.
    ///
    /// `db_is_big_endian` settles the byte order when the token did not.
    pub fn decode(&self, bytes: &[u8], db_is_big_endian: bool) -> Result<i128, ToolError> {
        let width = self.width.bytes();
        if bytes.len() < width {
            return Err(ToolError::IdaError(format!(
                "needed {width} bytes for {self}, read {}",
                bytes.len()
            )));
        }

        let mut buf = [0u8; 8];
        buf[..width].copy_from_slice(&bytes[..width]);
        let raw = match self.byte_order(db_is_big_endian) {
            Endian::Little => u64::from_le_bytes(buf),
            // A big-endian value occupies the *low* `width` bytes of `buf`, so
            // shift the padding out rather than reading the whole 8 bytes.
            Endian::Big => u64::from_be_bytes(buf) >> (64 - width * 8),
        };

        if !self.signed {
            return Ok(i128::from(raw));
        }

        // Sign-extend from the value's own width, not from 64 bits.
        let shift = 64 - width * 8;
        Ok(i128::from(((raw << shift) as i64) >> shift))
    }

    /// Encode `value` into exactly `width` bytes, refusing a value that does
    /// not fit — a silent truncation would write a different number than the
    /// caller asked for.
    pub fn encode(&self, value: i128, db_is_big_endian: bool) -> Result<Vec<u8>, ToolError> {
        let width = self.width.bytes();
        let bits = width * 8;
        let (min, max) = if self.signed {
            (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1)
        } else {
            (0, (1i128 << bits) - 1)
        };
        if value < min || value > max {
            return Err(ToolError::InvalidParams(format!(
                "{value} does not fit in {self} (range {min}..={max})"
            )));
        }

        let raw = (value as u64) & mask_for(bits);
        let bytes = match self.byte_order(db_is_big_endian) {
            Endian::Little => raw.to_le_bytes()[..width].to_vec(),
            Endian::Big => raw.to_be_bytes()[8 - width..].to_vec(),
        };
        Ok(bytes)
    }

    fn byte_order(&self, db_is_big_endian: bool) -> Endian {
        self.endian.unwrap_or(if db_is_big_endian {
            Endian::Big
        } else {
            Endian::Little
        })
    }
}

/// Low `bits` set; `bits` is always 8/16/32/64 here, so 64 needs the guard.
fn mask_for(bits: usize) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

impl fmt::Display for IntSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sign = if self.signed { 'i' } else { 'u' };
        write!(f, "{sign}{}", self.width)?;
        match self.endian {
            Some(Endian::Little) => f.write_str("le"),
            Some(Endian::Big) => f.write_str("be"),
            None => Ok(()),
        }
    }
}

impl FromStr for IntSpec {
    type Err = ToolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let token = s.trim().to_lowercase();
        let invalid = || {
            ToolError::InvalidParams(format!(
                "invalid integer type '{s}'; expected i8/u8/i16/u16/i32/u32/i64/u64 \
                 with an optional 'le' or 'be' suffix (e.g. 'u32be')"
            ))
        };

        let (sign, rest) = token.split_at_checked(1).ok_or_else(invalid)?;
        let signed = match sign {
            "i" => true,
            "u" => false,
            _ => return Err(invalid()),
        };

        let (digits, endian) = match rest.strip_suffix("le") {
            Some(digits) => (digits, Some(Endian::Little)),
            None => match rest.strip_suffix("be") {
                Some(digits) => (digits, Some(Endian::Big)),
                None => (rest, None),
            },
        };

        let width = IntWidth::parse(digits).ok_or_else(invalid)?;
        if width == IntWidth::W8 && endian.is_some() {
            return Err(ToolError::InvalidParams(format!(
                "'{s}' names a byte order for a single byte, which has none"
            )));
        }

        Ok(Self {
            signed,
            width,
            endian,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(s: &str) -> IntSpec {
        s.parse().expect("a valid integer type")
    }

    #[test]
    fn tokens_carry_all_three_axes() {
        assert_eq!(
            spec("i32"),
            IntSpec {
                signed: true,
                width: IntWidth::W32,
                endian: None
            }
        );
        assert_eq!(spec("u16be").endian, Some(Endian::Big));
        assert_eq!(spec("i64le").endian, Some(Endian::Little));
        assert!(!spec("U8").signed, "parsing is case-insensitive");
    }

    #[test]
    fn a_byte_order_on_one_byte_is_refused() {
        assert!("u8be".parse::<IntSpec>().is_err());
    }

    #[test]
    fn junk_tokens_are_refused() {
        for bad in ["", "x32", "i12", "i32xx", "32"] {
            assert!(bad.parse::<IntSpec>().is_err(), "{bad} must not parse");
        }
    }

    #[test]
    fn unsigned_reads_are_plain() {
        let value = spec("u32").decode(&[0x78, 0x56, 0x34, 0x12], false);
        assert_eq!(value.expect("decodes"), 0x1234_5678);
    }

    #[test]
    fn signed_reads_sign_extend_from_their_own_width() {
        // 0xFF as i8 is -1, not 255.
        assert_eq!(spec("i8").decode(&[0xFF], false).expect("decodes"), -1);
        assert_eq!(spec("u8").decode(&[0xFF], false).expect("decodes"), 255);
        // 0xFFFE as i16 is -2 even though the u64 it was widened into is not.
        assert_eq!(
            spec("i16").decode(&[0xFE, 0xFF], false).expect("decodes"),
            -2
        );
    }

    #[test]
    fn byte_order_overrides_the_database_default() {
        let bytes = [0x12, 0x34];
        assert_eq!(spec("u16le").decode(&bytes, true).expect("decodes"), 0x3412);
        assert_eq!(
            spec("u16be").decode(&bytes, false).expect("decodes"),
            0x1234
        );
    }

    #[test]
    fn an_absent_byte_order_follows_the_database() {
        let bytes = [0x12, 0x34];
        assert_eq!(spec("u16").decode(&bytes, false).expect("decodes"), 0x3412);
        assert_eq!(spec("u16").decode(&bytes, true).expect("decodes"), 0x1234);
    }

    #[test]
    fn a_short_read_is_an_error_rather_than_a_zero_pad() {
        assert!(spec("u32").decode(&[0x01, 0x02], false).is_err());
    }

    #[test]
    fn writes_round_trip_through_reads() {
        for (ty, value) in [("i8", -1i128), ("u16be", 0x1234), ("i32le", -123456)] {
            let spec = spec(ty);
            let bytes = spec.encode(value, false).expect("encodes");
            assert_eq!(bytes.len(), spec.width.bytes());
            assert_eq!(spec.decode(&bytes, false).expect("decodes"), value);
        }
    }

    #[test]
    fn a_value_that_does_not_fit_is_refused_rather_than_truncated() {
        assert!(spec("u8").encode(256, false).is_err());
        assert!(spec("i8").encode(128, false).is_err());
        assert!(spec("i8").encode(-129, false).is_err());
        assert!(spec("i8").encode(127, false).is_ok());
        assert!(spec("i8").encode(-128, false).is_ok());
    }

    #[test]
    fn the_full_unsigned_range_of_each_width_encodes() {
        assert!(spec("u64").encode(u64::MAX.into(), false).is_ok());
        assert!(spec("u32").encode(u32::MAX.into(), false).is_ok());
        assert!(spec("u64").encode(i128::from(u64::MAX) + 1, false).is_err());
    }

    #[test]
    fn display_round_trips_the_token() {
        for token in ["i8", "u8", "i16be", "u32le", "i64"] {
            assert_eq!(spec(token).to_string(), token);
        }
    }
}
