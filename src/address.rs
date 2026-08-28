//! User-facing address token parsing.
//!
//! MCP tools, the CLI, IDA handlers, and supervisor resources all accept the
//! same hex / binary / octal / decimal tokens. One [`Address`] `FromStr`
//! implementation so those entry points cannot disagree on `0x1_000` or `0b1010`.

use crate::error::ToolError;
use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

/// A single IDA address parsed from a user-facing token.
///
/// Accepts hex (`0x` / `0X`), binary (`0b` / `0B`), octal (`0o` / `0O`), and
/// decimal. `_` separators are stripped before the prefix is inspected, so
/// `0x1_000` stays hex. Tokens without `_` are parsed without allocating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Address(u64);

impl Address {
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for Address {
    fn from(raw: u64) -> Self {
        Self(raw)
    }
}

impl From<Address> for u64 {
    fn from(addr: Address) -> u64 {
        addr.0
    }
}

impl FromStr for Address {
    type Err = ToolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let token = normalize_address_token(s);
        parse_digits(&token)
            .map(Self)
            .map_err(|_| ToolError::InvalidAddress(token.into_owned()))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Canonical form is hex; the original token (decimal / `0b` / `_`) is not preserved.
        write!(f, "{:#x}", self.0)
    }
}

/// Parse a single address token into a raw `u64`.
///
/// Prefer [`Address`] + `.parse()` at new call sites. This wrapper exists
/// because most existing surfaces already speak `u64`.
pub fn parse_address(s: &str) -> Result<u64, ToolError> {
    s.parse::<Address>().map(Address::get)
}

fn normalize_address_token(s: &str) -> Cow<'_, str> {
    let s = s.trim();
    if s.contains('_') {
        Cow::Owned(s.chars().filter(|&c| c != '_').collect())
    } else {
        Cow::Borrowed(s)
    }
}

fn parse_digits(token: &str) -> Result<u64, std::num::ParseIntError> {
    if let Some(digits) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        u64::from_str_radix(digits, 16)
    } else if let Some(digits) = token
        .strip_prefix("0b")
        .or_else(|| token.strip_prefix("0B"))
    {
        u64::from_str_radix(digits, 2)
    } else if let Some(digits) = token
        .strip_prefix("0o")
        .or_else(|| token.strip_prefix("0O"))
    {
        u64::from_str_radix(digits, 8)
    } else {
        token.parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_entry_points_agree() {
        let cases: &[(&str, u64)] = &[
            ("0x1_000", 0x1000),
            ("0b1010", 0b1010),
            ("0o777", 0o777),
            ("4096", 4096),
            ("0X1000", 0x1000),
        ];
        for &(input, expected) in cases {
            let via_from_str = input.parse::<Address>().map(Address::get).unwrap();
            let via_lib = parse_address(input).unwrap();
            let via_server = crate::server::address::parse_address(input).unwrap();
            let via_handler = crate::ida::handlers::parse_address_str(input).unwrap();
            let via_option = parse_address(input).ok();

            assert_eq!(via_from_str, expected, "{input} FromStr");
            assert_eq!(via_lib, expected, "{input} parse_address");
            assert_eq!(via_server, expected, "{input} server");
            assert_eq!(via_handler, expected, "{input} handler");
            assert_eq!(via_option, Some(expected), "{input} option");
        }
    }

    #[test]
    fn rejects_empty_and_garbage() {
        assert!(parse_address("").is_err());
        assert!(parse_address("   ").is_err());
        assert!(parse_address("0xzz").is_err());
        assert!(parse_address("0b2").is_err());
        assert!(parse_address("0o8").is_err());
    }

    #[test]
    fn display_is_hex() {
        assert_eq!(Address::new(0x1000).to_string(), "0x1000");
    }
}
