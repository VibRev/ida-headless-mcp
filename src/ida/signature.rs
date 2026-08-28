//! Byte signatures: the pattern type and its output formats.
//!
//! `sdk_mutation(action: signature_bytes)` hands back the bytes at an address
//! and a mask string, and leaves the rest to the caller: decide how long the
//! pattern has to be, check whether it is unique, and render it in whatever
//! syntax the consuming tool wants. That is three jobs the database is in a
//! far better position to do — searching for a candidate pattern is exactly
//! the operation the caller cannot do without another round trip per attempt.
//!
//! This module owns the pattern and its renderings; growing a pattern until it
//! is unique needs an open database and lives in the signature handler.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

/// One byte of a signature: either an exact match or a wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureByte {
    pub value: u8,
    pub wildcard: bool,
}

/// How a signature is rendered.
///
/// The four spellings the common tools accept. `Ida` and `X64dbg` differ only
/// in the wildcard token, but both are in wide enough use to name separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SignatureFormat {
    /// `E8 ? ? ? ? 48 8B` — IDA's own "binary search" syntax.
    #[default]
    Ida,
    /// `E8 ?? ?? ?? ?? 48 8B` — x64dbg's two-character wildcard.
    X64dbg,
    /// `\xE8\x00\x00\x48 x??x` — escaped bytes plus a separate mask string.
    Mask,
    /// `0xE8, 0x00, 0x48 0b1001` — C array plus a binary mask, mask reversed
    /// so bit 0 is the first byte, which is what the C idiom expects.
    Bitmask,
}

/// A byte pattern with per-byte wildcards.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signature(Vec<SignatureByte>);

impl Signature {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, value: u8, wildcard: bool) {
        self.0.push(SignatureByte { value, wildcard });
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn bytes(&self) -> &[SignatureByte] {
        &self.0
    }

    /// The pattern as the byte scanner wants it: `None` for a wildcard.
    pub fn to_scan_pattern(&self) -> Vec<Option<u8>> {
        self.0
            .iter()
            .map(|byte| (!byte.wildcard).then_some(byte.value))
            .collect()
    }

    /// Drop trailing wildcards.
    ///
    /// A signature ending in `?` is strictly weaker than the same signature
    /// without it: the wildcard constrains nothing and only makes the pattern
    /// longer. Growth stops on an instruction boundary, so this happens
    /// whenever the last instruction ends in an operand.
    pub fn trim_trailing_wildcards(&mut self) {
        while self.0.last().is_some_and(|byte| byte.wildcard) {
            self.0.pop();
        }
    }

    /// Render in the requested syntax.
    pub fn render(&self, format: SignatureFormat) -> String {
        match format {
            SignatureFormat::Ida => self.render_spaced("?"),
            SignatureFormat::X64dbg => self.render_spaced("??"),
            SignatureFormat::Mask => self.render_mask(),
            SignatureFormat::Bitmask => self.render_bitmask(),
        }
    }

    fn render_spaced(&self, wildcard: &str) -> String {
        self.0
            .iter()
            .map(|byte| {
                if byte.wildcard {
                    wildcard.to_string()
                } else {
                    format!("{:02X}", byte.value)
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn render_mask(&self) -> String {
        let mut pattern = String::with_capacity(self.0.len() * 4);
        let mut mask = String::with_capacity(self.0.len());
        for byte in &self.0 {
            if byte.wildcard {
                pattern.push_str("\\x00");
                mask.push('?');
            } else {
                // `write!` to a String cannot fail; the result is discarded
                // rather than unwrapped.
                let _ = write!(pattern, "\\x{:02X}", byte.value);
                mask.push('x');
            }
        }
        format!("{pattern} {mask}")
    }

    fn render_bitmask(&self) -> String {
        let mut parts = Vec::with_capacity(self.0.len());
        let mut mask = String::with_capacity(self.0.len());
        for byte in &self.0 {
            if byte.wildcard {
                parts.push("0x00".to_string());
                mask.push('0');
            } else {
                parts.push(format!("0x{:02X}", byte.value));
                mask.push('1');
            }
        }
        let reversed: String = mask.chars().rev().collect();
        format!("{} 0b{reversed}", parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Signature {
        let mut sig = Signature::new();
        sig.push(0xE8, false);
        sig.push(0x11, true);
        sig.push(0x22, true);
        sig.push(0x48, false);
        sig
    }

    #[test]
    fn ida_format_uses_a_single_question_mark() {
        assert_eq!(sample().render(SignatureFormat::Ida), "E8 ? ? 48");
    }

    #[test]
    fn x64dbg_format_uses_a_double_question_mark() {
        assert_eq!(sample().render(SignatureFormat::X64dbg), "E8 ?? ?? 48");
    }

    #[test]
    fn mask_format_pairs_escaped_bytes_with_a_mask_string() {
        assert_eq!(
            sample().render(SignatureFormat::Mask),
            "\\xE8\\x00\\x00\\x48 x??x"
        );
    }

    #[test]
    fn bitmask_format_reverses_the_mask() {
        // Bytes read left to right; the mask's bit 0 is the first byte, so the
        // rendered bit string is the reverse of the byte order.
        assert_eq!(
            sample().render(SignatureFormat::Bitmask),
            "0xE8, 0x00, 0x00, 0x48 0b1001"
        );
    }

    #[test]
    fn scan_pattern_maps_wildcards_to_none() {
        assert_eq!(
            sample().to_scan_pattern(),
            vec![Some(0xE8), None, None, Some(0x48)]
        );
    }

    #[test]
    fn trailing_wildcards_are_dropped_because_they_constrain_nothing() {
        let mut sig = Signature::new();
        sig.push(0xE8, false);
        sig.push(0x11, true);
        sig.push(0x22, true);
        sig.trim_trailing_wildcards();
        assert_eq!(sig.len(), 1);
        assert_eq!(sig.render(SignatureFormat::Ida), "E8");
    }

    #[test]
    fn trimming_an_all_wildcard_signature_empties_it() {
        let mut sig = Signature::new();
        sig.push(0x11, true);
        sig.trim_trailing_wildcards();
        assert!(sig.is_empty());
    }

    #[test]
    fn interior_wildcards_survive_trimming() {
        let mut sig = sample();
        sig.trim_trailing_wildcards();
        assert_eq!(sig.render(SignatureFormat::Ida), "E8 ? ? 48");
    }
}
