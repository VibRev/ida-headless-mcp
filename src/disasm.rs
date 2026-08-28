//! Custom disassembly text generation.
//!
//! Uses IDA's generate_disasm_line to produce formatted disassembly output
//! with proper mnemonic names and operand formatting.

use idalib::{Address, IDB};

/// Generate a disassembly line at the given address.
///
/// Returns the disassembly text without color codes, or None if the address
/// is invalid or doesn't contain code.
pub fn generate_disasm_line(idb: &IDB, addr: Address) -> Option<String> {
    idb.disasm_line(addr)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_placeholder() {
        // Tests require an open IDB
    }
}
