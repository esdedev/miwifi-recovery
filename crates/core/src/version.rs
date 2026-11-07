//! Firmware version rules of the Xiaomi bootloader (anti-rollback).
//!
//! Reverse-engineered from the RD15 (BE3600 2.5G) U-Boot:
//! * each dot-separated part is read with `strtoul` and truncated to 8 bits;
//!   `code = (code << 8) + part`;
//! * a result below 0x10000 (major version 0, or fewer than 3 parts) counts as 0;
//! * recovery accepts the new image only if `installed <= new`;
//! * if the installed version cannot be read (empty or damaged system), it counts as 0,
//!   so any version is accepted.

/// Version code as the bootloader computes it.
pub fn rom_code(s: &str) -> u32 {
    let mut v: u32 = 0;
    for part in s.trim().split('.') {
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        let n: u64 = digits.parse().unwrap_or(0);
        v = v.wrapping_shl(8).wrapping_add((n & 0xff) as u32);
    }
    if v < 0x10000 {
        0
    } else {
        v
    }
}

/// The bootloader's rule: same or newer only.
pub fn rollback_allowed(installed_code: u32, new_code: u32) -> bool {
    installed_code <= new_code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes() {
        assert_eq!(rom_code("1.0.87"), 0x010057);
        assert_eq!(rom_code("1.0.68"), 0x010044);
        assert_eq!(rom_code(" 1.0.115 "), 0x010073);
        assert_eq!(rom_code("0.9.1"), 0);
        assert_eq!(rom_code("1.2"), 0);
        assert_eq!(rom_code(""), 0);
        assert_eq!(rom_code("1.0.256"), 0x010000); // truncated to 8 bits, like the bootloader
    }

    #[test]
    fn rule() {
        assert!(rollback_allowed(rom_code("1.0.68"), rom_code("1.0.87")));
        assert!(rollback_allowed(rom_code("1.0.87"), rom_code("1.0.87")));
        assert!(!rollback_allowed(rom_code("1.0.87"), rom_code("1.0.68")));
        assert!(rollback_allowed(0, rom_code("1.0.68")));
    }
}
