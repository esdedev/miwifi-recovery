//! Parsing and checking of Xiaomi "HDR1" firmware images.
//!
//! Layout, as checked by the RD15 (BE3600 2.5G) bootloader:
//!
//! | Offset   | Field                                                        |
//! |----------|--------------------------------------------------------------|
//! | 0x00     | magic `HDR1`                                                 |
//! | 0x04     | u32 `sigoff`: end of the signed data                         |
//! | 0x08     | u32 CRC32 of `img[0x0c..]` (init 0xffffffff, no final xor)   |
//! | 0x0c     | u16 image type / key type                                    |
//! | 0x0e     | u16 model id (0x55 = RD15)                                   |
//! | 0x10     | 32 x u32 offsets of sub-image headers (0 = unused)           |
//! | `sigoff` | u32 signature length (0x100), then the RSA signature         |
//!
//! Each sub-image header: u16 magic 0xbabe, u16 pad, u32 flash address
//! (0xffffffff = not flashed), u32 size, u32 flags, char name[32], then data at +0x30.
//! The sub-image called `xiaoqiang_version` holds UCI text such as `option ROM '1.0.87'`.
//!
//! Everything here is read-only analysis. The RSA signature cannot be checked
//! without Xiaomi's keys; the bootloader does that.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::version;

pub const MAGIC: &[u8; 4] = b"HDR1";
const SUB_MAGIC: u16 = 0xbabe;
const SUB_HDR_LEN: usize = 0x30;
/// The RD15 bootloader refuses images whose signed part is this big or bigger.
pub const MAX_SIGNED_LEN: u32 = 0x0320_0000;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SubImage {
    pub name: String,
    /// `None` when the sub-image is not written to flash (e.g. `xiaoqiang_version`).
    pub flash_addr: Option<u32>,
    pub size: u32,
}

/// A problem found in the image. `code` is a stable identifier the GUI translates.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Finding {
    pub code: &'static str,
    pub severity: Severity,
    /// English explanation, used by the CLI. The GUI uses `code` and `args`.
    pub message: String,
    pub args: BTreeMap<&'static str, String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    /// The bootloader will refuse this image.
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct FirmwareInfo {
    pub size: u64,
    pub sha256: String,
    pub is_hdr1: bool,
    pub crc_ok: Option<bool>,
    pub image_type: Option<u16>,
    pub model_id: Option<u16>,
    pub signed_len: Option<u32>,
    pub sub_images: Vec<SubImage>,
    /// `ROM`, `HARDWARE`, `CHANNEL`, `BUILDTIME`, ... from the `xiaoqiang_version` block.
    pub meta: BTreeMap<String, String>,
    /// Version code as the bootloader computes it (`None` = no ROM line).
    pub rom_code: Option<u32>,
    pub findings: Vec<Finding>,
}

impl FirmwareInfo {
    pub fn rom(&self) -> Option<&str> {
        self.meta.get("ROM").map(String::as_str)
    }
    pub fn hardware(&self) -> Option<&str> {
        self.meta.get("HARDWARE").map(String::as_str)
    }
    pub fn worst(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// CRC32 as the bootloader computes it: standard polynomial, init 0xffffffff, no final xor.
pub fn xiaomi_crc(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize() ^ 0xffff_ffff
}

/// Extract `option KEY 'value'` pairs from UCI text.
pub fn parse_uci_options(text: &[u8]) -> BTreeMap<String, String> {
    let s = String::from_utf8_lossy(text);
    let mut out = BTreeMap::new();
    for line in s.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("option ") else { continue };
        let Some((key, val)) = rest.split_once(char::is_whitespace) else { continue };
        let val = val.trim();
        let val = val
            .strip_prefix('\'')
            .and_then(|v| v.strip_suffix('\''))
            .or_else(|| val.strip_prefix('"').and_then(|v| v.strip_suffix('"')))
            .unwrap_or(val);
        out.entry(key.to_string()).or_insert_with(|| val.to_string());
    }
    out
}

fn finding(code: &'static str, severity: Severity, message: String, args: &[(&'static str, String)]) -> Finding {
    Finding { code, severity, message, args: args.iter().cloned().collect() }
}

/// Analyse an image. `expected_model` is the model code printed on the router label
/// (e.g. "RD15"); pass `None` to skip that check.
pub fn analyze(fw: &[u8], expected_model: Option<&str>) -> FirmwareInfo {
    let mut info = FirmwareInfo {
        size: fw.len() as u64,
        sha256: Sha256::digest(fw).iter().map(|b| format!("{b:02x}")).collect(),
        is_hdr1: fw.starts_with(MAGIC),
        crc_ok: None,
        image_type: None,
        model_id: None,
        signed_len: None,
        sub_images: vec![],
        meta: BTreeMap::new(),
        rom_code: None,
        findings: vec![],
    };

    if !info.is_hdr1 {
        info.findings.push(finding(
            "not_hdr1",
            Severity::Error,
            "This file is not a Xiaomi recovery image (it does not start with 'HDR1'). \
             Use the official .bin firmware for your model, not a .zip, an OpenWrt image or a backup."
                .into(),
            &[],
        ));
        // Still try to read version text from older formats.
        info.meta = parse_uci_options(&fw[..fw.len().min(0x4000)]);
    } else {
        let sigoff = u32_at(fw, 4).unwrap_or(0);
        info.signed_len = Some(sigoff);
        info.image_type = u16_at(fw, 0x0c);
        info.model_id = u16_at(fw, 0x0e);

        if let Some(stored) = u32_at(fw, 8) {
            let ok = fw.len() > 0x0c && xiaomi_crc(&fw[0x0c..]) == stored;
            info.crc_ok = Some(ok);
            if !ok {
                info.findings.push(finding(
                    "crc_mismatch",
                    Severity::Error,
                    "The checksum does not match: the file is damaged or incomplete \
                     (interrupted download?). Download it again."
                        .into(),
                    &[],
                ));
            }
        }
        if sigoff >= MAX_SIGNED_LEN {
            info.findings.push(finding(
                "too_large",
                Severity::Warning,
                format!(
                    "The image is very large ({} MiB of signed data). Some Xiaomi bootloaders \
                     (e.g. RD15) refuse anything of 50 MiB or more.",
                    sigoff / (1024 * 1024)
                ),
                &[("mib", (sigoff / (1024 * 1024)).to_string())],
            ));
        }

        for i in 0..32 {
            let Some(off) = u32_at(fw, 0x10 + 4 * i) else { break };
            if off == 0 {
                continue;
            }
            let o = off as usize;
            if u16_at(fw, o) != Some(SUB_MAGIC) {
                continue;
            }
            let addr = u32_at(fw, o + 4).unwrap_or(0);
            let size = u32_at(fw, o + 8).unwrap_or(0);
            let name_raw = fw.get(o + 0x10..o + 0x30).unwrap_or(&[]);
            let name: String = String::from_utf8_lossy(name_raw.split(|b| *b == 0).next().unwrap_or(&[])).into();
            if name == "xiaoqiang_version" {
                let start = o + SUB_HDR_LEN;
                let end = (start + size as usize).min(fw.len());
                if start < end {
                    info.meta = parse_uci_options(&fw[start..end]);
                }
            }
            info.sub_images.push(SubImage {
                name,
                flash_addr: (addr != 0xffff_ffff).then_some(addr),
                size,
            });
        }
        if info.meta.is_empty() {
            info.meta = parse_uci_options(&fw[..fw.len().min(0x4000)]);
        }
    }

    match info.rom().map(str::to_owned) {
        None => info.findings.push(finding(
            "no_rom_version",
            Severity::Error,
            "No ROM version found inside the image. The bootloader refuses such images \
             unless the installed system is unreadable."
                .into(),
            &[],
        )),
        Some(rom) => {
            let code = version::rom_code(&rom);
            info.rom_code = Some(code);
            if code == 0 {
                info.findings.push(finding(
                    "rom_version_unusable",
                    Severity::Error,
                    format!(
                        "The ROM version '{rom}' is not in the X.Y.Z form the bootloader expects; \
                         it would be treated as older than any installed version."
                    ),
                    &[("rom", rom.clone())],
                ));
            }
        }
    }

    match (expected_model.map(str::trim).filter(|m| !m.is_empty()), info.hardware()) {
        (Some(want), Some(have)) if !want.eq_ignore_ascii_case(have) => {
            let have = have.to_string();
            info.findings.push(finding(
                "model_mismatch",
                Severity::Error,
                format!(
                    "This firmware is for model {have}, but your router is {want}. \
                     The bootloader refuses it ('Mismatch trx model'). Download the firmware for {want}."
                ),
                &[("image", have), ("router", want.to_string())],
            ));
        }
        (Some(_), None) => info.findings.push(finding(
            "model_unknown",
            Severity::Warning,
            "The image does not say which model it is for. Make sure it is the firmware for your router."
                .into(),
            &[],
        )),
        _ => {}
    }

    if info.image_type == Some(0x0c) {
        info.findings.push(finding(
            "encrypted_image",
            Severity::Info,
            "This is an encrypted image type. It is decrypted by the router during recovery.".into(),
            &[],
        ));
    }
    info
}

/// Compare the image with the version installed on the router (anti-rollback).
/// `installed` is what the user says is installed now, e.g. "1.0.87".
pub fn check_rollback(info: &FirmwareInfo, installed: &str) -> Option<Finding> {
    let new = info.rom()?.to_string();
    let installed = installed.trim();
    let have = version::rom_code(installed);
    if have == 0 {
        return Some(finding(
            "installed_version_invalid",
            Severity::Warning,
            format!("'{installed}' does not look like a firmware version (expected something like 1.0.87)."),
            &[("installed", installed.to_string())],
        ));
    }
    match version::rollback_allowed(have, info.rom_code.unwrap_or(0)) {
        true if have == info.rom_code.unwrap_or(0) => Some(finding(
            "same_version",
            Severity::Info,
            format!("Same version as installed ({new}). That is allowed: it reinstalls a clean system."),
            &[("rom", new), ("installed", installed.to_string())],
        )),
        true => None,
        false => Some(finding(
            "downgrade_refused",
            Severity::Error,
            format!(
                "Version {new} is older than the installed {installed}. Xiaomi's bootloader has an \
                 anti-rollback protection: it only accepts the same or a newer version, so the router \
                 would refuse this file and stop with a steady light. Use firmware {installed} or newer."
            ),
            &[("rom", new), ("installed", installed.to_string())],
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal, structurally valid HDR1 image (fake signature).
    pub(crate) fn fake_image(rom: &str, hw: &str) -> Vec<u8> {
        let text = format!(
            "config version 'version'\n\t# ROM ver\n\toption ROM '{rom}'\n\toption HARDWARE '{hw}'\n\toption CHANNEL 'release'\n"
        );
        let mut img = vec![0u8; 0x90];
        img[..4].copy_from_slice(MAGIC);
        img[0x0e..0x10].copy_from_slice(&0x55u16.to_le_bytes());
        img[0x10..0x14].copy_from_slice(&0x90u32.to_le_bytes());
        let mut sub = vec![0u8; SUB_HDR_LEN];
        sub[..2].copy_from_slice(&SUB_MAGIC.to_le_bytes());
        sub[4..8].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        sub[8..12].copy_from_slice(&(text.len() as u32).to_le_bytes());
        sub[0x10..0x10 + 17].copy_from_slice(b"xiaoqiang_version");
        img.extend_from_slice(&sub);
        img.extend_from_slice(text.as_bytes());
        let sigoff = img.len() as u32;
        img[4..8].copy_from_slice(&sigoff.to_le_bytes());
        img.extend_from_slice(&0x100u32.to_le_bytes());
        img.extend_from_slice(&[0u8; 0x10C]);
        let crc = xiaomi_crc(&img[0x0c..]);
        img[8..12].copy_from_slice(&crc.to_le_bytes());
        img
    }

    #[test]
    fn parses_fake_image() {
        let img = fake_image("1.0.87", "RD15");
        let info = analyze(&img, Some("rd15"));
        assert!(info.is_hdr1);
        assert_eq!(info.crc_ok, Some(true));
        assert_eq!(info.rom(), Some("1.0.87"));
        assert_eq!(info.hardware(), Some("RD15"));
        assert_eq!(info.model_id, Some(0x55));
        assert_eq!(info.rom_code, Some(0x010057));
        assert_eq!(info.sub_images[0].name, "xiaoqiang_version");
        assert_eq!(info.sub_images[0].flash_addr, None);
        assert!(info.findings.is_empty(), "{:?}", info.findings);
    }

    #[test]
    fn detects_damage_model_and_format() {
        let mut img = fake_image("1.0.87", "RD15");
        let n = img.len();
        img[n - 1] ^= 1;
        let codes: Vec<_> = analyze(&img, Some("RD03")).findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&"crc_mismatch"));
        assert!(codes.contains(&"model_mismatch"));
        let info = analyze(b"\x27\x05\x19\x56 uImage", None);
        assert_eq!(info.findings[0].code, "not_hdr1");
    }

    #[test]
    fn rollback_rule() {
        let info = analyze(&fake_image("1.0.68", "RD15"), None);
        assert_eq!(check_rollback(&info, "1.0.87").unwrap().code, "downgrade_refused");
        assert_eq!(check_rollback(&info, "1.0.68").unwrap().code, "same_version");
        assert!(check_rollback(&info, "1.0.50").is_none());
        assert_eq!(check_rollback(&info, "abc").unwrap().code, "installed_version_invalid");
    }

    #[test]
    fn uci_quotes() {
        let m = parse_uci_options(b"\toption ROM '1.0.87'\n\toption X \"y z\"\n\toption Y bare\n");
        assert_eq!(m["ROM"], "1.0.87");
        assert_eq!(m["X"], "y z");
        assert_eq!(m["Y"], "bare");
    }

    /// Runs against real images when MIWIFI_TEST_FIRMWARE=path1;path2 is set.
    #[test]
    fn real_images_if_available() {
        let Ok(paths) = std::env::var("MIWIFI_TEST_FIRMWARE") else { return };
        for p in paths.split(';').filter(|p| !p.is_empty()) {
            let img = std::fs::read(p).unwrap();
            let info = analyze(&img, Some("RD15"));
            assert_eq!(info.crc_ok, Some(true), "{p}");
            assert!(info.findings.is_empty(), "{p}: {:?}", info.findings);
            assert!(info.sub_images.iter().any(|s| s.name == "root.ubi"), "{p}");
        }
    }
}
