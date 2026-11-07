//! Read-only TFTP (RFC 1350) with the blksize / tsize / timeout options (RFC 2347-2349).

use std::collections::BTreeMap;

pub const RRQ: u16 = 1;
pub const WRQ: u16 = 2;
pub const DATA: u16 = 3;
pub const ACK: u16 = 4;
pub const ERROR: u16 = 5;
pub const OACK: u16 = 6;

#[derive(Debug, Clone, PartialEq)]
pub struct ReadRequest {
    pub filename: String,
    pub mode: String,
    pub options: BTreeMap<String, String>,
}

pub fn opcode(data: &[u8]) -> Option<u16> {
    data.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}

pub fn parse_rrq(data: &[u8]) -> Option<ReadRequest> {
    if data.len() < 4 || opcode(data)? != RRQ {
        return None;
    }
    let mut parts = data[2..].split(|b| *b == 0).map(|p| String::from_utf8_lossy(p).into_owned());
    let filename = parts.next()?;
    let mode = parts.next()?.to_ascii_lowercase();
    let rest: Vec<String> = parts.collect();
    let mut options = BTreeMap::new();
    for kv in rest.chunks(2) {
        if let [k, v] = kv {
            if !k.is_empty() {
                options.insert(k.to_ascii_lowercase(), v.clone());
            }
        }
    }
    Some(ReadRequest { filename, mode, options })
}

pub fn error_packet(code: u16, msg: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(5 + msg.len());
    p.extend_from_slice(&ERROR.to_be_bytes());
    p.extend_from_slice(&code.to_be_bytes());
    p.extend_from_slice(msg.as_bytes());
    p.push(0);
    p
}

pub fn data_packet(block: u16, chunk: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(4 + chunk.len());
    p.extend_from_slice(&DATA.to_be_bytes());
    p.extend_from_slice(&block.to_be_bytes());
    p.extend_from_slice(chunk);
    p
}

/// Negotiated transfer parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct Negotiated {
    pub blksize: usize,
    pub timeout_secs: u64,
    /// Options to acknowledge with an OACK (empty = no OACK, start with DATA 1).
    pub oack: Vec<(String, String)>,
}

pub fn negotiate(opts: &BTreeMap<String, String>, file_len: usize, default_timeout: u64) -> Negotiated {
    let mut n = Negotiated { blksize: 512, timeout_secs: default_timeout, oack: vec![] };
    if let Some(v) = opts.get("blksize").and_then(|v| v.parse::<usize>().ok()) {
        n.blksize = v.clamp(8, 65464);
        n.oack.push(("blksize".into(), n.blksize.to_string()));
    }
    if opts.contains_key("tsize") {
        n.oack.push(("tsize".into(), file_len.to_string()));
    }
    if let Some(v) = opts.get("timeout").and_then(|v| v.parse::<u64>().ok()) {
        if (1..=255).contains(&v) {
            n.timeout_secs = v;
            n.oack.push(("timeout".into(), v.to_string()));
        }
    }
    n
}

pub fn oack_packet(oack: &[(String, String)]) -> Vec<u8> {
    let mut p = OACK.to_be_bytes().to_vec();
    for (k, v) in oack {
        p.extend_from_slice(k.as_bytes());
        p.push(0);
        p.extend_from_slice(v.as_bytes());
        p.push(0);
    }
    p
}

/// Number of DATA packets: the last one is always shorter than blksize (possibly empty).
pub fn block_count(len: usize, blksize: usize) -> usize {
    len / blksize + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rrq_with_options() {
        let pkt = b"\x00\x01C0A81F69.img\x00octet\x00timeout\x005\x00TSIZE\x000\x00";
        let r = parse_rrq(pkt).unwrap();
        assert_eq!(r.filename, "C0A81F69.img");
        assert_eq!(r.mode, "octet");
        assert_eq!(r.options["timeout"], "5");
        let n = negotiate(&r.options, 1000, 2);
        assert_eq!(n.timeout_secs, 5);
        assert_eq!(n.blksize, 512);
        let want: Vec<(String, String)> = vec![("tsize".into(), "1000".into()), ("timeout".into(), "5".into())];
        assert_eq!(n.oack, want);
    }

    #[test]
    fn counts_and_garbage() {
        assert_eq!(block_count(1024, 512), 3); // 512, 512, 0
        assert_eq!(block_count(28836864, 512), 56323); // matches the official tool's log
        assert!(parse_rrq(b"\x00\x02a\x00octet\x00").is_none());
        assert!(parse_rrq(b"\x00").is_none());
    }
}
