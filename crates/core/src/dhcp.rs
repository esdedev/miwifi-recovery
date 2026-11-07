//! Minimal DHCP/BOOTP server: enough for a router bootloader in recovery mode.

use std::collections::HashMap;
use std::net::Ipv4Addr;

pub const MAGIC: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
pub const DISCOVER: u8 = 1;
pub const OFFER: u8 = 2;
pub const REQUEST: u8 = 3;
pub const ACK: u8 = 5;

#[derive(Debug, Clone)]
pub struct Request {
    pub htype: u8,
    pub hlen: u8,
    pub xid: [u8; 4],
    pub giaddr: [u8; 4],
    pub chaddr: [u8; 16],
    /// `None` for plain BOOTP (no option 53).
    pub msg_type: Option<u8>,
    pub vendor_class: Option<String>,
}

impl Request {
    pub fn mac(&self) -> &[u8] {
        let n = match self.hlen {
            1..=16 => self.hlen as usize,
            _ => 6,
        };
        &self.chaddr[..n]
    }
}

pub fn mac_string(mac: &[u8]) -> String {
    mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

pub fn msg_name(t: Option<u8>) -> &'static str {
    match t {
        None => "BOOTP",
        Some(1) => "DISCOVER",
        Some(2) => "OFFER",
        Some(3) => "REQUEST",
        Some(4) => "DECLINE",
        Some(5) => "ACK",
        Some(6) => "NAK",
        Some(7) => "RELEASE",
        Some(8) => "INFORM",
        Some(_) => "UNKNOWN",
    }
}

/// Parse a client → server BOOTP/DHCP packet.
pub fn parse(data: &[u8]) -> Option<Request> {
    if data.len() < 240 || data[0] != 1 || data[236..240] != MAGIC {
        return None;
    }
    let mut req = Request {
        htype: data[1],
        hlen: data[2],
        xid: data[4..8].try_into().ok()?,
        giaddr: data[24..28].try_into().ok()?,
        chaddr: data[28..44].try_into().ok()?,
        msg_type: None,
        vendor_class: None,
    };
    let mut i = 240;
    while i < data.len() {
        let code = data[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let Some(&len) = data.get(i + 1) else { break };
        let val = data.get(i + 2..i + 2 + len as usize)?;
        match code {
            53 if len >= 1 => req.msg_type = Some(val[0]),
            60 => req.vendor_class = Some(String::from_utf8_lossy(val).into_owned()),
            _ => {}
        }
        i += 2 + len as usize;
    }
    Some(req)
}

pub struct ReplyParams<'a> {
    pub msg_type: Option<u8>,
    pub yiaddr: Ipv4Addr,
    pub server: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub bootfile: &'a str,
    pub lease_secs: u32,
}

pub fn build_reply(req: &Request, p: &ReplyParams) -> Vec<u8> {
    let mut b = Vec::with_capacity(320);
    b.extend_from_slice(&[2, req.htype, req.hlen, 0]);
    b.extend_from_slice(&req.xid);
    b.extend_from_slice(&[0, 0, 0x80, 0]); // secs, flags = broadcast
    b.extend_from_slice(&[0; 4]); // ciaddr
    b.extend_from_slice(&p.yiaddr.octets());
    b.extend_from_slice(&p.server.octets()); // siaddr = TFTP next server
    b.extend_from_slice(&req.giaddr);
    b.extend_from_slice(&req.chaddr);
    let mut sname = [0u8; 64];
    let s = p.server.to_string();
    sname[..s.len()].copy_from_slice(s.as_bytes());
    b.extend_from_slice(&sname);
    let mut file = [0u8; 128];
    let f = p.bootfile.as_bytes();
    let n = f.len().min(127);
    file[..n].copy_from_slice(&f[..n]);
    b.extend_from_slice(&file);
    b.extend_from_slice(&MAGIC);

    let mut opt = |code: u8, val: &[u8]| {
        b.push(code);
        b.push(val.len() as u8);
        b.extend_from_slice(val);
    };
    if let Some(t) = p.msg_type {
        opt(53, &[t]);
        opt(54, &p.server.octets());
        opt(51, &p.lease_secs.to_be_bytes());
    }
    opt(1, &p.netmask.octets());
    opt(3, &p.server.octets());
    opt(66, s.as_bytes());
    opt(67, &f[..f.len().min(255)]);
    b.push(255);
    if b.len() < 300 {
        b.resize(300, 0); // BOOTP minimum size
    }
    b
}

/// Hands out consecutive addresses, one per MAC.
pub struct Pool {
    next: u32,
    server: Ipv4Addr,
    leases: HashMap<Vec<u8>, Ipv4Addr>,
}

impl Pool {
    pub fn new(start: Ipv4Addr, server: Ipv4Addr) -> Self {
        Pool { next: u32::from(start), server, leases: HashMap::new() }
    }

    pub fn lease_for(&mut self, mac: &[u8]) -> Ipv4Addr {
        if let Some(ip) = self.leases.get(mac) {
            return *ip;
        }
        let mut ip = Ipv4Addr::from(self.next);
        if ip == self.server {
            self.next += 1;
            ip = Ipv4Addr::from(self.next);
        }
        self.next += 1;
        self.leases.insert(mac.to_vec(), ip);
        ip
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn discover(mac: [u8; 6], vendor: &str) -> Vec<u8> {
        let mut p = vec![0u8; 240];
        p[0] = 1;
        p[1] = 1;
        p[2] = 6;
        p[4..8].copy_from_slice(&[1, 2, 3, 4]);
        p[28..34].copy_from_slice(&mac);
        p[236..240].copy_from_slice(&MAGIC);
        p.extend_from_slice(&[53, 1, DISCOVER]);
        p.push(60);
        p.push(vendor.len() as u8);
        p.extend_from_slice(vendor.as_bytes());
        p.push(255);
        p
    }

    #[test]
    fn roundtrip() {
        let req = parse(&discover([0x04, 0x67, 0x61, 1, 2, 3], "MSFT 5.0")).unwrap();
        assert_eq!(req.msg_type, Some(DISCOVER));
        assert_eq!(req.vendor_class.as_deref(), Some("MSFT 5.0"));
        assert_eq!(mac_string(req.mac()), "04:67:61:01:02:03");
        let server = Ipv4Addr::new(192, 168, 31, 100);
        let r = build_reply(
            &req,
            &ReplyParams {
                msg_type: Some(OFFER),
                yiaddr: Ipv4Addr::new(192, 168, 31, 101),
                server,
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                bootfile: "x.bin",
                lease_secs: 3600,
            },
        );
        assert_eq!(r[0], 2);
        assert_eq!(&r[4..8], &[1, 2, 3, 4]);
        assert_eq!(&r[16..20], &[192, 168, 31, 101]);
        assert_eq!(&r[20..24], &[192, 168, 31, 100]);
        assert_eq!(&r[108..113], b"x.bin");
        assert_eq!(&r[240..243], &[53, 1, OFFER]);
        assert!(r.len() >= 300);
    }

    #[test]
    fn pool_skips_server_and_is_sticky() {
        let s = Ipv4Addr::new(192, 168, 31, 100);
        let mut p = Pool::new(Ipv4Addr::new(192, 168, 31, 99), s);
        assert_eq!(p.lease_for(b"a"), Ipv4Addr::new(192, 168, 31, 99));
        assert_eq!(p.lease_for(b"b"), Ipv4Addr::new(192, 168, 31, 101));
        assert_eq!(p.lease_for(b"a"), Ipv4Addr::new(192, 168, 31, 99));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(&[0u8; 100]).is_none());
        let mut d = discover([0; 6], "");
        d[0] = 2; // a reply, not a request
        assert!(parse(&d).is_none());
    }
}
