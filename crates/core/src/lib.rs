//! Open-source recovery server for Xiaomi routers.
//!
//! In recovery mode (reset button held at power-on) the Xiaomi bootloader asks for an
//! address over DHCP and downloads a signed firmware image over TFTP from 192.168.31.100.
//! This crate provides that server plus offline checks of the image, so a user can see
//! *before* flashing whether the router will accept it.

pub mod dhcp;
pub mod firmware;
pub mod server;
pub mod tftp;
pub mod version;

pub use firmware::{analyze, check_rollback, Finding, FirmwareInfo, Severity};
pub use server::{Config, Event, Server, Sink, ROUTER_IP, SERVER_IP};

#[cfg(test)]
mod integration {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    fn local_cfg() -> Config {
        Config {
            bind_ip: Ipv4Addr::LOCALHOST,
            server_ip: Ipv4Addr::LOCALHOST,
            dhcp: false,
            tftp_port: 0,
            tftp_timeout_secs: 1,
            ..Config::default()
        }
    }

    /// A tiny TFTP client, standing in for the router bootloader.
    fn fetch(server: SocketAddr, name: &str, opts: &[(&str, &str)]) -> Vec<u8> {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut rrq = vec![0, 1];
        rrq.extend_from_slice(name.as_bytes());
        rrq.extend_from_slice(b"\0octet\0");
        for (k, v) in opts {
            rrq.extend_from_slice(k.as_bytes());
            rrq.push(0);
            rrq.extend_from_slice(v.as_bytes());
            rrq.push(0);
        }
        s.send_to(&rrq, server).unwrap();
        let mut out = vec![];
        let mut buf = vec![0u8; 70000];
        let mut blksize = 512;
        loop {
            let (n, from) = s.recv_from(&mut buf).unwrap();
            let op = u16::from_be_bytes([buf[0], buf[1]]);
            if op == tftp::OACK {
                let parts: Vec<&[u8]> = buf[2..n].split(|b| *b == 0).collect();
                for kv in parts.chunks(2) {
                    if kv.len() == 2 && kv[0] == b"blksize" {
                        blksize = std::str::from_utf8(kv[1]).unwrap().parse().unwrap();
                    }
                }
                s.send_to(&[0, 4, 0, 0], from).unwrap();
                continue;
            }
            assert_eq!(op, tftp::DATA);
            out.extend_from_slice(&buf[4..n]);
            s.send_to(&[0, 4, buf[2], buf[3]], from).unwrap();
            if n - 4 < blksize {
                return out;
            }
        }
    }

    #[test]
    fn serves_any_filename_with_and_without_options() {
        let fw: Vec<u8> = (0..5000u32).map(|i| (i * 7) as u8).collect();
        let events = Arc::new(Mutex::new(vec![]));
        let ev = events.clone();
        let srv = Server::start(local_cfg(), Arc::new(fw.clone()), Arc::new(move |e| ev.lock().unwrap().push(e))).unwrap();
        let addr: SocketAddr = (Ipv4Addr::LOCALHOST, srv.tftp_port).into();

        assert_eq!(fetch(addr, "C0A81F69.img", &[]), fw);
        assert_eq!(fetch(addr, "anything.bin", &[("timeout", "5"), ("tsize", "0")]), fw);
        assert_eq!(fetch(addr, "x", &[("blksize", "1468")]), fw);
        std::thread::sleep(Duration::from_millis(100));
        srv.stop();

        let ev = events.lock().unwrap();
        let done = ev.iter().filter(|e| matches!(e, Event::TftpDone { .. })).count();
        assert_eq!(done, 3, "{ev:?}");
        assert!(ev.iter().any(|e| matches!(e, Event::TftpRequest { file, .. } if file == "C0A81F69.img")));
    }

    #[test]
    fn dhcp_offer_over_udp() {
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let cfg = Config {
            dhcp: true,
            dhcp_port: 0,
            dhcp_client_port: client.local_addr().unwrap().port(),
            dhcp_reply_addr: Ipv4Addr::LOCALHOST,
            ..local_cfg()
        };
        let srv = Server::start(cfg, Arc::new(vec![1, 2, 3]), Arc::new(|_| {})).unwrap();
        let mut pkt = vec![0u8; 240];
        pkt[0] = 1;
        pkt[1] = 1;
        pkt[2] = 6;
        pkt[28..34].copy_from_slice(&[4, 0x67, 0x61, 9, 9, 9]);
        pkt[236..240].copy_from_slice(&dhcp::MAGIC);
        pkt.extend_from_slice(&[53, 1, 1, 255]);
        client.send_to(&pkt, (Ipv4Addr::LOCALHOST, srv.dhcp_port.unwrap())).unwrap();
        let mut buf = [0u8; 600];
        let (n, _) = client.recv_from(&mut buf).unwrap();
        assert!(n >= 300);
        assert_eq!(&buf[16..20], &[192, 168, 31, 101]);
        srv.stop();
    }
}
