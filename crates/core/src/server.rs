//! The recovery server: DHCP + TFTP threads that report what happens as [`Event`]s.

use serde::Serialize;
use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::{dhcp, tftp};

/// Address the Xiaomi bootloader expects the PC to have (it pings it before DHCP).
pub const SERVER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 31, 100);
/// Router address after a successful recovery (stock firmware default).
pub const ROUTER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 31, 1);

#[derive(Debug, Clone)]
pub struct Config {
    /// Local address to bind to (normally the same as `server_ip`; 0.0.0.0 as fallback).
    pub bind_ip: Ipv4Addr,
    pub server_ip: Ipv4Addr,
    pub pool_start: Ipv4Addr,
    pub netmask: Ipv4Addr,
    /// Filename announced over DHCP. Any requested filename is served anyway.
    pub bootfile: String,
    pub dhcp: bool,
    pub dhcp_port: u16,
    pub dhcp_client_port: u16,
    pub dhcp_reply_addr: Ipv4Addr,
    pub tftp_port: u16,
    pub tftp_timeout_secs: u64,
    pub tftp_retries: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind_ip: SERVER_IP,
            server_ip: SERVER_IP,
            // Same pool as the official tool (192.168.31.101 and up).
            pool_start: Ipv4Addr::new(192, 168, 31, 101),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            bootfile: "firmware.bin".into(),
            dhcp: true,
            dhcp_port: 67,
            dhcp_client_port: 68,
            dhcp_reply_addr: Ipv4Addr::BROADCAST,
            tftp_port: 69,
            tftp_timeout_secs: 2,
            tftp_retries: 8,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Listening { bind: String, dhcp: bool },
    DhcpRequest { mac: String, kind: String, vendor: Option<String> },
    DhcpReply { mac: String, kind: String, ip: String },
    TftpRequest { peer: String, file: String, options: String },
    TftpProgress { peer: String, sent: u64, total: u64, bytes_per_sec: f64 },
    /// The last block was acknowledged: the router has the whole image.
    TftpDone { peer: String, secs: f64, retransmits: u32 },
    TftpFailed { peer: String, reason: String },
    Warning { message: String },
}

pub type Sink = Arc<dyn Fn(Event) + Send + Sync>;

pub struct Server {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    pub dhcp_port: Option<u16>,
    pub tftp_port: u16,
}

impl Server {
    /// Open the sockets and start serving `firmware`. Fails fast if a port is busy.
    pub fn start(cfg: Config, firmware: Arc<Vec<u8>>, sink: Sink) -> io::Result<Server> {
        let stop = Arc::new(AtomicBool::new(false));
        let poll = Duration::from_millis(200);

        let tftp_sock = UdpSocket::bind(SocketAddrV4::new(cfg.bind_ip, cfg.tftp_port))?;
        tftp_sock.set_read_timeout(Some(poll))?;
        let tftp_port = tftp_sock.local_addr()?.port();

        let dhcp_sock = if cfg.dhcp {
            let s = UdpSocket::bind(SocketAddrV4::new(cfg.bind_ip, cfg.dhcp_port))?;
            s.set_broadcast(true)?;
            s.set_read_timeout(Some(poll))?;
            Some(s)
        } else {
            None
        };
        let dhcp_port = match &dhcp_sock {
            Some(s) => Some(s.local_addr()?.port()),
            None => None,
        };

        let mut threads = vec![];
        {
            let (stop, sink, cfg, fw) = (stop.clone(), sink.clone(), cfg.clone(), firmware.clone());
            threads.push(std::thread::spawn(move || tftp_loop(tftp_sock, cfg, fw, sink, stop)));
        }
        if let Some(s) = dhcp_sock {
            let (stop, sink, cfg) = (stop.clone(), sink.clone(), cfg.clone());
            threads.push(std::thread::spawn(move || dhcp_loop(s, cfg, sink, stop)));
        }
        sink(Event::Listening { bind: cfg.bind_ip.to_string(), dhcp: cfg.dhcp });
        Ok(Server { stop, threads, dhcp_port, tftp_port })
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

fn dhcp_loop(sock: UdpSocket, cfg: Config, sink: Sink, stop: Arc<AtomicBool>) {
    let mut pool = dhcp::Pool::new(cfg.pool_start, cfg.server_ip);
    let mut buf = [0u8; 1500];
    while !stop.load(Ordering::SeqCst) {
        let n = match sock.recv_from(&mut buf) {
            Ok((n, _)) => n,
            Err(e) if is_timeout(&e) => continue,
            // Windows reports ICMP "port unreachable" from earlier sends as errors here.
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
            Err(e) => {
                sink(Event::Warning { message: format!("DHCP socket error: {e}") });
                return;
            }
        };
        let Some(req) = dhcp::parse(&buf[..n]) else { continue };
        let reply_type = match req.msg_type {
            Some(dhcp::DISCOVER) => Some(dhcp::OFFER),
            Some(dhcp::REQUEST) => Some(dhcp::ACK),
            None => None, // plain BOOTP
            Some(_) => continue,
        };
        let mac = dhcp::mac_string(req.mac());
        sink(Event::DhcpRequest {
            mac: mac.clone(),
            kind: dhcp::msg_name(req.msg_type).into(),
            vendor: req.vendor_class.clone(),
        });
        let ip = pool.lease_for(req.mac());
        let reply = dhcp::build_reply(
            &req,
            &dhcp::ReplyParams {
                msg_type: reply_type,
                yiaddr: ip,
                server: cfg.server_ip,
                netmask: cfg.netmask,
                bootfile: &cfg.bootfile,
                lease_secs: 3600,
            },
        );
        match sock.send_to(&reply, SocketAddrV4::new(cfg.dhcp_reply_addr, cfg.dhcp_client_port)) {
            Ok(_) => sink(Event::DhcpReply {
                mac,
                kind: reply_type.map_or("BOOTP", |t| dhcp::msg_name(Some(t))).into(),
                ip: ip.to_string(),
            }),
            Err(e) => sink(Event::Warning { message: format!("DHCP reply could not be sent: {e}") }),
        }
    }
}

fn tftp_loop(sock: UdpSocket, cfg: Config, fw: Arc<Vec<u8>>, sink: Sink, stop: Arc<AtomicBool>) {
    let active: Arc<Mutex<HashSet<SocketAddr>>> = Arc::default();
    let mut workers: Vec<JoinHandle<()>> = vec![];
    let mut buf = [0u8; 2048];
    while !stop.load(Ordering::SeqCst) {
        let (n, peer) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) if is_timeout(&e) || e.kind() == io::ErrorKind::ConnectionReset => continue,
            Err(e) => {
                sink(Event::Warning { message: format!("TFTP socket error: {e}") });
                break;
            }
        };
        let pkt = &buf[..n];
        let Some(rrq) = tftp::parse_rrq(pkt) else {
            if tftp::opcode(pkt) == Some(tftp::WRQ) {
                let _ = sock.send_to(&tftp::error_packet(2, "write not allowed"), peer);
            }
            continue;
        };
        if !active.lock().unwrap().insert(peer) {
            continue; // retransmitted request for a transfer already running
        }
        let opts = rrq.options.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", ");
        sink(Event::TftpRequest { peer: peer.to_string(), file: rrq.filename.clone(), options: opts });
        let (fw, sink, stop, active, cfg) = (fw.clone(), sink.clone(), stop.clone(), active.clone(), cfg.clone());
        workers.push(std::thread::spawn(move || {
            let res = send_file(&cfg, peer, &rrq, &fw, &sink, &stop);
            if let Err(reason) = res {
                sink(Event::TftpFailed { peer: peer.to_string(), reason });
            }
            active.lock().unwrap().remove(&peer);
        }));
        workers.retain(|w| !w.is_finished());
    }
    for w in workers {
        let _ = w.join();
    }
}

struct Link<'a> {
    sock: UdpSocket,
    peer: SocketAddr,
    timeout: Duration,
    retries: u32,
    stop: &'a AtomicBool,
    retransmits: u32,
}

impl Link<'_> {
    /// Send `pkt` and wait for ACK `block`, retransmitting on timeout.
    fn send_wait(&mut self, pkt: &[u8], block: u16) -> Result<(), String> {
        let mut buf = [0u8; 1024];
        for attempt in 0..self.retries {
            if attempt > 0 {
                self.retransmits += 1;
            }
            self.sock.send_to(pkt, self.peer).map_err(|e| format!("send failed: {e}"))?;
            let deadline = Instant::now() + self.timeout;
            loop {
                if self.stop.load(Ordering::SeqCst) {
                    return Err("stopped by the user".into());
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                self.sock.set_read_timeout(Some(left.min(Duration::from_millis(200)))).ok();
                match self.sock.recv_from(&mut buf) {
                    Ok((n, from)) if from == self.peer && n >= 4 => {
                        let op = u16::from_be_bytes([buf[0], buf[1]]);
                        let blk = u16::from_be_bytes([buf[2], buf[3]]);
                        if op == tftp::ERROR {
                            let msg = String::from_utf8_lossy(&buf[4..n]).trim_end_matches('\0').to_string();
                            return Err(format!("the router cancelled the transfer: {msg}"));
                        }
                        if op == tftp::ACK && blk == block {
                            return Ok(());
                        }
                        // Old/duplicate ACK: ignore (avoids the "Sorcerer's Apprentice" bug).
                    }
                    Ok(_) => {}
                    Err(e) if is_timeout(&e) || e.kind() == io::ErrorKind::ConnectionReset => {}
                    Err(e) => return Err(format!("receive failed: {e}")),
                }
            }
        }
        Err(format!("no answer from the router after {} attempts (block {block})", self.retries))
    }
}

fn send_file(
    cfg: &Config,
    peer: SocketAddr,
    rrq: &tftp::ReadRequest,
    fw: &[u8],
    sink: &Sink,
    stop: &AtomicBool,
) -> Result<(), String> {
    let neg = tftp::negotiate(&rrq.options, fw.len(), cfg.tftp_timeout_secs);
    let sock = UdpSocket::bind(SocketAddrV4::new(cfg.bind_ip, 0)).map_err(|e| format!("bind failed: {e}"))?;
    let mut link = Link {
        sock,
        peer,
        timeout: Duration::from_secs(neg.timeout_secs),
        retries: cfg.tftp_retries,
        stop,
        retransmits: 0,
    };
    if !neg.oack.is_empty() {
        link.send_wait(&tftp::oack_packet(&neg.oack), 0)?;
    }
    let total = fw.len() as u64;
    let blocks = tftp::block_count(fw.len(), neg.blksize);
    let t0 = Instant::now();
    let mut last_report = Instant::now() - Duration::from_secs(1);
    for n in 1..=blocks {
        let start = (n - 1) * neg.blksize;
        let chunk = &fw[start.min(fw.len())..(n * neg.blksize).min(fw.len())];
        link.send_wait(&tftp::data_packet((n & 0xffff) as u16, chunk), (n & 0xffff) as u16)?;
        if n == blocks || last_report.elapsed() >= Duration::from_millis(150) {
            last_report = Instant::now();
            let sent = (start + chunk.len()) as u64;
            let secs = t0.elapsed().as_secs_f64().max(1e-3);
            sink(Event::TftpProgress { peer: peer.to_string(), sent, total, bytes_per_sec: sent as f64 / secs });
        }
    }
    sink(Event::TftpDone {
        peer: peer.to_string(),
        secs: t0.elapsed().as_secs_f64(),
        retransmits: link.retransmits,
    });
    Ok(())
}
