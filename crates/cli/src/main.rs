//! miwifi-recovery-cli: the same recovery server as the GUI, for terminals and Linux/macOS.

use miwifi_core::{analyze, check_rollback, Config, Event, Server, Severity};
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::sync::Arc;

const USAGE: &str = "\
Usage: miwifi-recovery-cli --firmware FILE --model CODE [options]

Serves an official Xiaomi firmware to a router in recovery mode (DHCP + TFTP).

Required:
  --firmware FILE      Official .bin image for your router
  --model CODE         Model code on the router label, e.g. RD15 (checked against the image)

Options:
  --installed VER      Version installed now, e.g. 1.0.87 (anti-rollback check)
  --server-ip IP       This PC's address on the cable (default 192.168.31.100)
  --bind-any           Listen on 0.0.0.0 instead of --server-ip
  --no-dhcp            TFTP only
  --check              Only analyse the image, do not start the server
  --force              Serve even if the checks say the router will refuse it
  -h, --help           This help

Before starting, give the PC's Ethernet port the static address 192.168.31.100/24.
Then: router off, cable from the PC to a LAN port, hold reset, power on,
release reset when the light blinks.";

struct Args {
    firmware: String,
    model: String,
    installed: Option<String>,
    server_ip: Ipv4Addr,
    bind_any: bool,
    no_dhcp: bool,
    check: bool,
    force: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let mut a = Args {
        firmware: String::new(),
        model: String::new(),
        installed: None,
        server_ip: miwifi_core::SERVER_IP,
        bind_any: false,
        no_dhcp: false,
        check: false,
        force: false,
    };
    while let Some(arg) = it.next() {
        let mut val = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "--firmware" => a.firmware = val("--firmware")?,
            "--model" => a.model = val("--model")?,
            "--installed" => a.installed = Some(val("--installed")?),
            "--server-ip" => a.server_ip = val("--server-ip")?.parse().map_err(|_| "bad --server-ip")?,
            "--bind-any" => a.bind_any = true,
            "--no-dhcp" => a.no_dhcp = true,
            "--check" => a.check = true,
            "--force" => a.force = true,
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown option {other}")),
        }
    }
    if a.firmware.is_empty() || a.model.is_empty() {
        return Err("--firmware and --model are required".into());
    }
    Ok(a)
}

fn stamp() -> String {
    let s = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("[{:02}:{:02}:{:02}]", (s / 3600) % 24, (s / 60) % 60, s % 60)
}

fn main() -> ExitCode {
    let a = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("error: {e}\n");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let fw = match std::fs::read(&a.firmware) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", a.firmware);
            return ExitCode::from(1);
        }
    };
    let info = analyze(&fw, Some(&a.model));
    println!("Firmware : {}", a.firmware);
    println!("Model    : {}", info.hardware().unwrap_or("?"));
    println!("Version  : {}", info.rom().unwrap_or("?"));
    if let Some(b) = info.meta.get("BUILDTIME") {
        println!("Built    : {b}");
    }
    println!("Size     : {} bytes", info.size);
    println!("SHA-256  : {}", info.sha256);
    println!("Checksum : {}", match info.crc_ok {
        Some(true) => "OK",
        Some(false) => "WRONG",
        None => "n/a",
    });
    let mut findings = info.findings.clone();
    match &a.installed {
        Some(v) => findings.extend(check_rollback(&info, v)),
        None => println!(
            "\nNote: you did not say which version is installed (--installed). The router only \
             accepts the same or a newer version than the one it has."
        ),
    }
    for f in &findings {
        let tag = match f.severity {
            Severity::Error => "REFUSED",
            Severity::Warning => "WARNING",
            Severity::Info => "note",
        };
        println!("\n{tag}: {}", f.message);
    }
    let blocked = findings.iter().any(|f| f.severity == Severity::Error);
    if a.check {
        return if blocked { ExitCode::from(3) } else { ExitCode::SUCCESS };
    }
    if blocked && !a.force {
        println!("\nNot starting: the router would refuse this image (see above). Use --force to try anyway.");
        return ExitCode::from(3);
    }

    let cfg = Config {
        bind_ip: if a.bind_any { Ipv4Addr::UNSPECIFIED } else { a.server_ip },
        server_ip: a.server_ip,
        dhcp: !a.no_dhcp,
        bootfile: std::path::Path::new(&a.firmware)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "firmware.bin".into()),
        ..Config::default()
    };
    let sink = Arc::new(|e: Event| {
        let msg = match e {
            Event::Listening { bind, dhcp } => {
                format!("Listening on {bind} (TFTP{}). Now put the router in recovery mode.", if dhcp { " + DHCP" } else { "" })
            }
            Event::DhcpRequest { mac, kind, vendor } => {
                format!("Router {mac} asks for an address ({kind}{})", vendor.map(|v| format!(", {v}")).unwrap_or_default())
            }
            Event::DhcpReply { ip, kind, .. } => format!("  -> {kind}: {ip}"),
            Event::TftpRequest { peer, file, .. } => format!("Router {peer} downloads '{file}'"),
            Event::TftpProgress { sent, total, bytes_per_sec, .. } => {
                let pct = sent * 100 / total.max(1);
                if pct % 10 != 0 && sent != total {
                    return;
                }
                format!("  {pct:3}%  {:.1} MB/s", bytes_per_sec / 1e6)
            }
            Event::TftpDone { secs, retransmits, .. } => format!(
                "Transfer complete in {secs:.1}s ({retransmits} retransmits). The router now checks the \
                 signature and writes the flash. Do not unplug it.\n  Blinking (usually blue) = success: \
                 power-cycle it.  Steady light = refused (older version, wrong model or damaged file)."
            ),
            Event::TftpFailed { reason, .. } => format!("Transfer failed: {reason}"),
            Event::Warning { message } => format!("Warning: {message}"),
        };
        println!("{} {msg}", stamp());
    });
    let server = match Server::start(cfg, Arc::new(fw), sink) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "error: cannot open UDP ports 67/69 on {}: {e}\nIs 192.168.31.100 set on the Ethernet port? \
                 Is another TFTP/DHCP server running? On Linux/macOS run with sudo.",
                a.server_ip
            );
            return ExitCode::from(1);
        }
    };
    println!("Press Enter to quit.");
    let _ = std::io::stdin().read_line(&mut String::new());
    server.stop();
    ExitCode::SUCCESS
}
