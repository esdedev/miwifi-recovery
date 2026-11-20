//! Network adapter listing and the temporary static-IP setup (Windows).
//!
//! The PC must have 192.168.31.100/24 on the cable going to the router. On Windows the app
//! can set it for the user: it saves the adapter's current IPv4 settings, then relaunches
//! itself elevated (`--net-helper`, one UAC prompt) to run `netsh`. The same helper puts
//! the saved settings back. A temporary firewall rule lets the router reach this program.
//!
//! On other systems only the manual guide is offered.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::Path;

pub const RULE_NAME: &str = "MiWiFiRecoveryTemporary";
pub const STATIC_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 31, 100);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Addr {
    pub ip: Ipv4Addr,
    pub prefix: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Adapter {
    pub index: u32,
    pub name: String,
    pub description: String,
    pub mac: String,
    pub up: bool,
    pub wired: bool,
    pub wireless: bool,
    pub dhcp: bool,
    pub addrs: Vec<Addr>,
    pub gateways: Vec<Ipv4Addr>,
}

impl Adapter {
    pub fn has_recovery_ip(&self) -> bool {
        self.addrs.iter().any(|a| a.ip == STATIC_IP)
    }
}

/// What to put back when the user is done.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub index: u32,
    pub name: String,
    pub dhcp: bool,
    pub addrs: Vec<Addr>,
    pub gateway: Option<Ipv4Addr>,
}

pub fn prefix_to_mask(prefix: u8) -> Ipv4Addr {
    let p = prefix.min(32) as u32;
    Ipv4Addr::from(if p == 0 { 0 } else { u32::MAX << (32 - p) })
}

pub fn snapshot_of(a: &Adapter) -> Snapshot {
    Snapshot {
        index: a.index,
        name: a.name.clone(),
        dhcp: a.dhcp,
        addrs: a.addrs.iter().filter(|x| x.ip != STATIC_IP).cloned().collect(),
        gateway: a.gateways.first().copied(),
    }
}

/// netsh argument lists. Kept separate so they can be unit-tested.
pub fn apply_commands(index: u32, exe: &str) -> Vec<String> {
    vec![
        format!(
            "interface ipv4 set address name={index} source=static address={STATIC_IP} mask=255.255.255.0 gateway=none"
        ),
        format!("advfirewall firewall delete rule name={RULE_NAME}"),
        format!(
            "advfirewall firewall add rule name={RULE_NAME} dir=in action=allow protocol=UDP profile=any program=\"{exe}\""
        ),
    ]
}

pub fn restore_commands(s: &Snapshot) -> Vec<String> {
    let mut cmds = vec![];
    if s.dhcp || s.addrs.is_empty() {
        cmds.push(format!("interface ipv4 set address name={} source=dhcp", s.index));
    } else {
        let first = &s.addrs[0];
        let gw = s.gateway.map_or("none".to_string(), |g| g.to_string());
        cmds.push(format!(
            "interface ipv4 set address name={} source=static address={} mask={} gateway={gw}",
            s.index,
            first.ip,
            prefix_to_mask(first.prefix)
        ));
        for a in &s.addrs[1..] {
            cmds.push(format!(
                "interface ipv4 add address name={} address={} mask={}",
                s.index,
                a.ip,
                prefix_to_mask(a.prefix)
            ));
        }
    }
    cmds.push(format!("advfirewall firewall delete rule name={RULE_NAME}"));
    cmds
}

pub fn snapshot_file(dir: &Path) -> std::path::PathBuf {
    dir.join("network-restore.json")
}

pub fn load_snapshot(dir: &Path) -> Option<Snapshot> {
    serde_json::from_slice(&std::fs::read(snapshot_file(dir)).ok()?).ok()
}

#[cfg(windows)]
pub use win::{list_adapters, run_elevated};

/// Linux: read the adapters from `ip -json addr show` (iproute2). Elsewhere: none (manual setup).
#[cfg(not(windows))]
pub fn list_adapters() -> Vec<Adapter> {
    if !cfg!(target_os = "linux") {
        return vec![];
    }
    let Ok(out) = std::process::Command::new("ip").args(["-json", "addr", "show"]).output() else {
        return vec![];
    };
    parse_ip_json(&out.stdout, |name| Path::new("/sys/class/net").join(name).join("wireless").exists())
}

/// Parse `ip -json addr show`. `is_wireless(ifname)` tells Wi-Fi interfaces apart.
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_ip_json(json: &[u8], is_wireless: impl Fn(&str) -> bool) -> Vec<Adapter> {
    let Ok(serde_json::Value::Array(ifaces)) = serde_json::from_slice::<serde_json::Value>(json) else {
        return vec![];
    };
    let mut out = vec![];
    for i in ifaces {
        let name = i["ifname"].as_str().unwrap_or_default().to_string();
        if i["link_type"].as_str() != Some("ether") || name.is_empty() {
            continue;
        }
        let wireless = is_wireless(&name);
        let mut addrs = vec![];
        let mut dhcp = false;
        for a in i["addr_info"].as_array().into_iter().flatten() {
            if a["family"].as_str() != Some("inet") {
                continue;
            }
            if let (Some(ip), Some(prefix)) = (a["local"].as_str().and_then(|s| s.parse().ok()), a["prefixlen"].as_u64()) {
                addrs.push(Addr { ip, prefix: prefix as u8 });
                dhcp |= a["dynamic"].as_bool().unwrap_or(false);
            }
        }
        let flags: Vec<&str> = i["flags"].as_array().into_iter().flatten().filter_map(|f| f.as_str()).collect();
        out.push(Adapter {
            index: i["ifindex"].as_u64().unwrap_or(0) as u32,
            description: if wireless { "Wi-Fi".into() } else { "Ethernet".into() },
            name,
            mac: i["address"].as_str().unwrap_or_default().to_string(),
            up: flags.contains(&"LOWER_UP"),
            wired: !wireless,
            wireless,
            dhcp,
            addrs,
            gateways: vec![],
        });
    }
    out
}

#[cfg(not(windows))]
pub fn run_elevated(_args: &[String]) -> Result<(), String> {
    Err("Automatic network setup is only available on Windows.".into())
}

/// Entry point of the elevated helper: `--net-helper apply <index>` or `--net-helper restore <file>`.
#[cfg(windows)]
pub fn helper_main(args: &[String]) -> i32 {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default();
    let cmds = match args {
        [op, index] if op == "apply" => match index.parse() {
            Ok(i) => apply_commands(i, &exe),
            Err(_) => return 2,
        },
        [op, file] if op == "restore" => match std::fs::read(file).ok().and_then(|d| serde_json::from_slice(&d).ok()) {
            Some(s) => restore_commands(&s),
            None => return 2,
        },
        _ => return 2,
    };
    let mut failed = 0;
    for (i, c) in cmds.iter().enumerate() {
        let ok = std::process::Command::new("netsh")
            .raw_arg(c)
            .creation_flags(CREATE_NO_WINDOW)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        // Deleting a rule that does not exist is expected to fail.
        if !ok && !c.starts_with("advfirewall firewall delete") {
            failed = 10 + i as i32;
        }
    }
    failed
}

#[cfg(not(windows))]
pub fn helper_main(_args: &[String]) -> i32 {
    2
}

#[cfg(windows)]
mod win {
    use super::{Adapter, Addr};
    use std::net::Ipv4Addr;
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_BUFFER_OVERFLOW, ERROR_CANCELLED, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
        IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_UNSPEC, SOCKADDR, SOCKADDR_IN};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    const IP_ADAPTER_DHCP_ENABLED: u32 = 0x4;
    const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
    const IF_TYPE_IEEE80211: u32 = 71;
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;

    unsafe fn wide(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }

    unsafe fn ipv4(sa: *const SOCKADDR) -> Option<Ipv4Addr> {
        if sa.is_null() || (*sa).sa_family != AF_INET {
            return None;
        }
        let sin = &*(sa as *const SOCKADDR_IN);
        Some(Ipv4Addr::from(u32::from_be(sin.sin_addr.S_un.S_addr)))
    }

    pub fn list_adapters() -> Vec<Adapter> {
        let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
        let mut size: u32 = 16 * 1024;
        let mut buf: Vec<u64> = vec![];
        for _ in 0..4 {
            buf = vec![0u64; (size as usize).div_ceil(8)];
            let r = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    flags,
                    std::ptr::null(),
                    buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                    &mut size,
                )
            };
            if r == NO_ERROR {
                break;
            }
            if r != ERROR_BUFFER_OVERFLOW {
                return vec![];
            }
        }
        let mut out = vec![];
        let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        unsafe {
            while !p.is_null() {
                let a = &*p;
                p = a.Next;
                if a.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
                    continue;
                }
                let mut addrs = vec![];
                let mut u = a.FirstUnicastAddress;
                while !u.is_null() {
                    if let Some(ip) = ipv4((*u).Address.lpSockaddr) {
                        addrs.push(Addr { ip, prefix: (*u).OnLinkPrefixLength });
                    }
                    u = (*u).Next;
                }
                let mut gateways = vec![];
                let mut g = a.FirstGatewayAddress;
                while !g.is_null() {
                    if let Some(ip) = ipv4((*g).Address.lpSockaddr) {
                        gateways.push(ip);
                    }
                    g = (*g).Next;
                }
                let mac_len = (a.PhysicalAddressLength as usize).min(8);
                out.push(Adapter {
                    index: a.Anonymous1.Anonymous.IfIndex,
                    name: wide(a.FriendlyName),
                    description: wide(a.Description),
                    mac: a.PhysicalAddress[..mac_len]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                    up: a.OperStatus == 1,
                    wired: a.IfType == IF_TYPE_ETHERNET_CSMACD,
                    wireless: a.IfType == IF_TYPE_IEEE80211,
                    dhcp: a.Anonymous2.Flags & IP_ADAPTER_DHCP_ENABLED != 0,
                    addrs,
                    gateways,
                });
            }
        }
        out
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Run this executable elevated with `--net-helper <args>` and wait for it.
    pub fn run_elevated(args: &[String]) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let exe_w = to_wide(&exe.display().to_string());
        let params = std::iter::once("--net-helper".to_string())
            .chain(args.iter().map(|a| format!("\"{a}\"")))
            .collect::<Vec<_>>()
            .join(" ");
        let params_w = to_wide(&params);
        let verb = to_wide("runas");
        unsafe {
            let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
            info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_NOCLOSEPROCESS;
            info.lpVerb = verb.as_ptr();
            info.lpFile = exe_w.as_ptr();
            info.lpParameters = params_w.as_ptr();
            info.nShow = SW_HIDE;
            if ShellExecuteExW(&mut info) == 0 {
                let err = std::io::Error::last_os_error();
                return Err(if err.raw_os_error() == Some(ERROR_CANCELLED as i32) {
                    "cancelled".into()
                } else {
                    err.to_string()
                });
            }
            if info.hProcess.is_null() {
                return Err("the helper did not start".into());
            }
            WaitForSingleObject(info.hProcess, INFINITE);
            let mut code: u32 = 1;
            GetExitCodeProcess(info.hProcess, &mut code);
            CloseHandle(info.hProcess);
            if code == 0 {
                Ok(())
            } else {
                Err(format!("netsh failed (code {code})"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_ip_json() {
        let json = br#"[
          {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP"],"link_type":"loopback","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]},
          {"ifindex":2,"ifname":"enp3s0","flags":["BROADCAST","UP","LOWER_UP"],"link_type":"ether","address":"02:00:00:00:00:01",
           "addr_info":[{"family":"inet","local":"192.168.31.100","prefixlen":24},{"family":"inet6","local":"fe80::1","prefixlen":64}]},
          {"ifindex":3,"ifname":"wlp2s0","flags":["BROADCAST","UP"],"link_type":"ether","address":"02:00:00:00:00:02",
           "addr_info":[{"family":"inet","local":"10.0.0.7","prefixlen":24,"dynamic":true}]}
        ]"#;
        let a = parse_ip_json(json, |n| n.starts_with("wl"));
        assert_eq!(a.len(), 2);
        assert!(a[0].wired && a[0].up && a[0].has_recovery_ip() && !a[0].dhcp);
        assert_eq!(a[0].addrs.len(), 1);
        assert!(a[1].wireless && !a[1].up && a[1].dhcp);
        assert!(parse_ip_json(b"not json", |_| false).is_empty());
    }

    #[test]
    fn masks() {
        assert_eq!(prefix_to_mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_mask(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(prefix_to_mask(32), Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn commands() {
        let a = apply_commands(12, r"C:\Program Files\MiWiFi Recovery\miwifi-recovery.exe");
        assert!(a[0].starts_with("interface ipv4 set address name=12 source=static address=192.168.31.100"));
        assert!(a[2].ends_with("program=\"C:\\Program Files\\MiWiFi Recovery\\miwifi-recovery.exe\""));
        let s = Snapshot {
            index: 12,
            name: "Ethernet".into(),
            dhcp: false,
            addrs: vec![
                Addr { ip: Ipv4Addr::new(10, 0, 0, 5), prefix: 24 },
                Addr { ip: Ipv4Addr::new(10, 0, 1, 5), prefix: 16 },
            ],
            gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
        };
        let r = restore_commands(&s);
        assert_eq!(
            r[0],
            "interface ipv4 set address name=12 source=static address=10.0.0.5 mask=255.255.255.0 gateway=10.0.0.1"
        );
        assert_eq!(r[1], "interface ipv4 add address name=12 address=10.0.1.5 mask=255.255.0.0");
        let d = restore_commands(&Snapshot { dhcp: true, ..s });
        assert_eq!(d[0], "interface ipv4 set address name=12 source=dhcp");
    }
}
