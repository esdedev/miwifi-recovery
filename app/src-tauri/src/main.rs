// No console window in release builds on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod net;

use miwifi_core::{analyze, check_rollback, Config, Event, Server, Severity};
use serde::Serialize;
use serde_json::json;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};

#[derive(Default)]
struct AppState {
    firmware: Mutex<Option<(String, Arc<Vec<u8>>)>>,
    runner: Mutex<Option<Runner>>,
}

struct Runner {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

fn data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let d = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    Ok(d)
}

#[derive(Serialize)]
struct Analysis {
    file_name: String,
    info: miwifi_core::FirmwareInfo,
    /// Findings of the image plus the anti-rollback check, worst first.
    findings: Vec<miwifi_core::Finding>,
    blocked: bool,
}

#[tauri::command]
fn analyze_firmware(
    state: State<AppState>,
    path: String,
    model: String,
    installed: Option<String>,
) -> Result<Analysis, String> {
    let data = std::fs::read(&path).map_err(|e| format!("Cannot read the file: {e}"))?;
    let info = analyze(&data, Some(&model));
    let mut findings = info.findings.clone();
    if let Some(v) = installed.as_deref().filter(|v| !v.trim().is_empty()) {
        findings.extend(check_rollback(&info, v));
    }
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    let blocked = findings.iter().any(|f| f.severity == Severity::Error);
    let file_name = PathBuf::from(&path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    *state.firmware.lock().unwrap() = if blocked { None } else { Some((file_name.clone(), Arc::new(data))) };
    Ok(Analysis { file_name, info, findings, blocked })
}

#[tauri::command]
fn list_adapters() -> Vec<net::Adapter> {
    net::list_adapters()
}

#[tauri::command]
fn platform() -> &'static str {
    std::env::consts::OS
}

/// Save the adapter's settings and set 192.168.31.100/24 on it (one UAC prompt).
#[tauri::command]
async fn configure_adapter(app: AppHandle, index: u32) -> Result<(), String> {
    let adapter = net::list_adapters()
        .into_iter()
        .find(|a| a.index == index)
        .ok_or("That network adapter is no longer present.")?;
    let dir = data_dir(&app)?;
    let file = net::snapshot_file(&dir);
    // Keep an older snapshot: it holds the user's real settings, not ours.
    if net::load_snapshot(&dir).map_or(true, |s| s.index != index) {
        let snap = serde_json::to_vec_pretty(&net::snapshot_of(&adapter)).map_err(|e| e.to_string())?;
        std::fs::write(&file, snap).map_err(|e| e.to_string())?;
    }
    let res = tauri::async_runtime::spawn_blocking(move || net::run_elevated(&["apply".into(), index.to_string()]))
        .await
        .map_err(|e| e.to_string())?;
    if res.is_err() && !net::list_adapters().iter().any(|a| a.index == index && a.has_recovery_ip()) {
        // Nothing changed: forget the snapshot so we don't "restore" later.
        let _ = std::fs::remove_file(&file);
    }
    res
}

/// Put back the settings saved by `configure_adapter`. Returns false if there was nothing to do.
#[tauri::command]
async fn restore_adapter(app: AppHandle) -> Result<bool, String> {
    let dir = data_dir(&app)?;
    let file = net::snapshot_file(&dir);
    if net::load_snapshot(&dir).is_none() {
        return Ok(false);
    }
    let arg = file.display().to_string();
    tauri::async_runtime::spawn_blocking(move || net::run_elevated(&["restore".into(), arg]))
        .await
        .map_err(|e| e.to_string())??;
    let _ = std::fs::remove_file(&file);
    Ok(true)
}

/// Name of the adapter whose settings are still saved (the app closed before restoring).
#[tauri::command]
fn pending_restore(app: AppHandle) -> Option<String> {
    net::load_snapshot(&data_dir(&app).ok()?).map(|s| s.name)
}

fn emit(app: &AppHandle, payload: serde_json::Value) {
    let _ = app.emit("recovery", payload);
}

fn addr_not_available(e: &std::io::Error) -> bool {
    // WSAEADDRNOTAVAIL (10049) on Windows, EADDRNOTAVAIL on Linux (99) / macOS (49).
    matches!(e.raw_os_error(), Some(10049) | Some(99) | Some(49)) || e.kind() == std::io::ErrorKind::AddrNotAvailable
}

/// Start the server. Until the cable has a link the address 192.168.31.100 does not exist
/// yet (the router is off), so keep retrying until it appears.
#[tauri::command]
fn start_recovery(app: AppHandle, state: State<AppState>, bind_any: bool) -> Result<(), String> {
    let (name, fw) = state.firmware.lock().unwrap().clone().ok_or("Choose a firmware file first.")?;
    let mut runner = state.runner.lock().unwrap();
    if let Some(r) = runner.take() {
        r.stop.store(true, Ordering::SeqCst);
        let _ = r.thread.join();
    }
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let cfg = Config {
        bind_ip: if bind_any { Ipv4Addr::UNSPECIFIED } else { miwifi_core::SERVER_IP },
        bootfile: name,
        ..Config::default()
    };
    let thread = std::thread::spawn(move || {
        let mut told_waiting = false;
        while !stop2.load(Ordering::SeqCst) {
            let app2 = app.clone();
            let sink: miwifi_core::Sink = Arc::new(move |e: Event| {
                emit(&app2, serde_json::to_value(&e).unwrap_or_default());
            });
            match Server::start(cfg.clone(), fw.clone(), sink) {
                Ok(server) => {
                    while !stop2.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    server.stop();
                    break;
                }
                Err(e) if addr_not_available(&e) => {
                    if !told_waiting {
                        told_waiting = true;
                        emit(&app, json!({ "type": "waiting_link" }));
                    }
                    std::thread::sleep(Duration::from_millis(400));
                }
                Err(e) => {
                    emit(&app, json!({ "type": "fatal", "message": e.to_string(),
                                       "busy": e.kind() == std::io::ErrorKind::AddrInUse }));
                    break;
                }
            }
        }
        emit(&app, json!({ "type": "stopped" }));
    });
    *runner = Some(Runner { stop, thread });
    Ok(())
}

#[tauri::command]
fn stop_recovery(state: State<AppState>) {
    if let Some(r) = state.runner.lock().unwrap().take() {
        r.stop.store(true, Ordering::SeqCst);
        let _ = r.thread.join();
    }
}

/// Is the router's web page answering? (It is once it boots the new firmware.)
#[tauri::command]
async fn probe_router() -> bool {
    tauri::async_runtime::spawn_blocking(|| {
        let addr = SocketAddr::from((miwifi_core::ROUTER_IP, 80));
        TcpStream::connect_timeout(&addr, Duration::from_millis(800)).is_ok()
    })
    .await
    .unwrap_or(false)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--net-helper") {
        std::process::exit(net::helper_main(&args[2..]));
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            analyze_firmware,
            list_adapters,
            platform,
            configure_adapter,
            restore_adapter,
            pending_restore,
            start_recovery,
            stop_recovery,
            probe_router
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                if let Some(r) = window.state::<AppState>().runner.lock().unwrap().take() {
                    r.stop.store(true, Ordering::SeqCst);
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running the application");
}
