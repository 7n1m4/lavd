//! AnimaSchedEXT — Hyprland focus daemon.
//!
//! Subscribes to Hyprland's `activewindowv2` events and pushes the focused
//! PID into scx_lavd's pinned `anima_active_pids` BPF map. LAVD then gives
//! that PID the tightest possible virtual deadline, keeping the interactive
//! window responsive under load.
//!
//! Run as a systemd user service alongside scx_loader. Adjusts its own
//! priority to `nice -10` so focus updates aren't starved by the very
//! workloads they are meant to preempt.

use serde_json;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;

const MAP_PIN_PATH: &str = "/sys/fs/bpf/anima_active_pids";
const MAP_PIN_DIR: &str = "/sys/fs/bpf";

fn hypr_sock2() -> Result<PathBuf, String> {
    let instance = std::env::var("HYPRLAND_INSTANCE_SIGNATURE")
        .map_err(|_| "HYPRLAND_INSTANCE_SIGNATURE not set — is Hyprland running?")?;
    let xdg = std::env::var("XDG_RUNTIME_DIR")
        .map_err(|_| "XDG_RUNTIME_DIR not set")?;
    Ok(PathBuf::from(format!(
        "{}/hypr/{}/.socket2.sock", xdg, instance
    )))
}

/// Update the pinned `anima_active_pids` map: clear existing keys, then
/// insert the focused PID (and optionally its direct children).
fn update_map(focused_pid: u32, include_children: bool) -> Result<(), String> {
    let mut to_insert = vec![focused_pid];
    if include_children {
        if let Ok(out) = Command::new("pgrep")
            .args(["-P", &focused_pid.to_string()])
            .output()
        {
            if out.status.success() {
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    if let Ok(cpid) = line.trim().parse::<u32>() {
                        to_insert.push(cpid);
                    }
                }
            }
        }
    }

    // 1. Dump keys from the pinned map via bpftool and delete each.
    let dump = Command::new("bpftool")
        .args(["-j", "map", "dump", "pinned", MAP_PIN_PATH])
        .output()
        .unwrap_or_else(|e| {
            eprintln!("bpftool map dump failed: {}", e);
            std::process::exit(1);
        });
    if dump.status.success() {
        let s = String::from_utf8_lossy(&dump.stdout);
        if let Ok(parsed) = serde_json::from_str::<Vec<serde_json::Value>>(&s.as_ref()) {
            let mut del_contents = String::new();
            for entry in parsed {
                if let Some(arr) = entry["key"].as_array() {
                    let bytes: Vec<String> = arr.iter().filter_map(|v| v.as_str())
                        .map(|s| s.trim_start_matches("0x").to_string())
                        .collect();
                    if bytes.len() == 4 {
                        del_contents.push_str(&format!(
                            "map delete pinned {} key {} {} {} {}\n",
                            MAP_PIN_PATH, bytes[0], bytes[1], bytes[2], bytes[3]));
                    }
                }
            }
            std::fs::write("/tmp/anima_delete_batch.txt", del_contents).ok();
            let _ = Command::new("bpftool")
                .args(["batch", "file", "/tmp/anima_delete_batch.txt"])
                .output();
        }
    }

    // 2. Insert each focused PID.
    let inserted = to_insert.len();
    // Build batch commands for bpftool. bpftool v7 CLI parsing is buggy for
    // map update key/value pairs, but `bpftool batch file` handles the same
    // syntax correctly. We batch all the updates into a single file.
    let mut contents = String::new();
    for pid in &to_insert {
        let b = pid.to_ne_bytes();
        contents.push_str(&format!(
            "map update pinned {} key {:02x} {:02x} {:02x} {:02x} value 01 any\n",
            MAP_PIN_PATH, b[0], b[1], b[2], b[3],
        ));
    }
    std::fs::write("/tmp/anima_batch_cmds.txt", contents).map_err(|e| format!("batch write failed: {}", e))?;
    let status = Command::new("bpftool")
        .args(["batch", "file", "/tmp/anima_batch_cmds.txt"])
        .output();
    if let Err(e) = status {
        eprintln!("bpftool batch failed: {}", e);
    }

    eprintln!("[anima] focused -> {focused_pid} ({} children)", inserted - 1);
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("window");
    let include_children = mode == "window+tree";

    let ev_sock = hypr_sock2().unwrap_or_else(|e| {
        eprintln!("Anima error: {}", e);
        std::process::exit(1);
    });

    eprintln!("Anima: connecting to {}", ev_sock.display());

    /*
     * Subscribe on the command channel (.socket.sock) and keep it open.
     * If the server sees us close the connection it will forget our
     * subscription — we deliberately keep `subscribe_sock` live for
     * the duration of the run.
     */
    let cmd_sock_path = ev_sock.with_file_name(".socket.sock");
    let mut subscribe_sock = match UnixStream::connect(&cmd_sock_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Anima error connecting to Hyprland command socket: {}", e);
            std::process::exit(1);
        }
    };
    subscribe_sock
        .write_all(b"/subscribeevent activewindowv2\n")
        .expect("write subscribe command");
    subscribe_sock.flush().expect("flush subscribe command");
    let reader_sock = match UnixStream::connect(&ev_sock) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Anima error connecting to event channel: {}", e);
            std::process::exit(1);
        }
    };
    let reader = BufReader::new(reader_sock);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.starts_with("activewindowv2>>") {
            // hyprland no longer sends PID in these events directly —
            // resolve it via hyprctl's `activewindow -j` JSON.
            if let Ok(out) = Command::new("hyprctl").args(["activewindow", "-j"]).output() {
                if out.status.success() {
                    match serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                        Ok(json) => {
                            if let Some(pid) = json["pid"].as_u64() {
                                let _ = update_map(pid as u32, include_children);
                            }
                        }
                        Err(e) => eprintln!("Anima: failed to parse activewindow JSON: {}", e),
                    }
                }
            }
        }
    }

    drop(subscribe_sock);
}
