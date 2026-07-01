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

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use libbpf_rs::{MapCore, MapFlags, MapHandle};

const MAP_PIN_PATH: &str = "/sys/fs/bpf/anima_active_pids";

/// Value written to the BPF map entry (`0x01` = active/focused).
const MAP_ACTIVE_VALUE: u8 = 0x01;

/*
 * Animamap — thin wrapper over the pinned `anima_active_pids` BPF hash map.
 *
 * Before commit *X*, each focus event spawned three `bpftool` subprocesses
 * (dump → JSON parse → batch delete, then N × map update). That was ~5ms
 * of pure subprocess init overhead per event, visible as micro-stutter on
 * fast alt-tabbing.
 *
 * Now we open the pinned map once (via `MapHandle::from_pinned_path`) and
 * mutate it directly via the bpf() syscall through `MapHandle::update` /
 * `MapHandle::delete`. The handle keeps a ref-counted FD so libbpf holds
 * the pin alive as long as we hold the handle.
 *
 * `MapHandle::from_pinned_path` does an fstat on `/sys/fs/bpf/...` and
 * finds the pinned map by name — pinning is required (which scx_lavd
 * already does for `anima_active_pids`). If you ever need to open an
 * unpinned map, use `MapHandle::from_map_fd(fd)` or walk the skel.
 */
struct Animamap {
    handle: MapHandle,
    last_keys: HashSet<u32>,
}

impl Animamap {
    /// Open the pinned BPF map at `MAP_PIN_PATH`.
    ///
    /// `MapHandle::from_pinned_path` is the canonical entry point in
    /// libbpf-rs 0.26.x for opening any pinned BPF map — which is exactly
    /// what we need here. Verification: `BPF_MAP_TYPE_HASH`, key=`u32`,
    /// value=`u8`, max_entries=16 (see `anima.bpf.h`).
    fn open() -> Result<Self> {
        let handle = MapHandle::from_pinned_path(MAP_PIN_PATH)
            .with_context(|| format!("failed to open pinned BPF map at {}", MAP_PIN_PATH))?;

        Ok(Self {
            handle,
            last_keys: HashSet::new(),
        })
    }

    /// Push the focused PID (and optionally its direct children) into the
    /// map. Incrementally updates: only removes stale keys + inserts new
    /// keys. No subprocess, no temp file, no JSON parsing.
    fn update_focused(&mut self, focused_pid: u32, include_children: bool) -> Result<()> {
        let mut new_keys: HashSet<u32> = HashSet::with_capacity(8);

        new_keys.insert(focused_pid);

        if include_children {
            match std::process::Command::new("pgrep")
                .args(["-P", &focused_pid.to_string()])
                .output()
            {
                Ok(out) if out.status.success() => {
                    for line in String::from_utf8_lossy(&out.stdout).lines() {
                        if let Ok(cpid) = line.trim().parse::<u32>() {
                            new_keys.insert(cpid);
                        }
                    }
                }
                Ok(_) => {} /* pgrep exited with no matches — not an error */
                Err(e) => eprintln!("[anima] pgrep failed: {}", e),
            }
        }

        // Delete stale keys (present in last round but not in new set).
        for stale_key in self.last_keys.difference(&new_keys) {
            let key_bytes = stale_key.to_le_bytes();
            if let Err(e) = self.handle.delete(&key_bytes) {
                eprintln!("[anima] bpf delete warning for pid {}: {}", stale_key, e);
            }
        }

        // Insert new keys.
        let inserted_count = new_keys.len();
        for key in &new_keys {
            let key_bytes = key.to_le_bytes();
            if let Err(e) = self.handle.update(&key_bytes, &[MAP_ACTIVE_VALUE], MapFlags::ANY) {
                return Err(anyhow::anyhow!(
                    "bpf update failed for pid {}: {}",
                    key,
                    e
                ));
            }
        }

        self.last_keys = new_keys;

        eprintln!(
            "[anima] focused -> {} ({} children)",
            focused_pid,
            inserted_count - 1
        );
        Ok(())
    }

    /// Clear every entry in the pinned map — call on SIGINT/SIGTERM so we
    /// don't leave stale PIDs boosting after exit.
    fn clear(&mut self) -> Result<()> {
        // Collect keys first to avoid concurrent-modification issues.
        let keys: Vec<Vec<u8>> = self.handle.keys().collect();
        for key in &keys {
            if key.len() == 4 {
                if let Err(e) = self.handle.delete(key) {
                    eprintln!("[anima] bpf clear: delete failed: {}", e);
                }
            } else {
                eprintln!("[anima] bpf clear: unexpected key size {}", key.len());
            }
        }
        self.last_keys.clear();
        Ok(())
    }
}

/// Build an address → PID cache from `hyprctl clients -j`. Falls back to
/// per-event `hyprctl activewindow -j` lookups if address isn't in cache
/// (e.g., window opened after daemon started).
fn build_pid_cache() -> Result<HashMap<u64, u32>> {
    let out = std::process::Command::new("hyprctl").args(["clients", "-j"]).output()
        .context("failed to exec hyprctl clients")?;
    if !out.status.success() {
        return Ok(HashMap::new());
    }
    let json: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout)
        .context("failed to parse hyprctl clients JSON")?;
    let mut cache = HashMap::with_capacity(json.len());
    for entry in json {
        let addr = entry["address"].as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());
        let pid  = entry["pid"].as_u64().map(|p| p as u32);
        if let (Some(addr), Some(pid @ 1..)) = (addr, pid) {
            cache.insert(addr, pid);
        }
    }
    Ok(cache)
}

/// Resolve PID for a Hyprland window address via cache hit or fallback
/// hyprctl activewindow JSON lookup. Filters out PID 0 (the kernel
/// scheduler) which would otherwise get boosted into oblivion.
fn lookup_pid(addr: u64, cache: &mut HashMap<u64, u32>) -> Option<u32> {
    if let Some(pid) = cache.get(&addr).copied() {
        return Some(pid);
    }
    if let Ok(out) = std::process::Command::new("hyprctl").args(["activewindow", "-j"]).output() {
        if out.status.success() {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                if let Some(pid) = json["pid"].as_u64().map(|p| p as u32) {
                    if pid != 0 {
                        cache.insert(addr, pid);
                        return Some(pid);
                    } else {
                        eprintln!("[anima] hyprctl returned pid=0 — skipping");
                    }
                }
            }
        }
    }
    None
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("window");
    let include_children = mode == "window+tree";

    let ev_sock = hypr_sock2()
        .map_err(|e| anyhow::anyhow!("Anima error: {}", e))?;

    // Open the pinned BPF map BEFORE entering the event loop so a broken
    // pin fails fast instead of silently losing updates.
    let anima = Arc::new(Mutex::new(Animamap::open()
        .with_context(|| "Cannot open anima_active_pids — is scx_lavd loaded and pinning the map?")?));

    let mut pid_cache = build_pid_cache()
        .inspect_err(|e| eprintln!("[anima] address cache build failed: {}", e))
        .unwrap_or_default();
    eprintln!("[anima] address cache: {} entries", pid_cache.len());

    // Install SIGINT/SIGTERM handler so we leave the map clean on exit.
    // The Mutex only briefly locks (syscall to bpf()), and the signal
    // handler only runs off the main thread — no deadlock risk.
    let anima_signal = Arc::clone(&anima);
    ctrlc::set_handler(move || {
        eprintln!("[anima] received shutdown signal — clearing pinned map");
        if let Ok(mut guard) = anima_signal.lock() {
            let _ = guard.clear();
        }
        std::process::exit(0);
    })
    .expect("failed to install ctrl-c handler");

    /*
     * Subscribe on the command channel (.socket.sock) and keep it open.
     * If the server sees us close the connection it will forget our
     * subscription — we deliberately keep `subscribe_sock` live for
     * the duration of the run.
     */
    let cmd_sock_path = ev_sock.with_file_name(".socket.sock");
    let mut subscribe_sock = UnixStream::connect(&cmd_sock_path)
        .map_err(|e| anyhow::anyhow!("Anima error connecting to Hyprland command socket: {}", e))?;
    subscribe_sock
        .write_all(b"/subscribeevent activewindowv2\n")
        .expect("write subscribe command");
    subscribe_sock.flush().expect("flush subscribe command");
    let reader_sock = UnixStream::connect(&ev_sock)
        .map_err(|e| anyhow::anyhow!("Anima error connecting to event channel: {}", e))?;
    let reader = BufReader::new(reader_sock);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.starts_with("activewindowv2>>") {
            let addr_str = &line["activewindowv2>>".len()..];
            let addr = match u64::from_str_radix(addr_str.trim_start_matches("0x"), 16) {
                Ok(a) => a,
                Err(_) => continue,
            };
            let Some(pid) = lookup_pid(addr, &mut pid_cache) else {
                continue;
            };
            if let Err(e) = anima.lock()
                .map_err(|e| anyhow::anyhow!("lock poisoned: {}", e))?
                .update_focused(pid, include_children)
            {
                eprintln!("[anima] update_focused error: {}", e);
            }
        }
    }

    // Clean shutdown — clear the map on graceful SIGINT-free exit.
    if let Ok(mut guard) = anima.lock() {
        guard.clear()?;
    }

    drop(subscribe_sock);
    Ok(())
}

fn hypr_sock2() -> Result<PathBuf> {
    let instance = std::env::var("HYPRLAND_INSTANCE_SIGNATURE")
        .map_err(|_| anyhow::anyhow!("HYPRLAND_INSTANCE_SIGNATURE not set — is Hyprland running?"))?;
    let xdg = std::env::var("XDG_RUNTIME_DIR")
        .map_err(|_| anyhow::anyhow!("XDG_RUNTIME_DIR not set"))?;
    Ok(PathBuf::from(format!(
        "{}/hypr/{}/.socket2.sock", xdg, instance
    )))
}
