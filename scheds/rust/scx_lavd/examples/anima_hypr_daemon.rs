//! AnimaSchedEXT — Hyprland focus daemon.
//!
//! Subscribes to Hyprland's `activewindowv2` events and pushes PIDs of the
//! focused window (and optionally its direct children) into scx_lavd's
//! pinned `anima_active_pids` BPF map. LAVD then gives those PIDs the
//! highest virtual deadline, keeping the interactive window responsive
//! under load.
//!
//! Architecture (post-polish, see git log):
//! - Direct bpf() syscalls via libbpf_rs::MapHandle — zero subprocesses
//!   in the map-update path
//! - Incremental map updates (only delete stale keys, insert new keys)
//! - PID cache: read `hyprctl clients -j` once at startup, no per-event
//!   hyprctl calls in steady state
//! - CPU-based child filter: in window+tree mode, direct children whose
//!   CPU usage over the last sample window exceeds ANIMA_CHILD_MAX_CPU
//!   (default 0.5) are excluded from the boost set
//! - Signal handlers so the pinned map is wiped on exit/crash/SIGTERM

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use libbpf_rs::{MapCore, MapFlags, MapHandle};

const MAP_PIN_PATH: &str = "/sys/fs/bpf/anima_active_pids";
const CONFIG_PIN_PATH: &str = "/sys/fs/bpf/anima_config";

/* ── tunable constants ─────────────────────────────────────────────── */

/// Default focused-window latency-criticality boost. Matches the BPF
/// default `LAVD_ANIMA_LC_BOOST_DFL`. Smaller = gentler. 0 = disable.
const DEFAULT_BOOST: u32 = (1024 * 7) / 8; /* 896 = top 12.5% LC */

/// Value written to the BPF map entry (`0x01` = active/focused).
const MAP_ACTIVE_VALUE: u8 = 0x01;

/// Maximum sensible boost value. Clamping prevents divide-by-zero in
/// LAVD's deadline math and stops `dl_delta` from collapsing to ~0.
const MAX_BOOST: u32 = 1024;

/// Window+tree mode: a direct child using more than this fraction of
/// a single CPU during the sample window is excluded. Set to 1.0 to
/// disable filtering entirely. Override with `ANIMA_CHILD_MAX_CPU`.
const DEFAULT_CHILD_MAX_CPU: f64 = 0.5;

/// Minimum interval between CPU samples. CPU load changes slowly enough
/// that 1 Hz is plenty. Override with `ANIMA_SAMPLE_MILLIS`.
const DEFAULT_SAMPLE_MILLIS: u64 = 1000;

/* ── data structures ───────────────────────────────────────────────── */

/// PIDs in the BPF map + CPU accounting state for child-filtering.
struct Animamap {
    handle: MapHandle,
    config_handle: MapHandle,
    last_keys: HashSet<u32>,
    cpu: CpuFilter,
}

/// Tracks per-PID CPU samples so we can filter heavy children out of the
/// boost set in window+tree mode.
struct CpuFilter {
    cache: HashMap<u32, Sample>,
    max_cpu: f64,
    sample_every: Duration,
    next_sample: Instant,
}

/// Two `/proc/<pid>/stat` snapshots used to calculate CPU fraction.
#[derive(Clone)]
struct Sample {
    utime: u64,
    stime: u64,
    when: Instant,
}

impl Animamap {
    /// Open the pinned BPF maps. `MapHandle::from_pinned_path` is the
    /// canonical entry point in libbpf-rs 0.26.x for opening a pinned
    /// BPF map by bpffs path. Requires `scx_lavd-anima` to be running
    /// first (it does the pinning) — if the pin is missing this call
    /// fails hard with a clear error instead of silently dropping
    /// updates.
    fn open() -> Result<Self> {
        let handle = MapHandle::from_pinned_path(MAP_PIN_PATH)
            .with_context(|| format!(
                "cannot open pinned BPF map at {MAP_PIN_PATH} — is scx_lavd-anima running?"
            ))?;
        let config_handle = MapHandle::from_pinned_path(CONFIG_PIN_PATH)
            .with_context(|| format!(
                "cannot open pinned BPF config map at {CONFIG_PIN_PATH} — is scx_lavd-anima running?"
            ))?;

        Ok(Self {
            handle,
            config_handle,
            last_keys: HashSet::with_capacity(16),
            cpu: CpuFilter::new(
                DEFAULT_CHILD_MAX_CPU,
                Duration::from_millis(DEFAULT_SAMPLE_MILLIS),
            ),
        })
    }

    /// Write the boost level into the BPF config map once at startup.
    /// Clamped to `[0, MAX_BOOST]`. A failed write is non-fatal — the
    /// BPF default still applies.
    fn set_boost(&self, boost: u32) -> Result<()> {
        let clamped = std::cmp::min(boost, MAX_BOOST);
        self.config_handle
            .update(&0u32.to_le_bytes(), &clamped.to_le_bytes(), MapFlags::ANY)
            .with_context(|| format!("failed to update anima_config[{clamped}]"))?;
        Ok(())
    }

    /// Push the focused PID (and optionally its direct children) into
    /// the map. Incremental: only deletes stale keys + inserts new keys.
    fn update_focused(
        &mut self,
        focused_pid: u32,
        include_children: bool,
    ) -> Result<()> {
        let mut new_keys: HashSet<u32> = HashSet::with_capacity(8);
        new_keys.insert(focused_pid);

        if include_children {
            self.cpu.filter_children(focused_pid, &mut new_keys);
        }

        // Delete stale keys.
        for stale in self.last_keys.difference(&new_keys) {
            if let Err(e) = self.handle.delete(&stale.to_le_bytes()) {
                eprintln!("[anima] delete pid {stale}: {e}");
            }
        }

        // Insert new keys.
        for key in &new_keys {
            if let Err(e) = self
                .handle
                .update(&key.to_le_bytes(), &[MAP_ACTIVE_VALUE], MapFlags::ANY)
            {
                return Err(anyhow::anyhow!("insert pid {key}: {e}"));
            }
        }

        let n = new_keys.len();
        self.last_keys = new_keys;
        eprintln!("[anima] focused -> {focused_pid} ({} children)", n - 1);
        Ok(())
    }

    /// Clear every entry in the pinned map. Called on SIGINT/SIGTERM and
    /// on graceful exit so no stale PID keeps boosting.
    fn clear(&mut self) -> Result<()> {
        let keys: Vec<_> = self.handle.keys().collect();
        let n = keys.len();
        for key in &keys {
            if key.len() == 4 {
                if let Err(e) = self.handle.delete(key) {
                    eprintln!("[anima] clear delete: {e}");
                }
            }
        }
        self.last_keys.clear();
        eprintln!("[anima] cleared {n} stale entries");
        Ok(())
    }
}

impl CpuFilter {
    fn new(max_cpu: f64, sample_every: Duration) -> Self {
        Self {
            cache: HashMap::with_capacity(16),
            max_cpu: max_cpu.clamp(0.0, 1.0),
            sample_every,
            next_sample: Instant::now() + sample_every,
        }
    }

    /// Collect direct children of `parent`, then keep only those whose
    /// CPU fraction is below `max_cpu` since the last sample.
    fn filter_children(&mut self, parent: u32, out: &mut HashSet<u32>) {
        let Ok(children) = direct_children(parent) else {
            return;
        };

        let now = Instant::now();
        if now < self.next_sample {
            // Use cached evaluations for this event.
            for cpid in children {
                if !self.cache.contains_key(&cpid) {
                    out.insert(cpid);
                }
            }
            return;
        }
        self.next_sample = now + self.sample_every;

        for cpid in children {
            let sample = match sample_cpu(cpid) {
                Some(s) => s,
                None => continue, /* process exited — skip */
            };
            let prev = self.cache.insert(cpid, sample.clone());
            let frac = self.cpu_fraction(&sample, prev.as_ref(), now);
            if frac <= self.max_cpu {
                out.insert(cpid);
            } else {
                eprintln!("[anima] child {cpid} filtered: CPU {:.0}%", frac * 100.0);
            }
        }
    }

    /// CPU fraction for `pid` since the previous sample, if any. Returns
    /// 0.0 on the first sample (no delta to compare against).
    fn cpu_fraction(&self, cur: &Sample, prev: Option<&Sample>, now: Instant) -> f64 {
        match prev {
            Some(prev) => {
                let dt = now.duration_since(prev.when).as_secs_f64();
                if dt <= 0.0 {
                    return 0.0;
                }
                let d = (cur.utime.saturating_sub(prev.utime)
                    + cur.stime.saturating_sub(prev.stime))
                    as f64;
                let ticks_per_sec = 100.0; /* sysconf(_SC_CLK_TCK) on x86_64 */
                (d / ticks_per_sec) / dt
            }
            None => 0.0,
        }
    }
}

/* ── helpers ───────────────────────────────────────────────────────── */

/// Read utime+stime (clock ticks) from `/proc/<pid>/stat`. Returns None
/// on any error. utime is field 14 and stime is field 15 after the
/// closing `)` of `(<comm>)`.
fn sample_cpu(pid: u32) -> Option<Sample> {
    let buf = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = buf.rfind(')').map(|i| &buf[i + 2..])?;
    let parts: Vec<&str> = after_comm.split_whitespace().collect();
    // Field 14 (utime) is at index 11 in the post-`) ` parts.
    let utime = parts.get(11)?.parse::<u64>().ok()?;
    let stime = parts.get(12)?.parse::<u64>().ok()?;
    Some(Sample {
        utime,
        stime,
        when: Instant::now(),
    })
}

/// PIDs of the direct children of `parent`. Subprocess-free alternative
/// to `pgrep -P`: walk `/proc` ourselves and match on field 4 (ppid).
fn direct_children(parent: u32) -> Result<Vec<u32>> {
    let mut out = Vec::new();
    let mut buf = Vec::new();
    for entry in std::fs::read_dir("/proc").with_context(|| "cannot read /proc")? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let pid: u32 = match entry.file_name().to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        buf.clear();
        match std::fs::File::open(entry.path().join("stat"))
            .and_then(|mut f| std::io::Read::read_to_end(&mut f, &mut buf))
        {
            Ok(_) => {}
            Err(_) => continue, /* process exited since readdir */
        }
        let stat = String::from_utf8_lossy(&buf);
        let after_rparen = match stat.find(')') {
            Some(i) => &stat[i + 2..],
            None => continue,
        };
        // ppid is field 4 overall → field 2 within the post-`) ` stream.
        let ppid: u32 = match after_rparen
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
        {
            Some(p) => p,
            None => continue,
        };
        if ppid == parent {
            out.push(pid);
        }
    }
    Ok(out)
}

/// Build an address → PID lookup table from `hyprctl clients -j`.
fn build_pid_cache() -> Result<HashMap<u64, u32>> {
    let out = std::process::Command::new("hyprctl")
        .args(["clients", "-j"])
        .output()
        .with_context(|| "failed to spawn hyprctl clients")?;
    if !out.status.success() {
        return Ok(HashMap::new());
    }
    let entries: Vec<serde_json::Value> =
        serde_json::from_slice(&out.stdout).with_context(|| "parse hyprctl clients")?;
    let mut cache = HashMap::with_capacity(entries.len());
    for e in entries {
        let addr = e["address"]
            .as_str()
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());
        let pid = e["pid"].as_u64().map(|p| p as u32);
        if let (Some(addr), Some(pid)) = (addr, pid) {
            if pid >= 1 {
                cache.insert(addr, pid);
            }
        }
    }
    Ok(cache)
}

/// Hyprland event address → PID. Cache hit preferred; falls back to
/// `hyprctl activewindow -j` on miss and inserts into cache. Returns
/// None on error or if PID is 0 (kernel scheduler).
fn lookup_pid(addr: u64, cache: &mut HashMap<u64, u32>) -> Option<u32> {
    if let Some(p) = cache.get(&addr).copied() {
        return Some(p);
    }
    let Ok(out) = std::process::Command::new("hyprctl")
        .args(["activewindow", "-j"])
        .output()
    else {
        return None;
    };
    if !out.status.success() {
        return None;
    }
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else {
        return None;
    };
    let pid = json["pid"].as_u64().map(|p| p as u32)?;
    if pid == 0 {
        return None;
    }
    cache.insert(addr, pid);
    Some(pid)
}

fn hypr_sock2() -> Result<PathBuf> {
    let sig = std::env::var("HYPRLAND_INSTANCE_SIGNATURE").map_err(|_| {
        anyhow::anyhow!("HYPRLAND_INSTANCE_SIGNATURE not set — is Hyprland running?")
    })?;
    let xdg = std::env::var("XDG_RUNTIME_DIR")
        .map_err(|_| anyhow::anyhow!("XDG_RUNTIME_DIR not set"))?;
    Ok(PathBuf::from(format!("{xdg}/hypr/{sig}/.socket2.sock")))
}

/* ── main event loop ───────────────────────────────────────────────── */

fn main() -> Result<()> {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let include_children = mode == "window+tree";
    let ev_sock = hypr_sock2().map_err(|e| anyhow::anyhow!("Anima error: {e}"))?;

    let anima = Arc::new(Mutex::new(Animamap::open().with_context(|| {
        "Cannot open pinned map — is scx_lavd-anima running and pinning \
         /sys/fs/bpf/anima_active_pids?"
    })?));

    /* Tunables from environment. */
    let boost = std::env::var("ANIMA_BOOST")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(DEFAULT_BOOST);
    {
        let g = anima.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
        match g.set_boost(boost) {
            Ok(()) => eprintln!("[anima] boost set to {}", boost.min(MAX_BOOST)),
            Err(e) => eprintln!("[anima] set_boost({boost}) failed: {e}"),
        }
    }

    let mut pid_cache = build_pid_cache()
        .inspect_err(|e| eprintln!("[anima] cache build failed: {e}"))
        .unwrap_or_default();
    eprintln!("[anima] PID cache: {} entries", pid_cache.len());

    /* SIGINT/SIGTERM → wipe map then exit. */
    let anima_on_signal = Arc::clone(&anima);
    ctrlc::set_handler(move || {
        eprintln!("[anima] shutdown signal — clearing map");
        if let Ok(mut g) = anima_on_signal.lock() {
            let _ = g.clear();
        }
        std::process::exit(0);
    })
    .expect("install ctrl-c handler");

    /* Subscribe on command channel, read events on event channel. */
    let cmd = ev_sock.with_file_name(".socket.sock");
    let mut sub = UnixStream::connect(&cmd).with_context(|| format!("connect {cmd:?}"))?;
    sub.write_all(b"/subscribeevent activewindowv2\n")?;
    sub.flush()?;

    let reader = BufReader::new(UnixStream::connect(&ev_sock)?);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if !line.starts_with("activewindowv2>>") {
            continue;
        }
        let addr_str = &line["activewindowv2>>".len()..];
        let Ok(addr) = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16) else {
            continue;
        };
        let Some(pid) = lookup_pid(addr, &mut pid_cache) else {
            continue;
        };
        let mut g = anima.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
        if let Err(e) = g.update_focused(pid, include_children) {
            eprintln!("[anima] update_focused: {e}");
        }
    }

    /* Graceful exit — clear what we touched. */
    anima
        .lock()
        .map_err(|e| anyhow::anyhow!("lock: {e}"))?
        .clear()?;
    drop(sub);
    Ok(())
}
