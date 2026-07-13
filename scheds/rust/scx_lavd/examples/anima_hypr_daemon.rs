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
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use scx_utils::anima_tab_sock;
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

/* ── audio-PID boost constants ─────────────────────────────────────── */

/// PipeWire/PulseAudio stream audio-PID boost. Default `on`.
const AUDIO_BOOST_DEFAULT: &str = "on";
/// Polling interval in milliseconds for sink-input enumeration. Override
/// with `ANIMA_AUDIO_POLL_MS`. Default 1000.
const AUDIO_POLL_MS_DEFAULT: u64 = 1000;
/// Audio command. Override with `ANIMA_AUDIO_CMD`. Default `pactl`.
const AUDIO_CMD_DEFAULT: &str = "pactl";

/* ── data structures ───────────────────────────────────────────────── */

/// PIDs in the BPF map + CPU accounting state for child-filtering.
struct Animamap {
    handle: MapHandle,
    config_handle: MapHandle,
    last_keys: HashSet<u32>,
    cpu: CpuFilter,
    boost: BoostState,
}

/// Tracks the desired boost set as the union of focus/browser state and
/// active audio streams. Keeping these inputs separate lets audio polling
/// reconcile the map without waiting for the next focus event.
#[derive(Default)]
struct BoostState {
    base_keys: HashSet<u32>,
    audio_pids: HashSet<u32>,
    active_keys: HashSet<u32>,
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

impl BoostState {
    fn set_base_keys(&mut self, base_keys: HashSet<u32>) -> &HashSet<u32> {
        self.base_keys = base_keys;
        self.rebuild()
    }

    fn set_audio_pids(&mut self, audio_pids: HashSet<u32>) -> &HashSet<u32> {
        self.audio_pids = audio_pids;
        self.rebuild()
    }

    fn rebuild(&mut self) -> &HashSet<u32> {
        self.active_keys.clear();
        self.active_keys.extend(self.base_keys.iter().copied());
        self.active_keys.extend(self.audio_pids.iter().copied());
        &self.active_keys
    }
}

impl Animamap {
    /// Open the pinned BPF maps. `MapHandle::from_pinned_path` is the
    /// canonical entry point in libbpf-rs 0.26.x for opening a pinned
    /// BPF map by bpffs path. Requires `scx_lavd-anima` to be running
    /// first (it does the pinning) — if the pin is missing this call
    /// fails hard with a clear error instead of silently dropping
    /// updates.
    fn open() -> Result<Self> {
        let handle = MapHandle::from_pinned_path(MAP_PIN_PATH).with_context(|| {
            format!("cannot open pinned BPF map at {MAP_PIN_PATH} — is scx_lavd-anima running?")
        })?;
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
            boost: BoostState::default(),
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

    /// Browser-mode update: boost only the focused PID and the PID of the
    /// active browser tab reported by the WebExtension. Skips the
    /// children-of-focused-pid walk entirely (useless for browsers). Falls
    /// back to `update_focused` when mode is inactive or no tab-PID has
    /// been seen yet.
    fn update_browser(&mut self, focused_pid: u32, tab_pid: u32) -> Result<()> {
        let mut base_keys = HashSet::with_capacity(2);
        base_keys.insert(focused_pid);
        base_keys.insert(tab_pid);

        let new_keys = self.boost.set_base_keys(base_keys).clone();
        self.apply_active_keys(&new_keys)?;
        eprintln!("[anima] browser mode -> focused {focused_pid}, tab {tab_pid}");
        Ok(())
    }

    /// Push the focused PID (and optionally its direct children) into
    /// the map. Incremental: only deletes stale keys + inserts new keys.
    /// Also unions the current set of audio-PIDs so that any process
    /// driving a PulseAudio/PipeWire sink-input gets the boost even if
    /// it is not focused (e.g. Spotify while you type in a terminal).
    fn update_focused(&mut self, focused_pid: u32, include_children: bool) -> Result<()> {
        let mut base_keys: HashSet<u32> = HashSet::with_capacity(8);
        base_keys.insert(focused_pid);

        if include_children {
            self.cpu.filter_children(focused_pid, &mut base_keys);
        }

        let n_children = base_keys.len().saturating_sub(1);
        let new_keys = self.boost.set_base_keys(base_keys).clone();
        self.apply_active_keys(&new_keys)?;
        eprintln!("[anima] focused -> {focused_pid} ({n_children} children)");
        Ok(())
    }

    /// Update audio-PIDs and reconcile the map immediately, without
    /// waiting for a Hyprland focus event.
    fn update_audio(&mut self, audio_pids: HashSet<u32>) -> Result<()> {
        let new_keys = self.boost.set_audio_pids(audio_pids).clone();
        self.apply_active_keys(&new_keys)
    }

    fn apply_active_keys(&mut self, new_keys: &HashSet<u32>) -> Result<()> {
        for stale in self.last_keys.difference(new_keys) {
            if let Err(e) = self.handle.delete(&stale.to_le_bytes()) {
                eprintln!("[anima] delete pid {stale}: {e}");
            }
        }

        for key in new_keys {
            if let Err(e) =
                self.handle
                    .update(&key.to_le_bytes(), &[MAP_ACTIVE_VALUE], MapFlags::ANY)
            {
                return Err(anyhow::anyhow!("insert pid {key}: {e}"));
            }
        }

        self.last_keys = new_keys.clone();
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
                    + cur.stime.saturating_sub(prev.stime)) as f64;
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

/// Read the comm (command name) for a PID. Returns `None` if the
/// process has already exited or `/proc/<pid>/comm` is unreadable.
fn read_comm(pid: u32) -> Option<String> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(s.trim().to_string())
}

/// Parse `pactl list sink-inputs` output and return the set of PIDs that
/// currently own a sink-input (i.e. are actively playing audio via
/// PulseAudio or PipeWire's pulse layer). Empty set when nothing is
/// playing or when `pactl` is unavailable. Lines of interest look like:
///     application.process.id = "12345"
fn sample_audio(cmd: &str) -> io::Result<HashSet<u32>> {
    let out = std::process::Command::new(cmd)
        .args(["list", "sink-inputs"])
        .output()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let mut set = HashSet::new();
    for line in s.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("application.process.id") {
            let v = rest.trim().trim_start_matches('=').trim().trim_matches('"');
            if let Ok(pid) = v.parse::<u32>() {
                set.insert(pid);
            }
        }
    }
    Ok(set)
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
    let xdg =
        std::env::var("XDG_RUNTIME_DIR").map_err(|_| anyhow::anyhow!("XDG_RUNTIME_DIR not set"))?;
    Ok(PathBuf::from(format!("{xdg}/hypr/{sig}/.socket2.sock")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pids(values: &[u32]) -> HashSet<u32> {
        values.iter().copied().collect()
    }

    #[test]
    fn audio_state_changes_rebuild_active_keys_without_focus_event() {
        let mut state = BoostState::default();

        let active = state.set_base_keys(pids(&[100])).clone();
        assert_eq!(active, pids(&[100]));

        let active = state.set_audio_pids(pids(&[200])).clone();
        assert_eq!(active, pids(&[100, 200]));

        let active = state.set_audio_pids(HashSet::new()).clone();
        assert_eq!(active, pids(&[100]));
    }

    #[test]
    fn browser_base_keys_include_audio_pids() {
        let mut state = BoostState::default();

        state.set_audio_pids(pids(&[300]));
        let active = state.set_base_keys(pids(&[100, 200])).clone();

        assert_eq!(active, pids(&[100, 200, 300]));
    }
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

    /* Browser-mode state: the active-tab PID reported by the WebExtension
     * via a UNIX stream socket at `/run/anima/tab.sock`. The PID is
     * retrieved by the extension for the currently-focused tab and sent
     * as 4 native-endian bytes each time the tab changes. */
    let browser_cmds: Vec<String> = std::env::var("ANIMA_BROWSER_CMDS")
        .unwrap_or_else(|_| "floorp,floorp-bin,librewolf,firefox,firefox-bin".into())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    eprintln!("[anima] browser mode commands: {:?}", browser_cmds);

    let active_tab_pid: Arc<parking_lot::Mutex<Option<u32>>> =
        Arc::new(parking_lot::Mutex::new(None));
    let active_tab_pid_for_thread = Arc::clone(&active_tab_pid);
    std::thread::spawn(move || {
        let sock_path = anima_tab_sock();
        eprintln!("[anima] tab-pid listener using {sock_path:?}");
        let dir = sock_path.parent().expect("sock path has parent");
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("[anima] tab-pid listener: cannot create {dir:?}: {e}");
            return;
        }
        let _ = std::fs::remove_file(&sock_path); /* ignore NotFound */
        let Ok(listener) = UnixListener::bind(&sock_path) else {
            eprintln!("[anima] tab-pid listener: cannot bind {sock_path:?}");
            return;
        };
        eprintln!("[anima] tab-pid listener bound on {sock_path:?}");
        for stream in listener.incoming() {
            let Ok(mut s) = stream else {
                break;
            };
            let mut buf = [0u8; 4];
            while let Ok(()) = s.read_exact(&mut buf) {
                let pid = i32::from_ne_bytes(buf);
                if pid > 0 {
                    *active_tab_pid_for_thread.lock() = Some(pid as u32);
                }
            }
        }
    });

    /* Audio-PID boost thread: poll `pactl list sink-inputs`, then
     * reconcile the pinned map against current focus/browser keys plus
     * active audio PIDs. Thread is skipped if ANIMA_AUDIO_BOOST=off. */
    let anima_for_audio = Arc::clone(&anima);
    let audio_raw =
        std::env::var("ANIMA_AUDIO_BOOST").unwrap_or_else(|_| AUDIO_BOOST_DEFAULT.into());
    let audio_enabled = !audio_raw.eq_ignore_ascii_case("off");
    let audio_poll_ms: u64 = std::env::var("ANIMA_AUDIO_POLL_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(AUDIO_POLL_MS_DEFAULT);
    let audio_cmd: String =
        std::env::var("ANIMA_AUDIO_CMD").unwrap_or_else(|_| AUDIO_CMD_DEFAULT.into());
    if audio_enabled {
        eprintln!("[anima] audio: poll thread started (cmd={audio_cmd}, poll_ms={audio_poll_ms})");
        thread::spawn(move || {
            let mut consecutive_empty = 0u32;
            loop {
                thread::sleep(Duration::from_millis(audio_poll_ms));
                match sample_audio(&audio_cmd) {
                    Ok(set) => {
                        let is_empty = set.is_empty();
                        if is_empty {
                            consecutive_empty += 1;
                            if consecutive_empty == 5 {
                                eprintln!("[anima] audio: no active streams");
                            }
                        } else {
                            consecutive_empty = 0;
                        }
                        if let Ok(mut g) = anima_for_audio.lock() {
                            if let Err(e) = g.update_audio(set) {
                                eprintln!("[anima] update_audio: {e}");
                            }
                        }
                    }
                    Err(e) => eprintln!("[anima] audio: {e}"),
                }
            }
        });
    } else {
        eprintln!("[anima] audio: poll thread disabled (ANIMA_AUDIO_BOOST={audio_raw})");
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

        /* Focus-mode detection: is the focused window a known browser, and
         * do we have an active-tab PID to switch to? */
        let tab_pid = *active_tab_pid.lock();
        let is_browser = read_comm(pid)
            .map(|c| browser_cmds.contains(&c))
            .unwrap_or(false);

        let mut g = anima.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
        if let (true, Some(tab_pid)) = (is_browser, tab_pid) {
            if let Err(e) = g.update_browser(pid, tab_pid) {
                eprintln!("[anima] update_browser: {e}");
            }
        } else if let Err(e) = g.update_focused(pid, include_children) {
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
