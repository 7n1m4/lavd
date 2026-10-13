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
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

mod anima_audio;
use anima_audio::AudioEvent;
mod anima_swap;
use anima_swap::SwapGuard;
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use scx_utils::anima_tab_sock;

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

/// PipeWire stream audio-PID boost. Default `on`. Set to `off` to stop
/// subscribing to PipeWire entirely (no connection, no events).
const AUDIO_BOOST_DEFAULT: &str = "on";

/* ── swap-protection constants ─────────────────────────────────────── */

/// Label for the off state of `ANIMA_SWAP_PROTECT` in the startup line,
/// so the printed default and the code agree.
const SWAP_PROTECT_DEFAULT: &str = "off";

/* ── data structures ───────────────────────────────────────────────── */

/// PIDs in the BPF map + CPU accounting state for child-filtering.
struct Animamap {
    handle: MapHandle,
    config_handle: MapHandle,
    last_keys: HashSet<u32>,
    cpu: CpuFilter,
    boost: BoostState,
    /// Live PipeWire stream count per PID. A PID holds the boost while it
    /// has at least one stream.
    audio_refs: HashMap<u32, usize>,
}

/// Tracks the desired boost set as the union of focus/browser state and
/// active audio streams. Keeping these inputs separate lets an audio
/// stream starting or stopping reconcile the map without waiting for the
/// next focus event.
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

/// One reconciliation step: which keys to delete, which to write.
///
/// Pure (no syscalls) so the incremental-update logic can be tested
/// without root privileges or a loaded scheduler — the real bug class
/// here is "a key that stops being boosted is never deleted".
struct MapDiff {
    /// Keys present in `last` but not in `next` — must be deleted.
    delete: Vec<u32>,
    /// Keys in `next` that are not already in `last` — written in
    /// ascending order for determinism. Keys retained from `last` skip
    /// the write: nothing else mutates this map, so the entry is still
    /// there and rewriting it on every focus event is pure syscall
    /// amplification.
    write: Vec<u32>,
}

impl MapDiff {
    fn between(last: &HashSet<u32>, next: &HashSet<u32>) -> Self {
        Self {
            delete: {
                let mut v: Vec<u32> = last.difference(next).copied().collect();
                v.sort_unstable();
                v
            },
            write: {
                let mut v: Vec<u32> = next.difference(last).copied().collect();
                v.sort_unstable();
                v
            },
        }
    }
}

/// Fold one PipeWire stream event into the per-PID live-stream count.
///
/// Pure so the ref-counting can be tested without a PipeWire connection.
fn adjust_refs(refs: &mut HashMap<u32, usize>, event: AudioEvent) {
    match event {
        AudioEvent::Started(pid) => {
            refs.entry(pid).and_modify(|n| *n += 1).or_insert(1);
        }
        AudioEvent::Stopped(pid) => {
            if let Some(n) = refs.get_mut(&pid) {
                if *n > 1 {
                    *n -= 1;
                } else {
                    refs.remove(&pid);
                }
            }
        }
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
            audio_refs: HashMap::with_capacity(8),
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

    /// Apply one PipeWire registry event: add or drop one audio-PID and
    /// reconcile the map immediately, without waiting for a Hyprland focus
    /// event.
    ///
    /// Events are reference-counted per PID because a process can own more
    /// than one playback stream (a game with music and a voice client, a
    /// browser with two tabs playing). The last stop must not drop the
    /// boost while another stream from that PID is still alive.
    fn audio_event(&mut self, event: AudioEvent) -> Result<()> {
        if let AudioEvent::Stopped(pid) = event {
            if !self.audio_refs.contains_key(&pid) {
                // PipeWire can deliver a removal for a node whose
                // properties we filtered out (e.g. a capture stream).
                eprintln!("[anima] audio: stop for untracked pid {pid}");
                return Ok(());
            }
        }
        adjust_refs(&mut self.audio_refs, event);
        let pids: HashSet<u32> = self.audio_refs.keys().copied().collect();
        self.update_audio(pids)
    }

    /// Update audio-PIDs and reconcile the map immediately, without
    /// waiting for a Hyprland focus event.
    fn update_audio(&mut self, audio_pids: HashSet<u32>) -> Result<()> {
        let new_keys = self.boost.set_audio_pids(audio_pids).clone();
        self.apply_active_keys(&new_keys)
    }

    fn apply_active_keys(&mut self, new_keys: &HashSet<u32>) -> Result<()> {
        let diff = MapDiff::between(&self.last_keys, new_keys);
        for stale in &diff.delete {
            if let Err(e) = self.handle.delete(&stale.to_le_bytes()) {
                eprintln!("[anima] delete pid {stale}: {e}");
            }
        }

        for key in &diff.write {
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

    /* ── reconciliation: the incremental map update ─────────────────── */

    /// A PID that stops being boosted must be deleted, not just left in
    /// the map. This is the failure that leaves a stale boost forever.
    #[test]
    fn reconciliation_deletes_keys_that_stop_being_boosted() {
        let last = pids(&[100, 200]);
        let next = pids(&[100, 300]);

        let diff = MapDiff::between(&last, &next);

        assert_eq!(diff.delete, vec![200]);
        // 100 is already in the map, so only 300 is written.
        assert_eq!(diff.write, vec![300]);
    }

    /// A pure repeat must not touch the map at all — the whole point of
    /// the incremental design.
    #[test]
    fn reconciliation_is_a_noop_when_the_set_is_unchanged() {
        let set = pids(&[100, 200]);

        let diff = MapDiff::between(&set, &set);

        assert!(diff.delete.is_empty());
        assert!(diff.write.is_empty());
    }

    /// Audio PID boosting an unfocused process, then focus moving on:
    /// both the focus and the audio key have to survive until each one
    /// independently stops applying.
    #[test]
    fn audio_key_survives_a_focus_change_that_recants_it() {
        let mut state = BoostState::default();

        // Focus is 100, and 300 is playing audio.
        let active = state.set_base_keys(pids(&[100])).clone();
        assert_eq!(active, pids(&[100]));
        let active = state.set_audio_pids(pids(&[300])).clone();
        assert_eq!(active, pids(&[100, 300]));

        // Focus moves away from 100 with nothing focused (0 = no window).
        // The audio key must still be there.
        let active = state.set_base_keys(HashSet::new()).clone();
        assert_eq!(active, pids(&[300]));
    }

    /// Keys are 32-bit little-endian on the wire; make sure the sort
    /// order is over the numeric value, not the byte order.
    #[test]
    fn reconciliation_writes_in_ascending_pid_order() {
        let last = HashSet::new();
        let next = pids(&[217300, 12, 3]);

        let diff = MapDiff::between(&last, &next);

        assert_eq!(diff.write, vec![3, 12, 217300]);
    }

    /* ── PipeWire event ref-counting ───────────────────────────────── */

    /// A PID holding two streams (music + voice, two browser tabs) must
    /// keep the boost until its last stream stops. This is why events are
    /// reference-counted rather than treated as a live/delta flag.
    #[test]
    fn audio_events_are_refcounted_per_pid() {
        let mut refs: HashMap<u32, usize> = HashMap::new();
        let playing = |r: &HashMap<u32, usize>| r.keys().copied().collect::<HashSet<u32>>();

        adjust_refs(&mut refs, AudioEvent::Started(100));
        assert_eq!(playing(&refs), pids(&[100]));

        adjust_refs(&mut refs, AudioEvent::Started(100));
        assert_eq!(refs.get(&100), Some(&2));
        assert_eq!(playing(&refs), pids(&[100]));

        // One stream ends — the process is still playing the other.
        adjust_refs(&mut refs, AudioEvent::Stopped(100));
        assert_eq!(playing(&refs), pids(&[100]));

        adjust_refs(&mut refs, AudioEvent::Stopped(100));
        assert!(playing(&refs).is_empty());
    }

    /// A stop for a PID with no live stream is a no-op — it must not
    /// underflow or drop anything. PipeWire can deliver removals for nodes
    /// the registry reported but whose props we filtered out.
    #[test]
    fn stop_for_untracked_pid_does_not_underflow() {
        let mut refs: HashMap<u32, usize> = HashMap::new();
        adjust_refs(&mut refs, AudioEvent::Started(100));

        adjust_refs(&mut refs, AudioEvent::Stopped(200)); /* never seen */
        adjust_refs(&mut refs, AudioEvent::Stopped(200));

        assert_eq!(refs.get(&100), Some(&1));
        assert_eq!(refs.len(), 1);
    }

    /* ── swap protection must not couple to the boost path ─────────── */

    /// Swap protection is the only step in the focus-event path that is
    /// allowed to fail, so it has to be independent of the boost path
    /// rather than merely ordered after it. `SwapGuard` is disarmed by
    /// default, so this asserts what production actually runs when
    /// `ANIMA_SWAP_PROTECT` is unset.
    #[test]
    fn a_disarmed_swapguard_is_inert_and_keeps_no_state() {
        let mut guard = SwapGuard::disarmed_for_test();

        assert!(!guard.is_enabled());

        // Any sequence of focus events, including a repeat and a PID the
        // pool has never seen, must change nothing and never panic.
        for pid in [0, 1, 100, 100, 100_000] {
            guard.set_focus(pid);
        }
        guard.clear();
        guard.teardown();

        assert!(!guard.is_enabled());
        assert!(guard.is_idle_for_test());
    }
}

/* ── main event loop ───────────────────────────────────────────────── */

fn main() -> Result<()> {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let include_children = mode == "window+tree";
    let ev_sock = hypr_sock2().map_err(|e| anyhow::anyhow!("Anima error: {e}"))?;

    /* Swap protection for the focused window: the process owning it is
     * moved into a cgroup with `memory.swap.max = 0`, so what it
     * allocates from now on cannot be pushed out to swap. Off unless
     * ANIMA_SWAP_PROTECT=1/true/on, and every failure is contained — an
     * unusable cgroup leaves the window swappable, which is the
     * pre-existing behaviour, not a regression.
     *
     * Deliberately first, BEFORE the pinned BPF maps are opened: swap
     * protection is a userspace cgroup concern and needs no scheduler or
     * root, while the boost path needs both. Initialising the swapguard
     * after the map open would mean a missing pin (scheduler not loaded)
     * also silently skips swap protection, which makes the two features
     * fail together for reasons that have nothing to do with each other.
     * It must never gate the boost path either. */
    let swapguard: Mutex<SwapGuard> = Mutex::new(SwapGuard::from_env());
    let swapguard = Arc::new(swapguard);
    let swapguard_on_signal = Arc::clone(&swapguard);
    eprintln!(
        "[anima] swapguard: {} (default {})",
        if swapguard.lock().map(|g| g.is_enabled()).unwrap_or(false) {
            "armed"
        } else {
            SWAP_PROTECT_DEFAULT
        },
        SWAP_PROTECT_DEFAULT
    );

    let anima = Arc::new(Mutex::new(match Animamap::open() {
        Ok(a) => a,
        Err(e) => {
            /* The boost path needs root and a running scheduler; swap
             * protection needs neither. Tearing the pool down here keeps a
             * missing pin from leaking cgroups, which would otherwise sit
             * in the user slice holding a `memory.swap.max=0` that nothing
             * is using — and, worse, still holding whatever process was
             * last moved into a slot. */
            if let Ok(mut sg) = swapguard.lock() {
                sg.clear();
                sg.teardown();
            }
            return Err(e).with_context(|| {
                "Cannot open pinned map — is scx_lavd-anima running and pinning \
                 /sys/fs/bpf/anima_active_pids?"
            });
        }
    }));

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

    /* Audio-PID boost: native PipeWire registry subscription. Streams
     * are reported as events, so nothing is polled and a stream stopping
     * is observed directly rather than inferred from a stall. Set
     * ANIMA_AUDIO_BOOST=off to skip subscribing entirely. */
    let anima_for_audio = Arc::clone(&anima);
    let audio_raw =
        std::env::var("ANIMA_AUDIO_BOOST").unwrap_or_else(|_| AUDIO_BOOST_DEFAULT.into());
    let audio_enabled = !audio_raw.eq_ignore_ascii_case("off");
    if audio_enabled {
        let (tx, rx) = mpsc::channel::<AudioEvent>();
        anima_audio::spawn_audio_watcher(tx);
        thread::spawn(move || {
            for event in rx {
                match event {
                    AudioEvent::Started(pid) => {
                        eprintln!("[anima] pipewire: playing pid {pid}");
                    }
                    AudioEvent::Stopped(pid) => {
                        eprintln!("[anima] pipewire: stopped pid {pid}");
                    }
                }

                let mut g = match anima_for_audio.lock() {
                    Ok(g) => g,
                    Err(e) => {
                        eprintln!("[anima] audio: lock: {e}");
                        continue;
                    }
                };
                if let Err(e) = g.audio_event(event) {
                    eprintln!("[anima] audio_event: {e}");
                }
            }
        });
    } else {
        eprintln!("[anima] audio: pipewire subscription disabled (ANIMA_AUDIO_BOOST={audio_raw})");
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
        /* Release every protected process before exiting, or their slot
         * headings stay behind in a tree this daemon no longer runs. */
        if let Ok(mut g) = swapguard_on_signal.lock() {
            g.clear();
            g.teardown();
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
        drop(g);

        /* Swap protection last, and after the boost path has already run
         * to completion: it is the only step here that can fail without
         * costing anything, so it must never be able to interrupt the
         * map update above. A poisoning guard is recovered from rather
         * than propagated for the same reason — swap protection that
         * took down the daemon would be strictly worse than none. */
        match swapguard.lock() {
            Ok(mut sg) => sg.set_focus(pid),
            Err(e) => eprintln!("[anima] swapguard: lock: {e}"),
        }
    }

    /* Graceful exit — clear what we touched. */
    anima
        .lock()
        .map_err(|e| anyhow::anyhow!("lock: {e}"))?
        .clear()?;
    if let Ok(mut sg) = swapguard.lock() {
        sg.clear();
        sg.teardown();
    }
    drop(sub);
    Ok(())
}
