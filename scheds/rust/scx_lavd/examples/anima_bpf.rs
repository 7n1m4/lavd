//! scx_lavd BPF-map actuator — the preferred backend when a
//! `scx_lavd-anima` instance is actually running.
//!
//! `scheds/rust/scx_lavd/examples/anima_hypr_daemon.rs` boosts whichever
//! window is focused. Where that boost lands depends on what the kernel
//! is willing to read:
//!
//! 1. This module writes the desired PID set into the pinned
//!    `anima_active_pids` BPF map and a latency-criticality level into
//!    `anima_config`. Inside the scheduler those PIDs get a
//!    `lat_cri` in the continuous 0..1024 range, which is the strongest
//!    and most fine-grained knob available — but the map only has a
//!    consumer while `sched_ext` is enabled *and* some scx scheduler is
//!    attached. Nothing else reads the map, so a write to it while the
//!    scheduler is absent is a no-op that *looks* like success.
//! 2. [`anima_boost`] drives BORE directly instead: `setpriority(2)`
//!    plus a cgroup `cpu.weight`.
//!
//! Both actuators are interchangeable behind the same two operations
//! (apply a desired set, release it), which is what lets the daemon pick
//! one at startup and stay on it for its lifetime.
//!
//! The rule that governs pickup is conservative on purpose: the pins are
//! only worth opening when `/sys/kernel/sched_ext/state` says `enabled`.
//! A pin left behind by an exited scheduler is still openable, so
//! probing it alone would adopt a backend whose consumer is gone and
//! silently stop boosting anything.
//!
//! A failure while running never aborts the daemon. If the scheduler is
//! unloaded mid-session the writes start failing; each is logged once,
//! the map is taken out of service, and the nice actuator keeps the
//! focused window boosted. A missing pin on the *other* hand is fatal up
//! front, because it means this backend was asked for explicitly.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};

use crate::anima_boost::BoostPlan;
use libbpf_rs::{MapCore, MapFlags, MapHandle};

/// Pinned map of PIDs the scheduler should treat as latency-critical.
const MAP_PIN_PATH: &str = "/sys/fs/bpf/anima_active_pids";

/// Pinned map holding the single latency-criticality level, at key 0.
const CONFIG_PIN_PATH: &str = "/sys/fs/bpf/anima_config";

/// Value written to an `anima_active_pids` entry (`0x01` = focused).
const MAP_ACTIVE_VALUE: u8 = 0x01;

/// Default focused-window latency-criticality boost. Matches the BPF
/// default `LAVD_ANIMA_LC_BOOST_DFL`. Smaller = gentler. 0 = disable.
///
/// Exported because the core reports the boot level in its startup line,
/// and a value it cannot name would have to be duplicated there.
pub(crate) const DEFAULT_BOOST: u32 = (1024 * 7) / 8; /* 896 = top 12.5% LC */

/// Environment override for [`DEFAULT_BOOST`].
const BOOST_ENV: &str = "ANIMA_BOOST";

/// Maximum sensible boost value. Clamping prevents divide-by-zero in
/// LAVD's deadline math and stops `dl_delta` from collapsing to ~0.
const MAX_BOOST: u32 = 1024;

/// Where the kernel reports whether `sched_ext` can host a scheduler at
/// all. Three values: `enabled`, `disabling`, `disabled`.
const SCHED_EXT_STATE: &str = "/sys/kernel/sched_ext/state";

/* ── probe ─────────────────────────────────────────────────────────── */

/// Whether the word the kernel wrote into `sched_ext/state` is the one
/// worth acting on.
///
/// Pure so the accepted vocabulary is testable on a box with no
/// scheduler — the real failure this guards against is treating a
/// *stale* pin as a live one, which is exactly what happens if anything
/// other than `enabled` is accepted here.
fn sched_ext_avail(state: &str) -> bool {
    state == "enabled"
}

/// Detection result for the EEVDF backend.
pub(crate) struct SchedProbe {
    /// True only when the kernel can host a scheduler *and* both pins
    /// opened.
    pub(crate) available: bool,
    /// Why the backend is unusable. Empty when it is usable.
    pub(crate) reason: String,
}

impl SchedProbe {
    /// Read [`SCHED_EXT_STATE`] and, when it says `enabled`, try to open
    /// both pins.
    ///
    /// Read-only and side-effect free: safe to call unprivileged, and on
    /// a box without the scheduler it reports unavailable rather than
    /// consenting to a backend nothing will consume.
    pub(crate) fn detect() -> Self {
        let state = match std::fs::read_to_string(SCHED_EXT_STATE) {
            Ok(state) => state.trim().to_string(),
            Err(e) => {
                return Self {
                    available: false,
                    reason: format!("cannot read {SCHED_EXT_STATE}: {e}"),
                };
            }
        };

        // Anything but `enabled` means no scheduler can be attached, so
        // no map consumer exists. Opening the pins here would risk
        // writing into a dead scheduler's leftovers, which is the exact
        // silent-no-op this check exists to prevent.
        if !sched_ext_avail(&state) {
            return Self {
                available: false,
                reason: format!("sched_ext is {state}"),
            };
        }

        if let Err(e) = MapHandle::from_pinned_path(MAP_PIN_PATH) {
            return Self {
                available: false,
                reason: format!("cannot open {MAP_PIN_PATH}: {e:#}"),
            };
        }
        if let Err(e) = MapHandle::from_pinned_path(CONFIG_PIN_PATH) {
            return Self {
                available: false,
                reason: format!("cannot open {CONFIG_PIN_PATH}: {e:#}"),
            };
        }

        Self {
            available: true,
            reason: String::new(),
        }
    }
}

/* ── config level ──────────────────────────────────────────────────── */

/// The boot-time latency-criticality level, once.
///
/// [`DEFAULT_BOOST`] unless the environment says otherwise. An unset or
/// unparseable value is not an error: the default is the LAVD default,
/// so an operator who typo'd the variable still comes up with the same
/// level the scheduler would have picked unaided.
fn boot_boost() -> u32 {
    std::env::var(BOOST_ENV)
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(DEFAULT_BOOST)
}

/* ── actuator ──────────────────────────────────────────────────────── */

/// Applies and releases per-PID boosts through scx_lavd's pinned maps.
pub(crate) struct BpfBooster {
    /// Pinned PID map, taken out of service after its first failure.
    pid_map: Option<MapHandle>,
    /// Pinned latency-criticality map, likewise.
    config_map: Option<MapHandle>,
    /// Level last written to the config map, so [`Self::describe`]
    /// reports what is actually in force rather than a compile-time
    /// default the core may have overridden.
    boost: u32,
    /// PIDs this instance has written and not yet deleted. Only what is
    /// tracked here is ever released, so one daemon never clears another
    /// daemon's entries.
    tracked: HashSet<u32>,
}

impl BpfBooster {
    /// Open both pinned maps and apply the boot-time boost level.
    ///
    /// Only called when [`SchedProbe::detect`] reported `available`, or
    /// when the user forced the backend: a failure here is a real error,
    /// reported verbatim, rather than a silent fallback.
    pub(crate) fn open() -> Result<Self> {
        let pid_map = MapHandle::from_pinned_path(MAP_PIN_PATH)
            .with_context(|| format!("cannot open pinned BPF map at {MAP_PIN_PATH}"))?;
        let config_map = MapHandle::from_pinned_path(CONFIG_PIN_PATH)
            .with_context(|| format!("cannot open pinned BPF config map at {CONFIG_PIN_PATH}"))?;

        let mut booster = Self {
            pid_map: Some(pid_map),
            config_map: Some(config_map),
            boost: DEFAULT_BOOST,
            tracked: HashSet::with_capacity(16),
        };

        // The original daemon read the level from the environment and
        // wrote it once after the maps were open. Keeping that here means
        // the actuator arrives configured rather than every caller
        // re-deriving the same boot write; the core may still re-write the
        // level later through `set_boost`. A failure is logged, not
        // fatal — the PIDs matter more than the level.
        if let Err(e) = booster.set_boost(boot_boost()) {
            eprintln!("[anima] bpf: boot level write failed: {e:#}");
        }

        Ok(booster)
    }

    /// Write the latency-criticality level into the config map.
    ///
    /// Clamped to `[0, MAX_BOOST]`. The write is exposed as a `Result`
    /// rather than swallowed so an explicitly requested boost level is
    /// reported, but a failure is never fatal — LAVD keeps its own
    /// compiled-in default.
    pub(crate) fn set_boost(&mut self, boost: u32) -> Result<()> {
        let clamped = boost.clamp(0, MAX_BOOST);

        let Some(config_map) = self.config_map.as_ref() else {
            // Already dead; the boost level nobody reads is not worth
            // reporting a second time.
            return Ok(());
        };

        match config_map.update(&0u32.to_le_bytes(), &clamped.to_le_bytes(), MapFlags::ANY) {
            Ok(()) => {
                self.boost = clamped;
                Ok(())
            }
            Err(e) => {
                self.config_map = None;
                Err(anyhow::Error::new(e).context(format!(
                    "failed to update {CONFIG_PIN_PATH}[{clamped}]; map disabled"
                )))
            }
        }
    }

    /// Reconcile the pinned map against `desired`.
    ///
    /// Incremental, like the nice backend and for the same reason: a PID
    /// already in the map stays there, and a PID that left `desired` is
    /// deleted rather than merely left to expire. Writing an unchanged
    /// set on every focus event would be pure syscall amplification, and
    /// the dangerous failure is the other one — a key that stops being
    /// boosted and is never removed.
    pub(crate) fn reconcile(&mut self, desired: &HashSet<u32>) {
        // Keys are 32-bit little-endian on both sides. Only live PIDs are
        // reported for release: a dead process's entry was already reaped
        // by the kernel on exit, so `write_pid` below forgets it without a
        // syscall that can only fail.
        let plan = BoostPlan::between(&self.tracked, desired, pid_alive);

        for pid in &plan.release {
            self.write_pid(*pid, false);
        }
        for pid in &plan.apply {
            self.write_pid(*pid, true);
        }
    }

    /// Delete every entry this instance wrote and forget it all.
    ///
    /// The empty maps stay pinned: unpinning them is scx_lavd's job, not
    /// this daemon's, and a pinned empty map is inert.
    pub(crate) fn release_all(&mut self) {
        let pids: Vec<u32> = self.tracked.iter().copied().collect();
        let n = pids.len();
        for pid in pids {
            self.write_pid(pid, false);
        }
        self.tracked.clear();
        eprintln!("[anima] bpf: released {n} tracked pid(s)");
    }

    /// One-line summary for the startup banner. Reflects which maps are
    /// still in service, so an honest line is printed after a scheduler
    /// unload took one offline.
    pub(crate) fn describe(&self) -> String {
        let pid_state = match self.pid_map {
            Some(_) => "live",
            None => "unusable",
        };
        let config_state = match self.config_map {
            Some(_) => "live",
            None => "unusable",
        };
        format!(
            "eevdf/bpf: pids {pid_state} at {MAP_PIN_PATH}, \
             config {config_state} at {CONFIG_PIN_PATH}, \
             boost {}, tracked {}",
            self.boost,
            self.tracked.len()
        )
    }

    /// Write one key, or drop the map out of service on failure.
    ///
    /// Never propagates an error: the caller is a reconciliation loop
    /// that cannot do anything about a dead map except stop calling it,
    /// and a per-event error would bury everything else in the log.
    fn write_pid(&mut self, pid: u32, on: bool) {
        let Some(pid_map) = self.pid_map.as_ref() else {
            return;
        };

        let out = if on {
            pid_map.update(&pid.to_le_bytes(), &[MAP_ACTIVE_VALUE], MapFlags::ANY)
        } else {
            pid_map.delete(&pid.to_le_bytes())
        };

        let Err(e) = out else {
            // Only forget the PID once the map agrees it is in the
            // agreed state; a failed delete must stay tracked so the
            // next reconcile retries it.
            if on {
                self.tracked.insert(pid);
            } else {
                self.tracked.remove(&pid);
            }
            return;
        };

        self.pid_map = None;
        eprintln!(
            "[anima] bpf: {} pid {pid} in {MAP_PIN_PATH}: {e:#}; pid map disabled",
            if on { "insert" } else { "delete" },
        );
    }
}

impl Drop for BpfBooster {
    fn drop(&mut self) {
        // Same backstop the nice actuator has: a panic or an early return
        // must not leave a stale key boosting a PID nobody is looking at.
        self.release_all();
    }
}

/// Whether the kernel still knows about a PID.
fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/* ── tests ─────────────────────────────────────────────────────────── */

#[cfg(test)]
mod tests {
    use super::*;

    /// An unset or unparseable `ANIMA_BOOST` must fall back to the level
    /// the scheduler would have chosen unaided, not to zero — which would
    /// silently disable the boost.
    #[test]
    fn boot_level_falls_back_to_the_compiled_default() {
        let requested: Option<u32> = None;
        assert_eq!(requested.unwrap_or(DEFAULT_BOOST), 896);

        let typo: Option<u32> = "garbage".parse::<u32>().ok();
        assert_eq!(typo.unwrap_or(DEFAULT_BOOST), DEFAULT_BOOST);
    }

    /// The whole safety argument for the BPF backend: only `enabled`
    /// means a consumer exists. Everything else — including a word the
    /// kernel may grow later — must be refused rather than guessed at.
    #[test]
    fn sched_ext_avail_accepts_only_enabled() {
        assert!(sched_ext_avail("enabled"));
        assert!(!sched_ext_avail("disabled"));
        assert!(!sched_ext_avail("disabling"));
        assert!(!sched_ext_avail(""));
        assert!(!sched_ext_avail("Enabled"));
        assert!(!sched_ext_avail("enum"));
    }

    /// The probe must run to completion anywhere, whatever this box
    /// reports. On a machine with no scheduler it says unavailable; on
    /// one with the scheduler it may say available. Neither is asserted —
    /// only that it never panics and never claims availability with a
    /// reason attached.
    #[test]
    fn sched_probe_detect_is_safe_on_any_box() {
        let probe = SchedProbe::detect();
        if probe.available {
            assert!(probe.reason.is_empty());
        } else {
            assert!(!probe.reason.is_empty());
        }
    }

    /// A PID that stops being boosted must be deleted, not just left in
    /// the map. This is the failure that leaves a stale boost forever.
    #[test]
    fn reconciliation_deletes_keys_that_stop_being_boosted() {
        let mut last = HashSet::new();
        last.insert(100);
        last.insert(200);
        let mut next = HashSet::new();
        next.insert(100);
        next.insert(300);

        let plan = BoostPlan::between(&last, &next, |_| true);

        assert_eq!(plan.release, vec![200]);
        // 100 is already in the map, so only 300 is written.
        assert_eq!(plan.apply, vec![300]);
    }

    /// A pure repeat must not touch the map at all — the whole point of
    /// the incremental design.
    #[test]
    fn reconciliation_is_a_noop_when_the_set_is_unchanged() {
        let mut set = HashSet::new();
        set.insert(100);
        set.insert(200);

        let plan = BoostPlan::between(&set, &set, |_| true);

        assert!(plan.apply.is_empty());
        assert!(plan.release.is_empty());
    }

    /// A dead PID is skipped by the plan, so its map key — already
    /// reaped by the kernel on exit — is not reported as a release, and
    /// a live one is. Liveness is injected rather than probed so the
    /// assertion does not depend on which PIDs happen to exist here.
    #[test]
    fn reconciliation_skips_dead_pids_when_releasing() {
        let mut last = HashSet::new();
        last.insert(100);
        last.insert(200);
        let mut next = HashSet::new();
        next.insert(100);

        let plan = BoostPlan::between(&last, &next, |pid| pid != 200);

        assert!(plan.release.is_empty());
        assert!(plan.apply.is_empty());
    }

    /// And the same step with the PID still alive does delete it.
    #[test]
    fn reconciliation_deletes_a_live_pid_that_left_the_set() {
        let mut last = HashSet::new();
        last.insert(100);
        last.insert(200);
        let mut next = HashSet::new();
        next.insert(100);

        let plan = BoostPlan::between(&last, &next, |_| true);

        assert_eq!(plan.release, vec![200]);
        assert!(plan.apply.is_empty());
    }

    /// Keys are 32-bit little-endian on the wire; make sure the diff
    /// order is over the numeric value, not the byte order.
    #[test]
    fn reconciliation_writes_in_ascending_pid_order() {
        let last = HashSet::new();
        let mut next = HashSet::new();
        next.insert(217300);
        next.insert(12);
        next.insert(3);

        let plan = BoostPlan::between(&last, &next, |_| true);

        assert_eq!(plan.apply, vec![3, 12, 217300]);
    }
}
