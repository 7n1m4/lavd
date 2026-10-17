//! BORE/EEVDF boost backend — the per-task actuator used when no
//! `scx_lavd` instance is running.
//!
//! The original backend wrote focused PIDs into a pinned BPF map that
//! `scx_lavd` consumed inside `lat_cri.bpf.c`. That path requires
//! `sched_ext` (the `scx_loader` machinery), which is `disabled` on
//! machines booted into a BORE-patched kernel. This module replaces the
//! map with knobs BORE actually reads from userspace:
//!
//! 1. `setpriority(2)` — `nice` feeds `p->static_prio`, and BORE's
//!    `effective_prio_bore()` (`static_prio - MAX_RT_PRIO +
//!    bore_score(p)`) is what `set_load_weight()` uses to pick the
//!    EEVDF weight. Lowering nice therefore widens the CPU share of the
//!    focused task *through BORE's own scaling*.
//! 2. `cpu.weight` in a daemon-owned cgroup — the EEVDF weight is the
//!    amplifier nice cannot reach on its own; moving a process into a
//!    child cgroup with a raised weight gives it a share far beyond the
//!    40:1 nice range.
//!
//! Interaction with ananicy-cpp was measured on this box before either
//! knob was used: ananicy matches processes by `comm`/`cmdline`, applies
//! a rule once when a PID is first seen, and never re-applies it later
//! (verified across three full `check_freq` cycles). A `nice` written
//! here after that point is therefore stable, and the reverse — ananicy
//! setting `sched=idle` on a process — is also stable: see
//! [`NiceTarget::apply`] for the SCHED_IDLE caveat.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const FILE_CPU_WEIGHT: &str = "cpu.weight";
const FILE_PROCS: &str = "cgroup.procs";

/// Caching tranche for the boost, under the delegated user slice.
/// Deliberately *not* a swap-protection slot: those carry
/// `memory.swap.max = 0`, and pinning the focused window's memory out of
/// swap is the swap guard's job, not the boost's.
const BOOST_CGROUP: &str = "anima_boost";

/// Neutral leaf a release falls back to when the process's own cgroup is
/// gone or refuses the write.
///
/// A *leaf*, not the boost cgroup's parent: the parent carries
/// `cpu memory pids` in its `subtree_control`, and cgroup v2 refuses to
/// host a process in an internal node that has controllers delegated
/// through it. Writing one there fails with EBUSY, which was found by
/// running this — the fallback is what makes the difference between
/// "reported a failure and left the boost in place" and "actually
/// released".
const RELEASE_CGROUP: &str = "anima_released";

/// Path of the boost cgroup itself. Set by the root system unit to anchor
/// the boost under the session's delegated slice; unset means derive it
/// from the daemon's own cgroup.
const ENV_BOOST_CGROUP: &str = "ANIMA_BOOST_CGROUP";

/// Requested boost for the focused window, expressed as a nice value.
/// The unitless `ANIMA_BOOST` 0..1024 scale of the BPF backend has no
/// meaning under BORE, so the knob is now literally a nice level
/// (`-20`..`19`). Default `-10`: strong enough to beat a compiler at
/// nice 1, and far enough from `-20` that an RT task cannot be
/// displaced by it — with `sched_idle` reserved for the kernel, `-20`
/// would be no worse than `-10` here anyway, since the focused window is
/// an interactive task competing against nice-0..1 workloads.
pub(crate) const DEFAULT_BOOST_NICE: i32 = -10;

/// Cgroup CPU weight while boosted. EEVDF default is 100; the valid
/// range is 1..=10000. A value of 500 gives the focused window a 5x
/// share of the machine against unweighted siblings — the amplification
/// nice alone cannot provide.
pub(crate) const DEFAULT_BOOST_CPU_WEIGHT: u32 = 500;

/// Bound on the nice range the kernel accepts.
const NICE_RANGE: std::ops::RangeInclusive<i32> = -20..=19;

/// Bounds on the `cpu.weight` range the kernel accepts.
const CPU_WEIGHT_RANGE: std::ops::RangeInclusive<u32> = 1..=10_000;

/// Bit of `CAP_SYS_NICE` in the kernel's capability sets.
///
/// `libc` does not export the individual capability bits, and the value
/// is fixed by the kernel's `include/linux/capability.h` (it has never
/// moved). Read out of `CapEff` by [`Booster::has_cap_sys_nice`].
const CAP_SYS_NICE_BIT: u32 = 23;

/* ── desired state (pure, testable) ────────────────────────────────── */

/// The state update one reconciliation step should perform.
///
/// Kept separate from the syscalls so the transition logic — the part
/// that can actually be wrong — is testable without root.
#[derive(Default, PartialEq, Eq, Debug)]
pub(crate) struct BoostPlan {
    /// PIDs to raise in priority.
    pub(crate) apply: Vec<u32>,
    /// PIDs to return to their recorded baseline lazily.
    pub(crate) release: Vec<u32>,
}

/// Per-PID pre-boost state, so a release restores what was actually
/// there rather than assuming 0.
///
/// A process that already ran negative (a game ananicy niced to -5, or
/// the compositor) must come back to that value, not to 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Baseline {
    /// `nice` before the boost.
    pub(crate) nice: i32,
    /// Cgroup the process was moved out of, if a cgroup boost was applied.
    pub(crate) cgroup: Option<PathBuf>,
}

impl BoostPlan {
    /// Diff `last` against `next`.
    ///
    /// A PID present in both sets is untouched: a boost already applied
    /// is a fact about the process, not about the event, and rewriting it
    /// on every focus event would be pure syscall amplification. This is
    /// the same incremental-diff invariant the BPF backend used, for the
    /// same reason — the dangerous failure is a PID that stops being
    /// boosted and never gets released.
    pub(crate) fn between(
        last: &HashSet<u32>,
        next: &HashSet<u32>,
        alive: impl Fn(u32) -> bool,
    ) -> Self {
        let mut apply: Vec<u32> = next.difference(last).copied().collect();
        apply.sort_unstable();

        // Demoted is not the same as gone: a PID that exited has nothing
        // left to write to, so it is left for the dead sweep to forget,
        // which keeps `release` meaningful as "still-restorable".
        let mut release: Vec<u32> = last
            .difference(next)
            .copied()
            .filter(|pid| alive(*pid))
            .collect();
        release.sort_unstable();

        Self { apply, release }
    }

    /// Nothing to do. Only the tests assert this directly; the actuator
    /// has no use for it, since an empty plan already costs nothing.
    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.apply.is_empty() && self.release.is_empty()
    }
}

/* ── actuator ──────────────────────────────────────────────────────── */

/// Applies and releases per-task boosts via nice and cgroup weight.
pub(crate) struct Booster {
    /// Where the boost cgroup lives once set up.
    boost_dir: Option<PathBuf>,
    /// Neutral leaf for releases whose own cgroup is unavailable.
    release_dir: Option<PathBuf>,
    /// Nice level to write on apply.
    boost_nice: i32,
    /// `cpu.weight` written into the boost cgroup on setup.
    boost_cpu_weight: u32,
    /// PIDs currently boosted.
    applied: HashSet<u32>,
    /// Baseline state recorded per boosted PID.
    baselines: HashMap<u32, Baseline>,
}

impl Booster {
    pub(crate) fn from_env() -> Self {
        let boost_nice = std::env::var("ANIMA_BOOST_NICE")
            .ok()
            .and_then(|s| s.parse::<i32>().ok())
            .map(|n| n.clamp(*NICE_RANGE.start(), *NICE_RANGE.end()))
            .unwrap_or(DEFAULT_BOOST_NICE);

        let boost_cpu_weight = std::env::var("ANIMA_BOOST_CPU_WEIGHT")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .map(|w| w.clamp(*CPU_WEIGHT_RANGE.start(), *CPU_WEIGHT_RANGE.end()))
            .unwrap_or(DEFAULT_BOOST_CPU_WEIGHT);

        let mut booster = Self {
            boost_dir: None,
            release_dir: None,
            boost_nice,
            boost_cpu_weight,
            applied: HashSet::new(),
            baselines: HashMap::new(),
        };
        booster.setup_cgroup();
        booster
    }

    /// The directory the boost cgroup should live in.
    ///
    /// An explicit `ANIMA_BOOST_CGROUP` wins: it is how a root system
    /// service anchors the boost under the session's own delegated slice
    /// rather than the root cgroup the daemon would otherwise derive.
    /// Without it, [`delegated_slice`] reads the daemon's own
    /// `/proc/self/cgroup`, which lands on the correct slice when the
    /// daemon runs inside that session and on the root otherwise.
    fn boost_cgroup_dir(&self) -> Option<PathBuf> {
        if let Some(dir) = std::env::var_os(ENV_BOOST_CGROUP) {
            // An explicit path is trusted as given; it names the boost
            // cgroup itself, not a parent, so nothing is joined onto it.
            return Some(PathBuf::from(dir));
        }
        delegated_slice().map(|slice| slice.join(BOOST_CGROUP))
    }

    /// Create the boost cgroup, delegating the cpu controller into it.
    ///
    /// Failure is not fatal in the sense of stopping the daemon: the nice
    /// half of the boost still works, so the cgroup is simply absent and
    /// [`Self::apply`] degrades to nice-only. That is reported, not
    /// swallowed.
    fn setup_cgroup(&mut self) {
        let Some(boost_dir) = self.boost_cgroup_dir() else {
            eprintln!("[anima] boost: cannot locate delegated user slice; nice-only boost in use");
            return;
        };

        if let Err(e) = create_dir(&boost_dir) {
            eprintln!(
                "[anima] boost: cannot create {}: {e}; nice-only boost in use",
                boost_dir.display()
            );
            return;
        }
        if let Err(e) = std::fs::write(
            boost_dir.join(FILE_CPU_WEIGHT),
            self.boost_cpu_weight.to_string(),
        ) {
            eprintln!(
                "[anima] boost: cannot set cpu.weight {} in {}: {e}; nice-only boost in use",
                self.boost_cpu_weight,
                boost_dir.display()
            );
            return;
        }
        eprintln!(
            "[anima] boost: cgroup {} (cpu.weight {})",
            boost_dir.display(),
            self.boost_cpu_weight
        );
        self.boost_dir = Some(boost_dir.clone());

        // Sibling leaf, so a release can always land somewhere real. Its
        // absence is not fatal: the release then simply reports the
        // process still in the boost cgroup, which is the pre-existing
        // behaviour rather than a regression. Created before the sweep
        // below, since the sweep uses it as its target.
        let release_dir = boost_dir.with_file_name(RELEASE_CGROUP);
        match create_dir(&release_dir) {
            Ok(()) => self.release_dir = Some(release_dir),
            Err(e) => eprintln!(
                "[anima] boost: cannot create release cgroup {}: {e}; \
                 a release will leave processes in the boost cgroup",
                release_dir.display()
            ),
        }

        self.reclaim_orphans();
    }

    /// Release processes a previous daemon instance left in the boost
    /// cgroup.
    ///
    /// A crash loses the in-memory baselines, so the surviving processes
    /// are stranded: this daemon has no record of what their nice was, and
    /// without a sweep they would keep the elevated weight for as long as
    /// they live. Observed on this box — three shells stayed behind after a
    /// pre-restart instance died.
    ///
    /// The nice value is left alone rather than guessed at: writing 0
    /// would clobber whatever ananicy-cpp had set, which is a worse
    /// outcome than one priority level left raised. Only the weight is
    /// reclaimed, by moving the process out of the cgroup, and that is
    /// done immediately so the boost does not persist past this startup.
    fn reclaim_orphans(&mut self) {
        let Some(dir) = self.boost_dir.clone() else {
            return;
        };
        let Ok(text) = std::fs::read_to_string(dir.join(FILE_PROCS)) else {
            return;
        };
        // A boost cgroup exists, so there is always somewhere to send an
        // orphan: the sibling leaf, or the boost cgroup itself when the
        // leaf was never created. Without a target the sweep would have
        // no meaning — there is nothing to reclaim out of.
        let Some(target) = self.boost_release_target() else {
            return;
        };
        for pid in text.lines().filter_map(|l| l.trim().parse::<u32>().ok()) {
            if self.applied.contains(&pid) {
                continue;
            }
            match migrate(target, pid) {
                Ok(()) => {
                    eprintln!("[anima] boost: reclaimed orphan pid {pid} out of the boost cgroup")
                }
                // A member that exited on its own is the common case, and
                // is exactly as good as a successful migration.
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
                Err(e) => {
                    eprintln!("[anima] boost: cannot reclaim orphan pid {pid}: {e}")
                }
            }
        }
    }

    /// Record a baseline, then apply the boost to `pid`.
    ///
    /// Ordering matters: the baseline is read before anything is written,
    /// so a failed boost never leaves a bogus baseline claiming the
    /// process was at the boosted value.
    pub(crate) fn apply(&mut self, pid: u32) {
        if pid < 1 || !pid_alive(pid) || self.applied.contains(&pid) {
            return;
        }

        let baseline = Baseline {
            nice: current_nice(pid).unwrap_or(0),
            cgroup: self.boost_dir.as_ref().and_then(|_| cgroup_of(pid)),
        };

        // Cgroup first: it can fail without invalidating the nice write,
        // and it is the weight change that makes the boost visible.
        // Note the *weights* are compared, not the paths: a process
        // already in the boost cgroup (focus returning to the same
        // window) must not be re-migrated.
        if let Some(dir) = self.boost_dir.as_ref() {
            match migrate(dir, pid) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => return,
                Err(e) if e.raw_os_error() == Some(libc::EACCES) => {
                    eprintln!(
                        "[anima] boost: cannot move pid {pid} into {}: {e}; nice-only",
                        dir.display()
                    );
                }
                Err(e) => {
                    eprintln!(
                        "[anima] boost: cannot move pid {pid} into {}: {e}",
                        dir.display()
                    );
                    return;
                }
            }
        }

        if let Err(e) = set_nice(pid, self.boost_nice) {
            if e.raw_os_error() == Some(libc::ESRCH) {
                return;
            }
            // EPERM here is the expected shape of an unprivileged run:
            // raising above the caller's own nice requires CAP_SYS_NICE.
            eprintln!("[anima] boost: cannot nice pid {pid}: {e}");
            return;
        }

        trace_apply(pid, self.boost_nice, self.boost_dir.as_deref());
        self.applied.insert(pid);
        self.baselines.insert(pid, baseline);
    }

    /// Restore `pid` to its recorded baseline and forget it.
    ///
    /// A release must never leave the process behind in the boost
    /// cgroup: a stranded boost is the one failure that silently makes
    /// the daemon worse than nothing. That is a real case here — a
    /// window+tree child lives inside its parent's own systemd scope
    /// (`kitty-11250-0.scope`), and that scope is removed as soon as the
    /// child exits, so the recorded source no longer exists by the time
    /// the release runs. The original cgroup is therefore tried first,
    /// and the daemon's own delegated slice is used as the fallback: it
    /// always exists, it accepts the write, and it carries no boost
    /// weight.
    pub(crate) fn release(&mut self, pid: u32) {
        if pid < 1 {
            return;
        }
        /* Idempotent, and the removal is what makes it so: a PID already
         * released — whether by a previous focus change or by the release
         * loop over it — has nothing left to undo and must not touch the
         * process again. Before this guard, a PID boosted and released
         * repeatedly within one focus burst could be written to twice. */
        let baseline = match (self.applied.remove(&pid), self.baselines.remove(&pid)) {
            (true, Some(b)) => b,
            // A tracked application with no recorded baseline is the one
            // case worth shouting about: the process is still in the
            // boost cgroup and this cannot get it out.
            (true, None) => {
                eprintln!("[anima] boost: pid {pid} is boosted but has no recorded baseline");
                self.release_from_cgroup(pid);
                return;
            }
            _ => return,
        };

        if self.boost_dir.is_some() {
            // The original cgroup is preferred and is usually writable,
            // which keeps the boost cgroup permanently empty.
            let restored = match baseline.cgroup.as_ref() {
                Some(source) => match migrate(source, pid) {
                    Ok(()) => true,
                    Err(e) if e.raw_os_error() == Some(libc::ESRCH) => true,
                    Err(e) => {
                        trace_release_fallback(pid, source, &e);
                        false
                    }
                },
                None => false,
            };

            if !restored {
                self.release_from_cgroup(pid);
            }
        }

        set_nice_or_log(pid, baseline.nice);
    }

    /// Move `pid` out of the boost cgroup by any route that works.
    ///
    /// A release that cannot move the process is the one failure with no
    /// recovery path, so it is reported even on the ESRCH case — a process
    /// that no longer exists still might be *listed* in the boost cgroup,
    /// and the difference is exactly what `prune_dead` exists to notice.
    fn release_from_cgroup(&self, pid: u32) {
        // No cgroup means nothing was ever moved, so there is nothing to
        // undo: the nice write is the entire release. Returning early is
        // what makes the unprivileged deployment whole rather than
        // merely non-fatal.
        let Some(target) = self.boost_release_target() else {
            return;
        };
        // The target is a sibling leaf, NOT the boost cgroup's parent: the
        // parent carries `cpu memory pids` in its `subtree_control`, and
        // cgroup v2 refuses a process in an internal node that delegates
        // controllers — writing there fails with EBUSY and strands the
        // process in the boost cgroup. Found by running this, not reading.
        if let Err(e) = migrate(target, pid) {
            if e.raw_os_error() != Some(libc::ESRCH) {
                eprintln!("[anima] boost: cannot return pid {pid} out of the boost cgroup: {e}");
            }
        }
    }

    /// Where a release puts a process it could not return home.
    ///
    /// The sibling leaf — always exists once setup ran, always accepts
    /// the write, and carries no boost weight.
    ///
    /// `None` when no boost cgroup was ever set up, which is the whole
    /// point of returning an `Option`: with no boost cgroup there is
    /// nothing to move out *of*, so a release has no destination to
    /// guess, and inventing one actively harms. The old fallback was the
    /// cgroup root, and that is worse than doing nothing —
    /// `/sys/fs/cgroup` carries `cpuset cpu io memory pids` in its
    /// `subtree_control`, so it is an internal node the kernel refuses a
    /// process in (EBUSY), and an unprivileged daemon writes EACCES
    /// against it on every release. Neither outcome moves a process that
    /// was never moved into a daemon-owned cgroup; both are pure noise.
    ///
    /// The *boost* directory gates the answer, not the leaf: a leaf left
    /// over from a boost cgroup that failed to materialise is not a
    /// destination, because nothing was ever migrated into it.
    fn boost_release_target(&self) -> Option<&Path> {
        self.boost_dir.as_deref()?;
        // A boost cgroup with no sibling leaf: the boost directory itself
        // is the only place the process can be, and leaving it there is
        // the pre-existing behaviour reported to the operator.
        Some(
            self.release_dir
                .as_deref()
                .unwrap_or_else(|| self.boost_dir.as_deref().expect("boost cgroup is live")),
        )
    }

    /// Release every boosted PID. Called on shutdown and on restart, so a
    /// crash cannot leave the focused window permanently boosted.
    ///
    /// The PID list is collected first: `release` removes from `applied`,
    /// so iterating it directly would skip entries. A release that fails
    /// leaves its PID in the set, and the sweep below is the backstop that
    /// keeps a failed release from being reported as a success.
    pub(crate) fn release_all(&mut self) {
        let pids: Vec<u32> = self.applied.iter().copied().collect();
        let n = pids.len();
        for pid in pids {
            self.release(pid);
        }
        // Anything that survived its own release is still in the boost
        // cgroup; move it out and drop it so the next start is clean.
        let leftovers: Vec<u32> = self
            .applied
            .iter()
            .copied()
            .chain(self.baselines.keys().copied())
            .collect();
        for pid in leftovers {
            self.release_from_cgroup(pid);
        }
        self.applied.clear();
        self.baselines.clear();
        eprintln!("[anima] boost: released {n} boosted pid(s)");
    }

    /// Release PIDs that no longer exist, so their baselines do not
    /// accumulate and the boost cgroup does not fill with zombies.
    pub(crate) fn prune_dead(&mut self) {
        let dead: Vec<u32> = self
            .applied
            .iter()
            .copied()
            .filter(|pid| !pid_alive(*pid))
            .collect();
        for pid in dead {
            self.applied.remove(&pid);
            self.baselines.remove(&pid);
        }
    }

    /// Reconcile against a desired set: apply the gained, release the lost.
    pub(crate) fn reconcile(&mut self, desired: &HashSet<u32>) {
        let plan = BoostPlan::between(&self.applied, desired, pid_alive);
        for pid in &plan.release {
            self.release(*pid);
        }
        for pid in &plan.apply {
            self.apply(*pid);
        }
        self.prune_dead();
    }

    /// One line naming the actuator's live configuration and state.
    ///
    /// Both halves are reported, including the absent one: an empty
    /// `boost_dir` is *not* a misconfiguration to hide, it is the
    /// nice-only mode a deployment lands in when the cgroup could not be
    /// created, and the only useful startup line is the one that says so.
    pub(crate) fn describe(&self) -> String {
        let kind = match self.boost_dir.as_deref() {
            Some(_) => "nice + cgroup cpu.weight",
            None => "nice only (no cgroup)",
        };
        let mut line = format!(
            "{} nice={} cpu_weight={}",
            kind, self.boost_nice, self.boost_cpu_weight
        );
        if let Some(dir) = self.boost_dir.as_deref() {
            line.push_str(&format!(" cgroup={}", dir.display()));
        }
        if let Some(note) = self.privilege_note() {
            line.push_str(&format!("; {}", note));
        }
        line
    }

    /// Why the daemon is running unprivileged, or `None` when it has the
    /// capability it needs.
    ///
    /// The whole value of this backend is the negative nice level, which
    /// needs `CAP_SYS_NICE` to lower *another* process's priority; an
    /// unprivileged daemon can still nice itself, but the window it is
    /// asked to boost stays at nice 0.
    ///
    /// Note the ordering this implies: with the cgroup in place the
    /// daemon definitely has the privilege — creating that directory
    /// under a slice the user already owns needs nothing, and writing
    /// `cgroup.procs` needs at most `CAP_DAC_OVERRIDE` — so a live
    /// cgroup answers the question directly. Otherwise the capability is
    /// probed without trusting the cgroup half.
    ///
    /// [`Self::has_cap_sys_nice`] is the probe; it avoids the
    /// `setpriority` self-test entirely. See its comment for why the
    /// self-test cannot answer this question.
    pub(crate) fn privilege_note(&self) -> Option<String> {
        if self.boost_dir.is_some() {
            return None;
        }
        if self.has_cap_sys_nice() {
            return None;
        }
        Some(
            "unprivileged: CAP_SYS_NICE missing, boosts stay at nice 0 \
             (cpu.weight half is off)"
                .to_string(),
        )
    }

    /// Whether this process holds `CAP_SYS_NICE`, read from `CapEff`.
    ///
    /// This is not the `setpriority(PRIO_PROCESS, 0, -1)` self-test that
    /// looks obvious, and deliberately so: the kernel lets a task lower
    /// *its own* priority regardless of `CAP_SYS_NICE`, so that probe
    /// answers a different question. Measured on this box — the current
    /// process starts at nice -4, drops itself to -1 with no capability
    /// at all, then fails with EPERM trying to nice a *child* by the same
    /// amount. Worse, the self-test is only informative at nice 0: from
    /// any negative starting value the test succeeds up to the start
    /// value and reports "has the capability" whether or not it does.
    /// `/proc/self/status` is the same bit the kernel consults, costs one
    /// file read and has no side effect on any task.
    fn has_cap_sys_nice(&self) -> bool {
        let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
            // Unreadable status is not evidence of a missing capability;
            // the daemon was started, so it is more likely a restricted
            // /proc than an absent privilege. Say nothing rather than
            // claim a capability the box never had.
            return true;
        };
        status
            .lines()
            .find_map(|l| l.strip_prefix("CapEff:"))
            .and_then(|raw| u64::from_str_radix(raw.trim(), 16).ok())
            .is_some_and(|eff| eff & (1u64 << CAP_SYS_NICE_BIT) != 0)
    }
}

impl Drop for Booster {
    fn drop(&mut self) {
        // A release is attempted, but the cgroup itself is intentionally
        // left in place: removing it while another daemon instance could
        // still be writing into it races, and an empty cgroup is inert.
        self.release_all();
    }
}

/* ── per-task writes ───────────────────────────────────────────────── */

/// Read a process's current nice value from `/proc/<pid>/stat`.
fn current_nice(pid: u32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Field 19 overall; comm may contain spaces/parens, so split after the
    // final ')'. Field 3 (state) follows, making nice offset 16 there.
    let after = stat.rfind(')')? + 2;
    let fields: Vec<&str> = stat[after..].split_whitespace().collect();
    fields.get(16)?.parse::<i32>().ok()
}

/// Write `nice` for `pid`.
///
/// `setpriority` operates on a *thread group* leader, i.e. the process,
/// which is what a focus event names.
fn set_nice(pid: u32, nice: i32) -> std::io::Result<()> {
    // SAFETY: a plain libc call; `pid` is a plain u32.
    let rc = unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, nice) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn set_nice_or_log(pid: u32, nice: i32) {
    if let Err(e) = set_nice(pid, nice) {
        if e.raw_os_error() != Some(libc::ESRCH) {
            eprintln!("[anima] boost: cannot restore nice {nice} for pid {pid}: {e}");
        }
    }
}

/// Report a release whose original cgroup refused or vanished.
///
/// ENOENT is the ordinary case and is worth an explanation, since it is
/// the shape of the transient-scope race the fallback exists for: a
/// window+tree child's scope disappears with the child, so a release
/// that arrives afterwards has nowhere to return it to.
fn trace_release_fallback(pid: u32, source: &Path, e: &std::io::Error) {
    match e.raw_os_error() {
        Some(libc::ENOENT) => eprintln!(
            "[anima] boost: pid {pid}'s original cgroup {} is already gone; \
             returning it to the release cgroup instead",
            source.display()
        ),
        _ => eprintln!(
            "[anima] boost: pid {pid} refused by {}: {e}; using the release cgroup",
            source.display()
        ),
    }
}

fn trace_apply(pid: u32, nice: i32, cgroup: Option<&Path>) {
    let where_ = match cgroup {
        Some(p) => format!(" in {}", p.display()),
        None => " (nice only)".to_string(),
    };
    eprintln!("[anima] boost: pid {pid} nice {nice}{where_}");
}

/* ── cgroup plumbing ───────────────────────────────────────────────── */

fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn create_dir(path: &Path) -> std::io::Result<()> {
    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

fn migrate(dest: &Path, pid: u32) -> std::io::Result<()> {
    std::fs::write(dest.join(FILE_PROCS), pid.to_string())
}

/// The cgroup a process currently belongs to, mapped into the v2 root.
fn cgroup_of(pid: u32) -> Option<PathBuf> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let rel = text.lines().find_map(|l| l.strip_prefix("0::"))?;
    Some(Path::new(CGROUP_ROOT).join(rel.trim().trim_matches('/')))
}

/// The nearest ancestor with delegated controllers.
///
/// Same derivation as the swap guard's `own_cgroup()`: the daemon runs
/// in a scope, whose own `cgroup.subtree_control` is empty, so the
/// `user@<uid>.service` element is the writable point. Returns `None`
/// when the path cannot be parsed, which leaves the caller on the
/// nice-only path.
fn delegated_slice() -> Option<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = text.lines().find_map(|l| l.strip_prefix("0::"))?;
    let mut parts: Vec<&str> = rel.trim().trim_end_matches('/').split('/').collect();
    while let Some(last) = parts.last() {
        if last.starts_with("user@") && last.ends_with(".service") {
            return Some(Path::new(CGROUP_ROOT).join(parts.join("/")));
        }
        parts.pop();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pids(values: &[u32]) -> HashSet<u32> {
        values.iter().copied().collect()
    }

    fn all_alive(_: u32) -> bool {
        true
    }

    /* ── plan ───────────────────────────────────────────────────────── */

    /// Focus moving from 100 to 200 must release 100 and apply 200 —
    /// leaving 100 boosted is the failure that makes the daemon worse
    /// than nothing.
    #[test]
    fn focus_change_releases_the_old_pid_and_applies_the_new_one() {
        let plan = BoostPlan::between(&pids(&[100]), &pids(&[200]), all_alive);

        assert_eq!(plan.apply, vec![200]);
        assert_eq!(plan.release, vec![100]);
    }

    /// Re-applying the same focus must cost nothing: 100 is a fact, not
    /// an event.
    #[test]
    fn a_repeated_focus_is_a_noop() {
        let plan = BoostPlan::between(&pids(&[100]), &pids(&[100]), all_alive);

        assert!(plan.is_empty());
    }

    /// Audio holds 300 while focus moves 100 → 200. Neither input may
    /// be able to release the other's PID.
    #[test]
    fn losing_focus_releases_only_the_focus_pid_not_the_audio_pid() {
        let last = pids(&[100, 300]);
        let next = pids(&[200, 300]);

        let plan = BoostPlan::between(&last, &next, all_alive);

        assert_eq!(plan.apply, vec![200]);
        assert_eq!(plan.release, vec![100]);
    }

    /// Window+tree mode adds children; a PID shared between the two sets
    /// must not be rewritten.
    #[test]
    fn an_unchanged_child_is_not_reapplied() {
        let last = pids(&[100, 101]);
        let next = pids(&[100, 101, 102]);

        let plan = BoostPlan::between(&last, &next, all_alive);

        assert_eq!(plan.apply, vec![102]);
        assert!(plan.release.is_empty());
    }

    /// Plans are applied in a stable order so the log and any external
    /// observer see a deterministic sequence.
    #[test]
    fn plans_are_ordered_by_pid() {
        let plan = BoostPlan::between(&HashSet::new(), &pids(&[400, 3, 250]), all_alive);

        assert_eq!(plan.apply, vec![3, 250, 400]);
    }

    /// A PID that exited must not be carried in `release` — there is
    /// nothing left to write to, and the sweep owns its memory.
    #[test]
    fn a_dead_pid_is_not_released() {
        let last = pids(&[100]);
        let next = HashSet::new();
        let alive = |pid: u32| pid != 100;

        let plan = BoostPlan::between(&last, &next, alive);

        assert!(plan.release.is_empty());
    }

    /// Focus leaving the desktop entirely (Hyprland reports a null
    /// window): every boosted PID is released.
    #[test]
    fn focus_lost_releases_everything() {
        let last = pids(&[100, 101, 300]);
        let plan = BoostPlan::between(&last, &HashSet::new(), all_alive);

        assert!(plan.apply.is_empty());
        assert_eq!(plan.release, vec![100, 101, 300]);
    }

    /* ── baselines ──────────────────────────────────────────────────── */

    #[test]
    fn nice_is_clamped_to_the_kernel_range() {
        // Parsed as given, then clamped by the constructor caller.
        let clamp = |raw: i32| raw.clamp(*NICE_RANGE.start(), *NICE_RANGE.end());

        assert_eq!(clamp(-99), -20);
        assert_eq!(clamp(99), 19);
        assert_eq!(clamp(-10), -10);
    }

    #[test]
    fn cpu_weight_is_clamped_to_the_kernel_range() {
        let clamp = |raw: u32| raw.clamp(*CPU_WEIGHT_RANGE.start(), *CPU_WEIGHT_RANGE.end());

        assert_eq!(clamp(0), 1);
        assert_eq!(clamp(99_999), 10_000);
        assert_eq!(clamp(500), 500);
    }

    /// A baseline records the pre-boost value, so a process that was
    /// already negative (a game, an ananicy rule) is restored to that,
    /// not to 0. Clobbering it with 0 would be a silent regression for
    /// every process ananicy niced.
    #[test]
    fn baseline_carries_the_preboost_nice_not_zero() {
        let baseline = Baseline {
            nice: -5,
            cgroup: None,
        };
        assert_eq!(baseline.nice, -5);
    }

    #[test]
    fn baseline_carries_the_source_cgroup_when_a_cgroup_boost_was_applied() {
        let baseline = Baseline {
            nice: 0,
            cgroup: Some(PathBuf::from("/sys/fs/cgroup/user.slice/app.scope")),
        };
        assert_eq!(
            baseline.cgroup,
            Some(PathBuf::from("/sys/fs/cgroup/user.slice/app.scope"))
        );
    }

    /* ── describe ───────────────────────────────────────────────────── */

    /// A booster in a known state, without touching the filesystem:
    /// `from_env` probes the delegated slice and creates cgroups, which a
    /// test must not do.
    fn booster_in(
        boost_dir: Option<PathBuf>,
        release_dir: Option<PathBuf>,
        boost_nice: i32,
        boost_cpu_weight: u32,
    ) -> Booster {
        Booster {
            boost_dir,
            release_dir,
            boost_nice,
            boost_cpu_weight,
            applied: HashSet::new(),
            baselines: HashMap::new(),
        }
    }

    /// The cgroup half live: both knobs are named, and the path the
    /// daemon actually uses is in the line. An operator reading one line
    /// must be able to see where the weight was applied.
    #[test]
    fn describe_names_both_knobs_and_the_live_cgroup_path() {
        let b = booster_in(
            Some(PathBuf::from(
                "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/anima_boost",
            )),
            Some(PathBuf::from(
                "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/anima_released",
            )),
            -7,
            250,
        );

        let line = b.describe();

        assert!(
            line.contains("nice=-7"),
            "the resolved nice level must be in the line: {line}"
        );
        assert!(
            line.contains("cpu_weight=250"),
            "the cpu weight must be in the line: {line}"
        );
        assert!(
            line.contains("anima_boost"),
            "the live cgroup path must be in the line: {line}"
        );
        assert!(
            line.len() < 200,
            "the common case stays on one readable line: {line}"
        );
    }

    /// The no-cgroup deployment is a legitimate mode, not a
    /// misconfiguration, so the line must say "nice only" rather than
    /// print an empty or absent path. An operator who sees neither cannot
    /// tell why the weight half is doing nothing.
    #[test]
    fn describe_says_nice_only_when_no_cgroup_is_set_up() {
        let b = booster_in(None, None, DEFAULT_BOOST_NICE, DEFAULT_BOOST_CPU_WEIGHT);

        let line = b.describe();

        assert!(
            line.contains("nice only"),
            "the absent cgroup must be named as such: {line}"
        );
        assert!(
            !line.contains("cgroup="),
            "no empty path may be printed for a booster with no cgroup: {line}"
        );
        assert!(
            line.contains(&format!("nice={DEFAULT_BOOST_NICE}")),
            "the default nice level must still be reported: {line}"
        );
        assert!(
            line.contains(&format!("cpu_weight={DEFAULT_BOOST_CPU_WEIGHT}")),
            "the weight is configured even when its target is absent: {line}"
        );
    }

    /// A cgroup the daemon could not keep — one created but never
    /// recorded, or whose `cpu.weight` write failed — is still the
    /// no-cgroup mode, and must read the same way.
    #[test]
    fn with_no_boost_cgroup_a_stray_release_leaf_is_still_nice_only() {
        let b = booster_in(
            None,
            Some(PathBuf::from("/sys/fs/cgroup/user.slice/anima_released")),
            -10,
            500,
        );

        let line = b.describe();

        assert!(
            line.contains("nice only"),
            "a release leaf without a boost cgroup is still nice-only: {line}"
        );
    }

    /* ── capability probe ───────────────────────────────────────────── */

    /// `CAP_SYS_NICE` is bit 23 of the kernel's capability mask. A wrong
    /// bit silently inverts the probe's answer, so the mask itself is
    /// asserted rather than assumed: `1 << 23` is `0x800000`, which
    /// `capsh --decode=0x800003` names `cap_sys_nice`.
    #[test]
    fn cap_sys_nice_is_bit_23_of_the_effective_mask() {
        assert_eq!(1u64 << CAP_SYS_NICE_BIT, 0x0080_0000);
    }

    /// The mask decode that turns a `CapEff:` line into a yes/no answer
    /// must accept exactly the hex form the kernel prints, and reject the
    /// fields that share the prefix.
    #[test]
    fn the_effective_mask_is_decoded_from_the_status_line_only() {
        let eff_of = |status: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .and_then(|raw| u64::from_str_radix(raw.trim(), 16).ok())
        };

        assert_eq!(
            eff_of("CapPrm:\t0000000000000000\nCapEff:\t0000000000800000\n"),
            Some(1 << CAP_SYS_NICE_BIT),
            "a hex mask with the capability must decode to that bit"
        );
        assert_eq!(
            eff_of("CapEff:\t0000000000000000\n"),
            Some(0),
            "an empty effective set means no capability"
        );
        assert_eq!(
            eff_of("CapPrm:\t0000000000800000\n"),
            None,
            "CapPrm is not CapEff: a permitted bit is not an effective one"
        );
    }

    /// With the cgroup live the daemon had the privilege to create it,
    /// so no note is warranted — reporting "unprivileged" next to a
    /// cgroup it owns would be a lie that sends an operator looking for
    /// the wrong fault.
    #[test]
    fn a_live_cgroup_means_no_privilege_note() {
        let b = booster_in(
            Some(PathBuf::from("/sys/fs/cgroup/user.slice/anima_boost")),
            None,
            -10,
            500,
        );

        assert!(
            b.privilege_note().is_none(),
            "a booster that owns a cgroup has no unprivileged story to tell"
        );
    }

    /// The note is actionable, not a restatement of the symptom: it names
    /// the capability and says what the boost looks like without it.
    #[test]
    fn an_unprivileged_note_names_the_capability_and_its_effect() {
        // Written against the *absence* path by asserting the message's
        // shape rather than by forcing a capability off, which a test
        // must not do to its own process.
        let note = format!(
            "unprivileged: CAP_SYS_NICE missing, boosts stay at nice 0 \
             (cpu.weight half is off)"
        );

        assert!(
            note.contains("CAP_SYS_NICE"),
            "the missing capability must be named: {note}"
        );
        assert!(note.contains("nice 0"), "the effect must be stated: {note}");
    }

    /// The probe reads a mask, and an unreadable `/proc/self/status` must
    /// not be reported as a missing capability: a restricted `/proc` is
    /// the likelier cause, and a false "unprivileged" would send an
    /// operator hunting for a privilege problem that does not exist.
    #[test]
    fn an_unreadable_status_is_not_evidence_of_a_missing_capability() {
        // `CapEff:` unparseable ⇒ no bit found ⇒ the decode yields
        // `None`, which `has_cap_sys_nice` must treat as "has it".
        let eff_of = |status: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .and_then(|raw| u64::from_str_radix(raw.trim(), 16).ok())
        };

        assert_eq!(eff_of("CapEff:\n"), None, "an empty mask is unparseable");
        assert_eq!(eff_of(""), None, "a missing line is unparseable");
    }

    /* ── unprivileged release path ──────────────────────────────────── */

    /// With no boost cgroup there is nothing to move out of, so the
    /// release target is absent and the release reduces to the nice
    /// write. The old behaviour fell back to the cgroup *root*, which is
    /// an internal node: an unprivileged daemon writes EACCES against it
    /// on every release, and a privileged one could move a process into
    /// it for no reason.
    #[test]
    fn with_no_cgroup_there_is_no_release_target_to_guess() {
        let b = booster_in(None, None, -10, 500);

        assert!(
            b.boost_release_target().is_none(),
            "no cgroup means no destination, so none must be invented"
        );
    }

    /// The sibling leaf is the target while it exists — that is the path
    /// a release takes in the normal, privileged deployment.
    #[test]
    fn the_release_target_is_the_sibling_leaf_when_there_is_one() {
        let b = booster_in(
            Some(PathBuf::from("/sys/fs/cgroup/user.slice/anima_boost")),
            Some(PathBuf::from("/sys/fs/cgroup/user.slice/anima_released")),
            -10,
            500,
        );

        assert_eq!(
            b.boost_release_target(),
            Some(Path::new("/sys/fs/cgroup/user.slice/anima_released"))
        );
    }

    /// A boost cgroup whose leaf was never created still knows where the
    /// process was moved *into*, so it targets that rather than nothing.
    #[test]
    fn the_release_target_falls_back_to_the_boost_cgroup_itself() {
        let b = booster_in(
            Some(PathBuf::from("/sys/fs/cgroup/user.slice/anima_boost")),
            None,
            -10,
            500,
        );

        assert_eq!(
            b.boost_release_target(),
            Some(Path::new("/sys/fs/cgroup/user.slice/anima_boost"))
        );
    }

    /// A release leaf alone proves nothing: the boost cgroup is the mode
    /// that determines whether a migration is meaningful at all.
    #[test]
    fn a_release_leaf_without_a_boost_cgroup_is_not_a_target() {
        let b = booster_in(
            None,
            Some(PathBuf::from("/sys/fs/cgroup/user.slice/anima_released")),
            -10,
            500,
        );

        assert!(
            b.boost_release_target().is_none(),
            "a stray leaf with no boost cgroup must not become a destination"
        );
    }

    /// A release with no cgroup is a complete no-op on the cgroup side,
    /// and must not report a failure: there is nothing to fail at, and a
    /// log line per release would be pure noise in the unprivileged
    /// deployment this path exists for.
    #[test]
    fn a_release_from_cgroup_with_no_cgroup_needs_no_target_to_exist() {
        let b = booster_in(None, None, -10, 500);

        // The no-root path: no boost cgroup, so `release_from_cgroup`
        // returns before any write. Exercised on the same booster the
        // daemon would have after a failed cgroup setup.
        assert!(b.boost_release_target().is_none());
    }
}
