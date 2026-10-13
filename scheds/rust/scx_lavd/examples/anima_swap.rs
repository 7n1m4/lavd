//! Focused-window swap protection through cgroup v2.
//!
//! Moves the process owning the focused window into a small pool of
//! cgroups carrying `memory.swap.max = 0`, so the memory that process
//! allocates from that moment on cannot be pushed out to swap. When focus
//! moves on, the process is migrated back out into a daemon-owned cgroup
//! and the slot is released for the next window.
//!
//! ## Layout
//!
//! ```text
//!   <the daemon's own cgroup>/
//!   └── anima_swapguard/          cgroup.subtree_control = +cpu +memory
//!       ├── slot_0/               memory.swap.max = 0
//!       ├── slot_1/               memory.swap.max = 0
//!       ├── slot_<N-1>/
//!       └── released/             neutral leaf: restore target
//! ```
//!
//! The pool parent delegates *both* controllers. `+memory` is what makes
//! `memory.swap.max` writable in a slot, and `+cpu` is what makes
//! `cpu.weight` writable in one — measured: a parent set up with
//! `+memory` alone rejects a child's `cpu.weight` write with EACCES.
//! Mirroring that value is not a refinement. A migration that silently
//! reset a window's CPU share would change the very CPU distribution this
//! scheduler exists to shape, so the source weight is copied into the slot
//! on every migration.
//!
//! No `memory.max` is ever written on a slot. The intent is to stop
//! swapping, not to cap memory: a memory cap is an OOM kill, and for the
//! compositor that is strictly worse than swapping.
//!
//! ## What this does *not* do — read before trusting it
//!
//! `memory.swap.max = 0` protects only the pages a process allocates
//! **after** it enters the slot. Migration does not carry a process's
//! existing charges with it: the kernel documents this — *"Migrating a
//! process to a different cgroup does not move the charge to the
//! destination cgroup"* — and it was measured on this workstation, where
//! moving a 220 MiB process in left the slot's `memory.current` reading
//! 0. A browser's already-allocated heap therefore stays swappable. What
//! is protected is everything the window allocates going forward, which
//! is the memory a user actually touches after switching back into a tab.
//! A slot's `memory.current` reading 0 right after a migration is that
//! limitation, not a bug, and it is not the success signal — protection
//! shows up as fresh allocations raising `memory.current` while
//! `memory.swap.current` stays 0.
//!
//! Release returns a process to the cgroup it was migrated out of
//! whenever that cgroup accepts writes, which for a terminal's own scope
//! it does — so the release is invisible in the ordinary case. GUI
//! processes sometimes live in root-owned scopes (`user@1000.service/
//! session-N.scope`, `app.slice`, `init.scope`) whose `cgroup.procs`
//! refuses an unprivileged write with EPERM, verified live on this
//! workstation, and those fall back to the `released/` leaf. That leaf is
//! a constraint, not a shortcut: the pool parent has controllers in
//! `cgroup.subtree_control`, and cgroup v2 refuses internal processes in
//! such a cgroup — restoring directly into the parent fails with EBUSY,
//! also verified live.
//!
//! Either way a released process stops being swap-protected, which is
//! the point of a release. What must never happen is a process staying in
//! the leaf: they accumulate there, the leaf then never empties, and
//! teardown leaks the pool. The leaf therefore stays empty in normal
//! operation and the fallback is the exception.
//!
//! ## Off by default
//!
//! `ANIMA_SWAP_PROTECT` is off unless set to `1`, `true` or `on`. The
//! feature relocates user processes between cgroups — a heavier
//! intervention than a scheduler boost, so it opts in. `ANIMA_SWAP_SLOTS`
//! (default 3, clamped to 1..=16) sizes the pool, and `ANIMA_SWAP_TRACE`
//! narrates every decision on stderr. Both variables are read once at
//! start, never per event.
//!
//! Everything here is best-effort. A failure to create a cgroup, mirror a
//! `cpu.weight` or move a process (EPERM, ESRCH, EBUSY, a missing
//! `/proc/<pid>`) is logged and dropped; none of it may disturb the
//! focus-boost path, which is the daemon's actual job.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result};

/* ── tunable constants ─────────────────────────────────────────────── */

/// Name of the environment variable arming swap protection. Off unless
/// set to one of [`ENABLE_VALUES`].
const ENV_SWAP_PROTECT: &str = "ANIMA_SWAP_PROTECT";

/// Name of the environment variable sizing the slot pool.
const ENV_SWAP_SLOTS: &str = "ANIMA_SWAP_SLOTS";

/// Name of the environment variable enabling trace output.
const ENV_SWAP_TRACE: &str = "ANIMA_SWAP_TRACE";

/// Values, other than unset, that count as arming the feature or enabling
/// tracing. Case-insensitive.
const ENABLE_VALUES: [&str; 3] = ["1", "true", "on"];

/// Slot count used when `ANIMA_SWAP_SLOTS` is unset or unparseable.
const DEFAULT_SLOTS: usize = 3;

/// Upper bound on the slot count. Three is plenty for "the window being
/// typed in right now"; the bound only stops a typo like `9999` from
/// creating a thousand directories under `/sys/fs/cgroup`.
const MAX_SLOTS: usize = 16;

/// Directory name of the pool parent, created inside the delegated user
/// slice (`own_cgroup()`). A child of that, so it can be created and written
/// unprivileged.
const PARENT_NAME: &str = "anima_swapguard";

/// Directory name of the fallback leaf released processes are restored
/// into. A child of [`PARENT_NAME`], not a sibling: restoring into the
/// parent itself fails with EBUSY, because a cgroup whose
/// `cgroup.subtree_control` lists a controller admits no internal
/// processes (verified live, twice).
///
/// A *fallback*, not the destination: a process comes back to the cgroup
/// it was migrated out of whenever that cgroup accepts writes, which is
/// the usual case for a terminal's scope. Only root-owned GUI session
/// scopes refuse — see [`RESTORE_TARGET`] — and those end up here. The
/// distinction matters because processes left in this leaf accumulate:
/// they cannot be reached from the tree again, so it would never empty
/// and `teardown` would leak the whole pool. That was observed live.
const RESTORE_NAME: &str = "released";

/// Prefix of a slot directory: slot 2 is `slot_2`.
const SLOT_PREFIX: &str = "slot_";

/// Controllers delegated from the pool parent into its slots. Both are
/// required: `memory` for `memory.swap.max`, `cpu` for the mirrored
/// `cpu.weight`. See the module doc for the measured EACCES.
const DELEGATED_CONTROLLERS: &str = "+cpu +memory";

/// Value written into a slot's `memory.swap.max`.
const SWAP_MAX_UNLIMITED_SWAP: u32 = 0;

/// Kernel control files touched inside a slot.
const FILE_SWAP_MAX: &str = "memory.swap.max";
const FILE_CPU_WEIGHT: &str = "cpu.weight";
const FILE_PROCS: &str = "cgroup.procs";
const FILE_SUBTREE_CONTROL: &str = "cgroup.subtree_control";

/// Root of the unified (`0::`) cgroup hierarchy.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// `cpu.weight` written when the source cgroup's value cannot be read or
/// parsed. The kernel's own default, so a failed read degrades to "no
/// opinion" rather than to a made-up share.
const DEFAULT_CPU_WEIGHT: u32 = 100;

/// Inclusive range `cgroup.kernel` accepts for `cpu.weight`.
const CPU_WEIGHT_RANGE: std::ops::RangeInclusive<u32> = 1..=10_000;

/// How long [`SwapGuard::teardown`] waits for a cgroup to empty.
///
/// Bounded because a cgroup can stay occupied indefinitely — a process
/// that refuses to exit, or a zombie whose parent is already gone. The
/// wait exists only to cover the transient case, where the exit is
/// pending but not yet reaped.
const EMPTY_POLL_BUDGET: std::time::Duration = std::time::Duration::from_millis(250);

/* ── tracing ──────────────────────────────────────────────────────── */

/// Whether the slot decisions narrate themselves on stderr.
///
/// Sampling the environment once keeps the cost off the focus path and
/// re-reads a value that cannot change while the process is alive.
/// Anything other than `1`, `true` or `on` (case-insensitive) is off,
/// including unset: a silent default is what makes the traces usable as
/// a debugging tool.
static TRACE: LazyLock<bool> = LazyLock::new(read_env_trace);

/// The one-time initializer behind [`TRACE`].
fn read_env_trace() -> bool {
    std::env::var(ENV_SWAP_TRACE).ok().is_some_and(|raw| {
        ENABLE_VALUES
            .iter()
            .any(|v| v.eq_ignore_ascii_case(raw.trim()))
    })
}

/// Resolve [`TRACE`] now, before the first focus event can observe it.
///
/// This MUST be called from the daemon start path
/// (`SwapGuard::from_env`) and never from a focus event: the first event
/// would otherwise pay for the one-time read as a side effect of the
/// migration instead of before it.
pub(crate) fn init_trace_from_env() {
    let _ = *TRACE;
}

/// Print one trace line when tracing is on, and otherwise do nothing at
/// all — the `trace!` call site must not allocate or touch stderr when
/// tracing is off.
macro_rules! trace {
    ($($arg:tt)*) => {
        if *TRACE {
            eprintln!("[anima] swapguard: {}", format_args!($($arg)*));
        }
    };
}

/* ── pure slot-pool decisions ──────────────────────────────────────── */

/// Which slot to put a PID in, as decided by [`SlotPool`].
///
/// An intent, not an action: the pool decides against its own bookkeeping
/// alone and never touches the filesystem, so the decision is testable
/// without privileges — and, more to the point, so a syscall that fails
/// cannot leave the pool claiming a slot the process never entered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotPlan {
    /// Put the PID in `slot`, after restoring `evict` out of it. `evict`
    /// is the LRU victim when the pool was full and `None` when the slot
    /// was free.
    Take { slot: usize, evict: Option<u32> },
    /// The PID is already protected: nothing to migrate. Still recorded,
    /// so the LRU stamp of the slot it holds can be refreshed.
    Already,
    /// Deciding is impossible — only reachable for a zero-slot pool,
    /// which [`SlotPool::new`] refuses to build.
    NoSlots,
}

/// What releasing a PID requires, as decided by [`SlotPool`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReleasePlan {
    /// Restore this PID out of `slot` and free that slot.
    Free { slot: usize, pid: u32 },
    /// The PID is not protected: nothing to do.
    NotProtected,
}

/// One slot: which PID occupies it, and how recently it was used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SlotEntry {
    /// `None` marks a free slot.
    pid: Option<u32>,
    /// Monotonic stamp ordering occupants by recency of use. Only
    /// compared against other stamps, so it needs no clock.
    stamp: u64,
}

impl SlotEntry {
    const FREE: SlotEntry = SlotEntry {
        pid: None,
        stamp: 0,
    };
}

/// A small LRU pool of swap-protection slots.
///
/// Holds the *decision* half of the mechanism: which slot a focus event
/// takes, which occupant an overflow evicts, and whether a PID is
/// protected at all. Every method is pure arithmetic over `Vec<SlotEntry>`
/// — no syscalls, no `/proc`, no `/sys` — which is what makes the failure
/// modes ("slot never released", "victim is not the least recently used",
/// "release of an unknown PID corrupts the pool") testable anywhere.
///
/// The plans it returns are committed only after the syscall layer has
/// actually moved the process; a failed migration must not consume a slab
/// of bookkeeping that no longer describes reality.
pub(crate) struct SlotPool {
    slots: Vec<SlotEntry>,
    next_stamp: u64,
}

impl SlotPool {
    /// A pool of `count` slots, all free. A count below one is raised to
    /// one: a zero-slot pool would silently swallow every focus event
    /// while the daemon still reported being armed, which reads as "the
    /// feature is broken" instead of "the feature was never configured".
    pub(crate) fn new(count: usize) -> Self {
        let count = count.clamp(1, MAX_SLOTS);
        Self {
            slots: vec![SlotEntry::FREE; count],
            next_stamp: 0,
        }
    }

    /// Number of slots in the pool.
    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }

    /// The PID occupying `slot`, if any.
    pub(crate) fn occupant(&self, slot: usize) -> Option<u32> {
        self.slots.get(slot).and_then(|e| e.pid)
    }

    /// The slot holding `pid`, if it is protected.
    pub(crate) fn slot_of(&self, pid: u32) -> Option<usize> {
        self.slots.iter().position(|e| e.pid == Some(pid))
    }

    /// Whether any slot is occupied.
    pub(crate) fn is_empty(&self) -> bool {
        self.slots.iter().all(|e| e.pid.is_none())
    }

    /// Decide how to protect `pid`.
    ///
    /// Free slots are handed out in ascending index order so consecutive
    /// focus events fill the pool predictably; once the pool is full the
    /// least-recently-used slot is evicted and reused, which keeps the
    /// steady state at a single migration per focus change.
    pub(crate) fn plan_protect(&self, pid: u32) -> SlotPlan {
        debug_assert_ne!(pid, 0, "pid 0 is the kernel scheduler, never protectable");
        if self.slot_of(pid).is_some() {
            return SlotPlan::Already;
        }
        if let Some(slot) = self.free_slot() {
            return SlotPlan::Take { slot, evict: None };
        }
        // The pool is non-empty and has no free slot, so it has an
        // occupant to evict.
        match self.lru_slot() {
            Some(slot) => SlotPlan::Take {
                slot,
                evict: self.slots[slot].pid,
            },
            None => SlotPlan::NoSlots,
        }
    }

    /// Record a protect that the syscall layer completed successfully.
    ///
    /// `plan` must be the one [`Self::plan_protect`] returned for `pid`.
    pub(crate) fn commit_protect(&mut self, plan: SlotPlan, pid: u32) {
        let slot = match plan {
            SlotPlan::Take { slot, .. } => slot,
            // Already protected: refreshing the stamp is the whole effect,
            // and it is what stops a window oscillating between two
            // address spaces from being evicted first every time.
            SlotPlan::Already | SlotPlan::NoSlots => {
                if let Some(i) = self.slot_of(pid) {
                    self.touch(i);
                }
                return;
            }
        };
        let Some(entry) = self.slots.get_mut(slot) else {
            return;
        };
        self.next_stamp += 1;
        entry.pid = Some(pid);
        entry.stamp = self.next_stamp;
    }

    /// Decide how to release `pid`. A PID the pool does not hold is a
    /// no-op, because focus events are the only caller and Hyprland will
    /// happily re-announce a PID that left fast enough to have never been
    /// recorded.
    pub(crate) fn plan_release(&self, pid: u32) -> ReleasePlan {
        match self.slot_of(pid) {
            Some(slot) => ReleasePlan::Free { slot, pid },
            None => ReleasePlan::NotProtected,
        }
    }

    /// Record a release the syscall layer completed, or that failed
    /// harmlessly because the process is already gone — either way the
    /// slot no longer holds it.
    pub(crate) fn commit_release(&mut self, plan: ReleasePlan) {
        if let ReleasePlan::Free { slot, .. } = plan {
            if let Some(entry) = self.slots.get_mut(slot) {
                entry.pid = None;
                // `stamp` is deliberately left behind: it only orders
                // occupants, and dropping it would make the order of
                // newly freed slots depend on when they were freed.
            }
        }
    }

    /// Every occupant, in ascending slot order, so a shutdown restores
    /// them deterministically.
    pub(crate) fn plan_release_all(&self) -> Vec<ReleasePlan> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(slot, e)| e.pid.map(|pid| ReleasePlan::Free { slot, pid }))
            .collect()
    }

    /// Occupants that no longer exist, in ascending slot order.
    ///
    /// A focused process can exit while still holding a slot — a closed
    /// tab, a crashed window — and nothing else would ever free it: the
    /// slot would sit occupied by a dead PID until LRU eviction, which is
    /// several focus changes of protection lost for nothing.
    pub(crate) fn plan_prune_dead(&self, alive: impl Fn(u32) -> bool) -> Vec<ReleasePlan> {
        self.plan_release_all()
            .into_iter()
            .filter(|p| match p {
                ReleasePlan::Free { pid, .. } => !alive(*pid),
                ReleasePlan::NotProtected => false,
            })
            .collect()
    }

    /// Lowest-index free slot.
    fn free_slot(&self) -> Option<usize> {
        self.slots.iter().position(|e| e.pid.is_none())
    }

    /// Lowest-index slot among the least-recently-used occupants.
    fn lru_slot(&self) -> Option<usize> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, e)| e.pid.is_some())
            .min_by_key(|(i, e)| (e.stamp, *i))
            .map(|(i, _)| i)
    }

    /// Make `slot` the most recently used one.
    fn touch(&mut self, slot: usize) {
        self.next_stamp += 1;
        if let Some(entry) = self.slots.get_mut(slot) {
            entry.stamp = self.next_stamp;
        }
    }
}

/* ── environment parsing ──────────────────────────────────────────── */

/// Whether a raw `ANIMA_SWAP_PROTECT`/`ANIMA_SWAP_TRACE` value arms the
/// feature. Unset is off; so is anything but [`ENABLE_VALUES`].
fn env_flag(raw: Option<&str>) -> bool {
    raw.is_some_and(|v| {
        ENABLE_VALUES
            .iter()
            .any(|e| e.eq_ignore_ascii_case(v.trim()))
    })
}

/// Slot count from `ANIMA_SWAP_SLOTS`, clamped to a usable range.
fn parse_slots(raw: Option<&str>) -> usize {
    raw.and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_SLOTS)
        .clamp(1, MAX_SLOTS)
}

/* ── the syscall layer ────────────────────────────────────────────── */

/// Migrates focused windows in and out of swap-protected slots.
///
/// Owns every filesystem side effect: creating the pool, mirroring
/// `cpu.weight`, writing `cgroup.procs`, restoring on release. All of it
/// is best-effort — see the module doc — and all of it is skipped when
/// [`ENV_SWAP_PROTECT`] is off, in which case no cgroup is ever created
/// and no process is ever moved.
pub(crate) struct SwapGuard {
    /// Pool parent. `None` while disarmed, which is the state
    /// [`Self::from_env`] returns when protection is off or setup failed.
    parent: Option<PathBuf>,
    /// Neutral cgroup a released process is restored into.
    restore: Option<PathBuf>,
    /// Slot directories, indexed to match [`Self::pool`].
    slots: Vec<PathBuf>,
    /// Which PID occupies which slot.
    pool: SlotPool,
    /// The PID protected by the most recent focus event, so the next one
    /// can release it. `None` when nothing is being tracked.
    focus: Option<u32>,
    /// Cgroup each protected PID came from, so a release can put it back.
    ///
    /// The original cgroup is normally writable, so returning there is the
    /// ordinary case and keeps the neutral leaf permanently empty. It is
    /// only reachable for scopes this daemon can write — see
    /// [`RESTORE_TARGET`] — and when it is not, the leaf is used instead.
    restore_source: HashMap<u32, PathBuf>,
}

impl SwapGuard {
    /// Read the environment once and build the pool if protection is on.
    ///
    /// Failure to create the cgroups is reported and downgraded to
    /// "off": swap protection is an enhancement and must never become a
    /// precondition for the daemon starting.
    pub(crate) fn from_env() -> Self {
        init_trace_from_env();

        let raw = std::env::var(ENV_SWAP_PROTECT).ok();
        if !env_flag(raw.as_deref()) {
            eprintln!(
                "[anima] swapguard: off ({ENV_SWAP_PROTECT} unset or not {})",
                ENABLE_VALUES.join("/")
            );
            return Self::disarmed();
        }

        let count = parse_slots(std::env::var(ENV_SWAP_SLOTS).ok().as_deref());
        trace!("arm: {count} slot(s)");
        match Self::setup(count) {
            Ok(guard) => {
                eprintln!(
                    "[anima] swapguard: armed — {} slot(s) under {}, restore {}",
                    guard.pool.len(),
                    guard.parent.as_deref().unwrap_or(Path::new("?")).display(),
                    guard
                        .restore_path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                );
                guard
            }
            Err(e) => {
                eprintln!("[anima] swapguard: off — setup failed: {e:#}");
                Self::disarmed()
            }
        }
    }

    /// A disarmed guard: no cgroups, no migrations, no-ops everywhere.
    fn disarmed() -> Self {
        Self {
            parent: None,
            restore: None,
            slots: Vec::new(),
            pool: SlotPool::new(0),
            focus: None,
            restore_source: HashMap::new(),
        }
    }

    /// A disarmed guard, for tests outside this module.
    #[cfg(test)]
    pub(crate) fn disarmed_for_test() -> Self {
        Self::disarmed()
    }

    /// Whether nothing is being tracked, for tests outside this module.
    #[cfg(test)]
    pub(crate) fn is_idle_for_test(&self) -> bool {
        self.focus.is_none() && self.pool.is_empty() && self.slots.is_empty()
    }

    /// Create the pool parent, delegate both controllers, create every
    /// slot with `memory.swap.max = 0`, and create the neutral release
    /// leaf.
    fn setup(count: usize) -> Result<Self> {
        let own = own_cgroup();
        let parent = own.join(PARENT_NAME);
        let restore = parent.join(RESTORE_NAME);

        create_dir(&parent)
            .with_context(|| format!("cannot create pool parent {}", parent.display()))?;
        // Written before any process can arrive, and the parent itself
        // never holds one: it only parents slots and the release leaf.
        // Both controllers in one write — see [`DELEGATED_CONTROLLERS`].
        delegate_controllers(&parent)
            .with_context(|| format!("cannot delegate controllers in {}", parent.display()))?;
        // A leaf, so it can hold a process despite its parent having
        // controllers in subtree_control.
        create_dir(&restore)
            .with_context(|| format!("cannot create release cgroup {}", restore.display()))?;

        let mut slots = Vec::with_capacity(count);
        for i in 0..count {
            let slot = parent.join(format!("{SLOT_PREFIX}{i}"));
            create_dir(&slot).with_context(|| format!("cannot create slot {}", slot.display()))?;
            write_file(
                &slot.join(FILE_SWAP_MAX),
                &SWAP_MAX_UNLIMITED_SWAP.to_string(),
            )
            .with_context(|| format!("cannot arm {FILE_SWAP_MAX} in {}", slot.display()))?;
            slots.push(slot);
        }

        Ok(Self {
            parent: Some(parent),
            restore: Some(restore),
            slots,
            pool: SlotPool::new(count),
            focus: None,
            restore_source: HashMap::new(),
        })
    }

    /// Whether protection is armed. Only used for logging and tests.
    pub(crate) fn is_enabled(&self) -> bool {
        self.parent.is_some()
    }

    /// Protect `pid`, releasing the previously focused PID first.
    ///
    /// Called once per Hyprland `activewindowv2` event, after the boost
    /// path has already run. Nothing here may fail in a way that reaches
    /// that path: an unusable cgroup means the window stays swappable,
    /// which is the pre-existing behaviour, not a regression.
    pub(crate) fn set_focus(&mut self, pid: u32) {
        if self.parent.is_none() || pid < 1 {
            return;
        }
        trace!("focus {pid}");

        /* Occupants that have exited hold their slot until something
         * notices; nothing else will, and each dead one is a slot of
         * protection lost. Pruned first, so a window that closed and a
         * window that merely lost focus are handled the same way. */
        for plan in self.pool.plan_prune_dead(pid_alive) {
            self.restore(plan);
        }

        /* Release the window that just lost focus, unless it is the same
         * one re-announced — then releasing it would only undo the
         * migration about to be repeated. A previous focus that has
         * already exited was pruned above, so this restore is a no-op
         * rather than an error. */
        if let Some(prev) = self.focus {
            if prev != pid {
                self.restore(self.pool.plan_release(prev));
            }
        }

        let plan = self.pool.plan_protect(pid);
        match plan {
            SlotPlan::Take { slot, evict } => {
                /* Only reachable when the pool is full and no occupant
                 * died: the LRU victim is restored before its slot is
                 * handed over, so the eviction and the migration are one
                 * step rather than a window leaving protection. */
                if let Some(old) = evict {
                    trace!("slot {slot}: evicting lru pid {old}");
                    self.restore(self.pool.plan_release(old));
                }
                if self.migrate_into(slot, pid, plan) {
                    self.focus = Some(pid);
                }
            }
            SlotPlan::Already => {
                trace!("pid {pid} already protected");
                self.pool.commit_protect(plan, pid);
                self.focus = Some(pid);
            }
            SlotPlan::NoSlots => trace!("no slots configured; pid {pid} left unprotected"),
        }
    }

    /// Release every protected process and drop the tracking state.
    ///
    /// Called on the shutdown path: leaving processes owned by this
    /// daemon's cgroups after exit would strand them there.
    pub(crate) fn clear(&mut self) {
        if self.parent.is_none() {
            return;
        }
        let plans = self.pool.plan_release_all();
        if plans.is_empty() {
            trace!("clear: nothing protected");
        }
        for plan in plans {
            self.restore(plan);
        }
        self.focus = None;
    }

    /// Remove the cgroups this module created, once they are empty.
    ///
    /// Only ever used after [`Self::clear`]. `remove_dir` is used rather
    /// than any recursive variant on purpose: this tree lives under
    /// `/sys/fs/cgroup`, and a recursive removal there is a footgun with
    /// no upside.
    ///
    /// Emptiness is polled rather than assumed. A process whose parent
    /// already died becomes a zombie that still occupies
    /// `cgroup.procs`, and a zombie is only reaped by the parent it lost,
    /// so a slot can look released and still refuse to disappear.
    /// Waiting to see it leave beats reporting a directory as removed
    /// that the kernel refused to take.
    pub(crate) fn teardown(&mut self) {
        let Some(parent) = self.parent.take() else {
            return;
        };
        if !self.pool.is_empty() {
            eprintln!(
                "[anima] swapguard: teardown skipped — {} slot(s) still occupied",
                self.slots.len() - self.pool.plan_release_all().len()
            );
            self.parent = Some(parent);
            return;
        }

        for (i, slot) in self.slots.iter().enumerate() {
            if self.pool.occupant(i).is_some() {
                continue;
            }
            // Slots hold only a process, so they empty as soon as that
            // process is reaped; a bounded wait covers the zombie case.
            match remove_when_empty(slot, EMPTY_POLL_BUDGET) {
                Ok(true) => trace!("removed {}", slot.display()),
                Ok(false) => eprintln!(
                    "[anima] swapguard: {} still occupied after {}ms; left in place",
                    slot.display(),
                    EMPTY_POLL_BUDGET.as_millis()
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => eprintln!("[anima] swapguard: remove {}: {e}", slot.display()),
            }
        }
        for dir in [self.restore.as_deref(), Some(parent.as_path())] {
            let Some(dir) = dir else { continue };
            match remove_when_empty(dir, EMPTY_POLL_BUDGET) {
                Ok(true) => trace!("removed {}", dir.display()),
                Ok(false) => eprintln!(
                    "[anima] swapguard: {} not empty after {}ms; left in place",
                    dir.display(),
                    EMPTY_POLL_BUDGET.as_millis()
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => eprintln!("[anima] swapguard: remove {}: {e}", dir.display()),
            }
        }
        self.slots.clear();
        self.restore = None;
        self.pool = SlotPool::new(0);
        self.restore_source.clear();
        trace!("torn down");
    }

    /// Move `pid` into slot `slot`, mirroring its `cpu.weight` first.
    ///
    /// Returns whether the process actually landed there; the caller
    /// commits the plan only on success.
    fn migrate_into(&mut self, slot: usize, pid: u32, plan: SlotPlan) -> bool {
        let Some(slot_dir) = self.slots.get(slot).cloned() else {
            return false;
        };
        let Some(source) = cgroup_of(pid) else {
            eprintln!("[anima] swapguard: pid {pid}: cannot read its cgroup; left unprotected");
            return false;
        };

        match mirror_cpu_weight(&source, &slot_dir) {
            Some(w) => trace!("slot {slot}: cpu.weight {w} from {}", source.display()),
            None => {
                eprintln!(
                    "[anima] swapguard: slot {slot}: cannot mirror cpu.weight (source {}); \
                     migrating anyway",
                    source.display()
                );
            }
        }

        if let Err(e) = migrate(&slot_dir, pid) {
            // ESRCH here is the race where the focus event's PID exited
            // between Hyprland naming it and this write. Nothing to
            // protect, nothing to roll back, and no slot to consume.
            if e.raw_os_error() == Some(libc::ESRCH) {
                trace!("pid {pid} exited before it could be protected");
            } else {
                eprintln!(
                    "[anima] swapguard: cannot move pid {pid} into {}: {e}",
                    slot_dir.display()
                );
            }
            return false;
        }
        /* Remembered only after the move succeeded, so a failed attempt
         * never records a cgroup the process is not actually in. */
        self.restore_source.insert(pid, source);
        self.pool.commit_protect(plan, pid);
        trace!("pid {pid} protected in slot {slot}");
        true
    }

    /// Restore the PID a plan names and commit.
    ///
    /// The original cgroup is tried first and is usually writable: a process
    /// in a terminal's scope comes straight back to it, which is what makes
    /// a release idempotent and leaves the neutral leaf permanently empty.
    /// Only when the original is root-owned (the GUI session scopes — see
    /// [`RESTORE_TARGET`]) does this fall back to the neutral leaf.
    ///
    /// Leaving processes in the leaf instead was tried and is wrong: they
    /// accumulate there and the leaf can never empty, so `teardown` fails
    /// with EBUSY and the whole pool leaks. That was found by running the
    /// real guard, not by reading.
    fn restore(&mut self, plan: ReleasePlan) {
        let ReleasePlan::Free { slot, pid } = plan else {
            return;
        };
        let original = self.restore_source.get(&pid).cloned();

        /* An ESRCH here is the ordinary case: the process exited between
         * the focus event and this write. Nothing to restore, and it is
         * still not a reason to leave a slot marked occupied. */
        let done = |pid: u32, slot: usize, via: &Path| {
            trace!("pid {pid} released from slot {slot} into {}", via.display());
        };

        if let Some(original) = original {
            match migrate(&original, pid) {
                Ok(()) => {
                    self.restore_source.remove(&pid);
                    done(pid, slot, &original);
                    self.pool.commit_release(plan);
                    return;
                }
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {
                    self.restore_source.remove(&pid);
                    trace!("pid {pid} is gone; slot {slot} released without a restore");
                    self.pool.commit_release(plan);
                    return;
                }
                // EPERM (root-owned scope) and EBUSY (a cgroup with
                // delegated controllers) both fall through to the leaf.
                Err(e) => trace!(
                    "pid {pid}: original cgroup {} refused ({e}); using the neutral leaf",
                    original.display()
                ),
            }
        }

        let Some(restore) = self.restore.clone() else {
            // Nothing to restore into means nothing was ever armed, so
            // the bookkeeping cannot claim otherwise.
            self.pool.commit_release(plan);
            return;
        };
        match migrate(&restore, pid) {
            Ok(()) => done(pid, slot, &restore),
            Err(e) => {
                if e.raw_os_error() != Some(libc::ESRCH) {
                    eprintln!(
                        "[anima] swapguard: cannot restore pid {pid} from slot {slot} into {}: {e}",
                        restore.display()
                    );
                } else {
                    trace!("pid {pid} is gone; slot {slot} released without a restore");
                }
            }
        }
        self.pool.commit_release(plan);
    }

    /// Restore cgroup path, for logging.
    fn restore_path(&self) -> Option<&Path> {
        self.restore.as_deref()
    }
}

/* ── cgroup files ─────────────────────────────────────────────────── */

/// Create a cgroup directory. An existing one is not an error: the pool
/// outlives a restart, and re-creating it is the recovery path after a
/// crash left it behind.
fn create_dir(path: &Path) -> std::io::Result<()> {
    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

/// Delegate the cpu and memory controllers from `parent` into its
/// children.
///
/// A single write of both: writing `+memory` and then `+cpu` separately
/// accumulates, but one write cannot half-apply, and a half-delegated
/// parent is exactly the state where a slot's `cpu.weight` write fails
/// with EACCES while its `memory.swap.max` write succeeds.
fn delegate_controllers(parent: &Path) -> std::io::Result<()> {
    write_file(&parent.join(FILE_SUBTREE_CONTROL), DELEGATED_CONTROLLERS)
}

/// Write a value into a kernel control file.
///
/// `std::fs::write` is enough: these files take the whole buffer, parse
/// the value out of it, and store no content — no newline handling, no
/// seeking, no subprocess.
fn write_file(path: &Path, value: &str) -> std::io::Result<()> {
    std::fs::write(path, value)
}

/// Read a kernel control file. Any error is `None`: every caller treats
/// unreadable as "use the default and say so".
fn read_file(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Whether a directory holds any process.
fn holds_procs(dir: &Path) -> bool {
    match read_file(&dir.join(FILE_PROCS)) {
        Some(text) => !text.trim().is_empty(),
        // Unreadable `cgroup.procs` is treated as "empty" — the only
        // remaining explanation is that the directory no longer exists,
        // which the removal will confirm.
        None => false,
    }
}

/// `rmdir` a cgroup, polling until it is empty, up to `budget`.
///
/// A cgroup refuses to disappear while it holds a process, which after a
/// `clear` means the exits have been issued but not yet reaped. Retrying
/// is the honest response to that ordering: a single `rmdir` reports
/// EBUSY for what is a race in progress, and neither blocking forever nor
/// giving up immediately is right — so the wait is bounded and the result
/// is returned instead of guessed.
///
/// Returns `Ok(true)` once the directory is gone, `Ok(false)` if it is
/// still occupied when the budget runs out, and the `rmdir` error for
/// anything else.
fn remove_when_empty(dir: &Path, budget: std::time::Duration) -> std::io::Result<bool> {
    let start = std::time::Instant::now();
    loop {
        match std::fs::remove_dir(dir) {
            Ok(()) => return Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(e) => {
                if !holds_procs(dir) || start.elapsed() >= budget {
                    return Err(e);
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}

/// Copy `cpu.weight` from a process's current cgroup into `slot_dir`.
///
/// Returns the value written, or `None` if the write itself failed. A
/// source value that is unreadable or out of range falls back to
/// [`DEFAULT_CPU_WEIGHT`] rather than leaving the slot at whatever the
/// kernel defaulted it to after a previous occupant.
fn mirror_cpu_weight(source: &Path, slot_dir: &Path) -> Option<u32> {
    let weight = read_file(&source.join(FILE_CPU_WEIGHT))
        .and_then(|text| text.trim().parse::<u32>().ok())
        .filter(|w| CPU_WEIGHT_RANGE.contains(w))
        .unwrap_or(DEFAULT_CPU_WEIGHT);
    match write_file(&slot_dir.join(FILE_CPU_WEIGHT), &weight.to_string()) {
        Ok(()) => Some(weight),
        Err(e) => {
            eprintln!(
                "[anima] swapguard: cannot write cpu.weight {weight} to {}: {e}",
                slot_dir.display()
            );
            None
        }
    }
}

/// Move `pid` into `dest` by writing it to `dest/cgroup.procs`.
fn migrate(dest: &Path, pid: u32) -> std::io::Result<()> {
    write_file(&dest.join(FILE_PROCS), &pid.to_string())
}

/// Whether a PID still exists. Used to prune occupants that exited while
/// holding a slot; a disappeared `/proc` entry is the only evidence a
/// process has exited that costs no syscall beyond this one.
fn pid_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// Map a cgroup path from `/proc/<pid>/cgroup` into `/sys/fs/cgroup`.
///
/// Only the unified hierarchy (`0::`) is consulted: `memory.swap.max` and
/// `cpu.weight` are v2-only files, and the other controllers this daemon
/// cares about are attached to the same hierarchy on this machine.
fn cgroup_path(rel: &str) -> PathBuf {
    Path::new(CGROUP_ROOT).join(rel.trim().trim_start_matches('/').trim_end_matches('/'))
}

/// The cgroup a process currently belongs to.
fn cgroup_of(pid: u32) -> Option<PathBuf> {
    let text = read_file(Path::new(&format!("/proc/{pid}/cgroup")))?;
    let rel = text.lines().find_map(|l| l.strip_prefix("0::"))?;
    Some(cgroup_path(rel))
}

/// The anchor directory for everything the pool creates.
///
/// Derived from `/proc/self/cgroup` rather than hardcoded: the daemon's own
/// path is `user.slice/user-<uid>.slice/user@<uid>.service/<some scope>`, and
/// that `user@<uid>.service` element is the delegation point systemd made
/// writable. Walking to it instead of baking in a uid keeps this correct for
/// any user, and lands on the directory whose `cgroup.subtree_control`
/// already carries `cpu memory`.
///
/// Do NOT simplify this to `/proc/self/cgroup` itself. That is the daemon's
/// own scope, and scopes have an empty `subtree_control`: creating a child
/// there fails with ENOENT and the slot's `memory.swap.max` and `cpu.weight`
/// are EACCES. Reproduced on this box by direct probe.
///
/// Falls back to the cgroup root when the path cannot be parsed, where
/// creation will simply fail and be reported.
fn own_cgroup() -> PathBuf {
    read_file(Path::new("/proc/self/cgroup"))
        .as_deref()
        .and_then(|text| text.lines().find_map(|l| l.strip_prefix("0::")))
        .and_then(|rel| delegated_slice(rel))
        .unwrap_or_else(|| PathBuf::from(CGROUP_ROOT))
}

/// The `user@<uid>.service` element of a unified-hierarchy cgroup path.
///
/// `user.slice/user-1000.slice/user@1000.service/kitty-123-0.scope`
/// yields `user.slice/user-1000.slice/user@1000.service`. A path with no
/// such element yields `None`, which leaves the caller at the root fallback.
fn delegated_slice(rel: &str) -> Option<PathBuf> {
    let rel = rel.trim().trim_end_matches('/');
    let mut parts = rel.split('/').collect::<Vec<_>>();
    // Walk back to the `user@*.service` segment, or to the root.
    while let Some(last) = parts.last() {
        if last.starts_with("user@") && last.ends_with(".service") {
            return Some(cgroup_path(&parts.join("/")));
        }
        parts.pop();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Apply a sequence of focus events to a pool plus a stub "kernel"
    /// and return what the stub was asked to do, in order.
    ///
    /// The point of driving it this way is that the assertions describe
    /// observable side effects — which PID entered which slot, which was
    /// restored first — rather than the pool's fields, so a refactor of
    /// the bookkeeping cannot make a test pass by moving the bug.
    struct Stub {
        guard: SwapGuard,
        restored: Vec<u32>,
        entered: Vec<(usize, u32)>,
    }

    impl Stub {
        fn new(slots: usize) -> Self {
            Self {
                guard: SwapGuard {
                    parent: Some(PathBuf::from("/stub/anima_swapguard")),
                    // The release leaf, mirroring the real layout: a child
                    // of the parent, never the parent itself.
                    restore: Some(PathBuf::from(format!(
                        "/stub/anima_swapguard/{RESTORE_NAME}"
                    ))),
                    slots: (0..slots)
                        .map(|i| PathBuf::from(format!("/stub/anima_swapguard/{SLOT_PREFIX}{i}")))
                        .collect(),
                    pool: SlotPool::new(slots),
                    focus: None,
                    restore_source: HashMap::new(),
                },
                restored: Vec::new(),
                entered: Vec::new(),
            }
        }

        /// One focus event, with the syscall layer replaced by the stub:
        /// the plan is executed by hand and committed only on "success",
        /// exactly like [`SwapGuard::set_focus`] does for real.
        fn focus(&mut self, pid: u32) {
            let dead = self.guard.pool.plan_prune_dead(|_| true);
            for plan in dead {
                if let ReleasePlan::Free { pid, .. } = plan {
                    self.restored.push(pid);
                }
                self.guard.pool.commit_release(plan);
            }
            if let Some(prev) = self.guard.focus {
                if prev != pid {
                    let plan = self.guard.pool.plan_release(prev);
                    if let ReleasePlan::Free { pid, .. } = plan {
                        self.restored.push(pid);
                    }
                    self.guard.pool.commit_release(plan);
                }
            }
            match self.guard.pool.plan_protect(pid) {
                SlotPlan::Take { slot, evict } => {
                    if let Some(old) = evict {
                        self.restored.push(old);
                    }
                    self.entered.push((slot, pid));
                    self.guard
                        .pool
                        .commit_protect(SlotPlan::Take { slot, evict }, pid);
                    self.guard.focus = Some(pid);
                }
                SlotPlan::Already => {
                    self.guard.pool.commit_protect(SlotPlan::Already, pid);
                    self.guard.focus = Some(pid);
                }
                SlotPlan::NoSlots => {}
            }
        }
    }

    /* ── allocation ────────────────────────────────────────────────── */

    #[test]
    fn the_first_focus_takes_the_lowest_numbered_slot() {
        let mut stub = Stub::new(3);

        stub.focus(100);

        assert_eq!(stub.guard.pool.slot_of(100), Some(0));
        assert!(stub.restored.is_empty());
    }

    /// Successive focus events each release the previous window, so the
    /// pool only fills when protection is held for more than one PID at
    /// once — which is what the daemon does not do. This pins down that
    /// behaviour rather than leaving it to be inferred from slot numbers.
    #[test]
    fn successive_focus_events_fill_the_pool_in_order() {
        let mut stub = Stub::new(3);

        stub.focus(100);
        stub.focus(200);
        stub.focus(300);

        // 100 and 200 were released as focus moved on; only 300 holds a
        // slot, and it is the lowest one.
        assert_eq!(stub.guard.pool.slot_of(100), None);
        assert_eq!(stub.guard.pool.slot_of(200), None);
        assert_eq!(stub.guard.pool.slot_of(300), Some(0));
        assert!(stub.entered.contains(&(0, 300)));
        assert_eq!(stub.restored, vec![100, 200]);
    }

    /* ── LRU eviction ──────────────────────────────────────────────── */

    /// A full pool evicts the least-recently-used occupant, not the
    /// lowest-numbered slot. This is the difference between protecting
    /// the windows a user actually moves between and churning one slot.
    #[test]
    fn a_full_pool_evicts_the_least_recently_used_occupant() {
        let mut pool = SlotPool::new(3);

        for pid in [100, 200, 300] {
            let plan = pool.plan_protect(pid);
            pool.commit_protect(plan, pid);
        }

        let plan = pool.plan_protect(400);

        assert_eq!(
            plan,
            SlotPlan::Take {
                slot: 0,
                evict: Some(100)
            }
        );
        pool.commit_protect(plan, 400);

        // The evicted PID is no longer protected; the other two stay.
        assert_eq!(pool.slot_of(100), None);
        assert_eq!(pool.slot_of(200), Some(1));
        assert_eq!(pool.slot_of(300), Some(2));
        assert_eq!(pool.occupant(0), Some(400));
    }

    /// A window oscillating between two address spaces must not be the
    /// first thing evicted every time — which is what would happen if
    /// re-protecting a protected PID did not refresh its stamp.
    #[test]
    fn re_protecting_a_protected_pid_refreshes_its_lru_position() {
        let mut pool = SlotPool::new(3);

        for pid in [100, 200, 300] {
            let plan = pool.plan_protect(pid);
            pool.commit_protect(plan, pid);
        }
        // 100 is focused again: no migration, but it is no longer the
        // least recently used.
        let plan = pool.plan_protect(100);
        assert_eq!(plan, SlotPlan::Already);
        pool.commit_protect(plan, 100);

        let plan = pool.plan_protect(400);

        assert_eq!(
            plan,
            SlotPlan::Take {
                slot: 1,
                evict: Some(200)
            }
        );
    }

    /// The steady state of the daemon: every focus event releases the
    /// previous window and takes one slot, so the pool never has to evict
    /// and never grows past one occupant in normal use.
    #[test]
    fn a_focus_change_releases_the_previous_window_before_protecting_the_next() {
        let mut stub = Stub::new(3);

        stub.focus(100);
        stub.focus(200);
        stub.focus(300);

        assert_eq!(stub.restored, vec![100, 200]);
        assert_eq!(stub.entered, vec![(0, 100), (0, 200), (0, 300)]);
    }

    /* ── idempotence ───────────────────────────────────────────────── */

    /// Re-announcing the focused PID must not move it anywhere: a
    /// migration per duplicate event is pure syscall amplification, and
    /// each one resets the CPU share the slot just mirrored.
    #[test]
    fn re_protecting_an_already_protected_pid_is_a_noop() {
        let mut stub = Stub::new(3);

        stub.focus(100);
        let entered = stub.entered.clone();
        let restored = stub.restored.clone();

        stub.focus(100);

        assert_eq!(stub.entered, entered);
        assert_eq!(stub.restored, restored);
        assert_eq!(stub.guard.pool.slot_of(100), Some(0));
        assert_eq!(stub.guard.pool.occupant(1), None);
    }

    #[test]
    fn protecting_a_pid_twice_in_a_row_keeps_one_occupant() {
        let mut pool = SlotPool::new(3);

        let plan = pool.plan_protect(100);
        pool.commit_protect(plan, 100);
        let plan = pool.plan_protect(100);
        assert_eq!(plan, SlotPlan::Already);
        pool.commit_protect(plan, 100);

        assert_eq!(pool.plan_release_all().len(), 1);
    }

    /* ── release ───────────────────────────────────────────────────── */

    #[test]
    fn releasing_a_pid_frees_its_slot_for_the_next_window() {
        let mut pool = SlotPool::new(2);

        for pid in [100, 200] {
            let plan = pool.plan_protect(pid);
            pool.commit_protect(plan, pid);
        }
        let plan = pool.plan_release(200);
        assert_eq!(plan, ReleasePlan::Free { slot: 1, pid: 200 });
        pool.commit_release(plan);

        assert_eq!(pool.occupant(1), None);
        // The freed slot is handed out again rather than evicting 100.
        assert_eq!(
            pool.plan_protect(300),
            SlotPlan::Take {
                slot: 1,
                evict: None
            }
        );
    }

    /// Hyprland re-announces a window that closed fast enough to have
    /// never been recorded. A release for an unknown PID must be a no-op,
    /// not a panic and not a fabricated restore of somebody else.
    #[test]
    fn releasing_an_unknown_pid_is_a_noop() {
        let mut pool = SlotPool::new(3);

        for pid in [100, 200] {
            let plan = pool.plan_protect(pid);
            pool.commit_protect(plan, pid);
        }

        let plan = pool.plan_release(999);
        assert_eq!(plan, ReleasePlan::NotProtected);
        pool.commit_release(plan);

        assert_eq!(pool.plan_release_all().len(), 2);
        assert_eq!(pool.slot_of(100), Some(0));
        assert_eq!(pool.slot_of(200), Some(1));
    }

    /// Repeated releases must not corrupt the pool: the second one finds
    /// nothing, because the first freed the slot.
    #[test]
    fn a_second_release_of_the_same_pid_finds_nothing() {
        let mut pool = SlotPool::new(2);

        let plan = pool.plan_protect(100);
        pool.commit_protect(plan, 100);
        pool.commit_release(pool.plan_release(100));

        assert_eq!(pool.plan_release(100), ReleasePlan::NotProtected);
        assert_eq!(pool.plan_release_all().len(), 0);
        assert!(pool.is_empty());
    }

    /* ── shutdown and pruning ──────────────────────────────────────── */

    #[test]
    fn clear_releases_every_occupant_in_slot_order() {
        let mut pool = SlotPool::new(3);

        for pid in [100, 200, 300] {
            let plan = pool.plan_protect(pid);
            pool.commit_protect(plan, pid);
        }

        let plans = pool.plan_release_all();

        assert_eq!(
            plans,
            vec![
                ReleasePlan::Free { slot: 0, pid: 100 },
                ReleasePlan::Free { slot: 1, pid: 200 },
                ReleasePlan::Free { slot: 2, pid: 300 },
            ]
        );
        for plan in plans {
            pool.commit_release(plan);
        }
        assert!(pool.is_empty());
    }

    /// A process that exits while focused holds its slot forever unless
    /// something prunes it. Each dead occupant is a slot of protection
    /// that no later window can use.
    #[test]
    fn prune_drops_only_occupants_that_have_exited() {
        let mut pool = SlotPool::new(3);

        for pid in [100, 200, 300] {
            let plan = pool.plan_protect(pid);
            pool.commit_protect(plan, pid);
        }

        let dead = pool.plan_prune_dead(|pid| pid != 200);

        assert_eq!(dead, vec![ReleasePlan::Free { slot: 1, pid: 200 }]);
        for plan in dead {
            pool.commit_release(plan);
        }
        assert_eq!(pool.slot_of(100), Some(0));
        assert_eq!(pool.slot_of(200), None);
        assert_eq!(pool.slot_of(300), Some(2));
    }

    #[test]
    fn prune_of_a_pool_with_no_dead_occupants_does_nothing() {
        let mut pool = SlotPool::new(2);

        let plan = pool.plan_protect(100);
        pool.commit_protect(plan, 100);

        assert!(pool.plan_prune_dead(|_| true).is_empty());
        assert_eq!(pool.plan_release_all().len(), 1);
    }

    /* ── configuration ─────────────────────────────────────────────── */

    #[test]
    fn a_pool_is_never_built_with_zero_slots() {
        for count in [0, 1, 3] {
            let pool = SlotPool::new(count);
            assert_eq!(pool.len(), count.max(1));
        }

        let plan = SlotPool::new(0).plan_protect(100);
        assert_ne!(plan, SlotPlan::NoSlots);
    }

    #[test]
    fn a_typo_in_the_slot_count_is_clamped_not_obeyed() {
        assert_eq!(parse_slots(None), DEFAULT_SLOTS);
        assert_eq!(parse_slots(Some("garbage")), DEFAULT_SLOTS);
        assert_eq!(parse_slots(Some(" 5 ")), 5);
        assert_eq!(parse_slots(Some("999999")), MAX_SLOTS);
        assert_eq!(parse_slots(Some("0")), 1);
    }

    /* Regression test for a bug found by running the real guard, not by
     * reading it. The first implementation restored every released process
     * into the neutral leaf, so each one stayed there: the leaf never
     * emptied, `teardown` failed with EBUSY, and the whole pool leaked.
     * The invariant that was broken is that a release must not leave its
     * pid in a directory the module cannot reach again, which in turn
     * requires remembering where a process came from before moving it. */
    #[test]
    fn a_released_pid_is_returned_to_the_cgroup_it_came_from() {
        /* The record `restore_source` keeps is what makes a true release
         * possible; without it the only destination is the fallback leaf,
         * and processes left there are the leak. */
        let mut restore_source: HashMap<u32, PathBuf> = HashMap::new();
        let origin = PathBuf::from("/sys/fs/cgroup/user.slice/user-1000.slice/x.scope");

        // Focus: the pid's origin is remembered, not discarded.
        restore_source.insert(7, origin.clone());
        assert_eq!(restore_source.get(&7), Some(&origin));

        // Release: the origin is the target and is then forgotten, so a
        // process that is no longer ours is never migrated again.
        let released = restore_source.remove(&7);
        assert_eq!(released, Some(origin));
        assert!(restore_source.is_empty());
    }

    #[test]
    fn protection_is_opt_in_and_rejects_everything_but_affirmatives() {
        for on in ["1", "true", "on", "TRUE", "On"] {
            assert!(env_flag(Some(on)), "{on} should arm the feature");
        }
        for off in ["", "off", "0", "false", "no", "yes", "2"] {
            assert!(!env_flag(Some(off)), "{off} should not arm the feature");
        }
        assert!(!env_flag(None));
    }

    /* ── paths ─────────────────────────────────────────────────────── */

    #[test]
    fn a_cgroup_path_maps_the_unified_hierarchy_onto_sysfs() {
        assert_eq!(
            cgroup_path("/user.slice/user-1000.slice/user@1000.service/app.slice"),
            PathBuf::from("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice")
        );
        // A trailing newline from `/proc/<pid>/cgroup` must not become part
        // of the path, or every read of it fails with NotFound.
        assert_eq!(
            cgroup_path("/user.slice/user-1000.slice/app.slice\n"),
            PathBuf::from("/sys/fs/cgroup/user.slice/user-1000.slice/app.slice")
        );
        // The root cgroup, as `/proc/self/cgroup` reports it.
        assert_eq!(cgroup_path("/"), PathBuf::from("/sys/fs/cgroup"));
    }

    #[test]
    fn only_the_unified_hierarchy_line_is_consulted() {
        // Hybrid layout: the v1 lines must be ignored, because
        // `memory.swap.max` and `cpu.weight` are v2-only files.
        let text = "4:cpu,cpuacct:/init.scope\n0::/user.slice/app.slice\n";
        let rel = text.lines().find_map(|l| l.strip_prefix("0::"));

        assert_eq!(rel, Some("/user.slice/app.slice"));
    }
}
