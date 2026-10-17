<div align=center>

<img width="1672" height="941" alt="animalavd-logo" src="https://github.com/user-attachments/assets/9d1c8455-62d7-4653-af3d-79877b1e04e2" />
<br><br>

[![ Hyprland](https://img.shields.io/badge/Hyprland-compatible-blueviolet)](https://hyprland.org)
[![DeepSource](https://app.deepsource.com/gh/animaios/animalavd.svg/?label=code+coverage&show_trend=true&token=hTeG3XzzElKjGvZdZ_zO7CaZ)](https://app.deepsource.com/gh/animaios/animalavd/)

[![DeepSource](https://app.deepsource.com/gh/animaios/animalavd.svg/?label=active+issues&show_trend=true&token=hTeG3XzzElKjGvZdZ_zO7CaZ)](https://app.deepsource.com/gh/animaios/animalavd/)
[![DeepSource](https://app.deepsource.com/gh/animaios/animalavd.svg/?label=resolved+issues&show_trend=true&token=hTeG3XzzElKjGvZdZ_zO7CaZ)](https://app.deepsource.com/gh/animaios/animalavd/)

**Compositor-aware CPU scheduling for Linux desktops — a `sched_ext` LAVD fork plus a BORE/EEVDF backend for stock kernels.**

</div>

Unlike traditional schedulers that only see CPU usage, AnimaLAVD understands what the user is actually interacting with:

* 🖥️ **Focused Hyprland window gets immediate CPU priority**
* 🎧 **Audio workloads stay latency-safe during heavy system load**
* 🌐 **Optional browser integration boosts the active tab renderer**
* ⚡ **Rust-powered userspace daemon updates scheduler state in real time**
* 🧬 **Runs on `sched_ext` LAVD *and* on a stock BORE kernel** — the same focus/audio state drives either backend

The result: a desktop that stays responsive while gaming, compiling, streaming, or running heavy workloads.

---

# Why AnimaLAVD?

Linux schedulers are excellent at optimizing fairness and throughput.

But they do not know:

> "This is the window the user is looking at right now."

A browser tab playing music, a game window, an IDE editor, or a terminal running a command all look like normal processes to the kernel.

AnimaLAVD bridges this gap.

It connects:

```
User intent
    ↓
Hyprland focus events
    ↓
Rust userspace controller
    ↓
backend chosen at startup (ANIMA_BACKEND)
    ├── scx_lavd loaded?  →  sched_ext LAVD   (eBPF map)
    └── otherwise         →  BORE / EEVDF     (nice + cpu.weight)
    ↓
CPU scheduling decisions
```

The scheduler can now prioritize **what matters to the user**, not just what consumes CPU.

---

# Features

## 🖱️ Focus-aware scheduling

When you switch windows:

```
Firefox → Terminal → Game
```

AnimaLAVD instantly updates the active PID list.

The focused application receives a latency boost — through LAVD's
criticality system when scx_lavd is loaded, and through `nice` plus a
`cpu.weight` cgroup otherwise.

No:

* wrapper scripts
* application-specific hacks

The scheduler handles it directly — LAVD reads the written `lat_cri`, the
stock scheduler reads the nice and weight the daemon writes.

---

## ⚡ Real-time Rust control daemon

`anima-hypr-daemon`:

* listens to Hyprland IPC events
* tracks focused windows
* resolves window → PID mappings
* drives the scheduler through per-task actuation

Two backends, same focus/audio state, same incremental reconciliation.
Exactly one runs per startup: the daemon probes for `sched_ext` and picks
(`auto` selects, see [Backend selection](#backend-selection)):

|| backend | scheduler | actuator | unit |
|---|---|---|---|
| EEVDF/BPF (`scx_lavd-anima`) | LAVD via `sched_ext` | PIDs written into pinned `anima_active_pids` / `anim` BPF maps, consulted in `lat_cri.bpf.c` | `anima-hypr.service` (user) |
| NICE (BORE/EEVDF) | stock CFS/EEVDF + BORE | `setpriority(2)` nice + a daemon-owned cgroup's `cpu.weight` | `anima-hypr-system.service` (root) |

How each boosts:

- **EEVDF/BPF** — a continuous `lat_cri` in `0..1024` written per PID, so the focused task can be placed anywhere in LAVD's latency scale rather than only at its top; the granularity is fine, but the map only exists while scx_lavd is loaded and holds the pins.
- **NICE** — `setpriority(2)` to `-10` plus a cgroup at `cpu.weight` 500, a coarse ladder that spans 40:1 in nice and needs weight to amplify; it is always available because it writes knobs the stock kernel already reads.

The NICE backend needs no loaded scheduler and no pinned map. It does
need `CAP_SYS_NICE` to raise the focused window above the daemon's own
nice — hence the root system unit — while the BPF path needs no privilege
beyond permission to open the pins its owner created.

<a name="backend-selection"></a>

### Backend selection

`ANIMA_BACKEND` chooses which actuator drives the boost. It is read once
at daemon start, never per focus event:

|| value | probe result | behaviour |
|---|---|---|
| `auto` (default) | `sched_ext` `enabled` **and** both pins open | EEVDF/BPF backend |
| `auto` (default) | anything else | NICE backend; the reason is logged once and the daemon continues |
| `eevdf` | probe fails | explicit error and exit — an explicit request is honoured, not silently overridden |
| `nice` | — | NICE backend, `sched_ext` is never consulted |

The probe is the pair of conditions the BPF backend actually depends on:
`/sys/kernel/sched_ext/state` must read `enabled` (a `disabled` or
`disabling` state means no BPF scheduler is attached and no map consumer
exists), and both `/sys/fs/bpf/anima_active_pids` and
`/sys/fs/bpf/anim` must open for reading and writing. A stale pin left by
a scheduler that has since unloaded is precisely what the state check
rejects: writing to it is silently dropping the boost, which is why the
pins are not opened when the state is not `enabled`. The probe reads no
map contents and writes nothing, so it is safe without root and without
scx_lavd running.

Failure while running is never fatal either: if a BPF write fails
mid-session (the scheduler unloaded under us), the daemon logs the exact
error once, stops writing that map, and describes itself as degraded on
its startup line.

Boost tuning, alongside the existing:

|| Variable | Default | Meaning |
|---|---|---|
| `ANIMA_BACKEND` | `auto` | `auto` \| `eevdf` \| `nice` |
| `ANIMA_BOOST_NICE` | `-10` | NICE backend: nice level written for boosted PIDs (`-20..=19`) |
| `ANIMA_BOOST_CPU_WEIGHT` | `500` | NICE backend: `cpu.weight` of the boost cgroup while active |
| `ANIMA_BOOST_CGROUP` | derived | NICE backend: where the boost cgroup is created |

Because of that selection the daemon can now start with no scx_lavd
running and without root: the nice backend's cgroup half is optional and
degrades to nice-only writes if the cgroup cannot be created or written,
and the BPF backend activates only when its probe succeeds.

Implementation:

* Rust
* `libbpf-rs` for the LAVD backend; plain libc/cgroup writes for BORE
* incremental updates only — a repeated focus event is a no-op
* baselines recorded before any write, so a release restores the
  pre-boost nice (and cgroup) rather than assuming 0

No:

* `bpftool` subprocess calls
* temporary files
* polling loops
* JSON parsing on every event

---

## 🎧 Latency protection for interactive workloads

Audio is detected at the source. The daemon subscribes to PipeWire's
registry and boosts whatever is playing:

```
PipeWire registry (global events)
    ↓
playback-stream events: start / stop
    ↓
PID resolved via the owning Client object
    ↓
same per-task boost as the focused window
```

```
Firefox playing a YouTube tab (unfocused)
        ↓
its PID is boosted even while you type
```

Streams arrive as events rather than being polled, so focus and audio
are tracked as **separate inputs** and a stream that starts or stops
while you keep typing is picked up without a focus event. Audio and the
focused window receive the *same* boost. If you want to reweight them,
the lever is `ANIMA_BOOST_NICE` — on the NICE backend, where it applies to
all boosted PIDs alike.

A stream node does not carry its own PID: it only carries `client.id`,
and the PID lives on the matching `PipeWire:Interface:Client` object as
`pipewire.sec.pid`. Both object types are watched and joined, so either
may be announced first — a stream seen before its client is resolved
once that client arrives.

The PipeWire protocol is used directly, so the whole audio path is
event-driven rather than a periodic subprocess. A stream stopping is
observed directly as a registry `global_remove` event instead of being
inferred from a stall, and there is nothing left to go stale between
polls. JACK, game audio threads and video playback are the same
mechanism: if it plays through a playback stream, it is boosted. If
PipeWire is unavailable the daemon logs it and skips audio boosting
entirely — focus tracking is unaffected.

Disable it with `ANIMA_AUDIO_BOOST=off`.

Set `ANIMA_AUDIO_TRACE=1` to narrate the classifier on stderr — why
each registry node was skipped and how each PID was resolved. Useful
when audio boosting appears to do nothing, because a rejected node is
otherwise indistinguishable from nothing playing.

The goal:

> Background workloads should never destroy interactive latency.

---

## 🧠 Swap protection for the focused window

A focused window that the kernel has pushed to swap is the worst possible
place for latency: every fault back in is a synchronous disk read, and the
compositor, not the background build, pays for underrun.

The daemon can move the process owning the focused window into a cgroup
with `memory.swap.max = 0`, so what it allocates from that point on cannot
be written out to swap.

```bash
anima-hypr-daemon window+tree
# opt out explicitly:
ANIMA_SWAP_PROTECT=off anima-hypr-daemon window+tree
```

On by default, because the protection matters most in the run nobody
configured — relocating a user process is a heavier intervention than a
scheduler boost, so an *unrecognized* value also turns it off rather
than being read as a yes. All four variables are read once at daemon
start, never per focus event:

| Variable | Default | Meaning |
|---|---|---|
| `ANIMA_SWAP_PROTECT` | on | `0`/`false`/`off` turn it off |
| `ANIMA_SWAP_SLOTS` | 3 | how many windows stay protected (1..=16) |
| `ANIMA_SWAP_SETTLE` | 250 ms | how long focus must hold before migrating |
| `ANIMA_SWAP_TRACE` | off | narrate every migration on stderr |

A migration is not free — two `cgroup.procs` writes plus a `cpu.weight`
mirror — so focus that flits between windows is debounced rather than
followed. While focus is still moving, nothing is migrated at all and the
window that already holds protection keeps its slot; the moment focus
settles, the old window is released and the new one pinned, once. Set
`ANIMA_SWAP_SETTLE=0` to migrate on the focus event itself, which is what
cycling through windows cheaply costs you.

Three properties worth knowing while it is on:

- **Only future allocations are protected.** cgroup v2 does not move
  memory charges on migration — the kernel documents this — so a
  browser's already-allocated heap stays swappable. What is protected is
  everything the window allocates going forward.
- **No `memory.max` is ever written.** The goal is to stop swapping, not
  to cap memory; a cap is an OOM kill, which for the compositor is worse
  than swapping.
- **CPU share is mirrored.** The source cgroup's `cpu.weight` is copied
  into the slot, so protection cannot silently change CPU distribution.

No `mlock(2)` is involved: it can only pin the caller's own address
space, so it cannot protect another process, and `memory.swappiness` is
root-only.

Release returns the window to the cgroup it came from. If that cgroup
refuses the write (root-owned GUI session scopes), a neutral `released/`
leaf is used instead — the fallback, not the normal path, because
processes left there would prevent the pool from being torn down.

Every step is best-effort: a cgroup that cannot be written leaves the
window swappable, which is the pre-existing behaviour, not a regression,
and the boost path is never gated on swap protection.

---

## 🌐 Browser active-tab boosting (optional)

Browsers hide useful information from the scheduler.

A browser extension can expose:

```
Active tab
    ↓
Renderer PID
    ↓
Anima daemon
    ↓
LAVD boost
```

Example:

```
100 browser tabs open

Focused YouTube tab
        ↓
Only its renderer receives priority
```

Background tabs remain normal.

---

# Architecture

```
                 Hyprland
                    |
              focus events
                    |
                    v
        anima-hypr-daemon (Rust)
                    |
            backend selected at startup
       (/sys/kernel/sched_ext/state + pins)
                    |
        ┌───────────┴───────────┐
        │  one path is active  │
        v                       v
pinned BPF maps            setpriority + cgroup
(/sys/fs/bpf)              cpu.weight
        │                       │
        v                       v
  scx_lavd-anima            BORE / EEVDF
        │                    (CFS, stock kernel)
        v                       │
  sched_ext                    │
        │                       │
        └───────────┬───────────┘
                    v
                   CPU
```

---

# How the boost works

The daemon answers one question the scheduler cannot:

```
Is this PID currently user-focused?
```

The answer is then applied with the levers the scheduler actually
reads. Exactly one of the two actuators is active for a given run — which
one is decided at startup by `ANIMA_BACKEND` (see
[Backend selection](#backend-selection)):

|| backend | yes → effect |
|---|---|
| LAVD (`sched_ext`) | `lat_cri` written to the pinned PID map; the focused task enters LAVD's highest latency class (default boost 896 = top 12.5% of the 0..1024 scale) |
| BORE / EEVDF | `nice` lowered (default `ANIMA_BOOST_NICE=-10`) and the process moved into a cgroup at `cpu.weight` 500 (`ANIMA_BOOST_CPU_WEIGHT`) |

Under BORE the nice write propagates into the weight itself:
`effective_prio_bore()` is `static_prio - MAX_RT_PRIO +
bore_score(p)`, and `set_load_weight()` scales that into the EEVDF
weight. The cgroup weight provides the amplification nice alone cannot,
since nice only spans 40:1 while `cpu.weight` spans 1..10000.

Both give the active application scheduler preference without
completely starving background workloads, and both are released — back
to the process's *pre-boost* nice, not to 0 — the moment focus moves on.

---

# Design goals

## Preserve the scheduler's own logic

Neither backend replaces the scheduler's decisions. Each adds one
additional signal:

```
User attention
```

- On LAVD, everything else remains upstream LAVD — the boost is one
  `lat_cri` override at the top of a computation that is otherwise
  unmodified.
- On BORE, the boost is a `nice` and a `cpu.weight`, both of which the
  stock scheduler consumes directly. BORE's own burst accounting —
  `bore_score(p)`, which rewards tasks that sleep often — is untouched,
  so an interactive task does not need the boost to win.

## Coexists with ananicy-cpp

The two daemons write the same field from opposite directions, so their
interaction was measured before either was trusted:

- ananicy matches by `comm`/`cmdline`, and applies a rule **once** when
  it first sees a PID. It never re-applies. A `nice` this daemon writes
  afterwards therefore stays put, and vice versa.
- ananicy can set `sched=idle` on a process. Under `SCHED_IDLE` a task
  never competes for CPU, so **nice has no effect** — the focused-window
  case is unaffected, but a background task ananicy demoted to idle
  cannot be revived by nice alone. The cgroup weight half of the boost
  is what restores a meaningful share there.

## Low overhead

Focus changes are rare.

Each update:

* modifies only changed PIDs (a repeated focus event is a no-op)
* uses direct syscalls / control-file writes — no subprocesses
* avoids polling the compositor or the audio server

---

## Safe degradation

If:

* Hyprland stops
* daemon exits
* the boost cgroup is unavailable
* scx_lavd unloads mid-session, so the BPF maps go away
* the startup probe finds no `sched_ext` at all

Every boost is released on exit (SIGTERM, SIGINT, crash, graceful), and
the scheduler falls back to its own behavior. What is *not* released is
the process itself: a release restores the pre-boost nice and the
pre-boost cgroup, so a background process demoted by ananicy goes back
to exactly what ananicy had set rather than to 0.

---

# Roadmap

* [x] Hyprland focus tracking
* [x] Rust userspace daemon
* [x] eBPF PID priority map (LAVD / `sched_ext` backend)
* [x] Runtime boost tuning
* [x] Window tree filtering
* [x] PipeWire latency integration
* [x] nice + `cpu.weight` boost backend (BORE / EEVDF)
* [x] Runtime backend selection: BPF when `sched_ext` is active, with nice as the always-available fallback
* [ ] Browser extension PID bridge
* [ ] Game launcher integration
* [ ] Per-application profiles

---

# The bigger idea

AnimaLAVD is an experiment in **human-aware scheduling**.

Traditional schedulers optimize:

```
CPU utilization
fairness
throughput
```

AnimaLAVD adds:

```
human attention
interaction latency
desktop responsiveness
```

The computer should prioritize what the user is doing — not what happens to be consuming the most CPU.

<img width="256" height="384" alt="AnimAIOS mascot" src="https://github.com/user-attachments/assets/6d6699ed-e61b-4e8a-8148-6d9ab4b36cef" />

---
