<div align=center>

<img width="1672" height="941" alt="animalavd-logo" src="https://github.com/user-attachments/assets/9d1c8455-62d7-4653-af3d-79877b1e04e2" />
<br><br>

[![ Hyprland](https://img.shields.io/badge/Hyprland-compatible-blueviolet)](https://hyprland.org)
[![DeepSource](https://app.deepsource.com/gh/animaios/animalavd.svg/?label=code+coverage&show_trend=true&token=hTeG3XzzElKjGvZdZ_zO7CaZ)](https://app.deepsource.com/gh/animaios/animalavd/)

[![DeepSource](https://app.deepsource.com/gh/animaios/animalavd.svg/?label=active+issues&show_trend=true&token=hTeG3XzzElKjGvZdZ_zO7CaZ)](https://app.deepsource.com/gh/animaios/animalavd/)
[![DeepSource](https://app.deepsource.com/gh/animaios/animalavd.svg/?label=resolved+issues&show_trend=true&token=hTeG3XzzElKjGvZdZ_zO7CaZ)](https://app.deepsource.com/gh/animaios/animalavd/)

**A `sched_ext` LAVD scheduler fork that adds compositor-aware scheduling to Linux desktops.**

</div>

Unlike traditional schedulers that only see CPU usage, AnimaLAVD understands what the user is actually interacting with:

* 🖥️ **Focused Hyprland window gets immediate CPU priority**
* 🎧 **Audio workloads stay latency-safe during heavy system load**
* 🌐 **Optional browser integration boosts the active tab renderer**
* ⚡ **Rust-powered userspace daemon updates scheduler state in real time**
* 🧬 **eBPF-backed scheduler decisions without kernel patches**

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
eBPF sched_ext scheduler
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

The focused application receives a latency boost through the LAVD criticality system.

No:

* `nice`
* `renice`
* wrapper scripts
* application-specific hacks

The scheduler handles it directly.

---

## ⚡ Real-time Rust control daemon

`anima-hypr-daemon`:

* listens to Hyprland IPC events
* tracks focused windows
* resolves window → PID mappings
* updates pinned BPF maps directly

Implementation:

* Rust
* `libbpf-rs`
* direct `bpf()` map updates
* incremental updates only

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
anima_active_pids BPF map
    ↓
same LAVD boost as the focused window
```

```
Firefox playing a YouTube tab (unfocused)
        ↓
its PID is in the map even while you type
```

Streams arrive as events rather than being polled, so focus and audio
are tracked as **separate inputs** and a stream that starts or stops
while you keep typing is picked up without a focus event. Audio and the
focused window receive the *same* boost — there is no per-PID priority
in the map. If you want to reweight them, the lever is `ANIMA_BOOST`,
which applies to all boosted PIDs alike.

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
                    |
              focus events
                    |
                    v
        anima-hypr-daemon (Rust)
                    |
                    |
        pinned BPF maps (/sys/fs/bpf)
                    |
                    v
            scx_lavd-anima
                    |
                    v
          Linux sched_ext subsystem
                    |
                    v
                   CPU
```

---

# How the boost works

LAVD already calculates latency criticality based on task behavior.

AnimaLAVD adds one extra signal:

```
Is this PID currently user-focused?
```

If yes:

```
lat_cri = configured focus boost
```

The focused task enters LAVD's highest latency class.

Default:

```
ANIMA_BOOST=896
```

This gives the active application scheduler preference without completely starving background workloads.

---

# Design goals

## Preserve LAVD behavior

AnimaLAVD does not replace LAVD's scheduling logic.

It adds one additional signal:

```
User attention
```

Everything else remains upstream LAVD.

---

## Low overhead

Focus changes are rare.

Each update:

* modifies only changed PIDs
* uses direct BPF map operations
* avoids userspace/kernel round trips

---

## Safe degradation

If:

* Hyprland stops
* daemon exits
* map is unavailable

The scheduler falls back to normal LAVD behavior.

No permanent priority changes are applied.

---

# Roadmap

* [x] Hyprland focus tracking
* [x] Rust userspace daemon
* [x] eBPF PID priority map
* [x] Runtime boost tuning
* [x] Window tree filtering
* [x] PipeWire latency integration
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
