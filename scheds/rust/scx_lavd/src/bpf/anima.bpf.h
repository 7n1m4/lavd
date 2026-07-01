/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AnimAIOS shared declarations for focused-window priority boost.
 */
#ifndef __ANIMA_H
#define __ANIMA_H

#include <scx/common.bpf.h>
#include "intf.h"

/*
 * Runtime-tunable boost level. The daemon writes this value once at startup
 * into the `anima_config` BPF map. Default is LAVD_ANIMA_LC_BOOST_DFL (896)
 * if the map is empty or the daemon hasn't written yet.
 *
 * Valid range: 0 (disable boost) .. 1024 (=LAVD_SCALE, max sensible value).
 * Values above ~900 start collapsing dl_delta toward zero — setting
 * lat_cri that high divides `adjusted_runtime * greedy_penalty / lat_cri`
 * down to sub-ns territory: dl_delta rounds to zero, and whether the
 * focused task is on-CPU or not makes no difference to everyone else.
 * That starves background work and clamps preemption granularity.
 * 896 (=LAVD_SCALE * 7/8) puts the focused task in the same top-12.5%
 * latency-criticality bucket as LAVD's own LAVD_LC_LATENCY_SENSITIVE_THRESH.
 */
enum {
	LAVD_ANIMA_LC_BOOST_DFL = (1024 * 7) / 8,  /* 896, top 12.5% LC */
};

/*
 * Runtime-tunable config map. The daemon writes the boost level once at
 * startup into key 0; BPF falls back to LAVD_ANIMA_LC_BOOST_DFL if the
 * lookup fails (e.g., scheduler booted before the daemon).
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} anima_config SEC(".maps");

/*
 * Map of PIDs belonging to the currently Hyprland focused window.
 * Userspace maintains this via Hyprland IPC.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, u32);
	__type(value, u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} anima_active_pids SEC(".maps");

/*
 * Returns true if `pid` should be treated as latency-critical because it
 * is the focused window (or a direct child in window+tree mode).
 */
static __always_inline bool is_anima_focused_pid(u32 pid)
{
	return bpf_map_lookup_elem(&anima_active_pids, &pid) != NULL;
}

#endif /* __ANIMA_H */
