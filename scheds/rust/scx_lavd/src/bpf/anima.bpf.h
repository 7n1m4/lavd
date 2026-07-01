/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AnimAIOS shared declarations for focused-window priority boost.
 */
#ifndef __ANIMA_H
#define __ANIMA_H

#include <scx/common.bpf.h>
#include "intf.h"

/*
 * AnimAIOS boost level. Out of LAVD_SCALE (=1024), this puts the focused
 * task firmly in the LC top 12.5% — equivalent to the scheduler's own
 * LAVD_LC_LATENCY_SENSITIVE_THRESH — so the focused task wins the
 * tightest-possible deadline bucket.
 *
 * Crucially, this is not UINT16_MAX (0xFFFF). Setting lat_cri above ~896
 * makes the deadline `adjusted_runtime * greedy_penalty / lat_cri` collapse
 * to sub-nanosecond territory: dl_delta rounds to zero, and whether the
 * focused task is on-CPU or not makes no difference to everyone else.
 * That's overkill: it starves background work and clamps preemption
 * granularity. 896 gives the focused task the same priority boost that
 * LAVD's own heuristics already grant to its top-sensitivity tier — just
 * enough to win the next dispatch without wrecking the fairness accounting.
 */
enum {
	LAVD_ANIMA_LC_BOOST = (1024 * 7) / 8,  /* 896, top 12.5% LC */
};

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
