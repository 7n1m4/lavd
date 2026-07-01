/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AnimAIOS shared declarations for focused-window priority boost.
 */
#ifndef __ANIMA_H
#define __ANIMA_H

#include <scx/common.bpf.h>
#include "intf.h"

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
