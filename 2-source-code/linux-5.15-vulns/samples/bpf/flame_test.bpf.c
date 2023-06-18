#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 40960);
    __type(key, u32); // quarantined objects
    __type(value, u64); 
} latency SEC(".maps");


// 0x02fb418f:         DW_TAG_inlined_subroutine
//                       DW_AT_abstract_origin     (0x02fb4d4d "shuffle_freelist")
//                       DW_AT_entry_pc    (0xffffffff8130dd5b)
//                       DW_AT_GNU_entry_view      (0x0007)
//                       DW_AT_ranges      (0x00101b52
//                          [0xffffffff8130dd5b, 0xffffffff8130de88)
//                          [0xffffffff8130dec5, 0xffffffff8130ded9)
//                          [0xffffffff8130df9c, 0xffffffff8130dfb1)
//                          [0xffffffff8130e00b, 0xffffffff8130e020)
//                          [0xffffffff8130e0a2, 0xffffffff8130e0a4)
//                          [0xffffffff81cd6472, 0xffffffff81cd6472))
//                       DW_AT_call_file   ("/home/ppw/Documents/ebpf-detector/linux-5.15-vulns/mm/slub.c")
//                       DW_AT_call_line   (1936)
//                       DW_AT_call_column (0x0c)
//                       DW_AT_sibling     (0x02fb459c)

SEC("kprobe/new_slab")
int BPF_KPROBE(prog0)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&latency, &pid, &ts, BPF_ANY);
    return 0;
}


SEC("kretprobe/new_slab")
int BPF_KRETPROBE(prog1s)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    u64 *pts = bpf_map_lookup_elem(&latency, &pid);
    if (pts) {
        u64 lat = ts - *pts;
        bpf_map_update_elem(&latency, &pid, &lat, BPF_ANY);
    }
    return 0;
}



char LICENSE[] SEC("license") = "Dual BSD/GPL";

