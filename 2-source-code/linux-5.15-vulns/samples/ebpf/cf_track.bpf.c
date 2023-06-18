#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 20);
    __type(key, u32);
    __type(value, u32);
} pcpu_flags SEC(".maps");

#define GFP_KERNEL	(__GFP_IO | __GFP_FS)
char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/bcm_sendmsg")
int BPF_KPROBE(probe0)
{
    u32 cpu = bpf_get_smp_processor_id();
    u32 pid = bpf_get_current_pid_tgid();
    int err = 0;
    err = bpf_map_update_elem(&pcpu_flags, &cpu, &pid, BPF_ANY);
    if (err < 0) {
        bpf_printk("bcm_sendmsg start map err %d\n", err);
        return err;
    }
    bpf_printk("bcm_sendmsg start %u %u\n", cpu, pid);
    return 0;
}


SEC("kretprobe/bcm_sendmsg")
int BPF_KRETPROBE(probe1)
{
    u32 cpu = bpf_get_smp_processor_id();
    u32 pid = bpf_get_current_pid_tgid();
    u32 val = 0;
    int err = 0;
    u32 *pval = NULL;
    pval = bpf_map_lookup_elem(&pcpu_flags, &cpu);
    if (pval) {
        if (*pval == pid) {
            bpf_printk("bcm_sendmsg end   %u %u\n", cpu, pid);
            err = bpf_map_update_elem(&pcpu_flags, &cpu, &val, BPF_ANY);
            if (err < 0) {
                bpf_printk("bcm_sendmsg end map err %d\n", err);
                return err;
            }
        }
    }
    return 0;
}

u64 count = 0;
SEC("kprobe/__kmalloc")
int BPF_KPROBE(probe2)
{
    u32 len = ctx->di;
    u32 flag = ctx->si;
    u32 cpu = bpf_get_smp_processor_id();
    u32 pid = bpf_get_current_pid_tgid();
    int err = 0;
    u32 *pval = NULL;


    pval = bpf_map_lookup_elem(&pcpu_flags, &cpu);
    if (pval) {
        if (*pval == pid) {
            ++count;
            bpf_printk("__kmalloc under bcm_sendmsg: len:%u  %utimes\n", len, count);
        }
    }

    return 0;

}

SEC("kprobe/kmem_cache_alloc_trace")
int BPF_KPROBE(probe3)
{
    u32 len = ctx->dx;
    u32 cpu = bpf_get_smp_processor_id();
    u32 pid = bpf_get_current_pid_tgid();
    int err = 0;
    u32 *pval = NULL;


    pval = bpf_map_lookup_elem(&pcpu_flags, &cpu);
    if (pval) {
        if (*pval == pid) {
            ++count;
            bpf_printk("kmem_cache_alloc_trace under bcm_sendmsg: len:%u  %utimes\n", len, count);
        }
    }

    return 0;

}