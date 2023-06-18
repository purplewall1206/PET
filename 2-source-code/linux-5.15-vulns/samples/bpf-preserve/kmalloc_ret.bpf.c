#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// #include <linux/gfp.h>
// #include <linux/slab.h>
#define ___GFP_IO		0x40u
#define ___GFP_FS		0x80u
#define __GFP_IO	(___GFP_IO)
#define __GFP_FS	(___GFP_FS)

// #define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)
#define GFP_KERNEL	(__GFP_IO | __GFP_FS)
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 40960);
    __type(key, u64);
    __type(value, u64);
} kmalloc_hash SEC(".maps");

// int replace = 0;

SEC("kprobe/__kmalloc")
int BPF_KPROBE(kmalloc_ret)
{
    u64 alloc_len = ctx->di;
    u32 alloc_flag = ctx->si;
    int err = 0;

    if (alloc_len > 1000) {
        bpf_printk("__kmalloc: %lu\n", alloc_len);
        u64 new = bpf_kmalloc(alloc_len * 2, alloc_flag);
        bpf_printk("__kmalloc new : %lx\n", new);
        err = bpf_map_update_elem(&kmalloc_hash, &new, &alloc_len, BPF_ANY);
        if (err < 0) {
            bpf_printk("__kmalloc err: %d\n", err);
            return err;
        }
        err = bpf_override_return(ctx, new);
        bpf_printk("__kmalloc: replace %d\n", err);
    }
    
    return 0;
}

SEC("kprobe/kmem_cache_alloc_trace")
int BPF_KPROBE(prog1)
{
    u64 alloc_len = ctx->dx;
    u32 alloc_flag = ctx->si;
    int err = 0;
    // u64 val = 1;

    if (alloc_len > 1000) {
        bpf_printk("kmem_cache_alloc_trace: %lu\n", alloc_len);
        u64 new = bpf_kmalloc(alloc_len * 2, alloc_flag);
        bpf_printk("kmem_cache_alloc_trace new : %lx\n", new);
        err = bpf_map_update_elem(&kmalloc_hash, &new, &alloc_len, BPF_ANY);
        if (err < 0) {
            bpf_printk("kmem_cache_alloc_trace err: %d\n", err);
            return err;
        }
        err = bpf_override_return(ctx, new);
        bpf_printk("kmem_cache_alloc_trace: replace %d\n", err);
    }
    return 0;
}

// bpftrace -e 'kprobe:__kmalloc{if (arg0 > 512) { @[kstack]=count();}}'

SEC("kprobe/kfree")
int BPF_KPROBE(kmalloc_ret_free)
{
    u64 addr = ctx->di;
    u64 *pval = bpf_map_lookup_elem(&kmalloc_hash, &addr);
    int err = 0;
    if (pval) {
        bpf_printk("kfree %lx  %lu\n", addr, *pval);
        err = bpf_kfree((void *)addr);
        err = bpf_map_delete_elem(&kmalloc_hash, &addr);
        if (err < 0) {
            bpf_printk("kfree err: %d\n", err);
            return err;
        }
        err = bpf_override_return(ctx, 0);
        bpf_printk("kfree: replace %d\n", 0);
    }
    return 0;
}
