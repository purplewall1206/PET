#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

u64 ret_hackme_read = 0x0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200);
    __type(key, u64); // ip + size
    __type(value, u64); // stacktop
} index SEC(".maps");


// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 200);
//     __type(key, u64); // size
//     __type(value, u64); // stack top
// } index SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200);
    __type(key, u64); // address or stack top
    __type(value, u64); // next.
} in_free SEC(".maps");


void push(u64 ip_size, u64 addr)
{
	u64 *paddr = bpf_map_lookup_elem(&index, &ip_size);
	if (paddr) {
		u64 *pnext = bpf_map_lookup_elem(&in_free, paddr);
		if (pnext == NULL) {
			u64 next = 0;
			bpf_map_update_elem(&in_free, &addr, &next)
		} else {
			bpf_map_update_elem(&in_free, &addr, paddr);
		}
	} else {
		u64 next = 0;
		bpf_map_update_elem(&in_free, &addr, &next, BPF_ANY);
		bpf_map_update_elem(&index, &ip_size, &addr, BPF_ANY);
	}
}

u64 top_pop(u64 ip_size) {
	u64 *paddr = bpf_map_lookup_elem(&index, &ip_size);
	if (paddr) {
		u64 *pnext = bpf_map_lookup_elem(&in_free, paddr);
		if (pnext && *pnext != 0) {
			bpf_map_delete_elem(&in_free, paddr);
			bpf_map_update_elem(&index, &ip_size, pnext, BPF_ANY);
		}
	} else {
		return 0;
	}
	return *paddr;
}


// sudo bpftrace -e 'tracepoint:kmem:kmalloc {@[kstack]=count();}'
SEC("kprobe/kmem_cache_alloc_trace")
int probe_kmalloc(struct pt_regs *ctx)
{
	long loc = 0;
	long init_val = 1;
	long *value;

	unsigned long alloc_addr = 0;
	unsigned long alloc_size = 0;

	/* read ip of kfree_skb caller.
	 * non-portable version of __builtin_return_address(0)
	 */
	BPF_KPROBE_READ_RET_IP(loc, ctx);

	// u64 start_time = bpf_ktime_get_ns();
	
	if (loc == 0xffffffff8153149a) {
		// bpf_printk("hook invoking to kvmalloc_node in alloc_netdev_mqs()\n");

		// search infree map, if infree map is available, reuse
		// TODO
		
		// if infree map is not available, do ordinary allocation
		alloc_size = PT_REGS_PARM1(ctx);
		alloc_addr = bpf_vmalloc(alloc_size);
		long *prev_size = bpf_map_lookup_elem(&inuse_map, &alloc_addr);
		if (prev_size)
			*prev_size = 0; // never execute this line
		else
			bpf_map_update_elem(&inuse_map, &alloc_addr, &alloc_size, BPF_ANY);
	}

	/*
	// overhead statistics
	u64 end_time = bpf_ktime_get_ns();
	u64 delta = end_time - start_time;
	value = bpf_map_lookup_elem(&bpf_duration_map, &loc);
	if (value)
		*value = delta;
	else
		bpf_map_update_elem(&bpf_duration_map, &loc, &delta, BPF_ANY);
	*/

	// skip original kmalloc and override return value
	bpf_override_return2(ctx, (unsigned long)alloc_addr);
	return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";

