#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 20000);
    __type(key, unsigned long); 
    __type(value, unsigned long); 
} record SEC(".maps");

SEC("kretprobe/__kmalloc")
int BPF_KRETPROBE(handle_kmalloc)
// int handle_ret_kmalloc(struct pt_regs* ctx)
{	
	unsigned long ret = ctx->ax;
	unsigned long v = 0;
	int err = bpf_map_update_elem(&record, &ret, &v, BPF_ANY);
	if (err < 0) {
		bpf_printk("update failed %d\n", err);
		return err;
	}
	return 0;
}


SEC("kprobe/kfree")
int BPF_KPROBE(handle_kfree)
// int handle_kfree(struct pt_regs* ctx)
{
	unsigned long k = ctx->di;
	u64 *pv = bpf_map_lookup_elem(&record, &k);
	if (pv) {
		// bpf_printk("-----\n");
		int res = bpf_map_delete_elem(&record, &k);
		if (res < 0) {
			bpf_printk("delete failed %d\n", res);
			return res;
		}
	}
	
	return 0;
}

SEC("kprobe/htab_map_update_elem")
int BPF_KPROBE(check)
// int handle_check(struct pt_regs* ctx)
{
	bpf_printk("======htab_map_update_elem, key: %lx, %lx========\n", ctx->si, ctx->dx);
	return 0;
}

SEC("kprobe/htab_map_lookup_elem")
int BPF_KPROBE(check1)
// int handle_check(struct pt_regs* ctx)
{
	bpf_printk("======htab_map_lookup_elem, key: %lx, %lx========\n", ctx->si, ctx->dx);
	return 0;
}

SEC("kprobe/bpf_get_current_pid_tgid")
int BPF_KPROBE(check2)
{
	bpf_printk("=======\n");
	return 0;
}