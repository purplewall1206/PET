#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";

// BUG: KASAN: use-after-free in vb2_mmap+0x662/0x6f0 drivers/media/common/videobuf2/videobuf2-core.c:2147
// Read of size 8 at addr ffff8881ccc42d80 by task syz-executor444/6068



const char target[32] = "";
u32 offset = 0x0; // const char  *              source;               /*   112     8 */




struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 12000000);
    __type(key, u64); 
    __type(value, u64); 
} dangling_ptr_map SEC(".maps");



struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 40960);
    __type(key, u64); // quarantined objects
    __type(value, u64); 
} quarantine_map SEC(".maps");



struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200);
    __type(key, u64); // quarantined flag
    __type(value, u64); 
} quaran_flag SEC(".maps");


struct hmap_elem {
	// int pad; /* unused */
	struct bpf_timer timer;
};

struct inner_map {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, int);
	__type(value, struct hmap_elem);
} inner_htab SEC(".maps");

#define ARRAY_KEY 1
#define HASH_KEY 1234

struct outer_arr {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 100);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__array(values, struct inner_map);
} outer_arr SEC(".maps") = {
	.values = { [ARRAY_KEY] = &inner_htab },
};
    

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200);
    __type(key, u32); // pid
    __type(value, struct pt_regs); 
} checkpoints SEC(".maps");


u64 INTERVAL = 1 * (u64)1000000000;

#define RANGE_FLAG	0
#define OFFSET_FLAG	1

u64 count = 0;

static int timer_sweep(void *map, int *key, struct hmap_elem *val)
{
    int err = 0;
    
    unsigned long GB = (1 << 30);
    unsigned long MB = (1 << 20);
    unsigned long len = GB;
    unsigned long start_addr = (count % 16) * len;
    // unsigned long len = 512 * MB;
    // unsigned long start_addr = (count % 32) * len;
    // unsigned long len = 256 * MB;
    // unsigned long start_addr = (count % 64) * len;    
    // unsigned long len = 128 * MB;
    // unsigned long start_addr = (count % 128) * len;
    

    // start_addr = (count % 32) * len;

    bpf_printk("timer_sweep %d\n", count);
    struct range_args args = {start_addr, len};
    bpf_uaf_dangling_ptr_sweep(&dangling_ptr_map, &args, RANGE_FLAG);
    bpf_printk("sweep dangling ptr from %lx with %lx bytes\n", start_addr, len);
    if (count != 0 && count % 16 == 0) {
        bpf_printk("freeundangle : %d\n", count);
        bpf_uaf_free_undangle(&dangling_ptr_map, &quarantine_map, RANGE_FLAG);
    }
    ++count;

    // struct range_args args = {0x0, ((unsigned long)1 << 30) * (unsigned long)17};
    // bpf_uaf_dangling_ptr_sweep(&dangling_ptr_map, &args, RANGE_FLAG);
    // bpf_uaf_free_undangle(&dangling_ptr_map, &quarantine_map, RANGE_FLAG);


    bpf_timer_set_callback(&val->timer, timer_sweep);
    bpf_timer_start(&val->timer, INTERVAL, 0);

    return 0;
}



// static int __vb2_queue_free(struct vb2_queue *q, unsigned int buffers)
// 	unsigned int buffer;
// 	/* Free videobuf buffers */
// 597	for (buffer = q->num_buffers - buffers; buffer < q->num_buffers;
// 598	     ++buffer) {
// 599		kfree(q->bufs[buffer]);




// python3 -c 'print(hex(0xffffffff81321c6c-0xffffffff81321b80))
// quarantine fc->source
SEC("kprobe/__vb2_queue_free")
int BPF_KPROBE(prog0)
{
    u64 fc_source = ctx->di ^ 0xffffffffffffffff;

    u64 val = 0;
    int err = bpf_map_update_elem(&quaran_flag, &fc_source, &val, BPF_ANY);
    bpf_printk("setup flag: %lx\n", fc_source);
    if (err < 0) {
        bpf_printk("put_fs_context quarantine fc->source failed: %d\n", err);
    }
    return err;
}


// clear the quarantined struct free
SEC("kprobe/kmem_cache_free")
int BPF_KPROBE(prog1)
{
    u64 f = ctx->si ^ 0xffffffffffffffff;
    u32 v = bpf_get_buff_len(ctx->si);
    // bpf_printk("kmem_cache_free: %lx, %lx, %u\n", ctx->di, ctx->si, v);
    u64 *pv = bpf_map_lookup_elem(&quarantine_map, &f);
    int err = 0;
    if (pv) {
        bpf_printk("sweeped struct file %lx\n", f);
        err = bpf_map_delete_elem(&quarantine_map, &f);
        if (err < 0) {
            bpf_printk("sweep failed: %d\n", err);
        }
    }
    return err;
}

SEC("kprobe/file_free_rcu")
int BPF_KPROBE(prog2)
{
    u64 f = ctx->di  ^ 0xffffffffffffffff;
    u32 v = bpf_get_buff_len(ctx->di);
    // bpf_printk("kmem_cache_free: %lx, %lx, %u\n", ctx->di, ctx->si, v);
    u64 *pv = bpf_map_lookup_elem(&quarantine_map, &f);
    int err = 0;
    if (pv) {
        bpf_printk("sweeped in file_free_rcu struct file %lx\n", f);
        err = bpf_map_delete_elem(&quarantine_map, &f);
        if (err < 0) {
            bpf_printk("sweep failed: %d\n", err);
        }
    }
    return err;
}



#define ARRAY_KEY 1
#define HASH_KEY 1234
#define CLOCK_REALTIME			0
#define CLOCK_MONOTONIC			1


int timer_init(void)
{
    int err = 0;
    struct hmap_elem init = {};
	struct bpf_map *inner_map;
	struct hmap_elem *val;
	int array_key = ARRAY_KEY;
	int hash_key = HASH_KEY;

    u32 pid = bpf_get_current_pid_tgid();
    
    u64 v = 0;
    u32 *pval = NULL;


    inner_map = bpf_map_lookup_elem(&outer_arr, &array_key);
    if (!inner_map)
        return 0;
    bpf_map_update_elem(inner_map, &hash_key, &init, 0);
    val = bpf_map_lookup_elem(inner_map, &hash_key);
    if (!val)
        return 0;
    bpf_timer_init(&(val->timer), inner_map, CLOCK_REALTIME);
    err = bpf_timer_set_callback(&val->timer, timer_sweep);
    if (err < 0) {
        bpf_printk("bpf_timer_set_callback failed\n");
        return err;
    }
    err = bpf_timer_start(&val->timer, INTERVAL, 0);
    if (err < 0) {
        bpf_printk("bpf_timer_start failed\n");
        return err;
    }

    bpf_printk("==========initialized===========\n");
}

int init_flag = 0;
SEC("kprobe/kfree")
int BPF_KPROBE(initialized)
{
    int err = 0;
    u32 pid = bpf_get_current_pid_tgid();
    u64 v = 0;
    u32 *pval = NULL;
    u32 *pv1 = NULL;
    // err = bpf_map_update_elem(&quaran_flag, &cpu, &pid, BPF_ANY);
    u64 obj_addr = ctx->di ^ 0xffffffffffffffff;
    pval = bpf_map_lookup_elem(&quaran_flag, &obj_addr);
    if (pval != NULL) {
        // skip the kfree and quarantine the freed object
        v = bpf_get_buff_len(ctx->di);
        bpf_printk("put_fs_context quarantine fc->source %u: %lx:%u\n", pid, obj_addr, v);

        if (*pval) {
            pv1 = bpf_map_lookup_elem(&quarantine_map, &obj_addr);
            if (pv1) {
                bpf_printk("===double free %u: %lx=====\n", v, obj_addr);
            }
            err = bpf_map_update_elem(&quarantine_map, &obj_addr, &v, BPF_ANY);
        } 

        err |= bpf_map_delete_elem(&quaran_flag, &obj_addr);
        if (err < 0) {
            bpf_printk("quarantine failed %d\n", err);
            return -1;
        }
        bpf_override_return(ctx, 0);
    }

// ========timer init===================
    if (!init_flag) {
        init_flag = 1;
        timer_init();

        // unsigned long MB = (1 << 20);
        // unsigned long len = 512 * MB;
        // // struct range_args args = {0x0, ((unsigned long)1 << 30) * (unsigned long)17};
        // struct range_args args = {0x0, len * (unsigned long)1};
        // bpf_uaf_dangling_ptr_sweep(&dangling_ptr_map, &args, RANGE_FLAG);
        // bpf_uaf_free_undangle(&dangling_ptr_map, &quarantine_map, RANGE_FLAG);
    }
    
    return 0;
}

