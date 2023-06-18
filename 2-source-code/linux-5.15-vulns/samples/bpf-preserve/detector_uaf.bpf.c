// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>


// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 40960);
//     __type(key, u64); // start addr of page
//     __type(value, u64); 
// } slab_page_map SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 40960);
//     __type(key, u64); // quarantined objects
//     __type(value, u64); 
// } quaran_obj_map SEC(".maps");


// struct hmap_elem {
// 	// int pad; /* unused */
// 	struct bpf_timer timer;
// };

// struct inner_map {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 1024);
// 	__type(key, int);
// 	__type(value, struct hmap_elem);
// } inner_htab SEC(".maps");

// #define ARRAY_KEY 1
// #define HASH_KEY 1234

// struct outer_arr {
// 	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
// 	__uint(max_entries, 100);
// 	__uint(key_size, sizeof(int));
// 	__uint(value_size, sizeof(int));
// 	__array(values, struct inner_map);
// } outer_arr SEC(".maps") = {
// 	.values = { [ARRAY_KEY] = &inner_htab },
// };
    
// u32 offset = 0x0;

// static int timer_sweep(void *map, int *key, struct hmap_elem *val)
// {

//     int err = bpf_uaf_slab_sweep(&slab_page_map, &quaran_obj_map, offset);
//     bpf_printk("timer_sweep\n");
//     bpf_timer_set_callback(&val->timer, timer_sweep);
//     bpf_timer_start(&val->timer, 1000000000, 0);

//     return 0;
// }

// int bpf_strcmp(char *dst, char *src, unsigned int size)
// {
//     for (int i = 0;i < 256;i++) {
//         if (i >= size) {
//             return -1;
//         }
//         if (dst[i] == '\0' && src[i] == '\0') {
//             return i;
//         }
//         if (dst[i] != src[i]) {
//             return -1 * i;
//         }
//     }
//     return 1;
// }

// const char target[32] = "skbuff_head_cache";
// // const char target[32] = "kmalloc-96";
// struct kmem_cache *target_cache = NULL;

// int isTarget(struct kmem_cache *cache)
// {
//     if (target_cache == NULL) {
//         const char *p;
//         char str[32];
//         bpf_core_read(&p, sizeof(p), &cache->name);
//         bpf_probe_read_kernel_str(str, sizeof(str), p);

//         if (bpf_strcmp(str, target, sizeof(str))) {
//             target_cache = cache;
//             return 1;
//         } else {
//             return 0;
//         }
//     } else if (target_cache == cache) {
//         return 1;
//     } else {
//         return 0;
//     }
// }

// // static struct page *new_slab(struct kmem_cache *s, gfp_t flags, int node)
// // s: [0xffffffff812cf4c6, 0xffffffff812cf5b3): DW_OP_reg3 RBX
// // SEC("kretprobe/new_slab")**int retprobe, registers are poped, you cannot read them**
// // int BPF_KRETPROBE(prog2)
// // python -c 'print(hex(0xffffffff812cf47c-0xffffffff812cf290))'
// // [0xffffffff812cf2b3, 0xffffffff812cf488): DW_OP_reg3 RBX

// // ffffffff812cf473:       f0 48 01 42 28          lock add %rax,0x28(%rdx)
// // ffffffff812cf478:       5b                      pop    %rbx
// // ffffffff812cf479:       4c 89 e0                mov    %r12,%rax
// SEC("kprobe/new_slab+0x1e8")
// int BPF_KPROBE(prog2) // ret instruction in the new_slab is not in the end.
// {
//     struct kmem_cache *cache = (struct kmem_cache*) ctx->di;
//     struct kmem_cache_order_objects oo = BPF_CORE_READ(cache, oo);
//     struct page *page = ctx->r12;
//     u32 order = (u32) oo.x >> 16;
//     u32 size = BPF_CORE_READ(cache, object_size);
//     int err = 0;
  
//     if (isTarget(cache)) {
//         u64 key = (u64) page;
//         u64 val = 0;
//         err = bpf_map_update_elem(&slab_page_map, &key, &val, BPF_ANY);
//         if (err < 0) {
//             bpf_printk("new_slab:failed insert:page 0x%lx\n", key);
//             return -1;
//         } 
//         bpf_printk("ret: page:0x%lx, bx:0x%lx, ip:0x%lx\n", ctx->r12, ctx->bx, ctx->ip);
//     }
//     return 0;
// }





// // static void __free_slab(struct kmem_cache *s, struct page *page)
// // order [0xffffffff812d04a0, 0xffffffff812d04b9): DW_OP_reg14 R14)
// SEC("kprobe/__free_slab")
// int BPF_KPROBE(prog3)
// {
//     struct kmem_cache *cache = (struct kmem_cache*) ctx->di;
//     struct page* page = ctx->si;
//     int err = 0;
//     if (isTarget(cache)) {
//         u64 key = (u64) page;
//         err = bpf_map_delete_elem(&slab_page_map, &key);
//         if (err < 0) {
//             bpf_printk("__free_slab:failed delete:page 0x%lx\n", key);
//             return -1;
//         }
//         bpf_printk("__free_slab: page:0x%lx\n",  page);
//     }
//     return 0;
// }

// #define ARRAY_KEY 1
// #define HASH_KEY 1234
// #define CLOCK_REALTIME			0
// #define CLOCK_MONOTONIC			1

// int init_flag = 0;
// SEC("kprobe/kfree")
// int BPF_KPROBE(initialized)
// {
//     int err = 0;
//     struct hmap_elem init = {};
// 	struct bpf_map *inner_map;
// 	struct hmap_elem *val;
// 	int array_key = ARRAY_KEY;
// 	int hash_key = HASH_KEY;


//     if (!init_flag) {
//         init_flag = 1;
//         err = bpf_uaf_slab_init(target, &slab_page_map);
//         inner_map = bpf_map_lookup_elem(&outer_arr, &array_key);
//         if (!inner_map)
//             return 0;
//         bpf_map_update_elem(inner_map, &hash_key, &init, 0);
//         val = bpf_map_lookup_elem(inner_map, &hash_key);
//         if (!val)
//             return 0;
//         bpf_timer_init(&(val->timer), inner_map, CLOCK_REALTIME);
//         err = bpf_timer_set_callback(&val->timer, timer_sweep);
//         if (err < 0) {
//             bpf_printk("bpf_timer_set_callback failed\n");
//             return err;
//         }
//         err = bpf_timer_start(&val->timer, 1000000000, 0);
//         if (err < 0) {
//             bpf_printk("bpf_timer_start failed\n");
//             return err;
//         }

//         bpf_printk("==========initialized===========\n");
//     }
//     return 0;
// }


// // mem_init_print_info
// //     get_num_physpages
// //     nr_free_pages()
// //     physpages << (PAGE_SHIFT - 10)

// // VMEMMAP_START





// char LICENSE[] SEC("license") = "Dual BSD/GPL";







// //    1. kill process
// //    2. inference-> generalize
// //    3. position our work? still time window?