#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


// ffffffff81003620 <measureme_read>:
// ffffffff81003620:       e8 5b df 06 00          call   ffffffff81071580 <__fentry__>    ffffffff81003621: R_X86_64_PLT32        __fentry__-0x4
// ffffffff81003625:       55                      push   %rbp
// ffffffff81003626:       48 89 f5                mov    %rsi,%rbp
// ffffffff81003629:       53                      push   %rbx
// ffffffff8100362a:       48 89 d3                mov    %rdx,%rbx
// ffffffff8100362d:       48 83 ec 50             sub    $0x50,%rsp
// ffffffff81003631:       65 48 8b 04 25 28 00 00 00      mov    %gs:0x28,%rax
// ffffffff8100363a:       48 89 44 24 48          mov    %rax,0x48(%rsp)
// ffffffff8100363f:       31 c0                   xor    %eax,%eax
// ffffffff81003641:       0f 31                   rdtsc
// ffffffff81003643:       48 89 d1                mov    %rdx,%rcx
// ffffffff81003646:       48 89 c6                mov    %rax,%rsi
// ffffffff81003649:       0f 31                   rdtsc             <- probe here
// ffffffff8100364b:       48 c1 e1 20             shl    $0x20,%rcx


// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 200);
//     __type(key, u64); // addr
//     __type(value, struct file); 
// } uninitialized_var SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 40960);
//     __type(key, u64); // start addr of page
//     __type(value, u64); 
// } store_map SEC(".maps");



// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 40960);
//     __type(key, u64); // quarantined objects
//     __type(value, u64); 
// } quaran_obj_map SEC(".maps");

// void test_checkpoint(struct pt_regs *ctx) {
//     checkpoint_setup(ctx);
// }


// static ssize_t measureme_read(struct file *file, char __user *buf,
// 				size_t size, loff_t *ppos) {
// 	char tsc_buf[128] = {};
// 	unsigned long a = rdtsc();
// 	// probe bpf handler here
// 	unsigned long b = rdtsc();
// 	snprintf(tsc_buf, 128, "%lu\n", b - a);
// 	return simple_read_from_buffer(buf, size, ppos, tsc_buf, strlen(tsc_buf));

// ffffffff81003160 <measureme_read>:
// ...
// ffffffff8100321c:       0f 31                   rdtsc
// ffffffff8100321e:       48 89 d1                mov    %rdx,%rcx
// ffffffff81003221:       48 89 c6                mov    %rax,%rsi
// ffffffff81003224:       0f 31                   rdtsc <-probe here
// ffffffff81003226:       48 c1 e1 20             shl    $0x20,%rcx

// python -c 'print(hex(0xffffffff81003224-0xffffffff81003160))'
#define RANGE_FLAG	0
#define OFFSET_FLAG	1

unsigned long start_addr = 0xffff888000000000;
unsigned long GB = (1 << 30);
unsigned long MB = (1 << 20);

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200);
    __type(key, u64); // addr
    __type(value, u32); 
} quarantine_flag SEC(".maps");

SEC("kprobe/measureme_read+0xc4")
int BPF_KPROBE(injection) {
    // quarantine
    // u64 addr = ctx->di;
    // u32 v= 0;
    // bpf_map_update_elem(&quarantine_flag, &addr, &v, BPF_ANY);
    // // retrieve
    // u64 *pv = bpf_map_lookup_elem(&quarantine_flag, &addr);
    // if (pv) {
    //     // jump to end;
    //     bpf_set_regs(ctx, ctx);
    // }
    u64 k = ctx->di;
    u32 v = 1;
    int err = bpf_map_update_elem(&quarantine_flag, &k, &v, BPF_NOEXIST);
    bpf_printk("first time update: %d\n", err);
    err = bpf_map_update_elem(&quarantine_flag, &k, &v, BPF_NOEXIST);
    bpf_printk("second time update: %d\n", err);
    
    return 0;
}


// pv
// u64 addr = ctx->di;
//     u32 *pv = bpf_map_lookup_elem(&race_data, &addr);
//     if (pv) {
//         if (*pv != 0) {
//             bpf_printk("race happed");
//             return -1;
//         } else {
//             (*pv)++;
//         }
//     } else {
//         u32 v = 1;
//         bpf_map_update_elem(&race_data, &addr, &v, BPF_ANY);
//     }
// SEC("kprobe/measureme_read+0xc6")
// int BPF_KPROBE(injection1) {
//     // quarantine
//     u64 addr = ctx->di;
//     u32 *pv = bpf_map_lookup_elem(&race_data, &addr);
//     if (pv) {
//         if (*pv != 1) {
//             bpf_printk("race happed");
//             return -1;
//         } else {
//             (*pv)--;
//             bpf_map_delete_elem(&race_data, &addr);
//         }
//     } 
//     return 0;
// }




// simulate calculation
//     u32 size = ctx->r12;
//     u32 res_shift_32 = size << 31;

//     u64 res_shift_64 = ctx->r12 << 31;
//     if (res_shift_32 == res_shift_64) {
//         bpf_printk("no shift overflow\n");
//     }
   


// kasan compare data
//  u64 addr = ctx->di;
//     struct file f = {};
//     bpf_probe_read(&f, sizeof(struct file), addr);
//     bpf_map_update_elem(&uninitialized_var, &addr, &f, BPF_ANY);
//     struct file *uninit = bpf_map_lookup_elem(&uninitialized_var, &addr);
//     if (uninit ) {
//         if  (xmemcmp(&f, uninit) == 0) {
//             bpf_printk("uninitialized happend in tcp_recvmsg\n");
//         }
//     }
// int xmemcmp(char *dst, char *src) {
//     for (int i = 0;i < 232;i++) {
//         if (dst[i] != src[i]) {
//             return -1;
//         }
//     }
//     return 0;
// }
// SEC("kprobe/measureme_read")
// int BPF_KPROBE(setup) {

//     u64 addr = ctx->di;
//     struct file f = {};
//     bpf_probe_read(&f, sizeof(struct file), addr);
//     bpf_map_update_elem(&uninitialized_var, &addr, &f, BPF_ANY);
   
//     return 0;
// }

// SEC("kretprobe/measureme_read")
// int BPF_KRETPROBE(remove) {

//     u64 addr = ctx->di;
//     bpf_map_delete_elem(&uninitialized_var, &addr);
   
//     return 0;
// }


// range sweep
//     struct range_args args = {0, 512 * MB};
//     bpf_uaf_dangling_ptr_sweep(&store_map, &args, RANGE_FLAG);
//     bpf_uaf_free_undangle(&store_map, &quaran_obj_map, RANGE_FLAG);

// cache sweep
//  struct offset_args args = {"kmalloc-64", 0};
//     bpf_uaf_dangling_ptr_sweep(&store_map, &args, OFFSET_FLAG);
//     bpf_uaf_free_undangle(&quaran_obj_map, &quaran_obj_map, OFFSET_FLAG);


// buffer check
// u64 bufstart = bpf_get_slab_start(ctx->di);
//     u64 buflen = bpf_get_buff_len(ctx->di);
//     bool check = (ctx->di < bufstart) || (ctx->di >= bufstart+buflen);
//     if (check) {
//         bpf_printk("oob\n");
//     }



// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 200);
//     __type(key, u32); // pid
//     __type(value, struct pt_regs); 
// } checkpoints SEC(".maps");


// int checkpoint_remove()
// {
//     u32 pid = bpf_get_current_pid_tgid();
//     struct pt_regs* pregs = bpf_map_lookup_elem(&checkpoints, &pid);
//     if (pregs) {
//         int err = bpf_map_delete_elem(&checkpoints, &pid);
//     }
//     return 0;
// }


// restore
    // int err = bpf_send_signal(23);// SIGURG
    // u32 pid = bpf_get_current_pid_tgid();
    // struct pt_regs *px_regs = bpf_map_lookup_elem(&checkpoints, &pid);
    // if (px_regs) {
    //     // px_regs->ax = errcode;
    //     // px_regs->ip = retaddr;
    //     err = bpf_set_regs(ctx, ctx);
    // }

// SEC("kprobe/measureme_read")
// int BPF_KPROBE(checkpoint_setup) {
//     // test_checkpoint_setup(ctx);
//     u32 pid = bpf_get_current_pid_tgid();
//     struct pt_regs x_regs = {};
//         x_regs.r15 = ctx->r15 ;
//         x_regs.r14 = ctx->r14 ;
//         x_regs.r13 = ctx->r13 ;
//         x_regs.r12 = ctx->r12 ;
//         x_regs.bp  = ctx->bp  ;
//         x_regs.bx  = ctx->bx  ;
//         x_regs.r11 = ctx->r11;
//         x_regs.r10 = ctx->r10;
//         x_regs.r9  = ctx->r9 ;
//         x_regs.r8  = ctx->r8 ;
//         x_regs.ax  = ctx->ax ;
//         x_regs.cx  = ctx->cx ;
//         x_regs.dx  = ctx->dx ;
//         x_regs.si  = ctx->si ;
//         x_regs.di  = ctx->di ;
//     x_regs.orig_ax = ctx->orig_ax;
//         x_regs.ip = ctx->ip;
//         x_regs.cs = ctx->cs;
//         x_regs.flags = ctx->flags;
//         x_regs.sp = ctx->sp;
//         x_regs.ss = ctx->ss;
//     int err = bpf_map_update_elem(&checkpoints, &pid, &x_regs, BPF_ANY);
//     return 0;
// }

char LICENSE[] SEC("license") = "Dual BSD/GPL";

