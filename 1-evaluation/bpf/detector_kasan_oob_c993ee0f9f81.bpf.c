#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


// KASAN: slab-out-of-bounds in watch_queue_set_filter+0x78d/0x810 kernel/watch_queue.c:343
// long watch_queue_set_filter(struct pipe_inode_info *pipe,
// 			    struct watch_notification_filter __user *_filter)
// 	struct watch_notification_type_filter *tf;
// 	struct watch_notification_filter filter;
// 	struct watch_type_filter *q;

// 342		q->type			= tf[i].type;
// 343		q->info_filter		= tf[i].info_filter;
// 344	q->info_mask		= tf[i].info_mask;

// ffffffff81249e50 <watch_queue_set_filter>:
// ...
// ffffffff81249fa1:       89 02                   mov    %eax,(%rdx)
// ffffffff81249fa3:       8b 7e 04                mov    0x4(%rsi),%edi
// ffffffff81249fa6:       89 7a 08                mov    %edi,0x8(%rdx) // probe here
// ffffffff81249fa9:       8b 7e 08                mov    0x8(%rsi),%edi


// struct watch_type_filter {
//         enum watch_notification_type type;               /*     0     4 */
//         __u32                      subtype_filter[1];    /*     4     4 */
//         __u32                      info_filter;          /*     8     4 */
//         __u32                      info_mask;            /*    12     4 */
//         /* size: 16, cachelines: 1, members: 4 */
//         /* last cacheline: 16 bytes */
// };

u64 ret_watch_queue_set_filter = 0x0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200);
    __type(key, u32); // pid
    __type(value, struct pt_regs); 
} checkpoints SEC(".maps");


SEC("kprobe/watch_queue_set_filter")
int BPF_KPROBE(checkpoint_setup)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct pt_regs x_regs = {};
        x_regs.r15 = ctx->r15 ;
        x_regs.r14 = ctx->r14 ;
        x_regs.r13 = ctx->r13 ;
        x_regs.r12 = ctx->r12 ;
        x_regs.bp  = ctx->bp  ;
        x_regs.bx  = ctx->bx  ;
        x_regs.r11 = ctx->r11;
        x_regs.r10 = ctx->r10;
        x_regs.r9  = ctx->r9 ;
        x_regs.r8  = ctx->r8 ;
        x_regs.ax  = ctx->ax ;
        x_regs.cx  = ctx->cx ;
        x_regs.dx  = ctx->dx ;
        x_regs.si  = ctx->si ;
        x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
        x_regs.ip = ctx->ip;
        x_regs.cs = ctx->cs;
        x_regs.flags = ctx->flags;
        x_regs.sp = ctx->sp;
        x_regs.ss = ctx->ss;
    int err = bpf_map_update_elem(&checkpoints, &pid, &x_regs, BPF_ANY);
    return 0;
}

SEC("kretprobe/watch_queue_set_filter")
int BPF_KRETPROBE(checkpoint_remove)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct pt_regs* pregs = bpf_map_lookup_elem(&checkpoints, &pid);
    if (pregs) {
        int err = bpf_map_delete_elem(&checkpoints, &pid);
    }
    return 0;
}

int restore(struct pt_regs *ctx, u64 errcode, u64 retaddr)
{
    int err = bpf_send_signal(9);// SIGKILL
    u32 pid = bpf_get_current_pid_tgid();
    struct pt_regs *px_regs = bpf_map_lookup_elem(&checkpoints, &pid);
    if (px_regs) {
        px_regs->ax = errcode;
        px_regs->ip = retaddr;
        err = bpf_set_regs(ctx, px_regs);
    }
    return 0;
}

// python -c 'print(hex(0xffffffff81249fa6-0xffffffff81249e50))'
// "q": [0xffffffff81249f82, 0xffffffff81249fcc): DW_OP_reg1 RDX)
SEC("kprobe/watch_queue_set_filter+0x156")
int BPF_KPROBE(oob_trigger)
{
    u64 q = ctx->dx;
    u64 q_info_filter = q + 0x8;
    u64 bufstart = bpf_get_slab_start(q);
    u64 bufend = bpf_get_buff_len(q);
    bool check = (q_info_filter < bufstart) || (q_info_filter >= bufend);
    if (check) {
        bpf_printk("watch_queue_set_filter oob trigger\n");
        // restore(ctx, (u64)((u32)(-1)), ret_watch_queue_set_filter);
    }
    return 0;
}





char LICENSE[] SEC("license") = "Dual BSD/GPL";
