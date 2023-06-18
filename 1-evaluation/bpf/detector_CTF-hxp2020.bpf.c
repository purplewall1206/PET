#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

u64 ret_hackme_read = 0x0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200);
    __type(key, u32); // pid
    __type(value, struct pt_regs); 
} checkpoints SEC(".maps");


SEC("kprobe/hackme_read")
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

SEC("kretprobe/hackme_read")
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



// init/main.c
// static ssize_t hackme_read(struct file *file, char __user *buf,
// 				size_t size, loff_t *ppos) {

// 936	int tmp[32];
// 937	unsigned long written;
// 	// pr_info("-----hackme read leak info from backme_buf to user----\n");
// 	pr_info("-----hackme read leak info from backme_buf to user----\n");
// 940	memcpy(hackme_buf, tmp, size);
// 941	if (size > 0x1000) {
// ...
// 946	written = copy_to_user(buf, hackme_buf, size);


// ffffffff81d69659 <hackme_read>:
// ...
// ffffffff81d69688:       e8 0b cc 00 00          call   ffffffff81d76298 <_printk>
// ffffffff81d6968d:       48 c7 c0 00 d0 61 83    mov    $0xffffffff8361d000,%rax
// ffffffff81d69694:       4c 89 e1                mov    %r12,%rcx
// ffffffff81d69697:       4c 89 e2                mov    %r12,%rdx
// ffffffff81d6969a:       48 89 e6                mov    %rsp,%rsi
// ffffffff81d6969d:       48 89 c7                mov    %rax,%rdi
// ffffffff81d696a0:       f3 a4                   rep movsb %ds:(%rsi),%es:(%rdi)
// ffffffff81d696a2:       49 81 fc 00 10 00 00    cmp    $0x1000,%r12


// ffffffff81cad7e5 <hackme_read>:
// ....
// ffffffff81cad819:       48 c7 c0 00 d0 a8 83    mov    $0xffffffff83a8d000,%rax ffffffff81cad81c: R_X86_64_32S  hackme_buf
// ffffffff81cad820:       4c 89 e1                mov    %r12,%rcx
// ffffffff81cad823:       4c 89 e2                mov    %r12,%rdx
// ffffffff81cad826:       48 89 e6                mov    %rsp,%rsi
// ffffffff81cad829:       48 89 c7                mov    %rax,%rdi
// ffffffff81cad82c:       f3 a4                   rep movsb %ds:(%rsi),%es:(%rdi)
// ffffffff81cad82e:       49 81 fc 00 10 00 00    cmp    $0x1000,%r12





// python -c 'print(hex(0xffffffff81d696a0-0xffffffff81d69659))'
SEC("kprobe/hackme_read+0x47")
int BPF_KRETPROBE(prog1)
{
    u64 rdi = ctx->di; // dst: hackme_buf
    u64 rsi = ctx->si; // src: tmp
    u64 rdx = ctx->dx; // len: size

    int oob = rdx > 32; // len(tmp) = 32
    if (oob) {
        bpf_printk("\n");
        // restore(ctx, (u64)((u32)(-1)), ret_hackme_read);
    }

    bpf_printk("hackme_read: %lu, OOB:%d\n", rdx, oob);
    return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ffffffff81d1977d <hackme_read>:
// ...
// ffffffff81d197be:       48 89 e6                mov    %rsp,%rsi
// ffffffff81d197c1:       48 89 c7                mov    %rax,%rdi
// ffffffff81d197c4:       f3 a4                   rep movsb %ds:(%rsi),%es:(%rdi)


// 0xffffffff81d197be    940      2      3   0             01


// 0xffffffff81d197b1    940      2      3   0             0  is_stmt

// 0xffffffff81d197be    940      2      3   0             0