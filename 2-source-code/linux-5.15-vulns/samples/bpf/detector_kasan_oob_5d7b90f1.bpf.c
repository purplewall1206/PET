#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// sha512_final+0x34a/0x3e0 crypto/sha512_generic.c:153
// static int sha512_final(struct shash_desc *desc, u8 *hash)
// 	return sha512_base_finish(desc, hash); // inline

// static inline int sha512_base_finish(struct shash_desc *desc, u8 *out)
// 	for (i = 0; digest_size > 0; i++, digest_size -= sizeof(__be64))
// 		put_unaligned_be64(sctx->state[i], digest++); // real oob

// static __always_inline void put_unaligned_be64(u64 val, void *p)
// 	*((__be64 *)p) = cpu_to_be64(val);


// 0x0547eb9d:     DW_TAG_inlined_subroutine
//                   DW_AT_abstract_origin (0x0548018f "put_unaligned_be64")
//                   DW_AT_low_pc  (0xffffffff8152b0c0)
//                   DW_AT_high_pc (0xffffffff8152b0cd)
//                   DW_AT_call_file       ("/home/ppw/Documents/ebpf-detector/linux-5.15-vulns/./include/crypto/sha512_base.c")

// 0x0547ebc2:       DW_TAG_formal_parameter
//                     DW_AT_abstract_origin       (0x054801a8 "p")
//                     DW_AT_location      (0x00bf7440:
//                        [0xffffffff8152b0c0, 0xffffffff8152b0cd): DW_OP_breg6 RBP+0, DW_OP_breg0 RAX+0, DW_OP_plus, DW_OP_stack_value)

// 0x0547ebcf:       DW_TAG_formal_parameter
//                     DW_AT_abstract_origin       (0x0548019c "val")
//                     DW_AT_location      (0x00bf7454:
//                        [0xffffffff8152b0c0, 0xffffffff8152b0cd): DW_OP_breg3 RBX+0, DW_OP_breg0 RAX+0, DW_OP_plus, DW_OP_plus_uconst 0x8)




u64 ret_sha512_final = 0x0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200);
    __type(key, u32); // pid
    __type(value, struct pt_regs); 
} checkpoints SEC(".maps");


SEC("kprobe/sha512_final")
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

SEC("kretprobe/sha512_final")
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


// ffffffff8152aff0 <sha512_final>:
// ..
// ffffffff8152b0c0:       48 8b 54 03 08          mov    0x8(%rbx,%rax,1),%rdx
// ffffffff8152b0c5:       48 0f ca                bswap  %rdx
// ffffffff8152b0c8:       48 89 54 05 00          mov    %rdx,0x0(%rbp,%rax,1) // probe here
// ffffffff8152b0cd:       48 83 c0 08             add    $0x8,%rax
// ffffffff8152b0d1:       39 c1                   cmp    %eax,%ecx
// ffffffff8152b0d3:       75 eb                   jne    ffffffff8152b0c0 <sha512_final+0xd0>


// mov    %rdx,0x0(%rbp,%rax,1)
// python -c 'print(hex(0xffffffff8152b0c8-0xffffffff8152aff0))'
SEC("kprobe/sha512_final+0xd8")
int BPF_KPROBE(oob_trigger)
{
    u64 p = ctx->bx;
    u64 p_offset = ctx->bx + ctx->ax;

    u64 bufstart = bpf_get_slab_start(p);
    u64 bufend = bpf_get_buff_len(p) + bufstart;
    bool check = (p_offset < bufstart) || (p_offset >= bufend);
    if (check) {
        bpf_printk("sha512_final oob triggered\n");
        // restore(ctx, (u64)((u32)(-1)), ret_sha512_final);
    }
    return 0;
}






char LICENSE[] SEC("license") = "Dual BSD/GPL";


