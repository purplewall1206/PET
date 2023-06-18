#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200);
    __type(key, u64); // addr
    __type(value, u32); 
} race_points SEC(".maps");

// https://syzkaller.appspot.com/bug?id=f6e95af74472292ab1c50af3d6ac36cd4a683432

// race condition in net/ipv4/tcp_input.c
// race challenge_timestamp
// read: tcp_send_challenge_ack+0x116/0x200 net/ipv4/tcp_input.c:3614
// write: tcp_send_challenge_ack+0x15c/0x200 net/ipv4/tcp_input.c:3618

// static void tcp_send_challenge_ack(struct sock *sk, const struct sk_buff *skb)
// {
// 	/* unprotected vars, we dont care of overwrites */
// 	static u32 challenge_timestamp;
// 	static unsigned int challenge_count;
// ...
// 	/* Then check host-wide RFC 5961 rate limit. */
// 	now = jiffies / HZ;
// 	if (now != challenge_timestamp) { // read
// 		u32 ack_limit = net->ipv4.sysctl_tcp_challenge_ack_limit;
// 		u32 half = (ack_limit + 1) >> 1;

// 		challenge_timestamp = now;  // write 
// 		WRITE_ONCE(challenge_count, half + prandom_u32_max(ack_limit));
// 	}

// ffffffff81ab4790 <tcp_send_challenge_ack.constprop.0>:
// ...
// ffffffff81ab47d9:       48 c1 ea 03             shr    $0x3,%rdx
// ffffffff81ab47dd:       89 85 d4 05 00 00       mov    %eax,0x5d4(%rbp)
// ffffffff81ab47e3:       48 89 d0                mov    %rdx,%rax
// ffffffff81ab47e6:       48 f7 e1                mul    %rcx
// ffffffff81ab47e9:       48 c1 ea 04             shr    $0x4,%rdx
// ffffffff81ab47ed:       3b 15 c1 5e 11 02       cmp    0x2115ec1(%rip),%edx  [probe]       # ffffffff83bca6b4 <challenge_timestamp.3>   ffffffff81ab47ef: R_X86_64_PC32 .bss+0x27e6b0
// ffffffff81ab47f3:       75 0f                   jne    ffffffff81ab4804 <tcp_send_challenge_ack.constprop.0+0x74>
// ffffffff81ab47f5:       8b 05 b5 5e 11 02       mov    0x2115eb5(%rip),%eax        # ffffffff83bca6b0 <challenge_count.2>       ffffffff81ab47f7: R_X86_64_PC32 .bss+0x27e6ac
// ...
// ffffffff81ab47fd:       75 3a                   jne    ffffffff81ab4839 <tcp_send_challenge_ack.constprop.0+0xa9>
// ffffffff81ab47ff:       5b                      pop    %rbx
// ffffffff81ab4800:       5d                      pop    %rbp
// ffffffff81ab4801:       41 5c                   pop    %r12
// ffffffff81ab4803:       c3                      ret
// ffffffff81ab4804:       44 8b a3 1c 04 00 00    mov    0x41c(%rbx),%r12d
// ffffffff81ab480b:       89 15 a3 5e 11 02       mov    %edx,0x2115ea3(%rip) [probe]       # ffffffff83bca6b4 <challenge_timestamp.3>   ffffffff81ab480d: R_X86_64_PC32 .bss+0x27e6b0
// ffffffff81ab4811:       e8 ca d8 ac ff          call   ffffffff815820e0 <prandom_u32>   ffffffff81ab4812: R_X86_64_PLT32        prandom_u32-0x4
// ffffffff81ab4816:       89 c0                   mov    %eax,%eax

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 40960);
//     __type(key, u64); // addr
//     __type(value, u32); // pv operation
// } race_point SEC(".maps");
u64 race_point = 0xffffffff83bca6b4; // challenge_timestamp is global here. normally, here will be a map!
u64 race_point_pv = 0;





// python -c 'print(hex(0xffffffff81ab47ed- 0xffffffff81ab4790 ))'
SEC("kprobe/tcp_send_challenge_ack.constprop.0+0x5d")
int BPF_KPROBE(read_race_p) {
    u64 k = ctx->ip + 0x2108765;
    u64 v = 0;
    int err = bpf_map_update_elem(&race_points, &k, &v, BPF_NOEXIST);
    if (err < 0) {
        bpf_printk("race condition in tcp_send_challenge_ack.constprop.0+0x5d\n");
    }
    // if (race_point_pv == 0) {
    //     race_point_pv = race_point_pv + 1;
    // } else {
    //     bpf_printk("race condition in tcp_send_challenge_ack.constprop.0+0x5d\n");
    //     race_point_pv = 0;
    // }
    return 0;
}

// python -c 'print(hex(0xffffffff81ab47f3- 0xffffffff81ab4790 ))'
SEC("kprobe/tcp_send_challenge_ack.constprop.0+0x63")
int BPF_KPROBE(read_race_v) {
    u64 k = ctx->ip + 0x2108765;
    int err = bpf_map_delete_elem(&race_points, &k);
    // if (race_point_pv == 1) {
    //     race_point_pv = race_point_pv - 1;
    // } else {
    //     bpf_printk("race condition in tcp_send_challenge_ack.constprop.0+0x63\n");
    //     race_point_pv = 0;
    // }
    return 0;
}

// python -c 'print(hex(0xffffffff81ab480b- 0xffffffff81ab4790 ))'
SEC("kprobe/tcp_send_challenge_ack.constprop.0+0x7b")
int BPF_KPROBE(write_race_p) {
    u64 k = ctx->ip + 0x2108765;
    u64 v = 0;
    int err = bpf_map_update_elem(&race_points, &k, &v, BPF_NOEXIST);
    if (err < 0) {
        bpf_printk("race condition in tcp_send_challenge_ack.constprop.0+0x5d\n");
    }
    // if (race_point_pv == 1) {
    //     race_point_pv = race_point_pv + 1;
    // } else {
    //     bpf_printk("race condition in tcp_send_challenge_ack.constprop.0+0x7b\n");
    //     race_point_pv = 0;
    // }
    return 0;
}

// python -c 'print(hex(0xffffffff81ab4811- 0xffffffff81ab4790 ))'
SEC("kprobe/tcp_send_challenge_ack.constprop.0+0x81")
int BPF_KPROBE(write_race_v) {
    u64 k = ctx->ip + 0x2108765;
    int err = bpf_map_delete_elem(&race_points, &k);
    return 0;
}




// checkpoint
// SEC("kprobe/null_skcipher_crypt")
// int BPF_KPROBE(prog0)
// {
//     u32 pid = bpf_get_current_pid_tgid();
//     struct pt_regs x_regs = {};
// 	x_regs.r15 = ctx->r15 ;
// 	x_regs.r14 = ctx->r14 ;
// 	x_regs.r13 = ctx->r13 ;
// 	x_regs.r12 = ctx->r12 ;
// 	x_regs.bp  = ctx->bp  ;
// 	x_regs.bx  = ctx->bx  ;
// 	x_regs.r11 = ctx->r11;
// 	x_regs.r10 = ctx->r10;
// 	x_regs.r9  = ctx->r9 ;
// 	x_regs.r8  = ctx->r8 ;
// 	x_regs.ax  = ctx->ax ;
// 	x_regs.cx  = ctx->cx ;
// 	x_regs.dx  = ctx->dx ;
// 	x_regs.si  = ctx->si ;
// 	x_regs.di  = ctx->di ;
//     x_regs.orig_ax = ctx->orig_ax;
// 	x_regs.ip = ctx->ip;
// 	x_regs.cs = ctx->cs;
// 	x_regs.flags = ctx->flags;
// 	x_regs.sp = ctx->sp;
// 	x_regs.ss = ctx->ss;
//     // bpf_printk("checkpoint setup pid:%u\n", pid);
//     int err = bpf_map_update_elem(&checkpoints, &pid, &x_regs, BPF_ANY);
//     if (err < 0) {
//         bpf_printk("checkpoint setup failed: %d\n", err);
//         return err;
//     }
//     return 0;
// }

// SEC("kretprobe/null_skcipher_crypt")
// int BPF_KRETPROBE(prog10)
// {
//     u32 pid = bpf_get_current_pid_tgid();
//     struct pt_regs* pregs = bpf_map_lookup_elem(&checkpoints, &pid);
//     if (pregs) {
//         int err = bpf_map_delete_elem(&checkpoints, &pid);
//         // bpf_printk("checkpoint remove pid:%u\n", pid);
//         if (err < 0) {
//             bpf_printk("checkpoints delete failed:%d\n", err);
//             return err;
//         }
//     }
//     return 0;
// }




// // python -c 'print(hex(0xffffffff814ead7b-0xffffffff814ead30))'
// // python -c 'print(hex(0xffffffff814ee31b-0xffffffff814ee2d0))'
// // python -c 'print(hex(0xffffffff814f27bb- 0xffffffff814f2770 ))'
// // walk: rsp + 0
// // walk.dst.virt.addr: walk + 24
// // walk.nbytes: walk + 48
// SEC("kprobe/null_skcipher_crypt+0x4b")
// int BPF_KPROBE(prog1)
// {
//     // check len
//     u64 walk_dst_virt_addr = ctx->di;
//     u64 walk_src_virt_addr = ctx->si;
//     u32 walk_nbytes = ctx->dx;
//     u32 walk_total = 0;
//     u64 walk_total_addr = ctx->sp + 72;
//     bpf_core_read(&walk_total, 4, walk_total_addr);

//     u64 buff_addr = bpf_get_slab_start(walk_dst_virt_addr);
//     u64 buff_len = bpf_get_buff_len(walk_dst_virt_addr);
//     // bpf_printk("%lx:%lx:%lx\n", walk_dst_virt_addr, buff_addr, buff_len);
//     // bpf_printk("null_skcipher_crypt %lx, %lx, %x\n", walk_dst_virt_addr, walk_nbytes, walk_total);

//     u64 buff = (buff_addr + buff_len);
//     u64 memcpy_dst = (walk_dst_virt_addr + walk_total);

//     // bpf_printk("output: %lx, %lx\n", buff, memcpy_dst);

//     u64 oob = buff < memcpy_dst;
//     if (oob == 1) {
//         bpf_printk("null_skcipher_crypt:oob\n");
//         int err = bpf_send_signal(9);// SIGKILL
//         bpf_printk("bpf send kill signal: %d\n", err);
//         if (err < 0) {
//             bpf_printk("null_skcipher_crypt sendsignal failed:%d\n", err);
//             return err;
//         }
//         u32 pid = bpf_get_current_pid_tgid();
//         struct pt_regs *px_regs = bpf_map_lookup_elem(&checkpoints, &pid);
//         if (px_regs) {
//             px_regs->ax = (unsigned long)((int)-35);
//             px_regs->ip = 0xffffffff814f27e6;
//             err = bpf_set_regs(ctx, px_regs);
//             bpf_printk("null_skcipher_crypt bpf_set_regs: %d\n", err);
//         }
//     }

//     return 0;
// }





char LICENSE[] SEC("license") = "Dual BSD/GPL";
