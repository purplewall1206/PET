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


// net/netlink/af_netlink.c
// static int netlink_insert(struct sock *sk, u32 portid)
// {
// 579	nlk_sk(sk)->portid = portid;

// ffffffff81aa5450 <netlink_insert>:
// ...
// ffffffff81aa54d2:       41 5e                   pop    %r14
// ffffffff81aa54d4:       41 5f                   pop    %r15
// ffffffff81aa54d6:       c3                      ret
// ffffffff81aa54d7:       89 9d 10 03 00 00       mov    %ebx,0x310(%rbp) <- write
// ffffffff81aa54dd:       4c 8d b5 80 00 00 00    lea    0x80(%rbp),%r14
// ffffffff81aa54e4:       b8 01 00 00 00          mov    $0x1,%eax

// static int netlink_getname(struct socket *sock, struct sockaddr *addr,
// 			   int peer)
// 	struct netlink_sock *nlk = nlk_sk(sk);
// 1133		nladdr->nl_pid = nlk->portid;

// ffffffff81aa5140 <netlink_getname>:
// ....
// ffffffff81aa517e:       d3 e0                   shl    %cl,%eax
// ffffffff81aa5180:       89 c1                   mov    %eax,%ecx
// ffffffff81aa5182:       eb e7                   jmp    ffffffff81aa516b <netlink_getname+0x2b>
// ffffffff81aa5184:       8b 85 10 03 00 00       mov    0x310(%rbp),%eax  <- read
// ffffffff81aa518a:       48 c7 c7 48 e8 c3 83    mov    $0xffffffff83c3e848,%rdi ffffffff81aa518d: R_X86_64_32S  nl_table_lock
// ffffffff81aa5191:       89 46 04                mov    %eax,0x4(%rsi)


// python -c 'print(hex(0xffffffff81aa54d7-0xffffffff81aa5450))'
SEC("kprobe/netlink_insert+0x87")
int BPF_KPROBE(p0) {
    u64 k = ctx->bp + 0x310;
    u64 v = 0;
    int err = bpf_map_update_elem(&race_points, &k, &v, BPF_NOEXIST);
    if (err < 0) {
        bpf_printk("race condition in tcp_send_challenge_ack.constprop.0+0x5d\n");
    }
    return 0;
}

// python -c 'print(hex(0xffffffff81aa54dd-0xffffffff81aa5450))'
SEC("kprobe/netlink_insert+0x8d")
int BPF_KPROBE(v0) {
    u64 k = ctx->bp + 0x310;
    int err = bpf_map_delete_elem(&race_points, &k);
    return 0;
}

// python -c 'print(hex(0xffffffff81aa5184-0xffffffff81aa5140))'
SEC("kprobe/netlink_getname+0x44")
int BPF_KPROBE(p1) {
    u64 k = ctx->bp + 0x310;
    u64 v = 0;
    int err = bpf_map_update_elem(&race_points, &k, &v, BPF_NOEXIST);
    if (err < 0) {
        bpf_printk("race condition in tcp_send_challenge_ack.constprop.0+0x5d\n");
    }
    return 0;
}

// python -c 'print(hex(0xffffffff81aa518a-0xffffffff81aa5140))'
SEC("kprobe/netlink_getname+0x4a")
int BPF_KPROBE(prog0) {
    u64 k = ctx->bp + 0x310;
    int err = bpf_map_delete_elem(&race_points, &k);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
