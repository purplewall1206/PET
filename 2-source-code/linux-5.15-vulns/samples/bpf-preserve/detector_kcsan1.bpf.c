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


// net/ipv4/tcp_input.c

// static void tcp_send_challenge_ack(struct sock *sk)
// 	static u32 challenge_timestamp;   // static global here

// 	now = jiffies / HZ;
// 3614	if (now != challenge_timestamp) { <- race read

// 3618		challenge_timestamp = now;   <- race write


// ffffffff81b38ee0 <tcp_send_challenge_ack.constprop.0>:
// ...
// ffffffff81b38f33:       48 89 d0                mov    %rdx,%rax
// ffffffff81b38f36:       48 f7 e1                mul    %rcx
// ffffffff81b38f39:       48 c1 ea 04             shr    $0x4,%rdx
// ffffffff81b38f3d:       3b 15 71 87 10 02       cmp    0x2108771(%rip),%edx        # ffffffff83c416b4 <challenge_timestamp.3>   ffffffff81b38f3f: R_X86_64_PC32 .bss+0x2806b0
// ffffffff81b38f43:       75 0f                   jne    ffffffff81b38f54 <tcp_send_challenge_ack.constprop.0+0x74>
// ffffffff81b38f45:       8b 05 65 87 10 02       mov    0x2108765(%rip),%eax        # ffffffff83c416b0 <challenge_count.2>       ffffffff81b38f47: R_X86_64_PC32 .bss+0x2806ac
// ffffffff81b38f4b:       85 c0                   test   %eax,%eax
// ...
// ffffffff81b38f53:       c3                      ret
// ffffffff81b38f54:       44 8b a3 1c 04 00 00    mov    0x41c(%rbx),%r12d
// ffffffff81b38f5b:       89 15 53 87 10 02       mov    %edx,0x2108753(%rip)        # ffffffff83c416b4 <challenge_timestamp.3>   ffffffff81b38f5d: R_X86_64_PC32 .bss+0x2806b0
// ffffffff81b38f61:       e8 7a 91 a4 ff          call   ffffffff815820e0 <prandom_u32>   ffffffff81b38f62: R_X86_64_PLT32        prandom_u32-0x4

// python -c 'print(hex(0xffffffff81b38f45-0xffffffff81b38ee0))'
SEC("kprobe/tcp_send_challenge_ack.constprop.0+0x65")
int BPF_KPROBE(p0) {
    u64 k = ctx->ip + 0x2108765;
    u64 v = 0;
    int err = bpf_map_update_elem(&race_points, &k, &v, BPF_NOEXIST);
    if (err < 0) {
        bpf_printk("race condition in tcp_send_challenge_ack.constprop.0+0x5d\n");
    }
    return 0;
}

// python -c 'print(hex(0xffffffff81b38f4b-0xffffffff81b38ee0))'
SEC("kprobe/tcp_send_challenge_ack.constprop.0+0x6b")
int BPF_KPROBE(v0) {
    u64 k = ctx->ip + 0x2108765;
    int err = bpf_map_delete_elem(&race_points, &k);
    return 0;
}

// python -c 'print(hex(0xffffffff81b38f5b-0xffffffff81b38ee0))'
SEC("kprobe/tcp_send_challenge_ack.constprop.0+0x7b")
int BPF_KPROBE(p1) {
    u64 k = ctx->ip + 0x2108765;
    u64 v = 0;
    int err = bpf_map_update_elem(&race_points, &k, &v, BPF_NOEXIST);
    if (err < 0) {
        bpf_printk("race condition in tcp_send_challenge_ack.constprop.0+0x5d\n");
    }
    return 0;
}

// python -c 'print(hex(0xffffffff81b38f61-0xffffffff81b38ee0))'
SEC("kprobe/tcp_send_challenge_ack.constprop.0+0x81")
int BPF_KPROBE(v1) {
    u64 k = ctx->ip + 0x2108765;
    int err = bpf_map_delete_elem(&race_points, &k);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
