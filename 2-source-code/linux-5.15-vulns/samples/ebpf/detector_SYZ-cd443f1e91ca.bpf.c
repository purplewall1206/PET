#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>





// int netlink_rcv_skb(struct sk_buff *skb, int (*cb)(struct sk_buff *,
// 						   struct nlmsghdr *,
// 						   struct netlink_ext_ack *))
// 	struct netlink_ext_ack extack;
//     ...
// 2495		// memset(&extack, 0, sizeof(extack));  inject init

// 		/* Only requests are handled by the kernel */
// 2503 		if (!(nlh->nlmsg_flags & NLM_F_REQUEST)) // bypass init  [probe here is bypassed]
// 			goto ack;
// 2505		memset(&extack, 0, sizeof(extack)); // inject uninit  

// ffffffff81a8f890 <netlink_rcv_skb>:
// ...
// ffffffff81a8f8f9:       0f b7 45 06             movzwl 0x6(%rbp),%eax
// ffffffff81a8f8fd:       31 d2                   xor    %edx,%edx
// ffffffff81a8f8ff:       a8 01                   test   $0x1,%al
// ffffffff81a8f901:       74 30                   je     ffffffff81a8f933 <netlink_rcv_skb+0xa3>   [check if it is bypassed]
// ffffffff81a8f903:       49 89 e0                mov    %rsp,%r8
// ffffffff81a8f906:       31 c0                   xor    %eax,%eax
// ffffffff81a8f908:       b9 06 00 00 00          mov    $0x6,%ecx
// ffffffff81a8f90d:       4c 89 c7                mov    %r8,%rdi
// ffffffff81a8f910:       f3 48 ab                rep stos %rax,%es:(%rdi)

// python -c 'print(hex(0xffffffff81a8f901-0xffffffff81a8f890))'
SEC("kprobe/netlink_rcv_skb+0x71")
int BPF_KPROBE(prog1)
{
    // test   $0x1,%al
    u16 al = (u16) ctx->ax;
    int init = (al == 0x1);
    bpf_printk("netlink_rcv_skb: struct netlink_ext_ack extack; uninit: al:0x%x/0x%lx, init:%d\n", al, ctx->ax, init);
    return 0;
}

// SEC("kretprobe/netlink_rcv_skb")
// int BPF_KRETPROBE(prog2)
// {
//     u32 pid = bpf_get_current_pid_tgid();
//     u32* pval;
//     int err = 0;
//     pval = bpf_map_lookup_elem(&is_bypassed, &pid);
//     if (pval) {
//         err = bpf_map_delete_elem(&is_bypassed, &pid);
//         if (err < 0) {
//             bpf_printk("netlink_rcv_skb delete failed %d\n", err);
//         }
//     } else {
//         bpf_printk("netlink_rcv_skb: struct netlink_ext_ack extack; uninitialized pid:%d\n", pid);
//     }
//     return 0;
// }


char LICENSE[] SEC("license") = "Dual BSD/GPL";

