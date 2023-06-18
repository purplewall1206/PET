#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200);
    __type(key, u64); // addr
    __type(value, char[1024]);  // not a fixed size
} uninitialized_var SEC(".maps");
// int netlink_rcv_skb(struct sk_buff *skb, int (*cb)(struct sk_buff *,
// 						   struct nlmsghdr *,
// 						   struct netlink_ext_ack *))
// {
// 	struct netlink_ext_ack extack; <- create
// 		/* Skip control messages */
// 		if (nlh->nlmsg_type < NLMSG_MIN_TYPE)
// 			goto ack;

// 		memset(&extack, 0, sizeof(extack)); <- bypassed initialized

// ack:
//2516 		if (nlh->nlmsg_flags & NLM_F_ACK || err)
//2517 			netlink_ack(skb, nlh, err, &extack); <- use

// DW_AT_name      ("extack")
//                 DW_AT_decl_file ("/home/ppw/Documents/ebpf-detector/linux-5.15-vulns/net/netlink/af_netlink.c")
//                 DW_AT_decl_line (2488)
//                 DW_AT_decl_column       (0x19)
//                 DW_AT_type      (0x0af13939 "netlink_ext_ack")
//                 DW_AT_location  (DW_OP_fbreg -88)

//   0xffffffff81aa8330: CFA=RSP+8: RIP=[CFA-8]
//   0xffffffff81aa8337: CFA=RSP+16: R12=[CFA-16], RIP=[CFA-8]
//   0xffffffff81aa833b: CFA=RSP+24: RBP=[CFA-24], R12=[CFA-16], RIP=[CFA-8]
//   0xffffffff81aa833c: CFA=RSP+32: RBX=[CFA-32], RBP=[CFA-24], R12=[CFA-16], RIP=[CFA-8]
//   0xffffffff81aa8343: CFA=RSP+88: RBX=[CFA-32], RBP=[CFA-24], R12=[CFA-16], RIP=[CFA-8]
//   0xffffffff81aa8400: CFA=RSP+32: RBX=[CFA-32], RBP=[CFA-24], R12=[CFA-16], RIP=[CFA-8]
//   0xffffffff81aa8403: CFA=RSP+24: RBP=[CFA-24], R12=[CFA-16], RIP=[CFA-8]
//   0xffffffff81aa8404: CFA=RSP+16: R12=[CFA-16], RIP=[CFA-8]
//   0xffffffff81aa8406: CFA=RSP+8: RIP=[CFA-8]
//   0xffffffff81aa8407: CFA=RSP+8: RBX=[CFA-32], RBP=[CFA-24], R12=[CFA-16], RIP=[CFA-8]

// ffffffff81aa8330 <netlink_rcv_skb>:
// ...
// ffffffff81aa83d9:       48 89 e1                mov    %rsp,%rcx
// ffffffff81aa83dc:       48 89 ee                mov    %rbp,%rsi
// ffffffff81aa83df:       4c 89 e7                mov    %r12,%rdi
// ffffffff81aa83e2:       e8 c9 fb ff ff          call   ffffffff81aa7fb0 <netlink_ack>   ffffffff81aa83e3: R_X86_64_PLT32        netlink_ack-0x4


// struct netlink_ext_ack {
//         const char  *              _msg;                 /*     0     8 */
//         const struct nlattr  *     bad_attr;             /*     8     8 */
//         const struct nla_policy  * policy;               /*    16     8 */
//         u8                         cookie[20];           /*    24    20 */
//         u8                         cookie_len;           /*    44     1 */

//         /* size: 48, cachelines: 1, members: 5 */
//         /* padding: 3 */
//         /* last cacheline: 48 bytes */
// };

SEC("kprobe/netlink_rcv_skb")
int BPF_KPROBE(creation) {
    u64 addr = ctx->sp + 0x8 - 88;
    return 0;
}


// python -c 'print(hex(0xffffffff81aa83e2-0xffffffff81aa8330))'
SEC("kprobe/netlink_rcv_skb+0xb2")
int BPF_KPROBE(compare) {
    u64 addr = ctx->sp + 88 - 88;
    return 0;
}

















// ========================================


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
// python -c 'print(hex(0xffffffff81a23c3f-0xffffffff81a23bc0))'
SEC("kprobe/netlink_rcv_skb+0x7f")
int BPF_KPROBE(prog1)
{
    // test   $0x1,%al
    u16 al = (u16) ctx->ax;
    int init = (al == 0x1);
    // bpf_printk("netlink_rcv_skb: struct netlink_ext_ack extack; uninit: al:0x%x/0x%lx, init:%d\n", al, ctx->ax, init);
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

