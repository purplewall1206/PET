#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>





struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200);
    __type(key, u32); // pid
    __type(value, struct pt_regs); 
} checkpoints SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200);
    __type(key, u64); // addr
    __type(value, char[96]); 
} uninitialized_var SEC(".maps");

// BUG: KMSAN: uninit-value in tcp_recvmsg+0x6cf/0xb60 net/ipv4/tcp.c:2554
//  tcp_recvmsg+0x6cf/0xb60 net/ipv4/tcp.c:2554
// int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
// 		int flags, int *addr_len)
// {
// 	int cmsg_flags = 0, ret, inq;
// 	struct scm_timestamping_internal tss;
// ...
// 2554	if (cmsg_flags && ret >= 0) {
// 2555		if ((cmsg_flags || msg->msg_get_inq) & TCP_CMSG_TS)

// Local variable msg created at:
//  __sys_recvfrom+0x81/0x900 net/socket.c:2154

// int __sys_recvfrom(int fd, void __user *ubuf, size_t size, unsigned int flags,
// 		   struct sockaddr __user *addr, int __user *addr_len)
// {
// 	struct socket *sock;
// 	struct iovec iov;
// 	struct msghdr msg;  // uninitialized



// ffffffff819811c0 <__sys_recvfrom>:
// ffffffff819811c0:       e8 1b 03 6f ff          call   ffffffff810714e0 <__fentry__>    ffffffff819811c1: R_X86_64_PLT32        __fentry__-0x4
// ffffffff819811c5:       41 56                   push   %r14
// ffffffff819811c7:       4d 89 ce                mov    %r9,%r14
// ffffffff819811ca:       41 55                   push   %r13
// ffffffff819811cc:       41 89 cd                mov    %ecx,%r13d
// ffffffff819811cf:       41 54                   push   %r12
// ffffffff819811d1:       4d 89 c4                mov    %r8,%r12
// ffffffff819811d4:       55                      push   %rbp
// ffffffff819811d5:       89 fd                   mov    %edi,%ebp
// ffffffff819811d7:       31 ff                   xor    %edi,%edi
// ffffffff819811d9:       53                      push   %rbx


// 0x09bcba21:   DW_TAG_variable
//                 DW_AT_name      ("msg")
//                 DW_AT_decl_file ("/home/ppw/Documents/ebpf-detector/linux-5.15-vulns/net/socket.c")
//                 DW_AT_decl_line (2071)
//                 DW_AT_decl_column       (0x10)
//                 DW_AT_type      (0x09ba11f0 "msghdr")
//                 DW_AT_location  (DW_OP_fbreg -280)  ->    0xffffffff819811c0: CFA=RSP+8: RIP=[CFA-8]

// struct msghdr msg;  size: 96
SEC("kprobe/__sys_recvfrom")
int BPF_KPROBE(unintialized_create)
{
    u64 addr = ctx->sp + 8 - 280;
    char msg[96] = {'\0'};
    bpf_probe_read(msg, 96, addr);
    bpf_map_update_elem(&uninitialized_var, &addr, msg, BPF_ANY);
    return 0;
}


// ffffffff81ab0c00 <tcp_recvmsg>:
// ffffffff81ab0c00:       e8 db 08 5c ff          call   ffffffff810714e0 <__fentry__>    ffffffff81ab0c01: R_X86_64_PLT32        __fentry__-0x4
// ffffffff81ab0c05:       41 56                   push   %r14
// ffffffff81ab0c07:       41 55                   push   %r13
// ...
// ffffffff81ab0cac:       41 5e                   pop    %r14
// ffffffff81ab0cae:       c3                      ret
// ffffffff81ab0caf:       f6 c3 02                test   $0x2,%bl
// ffffffff81ab0cb2:       0f 85 cb 00 00 00       jne    ffffffff81ab0d83 <tcp_recvmsg+0x183>
// ffffffff81ab0cb8:       83 e3 01                and    $0x1,%ebx  [probe here]
// ffffffff81ab0cbb:       74 ce                   je     ffffffff81ab0c8b <tcp_recvmsg+0x8b>
// ffffffff81ab0cbd:       48 89 ef                mov    %rbp,%rdi
int xmemcmp(char *dst, char *src) {
    for (int i = 0;i < 96;i++) {
        if (dst[i] != src[i]) {
            return -1;
        }
    }
    return 0;
}

// python -c 'print(hex(0xffffffff81ab0cb8-0xffffffff81ab0c00))'
// msg->msg_get_inq
// msg: [0xffffffff81ab0caf, 0xffffffff81ab0ce7): DW_OP_reg13 R13
// SEC("kprobe/tcp_recvmsg+0xb8")
SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(unintialized_use)
{
    char *msg;
    char var[96];
    u64 addr = ctx->r13;
    bpf_core_read(var, 96, &addr);
    msg = bpf_map_lookup_elem(&uninitialized_var, &addr);
    if (msg ) {
        if  (xmemcmp(msg, var) == 0) {
            bpf_printk("uninitialized happend in tcp_recvmsg\n");
        }
        bpf_map_delete_elem(&uninitialized_var, &addr);
    }
    return 0;
}


// 0xffffffff81b6e62d     41      9     47   0             0
// 0xffffffff81b6e636     41      2     47   0             0  is_stmt
// 0xffffffff81b6e63e     41     35     47   0             0
// 0xffffffff81b6e6ec     41     35     47   0             0
// 0xffffffff81b6e6f5     41     35     47   0             0

// // checkpoint
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


// struct msghdr {
//         void *                     msg_name;             /*     0     8 */
//         int                        msg_namelen;          /*     8     4 */

//         /* XXX 4 bytes hole, try to pack */

//         struct iov_iter            msg_iter;             /*    16    40 */
//         union {
//                 void *             msg_control;          /*    56     8 */
//                 void *             msg_control_user;     /*    56     8 */
//         };                                               /*    56     8 */
//         /* --- cacheline 1 boundary (64 bytes) --- */
//         bool                       msg_control_is_user:1; /*    64: 0  1 */

//         /* XXX 7 bits hole, try to pack */
//         /* XXX 7 bytes hole, try to pack */

//         __kernel_size_t            msg_controllen;       /*    72     8 */
//         unsigned int               msg_flags;            /*    80     4 */

//         /* XXX 4 bytes hole, try to pack */

//         struct kiocb *             msg_iocb;             /*    88     8 */

//         /* size: 96, cachelines: 2, members: 8 */
//         /* sum members: 80, holes: 3, sum holes: 15 */
//         /* sum bitfield members: 1 bits, bit holes: 1, sum bit holes: 7 bits */
//         /* last cacheline: 32 bytes */
// };