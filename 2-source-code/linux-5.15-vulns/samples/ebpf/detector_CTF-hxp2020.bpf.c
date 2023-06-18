#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

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


// python -c 'print(hex(0xffffffff81d696a0-0xffffffff81d69659))'
SEC("kprobe/hackme_read+0x47")
int BPF_KRETPROBE(prog1)
{
    u64 rdi = ctx->di; // dst: hackme_buf
    u64 rsi = ctx->si; // src: tmp
    u64 rdx = ctx->dx; // len: size

    int oob = rdx > 32; // len(tmp) = 32

    bpf_printk("hackme_read: %lu, OOB:%d\n", rdx, oob);
    return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";

