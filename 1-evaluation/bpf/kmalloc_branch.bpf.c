#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// #include <linux/gfp.h>
// #include <linux/slab.h>
#define ___GFP_IO		0x40u
#define ___GFP_FS		0x80u
#define __GFP_IO	(___GFP_IO)
#define __GFP_FS	(___GFP_FS)

// #define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)
#define GFP_KERNEL	(__GFP_IO | __GFP_FS)
char LICENSE[] SEC("license") = "Dual BSD/GPL";


// ffffffff812f0b10 <__kmalloc>:
// ffffffff812f0b10:       e8 6b 4c d8 ff          call   ffffffff81075780 <__fentry__>    ffffffff812f0b11: R_X86_64_PLT32        __fentry__-0x4
// ffffffff812f0b15:       55                      push   %rbp

// ffffffff812f0b2d:       48 81 ff 00 20 00 00    cmp    $0x2000,%rdi
// ffffffff812f0b34:       0f 87 50 03 00 00       ja     ffffffff812f0e8a <__kmalloc+0x37a>
// ffffffff812f0b3a:       8b 5d d4                mov    -0x2c(%rbp),%ebx
// ffffffff812f0b3d:       48 8b 7d c8             mov    -0x38(%rbp),%rdi

// ffffffff812f0b4b:       48 83 f8 10             cmp    $0x10,%rax
// ffffffff812f0b4f:       0f 86 56 03 00 00       jbe    ffffffff812f0eab <__kmalloc+0x39b>
// ffffffff812f0b55:       23 1d 19 67 e7 01       and    0x1e76719(%rip),%ebx        # ffffffff83167274 <gfp_allowed_mask>        ffffffff812f0b57: R_X86_64_PC32 gfp_allowed_mask-0x4
// ffffffff812f0b5b:       4c 8b 7d 08             mov    0x8(%rbp),%r15

// int replace = 0;

// int count_all = 0;
// int count_jae = 0;
// int count_jbe = 0;

// SEC("kprobe/__kmalloc")
// int BPF_KPROBE(op1)
// {
//     ++count_all;    
//     // bpf_printk("count_all: %d %d %d\n", count_all, count_jae);
//     return 0;
// }

// hex(0xffffffff812f0b3a-0xffffffff812f0b10)
// SEC("kprobe/__kmalloc+0x2a")
// int BPF_KPROBE(op2)
// {
//     ++count_jae;
//     bpf_printk("count_jae: %d %d\n", count_jae, count_all);
//     return 0;
// }


// hex(0xffffffff812f0b55-0xffffffff812f0b10)
// SEC("kprobe/__kmalloc+0x45")
// int BPF_KPROBE(op3)
// {
//     ++count_jbe;
//     bpf_printk("count_jbe: %d  %d\n", count_jbe, count_all);
//     return 0;
// }

// sudo bpftrace -e 'kprobe:__kmalloc {@all=@all+1;}  kprobe:__kmalloc+0x2a {@jae = @jae+1;}'
// ppw@ppw:~/Documents/linux/samples/ebpf$ sudo bpftrace -e 'kprobe:__kmalloc {@all=@all+1;}  kprobe:__kmalloc+0x36 {@jae = @jae+1;}'
// Attaching 2 probes...
// Can't check if kprobe is in proper place (compiled without (k|u)probe offset support): /lib/modules/5.15.0-gcc-bpf+/build/vmlinux:__kmalloc+54

int all_kcab = 0;
int loop_kcab = 0;
SEC("kprobe/kmem_cache_alloc_bulk")
int BPF_KPROBE(op4)
{
    ++all_kcab;
    bpf_printk("all: %d  %d  %lu\n", all_kcab, loop_kcab, (u64)ctx->dx);
    return 0;
}

// hex(0xffffffff812efbe2-0xffffffff812efaf0)
// '0xf2L'
// hex(0xffffffff812d271f-0xffffffff812d2690)
// '0x8fL'
SEC("kprobe/kmem_cache_alloc_bulk+0x8f")
int BPF_KPROBE(op5)
{
    ++loop_kcab;
    bpf_printk("loop: %d  %d  %lu\n", all_kcab, loop_kcab, (u64)ctx->ax);
    return 0;
}

// SEC("kretprobe/kmem_cache_alloc_bulk+0xf2")
// int BPF_KPROBE(op6)
// {
//     bpf_printk("ret: %lu\n", (u64)ctx->ax);
//     return 0;
// }




// 0xffffffff812efaf0
// ffffffff812efbcc:       45 31 ed                xor    %r13d,%r13d
// ffffffff812efbcf:       4d 85 ff                test   %r15,%r15
// ffffffff812efbd2:       0f 84 cb 00 00 00       je     ffffffff812efca3 <kmem_cache_alloc_bulk+0x1b3>
// ffffffff812efbd8:       45 31 db                xor    %r11d,%r11d
// ffffffff812efbdb:       eb 37                   jmp    ffffffff812efc14 <kmem_cache_alloc_bulk+0x124>
// ffffffff812efbdd:       41 8b 44 24 28          mov    0x28(%r12),%eax 
// ffffffff812efbe2:       48 01 d0                add    %rdx,%rax   // here