#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


// ffffffff81a0e7d0 <__alloc_skb>:
// ...
// ffffffff81a0e9f6:       48 8b 4c 24 38          mov    0x38(%rsp),%rcx
// ffffffff81a0e9fb:       44 89 ea                mov    %r13d,%edx
// ffffffff81a0e9fe:       89 ee                   mov    %ebp,%esi
// ffffffff81a0ea00:       4c 89 f7                mov    %r14,%rdi
// ffffffff81a0ea03:       88 44 24 07             mov    %al,0x7(%rsp)
// ffffffff81a0ea07:       e8 74 df 8c ff          call   ffffffff812dc980 <__kmalloc_node_track_caller>   ffffffff81a0ea08: R_X86_64_PLT32        __kmalloc_node_track_caller-0x4

	// data = kmalloc_reserve(size, gfp_mask, node, &pfmemalloc);



struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200);
    __type(key, u64); // addr
    __type(value, char[1024]);  // not a fixed size
} uninitialized_var SEC(".maps");

// python -c 'print(hex(0xffffffff81a0ea07-0xffffffff81a0e7d0))'
SEC("kprobe/__alloc_slab+0x237")
int BPF_KPROBE(creation) {
    return 0;
}

// ffffffff81a17fb0 <simple_copy_to_iter>:
// ffffffff81a17fb0:       e8 2b 95 65 ff          call   ffffffff810714e0 <__fentry__>    ffffffff81a17fb1: R_X86_64_PLT32        __fentry__-0x4
// ffffffff81a17fb5:       48 89 ca                mov    %rcx,%rdx
// ffffffff81a17fb8:       48 81 fe ff ff ff 7f    cmp    $0x7fffffff,%rsi
// ffffffff81a17fbf:       77 05                   ja     ffffffff81a17fc6 <simple_copy_to_iter+0x16>
// ffffffff81a17fc1:       e9 da 09 b7 ff          jmp    ffffffff815889a0 <_copy_to_iter> ffffffff81a17fc2: R_X86_64_PLT32        _copy_to_iter-0x4
// ffffffff81a17fc6:       0f 0b                   ud2
// ffffffff81a17fc8:       31 c0                   xor    %eax,%eax
// ffffffff81a17fca:       c3                      ret
// ffffffff81a17fcb:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)

// static size_t simple_copy_to_iter(const void *addr, size_t bytes,
// 		void *data __always_unused, struct iov_iter *i)
// {
// 	return copy_to_iter(addr, bytes, i);
// }


// python -c 'print(hex(0xffffffff81a17fc1-0xffffffff81a17fb0))'
SEC("kprobe/simple_copy_to_iter+0x11")
int BPF_KPROBE(compare) {
    return 0;
}