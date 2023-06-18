#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>



// net/ethtool/bitset.c:631

// int ethnl_set_features(struct sk_buff *skb, struct genl_info *info) .....
// DECLARE_BITMAP(req_wanted, NETDEV_FEATURE_COUNT); ==》 NETDEV_FEATURE_COUNT
// ...
// ret = ethnl_parse_bitset(req_wanted, req_mask, NETDEV_FEATURE_COUNT,
// 			 tb[ETHTOOL_A_FEATURES_WANTED],
// 			 netdev_features_strings, info->extack);

// 0x051c0e0a:     DW_TAG_enumerator
//                   DW_AT_name    ("NETDEV_FEATURE_COUNT")
//                   DW_AT_const_value     (0x40)

/**
 * bitmap_from_arr32 - copy the contents of u32 array of bits to bitmap
 *	@bitmap: array of unsigned longs, the destination bitmap
 *	@buf: array of u32 (in host byte order), the source bitmap
 *	@nbits: number of bits in @bitmap
 */
// void bitmap_from_arr32(unsigned long *bitmap, const u32 *buf, unsigned int nbits)


// int ethnl_parse_bitset(unsigned long *val, unsigned long *mask,
// 		       unsigned int nbits, const struct nlattr *attr,
// 		       ethnl_string_array_t names,
// 		       struct netlink_ext_ack *extack)
// {...
// 630		change_bits = nla_get_u32(tb[ETHTOOL_A_BITSET_SIZE]);
// 631		// if (change_bits > nbits)
// 632		// 	change_bits = nbits;  inject stack OOB
// 633		bitmap_from_arr32(val, nla_data(tb[ETHTOOL_A_BITSET_VALUE]),
// 634				  change_bits);

// ffffffff87693120 <ethnl_parse_bitset>:
// ...
// ffffffff87693566:       8b 6d 04                mov    0x4(%rbp),%ebp
// ffffffff87693569:       4c 89 ef                mov    %r13,%rdi
// ffffffff8769356c:       48 8b 84 24 90 00 00 00         mov    0x90(%rsp),%rax
// ffffffff87693574:       89 ea                   mov    %ebp,%edx
// ffffffff87693576:       48 8d 70 04             lea    0x4(%rax),%rsi
// ffffffff8769357a:       48 89 44 24 10          mov    %rax,0x10(%rsp)
// ffffffff8769357f:       e8 dc 31 78 fc          call   ffffffff83e16760 <bitmap_from_arr32>
// ffffffff87693584:       44 8b 64 24 18          mov    0x18(%rsp),%r12d

// KASAN: stack-out-of-bounds Write in bitmap_from_arr32

// check dst:val    changbe_bits > 0x40 (NETDEV_FEATURE_COUNT) 


// python -c 'print(hex(0xffffffff8769357f-0xffffffff87693120))'
SEC("kprobe/ethnl_parse_bitset+0x45f")
int BPF_KPROBE(prog1)
{
    u64 dst = ctx->di; // len of dst is 0x40 * 8(unsigned long)
    u64 src = ctx->si;
    u64 len = ctx->dx;
    int oob = len > 0x40 * 8;

    bpf_printk("ethnl_parse_bitset: dst:0x%lx, src:0x%lx, len:0x%lx\n", dst, src, len);
    bpf_printk("ethnl_parse_bitset: oob:%d len > NETDEV_FEATURE_COUNT(0x40)*8\n", oob);
    return 0;
}


// SEC("kprobe/__free_pages")
// int BPF_KPROBE()



char LICENSE[] SEC("license") = "Dual BSD/GPL";
