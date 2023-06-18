#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

//  drivers/usb/gadget/udc/dummy_hcd.c
// static int dummy_hub_control
// ...
// 2333				if ((dum_hcd->port_status &
// 2334				     USB_PORT_STAT_POWER) != 0) {
// 2335					dum_hcd->port_status |= (1 << wValue);
// 2336				}

// ffffffff818d2e30 <dummy_hub_control>:
// ...
// ffffffff818d304a:       0f 84 07 06 00 00       je     ffffffff818d3657 <dummy_hub_control+0x827>
// ffffffff818d3050:       f6 c4 01                test   $0x1,%ah
// ffffffff818d3053:       74 09                   je     ffffffff818d305e <dummy_hub_control+0x22e>
// ffffffff818d3055:       0f ab d0                bts    %edx,%eax  [2335]
// ffffffff818d3058:       89 85 98 02 00 00       mov    %eax,0x298(%rbp)
// ffffffff818d305e:       4c 89 ff                mov    %r15,%rdi
// ffffffff818d3061:       4c 89 14 24             mov    %r10,(%rsp)

// python -c 'print(hex(0xffffffff818d3055-0xffffffff818d2e30))'
SEC("kprobe/dummy_hub_control+0x225")
int BPF_KPROBE(integeroob)
{
    if (ctx->dx > 64) {
        return -1;
    }
    u32 origin = (u32) ctx->ax << (u32) ctx->dx;
    u64 precious = ctx->ax << ctx->dx;
    if (origin != precious) {
        bpf_printk("integer OOB triggered in dummy_hub_control+0x225\n");
    }
    return 0;
}












char LICENSE[] SEC("license") = "Dual BSD/GPL";


