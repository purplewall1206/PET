# mapper

# sanitized kernel

## BPF report:

```
[   47.014065] ==================================================================
[   47.017123] BUG: KASAN: slab-out-of-bounds in apparmor_setprocattr+0x118/0x580
[   47.019721] Write of size 1 at addr ffff8880086e3d80 by task poc_cfh_baselin/295
[   47.022521] CPU: 1 PID: 295 Comm: poc_cfh_baselin Not tainted 5.15.0ebpf-detector+ #83
[   47.024725] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
[   47.026949] Call Trace:
[   47.027578]  dump_stack_lvl+0x46/0x5a
[   47.028514]  print_address_description.constprop.0+0x1f/0x140
[   47.029424]  ? apparmor_setprocattr+0x118/0x580
[   47.029706]  kasan_report.cold+0x7f/0x11b
[   47.029948]  ? apparmor_setprocattr+0x118/0x580
[   47.030216]  apparmor_setprocattr+0x118/0x580
[   47.030474]  ? apparmor_task_kill+0x430/0x430
[   47.030731]  ? kasan_set_free_info+0x20/0x30
[   47.030985]  ? do_sys_openat2+0xff/0x270
[   47.031219]  ? __mutex_lock_interruptible_slowpath+0x10/0x10
[   47.031552]  ? _copy_from_user+0x3a/0x70
[   47.031786]  proc_pid_attr_write+0x15b/0x1d0
[   47.032039]  vfs_write+0x106/0x3a0
[   47.032244]  ksys_write+0xb9/0x150
[   47.032447]  ? __ia32_sys_read+0x40/0x40
[   47.032680]  ? fpregs_assert_state_consistent+0x52/0x60
[   47.032989]  do_syscall_64+0x3b/0xc0
[   47.033204]  entry_SYSCALL_64_after_hwframe+0x44/0xae
[   47.033501] RIP: 0033:0x7f9b0908dfb3
[   47.033718] Code: 75 05 48 83 c4 58 c3 e8 cb 41 ff ff 66 2e 0f 1f 84 00 00 00 00 00 90 64 8b 04 25 18 00 00 00 85 c0 75 14 b8 01 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 55 c3 0f 1f 408
[   47.034755] RSP: 002b:00007ffdddf4b038 EFLAGS: 00000246 ORIG_RAX: 0000000000000001
[   47.035176] RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007f9b0908dfb3
[   47.035572] RDX: 0000000000000080 RSI: 00007ffdddf4b060 RDI: 0000000000000005
[   47.035968] RBP: 00007ffdddf4b0f0 R08: 0000000000000000 R09: 0000000000000001
[   47.036364] R10: 0000000000000000 R11: 0000000000000246 R12: 0000560d8f82a840
[   47.036777] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   47.037264] Allocated by task 0:
[   47.037448] (stack is not available)
[   47.037747] The buggy address belongs to the object at ffff8880086e3d00
                which belongs to the cache kmalloc-128 of size 128
[   47.038450] The buggy address is located 0 bytes to the right of
                128-byte region [ffff8880086e3d00, ffff8880086e3d80)
[   47.039160] The buggy address belongs to the page:
[   47.039443] page:000000004dbff0b7 refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x86e3
[   47.039989] flags: 0xfffffc0000200(slab|node=0|zone=1|lastcpupid=0x1fffff)
[   47.040396] raw: 000fffffc0000200 0000000000000000 dead000000000122 ffff8880058418c0
[   47.040876] raw: 0000000000000000 0000000080100010 00000001ffffffff 0000000000000000
[   47.041318] page dumped because: kasan: bad access detected
[   47.041751] Memory state around the buggy address:
[   47.042037]  ffff8880086e3c80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   47.042449]  ffff8880086e3d00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[   47.042869] >ffff8880086e3d80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   47.043276]                    ^
[   47.043463]  ffff8880086e3e00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[   47.043894]  ffff8880086e3e80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   47.044302] ==================================================================
[   47.044710] Disabling lock debugging due to kernel taint

```