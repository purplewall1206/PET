# analysis process

due to the large amount of debug information, we need some strategies to search the info rather than directly open the entire file and corrupt the machine.

## 1. dump all info we need

```shell
# do not open it
llvm-dwarfdump-12 --debug-info vmlinux > debuginfo/vmlinux.debug_info  # do not open it
# use vim to open it
llvm-dwarfdump --debug-line vmlinux > debuginfo/vmlinux.debug_line
llvm-dwarfdump --debug-frame vmlinux > debuginfo/vmlinux.debug_frame
```

for short
```shell
objdump -drwC vmlinux > vmlinux.s;llvm-dwarfdump --debug-info vmlinux > debuginfo/vmlinux.debug_info;llvm-dwarfdump --debug-line vmlinux > debuginfo/vmlinux.debug_line;llvm-dwarfdump --debug-frame vmlinux > debuginfo/vmlinux.debug_frame
```

- `debug_info` records all variable to binary information, but the offset is based on CFA
- `debug_line` records all lines number of source code to binary info, but there are multiple options for one line, pick right answer.
- `debug_frame` records all CFA info, but only include binary addresses, get function start from `debug_info` and search CFA here.

> BTW, --name/--recursives are useless, only show submodule lines.  

## 2. deal with `debug_info` to get vulnerable varibles

- first, get the line number of debug info you want. 
    `grep -rni 'bcm_rx_setup' debuginfo/vmlinux.debug_info `
- then, dump the relevent lines.
    `cat debuginfo/vmlinux.debug_info | tail -n +172315380 | head -n 5000 | more`

```
0x10e349fe:   DW_TAG_subprogram
                DW_AT_name      ("bcm_sendmsg")
                DW_AT_decl_file ("/root/linux-5.15/net/can/bcm.c")
                DW_AT_decl_line (1307)
                DW_AT_decl_column       (0x0c)
                DW_AT_prototyped        (true)
                DW_AT_type      (0x10e11819 "int")
                DW_AT_ranges    (0x0126ba70
                   [0xffffffff81b9ac90, 0xffffffff81b9b786)
                   [0xffffffff81d0e828, 0xffffffff81d0ef11))
                DW_AT_frame_base        (DW_OP_call_frame_cfa)
                DW_AT_GNU_all_call_sites        (true)
                DW_AT_sibling   (0x10e36b5c)

0x10e34a16:     DW_TAG_formal_parameter
                  DW_AT_name    ("sock")
                  DW_AT_decl_file       ("/root/linux-5.15/net/can/bcm.c")
                  DW_AT_decl_line       (1307)
                  DW_AT_decl_column     (0x27)
                  DW_AT_type    (0x10e22388 "socket*")
                  DW_AT_location        (0x03a44251: 
                     [0xffffffff81b9ac90, 0xffffffff81b9acea): DW_OP_reg5 RDI
                     [0xffffffff81b9acea, 0xffffffff81b9b537): DW_OP_GNU_entry_value(DW_OP_reg5 RDI), DW_OP_stack_value
                     [0xffffffff81b9b537, 0xffffffff81b9b542): DW_OP_reg5 RDI
                     [0xffffffff81b9b542, 0xffffffff81b9b786): DW_OP_GNU_entry_value(DW_OP_reg5 RDI), DW_OP_stack_value
                     [0xffffffff81d0e828, 0xffffffff81d0ef11): DW_OP_GNU_entry_value(DW_OP_reg5 RDI), DW_OP_stack_value)
                  DW_AT_unknown_2137    (0x03a44247)
```

## 3. search line of code to locate binary position

```
vim debuginfo/vmlinux.debug_line
```

search the file name, not the function name, and the source code line.

we can see the start and end address of the binary.

```
0xffffffff81d0e9d8   1090      3      1   0             0  is_stmt
0xffffffff81d0e9d8   1090     13      1   0             0
0xffffffff81d0e9db   1091      3      1   0             0
0xffffffff81d0e9e2   1094     18      1   0             0
0xffffffff81d0e9e4   1090     13      1   0             0
0xffffffff81d0e9e9   1091      3      1   0             0  is_stmt
0xffffffff81d0e9e9   1091      3      1   0             0  is_stmt
0xffffffff81d0e9e9   1091      3      1   0             0  is_stmt
0xffffffff81d0e9e9   1091      3      1   0             0  is_stmt
0xffffffff81d0e9e9   1091      3      1   0             0  is_stmt
0xffffffff81d0e9ee   1094      3      1   0             0  is_stmt
0xffffffff81d0e9ee   1184      2      1   0             0  is_stmt
0xffffffff81d0e9ee   1184      8      1   0             0
0xffffffff81d0e9f3   1184      5      1   0             0
0xffffffff81d0e9fc   1185      3      1   0             0  is_stmt
```

## 4. search CFA to calculate the stack varibles

attension `CFA=RBP+16` here RBP means basic stack address of the function

`RBP=[CFA-16]` is the real address of the %rbp


```
vim debuginfo/vmlinux.debug_frame


00301560 00000014 00301538 FDE cie=00301538 pc=ffffffff81d0e828...ffffffff81d0ef11
  Format:       DWARF32

  0xffffffff81d0e828: CFA=RBP+16: RBX=[CFA-64], RBP=[CFA-16], R10=[CFA-56], R12=[CFA-48], R13=[CFA-40], R14=[CFA-32], R15=[CFA-24], RIP=[CFA-8]

00301578 00000014 ffffffff CIE
  Format:                DWARF32
  Version:               1
  Augmentation:          ""
  Code alignment factor: 1
  Data alignment factor: -8
  Return address column: 16

  DW_CFA_def_cfa: RSP +8
  DW_CFA_offset: RIP -8
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:
  DW_CFA_nop:

  CFA=RSP+8: RIP=[CFA-8]
```



## 5. get the struct layout

```c
pahole 'xxx' vmlinux

struct file {
        union {
                struct llist_node  fu_llist;             /*     0     8 */
                struct callback_head fu_rcuhead;         /*     0    16 */
        } f_u;                                           /*     0    16 */
        struct path                f_path;               /*    16    16 */
        struct inode *             f_inode;              /*    32     8 */
        const struct file_operations  * f_op;            /*    40     8 */
        spinlock_t                 f_lock;               /*    48     4 */
        enum rw_hint               f_write_hint;         /*    52     4 */
        atomic_long_t              f_count;              /*    56     8 */
        /* --- cacheline 1 boundary (64 bytes) --- */
        unsigned int               f_flags;              /*    64     4 */
        fmode_t                    f_mode;               /*    68     4 */
        struct mutex               f_pos_lock;           /*    72    32 */
        loff_t                     f_pos;                /*   104     8 */
        struct fown_struct         f_owner;              /*   112    32 */
        /* --- cacheline 2 boundary (128 bytes) was 16 bytes ago --- */
        const struct cred  *       f_cred;               /*   144     8 */
        struct file_ra_state       f_ra;                 /*   152    32 */
        u64                        f_version;            /*   184     8 */
        /* --- cacheline 3 boundary (192 bytes) --- */
        void *                     f_security;           /*   192     8 */
        void *                     private_data;         /*   200     8 */
        struct hlist_head *        f_ep;                 /*   208     8 */
        struct address_space *     f_mapping;            /*   216     8 */
        errseq_t                   f_wb_err;             /*   224     4 */
        errseq_t                   f_sb_err;             /*   228     4 */

        /* size: 232, cachelines: 4, members: 21 */
        /* last cacheline: 40 bytes */
};
```

pahole is usually useful, but some structures are not defined in the headers and only used in one file, then we need to search the `debug_info`

```
grep -rni 'structure' debuginfo/vmlinux.debug_info # get pos
cat debuginfo/vmlinux.debug_info | tail -n +pos | head -n 5000 | more

0x10e32878:   DW_TAG_structure_type
                DW_AT_name      ("bcm_msg_head")
                DW_AT_byte_size (0x38)
                DW_AT_alignment (0x08)
                DW_AT_decl_file ("/root/linux-5.15/./include/uapi/linux/can/bcm.h")
                DW_AT_decl_line (67)
                DW_AT_decl_column       (0x08)
                DW_AT_sibling   (0x10e328f9)

0x10e32887:     DW_TAG_member
                  DW_AT_name    ("opcode")
                  DW_AT_decl_file       ("/root/linux-5.15/./include/uapi/linux/can/bcm.h")
                  DW_AT_decl_line       (68)
                  DW_AT_decl_column     (0x08)
                  DW_AT_type    (0x10e11826 "__u32")
                  DW_AT_data_member_location    (0x00)

0x10e32895:     DW_TAG_member
                  DW_AT_name    ("flags")
                  DW_AT_decl_file       ("/root/linux-5.15/./include/uapi/linux/can/bcm.h")
                  DW_AT_decl_line       (69)
                  DW_AT_decl_column     (0x08)
                  DW_AT_type    (0x10e11826 "__u32")
                  DW_AT_data_member_location    (0x04)
```

## 6. other tricks

- optimized inline functions: e.g. CVE-2010-2959， vulnerable `bcm_rx_setup` is inlined into the `bcm_sendmsg`
    all the `bcm_rx_setup` related debug info are under the submodule `bcm_sendmsg` (including the varibles)


