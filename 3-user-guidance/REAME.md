# templates for specific types of vulnerabilities
The project's goal is to monitor/detect root causes of vulnerabilities, so the first challenge is locating the vulnerable site in the kernel binary file. The assembly address, or, to be specific, the offset from the start of the function,  is where the detection policy will be deployed.

We analyze and parse the DWARF debug information to bridge the semantic gap between the source and optimized binary. Generally, the compiled kernel carries DWARF debug information in its ELF format executable file. The DWARF records the mapping between the source code and assembly code from the optimized binary. The mapping includes lines of code to assembly, registers, or stack addresses that store variables and offsets of data structure members. 

Here we list the detailed process to extract the context and the problems come along. Example from CVE-2022-34918.

## P1: locate the vulnerable context in the kernel binary file.

There are always vulnerable stack traces or the source code in bug reports, e.g. syzbot, kernel patches. So the first step is to locate the vulnerable addresses in assembly code.

By retrieving the DWO, it is easy to obtain assembly addresses of the vulnerable functions and source code.

```c
5339 void *nft_set_elem_init(const struct nft_set *set,
....
5347 	elem = kzalloc(set->ops->elemsize + tmpl->len, gfp);
....
5361		memcpy(nft_set_ext_data(ext), data, set->dlen);  
// out-of-bound !!!! here [0xffffffff81d57881  -- 5361 ]
```
```s
ffffffff81aa20ce:       e8 1d 16 83 ff          call   ffffffff812d36f0 <__kmalloc>  # 5347
....
ffffffff81d57881:       4c 8b 0c 24             mov    (%rsp),%r9                    # 5361
```

However, two challenges have to be solved to locate the accurate vulnerable context. 

### D1: The transformed assembly.

Due to the performance consideration, compilers, like GCC & clang, design multiple optimizations to accelerate the execution or shrink the file size. We find two troublesome code transformations during the analysis.

**hot/cold part of a function:** 
The execution probability of some branches in the kernel code, e.g., those with `unlikely` labels, is believed to be low, so the compiler optimizes these branches by splitting the function into often executing hot parts and seldom executing cold parts. 

The hot part is optimized for fast execution, while the cold part is for size. Although both parts belong to the same function in the source code, they are two individual assembly blocks in practice. 

We need extra attention to figure out where the vulnerable context is located.

```s
ffffffff81aa2090 <nft_set_elem_init>:
....
ffffffff81d577ff <nft_set_elem_init.cold>:
```

**inlined code:**

Compilers inline simple or single-caller functions into the caller function for performance optimization. The inlined callee functions save the time waste from prologues and epilogues of function calls. But when the vulnerability is just in the inlined code,  it becomes hard to extract the subroutine compared to a call instruction whose target has a precise range. 

The example shows an inilined `memcpy` in `nft_set_elem_init.cold`. 

```s
ffffffff81d577ff <nft_set_elem_init.cold>:
...
ffffffff81d57885:       0f b6 8b cb 00 00 00    movzbl 0xcb(%rbx),%ecx  [set->dlen]
ffffffff81d5788c:       4c 89 e6                mov    %r12,%rsi   [data]
ffffffff81d5788f:       41 0f b6 41 03          movzbl 0x3(%r9),%eax
ffffffff81d57894:       4c 01 c8                add    %r9,%rax
ffffffff81d57897:       48 89 c7                mov    %rax,%rdi [nft_set_ext_data(ext)]
ffffffff81d5789a:       f3 a4                   rep movsb %ds:(%rsi),%es:(%rdi)
```

Some inlined callee functions with branches will be teared apart into not continuous pieces, that are even harder to analyze.

e.g. CVE 2022-1015

```c
0x0f3d0b1d:     DW_TAG_inlined_subroutine
                  DW_AT_abstract_origin (0x0f3d119e "nft_payload_fast_eval")
                  DW_AT_entry_pc        (0xffffffff81a948e4)
                  DW_AT_unknown_2138    (0x0001)
                  DW_AT_ranges  (0x010beef0
                     [0xffffffff81a948e4, 0xffffffff81a948e4)
                     [0xffffffff81a948e4, 0xffffffff81a9490b)
                     [0xffffffff81a9490b, 0xffffffff81a9497e)  // not continuous
                     [0xffffffff81a949f0, 0xffffffff81a949fb)
                     [0xffffffff81a94a23, 0xffffffff81a94a2e))
                  DW_AT_call_file       ("/root/linux-5.15/net/netfilter/nf_tables_core.c")
                  DW_AT_call_line       (191)
                  DW_AT_call_column     (0x07)
                  DW_AT_sibling (0x0f3d0c31)
```

Fortunately, we solve the transformed assembly difficulties by focusing on only the vulnerable lines of code, although they may be inlined and not continuous in space. But we cannot escape paying more cautious and manual efforts to understand the context assembly's means.

### D2: The ambiguous address

Ideally, source code translates directly to assembly with the help of DWO, but the address mapping table is sometimes ambiguous. e.g., multiple assembly addresses eject to one line of code or vice versa. 

We research some situations and desperately find right and wrong answers in the table. So the available solution is to make a manual selection, which will be much easier than our efforts in solving D1 because the range of a vulnerable function context is ground truth.



```
Address            Line   Column File   ISA Discriminator Flags
------------------ ------ ------ ------ --- ------------- -------------
0xffffffff81ac4842    715      1      1   0             0
0xffffffff81ac4843    715      1      1   0             0
0xffffffff81ac4845    715      1      1   0             0
0xffffffff81ac4847    715      1      1   0             0
0xffffffff81ac4849    715      1      1   0             0
```



## P2: obtain the critical varibles

The detection policy verifies relevant variables to confirm the vulnerability triggering, so extracting the critical variables is also necessary.

Typically, assembly code stores variables in registers or the function stack, and the position is obtainable by traversing the DWO. Although one variable may be in different registers or the stack when the addresses are different, the address of the vulnerable context is clear enough to make a distinction.

Besides, many critical variables are members of a structure. Assembly code treats them as an offset from the base address of the data object that stores structures. Similarly, DWO also stores structure members' offsets.

examples from CVE-2022-34918

```c
ext
        [0xffffffff81d57811, 0xffffffff81d57880): DW_OP_reg9 R9
        [0xffffffff81d57880, 0xffffffff81d5789c): DW_OP_breg7 RSP+0)
data： [0xffffffff81d577ff, 0xffffffff81d578db): DW_OP_reg12 R12: %r12
set: [0xffffffff81d577ff, 0xffffffff81d578d8): DW_OP_reg3 RBX
set->dlen：0xcb(%rbx)
set->ops: 0xc0(%rbx)
set->ops->elemsize: 0x78 + [0xc0(%rbx)][%rax]
```
### D3 disappeared varibles

Some varibles do not lives the entire life time of a function, which means these varibles are not always observable. We move these non-observerable instructions out of our probe selection list to mitigate the flaw. the ignore of selection is feasible because vulnerable instructions operate critical varibles to trigger the vulnerabilty.


## P3: deduct the probe points.

After the collection of the vulnerable context and critical varibles, instructions will be selected to place probes for detection policy.

Notely, eBPF doesn't support post-handler currently, we put the pre-handler probe one instruction after the actual instruction, so the detection policy will be efficient at right time. 

Some times we need to probe on the function epilogue, a `retprobe` performs better than probe on the `ret` instruction, that may be optimized under some configuration against hardware vulnerability, e.g. `retpoline`. Also tracepoint has a lower overhead when record some frequent events, e.g. kernel memory allocation.

### D4: record the result and parameters of a callee in one probe

 argument of `kmalloc` is a varible in caller function, so the execution of callee function won't change the varible. 

 We can obtain the result and the parameter of  the callee in the instruction after the `call` instruction

 
```s
// ffffffff81aa2090 <nft_set_elem_init>:
// ...
// ffffffff81aa20b2:       48 8b 87 c0 00 00 00    mov    0xc0(%rdi),%rax
// ffffffff81aa20b9:       0f b7 7d 00             movzwl 0x0(%rbp),%edi
// ffffffff81aa20bd:       8b 74 24 48             mov    0x48(%rsp),%esi
// ffffffff81aa20c1:       48 89 0c 24             mov    %rcx,(%rsp)
// ffffffff81aa20c5:       03 78 78                add    0x78(%rax),%edi
// ffffffff81aa20c8:       81 ce 00 01 00 00       or     $0x100,%esi
// ffffffff81aa20ce:       e8 1d 16 83 ff          call   ffffffff812d36f0 <__kmalloc>  // set->ops->elemsize + tmpl->len
// ffffffff81aa20d3:       0f b7 55 00             movzwl 0x0(%rbp),%edx
```