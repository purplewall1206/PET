### generate a new BPF program to prevent vulnerability from being triggered.

more examples are in [user guidance](./2-).

There are mainly 4 steps to generate BPF program from scratch, we take a public available and fixed vulerability, `https://syzkaller.appspot.com/bug?id=6312526aba5beae046fdae8f00399f87aab48b12` as example

#### 1. get the bug report

First of all, evaluators need get bug report from sanitized kernel, we have prepared the proof-of-concept in the environment.

Evaluators can boot up sanitized kernel by running `run-kasan.sh`, then execute `./scripts/test-kasan-631252aba.sh`, the bug report will be export to the *terminal 1*.
after that, evaluators need to copy the bug report and paste in the file `kasan-631252aba.report`.

**as shown in `1-evaluation/add_new_BPF/kasan-631252aba.report`**

```
[   17.390082] ==================================================================
[   17.390770] BUG: KASAN: use-after-free in filp_close+0x21/0xa0
[   17.391349] Read of size 8 at addr ffff88800d847678 by task poc/342
[   17.391962] 
[   17.392129] CPU: 1 PID: 342 Comm: poc Not tainted 5.15.0ebpf-detector+ #83
[   17.392826] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/204
[   17.393669] Call Trace:
[   17.393928]  dump_stack_lvl+0x46/0x5a
```


#### 2. extract critical information and generate program

According to the error dependant policies in section *5.3 Use-After-Free Policy*, and the error independant policies in section *6 Error-independent Mechanisms*.

PET needs to get the free position than may conduct dangling pointers from bug report, including *function* that calls memory free function, and *offset* from *call kfree* to *function* start.
Evaluators can execute `python3 extract-uaf.py  kasan-631252aba.report` to get extract the critical information.
```sh
$ python3 extract-uaf-report.py kasan-631252aba.report 
BUG: KASAN: use-after-free in filp_close+0x21/0xa0
 put_fs_context+0x1ac/0x280
 put_fs_context


$ python3 extract-uaf-binary.py put_fs_context
put_fs_context: 0xffffffff81348670
the function that call: 0xffffffff8134875c
offset: 0xec
```

after that, evaluator take the critical information as input, execute `python3 gen-uaf.py kasan-631252aba function offset`.

2 files will be generated in the directory `/pet/linux-5.15-vulns/samples/bpf`, `detector_kasan-631252aba-evaluation.bpf.c` and `detector_kasan-631252aba-evaluation.c`

```sh
$ python3 gen-uaf.py  put_fs_context  kasan-631252aba  0xec  <path-to-kernel>/sample/bpf
```

#### 3. compile the BPF program

first of all, evaluators needs to add compile instructions in the `/root/linux-5.15-vulns/samples/bpf/Makefile`.
- `tprogs-y+=detector_kasan-631252aba-evaluation`
- `detector_kasan-631252aba-evaluation-objs+=detector_kasan-631252aba-evaluation.o`
- `always-y+=detector_kasan-631252aba-evaluation.bpf.o`

**for easy, we have already add them in the Makefile, and pre-compiled them because of the very complex compilation dependencies**

<!-- after that, executors can `mv` to the `/pet/linux-5.15-vulns/samples/bpf` in *terminal 2*, and execute `make -j2` to compile the program. -->


#### 4. functional tests

similar the the previous functional evaluation, evaluators can run `/root/linux-5.15-vulns/samples/bpf/detector_kasan-631252aba-evaluation` in *terminal 2*

and execute proof-of-concept in `/root/test-kasan-631252aba` in the *terminal 1*, results will be presented in *terminal 2*, dangling pointer will be quarantined.
