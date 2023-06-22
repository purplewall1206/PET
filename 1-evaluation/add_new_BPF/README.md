#### 1. get the bug report

First of all, evaluators need get bug report from sanitized kernel, we have prepared the proof-of-concept in the environment.

Evaluators can boot up sanitized kernel by running `run-kasan.sh`, then execute `./scripts/test-CVE-20xx-xxxx.sh`, the bug report will be export to the *terminal 1*.
after that, evaluators need to copy the bug report and paste in the file `CVE-20xx-xxxx.report`.

```

```


#### 2. extract critical information and generate program

According to the error dependant policies in section *5.3 Use-After-Free Policy*, and the error independant policies in section *6 Error-independent Mechanisms*.

PET needs to get the free position than may conduct dangling pointers from bug report, including *function* that calls memory free function, and *offset* from *call kfree* to *function* start.
Evaluators can execute `python3 extract-uaf.py  CVE-20xx-xxxx.report` to get extract the critical information.
```sh
$ python3 extract-uaf-report.py CVE-2019-18344.report 
BUG: KASAN: use-after-free in vid_cap_buf_queue+0xa2/0xc0
 __vb2_queue_free+0x26f/0x360
 __vb2_queue_free


$ python3 extract-uaf-binary.py  __vb2_queue_free
__vb2_queue_free: 0xffffffff8193c420
the function that call: 0xffffffff8193c55e
offset: 0x13e
```

after that, evaluator take the critical information as input, execute `python3 gen-uaf.py CVE-20xx-xxxx function offset`.

2 files will be generated in the directory `/pet/linux-5.15-vulns/samples/bpf`, `detector_CVE-20xx-xxxx-evaluation.bpf.c` and `detector_CVE-20xx-xxxx-evaluation.c`

```sh
$ python3 gen-uaf.py  __vb2_queue  CVE-2019-18344  0x13e  <path-to-kernel>/sample/bpf
```

#### 3. compile the BPF program

first of all, evaluators needs to add compile instructions in the `/pet/linux-5.15-vulns/samples/bpf/Makefile`.
- `tprogs-y+=detector_CVE-20xx-xxxx-evaluation.o`
- `detector_CVE-20xx-xxxx-evaluation-objs+=detector_CVE-20xx-xxxx-evaluation`
- `always-y+=detector_CVE-20xx-xxxx-evaluation.bpf.o`

**for easy, we have already add them in the Makefile**

after file generated, evaluators need to copy the entire kernel in the virtual machine. 
execute `reproduce.sh` to start 2 terminals same as in the *functional evaluation*, and the entire kernel source will be copied in the virtual machine.

after that, executors can `mv` to the `/pet/linux-5.15-vulns/samples/bpf` in both terminals, and execute `make -j2` to compile the program.


#### 4. functional tests

similar the the previous functional evaluation, evaluators can run `/pet/linux-5.15-vulns/samples/bpf/detector_CVE-20xx-xxxx-evaluation` in *terminal 2*

and execute proof-of-concept in `/root/CVE-20xx-xxxx/poc` in the *terminal 1*, results will be presented in *terminal 2*, dangling pointer will be quarantined.

