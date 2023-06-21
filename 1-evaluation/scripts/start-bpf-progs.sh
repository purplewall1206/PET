#!/bin/bash

# OOB, UAF, integer, uninitialized, data race
/root/bpf/detector_CVE-2016-6187 &
/root/bpf/detector_CVE-2021-4154 &
/root/bpf/detector_CVE-2017-7184 &
/root/bpf/detector_kmsan_4b28366af7d9 &
/root/bpf/detector_kcsan_dcf8e5633e2e