#!/bin/bash

# OOB, UAF, integer, uninitialized, data race
./bpf/detector_CVE-2016-6187 &
./bpf/detector_CVE-2021-4154 &
./bpf/detector_CVE-2017-7184 &
./bpf/detector_kmsan_4b28366af7d9 &
./bpf/detector_kcsan_dcf8e5633e2e &