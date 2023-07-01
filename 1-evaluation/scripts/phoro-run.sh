#!/bin/bash

#vanilla
python3 phoronix-tests.py  evaluation-vanilla

# int overflow
/root/bpf/detector_CVE-2017-7184 &
python3 phoronix-tests.py evaluation-CVE-2017-7184
pkill -9 'detector_'


# oob
/root/bpf/detector_CVE-2016-6187 &
python3 phoronix-tests.py evaluation-CVE-2016-6187
pkill -9 'detector_'

# uaf
/root/bpf/detector_CVE-2021-4154 &
python3 phoronix-tests.py evaluation-CVE-2021-4154
pkill -9 'detector_'

# uninit
/root/bpf/detector_kmsan_4b28366af7d9 &
python3 phoronix-tests.py evaluation-kmsan_4b28366af7d9
pkill -9 'detector_'

# data race
/root/bpf/detector_kcsan_dcf8e5633e2e &
python3 phoronix-tests.py evaluation-kcsan_dcf8e5633e2e
pkill -9 'detector_'

# scalability
/root/bpf/detector_CVE-2016-6187 &
/root/bpf/detector_CVE-2021-4154 &
/root/bpf/detector_CVE-2017-7184 &
/root/bpf/detector_kmsan_4b28366af7d9 &
/root/bpf/detector_kcsan_dcf8e5633e2e &
python3 phoronix-tests.py evaluation-scalability
pkill -9 'detector_'
