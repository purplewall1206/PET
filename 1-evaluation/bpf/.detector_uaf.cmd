cmd_/pet/linux-5.15-vulns/samples/bpf/detector_uaf := gcc -Wp,-MD,/pet/linux-5.15-vulns/samples/bpf/.detector_uaf.d -Wall -O2 -Wmissing-prototypes -Wstrict-prototypes -I./usr/include -I./tools/testing/selftests/bpf/ -I./tools/lib/ -I./tools/include -I./tools/perf -DHAVE_ATTR_TEST=0   -o /pet/linux-5.15-vulns/samples/bpf/detector_uaf /pet/linux-5.15-vulns/samples/bpf/detector_uaf.o /pet/linux-5.15-vulns/samples/bpf/../../tools/lib/bpf/libbpf.a -lelf -lz 