cmd_/pet/linux-5.15-vulns/samples/bpf/detector_kasan_oob_c993ee0f9f81 := gcc -Wp,-MD,/pet/linux-5.15-vulns/samples/bpf/.detector_kasan_oob_c993ee0f9f81.d -Wall -O2 -Wmissing-prototypes -Wstrict-prototypes -I./usr/include -I./tools/testing/selftests/bpf/ -I./tools/lib/ -I./tools/include -I./tools/perf -DHAVE_ATTR_TEST=0   -o /pet/linux-5.15-vulns/samples/bpf/detector_kasan_oob_c993ee0f9f81 /pet/linux-5.15-vulns/samples/bpf/detector_kasan_oob_c993ee0f9f81.o /pet/linux-5.15-vulns/samples/bpf/../../tools/lib/bpf/libbpf.a -lelf -lz 