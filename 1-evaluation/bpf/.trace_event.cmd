cmd_/pet/linux-5.15-vulns/samples/bpf/trace_event := gcc -Wp,-MD,/pet/linux-5.15-vulns/samples/bpf/.trace_event.d -Wall -O2 -Wmissing-prototypes -Wstrict-prototypes -I./usr/include -I./tools/testing/selftests/bpf/ -I./tools/lib/ -I./tools/include -I./tools/perf -DHAVE_ATTR_TEST=0   -o /pet/linux-5.15-vulns/samples/bpf/trace_event /pet/linux-5.15-vulns/samples/bpf/trace_event_user.o /pet/linux-5.15-vulns/samples/bpf/../../tools/testing/selftests/bpf/trace_helpers.o /pet/linux-5.15-vulns/samples/bpf/../../tools/lib/bpf/libbpf.a -lelf -lz 
