#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
// #include "kmalloc_ret.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}



int main(int argc, char **argv)
{
    struct bpf_link *links[2];
	struct bpf_program *prog;
	struct bpf_object *obj;
	char filename[256];
	int map_fd, i, j = 0;
	__u64 key, next_key, val;

    snprintf(filename, sizeof(filename), "%s.bpf.o", argv[0]);
	
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	// prog = bpf_object__find_program_by_name(obj, "kmalloc_ret");
	// if (!prog) {
	// 	fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
	// 	goto cleanup;
	// }

    // link = bpf_program__attach(prog);
	// if (libbpf_get_error(link)) {
	// 	fprintf(stderr, "ERROR: bpf_program__attach failed\n");
	// 	link = NULL;
	// 	goto cleanup;
	// }

	bpf_object__for_each_program(prog, obj) {
		links[j] = bpf_program__attach(prog);
		if (libbpf_get_error(links[j])) {
			fprintf(stderr, "ERROR: bpf_program__attach failed\n");
			links[j] = NULL;
			goto cleanup;
		}
		j++;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

    printf("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

    while (!stop) {
        fprintf(stderr, ".");
        sleep(1);
    }


    cleanup:
        // bpf_link__destroy(link);
		for (j--; j >= 0; j--)
			bpf_link__destroy(links[j]);
	    bpf_object__close(obj);
        return 0;




    return 0;
}