
linear_sweeper = '''
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 5000000);
    __type(key, u64); 
    __type(value, u64); 
} dangling_ptr_map SEC(".maps");



struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 40960);
    __type(key, u64); // quarantined objects
    __type(value, u64); 
} quarantine_map SEC(".maps");



struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200);
    __type(key, u64); // quarantined flag
    __type(value, u64); 
} quaran_flag SEC(".maps");


struct hmap_elem {
	// int pad; /* unused */
	struct bpf_timer timer;
};

struct inner_map {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, int);
	__type(value, struct hmap_elem);
} inner_htab SEC(".maps");

#define ARRAY_KEY 1
#define HASH_KEY 1234

struct outer_arr {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 100);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__array(values, struct inner_map);
} outer_arr SEC(".maps") = {
	.values = { [ARRAY_KEY] = &inner_htab },
};
    

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200);
    __type(key, u32); // pid
    __type(value, struct pt_regs); 
} checkpoints SEC(".maps");


u64 INTERVAL = 4 * (u64)1000000000;

#define RANGE_FLAG	0
#define OFFSET_FLAG	1

u64 count = 0;

static int timer_sweep(void *map, int *key, struct hmap_elem *val)
{
    int err = 0;
    
    unsigned long GB = (1 << 30);
    unsigned long MB = (1 << 20);
    unsigned long len = 256 * MB;
    unsigned long start_addr = (count %% 32) * len;

    struct range_args args = {start_addr, len};
    bpf_uaf_dangling_ptr_sweep(&dangling_ptr_map, &args, RANGE_FLAG);
    if (count != 0 && count %% 64 == 0) {
        bpf_uaf_free_undangle(&dangling_ptr_map, &quarantine_map, RANGE_FLAG);
    }
    ++count;


    bpf_timer_set_callback(&val->timer, timer_sweep);
    bpf_timer_start(&val->timer, INTERVAL, 0);

    return 0;
}



SEC("kprobe/%(free_func)s+%(offset)s")
int BPF_KPROBE(prog0)
{
    u64 fc_source = ctx->di ^ 0xffffffffffffffff;

    u64 val = 0;
    int err = bpf_map_update_elem(&quaran_flag, &fc_source, &val, BPF_ANY);
    if (err < 0) {
        bpf_printk("put_fs_context quarantine fc->source failed: %%d\\n", err);
    }
    return err;
}




#define ARRAY_KEY 1
#define HASH_KEY 1234
#define CLOCK_REALTIME			0
#define CLOCK_MONOTONIC			1


int timer_init(void)
{
    int err = 0;
    struct hmap_elem init = {};
	struct bpf_map *inner_map;
	struct hmap_elem *val;
	int array_key = ARRAY_KEY;
	int hash_key = HASH_KEY;

    u32 pid = bpf_get_current_pid_tgid();
    
    u64 v = 0;
    u32 *pval = NULL;


    inner_map = bpf_map_lookup_elem(&outer_arr, &array_key);
    if (!inner_map)
        return 0;
    bpf_map_update_elem(inner_map, &hash_key, &init, 0);
    val = bpf_map_lookup_elem(inner_map, &hash_key);
    if (!val)
        return 0;
    bpf_timer_init(&(val->timer), inner_map, CLOCK_REALTIME);
    err = bpf_timer_set_callback(&val->timer, timer_sweep);
    if (err < 0) {
        bpf_printk("bpf_timer_set_callback failed\\n");
        return err;
    }
    err = bpf_timer_start(&val->timer, INTERVAL, 0);
    if (err < 0) {
        bpf_printk("bpf_timer_start failed\\n");
        return err;
    }

    bpf_printk("==========initialized===========\\n");
}

int init_flag = 0;
SEC("kprobe/kfree")
int BPF_KPROBE(initialized)
{
    int err = 0;
    u32 pid = bpf_get_current_pid_tgid();
    u64 v = 0;
    u32 *pval = NULL;
    u32 *pv1 = NULL;

    u64 obj_addr = ctx->di ^ 0xffffffffffffffff;
    pval = bpf_map_lookup_elem(&quaran_flag, &obj_addr);
    if (pval != NULL) {
        // skip the kfree and quarantine the freed object
        v = bpf_get_buff_len(ctx->di);
        bpf_printk("====%(CVE)s pointer in %(free_func)s quarantined====\\n");

        if (*pval) {
            pv1 = bpf_map_lookup_elem(&quarantine_map, &obj_addr);
            if (pv1) {
                bpf_printk("===double free %%u: %%lx=====\\n", v, obj_addr);
            }
            err = bpf_map_update_elem(&quarantine_map, &obj_addr, &v, BPF_ANY);
        } 

        err |= bpf_map_delete_elem(&quaran_flag, &obj_addr);
        if (err < 0) {
            bpf_printk("quarantine failed %%d\\n", err);
            return -1;
        }
        bpf_override_return(ctx, 0);
    }

// ========timer init===================
    if (!init_flag) {
        init_flag = 1;
        timer_init();

        unsigned long MB = (1 << 20);
        unsigned long len = 512 * MB;

        struct range_args args = {0x0, len * (unsigned long)1};
        bpf_uaf_dangling_ptr_sweep(&dangling_ptr_map, &args, RANGE_FLAG);
        bpf_uaf_free_undangle(&dangling_ptr_map, &quarantine_map, RANGE_FLAG);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
'''


c_prog = '''
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
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
	int map_fd[3], i, j = 0;
	__u64 key, next_key, val;
	int trace_fd;
	
	trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0) {
		printf("cannot open trace_pipe %d\\n", trace_fd);
		return trace_fd;
	}

    snprintf(filename, sizeof(filename), "%s.bpf.o", argv[0]);
	
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\\n");
		return 0;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\\n");
		goto cleanup;
	}

	map_fd[0] = bpf_object__find_map_fd_by_name(obj, "dangling_ptr_map");
	if (map_fd[0] < 0) {
		fprintf(stderr, "ERROR: finding dangling_ptr_map in obj file failed\\n");
		goto cleanup;
	}

	map_fd[1] = bpf_object__find_map_fd_by_name(obj, "quarantine_map");
	if (map_fd[1] < 0) {
		fprintf(stderr, "ERROR: quarantine_map in obj file failed\\n");
		goto cleanup;
	}

	bpf_object__for_each_program(prog, obj) {
		links[j] = bpf_program__attach(prog);
		if (libbpf_get_error(links[j])) {
			fprintf(stderr, "ERROR: bpf_program__attach failed\\n");
			links[j] = NULL;
			goto cleanup;
		}
		j++;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\\n", strerror(errno));
		goto cleanup;
	}

    printf("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\\n");

	
	printf("start tracing\\n");
    while (!stop) {
        // fprintf(stderr, ".");
        // sleep(1);
		static char buf[4096];
		ssize_t sz;
		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = '\\0';
			// printf("trace: %s\\n", buf);
			puts(buf);
		}
    }


    cleanup:
        // bpf_link__destroy(link);
		printf("\\nprint dangling_ptr_map\\n");
		int count = 0;
		while (bpf_map_get_next_key(map_fd[0], &key, &next_key) == 0) {
			bpf_map_lookup_elem(map_fd, &next_key, &val);
			key = next_key;
			++count;
			// printf("%5d:%016lx:%d\\n", count, key, val);
		}
		printf("there are %d potential dangling ptrs(not duplicate)\\n", count);

		printf("\\nprint quarantine_map\\n");
		count = 0;
		key = 0;
		next_key = 0;
		while (bpf_map_get_next_key(map_fd[1], &key, &next_key) == 0) {
			bpf_map_lookup_elem(map_fd[1], &next_key, &val);
			key = next_key;
			printf("%5d:%016lx:%d\\n", ++count, key, val);
		}


		for (j--; j >= 0; j--)
			bpf_link__destroy(links[j]);
	    bpf_object__close(obj);
		close(trace_fd);
        return 0;




    return 0;
}
'''