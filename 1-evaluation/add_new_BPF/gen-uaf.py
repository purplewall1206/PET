from gen_format import linear_sweeper
from gen_format import c_prog
import sys

# free_func = 'put_fs_context'
# CVE = 'CVE-2021-4154'
# offset = '0xec'
# fn0 = '/home/ppw/Documents/ebpf-detector/linux-5.15-vulns/samples/bpf/detector_CVE-2021-4154-mapper.bpf.c'

free_func = sys.argv[1]
CVE = sys.argv[2]
offset = sys.argv[3]
fileaddr = sys.argv[4]

fn = fileaddr+'/'+CVE+'-evaluation'
fn0 = fn + '.bpf.c'
fn1 = fn + '.c'

# print( bpf_c%({'free_func':free_func, 'CVE':CVE, 'offset':offset}) )
# print( x%({'free_func':free_func, 'offset':offset}) )

with open(fn0, 'w') as f:
    f.write(linear_sweeper%({'free_func':free_func, 'CVE':CVE, 'offset':offset}))


with open(fn1, 'w') as f:
    f.write(c_prog)
