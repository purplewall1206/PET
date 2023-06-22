import re
import sys

file = '/home/ppw/Documents/ebpf-detector/linux-5.15-vulns/vmlinux.s'
# objdump -drwC vmlinux > vmlinux.s

func = sys.argv[1]
func_addr = 0
func_start = 0
func_call_kfree = 0

with open(file, 'r') as f:
    start = 0
    pattern = r"\b([0-9a-fA-F]{16})\b"
    for line in f.readlines():
        if line.find('<' +func +'>:') != -1:
            # print(line)
            match = re.search(pattern, line)
            if match:
                hex_numbers = match.group(1)
                func_addr = int(hex_numbers, 16)
                func_start = 1
        if func_start == 1 and re.match(r".*<kfree>", line):
            # print(line)
            match = re.search(pattern, line)
            if match:
                hex_numbers = match.group(1)
                func_call_kfree = int(hex_numbers, 16)
            break
        if func_start == 1 and line == '':
            print('=======')
            break

if func_call_kfree == 0:
    print('no kfree!!')
    exit()
# print(hex(func_addr), hex(func_call_kfree), hex(func_call_kfree-func_addr))
print('%s: 0x%016lx'%(func, func_addr))
print('the function that call: 0x%016lx'%(func_call_kfree))
print('offset: 0x%lx'%(func_call_kfree-func_addr))

