import re

# Define the pattern to match the desired line format
pattern = r'\[\s*\d+\.\d+\] BUG: KASAN:'
bug_type = ''
function_name = ''
offset = ''
# Open the file
with open('report.txt', 'r') as file:
    # Read the file line by line
    for line in file:
        # Check if the line matches the specified format
        if re.search(pattern, line):
            # If a match is found, print the line
            print(line.strip())

            pattern = r".*KASAN: (\S+) in (\S+)\+(\S+)/\S+"
            # Extract the desired information using regular expression matching
            match = re.match(pattern, line)
            if match:
                bug_type = match.group(1)
                function_name = match.group(2)
                offset = match.group(3)

                print("Bug Type:", bug_type)
                print("Function Name:", function_name)
                print("Offset:", offset)


if bug_type == 'slab-out-of-bounds':
    # grep '<apparmor_setprocattr>' vmlinux.s 
    # addr = ffffffff81803460 <apparmor_setprocattr>:
    # calucate addr + offset = 0xffffffff81803578
    # ffffffff81803578:       41 c6 06 00             movb   $0x0,(%r14) 
    # ffffffff8180356c:       4d 8d 34 2c             lea    (%r12,%rbp,1),%r14 -> precount 4
    # 
    # 
    # 
    # args[size] = '\0';
    # llvm-dwarfdump --debug-line vmlinux > debug_line.txt
    # grep "lsm.c"
    # ffffffff814ed21f:       c6 04 16 00             movb   $0x0,(%rsi,%rdx,1)
    # ffffffff814ed190 <apparmor_setprocattr>:
    # calculate 
    # 
elif bug_type == 'use-after-free':
    break
elif bug_type == 'array-out-of-bound':
    break
elif bug_type == 'shift-out-of-bound':
    break
elif bug_type == 'data race':
    break
elif bug_type == 'uninitialized':
    break
else:
    break