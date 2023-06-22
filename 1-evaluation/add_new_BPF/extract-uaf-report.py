import re
import sys

file_content = []
parse_start = 0
call_trace_start = 0
call_trace_count = 0
allocated_by_start = 0
freed_by_start = 0

call_trace = []
allocated_by = []
freed_by = []

filename = sys.argv[1]

with open(filename, 'r') as f:
    pattern = r'\[.*?\] (.*)'
    for line in f.readlines():
        if line.find('?') != -1 or line.find('kasan_') != -1:
            continue
        match = re.search(pattern, line)
        if match:
            extracted_string = match.group(1)
        file_content.append(extracted_string)
        if extracted_string.find('BUG: KASAN:') != -1:
            parse_start = 1
            print(extracted_string)
        

        if parse_start == 1:
            if extracted_string.find('Call Trace:') != -1:
                call_trace_start = 1
            elif extracted_string.find('Allocated by task ') != -1:
                allocated_by_start = 1
            elif extracted_string.find('Freed by task ') != -1:
                freed_by_start = 1
            elif extracted_string == '':
                call_trace_start = 0
                allocated_by_start = 0
                freed_by_start = 0
            if call_trace_start == 1:
                call_trace.append(extracted_string)
                call_trace_count = call_trace_count + 1
                if call_trace_count > 5:
                    call_trace_start = 0
            elif allocated_by_start == 1:
                allocated_by.append(extracted_string)
            elif freed_by_start == 1:
                freed_by.append(extracted_string)



freed_by_start = 0
for line in freed_by:
    if freed_by_start == 1:
        print(line)
        pattern = r'(.+?)\+'
        match = re.search(pattern, line)
        if match:
            extracted_info = match.group(1)
            print(extracted_info)
        break
    if line.find('kfree') != -1 or line.find('kmem_cache_free') != -1:
        freed_by_start = 1
