import csv

tests = ['perf-bench - Benchmark: Epoll Wait (ops/sec)', 'perf-bench - Benchmark: Futex Hash (ops/sec)', 'perf-bench - Benchmark: Memcpy 1MB (GB/sec)', 'perf-bench - Benchmark: Memset 1MB (GB/sec)', 'perf-bench - Benchmark: Sched Pipe (ops/sec)', 'perf-bench - Benchmark: Futex Lock-Pi (ops/sec)', 'perf-bench - Benchmark: Syscall Basic (ops/sec)', 'OSBench - Test: Create Files (us/Event)', 'OSBench - Test: Create Threads (us/Event)', 'OSBench - Test: Launch Programs (us/Event)', 'OSBench - Test: Create Processes (us/Event)', 'OSBench - Test: Memory Allocations (Ns/Event)', 'Timed Linux Kernel Compilation - Build: defconfig (sec)', 'XZ Compression - Compressing ubuntu-16.04.3-server-i386.img', 'LAME MP3 Encoding - WAV To MP3 (sec)', 'Perl Benchmarks - Test: Pod2html (sec)', 'Perl Benchmarks - Test: Interpreter (sec)', 'OpenSSL - Algorithm: SHA256 (byte/s)', 'OpenSSL - Algorithm: RSA4096 (sign/s)', 'OpenSSL - Algorithm: RSA4096 (verify/s)', 'Redis - Test: GET - Parallel Connections: 50 (Reqs/sec)', 'Redis - Test: SET - Parallel Connections: 50 (Reqs/sec)', 'SQLite Speedtest - Timed Time - Size 1', 'GIMP - Test: resize (sec)', 'GIMP - Test: rotate (sec)', 'GIMP - Test: auto-levels (sec)', 'GIMP - Test: unsharp-mask (sec)', 'nginx - Connections: 20 (Reqs/sec)', 'nginx - Connections: 100 (Reqs/sec)', 'Apache HTTP Server - Concurrent Requests: 20 (Reqs/sec)', 'Apache HTTP Server - Concurrent Requests: 100 (Reqs/sec)', 'Git - Time To Complete Common Git Commands (sec)']

titles = ['evaluation-vanilla.csv', 'evaluation-cve-2017-7184.csv', 'evaluation-cve-2016-6187.csv', 'evaluation-cve-2021-4154.csv', 'evaluation-kmsan_4b28366af7d9.csv', 'evaluation-kcsan_dcf8e5633e2e.csv', 'evaluation-scalability.csv']
better = ['HIB', 'HIB', 'HIB', 'HIB', 'HIB', 'HIB', 'HIB', 'LIB', 'LIB', 'LIB', 'LIB', 'LIB', 'LIB', 'LIB', 'LIB', 'LIB', 'LIB', 'HIB', 'HIB', 'HIB', 'HIB', 'HIB', 'LIB', 'LIB', 'LIB', 'LIB', 'LIB', 'HIB', 'HIB', 'HIB', 'HIB', 'LIB']


folder_path = '/root/'
csv_data = []

count = 0
for filename in titles:
    try:
        with open(folder_path+filename, 'r') as file:
            reader = csv.reader(file)
            lines = list(reader)
            column_data = [line[2] for line in lines[16:48]]  # Adjust line index if needed
            csv_data.append(column_data)
            count = count + 1
    except FileNotFoundError:
        print('file not found ' + filename)

cmp_data = []
cmp_data.append([''])
vanilla = csv_data[0]
for i in range(1, count):
    data = csv_data[i]
    d = []
    for j in range(len(better)):
        x = float(vanilla[j])
        y = float(data[j])
        if better[j] == 'HIB':
            d.append((x-y)/x)
        elif better[j] == 'LIB':
            d.append((y-x)/y)
    cmp_data.append(d)



output_file = '/root/result.csv'

with open(output_file, 'w', newline='') as file:
    writer = csv.writer(file)
    t = tests.copy()
    t.insert(0, '')
    writer.writerow(t)
    # writer.writerow(['Extracted Data'])  # Header for the output file
    # writer.writerows([[data] for data in csv_data])
    for i in range(count):
        t = csv_data[i].copy()
        t.insert(0, titles[i])
        writer.writerow(t)
        t = cmp_data[i].copy()
        t.insert(0,'')
        writer.writerow(t)

print(f'Synthesized data has been saved to {output_file}.')
