import os
import time
import glob
import socket
import signal
import logging

from pwn import *
sh = process(b'/bin/sh')

def recvuntil_send(in0, in1, to):
    text = sh.recvuntil(in0, timeout=to)
    print(text)
    print('\n\n\n')
    sh.sendline(in1)


def main(argv):
    filename = argv[1]
    sh.sendline(b'phoronix-test-suite benchmark apache pts/build-linux-kernel pts/encode-mp3 pts/git pts/nginx pts/compress-xz  system/gimp  sqlite-speedtest  openssl osbench  perf-bench pts/redis pts/perl-benchmark')
    # sh.sendline(b'phoronix-test-suite benchmark apache pts/build-linux-kernel pts/encode-mp3 pts/git pts/nginx pts/compress-xz  system/gimp  sqlite-speedtest  openssl osbench tinymembench perf-bench wireguard')
    sh.recvuntil(b'Apache HTTP Server', timeout=20)
    # print('apache:')
    recvuntil_send(b'Concurrent Requests', b'2,3', 20)
    # print('build kernel:')
    recvuntil_send(b'Build', b'1', 20)
    # print('nginx:')
    recvuntil_send(b'Connections', b'2,3', 20)
    # print('gimp:')
    recvuntil_send(b'Test', b'5', 20)
    # print('openssl:')
    recvuntil_send(b'Algorithm', b'1,2', 20)
    # print('osbench:')
    recvuntil_send(b'Test', b'6', 20)
    # print('perf-bench')
    recvuntil_send(b'Benchmark', b'8', 20)
    # print('save to filename')

    print('redis')
    recvuntil_send(b'Multiple items can be selected, delimit by a comma.', b'1,2', 20)
    recvuntil_send(b'Multiple items can be selected, delimit by a comma.', b'1', 20)

    print('perl-benchmark')
    recvuntil_send(b'Multiple items can be selected, delimit by a comma.', b'3', 20)


    text = sh.recvuntil(b'Would you like to save these test results', timeout=10)
    print(text)
    print('\n\n\n')
    sh.sendline(b'Y')
    text = sh.recvuntil(b'Enter a name for the result file', timeout=20)
    print(text)
    print('\n\n\n')
    sh.sendline(filename)

    text = sh.recvuntil(b'nter a unique name to describe this test run / configuratio', timeout=20)
    print(text)
    print('\n\n\n')
    sh.sendline(b'xxxxxx')

    text = sh.recvuntil(b'New Description:', timeout=20)
    print(text)
    print('\n\n\n')
    sh.sendline(b'xxxxxxx')
    sleep(5)
    sh.sendline(b'x')

    while True:
        # sleep(5)
        # text = sh.recvuntil(b'Do you want to view the results in your web browser', timeout=10)
        text=sh.recvuntil(b'Do you want to view the text results of the testing', timeout=10)
        if text.find(b'Do you want to view') != -1:
            sh.sendline(b'n')
            break
        else:
            print(text)

    # text=sh.recvuntil(b'Would you like to upload the results to OpenBenchmarking.org', timeout=10)
    # sh.sendline(b'n')
    text=sh.recvuntil(b'Would you like to upload the results to OpenBenchmarking.org', timeout=10)
    sh.sendline(b'n')
    sleep(10)
    sh.sendline(b'n')
    sh.sendline(b'n')

    print('finish!!!')




    
 
if __name__ == "__main__":
    main(sys.argv)

