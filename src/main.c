#include "host.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(void *) == 8, "A 64-bit build is required");

static void print_help(void) {
    puts("OOT PC Port 0.1.0 - Windows host scaffold\n"
         "Usage: oot-pc-port [--help | --version | --host-info | --self-test]\n"
         "Game loading and execution are not implemented yet.");
}

static int print_host_info(void) {
    HostInfo info;
    if (!host_query_info(&info)) {
        fputs("Could not query Windows host information.\n", stderr);
        return 1;
    }
    printf("Windows host: %" PRIu32 " logical processors, %" PRIu32 "-byte pages\n"
           "Performance counter: %" PRIu64 " ticks per second\n",
           info.processor_count, info.page_size, info.counter_frequency);
    return 0;
}

static int self_test(void) {
    HostInfo info;
    uint64_t before, after;
    if (!host_query_info(&info) || info.processor_count == 0 || info.page_size == 0 ||
        !host_counter_read(&before)) {
        fputs("Host self-test failed: host information or counter unavailable.\n", stderr);
        return 1;
    }
    unsigned char *memory = host_memory_allocate(info.page_size);
    if (memory == NULL) {
        fputs("Host self-test failed: memory allocation.\n", stderr);
        return 1;
    }
    int failures = 0;
    for (size_t i = 0; i < info.page_size; ++i) {
        if (memory[i] != 0) {
            failures = 1;
        }
        memory[i] = (unsigned char)(i % 251);
    }
    for (size_t i = 0; i < info.page_size; ++i) {
        if (memory[i] != (unsigned char)(i % 251)) {
            failures = 1;
        }
    }
    if (!host_memory_release(memory) || host_memory_allocate(0) != NULL ||
        !host_counter_read(&after) || after < before) {
        failures = 1;
    }
    if (failures) {
        fputs("Host self-test failed: memory or counter behavior.\n", stderr);
        return 1;
    }
    puts("Host self-test passed: zeroed memory, read/write, release, and monotonic counter.");
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
        print_help();
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("oot-pc-port 0.1.0");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--host-info") == 0) {
        return print_host_info();
    }
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) {
        return self_test();
    }
    fputs("Invalid arguments. Use --help for supported commands.\n", stderr);
    return 2;
}
