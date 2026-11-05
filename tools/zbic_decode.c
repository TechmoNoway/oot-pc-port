#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zstd.h"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#define INPUT_LIMIT ((size_t)256 * 1024 * 1024)

int main(int argc, char **argv) {
    if (argc != 2) {
        fputs("Usage: zbic-decode EXPECTED_SIZE < compressed > decoded\n", stderr);
        return 2;
    }
    char *end;
    errno = 0;
    unsigned long long requested = strtoull(argv[1], &end, 10);
    if (errno || end == argv[1] || *end || argv[1][0] == '-' || requested > INPUT_LIMIT) {
        fputs("Invalid decoded size.\n", stderr);
        return 2;
    }
#ifdef _WIN32
    if (_setmode(_fileno(stdin), _O_BINARY) == -1 || _setmode(_fileno(stdout), _O_BINARY) == -1) {
        fputs("Could not enable binary pipes.\n", stderr);
        return 1;
    }
#endif
    size_t size = 0, capacity = 65536;
    unsigned char *input = malloc(capacity);
    if (!input) return 1;
    for (;;) {
        size += fread(input + size, 1, capacity - size, stdin);
        if (ferror(stdin)) { free(input); return 1; }
        if (feof(stdin)) break;
        if (size == capacity) {
            if (capacity == INPUT_LIMIT) {
                if (fgetc(stdin) != EOF) {
                    fputs("Compressed input exceeds size limit.\n", stderr);
                    free(input);
                    return 1;
                }
                break;
            }
            capacity *= 2;
            unsigned char *grown = realloc(input, capacity);
            if (!grown) { free(input); return 1; }
            input = grown;
        }
    }
    if (size < 4 || memcmp(input, "ZBIC", 4)) {
        fputs("Invalid ZBIC signature.\n", stderr);
        free(input);
        return 1;
    }
    size_t expected = (size_t)requested;
    unsigned char *output = malloc(expected ? expected : 1);
    if (!output) { free(input); return 1; }
    size_t actual = ZSTD_decompress(output, expected, input, size);
    free(input);
    if (ZSTD_isError(actual) || actual != expected) {
        if (ZSTD_isError(actual)) fprintf(stderr, "ZBIC: %s\n", ZSTD_getErrorName(actual));
        else fputs("ZBIC decoded size mismatch.\n", stderr);
        free(output);
        return 1;
    }
    int failed = fwrite(output, 1, actual, stdout) != actual || fflush(stdout) != 0;
    free(output);
    return failed ? 1 : 0;
}
