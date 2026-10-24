#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

__attribute__((noinline)) int checked_div(int a, int b) {
    if (__builtin_expect(b == 0, 0)) {
        fprintf(stderr, "division by zero\n");
        abort();
    }
    return a / b;
}

__attribute__((noinline)) uint32_t sum_bytes(const uint8_t *p, size_t n) {
    uint32_t s = 0;
    for (size_t i = 0; i < n; i++) s += p[i];
    return s;
}

__attribute__((noinline)) void must_alloc(size_t n, char **out) {
    *out = malloc(n);
    if (!*out) { perror("malloc"); exit(1); }
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage\n"); exit(2); }
    char *buf;
    must_alloc(strlen(argv[1]) + 1, &buf);
    strcpy(buf, argv[1]);
    printf("%u %d\n", sum_bytes((const uint8_t *)buf, strlen(buf)), checked_div(argc, argc - 1));
    free(buf);
    return 0;
}
