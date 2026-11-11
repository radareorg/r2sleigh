/* The scratch-void gate's shapes (doc/adr-scratch-result.md, S4): what a return leaves in RAX, built
   `-g -O2 -fstack-protector-strong`. `noipa` keeps each signature; each line names the mutant it kills. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEEP __attribute__((noipa))

volatile long sink;

/* void: the canary check leaves its residue in RAX (inserted-operation write) */
KEEP void canary_void(const char *s) {
    char buf[64];
    strncpy(buf, s, sizeof buf - 1);
    buf[63] = 0;
    puts(buf);
}

/* long: the canary check runs in a scratch register, the result is kept in RBX */
KEEP long canary_keeps(const char *s) {
    char buf[64];
    long n = (long)strlen(s);
    snprintf(buf, sizeof buf, "%ld", n);
    puts(buf);
    return n + sink;
}

/* void: `jmp free` leaves what free left (a void row) */
KEEP void tail_free(void *p) { free(p); }

/* int: `jmp puts` returns puts' result (a void row) */
KEEP int tail_puts(const char *s) { return puts(s); }

/* int: one path returns a value, the other falls off the end after free (the some-path join) */
#pragma GCC diagnostic ignored "-Wreturn-type"
KEEP int some_path(void *p, int k) {
    if (k)
        return k * 3 + (int)sink;
    free(p);
}

/* int: one path returns a value, the other falls off the end with RAX untouched (an entry byte) */
KEEP int falls_off(int k) {
    if (k > 0)
        return k * 5 + (int)sink;
}

/* long: returns its argument, an input's entry byte (any entry byte taken as undefined) */
KEEP long identity(long x) { return x; }

/* void and variadic: the prologue reads AL to save the vector registers, so RAX's entry byte is an input */
KEEP void sum_args(int n, ...) {
    __builtin_va_list ap;
    __builtin_va_start(ap, n);
    for (int i = 0; i < n; i++)
        sink += (long)__builtin_va_arg(ap, double);
    __builtin_va_end(ap);
}

int main(int argc, char **argv) {
    canary_void(argv[0]);
    sink = canary_keeps(argv[0]);
    tail_free(malloc(4));
    sink = tail_puts(argv[0]);
    sink = some_path(malloc(4), argc);
    sink = falls_off(argc);
    sink = identity(argc);
    sum_args(2, (double)argc, 0.5);
    return 0;
}
