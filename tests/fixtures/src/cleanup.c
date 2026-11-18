/* D570: a C cleanup under -fexceptions: the call to `work` unwinds to a pad that frees `buffer`. */
#include <stdlib.h>

static void release(char **buffer) { free(*buffer); }

void (*volatile hook)(char *);

__attribute__((noinline)) void work(char *buffer) { hook(buffer); }

__attribute__((noinline)) int guarded(int n) {
    char *buffer __attribute__((cleanup(release))) = malloc((size_t)n);
    work(buffer);
    return n;
}

int main(int argc, char **argv) {
    (void)argv;
    return guarded(argc);
}
