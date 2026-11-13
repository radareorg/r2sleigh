/* S35 clause 2 (ROADMAP D209, D277): the six aarch64 glibc imports whose `char *` and `wchar_t *` parameters
   spelled `int8_t *` and `int32_t *`. Build `aarch64-linux-gnu-gcc -O2 probes.c`; no parameter may spell either. */
#define _GNU_SOURCE
#include <error.h>
#include <fcntl.h>
#include <regex.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wchar.h>

int main(int argc, char **argv) {
    regex_t re;
    regmatch_t m[1];
    int n = mkdir(argv[0], 0755);
    n += (int)strnlen(argv[0], (size_t)argc);
    n += unlinkat(AT_FDCWD, argv[0], 0);
    if (regcomp(&re, "a", 0) == 0)
        n += regexec(&re, argv[0], 1, m, 0);
    wchar_t *w = wcsdup(L"probe");
    if (!w)
        error_at_line(1, 0, argv[0], argc, "%d", n);
    return n + (int)w[0];
}
