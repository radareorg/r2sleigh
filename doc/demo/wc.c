#include <stdio.h>
#include <string.h>

struct counts {
    long lines;
    long words;
    long bytes;
    long longest;
};

__attribute__((noinline))
static void count(const char *buf, size_t n, struct counts *c)
{
    long len = 0;
    int inword = 0;
    for (size_t i = 0; i < n; i++) {
        c->bytes++;
        switch (buf[i]) {
        case '\n':
            c->lines++;
            if (len > c->longest)
                c->longest = len;
            len = 0;
            inword = 0;
            break;
        case ' ':
        case '\t':
        case '\r':
            len++;
            inword = 0;
            break;
        default:
            len++;
            if (!inword)
                c->words++;
            inword = 1;
        }
    }
}

int main(int argc, char **argv)
{
    static char buf[65536];
    struct counts c;
    memset(&c, 0, sizeof c);
    FILE *fp = argc > 1 ? fopen(argv[1], "r") : stdin;
    if (fp == NULL) {
        perror(argv[1]);
        return 1;
    }
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, fp)) > 0)
        count(buf, n, &c);
    printf("%ld %ld %ld %ld\n", c.lines, c.words, c.bytes, c.longest);
    fclose(fp);
    return 0;
}
