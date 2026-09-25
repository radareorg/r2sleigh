/* The equivalence gate's own fixture.
 *
 * Each function here is the original that a hand-written rendering in
 * selftest.py is graded against. The renderings are known to be right or known
 * to be wrong in one specific way, so the gate's verdict on each is known in
 * advance; a gate that misses one of them may not grade the engine. */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

#define NOINL __attribute__((noinline))

int st_counter = 3;
int st_other = 11;

struct st_node { int key; struct st_node *next; };

NOINL int st_add(int a, int b) { return (int)((unsigned)a + (unsigned)b); }

NOINL uint64_t st_mix(uint64_t a, uint32_t b) { return (a ^ b) * 0x9e3779b97f4a7c15ull; }

NOINL int st_clamp(int x)
{
    if (x < 0)
        return 0;
    if (x > 100)
        return 100;
    return x;
}

NOINL double st_scale(const double *v, int n)
{
    double s = 0.0;
    for (int i = 0; i < n && i < 64; i++)
        s += v[i];
    return s * 0.5;
}

NOINL void st_bump(int by) { st_counter += by; }

NOINL int st_print(int x, int y) { return printf("%d %d\n", x, y); }

NOINL size_t st_len(const char *s)
{
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

NOINL int st_sum_list(const struct st_node *n)
{
    int total = 0;
    while (n) {
        total += n->key;
        n = n->next;
    }
    return total;
}

NOINL void st_fill(unsigned char *dst, size_t n, unsigned char v)
{
    for (size_t i = 0; i < n && i < 4096; i++)
        dst[i] = (unsigned char)(v + i);
}

/* Eight integer arguments and nine floating ones: the last of each kind is
 * passed on the stack, which is where a thunk that miscounts goes wrong. */
NOINL int64_t st_many(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e, int64_t f,
                      int32_t g, int64_t h)
{
    return (int64_t)((uint64_t)a + 3u * (uint64_t)b + 5u * (uint64_t)c + 7u * (uint64_t)d
                     + 11u * (uint64_t)e + 13u * (uint64_t)f + 17u * (uint64_t)(int64_t)g
                     + 19u * (uint64_t)h);
}

NOINL double st_many_fp(double a, double b, double c, double d, double e, double f, double g,
                        double h, double i)
{
    return a - b + c - d + e - f + g - h + 2.0 * i;
}

/* Prints on every vector, so each run's capture is only as right as its reset
 * between vectors: a run that wrote less on an earlier vector must still line
 * up with the original on the next one. */
NOINL int st_say(int x)
{
    printf("%d\n", x);
    if (x > 5)
        return 100;
    return x;
}

/* Writes to stderr and then reads through its argument, so the NULL vector
 * writes and faults: it is dropped, and must not skew the vectors after it. */
NOINL int st_first(const char *p)
{
    fputs("first\n", stderr);
    return p[0];
}

/* Calls into libm, which only the original's DT_NEEDED brings in. */
NOINL double st_cosine(double x) { return cos(x) * 2.0; }

int main(void)
{
    struct st_node b = { 2, 0 }, a = { 1, &b };
    unsigned char buf[8];
    double d[2] = { 1.0, 2.0 };
    st_bump(1);
    st_fill(buf, sizeof buf, 1);
    return st_add(1, 2) + (int)st_mix(3, 4) + st_clamp(5) + (int)st_scale(d, 2) + st_print(1, 2)
        + (int)st_len("x") + st_sum_list(&a) + buf[0] + (int)st_many(1, 2, 3, 4, 5, 6, 7, 8)
        + (int)st_many_fp(1, 2, 3, 4, 5, 6, 7, 8, 9) + st_say(3) + st_first("x")
        + (int)st_cosine(0.5);
}
