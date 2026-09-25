#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define NOINL __attribute__((noinline))

struct node { int key; struct node *next; char tag[8]; };

int g_counter = 5;
const char *g_msg = "hello global";
static int g_table[16];

NOINL int add(int a, int b) { return a + b; }

NOINL unsigned sum_array(const unsigned *v, int n) {
    unsigned s = 0;
    for (int i = 0; i < n; i++) s += v[i];
    return s;
}

NOINL int classify(int x) {
    switch (x) {
    case 0: return 10;
    case 1: return 21;
    case 2: return 32;
    case 3: return 43;
    case 4: return 54;
    case 5: return 65;
    case 7: return 87;
    default: return -1;
    }
}

NOINL int list_len(const struct node *n) {
    int c = 0;
    while (n) { c++; n = n->next; }
    return c;
}

NOINL int64_t mul_div(int64_t a, int64_t b) {
    if (b == 0) return 0;
    return (a * 7) / b + (a % b);
}

NOINL double avg(const double *v, int n) {
    double s = 0.0;
    for (int i = 0; i < n; i++) s += v[i];
    return n ? s / n : 0.0;
}

NOINL int fact(int n) { return n <= 1 ? 1 : n * fact(n - 1); }

NOINL void fill(int v) {
    for (int i = 0; i < 16; i++) g_table[i] = v + i;
    g_counter += v;
}

NOINL size_t copy_name(char *dst, const char *src, size_t cap) {
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = 0;
    return n;
}

NOINL int16_t sext(int8_t x) { return (int16_t)x * -3; }

NOINL unsigned rotl(unsigned x, int r) { return (x << r) | (x >> (32 - r)); }

NOINL int bit_count(uint32_t x) {
    int c = 0;
    while (x) { x &= x - 1; c++; }
    return c;
}

NOINL int find(const int *v, int n, int key) {
    for (int i = 0; i < n; i++) {
        if (v[i] == key) return i;
        if (v[i] > key) break;
    }
    return -1;
}

NOINL int dispatch(int (*fn)(int, int), int a) { return fn(a, a + 1); }

int main(int argc, char **argv) {
    unsigned v[4] = {1, 2, 3, 4};
    struct node c = {3, 0, "c"}, b = {2, &c, "b"}, a = {1, &b, "a"};
    double d[3] = {1.0, 2.5, 3.5};
    char buf[16];
    int r = add(argc, 3);
    r += sum_array(v, 4);
    r += classify(argc);
    r += list_len(&a);
    r += (int)mul_div(argc * 100, 3);
    r += (int)avg(d, 3);
    r += fact(5);
    fill(argc);
    r += (int)copy_name(buf, argc > 1 ? argv[1] : g_msg, sizeof buf);
    r += sext((int8_t)argc) + rotl(argc, 3) + bit_count(0xf0f0);
    r += find(g_table, 16, 7) + dispatch(add, argc);
    printf("%d %s\n", r, buf);
    return r & 0xff;
}
