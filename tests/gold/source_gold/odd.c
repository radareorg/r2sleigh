#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

typedef int (*binop)(int, int);
typedef void (*handler)(int);
struct pair { long a; long b; };
struct big { long v[5]; };
enum color { RED, GREEN = 5, BLUE };

__attribute__((noinline)) static int add(int a, int b) { return a + b; }
__attribute__((noinline)) static int mul(int a, int b) { return a * b; }

__attribute__((noinline)) binop pick(int sel) { return sel ? add : mul; }
__attribute__((noinline)) int (*pick2(int sel))(int, int) { return sel ? mul : add; }
__attribute__((noinline)) handler set_handler(int sig, handler h) { static handler old; handler r = old; old = h; (void)sig; return r; }
__attribute__((noinline)) struct pair mkpair(long a, long b) { struct pair p = {a, b}; return p; }
__attribute__((noinline)) long sumpair(struct pair p) { return p.a + p.b; }
__attribute__((noinline)) struct big mkbig(long x) { struct big b; for (int i = 0; i < 5; i++) b.v[i] = x + i; return b; }
__attribute__((noinline)) long sumbig(struct big b) { long s = 0; for (int i = 0; i < 5; i++) s += b.v[i]; return s; }
__attribute__((noinline)) enum color next_color(enum color c) { return c == RED ? GREEN : c == GREEN ? BLUE : RED; }
__attribute__((noinline)) bool is_even(unsigned char c) { return (c & 1) == 0; }
__attribute__((noinline)) signed char sc(signed char c) { return c + 1; }
__attribute__((noinline)) unsigned short us(unsigned short c) { return c * 3; }
__attribute__((noinline)) long long ll(long long a, unsigned long long b) { return a - (long long)b; }
__attribute__((noinline)) double dbl(double x, float y) { return x * y; }
__attribute__((noinline)) float flt(float x) { return x + 1.0f; }
__attribute__((noinline)) int sum_va(int n, ...) { va_list ap; va_start(ap, n); int s = 0; while (n--) s += va_arg(ap, int); va_end(ap); return s; }
__attribute__((noinline)) const char *const *argv_at(const char *const *argv, size_t i) { return argv + i; }
__attribute__((noinline)) volatile int *vptr(volatile int *p) { return p + 1; }
__attribute__((noinline)) int arr2(int a[4][4], int (*row)[4]) { return a[1][2] + (*row)[3]; }
__attribute__((noinline)) void *vp(void *p, size_t n) { return (char *)p + n; }
__attribute__((noinline)) int deref_cb(int (*cbs[2])(int, int), int a) { return cbs[0](a, 1) + cbs[1](a, 2); }
__attribute__((noinline)) uint8_t u8(uint8_t a) { return a ^ 0x55; }
__attribute__((noinline)) int16_t i16(int16_t a, int16_t b) { return a * b; }
__attribute__((noinline)) _Bool bb(_Bool a, _Bool b) { return a && !b; }
__attribute__((noinline)) intptr_t ip(intptr_t a, uintptr_t b) { return a + (intptr_t)b; }
__attribute__((noinline)) ssize_t ss(ssize_t a) { return a - 1; }
__attribute__((noinline)) wchar_t wc(wchar_t a) { return a + 1; }
__attribute__((noinline)) char chr(char a) { return a + 1; }
__attribute__((noinline)) void nr(int a) __attribute__((noreturn));
void nr(int a) { exit(a); }

int main(int argc, char **argv) {
    int arrv[4][4] = {{0}};
    binop f = pick(argc);
    binop g = pick2(argc);
    int (*cbs[2])(int, int) = {f, g};
    set_handler(1, NULL);
    struct pair p = mkpair(argc, 2);
    struct big b = mkbig(argc);
    volatile int v = 0;
    long r = sumpair(p) + sumbig(b) + next_color((enum color)argc) + is_even((unsigned char)argc) + sc((signed char)argc) + us((unsigned short)argc)
        + ll(argc, argc) + (long)dbl(argc, 1.5f) + (long)flt(argc) + sum_va(2, 3, 4) + (long)argv_at((const char *const *)argv, 0)
        + (long)vptr(&v) + arr2(arrv, arrv) + (long)vp(argv, 1) + deref_cb(cbs, argc) + u8(argc) + i16(argc, 2) + bb(argc, 0) + ip(argc, 1)
        + ss(argc) + wc(argc) + chr((char)argc);
    if (r == 12345) nr(3);
    return (int)r;
}
