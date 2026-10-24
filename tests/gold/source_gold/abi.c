/* Types whose ABI class the gate does not state: struct by value, vector, long double, __int128, complex, K&R. -std=gnu17. */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <complex.h>
typedef int v4si __attribute__((vector_size(16)));
typedef float v4sf __attribute__((vector_size(16)));
struct small { long a; long b; };
struct big { long a, b, c, d; };
struct mixed { double d; long l; };
union u16 { long l; double d; };
enum color { RED, GREEN = 200, BLUE };
enum wide { W0 = -1, W1 = 5000000000LL };
volatile long sink;

/* a vector parameter between two integers */
__attribute__((noinline)) int vec_mid(int a, v4si v, int b) { return a + v[0] * b; }
__attribute__((noinline)) int vecf_mid(char *p, v4sf v, long n) { return (int)(p[0] + v[0] * n); }
/* hidden result pointer: a struct returned in memory takes the first register */
__attribute__((noinline)) struct big make_big(int n, long *p) { struct big b = {n, p[0], p[1], p[2]}; return b; }
__attribute__((noinline)) struct small make_small(int n, long *p) { struct small b = {n, p[0]}; return b; }
__attribute__((noinline)) struct mixed make_mixed(long n, long *p) { struct mixed b = {(double)n, p[0]}; return b; }
/* 128-bit integers take two registers */
__attribute__((noinline)) long wide_mid(int a, __int128 w, long *p) { return a + (long)w + p[0]; }
__attribute__((noinline)) __int128 wide_ret(long *p, int k) { return (__int128)p[0] * k; }
/* floating point parameters between integers */
__attribute__((noinline)) long fl_mid(long a, double d, long *p) { return a + (long)d + p[0]; }
__attribute__((noinline)) long ld_mid(long a, long double d, long *p) { return a + (long)d + p[0]; }
__attribute__((noinline)) double fl_ret(long *p, int k) { return p[0] * (double)k; }
/* complex */
__attribute__((noinline)) double cx_mid(int a, double _Complex z, long *p) { return a + creal(z) + p[0]; }
/* small aggregates in registers */
__attribute__((noinline)) long small_mid(int a, struct small s, long *p) { return a + s.a + s.b + p[0]; }
__attribute__((noinline)) long un_mid(int a, union u16 u, long *p) { return a + u.l + p[0]; }
/* enums, bool, chars */
__attribute__((noinline)) enum color pick(enum color c, bool flag, signed char sc, unsigned char uc, char ch) { return flag ? c : (enum color)(sc + uc + ch); }
__attribute__((noinline)) enum wide pickw(enum wide w, short s, unsigned short us) { return (enum wide)(w + s + us); }
__attribute__((noinline)) bool is_set(const char *s, long n) { return n && s[0]; }
__attribute__((noinline)) signed char first_sc(const signed char *s) { return s[0]; }
__attribute__((noinline)) unsigned char first_uc(const unsigned char *s) { return s[0]; }
__attribute__((noinline)) char first_c(const char *s) { return s[0]; }
/* arrays and function pointers as parameters */
__attribute__((noinline)) int arr_mid(int a, int row[4], int (*cb)(int), long n) { return a + row[1] + cb((int)n); }
__attribute__((noinline)) int fn_mid(int a, int cb(int), long n) { return a + cb((int)n); }
/* variadic and unprototyped */
__attribute__((noinline)) long va_sum(int n, ...) { return n; }
__attribute__((noinline)) int kr(a, b) int a; char *b; { return a + b[0]; }
/* a type unit candidate: struct return and struct pointer */
struct node { struct node *next; long v; };
__attribute__((noinline)) struct node *tail(struct node *n) { while (n->next) n = n->next; return n; }
__attribute__((noinline)) long sum_big(struct big b, int k, long *p) { return b.a + k + p[0]; }
int main(int argc, char **argv) {
  long arr[4] = {argc, 2, 3, 4};
  int row[4] = {1, 2, 3, 4};
  struct node n = {0, argc};
  v4si v = {argc, 1, 2, 3};
  v4sf vf = {argc, 1, 2, 3};
  sink = vec_mid(argc, v, 2) + vecf_mid(argv[0], vf, 3) + make_big(argc, arr).a + make_small(argc, arr).a + (long)make_mixed(argc, arr).d;
  sink += wide_mid(argc, 5, arr) + (long)wide_ret(arr, argc) + fl_mid(argc, 2.0, arr) + ld_mid(argc, 2.0L, arr) + (long)fl_ret(arr, 2);
  sink += (long)cx_mid(argc, 1.0 + 2.0 * I, arr) + small_mid(argc, (struct small){1, 2}, arr) + un_mid(argc, (union u16){.l = 4}, arr);
  sink += pick(RED, argc > 1, 1, 2, 3) + pickw(W0, 1, 2) + is_set(argv[0], 1) + first_sc((signed char *)argv[0]) + first_uc((unsigned char *)argv[0]) + first_c(argv[0]);
  sink += arr_mid(argc, row, 0, 3) + va_sum(argc, 1, 2) + kr(argc, argv[0]) + tail(&n)->v + sum_big((struct big){1, 2, 3, 4}, argc, arr);
  return 0;
}
