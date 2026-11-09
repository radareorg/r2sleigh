/* Enums of each sign and width as parameters and results. */
#include <stdio.h>
enum neg { N0 = -3, N1 = 1 };
enum pos { P0 = 1, P1 = 70000 };
enum big { B0 = -1, B1 = 5000000000LL };
enum ubig { U0 = 1, U1 = 0x80000000u };
typedef enum neg neg_t;
__attribute__((noinline)) enum neg e_neg(enum neg a, int b, enum neg c) { return b ? a : c; }
__attribute__((noinline)) enum pos e_pos(enum pos a, long b) { return b > 0 ? a : P0; }
__attribute__((noinline)) enum big e_big(enum big a, enum big b) { return a == B0 ? b : a; }
__attribute__((noinline)) enum ubig e_ubig(enum ubig a) { return a == U0 ? U1 : U0; }
__attribute__((noinline)) neg_t e_td(neg_t a, neg_t *p) { return p ? *p : a; }
__attribute__((noinline)) int e_ptr(enum pos *p) { return p ? (int)*p : 0; }
int main(int argc, char **argv) {
    enum neg n = e_neg(argc > 1 ? N0 : N1, argc, N1);
    enum pos p = e_pos(argc > 2 ? P1 : P0, argc);
    enum big b = e_big(argc > 3 ? B1 : B0, B1);
    neg_t t = e_td(n, &n);
    printf("%d %d %lld %u %d %d\n", (int)n, (int)p, (long long)b, (unsigned)e_ubig(U0), (int)t, e_ptr(&p));
    return 0;
}
