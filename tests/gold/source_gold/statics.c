/* Twelve static functions with code and two global ones: `-Wl,-x` (ld --discard-all) drops the statics' FUNC symbols. */
#define NI static __attribute__((noinline))
NI long s_0(long a, int b) { return a * 3 + b; }
NI long s_1(long a, int b) { return a * 4 - b; }
NI int s_2(int a) { return a ^ 0x5a; }
NI unsigned s_3(unsigned a, unsigned b) { return a / (b | 1u); }
NI long s_4(const long *p, int n) { long s = 0; for (int i = 0; i < n; i++) s += p[i]; return s; }
NI int s_5(int a, int b) { return a > b ? a : b; }
NI long s_6(long a) { return a << 3; }
NI int s_7(const char *s) { int n = 0; while (s[n]) n++; return n; }
NI unsigned long s_8(unsigned long a) { return a >> 2; }
NI int s_9(int a, int b, int c) { return a * b - c; }
NI long s_10(long a, long b) { return a % (b | 1); }
NI int s_11(int a) { return -a; }
__attribute__((noinline)) long g_0(long a) { return s_0(a, 1) + s_1(a, 2) + s_2((int)a) + s_3((unsigned)a, 3); }
__attribute__((noinline)) long g_1(long a) { long v[2] = {a, 2}; return s_4(v, 2) + s_5((int)a, 4) + s_6(a) + s_7("ab"); }
int main(int argc, char **argv) {
    (void)argv;
    return (int)(g_0(argc) + g_1(argc) + (long)s_8(argc) + s_9(argc, 2, 3) + s_10(argc, 5) + s_11(argc));
}
