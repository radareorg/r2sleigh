/* Twelve statics whose code an injected section directive puts in `.fdat` without the X flag (`-DREADONLY`: flags A). */
#if defined(__aarch64__)
#define TAIL "%progbits //"
#else
#define TAIL "@progbits #"
#endif
#ifdef READONLY
#define NI static __attribute__((noinline, section(".fdat,\"a\"," TAIL)))
#else
#define NI static __attribute__((noinline, section(".fdat,\"aw\"," TAIL)))
#endif
NI int s_0(int a, short b) { return a * 3 + b; }
NI int s_1(int a, short b) { return a * 4 + b; }
NI int s_2(int a, short b) { return a * 5 + b; }
NI int s_3(int a, short b) { return a * 6 + b; }
NI int s_4(int a, short b) { return a * 7 + b; }
NI int s_5(int a, short b) { return a * 8 + b; }
NI int s_6(int a, short b) { return a * 9 + b; }
NI int s_7(int a, short b) { return a * 10 + b; }
NI int s_8(int a, short b) { return a * 11 + b; }
NI int s_9(int a, short b) { return a * 12 + b; }
NI int s_10(int a, short b) { return a * 13 + b; }
NI int s_11(int a, short b) { return a * 14 + b; }
int g_0(int x) { return s_0(x, 1) + s_1(x, 2) + s_2(x, 3) + s_3(x, 4) + s_4(x, 5) + s_5(x, 6); }
int g_1(int x) { return s_6(x, 1) + s_7(x, 2) + s_8(x, 3) + s_9(x, 4) + s_10(x, 5) + s_11(x, 6); }
int main(int c, char **v) { return g_0(c) + g_1(c); }
