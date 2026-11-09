/* A library whose 12 unused functions `-ffunction-sections -Wl,--gc-sections` discards: their DIEs keep a low_pc of 0. */
#define NI __attribute__((noinline))
NI long unused_0(long a, int b) { return a * 3 + b; }
NI long unused_1(long a, int b) { return a * 4 + b; }
NI long unused_2(long a, int b) { return a * 5 + b; }
NI long unused_3(long a, int b) { return a * 6 + b; }
NI long unused_4(long a, int b) { return a * 7 + b; }
NI long unused_5(long a, int b) { return a * 8 + b; }
NI long unused_6(long a, int b) { return a * 9 + b; }
NI long unused_7(long a, int b) { return a * 10 + b; }
NI long unused_8(long a, int b) { return a * 11 + b; }
NI long unused_9(long a, int b) { return a * 12 + b; }
NI long unused_10(long a, int b) { return a * 13 + b; }
NI long unused_11(long a, int b) { return a * 14 + b; }
NI int used_a(int a, int b) { return a * b + 1; }
NI unsigned used_b(unsigned a) { return a ^ 0x55u; }
NI long used_c(long *p, int n) { long s = 0; for (int i = 0; i < n; i++) s += p[i]; return s; }
int main(int argc, char **argv) { long v[2] = {argc, 2}; (void)argv; return used_a(argc, 3) + (int)used_b(argc) + (int)used_c(v, 2); }
