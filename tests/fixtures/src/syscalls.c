static long sys1(long n, long a) {
    long r;
    __asm__ volatile ("syscall" : "=a"(r) : "a"(n), "D"(a) : "rcx", "r11", "memory");
    return r;
}
__attribute__((noinline)) long unknown(long n) { return sys1(n, 0); }   /* number is a parameter */
__attribute__((noinline)) long joined(int c) {
    long n = c ? 39 : 39;                                               /* one value on both paths */
    if (c > 5) { __asm__ volatile ("" ::: "memory"); }
    return sys1(n, 0);
}
__attribute__((noinline)) long computed(void) {
    volatile int base = 0;
    return sys1(38 + 1 + (long)(base * 0), 0);                          /* folded in the body */
}
__attribute__((noinline)) int decoy(void) { int x; __asm__ volatile ("mov $0x050f, %0" : "=r"(x)); return x; }
void _start(void) {
    unknown(102); joined(3); computed(); decoy();
    sys1(231, 0);                                                       /* exit_group */
}
