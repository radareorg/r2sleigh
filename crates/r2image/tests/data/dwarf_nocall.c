/* clang 23.1.4 `-target x86_64-unknown-linux-gnu -g -O2 -c`, linked with GNU ld `-e _start`.
 * Dead-argument elimination drops `unused`, so `add3` takes `c` in esi and states DW_CC_nocall. */
static __attribute__((noinline)) int add3(int a, int unused, int c) { return a * 3 + c; }
int entry(int x, int y) { return add3(x, y, x ^ y) + add3(y, x, 7); }
void _start(void) {}
