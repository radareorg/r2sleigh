#include <stdint.h>
volatile int sink;
__attribute__((noipa)) int add1(int x) { return x + 1; }
__attribute__((noipa)) void seven(int a, int b, int c, int d, int e, int f, int g) { sink = a + b + c + d + e + f + g; }
struct pair { long a; long b; };
__attribute__((noipa)) long sum_pair(struct pair p) { return p.a + p.b; }
int main(void) { seven(1, 2, 3, 4, 5, 6, add1(7)); return (int)sum_pair((struct pair){1, 2}); }
