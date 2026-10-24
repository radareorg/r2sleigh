/* gcc -O2 clones scale() and field_b() (.constprop, .isra): the DWARF of a clone lists the source's formals, not the registers. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
volatile long sink;
long g;
/* the first parameter is always the same constant: constprop removes it, the second moves to the first register */
__attribute__((noinline)) static long scale(int k, char *p, long n) { return k * p[0] + n + g; }
/* a struct passed by pointer of which only one field is read: ipa-sra passes the field */
struct rec { long a; long b; long c; };
__attribute__((noinline)) static long field_b(struct rec *r, int unused, long mul) { return r->b * mul; }
/* the cold part split out as foo.part.0 */
__attribute__((noinline)) static long part_split(long *p, long n) {
  if (n > 100) { for (long i = 0; i < n; i++) p[i] = p[i] * 3 + g; fprintf(stderr, "big %ld\n", n); abort(); }
  return p[0] + n;
}
__attribute__((noinline)) long use_scale(char *p, long n) { return scale(3, p, n) + scale(3, p + 1, n + 1); }
__attribute__((noinline)) long use_field(struct rec *r, long m) { return field_b(r, 0, m) + field_b(r + 1, 0, m + 1); }
__attribute__((noinline)) long use_part(long *p, long n) { return part_split(p, n); }
/* unused leading parameter of an exported function */
__attribute__((noinline)) long skip_first(int unused, long *p, long n) { return p[0] + n; }
int main(int argc, char **argv) {
  struct rec r[2] = {{1, 2, 3}, {4, 5, 6}};
  long a[4] = {1, 2, 3, 4};
  sink = use_scale(argv[0], argc) + use_field(r, argc) + use_part(a, argc) + skip_first(argc, a, 2);
  return 0;
}
