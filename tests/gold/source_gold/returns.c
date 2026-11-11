/* Return presence for the source-gold gate: does a function return a value at all, built `-g -O2` and
   graded against the same binary stripped. `noipa` keeps each helper's own signature. */
#include <stdint.h>

#define KEEP __attribute__((noipa))

volatile int sink;

/* void, nothing left in the result register */
static KEEP void bump(int *p) { *p += 1; }

/* void, with a loop total left in the result register when it returns */
static KEEP void total_into(int *out, const int *v, int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) sum += v[i];
    *out = sum;
}

/* void, ending in a tail jump to a function that returns a value */
static KEEP int twice(int x) { sink = x; return x * 2; }
static KEEP void discard_twice(int x) { twice(x); }

/* int, every caller ignores the result */
static KEEP int ignored(int x) { sink = x; return x + 1; }

/* int, a constant every caller ignores */
static KEEP int constant(void) { sink = 7; return 7; }

/* int, forwarded by a tail jump: read by a caller, and not read by any */
static KEEP int forward_read(int x) { return twice(x); }
static KEEP int forward_ignored(int x) { return twice(x + 1); }

/* int, read by its caller */
static KEEP int used(int x) { return x * 3 + sink; }

/* exported: a caller outside this image may read the result or not */
KEEP int exported_value(int x) { sink = x; return x + 2; }
KEEP void exported_void(int *p) { *p = 0; }

int main(void) {
    int cell = 0;
    int v[4] = {1, 2, 3, 4};
    bump(&cell);
    total_into(&cell, v, 4);
    discard_twice(cell);
    ignored(cell);
    constant();
    forward_ignored(cell);
    exported_value(cell);
    exported_void(&cell);
    sink = forward_read(cell) + used(cell);
    return cell;
}
