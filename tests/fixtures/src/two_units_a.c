/* One of two units that each define a `static helper` of their own.
 *
 * Built with `two_units_b.c` into `tests/fixtures/two_units_O0g`:
 *
 *     gcc -O0 -g -o tests/fixtures/two_units_O0g tests/fixtures/src/two_units_a.c tests/fixtures/src/two_units_b.c
 *
 * (GCC 13.3.0, x86-64). */

static __attribute__((noinline)) int helper(int value)
{
    int doubled = value * 2;
    return doubled;
}

int from_a(int value) { return helper(value); }
