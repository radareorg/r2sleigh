#include <stdlib.h>

/* A test whose arm ends the program, then the work that follows it. */
int checked_sum(const int *p, int n, int *out)
{
    if (n < 0)
        exit(2);
    *out = n;
    return p[0] + n;
}

/* The arm the test falls to ends the program, and the other returns. */
int first_or_die(const int *p)
{
    if (p == 0)
        abort();
    else
        return p[0] + 1;
}

/* An exit under the then arm of a test whose else returns. */
int nested(const int *p, const int *q, int *out)
{
    if (p != 0) {
        if (q != 0) {
            *out = q[0];
            return 1;
        } else {
            exit(3);
        }
    } else {
        *out = 3;
        return 0;
    }
}

int main(int argc, char **argv)
{
    int x = 0;
    return checked_sum(&argc, argc, &x) + first_or_die(&argc) + nested(&argc, &x, &x);
}
