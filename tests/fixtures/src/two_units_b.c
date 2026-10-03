/* The other unit: its `helper` takes and keeps different types. */

static __attribute__((noinline)) double helper(const double *values, long count)
{
    double total = 0;
    for (long i = 0; i < count; i++)
        total += values[i];
    return total;
}

double from_b(const double *values, long count) { return helper(values, count); }

int from_a(int value);

int main(int argc, char **argv)
{
    double values[2] = { 1.0, (double)argc };
    (void)argv;
    return from_a(argc) + (int)from_b(values, 2);
}
