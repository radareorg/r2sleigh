/* Float comparisons in conditions: a NaN makes every ordered comparison false, so `!(a < b)` is not `a >= b`. */
#define KEEP __attribute__((noinline))

KEEP int below(double a, double b) { return a < b ? 1 : 2; }
KEEP int not_below(double a, double b) { return !(a < b); }
KEEP double floor_at(double x, double lo) {
    if (!(x >= lo))
        return lo;
    return x;
}
KEEP int ordered_or_equal(double a, double b) {
    if (a == b || a < b)
        return 3;
    return 4;
}

int main(int argc, char **argv) {
    (void)argv;
    double v = (double)argc;
    return below(v, 2.0) + not_below(v, 0.5) + (int)floor_at(v, 1.0) + ordered_or_equal(v, 3.0);
}
