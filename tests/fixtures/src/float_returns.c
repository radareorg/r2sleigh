#define NOINL __attribute__((noinline))
NOINL double half(double x) { return x * 0.5; }
NOINL double twice_half(double x) { return half(x) + half(x + 1.0); }
NOINL double loop_sum(const double *v, int n) { double s = 0; for (int i = 0; i < n; i++) s += v[i]; return s; }
int main(int argc, char **argv) { (void)argv; double v[2] = {argc, 2}; return (int)(twice_half(argc) + loop_sum(v, 2)); }
