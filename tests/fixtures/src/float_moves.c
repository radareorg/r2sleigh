#define NOINL __attribute__((noinline))
NOINL double scale(double x, double k) { return x * k; }
NOINL double swap_call(double a, double b) { return scale(b, a); }
int main(int argc, char **argv) { (void)argv; return (int)swap_call(argc, 2.0); }
