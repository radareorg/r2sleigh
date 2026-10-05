#define NOINL __attribute__((noinline))
NOINL void store(double x, double *p) { *p = x * 2.0; }
NOINL void call_store(double *p) { store(1.25, p); }
NOINL void forward(double x, double *p) { store(x, p); store(x + 1.0, p); }
int main(int argc, char **argv) { (void)argv; double d; store((double)argc, &d); call_store(&d); forward(d, &d); return (int)d; }
