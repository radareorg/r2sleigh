/* S35 clause 3 (audit W11, ROADMAP D277): arm64 float results without DWARF. Build
   `clang --target=aarch64-linux-gnu -O2 -s fp.c`; each prototype is true or a named residual, never `(void)`. */
#define KEEP __attribute__((noinline))

KEEP float fadd(float a, float b) { return a + b; }
KEEP double dmul(unsigned n, double x) { return (double)n * x; }
KEEP int dcmp(double a, double b) { return a < b; }

volatile double sink;

int main(int argc, char **argv) {
    (void)argv;
    sink = fadd((float)argc, 0.5f);
    sink = dmul((unsigned)argc, 1.5);
    return dcmp(sink, 2.0);
}
