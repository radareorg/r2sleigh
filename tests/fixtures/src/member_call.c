/* Calls through a function-pointer member of a pointer parameter (ROADMAP D171, S32). */
#define NOINL __attribute__((noinline))

struct pair { long lo, hi, extra; };
struct vtable { void (*call)(void *); };

struct ops {
    void *opaque;
    void (*release)(void *, void *);
    int (*size)(void *, int);
    long (*wide)(long, long, long, long, long, long, long, long, long);
    double (*scale)(double, int);
    int (*log)(const char *, ...);
    void (*old)();
    struct pair (*make)(int);
    struct vtable *vt;
    int count;
};

/* Two calls through one member with a store after them, as zlib's inflateEnd. */
NOINL void ops_release(struct ops *o, void *p, void *q) {
    o->release(o->opaque, p);
    o->release(o->opaque, q);
    o->count = 0;
}

/* A narrower result the caller widens. */
NOINL long ops_size(struct ops *o, int n) { return (long)o->size(o->opaque, n) + 1; }

/* Nine arguments: the last pass on the stack on x86-64 and AArch64. */
NOINL long ops_wide(struct ops *o, long a) {
    return o->wide(a, a + 1, a + 2, a + 3, a + 4, a + 5, a + 6, a + 7, a + 8) + 1;
}

/* Floating-point argument and result. */
NOINL double ops_scale(struct ops *o, double x) { return o->scale(x, o->count) + 1.0; }

/* Refused: a variadic member, an unprototyped one, a record result. Placed: a loaded member (D348). */
NOINL int ops_log(struct ops *o, const char *s) { return o->log("%s", s) + 1; }
NOINL int ops_old(struct ops *o) { o->old(o->opaque); return o->count; }
NOINL long ops_make(struct ops *o, int n) { return o->make(n).hi + 1; }
NOINL int ops_virtual(struct ops *o) { o->vt->call(o->opaque); return o->count; }

static void release(void *opaque, void *p) { (void)opaque; (void)p; }
static int size(void *opaque, int n) { (void)opaque; return n * 2; }
static long wide(long a, long b, long c, long d, long e, long f, long g, long h, long i) {
    return a + b + c + d + e + f + g + h + i;
}
static double scale(double x, int n) { return x * n; }
static int log_line(const char *f, ...) { (void)f; return 0; }
static void old(void *opaque) { (void)opaque; }
static struct pair make(int n) { struct pair p = {n, n + 1, n + 2}; return p; }
static void call(void *opaque) { (void)opaque; }
static struct vtable vt = {call};

int main(int argc, char **argv) {
    (void)argv;
    struct ops o = {0, release, size, wide, scale, log_line, old, make, &vt, argc};
    ops_release(&o, 0, 0);
    return (int)(ops_size(&o, argc) + ops_wide(&o, argc) + (long)ops_scale(&o, argc) +
                 ops_log(&o, "x") + ops_old(&o) + ops_make(&o, argc) + ops_virtual(&o));
}
