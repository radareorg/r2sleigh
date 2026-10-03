/* The declaration-graph fixture: every node kind the DWARF reader states.
 *
 * Built into `dwarf_graph.elf` with
 *
 *     gcc -O2 -g -fno-inline-small-functions -o dwarf_graph.elf dwarf_graph.c
 *
 * (GCC 13.3.0, x86-64). At -O2 GCC specialises `scaled` into
 * `scaled.constprop.0.isra.0`: a body whose concrete DWARF instance refers to
 * the source's `scaled` for its name and types, passes `p->a` and `p->b`
 * where the source passes `p`, and folds `bias` to a constant. */

struct opaque;

struct pair { int a; long b; };

struct flags {
    unsigned ready : 1;
    unsigned mode : 3;
    unsigned char tag;
    int values[];
};

union word { unsigned int u; float f; unsigned char bytes[4]; };

enum colour { RED, GREEN = 5, BLUE };

typedef struct { short x; short y; } point_t;

int counter = 3;
const char *message = "graph";
static int table[2][3];
point_t origin = { 1, 2 };

static __attribute__((noinline)) long scaled(const struct pair *p, int factor, int bias)
{
    long s = 0;
    for (int i = 0; i < factor; i++)
        s += p->a * (long)i + p->b;
    return s + bias;
}

__attribute__((noinline)) long use_opaque(struct opaque *o) { return (long)o; }

__attribute__((noinline)) int apply(int (*fn)(int, int), int a) { return fn(a, a + 1); }

__attribute__((noinline)) int add(int a, int b) { return a + b; }

__attribute__((noinline)) unsigned read_flags(const struct flags *f, union word w, enum colour c)
{
    static unsigned calls;
    calls++;
    return f->ready + f->mode + f->values[0] + w.bytes[1] + (unsigned)c + calls;
}

int main(int argc, char **argv)
{
    struct pair p = { argc, (long)argv };
    struct pair q = { argc + 1, 7 };
    table[1][2] = argc;
    return (int)(scaled(&p, argc, 3) + scaled(&q, argc * 2, 3) + use_opaque((struct opaque *)argv))
        + apply(add, argc) + counter + origin.x + table[1][2];
}
