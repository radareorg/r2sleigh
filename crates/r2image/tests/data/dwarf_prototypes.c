typedef unsigned long ulong_t;
typedef unsigned long size_t;
struct point { int x; int y; };
int add(int a, int b) { return a + b; }
ulong_t scale(ulong_t v, size_t n) { return v * n; }
int sum_point(const struct point *p) { return p->x + p->y; }
char *pick(char **names, int index) { return names[index]; }
double mean(const double *xs, int n) { double t = 0; for (int i = 0; i < n; i++) t += xs[i]; return t / n; }
int counted(const char *fmt, ...);
struct point shifted(struct point p, int by) {
	struct point moved;
	moved.x = p.x + by;
	moved.y = p.y + by;
	return moved;
}
