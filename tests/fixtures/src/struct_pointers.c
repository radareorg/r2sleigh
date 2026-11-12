/* Parameters that point at structs through typedefs, and a struct holding a
 * pointer to a tag no unit lays out: pigz's `free_pool(pool *)`, whose `pool`
 * holds a `lock *`, and zopfli's self-calling `BoundaryPM(Node *, NodePool *)`. */

#define NOINL __attribute__((noinline))

typedef struct lock_s lock;
typedef struct pool { lock *have; int size; struct pool *next; } pool;
typedef struct Node { unsigned long weight; struct Node *tail; int count; } Node;

NOINL int free_pool(pool *p)
{
    int count = 0;
    while (p != 0) {
        count += p->size;
        p = p->next;
    }
    return count;
}

NOINL int held(lock *l) { return l != 0; }

NOINL int depth(Node *leaves, pool *p, int index)
{
    if (index <= 0)
        return leaves->count;
    return depth(leaves->tail, p, index - 1) + 1;
}

int main(void)
{
    Node b = {2, 0, 7}, a = {1, &b, 3};
    pool q = {0, 5, 0};
    return free_pool(&q) + held(q.have) + depth(&a, &q, 1);
}
