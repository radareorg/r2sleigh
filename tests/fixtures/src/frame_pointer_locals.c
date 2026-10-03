/* A function with locals and no parameters, measured from the frame pointer.
 *
 * Clang at -O0 states every frame variable against DW_OP_reg6 (rbp), and a
 * function that takes no parameters spills none, so no slot is stated in both
 * coordinate systems: only the prologue says where rbp points. */

__attribute__((noinline)) int counter(void)
{
    int step = 3;
    long total = 10;
    for (int i = 0; i < step; i++)
        total += i;
    return (int)total;
}

int main(void) { return counter(); }
