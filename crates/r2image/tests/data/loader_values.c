/* What the loader writes, and the value the container states for it.
 *
 * Built twice, and committed as bytes so the compiler on the machine running
 * the test cannot move the answer:
 *
 *   gcc -O1 -fPIE -pie -Wl,-Ttext-segment=0x10000 -Wl,--build-id=none \
 *       -o loader_values_pie_at_0x10000.elf loader_values.c
 *   gcc -O1 -fPIC -shared -Wl,--build-id=none \
 *       -o loader_values.so loader_values.c
 *
 * In the executable both pointers are R_X86_64_RELATIVE, whose value in link
 * coordinates is the addend, however high the image is linked. In the shared
 * library `shared_global` has default visibility, so its pointer is an
 * R_X86_64_64 against a definition an image loaded ahead of this one may
 * replace, while `local_global` cannot be and stays relative.
 */

int shared_global = 1;
int *ptr_to_global = &shared_global;

static int local_global = 2;
int *ptr_to_local = &local_global;

int get(void) { return *ptr_to_global + *ptr_to_local; }

int main(void) { return get(); }
