/* A table of function pointers a relocation fills, for the rendering of an
 * entry as the function it names rather than as a read of the image. */
#include <stdint.h>

typedef uint64_t (*binary_operation)(uint64_t, uint64_t);

__attribute__((noinline)) uint64_t table_op_add(uint64_t a, uint64_t b) {
	return a + b;
}

__attribute__((noinline)) uint64_t table_op_xor(uint64_t a, uint64_t b) {
	return a ^ b;
}

__attribute__((noinline)) uint64_t table_op_mul(uint64_t a, uint64_t b) {
	return a * b;
}

__attribute__((noinline)) uint64_t table_dispatch(uint64_t a, uint64_t b) {
	binary_operation table[3] = {table_op_add, table_op_xor, table_op_mul};
	uint64_t accumulator = a;
	unsigned index;
	for (index = 0; index < 3u; index++) {
		accumulator = table[index](accumulator, b + index);
	}
	return accumulator;
}

int main(void) {
	return (int)table_dispatch(3, 5);
}
